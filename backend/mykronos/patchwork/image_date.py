"""Move a patched image's pin to a package snapshot image-refresh already published.

The deterministic fixer `bump-image-date` (registered in `fixers.FIXERS`). It
does not move image. TheHub and MyKronos run third-party images as patched
derivatives, pinned as `<registry>/<name>:<version>-p<YYYYMMDD>` with the
recipe under `x-thehub-build` / `x-mykronos-build`; the date is the package
snapshot, so a newer date is the same recipe on newer packages. This module
proposes exactly one kind of edit: `-p<old>` to `-p<new>` on the lines that
pin that image, and nothing else.

**The evidence is the registry, not the advisory.** The `image-refresh` lane
(`deploy/concourse/pipelines/thehub.yml` and `mykronos.yml`, deciding with
`mykronos.image_refresh`) rebuilds each recipe at today's date and pushes
`-p<today>` only when its verdict is `improved`, and the registry has deletes
disabled, so a newer `-p<date>` for the same repository and the same tag
prefix is the lane's record that it judged that snapshot an improvement. (The
one other writer of a dated tag is TheHub's `publish-patched-images.sh`,
which pushes whatever date a deployed compose file pins when the registry
lacks it; such a tag is a date a person already chose. The registry cannot
say which wrote a tag, and the pull request does not pretend to.) A finding's
`fixed_version` is deliberately not consulted: the publish rule is the
evidence, and a fixed version says only that a patched package exists
somewhere.

What that evidence does and does not establish differs by lane, and the pull
request says which:

- MyKronos's lane publishes per image (`outcome: improved`): this image
  removed a HIGH/CRITICAL pair and added none, or, with no HIGH/CRITICAL
  change, removed a MEDIUM and added none.
- TheHub's lane decides over the whole set and, when the set improved, pushes
  every candidate, "improved or not", because the demo's date is one
  variable. For one TheHub image a newer tag therefore guarantees only that it
  gained no HIGH/CRITICAL pair; it may be unchanged.

So the lake is consulted too. When a containers lane has ingested findings
for the newer tag, a finding still present there is not claimed as cleared,
and an image whose every finding persists gets no pull request. When the lake
holds nothing for the newer tag, the pull request says so: it then rests on
the publish rule alone.

**The edit.** Production pins are literal dates (TheHub's
`test_production_dates_are_literal_so_no_variable_can_move_them`). The demo
reads `${THEHUB_DEMO_PATCH_DATE:-<date>}`, and a TheHub test holds that
default equal to production's pin for the same image, so a default is moved
only where it equals the old production pin. Every production pin of that
image must agree on the old date, or nothing is changed: half a move is a
state no test allows. A pin carrying a digest is refused, since the digest
names the old bytes.

`propose` is pure: the registry listing, the compose files and the lake's
view of the newer tag are all arguments, so a test can say exactly what the
platform saw. `RegistryTags` is the one network read.
"""

from __future__ import annotations

import datetime as dt
import logging
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import quote, urljoin

import httpx2

from mykronos.image_refresh import COMPOSE_FILES, MYKRONOS_COMPOSE_FILES
from mykronos.patchwork.fixers import ProposedFix
from mykronos.patchwork.regression_prompt import regression_prompt
from mykronos.patchwork.rejection import rejection_prompt

logger = logging.getLogger(__name__)

FIXER_NAME = "bump-image-date"

#: Every compose file a recipe can live in: TheHub's two at the root, and the
#: two MyKronos's own recipes are declared in. Read from `image_refresh`, the
#: lane that publishes the tags, so the fixer reads the files the lane reads.
CANDIDATE_COMPOSE_FILES: tuple[str, ...] = (*COMPOSE_FILES, *MYKRONOS_COMPOSE_FILES)

#: Hosts a finding's image may not name. A tag listed on the configured
#: registry is evidence about *that* registry's image, and must never be read
#: as evidence about a public image of the same name.
PUBLIC_REGISTRIES = frozenset(
    {
        "docker.io",
        "index.docker.io",
        "registry-1.docker.io",
        "ghcr.io",
        "quay.io",
        "gcr.io",
        "mcr.microsoft.com",
        "public.ecr.aws",
        "registry.k8s.io",
    }
)

_TAG = re.compile(r"^(?P<prefix>[A-Za-z0-9_][A-Za-z0-9_.-]*?)-p(?P<date>\d{8})$")
#: One `image:` line, keeping everything around the reference byte-for-byte.
_IMAGE_LINE = re.compile(r"^(?P<lead>\s*image:\s*[\"']?)(?P<ref>[^\s\"'#]+)")
_LITERAL = re.compile(
    r"^(?P<path>[^:@\s]+):(?P<prefix>[A-Za-z0-9_][A-Za-z0-9_.-]*?)-p(?P<date>\d{8})"
    r"(?P<digest>@sha256:[0-9a-f]+)?$"
)
_DEFAULTED = re.compile(
    r"^(?P<path>[^:@\s]+):(?P<prefix>[A-Za-z0-9_][A-Za-z0-9_.-]*?)"
    r"-p\$\{(?P<var>[A-Za-z_][A-Za-z0-9_]*):-(?P<date>\d{8})\}$"
)

#: How many finding lines a pull request body lists before summarising. An
#: image can carry hundreds; a reviewer needs the shape, and the lake has the
#: rest.
LISTED_FINDINGS = 40


def _is_date(value: str) -> bool:
    try:
        dt.datetime.strptime(value, "%Y%m%d")
    except ValueError:
        return False
    return True


def _split_host(reference: str) -> tuple[str | None, str]:
    """`host/rest` when the first component is a registry host, else (None, ref).

    A compose `${REGISTRY:-localhost:5000}` counts as a host: it is one.
    """
    first, sep, rest = reference.partition("/")
    if sep and (
        first.startswith("${") or "." in first or ":" in first or first == "localhost"
    ):
        return first, rest
    return None, reference


@dataclass(frozen=True)
class PatchedImage:
    """`<host>/<path>:<prefix>-p<date>`, the shape image-refresh publishes."""

    host: str
    path: str
    prefix: str
    date: str

    @property
    def tag(self) -> str:
        return f"{self.prefix}-p{self.date}"

    @property
    def path_tag(self) -> str:
        return f"{self.path}:{self.tag}"

    @property
    def reference(self) -> str:
        return f"{self.host}/{self.path_tag}"

    def with_date(self, date: str) -> PatchedImage:
        return PatchedImage(self.host, self.path, self.prefix, date)


def parse_image(reference: str) -> PatchedImage | None:
    """The patched image a finding names, or None when it is not that shape.

    None for: no registry host (a bare name pulls from Docker Hub), a public
    registry, or a tag without a valid `-p<YYYYMMDD>` suffix. A digest is
    dropped: Trivy names what it scanned by tag.
    """
    ref = reference.strip().split("@", 1)[0]
    host, rest = _split_host(ref)
    if host is None or host.startswith("${") or host.lower() in PUBLIC_REGISTRIES:
        return None
    path, sep, tag = rest.rpartition(":")
    if not sep or not path or "/" in tag:
        return None
    match = _TAG.match(tag)
    if not match or not _is_date(match.group("date")):
        return None
    return PatchedImage(host, path, match.group("prefix"), match.group("date"))


def image_of_finding(finding: Mapping[str, Any]) -> PatchedImage | None:
    """The patched image of a container finding, or None if it is not one."""
    if finding.get("capability") != "containers":
        return None
    raw = finding.get("raw_finding_json")
    image = raw.get("image") if isinstance(raw, dict) else None
    return parse_image(image) if isinstance(image, str) else None


def newer_date(image: PatchedImage, tags: Iterable[str]) -> str | None:
    """The newest `-p<date>` tag strictly after `image`'s, same prefix only.

    `7.4.11-alpine-p20261020` is newer than `7.4.11-alpine-p20261011`;
    `7.4.12-alpine-p20261020` and `7.4.11-trixie-p20261020` are other images
    and never count, however new.
    """
    best: str | None = None
    for tag in tags:
        match = _TAG.match(tag)
        if not match or match.group("prefix") != image.prefix:
            continue
        date = match.group("date")
        if _is_date(date) and date > image.date and (best is None or date > best):
            best = date
    return best


# --------------------------------------------------------------------------
# The compose edit
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Change:
    path: str
    line: int
    before: str
    after: str
    kind: str  # "pin" or "demo default"


@dataclass
class Rewrite:
    files: dict[str, str]
    changes: list[Change]
    #: Demo defaults for this image left alone because they did not equal the
    #: production pin. Reported, never "fixed": the invariant was already off.
    untouched_defaults: list[Change] = field(default_factory=list)


def _host_matches(line_host: str | None, image: PatchedImage) -> bool:
    """A compose line names the registry the finding's image came from.

    `${REGISTRY:-...}` resolves per environment and `localhost:<port>` is the
    host's own view of the registry; both are how these stacks spell it. A
    line with no host at all pulls from Docker Hub and is never this image.
    """
    if line_host is None:
        return False
    return (
        line_host.startswith("${")
        or line_host == image.host
        or line_host == "localhost"
        or line_host.startswith("localhost:")
    )


def rewrite(files: Mapping[str, str], image: PatchedImage, new_date: str) -> Rewrite | str:
    """Move every pin of `image` to `new_date`, or say why not.

    Returns the changed files only. A string is a refusal, worded for the
    remediation event a person reads.
    """
    pins: list[tuple[str, int, str, re.Match[str], re.Match[str]]] = []
    defaults: list[tuple[str, int, str, re.Match[str], re.Match[str]]] = []
    other_dates: set[str] = set()
    digest_pinned: list[str] = []

    for path in sorted(files):
        for index, line in enumerate(files[path].splitlines(keepends=True)):
            body = line.rstrip("\r\n")
            head = _IMAGE_LINE.match(body)
            if not head:
                continue
            host, rest = _split_host(head.group("ref"))
            if not _host_matches(host, image):
                continue
            literal = _LITERAL.match(rest)
            defaulted = None if literal else _DEFAULTED.match(rest)
            found = literal or defaulted
            if not found or found.group("path") != image.path:
                continue
            if found.group("prefix") != image.prefix:
                continue
            if literal:
                if literal.group("date") != image.date:
                    other_dates.add(literal.group("date"))
                elif literal.group("digest"):
                    digest_pinned.append(f"{path}:{index + 1}")
                else:
                    pins.append((path, index, line, head, literal))
            elif defaulted:
                defaults.append((path, index, line, head, defaulted))

    if digest_pinned:
        return (
            f"{image.path_tag} is pinned by digest at {', '.join(digest_pinned)}; "
            "the digest names the old bytes, so moving the date alone would "
            "name an image that does not match it."
        )
    if not pins:
        if other_dates:
            return (
                f"No compose file pins {image.path_tag} exactly. This repository "
                f"pins {image.path}:{image.prefix} at -p{', -p'.join(sorted(other_dates))}, "
                "so the finding describes an image it no longer runs."
            )
        return (
            f"No compose file pins {image.path_tag} exactly (searched "
            f"{', '.join(sorted(files)) or 'no compose files'}). Nothing was "
            "changed: an edit needs the old tag string to find."
        )
    if other_dates:
        return (
            f"Production pins of {image.path}:{image.prefix} disagree: "
            f"-p{image.date} and -p{', -p'.join(sorted(other_dates))}. Moving only "
            "some of them is a state no test allows; reconcile them by hand."
        )

    lines_by_path = {path: text.splitlines(keepends=True) for path, text in files.items()}
    changes: list[Change] = []
    untouched: list[Change] = []

    def _replace(path: str, index: int, line: str, head: re.Match[str], new_ref: str) -> str:
        start, end = head.span("ref")
        updated = line[:start] + new_ref + line[end:]
        lines_by_path[path][index] = updated
        return updated

    for path, index, line, head, _literal in pins:
        ref = head.group("ref")
        old_suffix = f"-p{image.date}"
        new_ref = ref[: -len(old_suffix)] + f"-p{new_date}"
        _replace(path, index, line, head, new_ref)
        changes.append(Change(path, index + 1, ref, new_ref, "pin"))

    for path, index, line, head, defaulted in defaults:
        ref = head.group("ref")
        if defaulted.group("date") != image.date:
            untouched.append(Change(path, index + 1, ref, ref, "demo default"))
            continue
        old_tail = f":-{image.date}}}"
        new_ref = ref[: -len(old_tail)] + f":-{new_date}}}"
        _replace(path, index, line, head, new_ref)
        changes.append(Change(path, index + 1, ref, new_ref, "demo default"))

    touched = {change.path for change in changes}
    return Rewrite(
        files={path: "".join(lines_by_path[path]) for path in sorted(touched)},
        changes=sorted(changes, key=lambda c: (c.path, c.line)),
        untouched_defaults=untouched,
    )


# --------------------------------------------------------------------------
# One proposal per image and date
# --------------------------------------------------------------------------


def _pair(finding: Mapping[str, Any]) -> tuple[str, str]:
    return (str(finding.get("rule_id") or ""), str(finding.get("package_name") or ""))


@dataclass
class ImageDatePlan:
    image: PatchedImage
    new_date: str
    fix: ProposedFix
    rewrite: Rewrite
    #: Findings this change should clear: every open one in the image, less
    #: any the lake has seen in the newer tag.
    clears: list[dict[str, Any]]
    #: Open findings the lake has already seen in the newer tag.
    persists: list[dict[str, Any]]
    #: True when a containers lane has ingested findings for the newer tag.
    verified: bool
    recipe: str | None

    @property
    def new_image(self) -> PatchedImage:
        return self.image.with_date(self.new_date)

    @property
    def lead_finding_id(self) -> str:
        return min(str(f["finding_id"]) for f in self.clears)


def recipe_kind(files: Mapping[str, str], changed_paths: Iterable[str]) -> str | None:
    """`x-thehub-build` or `x-mykronos-build`, from the files the edit touches."""
    text = "".join(files.get(path, "") for path in changed_paths)
    if "x-thehub-build" in text:
        return "x-thehub-build"
    if "x-mykronos-build" in text:
        return "x-mykronos-build"
    return None


def propose(
    image: PatchedImage,
    *,
    tags: Iterable[str],
    files: Mapping[str, str],
    findings: Iterable[Mapping[str, Any]],
    observed_in_newer: set[tuple[str, str]] | None,
) -> ImageDatePlan | str:
    """The one change for `image`, or the reason there is none.

    `findings` are the open findings in `image` (the group). `observed_in_newer`
    is the set of (rule_id, package_name) the lake holds for the newer tag, or
    None when the lake holds nothing for it at all.
    """
    tag_list = list(tags)
    new = newer_date(image, tag_list)
    if new is None:
        return (
            f"The registry holds no tag for {image.path}:{image.prefix} newer than "
            f"-p{image.date}, so image-refresh has not published a strictly better "
            "rebuild of this image."
        )
    edit = rewrite(files, image, new)
    if isinstance(edit, str):
        return edit

    group = [dict(f) for f in findings]
    if observed_in_newer is None:
        clears, persists = group, []
    else:
        clears = [f for f in group if _pair(f) not in observed_in_newer]
        persists = [f for f in group if _pair(f) in observed_in_newer]
    if not clears:
        return (
            f"{image.path}:{image.prefix}-p{new} has been scanned and still carries "
            f"every one of this image's {len(group)} open finding(s); moving the "
            "date would clear nothing."
        )

    verified = observed_in_newer is not None
    recipe = recipe_kind(files, edit.files)
    new_tag = f"{image.prefix}-p{new}"
    notes = [
        f"The edit is the date only: `{image.path}:{image.tag}` to "
        f"`{image.path}:{new_tag}`, the same recipe on a newer package snapshot. "
        "Nothing here moves the base image or the vendor version.",
        _evidence_note(recipe),
        (
            f"Verified against the lake: a containers lane has scanned `{new_tag}`, "
            f"and {len(clears)} of this image's {len(group)} open finding(s) are "
            "absent from it."
            if verified
            else f"Not verified against a scan: the platform keeps no Trivy result "
            f"for `{new_tag}` (no containers lane has ingested it), so this rests on "
            "image-refresh's publish rule alone. Confirm the findings close after "
            "the next containers scan."
        ),
        "A MEDIUM introduced by the new snapshot does not stop either lane "
        "from publishing when a HIGH/CRITICAL was removed. Read the next "
        "containers scan of the new tag, not only the count.",
    ]
    fix = ProposedFix(
        files=edit.files,
        summary=f"Move `{image.path}:{image.prefix}` to the -p{new} package snapshot",
        review_notes=notes,
        # Deterministic either way. Lower when no scan of the new tag backs
        # the claim, so a repository that raises its floor can refuse to act
        # on the publish rule alone.
        confidence=1.0 if verified else 0.9,
    )
    return ImageDatePlan(
        image=image,
        new_date=new,
        fix=fix,
        rewrite=edit,
        clears=sorted(clears, key=lambda f: str(f["finding_id"])),
        persists=sorted(persists, key=lambda f: str(f["finding_id"])),
        verified=verified,
        recipe=recipe,
    )


def _evidence_note(recipe: str | None) -> str:
    if recipe == "x-thehub-build":
        return (
            "The new tag exists because TheHub's image-refresh lane published it, "
            "which it does only on an `improved` verdict. That verdict is over the "
            "whole set, and an improved set pushes every candidate, so for this "
            "one image the tag guarantees no new HIGH/CRITICAL (vulnerability, "
            "package) pair, not that this image itself improved."
        )
    return (
        "The new tag exists because image-refresh published it, which it does "
        "for an image only on an `improved` outcome: a HIGH/CRITICAL pair "
        "removed and none added, or, with no HIGH/CRITICAL change, a MEDIUM "
        "removed and none added."
    )


def _rollout(plan: ImageDatePlan) -> list[str]:
    new = plan.new_image.path_tag
    if plan.recipe == "x-thehub-build":
        lines = [
            f"- `scripts/deploy.sh` runs `scripts/publish-patched-images.sh` before it "
            f"recreates anything. That script builds only a pinned tag the registry "
            f"lacks; `{new}` is already present, so it is left alone and production "
            "pulls the exact bytes image-refresh scanned on the next deploy.",
        ]
        if any(c.kind == "demo default" for c in plan.rewrite.changes):
            lines.append(
                "- The demo's `THEHUB_DEMO_PATCH_DATE` default moves with it, because "
                "it equalled the production pin, and TheHub's "
                "`test_the_demos_patched_images_take_their_date_from_the_refresh_lane` "
                "holds the two equal."
            )
    else:
        lines = [
            f"- The service runs `{new}` when its stack is next recreated from this "
            "compose file.",
        ]
    for change in plan.rewrite.untouched_defaults:
        lines.append(
            f"- Left alone: `{change.path}:{change.line}` defaults to a different "
            "date than production pinned, so it was already out of step and this "
            "change does not guess which is right."
        )
    lines.append(
        "- Production moves only when a person merges this. Nothing here merges "
        "it, and image-refresh never moves a production pin."
    )
    return lines


def _finding_line(finding: Mapping[str, Any]) -> str:
    package = finding.get("package_name") or "?"
    version = finding.get("package_version") or "?"
    return (
        f"- **{finding.get('rule_id')}** ({finding.get('severity')}) in `{package}` "
        f"{version} — {finding.get('title')}"
    )


def _listed(findings: list[dict[str, Any]]) -> list[str]:
    lines = [_finding_line(f) for f in findings[:LISTED_FINDINGS]]
    if len(findings) > LISTED_FINDINGS:
        lines.append(f"- … and {len(findings) - LISTED_FINDINGS} more in the same image.")
    return lines


def render_pr_body(plan: ImageDatePlan) -> str:
    """What a reviewer reads. Same order as `pipeline.render_pr_body`."""
    fix = plan.fix
    lines = [
        f"## {fix.summary}",
        "",
        "**Draft, and it stays that way.** Mykronos opens this for review; it "
        "has no ability to merge — the client it uses exposes no merge "
        "operation at all (spec 08 §3).",
        "",
        "### Before you approve",
        "",
        *[f"- {note}" for note in fix.review_notes],
        "",
        "### Tags",
        "",
        f"- Old: `{plan.image.reference}`",
        f"- New: `{plan.new_image.reference}`",
        "",
        f"### Findings this should clear ({len(plan.clears)})",
        "",
        *_listed(plan.clears),
    ]
    if plan.persists:
        lines += [
            "",
            f"### Findings the new tag still carries ({len(plan.persists)})",
            "",
            *_listed(plan.persists),
        ]
    lines += [
        "",
        "### Changes",
        "",
        *[
            f"- `{c.path}:{c.line}` ({c.kind}): `{c.before}` → `{c.after}`"
            for c in plan.rewrite.changes
        ],
        "",
        "### Rollout",
        "",
        *_rollout(plan),
        "",
        regression_prompt(),
        "",
        rejection_prompt(),
        "",
        "---",
        "",
        f"<sub>Generated deterministically by `{FIXER_NAME}` — no model was "
        "involved, and re-running produces the same diff. If you edit this "
        "branch, Patchwork stops touching it permanently (spec 08 §3).</sub>",
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------------
# The registry
# --------------------------------------------------------------------------


class TagSource(Protocol):
    async def tags(self, repository: str) -> list[str] | None:
        """Every tag of `repository`, [] if it has none, None if unreadable."""
        ...


class RegistryTags:
    """`GET /v2/<repository>/tags/list` on the registry the lanes publish to.

    No Python in this repository read that registry before: the lanes reach it
    as Concourse's `((registry))` with `crane` and `trivy --insecure`, which is
    plain HTTP. This is the same read through the same port, from wherever the
    backend runs (its compose file names the route). Anonymous and read-only,
    as the registry itself is: a listing is the whole of what is asked.
    """

    MAX_PAGES = 20

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 10.0,
        transport: httpx2.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/") + "/"
        self.timeout = timeout
        self.transport = transport

    @classmethod
    def from_settings(cls, settings: Any) -> RegistryTags | None:
        url = str(getattr(settings, "patchwork_image_registry", "") or "").strip()
        return cls(url) if url else None

    async def tags(self, repository: str) -> list[str] | None:
        found: list[str] = []
        url: str | None = urljoin(
            self.base_url, f"v2/{quote(repository, safe='/')}/tags/list?n=1000"
        )
        try:
            async with httpx2.AsyncClient(
                timeout=self.timeout, transport=self.transport, follow_redirects=False
            ) as client:
                for _ in range(self.MAX_PAGES):
                    if url is None:
                        break
                    response = await client.get(url)
                    if response.status_code == 404:
                        return found
                    response.raise_for_status()
                    found.extend(str(t) for t in (response.json().get("tags") or []))
                    url = _next_page(self.base_url, response.headers.get("link"))
        except (httpx2.HTTPError, ValueError) as exc:
            logger.warning("Could not list tags of %s: %s", repository, exc)
            return None
        return found


def _next_page(base_url: str, link: str | None) -> str | None:
    """The `rel="next"` target of a registry `Link` header, on the same host."""
    if not link:
        return None
    match = re.search(r"<([^>]+)>\s*;\s*rel=\"?next\"?", link)
    if not match:
        return None
    target = match.group(1)
    # Only a path. A Link to another host is not followed.
    return urljoin(base_url, target) if target.startswith("/v2/") else None
