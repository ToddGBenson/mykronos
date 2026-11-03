"""Refresh the workflow templates from the pins the estate runs (#376, TheHub #60876).

`pins.reconcile_pins` stops an install from moving a target's pin backwards.
It does not move the *template* forward, so every install still renders a
stale pin and relies on the reconcile step to discard it. Dependabot cannot
do it either: it does not parse `.j2`.

What does stay current is every rendered workflow whose repository runs
Dependabot -- this repository's own `.github/workflows/` and `actions/`, and
each onboarded repository's generated `mykronos-*.yml`. This module reads
those as *sources* and moves each template pin to the newest release they
carry. The rules, each for a reason:

* **Forward only.** A source older than the template is ignored. The
  template is never the downgrade.
* **Same major only, unless asked.** A major can change runner requirements
  (#376 item 3, CodeQL v4); that belongs in a tested change, so it is
  reported, not applied. `allow_major=True` applies it.
* **A pin is `owner/repo@<40-hex sha>  # vX.Y.Z` or it is not read.** A tag
  ref, a branch, a pre-release or a missing comment gives no comparable
  version, and guessing in the template's favour is the bug being fixed.
* **One repository, one release.** `github/codeql-action/init` and
  `.../analyze` are two paths of one release. Versions are compared per
  `owner/repo`, so a source that only uses `init` still moves `analyze`, and
  a template never runs two CodeQL releases in one job.
* **Two SHAs for one release is a conflict, not a choice.** That is what a
  moved tag looks like; the repository is left alone and the conflict named.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

from mykronos.installer.pins import parse_version

#: A `uses:` line in `owner/repo@<40-hex sha>  # vX.Y.Z` form, split so the
#: SHA and the release label can be replaced in place and everything else --
#: indentation, the template's own comment spacing -- is kept byte for byte.
_PIN = re.compile(
    r"^[ \t]*(?:-[ \t]+)?uses:[ \t]*"
    r"(?P<action>[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+)"
    r"@(?P<sha>[0-9a-f]{40})"
    r"(?P<sep>[ \t]*#[ \t]*)(?P<label>\S+)",
    re.MULTILINE,
)


def _repository(action: str) -> str:
    """`github/codeql-action/init` -> `github/codeql-action`."""
    return "/".join(action.split("/")[:2])


@dataclass(frozen=True)
class SourcePin:
    repository: str
    sha: str
    label: str
    version: tuple[int, int, int]
    origin: str


@dataclass(frozen=True)
class TemplatePinChange:
    path: str
    action: str
    old_version: str
    new_version: str
    source: str

    def describe(self) -> str:
        return (
            f"{self.path}: {self.action} {self.old_version} -> {self.new_version} "
            f"(from {self.source})"
        )


@dataclass(frozen=True)
class TemplatePinSkip:
    path: str
    action: str
    template_version: str
    source_version: str
    source: str
    reason: str

    def describe(self) -> str:
        return (
            f"{self.path}: {self.action} kept at {self.template_version}; "
            f"{self.source} has {self.source_version} -- {self.reason}"
        )


#: `owner/repo` -> major -> the newest pin of that major. Kept per major so a
#: new major in one source (refused unless asked) cannot hide a same-major
#: patch in another.
SourcePins = dict[str, dict[int, SourcePin]]


def collect_source_pins(sources: Mapping[str, str]) -> tuple[SourcePins, list[str]]:
    """The newest SHA + release pin per `owner/repo` and major across `sources`.

    Returns the pins and a description of every conflict: two SHAs claiming
    the newest release of one repository and major. A conflicted entry is
    left out, so nothing is refreshed from it.
    """
    best: SourcePins = {}
    rivals: dict[tuple[str, int], set[str]] = {}
    for origin in sorted(sources):
        content = sources[origin].replace("\r\n", "\n")
        for match in _PIN.finditer(content):
            version = parse_version(match.group("label"))
            if version is None:
                continue
            repository = _repository(match.group("action"))
            pin = SourcePin(
                repository=repository,
                sha=match.group("sha"),
                label=match.group("label"),
                version=version,
                origin=origin,
            )
            majors = best.setdefault(repository, {})
            current = majors.get(version[0])
            if current is None or pin.version > current.version:
                majors[version[0]] = pin
                rivals[(repository, version[0])] = {pin.sha}
            elif pin.version == current.version:
                rivals[(repository, version[0])].add(pin.sha)

    conflicts = []
    for (repository, major), shas in sorted(rivals.items()):
        if len(shas) > 1:
            pin = best[repository].pop(major)
            conflicts.append(
                f"{repository} {pin.label} is pinned to {len(shas)} different SHAs "
                f"({', '.join(sorted(s[:12] for s in shas))}); not refreshing it"
            )
    return best, conflicts


def refresh_template(
    path: str,
    content: str,
    pins: SourcePins,
    *,
    allow_major: bool = False,
) -> tuple[str, list[TemplatePinChange], list[TemplatePinSkip]]:
    """`content` with every pin moved forward to the newest one in `pins`."""
    changes: list[TemplatePinChange] = []
    skips: list[TemplatePinSkip] = []
    pieces: list[str] = []
    cursor = 0
    for match in _PIN.finditer(content):
        ours = parse_version(match.group("label"))
        if ours is None:
            continue
        action = match.group("action")
        label = match.group("label")
        majors = pins.get(_repository(action), {})
        same = majors.get(ours[0])
        newer_major = max((m for m in majors if m > ours[0]), default=None)

        def skip(theirs: SourcePin, reason: str) -> None:
            skips.append(
                TemplatePinSkip(
                    path=path,
                    action=action,  # noqa: B023 - called within this iteration
                    template_version=label,  # noqa: B023
                    source_version=theirs.label,
                    source=theirs.origin,
                    reason=reason,
                )
            )

        target: SourcePin | None = None
        if newer_major is not None and allow_major:
            target = majors[newer_major]
        else:
            if newer_major is not None:
                skip(majors[newer_major], "a new major is a tested change, not a pin refresh")
            if same is not None and same.sha != match.group("sha"):
                if same.version > ours:
                    target = same
                elif same.version == ours:
                    skip(same, "same release, different SHA; not guessing which is right")
        if target is None:
            continue

        pieces.append(content[cursor : match.start("sha")])
        pieces.append(target.sha)
        pieces.append(match.group("sep"))
        pieces.append(target.label)
        cursor = match.end("label")
        changes.append(
            TemplatePinChange(
                path=path,
                action=action,
                old_version=label,
                new_version=target.label,
                source=target.origin,
            )
        )

    pieces.append(content[cursor:])
    return "".join(pieces), changes, skips


def refresh_templates(
    templates: Mapping[str, str],
    sources: Mapping[str, str],
    *,
    allow_major: bool = False,
) -> tuple[dict[str, str], list[TemplatePinChange], list[TemplatePinSkip], list[str]]:
    """Every template refreshed from `sources`: (contents, changes, skips, conflicts)."""
    pins, conflicts = collect_source_pins(sources)
    out: dict[str, str] = {}
    changes: list[TemplatePinChange] = []
    skips: list[TemplatePinSkip] = []
    for name in sorted(templates):
        content, changed, skipped = refresh_template(
            name, templates[name], pins, allow_major=allow_major
        )
        out[name] = content
        changes.extend(changed)
        skips.extend(skipped)
    return out, changes, skips, conflicts
