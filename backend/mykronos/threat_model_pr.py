"""Threat-model drafts and drift land as pull requests (TheHub #60900, epic
#60881).

Decided with the epic: the repository's `.sdlc/threat-model.yaml` stays the
source of truth, and MyKronos never writes it directly. What MyKronos drafts
(`threat_model_draft`) arrives as a pull request per repository, carrying the
diff and the evidence behind every element, and a person merges it or does
not.

**Two cases, one branch.**

- **No file yet** - the whole draft is proposed as the new file.
- **A valid file** - the draft is compared with it, and every drafted element
  the declared model does not already cover is *drift*: code or exposure that
  moved on while the file did not. Drift is proposed as additions to the
  existing file, inserted into its sections as text so the comments a person
  wrote stay where they were. Nothing declared is changed or removed: a
  pull request that rewrote a person's rows from evidence would be the
  register overruling its own source of truth.

An **invalid** or **unreadable** file proposes nothing. A draft built on a
typo would be proposing changes to a file nobody can read, and "could not
look" is never evidence of absence (B-058).

**Covered** is decided by the same matcher placement uses (`surface_match`):
a drafted hostname is covered when a declared surface's selectors would place
a finding at that host in it, an image when a declared surface names that
image, a path when a declared glob matches it, a port when a declared address
names that port. A drafted control is covered by a declared control of the
same kind on the surface that covers what the drafted one applies to (or a
declared control of that kind with no `applies_to`).

**One open pull request per repository.** A later run with new drift commits
to the open branch and updates its description rather than opening a second;
a run whose proposal is byte-identical to what the open branch already holds
changes nothing. A branch a person has edited is never overwritten: the
description records the sha256 of the file MyKronos last committed, and a
branch file that no longer hashes to it (or a description without the
record) is `kept` as the reviewer left it. The description is a reviewer's
too: the record also carries the hash of the description MyKronos wrote, and
a description a person edited keeps their text on a later update, with only
the record replaced and a dated line appended. (There is a window between
the hash check and the commit in which a reviewer's push could be
overwritten; for a weekly, off-by-default job that is accepted rather than
locked against.)

**Only a private repository is written to.** A threat model drafted from
MyKronos evidence names routes, hostnames, published ports, controls and open
weaknesses: an exposure map. GitHub's own `visibility` is read before
anything is written, and a repository that is public, internal, or whose
visibility could not be read or was not reported is `refused`: no branch, no
file, no description. The draft stays readable inside MyKronos
(`GET /repos/{id}/threat-model/draft`). A repository that turned public
while a proposal was open is refused too, and the refusal names that pull
request so a person can close it; the sweep audits every refusal.

**Relation to TheHub's DEV-B `Threat-Model-MD:` trailer.** They are separate
gates over different artifacts. The trailer is TheHub's own deploy check: a
commit touching threat-relevant files must cite a hand-written threat-model
markdown, or production deploy refuses. This module proposes changes to the
machine-readable `.sdlc/threat-model.yaml` that MyKronos's risk engine reads;
it neither writes nor satisfies the trailer, and a merged proposal is not a
`Threat-Model-MD:` citation.
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from types import SimpleNamespace
from typing import Any, Literal

from sqlalchemy import select

from mykronos import surface_match
from mykronos import threat_model_draft as tmd
from mykronos.github import GitHubClient
from mykronos.github.client import FileChange, GitHubError, PullRequest
from mykronos.logsafe import scrub
from mykronos.schemas import utcnow
from mykronos.threat_model_manifest import MANIFEST_PATH, ThreatModelManifest, parse_manifest

logger = logging.getLogger(__name__)

#: Every branch this module opens starts with this, which is how the open
#: pull request is found again.
BRANCH_PREFIX = "mykronos/threat-model-"

#: Who the job acts as in the audit log.
DRAFT_ACTOR = "system:threat-model-draft"

ProposalState = Literal[
    "opened",
    "updated",
    "unchanged",
    "kept",
    "no_drift",
    "invalid",
    "unreadable",
    "refused",
    "failed",
]

#: Recorded in the description: the hash of the file MyKronos committed, so
#: a later run can tell its own proposal from a reviewer's edit of it.
#: `body:` is the hash of the description text MyKronos wrote above it; a
#: record without one marks a description a person has edited.
_PROPOSAL_MARK = "<!-- mykronos-threat-model-proposal sha256:{}{} -->"
_PROPOSAL_MARK_RE = re.compile(
    r"<!-- mykronos-threat-model-proposal sha256:([0-9a-f]{64})(?: body:([0-9a-f]{64}))? -->"
)

_TOP_KEY = re.compile(r"^([a-z_]+):")


# --------------------------------------------------------------------------
# Coverage
# --------------------------------------------------------------------------


def _declared_surfaces(manifest: ThreatModelManifest) -> list[SimpleNamespace]:
    return [
        SimpleNamespace(
            id=item.id, kind=kind, name=item.name, selectors=item.selectors.model_dump()
        )
        for kind, item in manifest.surfaces()
    ]


def _probes(selectors: dict[str, list[str]]) -> list[tuple[str, dict[str, Any]]]:
    """Each selector value as the finding `surface_match` would place."""
    out: list[tuple[str, dict[str, Any]]] = []
    for host in selectors.get("hostnames") or []:
        out.append(
            ("dast", {"raw_finding_json": {"instance": {"uri": f"https://{host}/"}}})
        )
    for image in selectors.get("images") or []:
        out.append(("containers", {"raw_finding_json": {"image": image}}))
    for path in selectors.get("paths") or []:
        out.append(("iac", {"file_path": path}))
    return out


def _covering(
    element: tmd.DraftElement, declared: list[SimpleNamespace]
) -> SimpleNamespace | None:
    """The declared surface that covers every selector of `element`, or None.

    A declared surface with the same id covers it outright: a person adopted
    the drafted element and may have narrowed its selectors since.
    """
    same = next((s for s in declared if s.id == element.id), None)
    if same is not None:
        return same
    selectors = element.selectors()
    probes = _probes(selectors)
    ports = [a.rpartition(":")[2] for a in selectors.get("addresses") or []]
    if not probes and not ports:
        return None
    candidates: list[SimpleNamespace] | None = None
    for capability, probe in probes:
        hits = {m.surface.id for m in surface_match.matches(probe, declared, capability=capability)}
        here = [s for s in declared if s.id in hits]
        candidates = here if candidates is None else [s for s in candidates if s.id in hits]
        if not candidates:
            return None
    for port in ports:
        here = [
            s
            for s in declared
            if any(a.rpartition(":")[2] in (port, "*") for a in s.selectors.get("addresses") or [])
        ]
        ids = {s.id for s in here}
        candidates = here if candidates is None else [s for s in candidates if s.id in ids]
        if not candidates:
            return None
    return candidates[0] if candidates else None


@dataclass
class Drift:
    """What the draft has that the declared file does not."""

    #: Drafted elements to add, in draft order, with any `applies_to`
    #: rewritten to the declared surface that covers the drafted one.
    additions: list[tmd.DraftElement] = field(default_factory=list)
    #: Drafted element id -> the declared id that already covers it.
    covered: dict[str, str] = field(default_factory=dict)

    @property
    def empty(self) -> bool:
        return not self.additions


def drift(declared: ThreatModelManifest, draft: tmd.Draft) -> Drift:
    """Compare a draft with a valid declared file."""
    surfaces = _declared_surfaces(declared)
    declared_ids = {s.id for s in surfaces} | {c.id for c in declared.controls}
    result = Drift()
    for element in draft.elements:
        if element.section == "controls":
            continue
        cover = _covering(element, surfaces)
        if cover is not None:
            result.covered[element.id] = cover.id
        else:
            result.additions.append(_fresh_id(element, declared_ids))
    added_ids = {e.body["id"] for e in result.additions}
    renamed = {
        original.id: added.body["id"]
        for original, added in zip(
            [e for e in draft.elements if e.section != "controls" and e.id not in result.covered],
            result.additions,
            strict=True,
        )
    }
    for element in draft.section("controls"):
        target = element.body.get("applies_to")
        resolved = result.covered.get(target or "", renamed.get(target or "", target))
        kind = element.body["kind"]
        if any(
            c.kind == kind and (c.applies_to is None or c.applies_to == resolved)
            for c in declared.controls
        ):
            result.covered[element.id] = next(
                c.id
                for c in declared.controls
                if c.kind == kind and (c.applies_to is None or c.applies_to == resolved)
            )
            continue
        addition = _fresh_id(element, declared_ids | added_ids)
        if resolved:
            addition.body["applies_to"] = resolved
        else:
            addition.body.pop("applies_to", None)
        added_ids.add(addition.body["id"])
        result.additions.append(addition)
    return result


def _fresh_id(element: tmd.DraftElement, taken: set[str]) -> tmd.DraftElement:
    body = dict(element.body)
    key, n = body["id"], 2
    while body["id"] in taken:
        body["id"] = f"{key}-{n}"
        n += 1
    return tmd.DraftElement(element.section, body, list(element.evidence))


# --------------------------------------------------------------------------
# Text
# --------------------------------------------------------------------------


def merge_text(declared_text: str, additions: list[tmd.DraftElement], draft: tmd.Draft) -> str:
    """`declared_text` with `additions` inserted at the end of their sections.

    Inserted as text so a person's comments and ordering survive; a section
    the file does not have is appended, and `key: []` becomes a list. The
    caller parses the result and proposes nothing if it is not valid.
    """
    lines = declared_text.rstrip("\n").split("\n")
    for section in tmd.SECTIONS:
        block = [tmd.render_element(e, draft) for e in additions if e.section == section]
        if not block:
            continue
        text = "\n\n".join(block).split("\n")
        start = next(
            (i for i, line in enumerate(lines) if _TOP_KEY.match(line) and
             line.split(":", 1)[0] == section),
            None,
        )
        if start is None:
            lines += ["", f"{section}:", *text]
            continue
        if lines[start].split(":", 1)[1].strip() in ("[]", "[ ]"):
            lines[start] = f"{section}:"
            lines[start + 1 : start + 1] = text
            continue
        end = next(
            (i for i in range(start + 1, len(lines)) if _TOP_KEY.match(lines[i])),
            len(lines),
        )
        # Before the blank lines and comments that lead into the next section.
        while end > start + 1 and (
            not lines[end - 1].strip() or lines[end - 1].lstrip().startswith("#")
            and not lines[end - 1].startswith("  ")
        ):
            end -= 1
        lines[end:end] = ["", *text]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# The pull request
# --------------------------------------------------------------------------


@dataclass
class Proposal:
    repo_full_name: str
    state: ProposalState
    reason: str = ""
    pull_request: PullRequest | None = None
    added: dict[str, int] = field(default_factory=dict)
    covered: int = 0


def _count(elements: list[tmd.DraftElement]) -> dict[str, int]:
    return {s: sum(1 for e in elements if e.section == s) for s in tmd.SECTIONS}


def _md(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _code(text: str) -> str:
    """`text` as inline code, so an `@name` cannot mention a person and a
    `#123` cannot cross-link an issue from the description."""
    flat = " ".join(text.replace("`", "'").split())
    return "`" + _md(flat) + "`" if flat else ""


def pr_body(
    draft: tmd.Draft, elements: list[tmd.DraftElement], *, kind: Literal["draft", "drift"]
) -> str:
    counts = _count(elements)
    summary = ", ".join(f"{n} {s.replace('_', ' ')}" for s, n in counts.items() if n)
    if kind == "draft":
        lead = (
            f"This repository has no `{MANIFEST_PATH}`. MyKronos drafted one from the "
            "evidence it already holds about it: " + (summary or "nothing citable") + "."
        )
    else:
        lead = (
            f"`{MANIFEST_PATH}` no longer covers everything MyKronos observes. This "
            f"pull request adds {summary}. Nothing already declared is changed or removed."
        )
    out = [
        lead,
        "",
        "Every element cites its evidence: the `# evidence` comments above it in the "
        "file, and the table below. `evidence_ref` is the first record that is a path "
        "in this repository or an https URL. Read each one, correct what is wrong, "
        "delete what does not belong, then merge; the threat-model-sync job loads the "
        "merged file (spec 28 §8).",
        "",
        "| Element | Section | Evidence |",
        "|---|---|---|",
    ]
    for element in elements:
        evidence = "<br>".join(
            _code(
                f"{e.source}: {e.detail}"
                + (f" ({e.ref})" if e.ref else "")
                + (f", {e.observed_at:%Y-%m-%d}" if e.observed_at else "")
            )
            for e in element.evidence[:6]
        )
        more = len(element.evidence) - 6
        if more > 0:
            evidence += f"<br>and {more} more"
        out.append(f"| `{element.body['id']}` | {element.section} | {evidence} |")
    placed = [t for t in draft.threats if t.element_id is not None]
    if draft.threats:
        out += [
            "",
            f"Open findings mapped to STRIDE: {len(draft.threats)} weakness group(s), "
            f"{len(placed)} placed in a drafted element (shown as `# threat` comments).",
        ]
    if draft.uncited:
        out += [
            "",
            f"{len(draft.uncited)} candidate(s) were seen but not drafted, because none "
            "of their evidence is a repository path or an https URL: "
            + "; ".join(_code(label) for label, _ in draft.uncited[:10])
            + ("; ..." if len(draft.uncited) > 10 else "")
            + ".",
        ]
    if draft.unread:
        out += [
            "",
            "Not read while drafting, so absent here rather than proven absent: "
            + ", ".join(draft.unread)
            + ".",
        ]
    out += ["", "Opened by MyKronos (TheHub #60899, #60900)."]
    return "\n".join(out)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _description_text(body: str) -> str:
    """A description as hashed: line endings normalised (GitHub's editor
    writes CRLF) and trailing space dropped."""
    return body.replace("\r\n", "\n").rstrip()


def _mark(content: str, description: str | None) -> str:
    """The record of the committed file, and of the description while it is
    still the one MyKronos wrote."""
    return _PROPOSAL_MARK.format(
        _sha256(content), f" body:{_sha256(description)}" if description is not None else ""
    )


async def repository_is_private(github: GitHubClient, repo_full_name: str) -> bool:
    """True only when GitHub says the repository is private.

    `public` and `internal` (readable by a whole enterprise) are not private,
    and neither is an answer that could not be read or did not say: "could
    not look" is never evidence (B-058), and here the cost of guessing wrong
    is publishing an exposure map.
    """
    try:
        info = await github.get_repo(repo_full_name)
    except Exception as exc:  # noqa: BLE001 - GitHubError, httpx errors alike
        logger.warning(
            "Threat-model draft: visibility of %s unreadable: %s",
            scrub(repo_full_name),
            scrub(str(exc)),
        )
        return False
    visibility = info.get("visibility")
    private = info.get("private")
    if visibility is not None:
        return visibility == "private" and private is not False
    return private is True


async def propose(
    github: GitHubClient,
    repo_full_name: str,
    default_branch: str,
    draft: tmd.Draft,
    *,
    now: datetime | None = None,
) -> Proposal:
    """Open or update the repository's threat-model pull request, or say why
    nothing was proposed."""
    moment = now or utcnow()
    # Before anything else, and before any body or file is built for
    # writing: threat and evidence detail goes only to a private repository.
    if not await repository_is_private(github, repo_full_name):
        reason = (
            "The repository is not known to be private (public, internal, or its "
            "visibility could not be read), so no threat-model detail is written to "
            "it. The draft stays readable in MyKronos."
        )
        # A read, never a write: a proposal opened while the repository was
        # private is now readable by whoever can read the repository.
        try:
            open_pr = await github.find_open_pull_request(repo_full_name, BRANCH_PREFIX)
        except Exception:  # noqa: BLE001 - the refusal stands either way
            open_pr = None
        if open_pr is not None:
            reason += (
                f" An open MyKronos threat-model proposal (#{open_pr.number}) is on it "
                "and is not updated; review whether to close it."
            )
        return Proposal(repo_full_name, "refused", reason, pull_request=open_pr)
    try:
        current = await github.get_file(repo_full_name, MANIFEST_PATH, default_branch)
    except Exception as exc:  # noqa: BLE001 - GitHubError, httpx errors alike
        logger.warning(
            "Threat-model draft: %s unreadable: %s", scrub(repo_full_name), scrub(str(exc))
        )
        return Proposal(repo_full_name, "unreadable", f"{MANIFEST_PATH} could not be read.")
    state = parse_manifest(current)
    if state.state == "invalid":
        return Proposal(
            repo_full_name,
            "invalid",
            f"{MANIFEST_PATH} is invalid ({state.error}); fix it before anything is proposed.",
        )

    kind: Literal["draft", "drift"]
    if state.state == "absent":
        elements = list(draft.elements)
        if not elements:
            return Proposal(repo_full_name, "no_drift", "Nothing citable to draft.")
        content, kind, covered = draft.render(), "draft", 0
    else:
        assert state.manifest is not None and current is not None
        found = drift(state.manifest, draft)
        if found.empty:
            return Proposal(
                repo_full_name,
                "no_drift",
                "The declared threat model covers everything drafted.",
                covered=len(found.covered),
            )
        elements, kind, covered = found.additions, "drift", len(found.covered)
        content = merge_text(current, elements, draft)

    check = parse_manifest(content)
    if check.state != "valid":
        return Proposal(
            repo_full_name,
            "failed",
            f"The proposed file would not parse ({check.error}); nothing was opened.",
        )

    title = (
        f"MyKronos: draft {MANIFEST_PATH} from evidence"
        if kind == "draft"
        else f"MyKronos: threat-model drift - {len(elements)} addition(s)"
    )
    description = _description_text(pr_body(draft, elements, kind=kind))
    body = "\n\n".join([description, _mark(content, description)])
    message = f"{title}\n\nDrafted from MyKronos evidence (TheHub #60899, #60900)."
    try:
        existing = await github.find_open_pull_request(repo_full_name, BRANCH_PREFIX)
        if existing is not None:
            held = await github.get_file(repo_full_name, MANIFEST_PATH, existing.head_branch)
            if held == content:
                return Proposal(
                    repo_full_name,
                    "unchanged",
                    "The open pull request already proposes this.",
                    pull_request=existing,
                    added=_count(elements),
                    covered=covered,
                )
            live = await github.get_pull_request(repo_full_name, existing.number)
            mark = _PROPOSAL_MARK_RE.search(live.body if live is not None else "")
            if held is None or mark is None or mark.group(1) != _sha256(held):
                # Not what MyKronos last committed: a person edited the
                # branch (or the description lost its record). Theirs stands.
                return Proposal(
                    repo_full_name,
                    "kept",
                    "The open pull request's branch was edited after MyKronos proposed "
                    "it; the edits were kept and nothing was committed.",
                    pull_request=existing,
                    added=_count(elements),
                    covered=covered,
                )
            assert live is not None
            above = _description_text(live.body[: mark.start()])
            if mark.group(2) is None or mark.group(2) != _sha256(above):
                # A person edited the description: their text stands, the
                # record is replaced, and a dated line says what changed.
                counts = ", ".join(
                    f"{n} {s.replace('_', ' ')}" for s, n in _count(elements).items() if n
                )
                kept = _description_text(
                    above
                    + f"\n\nMyKronos updated the proposed file on {moment:%Y-%m-%d}: it now "
                    f"adds {counts or 'nothing new'}. The description was edited, so it "
                    "was kept; each element's evidence is in its `# evidence` comments."
                )
                body = "\n\n".join([kept, _mark(content, None)])
            await github.commit_files(
                repo_full_name,
                existing.head_branch,
                message,
                [FileChange(path=MANIFEST_PATH, content=content)],
            )
            pull_request = await github.update_pull_request(
                repo_full_name, existing.number, title=title, body=body
            )
            return Proposal(
                repo_full_name, "updated", pull_request=pull_request,
                added=_count(elements), covered=covered,
            )
        branch = f"{BRANCH_PREFIX}{moment:%Y%m%dT%H%M%S}"
        await github.create_branch(repo_full_name, branch, default_branch)
        await github.commit_files(
            repo_full_name, branch, message, [FileChange(path=MANIFEST_PATH, content=content)]
        )
        pull_request = await github.create_pull_request(
            repo_full_name, head=branch, base=default_branch, title=title, body=body
        )
    except GitHubError as exc:
        logger.warning(
            "Threat-model draft PR for %s failed: %s", scrub(repo_full_name), scrub(str(exc))
        )
        return Proposal(repo_full_name, "failed", scrub(str(exc)))
    return Proposal(
        repo_full_name, "opened", pull_request=pull_request,
        added=_count(elements), covered=covered,
    )


async def propose_for_repo(
    db: Any,
    catalog: Any,
    github: GitHubClient,
    repo_full_name: str,
    default_branch: str,
    *,
    actor: str = DRAFT_ACTOR,
) -> tuple[tmd.Draft, Proposal]:
    """Gather, draft, propose, and audit what was proposed."""
    bundle = await tmd.gather(db, catalog, github, repo_full_name, default_branch)
    built = tmd.draft(bundle, now=utcnow())
    proposal = await propose(github, repo_full_name, default_branch, built)
    if proposal.state in ("opened", "updated", "refused") or actor != DRAFT_ACTOR:
        with db.session() as session:
            db.audit(
                session,
                actor=actor,
                action="threat_model.propose",
                entity_type="repo",
                entity_id=repo_full_name,
                repo_full_name=repo_full_name,
                state=proposal.state,
                reason=proposal.reason,
                pull_request=proposal.pull_request.url if proposal.pull_request else None,
                **{f"added_{k}": v for k, v in proposal.added.items()},
            )
    return built, proposal


@dataclass
class SweepResult:
    proposals: list[Proposal] = field(default_factory=list)

    def summary(self) -> str:
        by: dict[str, int] = {}
        for p in self.proposals:
            by[p.state] = by.get(p.state, 0) + 1
        return ", ".join(f"{n} {s}" for s, n in sorted(by.items())) or "no repositories"


async def sweep(db: Any, catalog: Any, factory: Any) -> SweepResult:
    """Draft and propose for every active onboarded repository. One failing
    never ends the sweep; a failure is raised at the end so the job reads it."""
    from mykronos.db.models import RepoOnboarding

    result = SweepResult()
    with db.session() as session:
        repos = [
            (r.github_repo_full_name, r.default_branch or "main", r.github_installation_id)
            for r in session.scalars(
                select(RepoOnboarding).where(RepoOnboarding.status == "active")
            )
        ]
    for name, branch, installation in repos:
        if installation is None:
            result.proposals.append(
                Proposal(name, "unreadable", "No GitHub installation to propose with.")
            )
            continue
        try:
            _, proposal = await propose_for_repo(
                db, catalog, factory.for_installation(installation), name, branch
            )
        except Exception as exc:  # noqa: BLE001 - one repository never ends the sweep
            logger.warning("Threat-model draft for %s failed: %s", scrub(name), scrub(str(exc)))
            proposal = Proposal(name, "failed", scrub(str(exc)))
        result.proposals.append(proposal)
    failed = [p.repo_full_name for p in result.proposals if p.state == "failed"]
    if failed:
        raise RuntimeError(f"Threat-model draft failed for: {', '.join(failed)}")
    return result
