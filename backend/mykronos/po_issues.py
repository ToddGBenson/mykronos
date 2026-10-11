"""The Product Owner tab over a repository's GitHub Issues (spec 35 §9, B-072,
D-153).

A repository whose manifest says `backlog.source: github_issues` keeps its
work items in GitHub, not in TheHub. keel does: its stories are issues, its
gate is a Projects field or a `gate:G<n>` label, and `ready` marks what its own
sprint runner may take (keel `docs/15-tracking.md`, `docs/16-sprint-automation.md`).

This module reads those issues through the GitHub App client the platform
already has and shapes them like the tab's Hub stories, so the Backlog and
Sprint views render them unchanged. It is **read only**, and that is a rule,
not a gap: the tab's writes are TheHub's sprint pull and MyKronos's rank, and
neither means anything for an issue (TheHub ADR 0093 keeps the write rules).
keel's sprint is `./keel sprint`.

Where the gate comes from is reported, never assumed. With a project named and
readable, the project's gate field is the gate. Otherwise the gate labels are,
and the tab says why: a GitHub App can read a Projects board only with
`organization_projects`, which no user-owned board can grant.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Literal

from mykronos import product_owner as po
from mykronos.github.client import GitHubClient, GitHubError, IssueInfo, PermissionDeniedError
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

#: Closed issues are read back this far, so a sprint shows what it finished.
DONE_WINDOW_DAYS = 14

#: A Projects option such as `G1 ready`, or a bare `G1`.
_GATE_OPTION = re.compile(r"^\s*(G\d+)\b", re.IGNORECASE)

#: What a refused write says. One sentence, so every write route says the same.
WRITES_REFUSED = (
    "This repository's backlog is GitHub Issues, which this tab reads only. "
    "Pulling into the sprint, returning to the backlog and ranking are not "
    "done here: keel's sprint is `./keel sprint`, not this tab. The write "
    "rules stay in TheHub ADR 0093."
)


def is_issues(manifest: po.ProcessManifest | None) -> bool:
    return manifest is not None and isinstance(manifest.backlog, po.GithubIssuesBacklog)


GateSource = Literal["project", "labels"]


@dataclass
class IssuesRead:
    """The Backlog and Sprint, as story dicts in `StoryOut`'s shape."""

    ok: bool
    error: str | None = None
    gate_source: GateSource = "labels"
    #: Why the gate is not from the project, when one was named.
    gate_note: str | None = None
    backlog: list[dict[str, Any]] = field(default_factory=list)
    sprint: list[dict[str, Any]] = field(default_factory=list)


def gate_from_option(value: str | None, manifest: po.ProcessManifest) -> str | None:
    """`G1 ready` -> `G1`; an option named exactly as a gate id -> that id."""
    if not value:
        return None
    match = _GATE_OPTION.match(value)
    candidate = match.group(1).upper() if match else value.strip()
    ids = {gate.id.upper(): gate.id for gate in manifest.gates}
    return ids.get(candidate.upper())


def gate_from_labels(
    labels: tuple[str, ...], prefix: str, manifest: po.ProcessManifest
) -> str | None:
    """The furthest gate any `gate:` label names. Two gate labels on one issue
    is a labelling mistake; the further one is shown, not the first found."""
    order = [gate.id for gate in manifest.gates]
    found = [
        gate
        for label in labels
        if label.lower().startswith(prefix.lower())
        and (gate := gate_from_option(label[len(prefix) :], manifest)) is not None
    ]
    return max(found, key=order.index) if found else None


def size_from_labels(labels: tuple[str, ...], prefix: str) -> str | None:
    for label in labels:
        if label.lower().startswith(prefix.lower()) and label[len(prefix) :].strip():
            return label[len(prefix) :].strip()
    return None


def check_evidence(evidence: str | None, issue: dict[str, Any]) -> po.CheckStatus:
    """A checklist item against an issue. Only what the issue itself shows is
    passed or failed; acceptance criteria and a threat model live in the body
    and the gate-record comments, which this does not parse, so they are
    *unavailable* -- "could not see", never "has none"."""
    if evidence is None:
        return "manual"
    if evidence == "sized":
        return "passed" if issue.get("size") else "failed"
    if evidence == "sprint":
        return "passed" if issue.get("bucket") == "sprint" else "failed"
    if evidence == "detail_500":
        return "passed" if issue.get("detail_length", 0) >= 500 else "failed"
    return "unavailable"


def _check(gate: po.Gate | None, issue: dict[str, Any]) -> dict[str, Any]:
    items = [
        po.CheckItemResult(
            id=item.id,
            text=item.text,
            evidence=item.evidence,
            status=check_evidence(item.evidence, issue),
        )
        for item in (gate.checklist if gate is not None else [])
    ]
    result = po.GateCheck(
        gate_id=gate.id if gate is not None else None,
        gate_name=gate.name if gate is not None else None,
        items=items,
    )
    return {
        "gate_id": result.gate_id,
        "gate_name": result.gate_name,
        "passed": result.passed,
        "failed": result.failed,
        "manual": result.manual,
        "unavailable": result.unavailable,
        "total": result.total,
        "items": [
            {"id": i.id, "text": i.text, "evidence": i.evidence, "status": i.status}
            for i in result.items
        ],
    }


def to_story(
    issue: IssueInfo,
    manifest: po.ProcessManifest,
    backlog: po.GithubIssuesBacklog,
    project_gates: dict[int, str] | None,
) -> dict[str, Any]:
    """One issue in the tab's story shape. `id` stays the issue number, so the
    response type is the one TheHub stories use; `ref` is `#<number>`, which
    is what the tab shows.

    With a readable project, the project's gate field is the only gate: an
    issue not on the board, or with the field empty, has none. Mixing in a
    label for some issues would show two sources as one."""
    if project_gates is not None:
        gate_id = project_gates.get(issue.number)
    else:
        gate_id = gate_from_labels(issue.labels, backlog.gate_label_prefix, manifest)
    gate = next((g for g in manifest.gates if g.id == gate_id), None)
    wanted = {label.lower() for label in backlog.sprint_labels}
    in_sprint = bool(wanted & {label.lower() for label in issue.labels})
    closed = issue.state == "closed"
    if closed:
        spine = "done"
    elif gate is not None and gate.id in manifest.spine_map:
        spine = manifest.spine_map[gate.id]
    else:
        spine = "idea"
    story: dict[str, Any] = {
        "id": issue.number,
        "ref": f"#{issue.number}",
        # Rendered as a link, so only GitHub's own issue URL gets through.
        "url": issue.url if issue.url.startswith("https://github.com/") else None,
        "state": issue.state,
        "title": issue.title,
        "bucket": "sprint" if in_sprint else "backlog",
        # The repository's own gate id, or `none`. Never a TheHub gate name.
        "gate": gate_id or "none",
        "gate_name": gate.name if gate is not None else None,
        "spine": spine,
        "size": size_from_labels(issue.labels, backlog.size_label_prefix),
        "tags": list(issue.labels),
        # Not parsed from the body (see `check_evidence`), so not counted.
        "acceptance_criteria": 0,
        "detail_length": len(issue.body),
        "rank": None,
        "created_at": issue.created_at.isoformat() if issue.created_at else None,
        "updated_at": issue.updated_at.isoformat() if issue.updated_at else None,
    }
    story["check"] = _check(gate, story)
    return story


async def _project_gates(
    github: GitHubClient,
    repo_full_name: str,
    backlog: po.GithubIssuesBacklog,
    manifest: po.ProcessManifest,
) -> tuple[dict[int, str] | None, str | None]:
    """issue number -> gate id from the project, or None with the reason the
    labels are used instead."""
    if backlog.project is None:
        return None, None
    owner = repo_full_name.split("/", 1)[0]
    try:
        values = await github.project_field_values(owner, backlog.project, backlog.gate_field)
    except PermissionDeniedError as exc:
        return None, (
            f"Project #{backlog.project} could not be read by the GitHub App ({exc}). "
            f"Gates come from `{backlog.gate_label_prefix}G<n>` labels instead. A GitHub App "
            "reads a Projects board only with `organization_projects: read`, which a "
            "board owned by a user account cannot grant."
        )
    except GitHubError as exc:
        logger.warning("Project read failed for %s (HTTP %s)", repo_full_name, exc.status)
        return None, (
            f"Project #{backlog.project} could not be read (HTTP {exc.status}). Gates come "
            f"from `{backlog.gate_label_prefix}G<n>` labels instead."
        )
    gates = {
        number: gate
        for number, option in values.get(repo_full_name, {}).items()
        if (gate := gate_from_option(option, manifest)) is not None
    }
    return gates, None


def _order_key(manifest: po.ProcessManifest) -> Any:
    order = {gate.id: index for index, gate in enumerate(manifest.gates)}

    def key(story: dict[str, Any]) -> tuple[int, str, int]:
        # Furthest gate first, then oldest, as TheHub's unranked stories are.
        return (-order.get(story["gate"], -1), story["created_at"] or "", story["id"])

    return key


async def read_backlog(
    github: GitHubClient | None, repo_full_name: str, manifest: po.ProcessManifest
) -> IssuesRead:
    """The repository's open issues, and those closed in the last
    `DONE_WINDOW_DAYS`, split into Backlog and Sprint."""
    backlog = manifest.backlog
    assert isinstance(backlog, po.GithubIssuesBacklog)
    if github is None:
        return IssuesRead(ok=False, error="No GitHub installation to read the issues with.")
    try:
        open_issues = await github.list_issues(
            repo_full_name, state="open", labels=backlog.labels or None
        )
        closed = await github.list_issues(
            repo_full_name,
            state="closed",
            labels=backlog.labels or None,
            since=utcnow() - timedelta(days=DONE_WINDOW_DAYS),
        )
    except PermissionDeniedError as exc:
        return IssuesRead(ok=False, error=str(exc))
    except GitHubError as exc:
        logger.warning("Issue read failed for %s (HTTP %s)", repo_full_name, exc.status)
        return IssuesRead(
            ok=False, error=f"GitHub did not list the issues (HTTP {exc.status or 'unreachable'})."
        )

    project_gates, note = await _project_gates(github, repo_full_name, backlog, manifest)
    read = IssuesRead(
        ok=True,
        gate_source="project" if project_gates is not None else "labels",
        gate_note=note,
    )
    for issue in open_issues + closed:
        story = to_story(issue, manifest, backlog, project_gates)
        if story["bucket"] == "sprint":
            read.sprint.append(story)
        elif issue.state == "open":
            # A closed issue that was never in the sprint is history, not backlog.
            read.backlog.append(story)
    read.backlog.sort(key=_order_key(manifest))
    read.sprint.sort(key=lambda s: (po.SPINE.index(s["spine"]), s["id"]))
    return read
