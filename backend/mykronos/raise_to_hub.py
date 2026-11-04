"""Raise a Hub incident or story from where the problem is seen (TheHub #60911).

Using Mykronos as the one tool, a person could not report anything from it.
`/api/dashboard/incident` is a CVE lookup, not an incident record, and every
bug, incident and feature had to be filed by leaving Mykronos for the Hub
API. TheHub already has `/api/incidents` and `/api/dev/stories`, so Mykronos
hands off to them with the evidence attached, rather than growing its own
tracker.

Three places can raise:

- **a failing lane** (subject `<owner/repo>:<capability>`): its last three
  builds, each with sha, status, time, Actions run and raw output path;
- **a finding** (subject: its id): repository, rule, severity, location or
  package, and its newest scan's sha and raw output path;
- **a health dependency** (subject: its name): the self-check's answer.

The evidence is built here from MyKronos's own records, never taken from the
browser, so what TheHub receives is what MyKronos holds. The link back is
the audit entry (`hub_raised`, entity = the subject), which also records
who raised it, of which kind (spec 34 §1). A person and an agent
credential are told apart, and no separate table can disagree with the log.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from mykronos.jobs import self_check

Kind = Literal["lane", "finding", "health"]
KINDS: tuple[str, ...] = ("lane", "finding", "health")
ACTION = "hub_raised"
ROOM = "devops"
SEVERITY = "error"
SOURCE_CAPABILITY = "mykronos_raise"


class SubjectNotFoundError(LookupError):
    """Nothing MyKronos holds matches the subject."""


@dataclass
class Draft:
    kind: str
    subject: str
    title: str
    evidence: str
    repo_full_name: str | None = None


def _run_url(repo: str, run_id: Any) -> str | None:
    text = str(run_id or "").strip()
    return f"https://github.com/{repo}/actions/runs/{text}" if text.isdigit() else None


def _scans(catalog: Any, repo: str, capability: str, limit: int) -> list[tuple[Any, ...]]:
    rows: list[tuple[Any, ...]] = catalog.query(
        """
        SELECT commit_sha, scan_status, started_at, github_workflow_run_id, raw_output_ref, branch
        FROM scan_runs
        WHERE repo_full_name = ? AND capability = ?
        ORDER BY started_at DESC
        LIMIT ?
        """,
        [repo, capability, limit],
    )
    return rows


def _scan_lines(repo: str, rows: list[tuple[Any, ...]]) -> list[str]:
    lines = []
    for sha, state, at, run_id, raw, branch in rows:
        parts = [
            f"- {str(sha or '')[:12] or '(no sha)'}",
            str(state or "unknown"),
            str(at)[:19] if at else "time not recorded",
            f"on {branch}" if branch else "",
            _run_url(repo, run_id) or "no Actions run",
            f"raw output: {raw}" if raw else "raw output: not recorded",
        ]
        lines.append(" · ".join(p for p in parts if p))
    return lines


def lane_draft(catalog: Any, subject: str) -> Draft:
    repo, _, capability = subject.rpartition(":")
    if not repo or not capability:
        raise SubjectNotFoundError(f"A lane is named <owner/repo>:<capability>, not {subject!r}.")
    rows = _scans(catalog, repo, capability, 3)
    if not rows:
        raise SubjectNotFoundError(f"MyKronos holds no {capability} scan of {repo}.")
    evidence = "\n".join(
        [
            f"Lane: {capability} on {repo}",
            "Last builds, newest first:",
            *_scan_lines(repo, rows),
        ]
    )
    state = str(rows[0][1] or "unknown")
    return Draft("lane", subject, f"{repo}: {capability} lane is {state}", evidence, repo)


def finding_draft(queries: Any, catalog: Any, subject: str) -> Draft:
    finding = queries.finding(subject)
    if not finding:
        raise SubjectNotFoundError(f"No finding {subject!r}.")
    repo = str(finding.get("repo_full_name") or "")
    capability = str(finding.get("capability") or "")
    rule = str(finding.get("rule_id") or "")
    severity = str(finding.get("severity") or "")
    where = (
        f"{finding.get('file_path')}:{finding.get('line_start') or ''}".rstrip(":")
        if finding.get("file_path")
        else f"{finding.get('package_name')}@{finding.get('package_version')}"
        if finding.get("package_name")
        else "no location recorded"
    )
    rows = _scans(catalog, repo, capability, 1) if repo and capability else []
    evidence = "\n".join(
        [
            f"Finding: {subject}",
            f"Repository: {repo}",
            f"Rule: {rule} ({capability}), severity {severity}, status {finding.get('status')}",
            f"Title: {finding.get('title') or ''}",
            f"Location: {where}",
            f"MyKronos page: /repos/-/findings/{subject}",
            "Newest scan of this lane:",
            *(_scan_lines(repo, rows) or ["- none recorded"]),
        ]
    )
    title = f"{repo}: {severity} {rule} - {finding.get('title') or where}"
    return Draft("finding", subject, title[:255], evidence, repo or None)


async def health_draft(settings: Any, subject: str) -> Draft:
    from mykronos.logsafe import scrub

    for name, result in await self_check(settings):
        if name != subject:
            continue
        state = (
            "not configured"
            if result.configured is False
            else "reachable"
            if result.reachable
            else "unreachable"
        )
        evidence = "\n".join(
            [
                f"Dependency: {name}",
                f"State: {state}",
                f"HTTP status: {result.status_code}" if result.status_code else "HTTP status: none",
                f"Detail: {scrub(result.detail) or 'none'}",
                "Seen on: MyKronos Health (/platform-health)",
            ]
        )
        return Draft("health", subject, f"MyKronos health: {name} is {state}", evidence)
    raise SubjectNotFoundError(f"No health dependency named {subject!r}.")


def source_ref(kind: str, subject: str) -> str:
    return f"mykronos:{kind}:{subject}"[:255]


def _detail(draft: Draft, actor: str, actor_kind: str, note: str | None) -> str:
    head = f"Raised from MyKronos by {actor} ({actor_kind})."
    body = [head, ""]
    if note and note.strip():
        body += [note.strip(), ""]
    body.append(draft.evidence)
    return "\n".join(body)


def incident_payload(
    draft: Draft, *, title: str, actor: str, actor_kind: str, note: str | None
) -> dict[str, Any]:
    return {
        "room": ROOM,
        "severity": SEVERITY,
        "title": title[:255],
        "detail": _detail(draft, actor, actor_kind, note),
        "source_capability": SOURCE_CAPABILITY,
        "source_ref": source_ref(draft.kind, draft.subject),
        "tags": ["mykronos-raised", f"raised-from:{draft.kind}"],
        "context": {"kind": draft.kind, "subject": draft.subject, "raised_by": actor},
    }


def story_payload(
    draft: Draft, *, title: str, actor: str, actor_kind: str, note: str | None
) -> dict[str, Any]:
    tags = ["mykronos-raised", f"raised-from:{draft.kind}"]
    if draft.repo_full_name:
        tags.append(f"repo:{draft.repo_full_name}")
    return {
        "title": title[:255],
        "detail": _detail(draft, actor, actor_kind, note),
        "bucket": "backlog",
        "tags": tags,
        "source_kind": "mykronos",
        "source_ref": source_ref(draft.kind, draft.subject),
    }
