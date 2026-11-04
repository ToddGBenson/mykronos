"""Before a fix is proposed for merge: did a scan of its branch clear the finding?
(TheHub #60746)

`verification.py` asks this after the merge, of the merge commit. That is the
efficacy question, and it is asked too late to stop a reviewer merging a fix
that does not work. This module asks it of the pull request's own head commit,
while it is still a draft, and records the answer on the pull request itself:
a section in the body and a label.

**The rescan is the pull request's own scan.** Every Actions lane runs on
`pull_request`, so opening the draft scans its head commit with the same tool
that produced the finding; nothing here dispatches anything. A repository
whose lanes do not scan pull requests produces no run for the head commit, and
after `BRANCH_RESCAN_DEADLINE` the pull request is labelled as not rescanned
rather than left looking verified.

**The verdict reads the run, keyed on rule and file, not on finding id.** A
finding's id includes its line, and a fix can move lines, so a finding still
present under a new id must still count as present. So "still reported" is:
some finding with this rule in this file (in this package, for a container
finding) was last seen by the branch's run. And "gone" is claimed only when no
such finding has been seen by any *later* run either, because a later scan of
the default branch, which still carries the finding, overwrites the
last-seen pointer and would otherwise make every fix look like it worked.
That case is `inconclusive`, said as such.

**Nothing here merges, marks ready, or approves.** A fix that cleared its
finding stays a draft for a person to decide; one that did not is labelled
`LABEL_STILL_OPEN` and its body says not to merge it. The GitHub client has no
merge operation at all (spec 08 §3).
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from mykronos.github.client import GitHubClient, GitHubError, PullRequest
from mykronos.lake.catalog import Catalog
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

#: How long to wait for a scan of the head commit before saying there was none.
BRANCH_RESCAN_DEADLINE = timedelta(hours=36)

VERIFIED_FIXED = "verified_fixed"
STILL_OPEN = "still_open"
INCONCLUSIVE = "inconclusive"
NOT_SCANNED = "not_scanned"
WAITING = "waiting"

LABEL_VERIFIED = "mykronos: rescan cleared the finding"
LABEL_STILL_OPEN = "mykronos: fix did not remove the finding"
LABEL_UNVERIFIED = "mykronos: rescan inconclusive"

LABELS: dict[str, str] = {
    VERIFIED_FIXED: LABEL_VERIFIED,
    STILL_OPEN: LABEL_STILL_OPEN,
    INCONCLUSIVE: LABEL_UNVERIFIED,
    NOT_SCANNED: LABEL_UNVERIFIED,
}

#: Marks the recorded section, so the verdict is written once per pull request.
MARKER = "<!-- mykronos:branch-rescan -->"


@dataclass
class FindingVerdict:
    finding_id: str
    outcome: str
    detail: str


@dataclass
class BranchVerdict:
    """One pull request's rescan, across every finding it claims to fix."""

    outcome: str
    head_sha: str
    scan_run_id: str | None = None
    findings: list[FindingVerdict] = field(default_factory=list)

    @property
    def proposed_for_merge(self) -> bool:
        return self.outcome == VERIFIED_FIXED


@dataclass
class BranchRescanResult:
    recorded: int = 0
    verified_fixed: int = 0
    still_open: int = 0
    inconclusive: int = 0
    not_scanned: int = 0
    waiting: int = 0
    errors: list[str] = field(default_factory=list)


def _finding(catalog: Catalog, finding_id: str) -> dict[str, Any] | None:
    columns = ("finding_id", "asset_id", "capability", "rule_id", "file_path", "package_name")
    rows = catalog.query(
        f"SELECT {', '.join(columns)} FROM findings WHERE finding_id = ? LIMIT 1",
        [finding_id],
    )
    return dict(zip(columns, rows[0], strict=True)) if rows else None


def _same_finding_clause(finding: Mapping[str, Any]) -> tuple[str, list[Any]]:
    """SQL matching `finding` by what survives a line move: rule and place."""
    if finding.get("capability") == "containers":
        return (
            "f.rule_id = ? AND coalesce(f.package_name, '') = ?",
            [finding.get("rule_id"), finding.get("package_name") or ""],
        )
    return (
        "f.rule_id = ? AND coalesce(f.file_path, '') = ?",
        [finding.get("rule_id"), finding.get("file_path") or ""],
    )


def finding_verdict(
    catalog: Catalog, finding: Mapping[str, Any], run_id: str, run_started_at: Any
) -> FindingVerdict:
    """Whether the branch's successful run `run_id` still reports `finding`."""
    clause, params = _same_finding_clause(finding)
    repo = finding.get("asset_id")
    reported = catalog.query(
        f"SELECT count(*) FROM findings f WHERE f.asset_id = ? "
        f"AND f.last_seen_scan_run_id = ? AND {clause}",
        [repo, run_id, *params],
    )
    finding_id = str(finding["finding_id"])
    if reported and int(reported[0][0]) > 0:
        return FindingVerdict(
            finding_id,
            STILL_OPEN,
            f"`{finding.get('rule_id')}` is still reported in "
            f"`{finding.get('file_path') or finding.get('package_name')}` by the scan "
            "of this branch.",
        )
    later = catalog.query(
        f"SELECT count(*) FROM findings f JOIN scan_runs r "
        f"ON r.scan_run_id = f.last_seen_scan_run_id "
        f"WHERE f.asset_id = ? AND r.started_at > ? AND {clause}",
        [repo, run_started_at, *params],
    )
    if later and int(later[0][0]) > 0:
        return FindingVerdict(
            finding_id,
            INCONCLUSIVE,
            "A later scan of another commit has re-reported this finding since the "
            "branch was scanned, so the branch scan's result for it can no longer "
            "be read.",
        )
    return FindingVerdict(
        finding_id,
        VERIFIED_FIXED,
        f"`{finding.get('rule_id')}` is no longer reported by the scan of this branch.",
    )


def branch_verdict(
    catalog: Catalog,
    *,
    repo_full_name: str,
    finding_ids: Iterable[str],
    head_sha: str,
    opened_at: datetime | None,
    now: datetime | None = None,
) -> BranchVerdict:
    """The rescan verdict for one pull request's head commit."""
    moment = now or utcnow()
    findings = [f for f in (_finding(catalog, fid) for fid in sorted(set(finding_ids))) if f]
    if not findings or not head_sha:
        return BranchVerdict(
            INCONCLUSIVE,
            head_sha,
            findings=[
                FindingVerdict(
                    fid,
                    INCONCLUSIVE,
                    "The finding is no longer in the lake, or the pull request has no head commit.",
                )
                for fid in sorted(set(finding_ids))
            ],
        )
    capabilities = sorted({str(f["capability"]) for f in findings})
    runs = catalog.query(
        f"SELECT capability, scan_run_id, scan_status, started_at FROM scan_runs "
        f"WHERE repo_full_name = ? AND commit_sha = ? "
        f"AND capability IN ({', '.join('?' * len(capabilities))}) "
        "ORDER BY started_at DESC",
        [repo_full_name, head_sha, *capabilities],
    )
    newest: dict[str, tuple[str, str, Any]] = {}
    for capability, scan_run_id, scan_status, started_at in runs:
        newest.setdefault(str(capability), (str(scan_run_id), str(scan_status), started_at))

    verdicts: list[FindingVerdict] = []
    run_ids: list[str] = []
    for finding in findings:
        found = newest.get(str(finding["capability"]))
        if found is None:
            waited = opened_at is not None and moment - opened_at >= BRANCH_RESCAN_DEADLINE
            verdicts.append(
                FindingVerdict(
                    str(finding["finding_id"]),
                    NOT_SCANNED if waited else WAITING,
                    f"No `{finding['capability']}` scan of `{head_sha[:12]}` arrived within "
                    f"{int(BRANCH_RESCAN_DEADLINE.total_seconds() // 3600)} hours of the "
                    "pull request opening.",
                )
            )
            continue
        run_id, scan_status, started_at = found
        run_ids.append(run_id)
        if scan_status != "success":
            verdicts.append(
                FindingVerdict(
                    str(finding["finding_id"]),
                    INCONCLUSIVE,
                    f"The `{finding['capability']}` scan of this branch ended "
                    f"`{scan_status}`; a scan that did not complete proves nothing "
                    "by what it did not report.",
                )
            )
            continue
        verdicts.append(finding_verdict(catalog, finding, run_id, started_at))

    outcomes = {v.outcome for v in verdicts}
    if STILL_OPEN in outcomes:
        outcome = STILL_OPEN
    elif WAITING in outcomes:
        outcome = WAITING
    elif outcomes == {VERIFIED_FIXED}:
        outcome = VERIFIED_FIXED
    elif NOT_SCANNED in outcomes and outcomes <= {NOT_SCANNED, VERIFIED_FIXED}:
        outcome = NOT_SCANNED
    else:
        outcome = INCONCLUSIVE
    return BranchVerdict(
        outcome, head_sha, scan_run_id=", ".join(sorted(set(run_ids))) or None, findings=verdicts
    )


_HEADLINES = {
    VERIFIED_FIXED: "The rescan of this branch no longer reports the finding.",
    STILL_OPEN: (
        "**Do not merge.** The rescan of this branch still reports the finding this "
        "pull request was opened to fix, so the fix does not remove it. Patchwork "
        "does not propose it for merge."
    ),
    INCONCLUSIVE: (
        "**Not verified.** The rescan of this branch could not show whether the "
        "finding is gone, so Patchwork does not propose it for merge."
    ),
    NOT_SCANNED: (
        "**Not verified.** No scan of this branch's head commit arrived, so "
        "Patchwork does not propose it for merge."
    ),
}


def render_section(verdict: BranchVerdict) -> str:
    """The body section recording the verdict."""
    lines = [
        MARKER,
        "### Rescan of this branch",
        "",
        _HEADLINES[verdict.outcome],
        "",
        f"- Commit: `{verdict.head_sha[:12]}`",
        f"- Scan run: `{verdict.scan_run_id}`" if verdict.scan_run_id else "- Scan run: none",
        *[f"- `{v.finding_id[:12]}`: {v.detail}" for v in verdict.findings],
        "",
        "Merging stays with a person. Patchwork never merges, marks ready or "
        "approves a pull request.",
    ]
    return "\n".join(lines)


async def record(
    github: GitHubClient, repo_full_name: str, pr: PullRequest, verdict: BranchVerdict
) -> None:
    """Write the verdict on the pull request: a body section and a label."""
    body = (pr.body or "").rstrip()
    new_body = f"{body}\n\n{render_section(verdict)}\n" if body else render_section(verdict)
    await github.update_pull_request(repo_full_name, pr.number, title=pr.title, body=new_body)
    await github.add_pull_request_labels(repo_full_name, pr.number, [LABELS[verdict.outcome]])


def open_fix_pull_requests(catalog: Catalog) -> dict[tuple[str, int], list[str]]:
    """(repo, PR number) -> the findings that PR was opened to fix."""
    if not catalog.all_files("remediation_events"):
        return {}
    rows = catalog.query(
        "SELECT repo_full_name, fix_pr_number, finding_id FROM remediation_events "
        "WHERE pipeline_stage_reached = 'pr_opened' AND pr_status = 'draft_open' "
        "AND fix_pr_number IS NOT NULL"
    )
    grouped: dict[tuple[str, int], list[str]] = {}
    for repo, number, finding_id in rows:
        grouped.setdefault((str(repo), int(number)), []).append(str(finding_id))
    return grouped


async def rescan_open_fixes(
    catalog: Catalog,
    clients: Mapping[str, GitHubClient],
    *,
    now: datetime | None = None,
    result: BranchRescanResult | None = None,
) -> BranchRescanResult:
    """Record a rescan verdict on every open fix pull request that has one.

    `clients` maps a repository to its installation client; a repository with
    none is skipped. A pull request already carrying `MARKER` is not
    re-recorded, and one with no verdict yet (`waiting`) is left for the next
    pass.
    """
    result = result or BranchRescanResult()
    for (repo, number), finding_ids in sorted(open_fix_pull_requests(catalog).items()):
        github = clients.get(repo)
        if github is None:
            continue
        try:
            pr = await github.get_pull_request(repo, number)
        except GitHubError as exc:
            result.errors.append(f"{repo}#{number}: {exc}")
            continue
        if pr is None or pr.state != "open" or pr.merged or MARKER in (pr.body or ""):
            continue
        verdict = branch_verdict(
            catalog,
            repo_full_name=repo,
            finding_ids=finding_ids,
            head_sha=pr.head_sha,
            opened_at=pr.created_at,
            now=now,
        )
        if verdict.outcome == WAITING:
            result.waiting += 1
            continue
        try:
            await record(github, repo, pr, verdict)
        except GitHubError as exc:
            result.errors.append(f"{repo}#{number}: {exc}")
            continue
        result.recorded += 1
        setattr(result, verdict.outcome, getattr(result, verdict.outcome) + 1)
    if result.recorded:
        logger.info(
            "Fix branch rescans: %d recorded (%d cleared, %d still open, %d inconclusive, "
            "%d not scanned), %d waiting",
            result.recorded,
            result.verified_fixed,
            result.still_open,
            result.inconclusive,
            result.not_scanned,
            result.waiting,
        )
    return result
