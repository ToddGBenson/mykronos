"""Every pull request Mykronos has open, in one place (spec 10 §2).

The platform opens pull requests from two unrelated places and records them in
two unrelated stores: workflow installs land in the operational database as
`WorkflowInstallEvent`, and Patchwork's fixes land in the lake as
`remediation_events`. Neither knows about the other, so answering "what is
Mykronos waiting on me for" meant opening every repository in turn.

Two decisions shape this module.

**Live state wins over recorded state.** Every row is confirmed against GitHub
before it is shown. The stored `pr_status` is what the platform last heard,
and it is wrong whenever a webhook was not delivered — which is not a rare
edge case: these four install pull requests were opened while the tunnel was
down, so nothing was ever delivered for them. A view of outstanding work that
lists merged pull requests as outstanding is worse than no view.

**A repository that cannot be reached is reported, not skipped.** A dropped
GitHub call would otherwise shorten the list, and a shorter list of things
demanding your attention looks exactly like progress.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from mykronos.db.models import RepoOnboarding, WorkflowInstallEvent
from mykronos.github.client import ChecksSummary, GitHubError
from mykronos.github.factory import GitHubClientFactory
from mykronos.lake.catalog import Catalog

logger = logging.getLogger(__name__)

#: Patchwork states that mean a pull request is still open and interesting.
#: `closed_unmerged` and `merged` are settled; listing them would turn the page
#: into a history rather than a work list.
LIVE_FIX_STATUSES = ("draft_open", "human_edited")


@dataclass
class PullRequestRow:
    repo_full_name: str
    number: int
    url: str
    #: `install` turns scanning on; `fix` changes application code. The
    #: distinction is the whole reason the page is worth reading: one is
    #: Mykronos's own configuration, the other is a proposal about your code.
    kind: str
    title: str
    state: str
    merged: bool
    draft: bool
    branch: str = ""
    opened_at: datetime | None = None
    changed_files: int | None = None
    #: What this pull request is for, in the terms of whichever half opened it.
    summary: str = ""
    #: Why, at more length — the installer's plan or Patchwork's rationale.
    detail: str = ""
    capabilities: list[str] = field(default_factory=list)
    finding_id: str | None = None
    #: Absent when the check-runs call failed. Distinct from "no checks", which
    #: is a real and different answer.
    checks: ChecksSummary | None = None
    #: True when Patchwork has stood down because a person committed to the
    #: branch (spec 08 §3). Worth surfacing: it means the fix is now yours.
    human_edited: bool = False


@dataclass
class PullRequestList:
    pull_requests: list[PullRequestRow] = field(default_factory=list)
    #: Repos GitHub would not answer for, with the reason. Shown rather than
    #: dropped, so a short list is never mistaken for a quiet week.
    unreachable: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class _Candidate:
    """A pull request the platform believes it opened, before confirmation."""

    repo_full_name: str
    installation_id: int
    number: int
    kind: str
    summary: str
    detail: str
    capabilities: list[str] = field(default_factory=list)
    finding_id: str | None = None
    human_edited: bool = False


def _install_candidates(session: Session) -> list[_Candidate]:
    """Open install pull requests, from the operational store.

    Keyed off `pending_pr_number` rather than off the event log: the log is
    append-only history, and a repo has at most one install PR outstanding
    (spec 03 §4). The event supplies the description; the onboarding row
    supplies the truth about which one is current.
    """
    candidates: list[_Candidate] = []
    rows = session.execute(
        select(RepoOnboarding).where(RepoOnboarding.pending_pr_number.is_not(None))
    ).scalars()

    for row in rows:
        event = session.execute(
            select(WorkflowInstallEvent)
            .where(WorkflowInstallEvent.repo_onboarding_id == row.id)
            .where(WorkflowInstallEvent.pr_number == row.pending_pr_number)
            .order_by(WorkflowInstallEvent.id.desc())
        ).scalars().first()

        pending = list(row.pending_capabilities or [])
        candidates.append(
            _Candidate(
                repo_full_name=row.github_repo_full_name,
                installation_id=row.github_installation_id,
                number=int(row.pending_pr_number or 0),
                kind="install",
                summary=", ".join(pending) or "no capabilities",
                detail=(event.detail if event else "") or "",
                capabilities=pending,
            )
        )
    return candidates


def _fix_candidates(
    session: Session, catalog: Catalog, repos: dict[str, int]
) -> list[_Candidate]:
    """Open Patchwork fixes, from the lake.

    Filtered to onboarded repositories: the lake outlives an offboarding, and
    a fix for a repo the platform no longer manages is not work anybody here
    can action.
    """
    if not repos:
        return []

    rows = catalog.query(
        "SELECT repo_full_name, fix_pr_number, finding_id, rationale, pr_status "
        "FROM remediation_events "
        f"WHERE pr_status IN ({', '.join('?' * len(LIVE_FIX_STATUSES))}) "
        "  AND fix_pr_number IS NOT NULL "
        "ORDER BY updated_at DESC",
        list(LIVE_FIX_STATUSES),
    )

    seen: set[tuple[str, int]] = set()
    candidates: list[_Candidate] = []
    for repo_full_name, number, finding_id, rationale, pr_status in rows:
        installation_id = repos.get(str(repo_full_name))
        if installation_id is None:
            continue
        key = (str(repo_full_name), int(number))
        if key in seen:
            continue
        seen.add(key)
        candidates.append(
            _Candidate(
                repo_full_name=str(repo_full_name),
                installation_id=installation_id,
                number=int(number),
                kind="fix",
                summary=str(finding_id or ""),
                detail=str(rationale or ""),
                finding_id=str(finding_id) if finding_id else None,
                human_edited=pr_status == "human_edited",
            )
        )
    return candidates


async def _confirm(
    candidate: _Candidate, factory: GitHubClientFactory
) -> tuple[PullRequestRow | None, tuple[str, str] | None]:
    """Ask GitHub what this pull request actually looks like now."""
    github = factory.for_installation(candidate.installation_id)
    try:
        pull_request = await github.get_pull_request(
            candidate.repo_full_name, candidate.number
        )
    except GitHubError as exc:
        return None, (candidate.repo_full_name, str(exc))

    if pull_request is None or pull_request.state != "open":
        # Merged, closed, or deleted. Not outstanding work, so not listed —
        # the platform's own record catches up via the pull_request webhook.
        return None, None

    checks: ChecksSummary | None = None
    if pull_request.head_sha:
        try:
            checks = await github.get_checks_summary(
                candidate.repo_full_name, pull_request.head_sha
            )
        except GitHubError as exc:
            # A missing check summary is a missing column, not a missing row.
            logger.debug(
                "No check summary for %s#%s: %s",
                candidate.repo_full_name,
                candidate.number,
                exc,
            )

    return (
        PullRequestRow(
            repo_full_name=candidate.repo_full_name,
            number=pull_request.number,
            url=pull_request.url,
            kind=candidate.kind,
            title=pull_request.title,
            state=pull_request.state,
            merged=pull_request.merged,
            draft=pull_request.draft,
            branch=pull_request.head_branch,
            opened_at=pull_request.created_at,
            changed_files=pull_request.changed_files,
            summary=candidate.summary,
            detail=candidate.detail,
            capabilities=candidate.capabilities,
            finding_id=candidate.finding_id,
            checks=checks,
            human_edited=candidate.human_edited,
        ),
        None,
    )


async def open_pull_requests(
    session: Session, catalog: Catalog, factory: GitHubClientFactory
) -> PullRequestList:
    """Everything Mykronos has open across every onboarded repository."""
    repos = {
        row.github_repo_full_name: row.github_installation_id
        for row in session.execute(select(RepoOnboarding)).scalars()
    }

    candidates = _install_candidates(session) + _fix_candidates(session, catalog, repos)

    # Concurrently: this is two GitHub round trips per pull request, and doing
    # them in series is what makes a dashboard page feel broken.
    confirmed = await asyncio.gather(
        *(_confirm(candidate, factory) for candidate in candidates)
    )

    result = PullRequestList()
    for row, failure in confirmed:
        if row is not None:
            result.pull_requests.append(row)
        if failure is not None:
            result.unreachable.append(failure)

    # Fixes before installs, oldest first. A fix is a proposal about your code
    # and an install is configuration; and within either, the one that has been
    # waiting longest is the one going stale.
    result.pull_requests.sort(
        key=lambda row: (
            row.kind != "fix",
            row.opened_at or datetime.max.replace(tzinfo=None),
        )
    )
    return result
