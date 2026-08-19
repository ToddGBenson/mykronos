"""i2i grooming API (spec 17 §7.2).

Turns a triaged finding, or a detected toxic combination, into a dev-ready
GitHub issue. This is issue creation, not pull-request creation, and not a
merge — Patchwork's structural "never merges" guarantee (spec 08 §3, no
merge method exists on `GitHubClient` at all) is untouched: an issue is a
work item, independent of whether Patchwork ever generates a fix for it.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from mykronos.adminauth import AdminDep
from mykronos.dashboard import DashboardQueries
from mykronos.db.models import RepoOnboarding
from mykronos.github.client import GitHubError
from mykronos.groom import open_or_update_story
from mykronos.logsafe import scrub
from mykronos.patchwork import correlate
from mykronos.patchwork.pipeline import DEFAULT_CORRELATION_CAPABILITIES
from mykronos.triage_story import TriageStory, gather_combination_story, gather_finding_story

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/triage", tags=["triage"])


class GroomResult(BaseModel):
    story_id: str
    dev_ready: bool
    missing_fields: list[str] = Field(
        description="Empty when dev_ready. Named, not just implied by the boolean, "
        "so a caller knows what to fill in rather than only that something's missing."
    )
    github_issue_number: int
    github_issue_url: str
    created: bool = Field(
        description="True if this groom opened a new issue; false if it updated one "
        "already opened by an earlier groom of the same finding/combination."
    )


def _queries(request: Request) -> DashboardQueries:
    return DashboardQueries(request.app.state.catalog)


def _github_for(request: Request, repo_full_name: str) -> Any:
    """The installed App's client for this repo, or `None` if it isn't
    onboarded through the App at all — same lookup `api/ingest.py`'s
    `_installation_client` makes, restated here rather than imported: each
    API module keeps its own small version of this, matching `_resolve_repo`/
    `_get`'s existing precedent (api/dashboard.py, api/repos.py)."""
    with request.app.state.db.session() as session:
        onboarding = (
            session.execute(
                select(RepoOnboarding).where(
                    RepoOnboarding.github_repo_full_name == repo_full_name
                )
            )
            .scalars()
            .first()
        )
    if onboarding is None:
        return None
    return request.app.state.github_factory.for_installation(onboarding.github_installation_id)


async def _open_or_update(request: Request, actor: str, story: TriageStory) -> GroomResult:
    """The API's wrapper around the shared grooming path (spec 19 §4.3).

    The work itself lives in `mykronos.groom` so the scheduled auto-routing
    pass runs identical code; this adds only what is specific to being inside
    a request — resolving the installation, and turning a GitHub failure into
    a status code rather than an exception a job would log.
    """
    github = _github_for(request, story.repo_full_name)
    if github is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"{story.repo_full_name} is not onboarded through the GitHub App — "
                "there is no installation to open an issue with."
            ),
        )

    try:
        outcome = await open_or_update_story(request.app.state.db, github, actor, story)
    except GitHubError as exc:
        logger.warning(
            "Grooming %s %s failed: %s", story.subject_type, scrub(story.subject_id), exc
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail=f"GitHub refused this: {exc}"
        ) from exc

    return GroomResult(
        story_id=outcome.story_id,
        dev_ready=story.dev_ready,
        missing_fields=story.missing_fields,
        github_issue_number=outcome.github_issue_number,
        github_issue_url=outcome.github_issue_url,
        created=outcome.created,
    )


@router.post("/{finding_id}/groom", response_model=GroomResult)
async def groom_finding(request: Request, finding_id: str, actor: AdminDep) -> GroomResult:
    """Build and open (or update) a dev-ready story for one finding (spec 17 §7.2)."""
    finding = _queries(request).finding(finding_id)
    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"No finding {finding_id!r}."
        )

    catalog = request.app.state.catalog
    with request.app.state.db.session() as session:
        story = gather_finding_story(catalog, session, request.app.state.knowledge, finding)

    return await _open_or_update(request, actor, story)


@router.post("/repos/{repo_id}/combinations/{combination_id}/groom", response_model=GroomResult)
async def groom_combination(
    request: Request, repo_id: str, combination_id: str, actor: AdminDep
) -> GroomResult:
    """Build and open (or update) a dev-ready story for a detected toxic
    combination (spec 17 §7.2). Repo-scoped in the path — unlike a finding, a
    `combination_id` alone names no repository, since combinations are
    detected fresh from a repo's current pool rather than stored (spec 08 §2
    stage 3): finding the one this id refers to means re-detecting over that
    repo's findings, the same computation the Findings tab already runs."""
    catalog = request.app.state.catalog
    with request.app.state.db.session() as session:
        onboarding = session.get(RepoOnboarding, repo_id)
        if onboarding is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=f"No repo {repo_id!r}."
            )
        repo_full_name = str(onboarding.github_repo_full_name)

        columns = [
            "finding_id",
            "capability",
            "rule_id",
            "title",
            "description",
            "severity",
            "file_path",
            "package_name",
            "status",
        ]
        rows = catalog.query(
            f"SELECT {', '.join(columns)} FROM findings "
            "WHERE asset_id = ? AND status = 'open' AND capability IN ("
            + ", ".join("?" for _ in DEFAULT_CORRELATION_CAPABILITIES)
            + ")",
            [repo_full_name, *sorted(DEFAULT_CORRELATION_CAPABILITIES)],
        )
        pool = [dict(zip(columns, row, strict=True)) for row in rows]

        combinations = correlate.detect(pool)
        combination = next(
            (c for c in combinations if c.combination_id == combination_id), None
        )
        if combination is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=(
                    f"No toxic combination {combination_id!r} is currently detected "
                    f"for {repo_full_name}. Combinations aren't stored — this id has "
                    "to match one the Findings tab is showing right now."
                ),
            )
        rule = next(
            (r for r in correlate.BUILT_IN_RULES if r.rule_id == combination.rule_id), None
        )
        by_id = {str(f["finding_id"]): f for f in pool}
        members = [by_id[fid] for fid in sorted(combination.finding_ids) if fid in by_id]

        story = gather_combination_story(
            catalog,
            session,
            request.app.state.knowledge,
            repo_full_name,
            combination,
            rule,
            members,
        )

    return await _open_or_update(request, actor, story)
