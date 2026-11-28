"""Release notes, kept per production release (TheHub #61703).

`POST /api/releases` is what deploy.ps1 calls once the backend confirms it
runs the sha it deployed. Only that sha is accepted, so a failed deploy, which
leaves another sha running, records nothing. A rollback records nothing either.
`GET /api/releases` lists the history and `GET /api/releases/{sha}` serves one
release's page, with a CSP that allows no script.
"""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Path, Request, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from mykronos import release_notes
from mykronos.adminauth import HumanDep, PrincipalDep
from mykronos.api.ingest import installation_client_for_repo
from mykronos.logsafe import scrub
from mykronos.oracle.deploy_gate import SELF_REPO_FULL_NAME

logger = logging.getLogger(__name__)
router = APIRouter(tags=["releases"])

#: The page carries no script of its own, and nothing in it may run any.
PAGE_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; "
    "form-action 'none'; frame-ancestors 'self'"
)
_SHA = r"^[0-9a-f]{40}$"


class GateDelta(BaseModel):
    """The deploy gate's answer deploy.ps1 acted on, as far as the notes use it."""

    verdict: str = Field(default="", max_length=32)
    direction: str = Field(default="", max_length=16)
    baseline_score: float | None = None
    candidate_score: float | None = None
    introduced: dict[str, int] = Field(default_factory=dict)
    fixed: dict[str, int] = Field(default_factory=dict)


class ReleaseIn(BaseModel):
    sha: str = Field(pattern=_SHA)
    previous_sha: str = Field(pattern=_SHA)
    gate: GateDelta | None = None


class ReleaseMeta(BaseModel):
    sha: str
    previous_sha: str
    generated_at: str
    commit_count: int
    pull_requests: list[int]
    stories: list[str]


class ReleaseList(BaseModel):
    releases: list[ReleaseMeta]


def _open_counts(request: Request, sha: str) -> dict[str, int]:
    rows = request.app.state.catalog.query(
        "SELECT inputs_snapshot FROM risk_decisions WHERE repo_full_name = ? "
        "AND lower(commit_sha) = ? ORDER BY evaluated_at DESC LIMIT 1",
        [SELF_REPO_FULL_NAME, sha],
    )
    return release_notes.open_counts(rows[0][0]) if rows else {}


@router.post("/api/releases", response_model=ReleaseMeta, status_code=status.HTTP_201_CREATED)
async def record_release(request: Request, body: ReleaseIn, principal: HumanDep) -> Any:
    """Generate and keep the notes for a confirmed production deploy.

    Refused (409) unless `sha` is the commit this backend runs, and for a
    rollback, whether the gate called it one or GitHub says `sha` is behind
    `previous_sha`. Those deploys produce no notice."""
    running = str(request.app.state.settings.build_sha or "").lower()
    if not running or running != body.sha:
        raise HTTPException(status.HTTP_409_CONFLICT, "That sha is not the one running here.")
    if body.gate is not None and body.gate.direction == "rollback":
        raise HTTPException(status.HTTP_409_CONFLICT, "A rollback produces no release notes.")
    github = installation_client_for_repo(request, SELF_REPO_FULL_NAME)
    if github is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "No GitHub installation.")
    comparison = await github.compare(SELF_REPO_FULL_NAME, body.previous_sha, body.sha)
    if comparison.status in ("behind", "identical"):
        raise HTTPException(
            status.HTTP_409_CONFLICT, f"Nothing shipped: {body.sha[:8]} is {comparison.status}."
        )
    commits = release_notes.first_parent(comparison.commits, body.sha)
    pulls: dict[int, Any] = {}
    for commit in commits:
        number = release_notes.pr_number_of(commit.message)
        if number is not None and number not in pulls:
            pr = await github.get_pull_request(SELF_REPO_FULL_NAME, number)
            if pr is not None:
                pulls[number] = pr
    gate = body.gate
    security = release_notes.SecurityDelta(
        score_before=gate.baseline_score if gate else None,
        score_after=gate.candidate_score if gate else None,
        introduced=dict(gate.introduced) if gate else {},
        fixed=dict(gate.fixed) if gate else {},
        open_before=_open_counts(request, body.previous_sha),
        open_after=_open_counts(request, body.sha),
        gate=(gate.verdict or "answered") if gate else "not asked",
    )
    release = release_notes.new_release(body.sha, body.previous_sha, commits, pulls, security)
    meta = release_notes.store(request.app.state.settings.datalake_dir, release)
    logger.info(
        "Release notes for %s over %s: %d items (%s)",
        body.sha[:8], body.previous_sha[:8], len(release.items), scrub(principal.actor),
    )
    return meta


@router.get("/api/releases", response_model=ReleaseList)
async def releases(request: Request, principal: PrincipalDep) -> Any:
    """Every release with notes, newest first."""
    return {"releases": release_notes.list_releases(request.app.state.settings.datalake_dir)}


@router.get("/api/releases/{sha}", response_class=HTMLResponse)
async def release_page(
    request: Request,
    principal: PrincipalDep,
    sha: Annotated[str, Path(pattern=_SHA)],
) -> HTMLResponse:
    """One release's notes, as the page deploy time rendered."""
    page = release_notes.read_html(request.app.state.settings.datalake_dir, sha)
    if page is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No release notes for that sha.")
    return HTMLResponse(
        page,
        headers={"Content-Security-Policy": PAGE_CSP, "X-Content-Type-Options": "nosniff"},
    )
