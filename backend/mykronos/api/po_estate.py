"""The Product Owner estate roll-up (spec 35 §8.7, D-141).

One row per active repository, built by calling the per-repository Product
Owner read itself. Nothing is recomputed here: sprint progress, "needs a
human" and the Oracle decision are exactly what that repository's tab shows,
so the two pages cannot disagree. The totals row is the sum of the rows.

A repository with no manifest is listed as "declares no process", never left
out, because a roll-up that drops the repositories with no process answers
the wrong question.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select

from mykronos.adminauth import PrincipalDep
from mykronos.api import product_owner as phase1
from mykronos.db.models import RepoOnboarding

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/dashboard", tags=["product-owner"])

#: Repositories read at once. Each read lists two TheHub buckets and reads
#: one manifest from GitHub.
ESTATE_CONCURRENCY = 4

PROCESS_WORD = {
    "valid": "declared",
    "invalid": "invalid manifest",
    "unreadable": "manifest unreadable",
    "absent": "declares no process",
}


class PoEstateRowOut(BaseModel):
    repo_id: str
    repo_full_name: str
    #: valid | invalid | absent | unreadable
    manifest_state: str
    #: declared | invalid manifest | manifest unreadable | declares no process
    process: str
    manifest_name: str | None
    #: None when TheHub could not be read for this repository: absent, not 0.
    sprint_done: int | None
    sprint_committed: int | None
    #: Stories the Overview lists under "needs a human".
    needs_human: int | None
    oracle_recommendation: str | None
    oracle_score: float | None
    hub_connected: bool
    #: This repository's Product Owner tab.
    link: str
    error: str | None


class PoEstateTotalsOut(BaseModel):
    repos: int
    declared: int
    declares_no_process: int
    invalid_or_unreadable: int
    #: Sums over the rows that have a value; `rows_without_hub` says how many
    #: rows do not.
    sprint_done: int
    sprint_committed: int
    needs_human: int
    rows_without_hub: int


class PoEstateOut(BaseModel):
    rows: list[PoEstateRowOut]
    totals: PoEstateTotalsOut


async def _row(request: Request, principal: Any, repo_id: str, name: str) -> PoEstateRowOut:
    link = f"/repos/{repo_id}?tab=product-owner"
    try:
        view = await phase1.product_owner(request, repo_id, principal)
    except HTTPException as exc:
        return PoEstateRowOut(
            repo_id=repo_id,
            repo_full_name=name,
            manifest_state="unreadable",
            process="manifest unreadable",
            manifest_name=None,
            sprint_done=None,
            sprint_committed=None,
            needs_human=None,
            oracle_recommendation=None,
            oracle_score=None,
            hub_connected=False,
            link=link,
            error=str(exc.detail),
        )
    connected = view.hub.connected
    manifest = view.manifest.manifest or {}
    return PoEstateRowOut(
        repo_id=repo_id,
        repo_full_name=view.repo_full_name,
        manifest_state=view.manifest.state,
        process=PROCESS_WORD.get(view.manifest.state, view.manifest.state),
        manifest_name=manifest.get("name") if view.manifest.state == "valid" else None,
        sprint_done=view.sprint_progress.done if connected else None,
        sprint_committed=view.sprint_progress.committed if connected else None,
        needs_human=(
            sum(1 for item in view.needs_human if item.story_id is not None) if connected else None
        ),
        oracle_recommendation=view.oracle.recommendation if view.oracle else None,
        oracle_score=view.oracle.overall_risk_score if view.oracle else None,
        hub_connected=connected,
        link=link,
        error=view.hub.error if not connected else None,
    )


def totals(rows: list[PoEstateRowOut]) -> PoEstateTotalsOut:
    return PoEstateTotalsOut(
        repos=len(rows),
        declared=sum(1 for r in rows if r.manifest_state == "valid"),
        declares_no_process=sum(1 for r in rows if r.manifest_state == "absent"),
        invalid_or_unreadable=sum(1 for r in rows if r.manifest_state in ("invalid", "unreadable")),
        sprint_done=sum(r.sprint_done or 0 for r in rows),
        sprint_committed=sum(r.sprint_committed or 0 for r in rows),
        needs_human=sum(r.needs_human or 0 for r in rows),
        rows_without_hub=sum(1 for r in rows if r.sprint_committed is None),
    )


@router.get("/product-owner/estate", response_model=PoEstateOut)
async def estate(request: Request, principal: PrincipalDep) -> PoEstateOut:
    """Every active repository's Product Owner read, one row each, summed."""
    with request.app.state.db.session() as session:
        repos = [
            (row.id, row.github_repo_full_name)
            for row in session.execute(
                select(RepoOnboarding)
                .where(RepoOnboarding.status == "active")
                .order_by(RepoOnboarding.github_repo_full_name)
            ).scalars()
        ]
    semaphore = asyncio.Semaphore(ESTATE_CONCURRENCY)

    async def one(repo_id: str, name: str) -> PoEstateRowOut:
        async with semaphore:
            return await _row(request, principal, repo_id, name)

    rows = list(await asyncio.gather(*(one(repo_id, name) for repo_id, name in repos)))
    return PoEstateOut(rows=rows, totals=totals(rows))
