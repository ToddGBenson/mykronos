"""`GET /api/briefing/daily`: the morning briefing, overall and per product
(TheHub #60860 and #60861, epic #60858).

The reasoning lives in `mykronos.daily_briefing`; this module reads the
inputs from outside the lake the way `GET /api/dashboard/briefing` does
(`briefing_sources.gather`, the onboarding ledger), plus TheHub's board and
the open pull requests (`delivery_sources.gather`, cached), and shapes the
answer.
"""

from __future__ import annotations

import asyncio
import dataclasses
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, Field

from mykronos import briefing_sources, daily_briefing, delivery_sources
from mykronos.adminauth import PrincipalDep
from mykronos.schemas import utcnow

router = APIRouter(prefix="/api/briefing", tags=["briefing"])


class BriefingLineOut(BaseModel):
    #: What changed.
    what: str
    #: Why it matters.
    so_what: str
    #: What it becomes. A line that is none of these is not on the page.
    work: Literal["merge", "decision", "story"]
    repo_full_name: str = ""
    #: A route or id to act on, when one exists.
    ref: str = ""


class BriefingSectionOut(BaseModel):
    key: str
    title: str
    #: ok | partial | unavailable | not_available. Anything but `ok` carries
    #: a `reason`; an unreadable source is never an empty `ok` section.
    status: Literal["ok", "partial", "unavailable", "not_available"]
    #: The store(s) the section reads.
    source: str
    #: How old the data is. Null when nothing was read.
    as_of: datetime | None
    reason: str = ""
    lines: list[BriefingLineOut] = Field(default_factory=list)
    #: The counts behind the lines.
    data: dict[str, Any] = Field(default_factory=dict)


class DailyBriefingOut(BaseModel):
    generated_at: datetime
    scope: Literal["overall", "product"]
    repo_full_name: str | None = None
    sections: list[BriefingSectionOut]


def _build_inputs(request: Request) -> dict[str, Any]:
    """`briefing.build`'s inputs from outside the lake, as the dashboard
    briefing reads them. Languages are left out: they are a live GitHub call
    per repository, and the unread-code section is not on this page."""
    state = request.app.state
    operational = briefing_sources.gather(
        state.settings, state.db, state.catalog, state.github_factory, state.templates
    )
    default_branches, scanned_by = briefing_sources.onboarding_maps(state.db)
    return {
        "default_branches": default_branches,
        "scanned_by": scanned_by,
        "concourse_token": bool(state.settings.concourse_api_token),
        "repo_ids": briefing_sources.repo_ids(state.db),
        "paused_jobs": operational.paused_jobs,
        "failing_jobs": operational.failing_jobs,
        "blocked_jobs": operational.blocked_jobs,
        "workflow_blocked_jobs": operational.workflow_blocked_jobs,
        "unhealthy_jobs": operational.unhealthy_jobs,
        "tokens": operational.tokens,
        "toxic_combinations": operational.toxic_combinations,
        "toxic_coverage": operational.toxic_coverage,
        "exposure": operational.exposure,
        "production_lag": operational.production_lag,
        "probe_setup": operational.probe_setup,
    }


@router.get("/daily", response_model=DailyBriefingOut)
async def daily_briefing_route(
    request: Request,
    principal: PrincipalDep,
    repo_id: Annotated[
        str | None,
        Query(
            description=(
                "One product's briefing, by onboarding id (as every dashboard "
                "route takes it). Omit for the overall briefing."
            ),
        ),
    ] = None,
) -> DailyBriefingOut:
    """What changed, so what, and whether it is work (TheHub #60860).

    Overall: Needs you today, Production truth, Can we trust our signals,
    Risk delta, Acceptances, Sprint health, Next-sprint candidates (ranked
    by risk removed x exposure / effort, with the weekly briefing-signal
    metric; TheHub #60862), Suggested focus. Per product
    (`repo_id`): Deploy and health, Findings delta, Capability lanes,
    Next-sprint candidates.

    Every section carries `source`, `as_of` and a `status`. A source that
    could not be read is `unavailable` with its reason. "Needs you", sprint
    health and the board check behind the focus and candidate lists read
    TheHub's board and GitHub (TheHub #60861), cached for a few minutes; an
    earlier answer standing in for a failed read makes its section
    `partial`. A read.
    """
    from mykronos.api.dashboard import _resolve_repo

    asset_id = _resolve_repo(request, repo_id) if repo_id else None
    state = request.app.state
    inputs, delivery = await asyncio.gather(
        asyncio.to_thread(_build_inputs, request),
        delivery_sources.gather(state, want_pull_requests=asset_id is None),
    )
    now = utcnow()
    if asset_id is None:
        report = await asyncio.to_thread(
            daily_briefing.build_overall,
            state.catalog,
            state.db,
            inputs,
            now=now,
            delivery=delivery,
        )
    else:
        report = await asyncio.to_thread(
            daily_briefing.build_product,
            state.catalog,
            state.db,
            inputs,
            asset_id=asset_id,
            now=now,
            delivery=delivery,
        )
    return DailyBriefingOut.model_validate(dataclasses.asdict(report))
