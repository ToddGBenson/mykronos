"""`GET /api/briefing/weekly`: the Monday intelligence page, one per
application (TheHub #60865, B7 of epic #60858).

The reasoning lives in `mykronos.weekly_briefing`; this module reads the
inputs per application and shapes the answer. The flash DM
(`mykronos.briefing_flash`) reads the same route, so the DM and the page
cannot disagree about what is exploited or critical.
"""

from __future__ import annotations

import asyncio
import dataclasses
from datetime import date, datetime
from typing import Annotated, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from mykronos import weekly_briefing
from mykronos.adminauth import PrincipalDep
from mykronos.db.models import RepoOnboarding
from mykronos.schemas import utcnow

router = APIRouter(prefix="/api/briefing", tags=["briefing"])


class WeeklyItemOut(BaseModel):
    what: str
    so_what: str = Field(description="Why it matters to this application.")
    action: str
    confidence: Literal["observed", "inferred"]
    confidence_reason: str = Field(description="What the confidence rests on.")
    source: str = Field(description="The advisory's public page or the MyKronos page.")
    severity: str
    new_this_week: bool
    flash: bool = Field(
        description="Known exploited or critical, and shipped: DMed the same day."
    )
    flash_reason: str
    key: str


class WeeklySectionOut(BaseModel):
    key: str
    title: str
    status: Literal["ok", "partial", "unavailable", "not_available"]
    source: str
    as_of: datetime | None
    reason: str = ""
    items: list[WeeklyItemOut] = Field(default_factory=list)
    data: dict[str, object] = Field(default_factory=dict)


class WeeklyPageOut(BaseModel):
    repo_full_name: str
    repo_id: str
    week_of: date = Field(description="The Monday the week starts on, local time.")
    generated_at: datetime
    sections: list[WeeklySectionOut]


class WeeklyBriefingOut(BaseModel):
    generated_at: datetime
    week_of: date
    pages: list[WeeklyPageOut]


def _zone(request: Request) -> ZoneInfo | None:
    try:
        return ZoneInfo(request.app.state.settings.briefing_dm_timezone)
    except (ZoneInfoNotFoundError, ValueError, AttributeError):
        return None


def _products(request: Request, repo_id: str | None) -> list[tuple[str, str, str]]:
    with request.app.state.db.session() as session:
        query = (
            select(
                RepoOnboarding.id,
                RepoOnboarding.github_repo_full_name,
                RepoOnboarding.default_branch,
            )
            .where(RepoOnboarding.status != "removed")
            .where(RepoOnboarding.synthetic.is_(False))
            .order_by(RepoOnboarding.github_repo_full_name)
        )
        if repo_id is not None:
            query = query.where(RepoOnboarding.id == repo_id)
        rows = session.execute(query).all()
    return [(str(i), str(n), str(b or "main")) for i, n, b in rows]


def build_pages(request: Request, repo_id: str | None) -> WeeklyBriefingOut:
    state = request.app.state
    now = utcnow()
    zone = _zone(request)
    local_today = now.astimezone(zone).date() if zone else now.date()
    pages = []
    for pid, name, branch in _products(request, repo_id):
        inputs = weekly_briefing.gather(state.db, state.catalog, pid, name, branch)
        page = weekly_briefing.build(inputs, now=now, local_today=local_today)
        pages.append(WeeklyPageOut.model_validate(dataclasses.asdict(page)))
    return WeeklyBriefingOut(
        generated_at=now, week_of=weekly_briefing.monday_of(local_today), pages=pages
    )


@router.get("/weekly", response_model=WeeklyBriefingOut)
async def weekly_briefing_route(
    request: Request,
    principal: PrincipalDep,
    repo_id: Annotated[
        str | None,
        Query(description="One application's page, by onboarding id. Omit for every one."),
    ] = None,
) -> WeeklyBriefingOut:
    """The Monday intelligence page per application (TheHub #60865).

    Sections: advisories matched to what ships (KEV, EPSS, severity here,
    reachability), threats fitted to the declared threat model, end-of-life
    images, malicious packages, external exposure, vendor changes and
    standards. Every item carries so-what, action, confidence and source; a
    section that could not be read, or has no feed, says so. An item is
    `flash` only when it is known exploited or critical and shipped. A read.
    """
    if repo_id is not None:
        from mykronos.api.dashboard import _resolve_repo

        _resolve_repo(request, repo_id)
    return await asyncio.to_thread(build_pages, request, repo_id)
