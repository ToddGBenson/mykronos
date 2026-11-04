"""Raise a Hub incident or story from where the problem is seen (TheHub #60911).

See `mykronos.raise_to_hub` for what each place sends and why the evidence
is built here, not in the browser.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from mykronos import raise_to_hub as rh
from mykronos.adminauth import PrincipalDep, WriterDep
from mykronos.api import product_owner as phase1
from mykronos.dashboard import DashboardQueries
from mykronos.db.models import AuditLogEntry
from mykronos.product_owner import HubUnavailableError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/dashboard", tags=["raise"])

KindParam = Literal["lane", "finding", "health"]


class RaiseDraftOut(BaseModel):
    kind: str
    subject: str
    title: str
    #: What TheHub will be sent, built from MyKronos's own records.
    evidence: str


class RaiseIn(BaseModel):
    kind: KindParam
    subject: str = Field(min_length=1, max_length=255)
    raise_as: Literal["incident", "story"]
    #: Defaults to the draft's title.
    title: str | None = Field(default=None, max_length=255)
    #: Put above the evidence.
    note: str | None = Field(default=None, max_length=4000)


class RaiseOut(BaseModel):
    hub_kind: str
    hub_id: int
    title: str


class RaisedLinkOut(BaseModel):
    subject: str
    hub_kind: str
    hub_id: int
    #: TheHub's status now, or "unknown" when it could not be read.
    status: str
    raised_by: str
    raised_at: str | None


class RaisedOut(BaseModel):
    links: list[RaisedLinkOut]


async def _draft(request: Request, kind: str, subject: str) -> rh.Draft:
    catalog = request.app.state.catalog
    try:
        if kind == "lane":
            return await asyncio.to_thread(rh.lane_draft, catalog, subject)
        if kind == "finding":
            return await asyncio.to_thread(
                rh.finding_draft, DashboardQueries(catalog), catalog, subject
            )
        return await rh.health_draft(request.app.state.settings, subject)
    except rh.SubjectNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.get("/raise/draft", response_model=RaiseDraftOut)
async def raise_draft(
    request: Request,
    principal: PrincipalDep,
    kind: Annotated[KindParam, Query()],
    subject: Annotated[str, Query(min_length=1, max_length=255)],
) -> RaiseDraftOut:
    """What raising this lane, finding or health dependency would send to TheHub
    (TheHub #60911): a title and the evidence MyKronos holds for it."""
    draft = await _draft(request, kind, subject)
    return RaiseDraftOut(
        kind=draft.kind, subject=draft.subject, title=draft.title, evidence=draft.evidence
    )


@router.post("/raise", response_model=RaiseOut, status_code=status.HTTP_201_CREATED)
async def raise_in_hub(
    request: Request, body: RaiseIn, actor: WriterDep, principal: PrincipalDep
) -> RaiseOut:
    """Open a Hub incident (room devops) or a backlog story for a lane, finding
    or health dependency, with MyKronos's evidence attached (TheHub #60911).
    The raise is audited with the caller's actor, kind and provenance, which is
    also how the row it came from finds its Hub id again."""
    hub = phase1._require_hub(request)
    draft = await _draft(request, body.kind, body.subject)
    title = (body.title or "").strip() or draft.title
    build = rh.incident_payload if body.raise_as == "incident" else rh.story_payload
    payload = build(
        draft, title=title, actor=actor, actor_kind=principal.kind.value, note=body.note
    )
    try:
        outcome = await (
            hub.open_incident(payload)
            if body.raise_as == "incident"
            else hub.create_story(payload)
        )
    except HubUnavailableError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
    created = outcome.body if isinstance(outcome.body, dict) else {}
    hub_id = created.get("id")
    if not outcome.ok or not isinstance(hub_id, int):
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=outcome.detail or "TheHub did not return the id of what it created.",
        )
    database = request.app.state.db
    with database.session() as session:
        database.audit(
            session,
            actor=actor,
            action=rh.ACTION,
            entity_type=body.kind,
            entity_id=body.subject,
            hub_kind=body.raise_as,
            hub_id=hub_id,
            title=title,
        )
    return RaiseOut(hub_kind=body.raise_as, hub_id=hub_id, title=title)


async def _hub_status(hub: object, kind: str, hub_id: int) -> str:
    if hub is None:
        return "unknown"
    path = f"/api/incidents/{hub_id}" if kind == "incident" else f"/api/dev/stories/{hub_id}"
    try:
        body = await hub.get_json(path)  # type: ignore[attr-defined]
    except HubUnavailableError:
        return "unknown"
    if not isinstance(body, dict):
        return "unknown"
    value = body.get("status") if kind == "incident" else body.get("gate") or body.get("status")
    return str(value) if value else "unknown"


@router.get("/raised", response_model=RaisedOut)
async def raised(
    request: Request,
    principal: PrincipalDep,
    kind: Annotated[KindParam, Query()],
    subject: Annotated[list[str], Query(max_length=200)],
) -> RaisedOut:
    """For each subject, the newest Hub incident or story raised from it, who
    raised it, and its status in TheHub now ("unknown" when unreadable)."""
    wanted = [s for s in subject if s][:200]
    with request.app.state.db.session() as session:
        rows = session.execute(
            select(AuditLogEntry)
            .where(
                AuditLogEntry.action == rh.ACTION,
                AuditLogEntry.entity_type == kind,
                AuditLogEntry.entity_id.in_(wanted),
            )
            .order_by(AuditLogEntry.created_at.desc())
        ).scalars()
        newest: dict[str, AuditLogEntry] = {}
        for row in rows:
            newest.setdefault(row.entity_id, row)
        entries = [
            (e.entity_id, dict(e.detail or {}), e.actor, e.created_at) for e in newest.values()
        ]
    hub = phase1._hub(request)
    links = []
    for entity_id, detail, actor, at in entries:
        hub_id = detail.get("hub_id")
        hub_kind = str(detail.get("hub_kind") or "")
        if not isinstance(hub_id, int):
            continue
        links.append(
            RaisedLinkOut(
                subject=entity_id,
                hub_kind=hub_kind,
                hub_id=hub_id,
                status=await _hub_status(hub, hub_kind, hub_id),
                raised_by=actor,
                raised_at=at.isoformat() if at else None,
            )
        )
    return RaisedOut(links=links)
