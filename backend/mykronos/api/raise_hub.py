"""Raise a Hub incident or story from where the problem is seen (TheHub #60911).

See `mykronos.raise_to_hub` for what each place sends and why the evidence
is built here, not in the browser.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from mykronos import raise_to_hub as rh
from mykronos.adminauth import PrincipalDep, WriterDep
from mykronos.api import product_owner as phase1
from mykronos.dashboard import DashboardQueries
from mykronos.db.models import AuditLogEntry, RepoOnboarding
from mykronos.product_owner import HubUnavailableError
from mykronos.ratelimit import hourly_refusal

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/dashboard", tags=["raise"])

KindParam = Literal["lane", "finding", "health"]

#: How long a Hub status read is reused (TheHub #61379). `raised` is rendered on
#: every page of rows, and used to read the Hub once per linked subject each time.
STATUS_TTL_SECONDS = 30.0
_CACHE_LIMIT = 1024
#: What a Hub item's status or gate reads once it is over, so the same subject
#: may be raised again. Anything else, or unreadable, is treated as still open
#: only when it was read: an unreadable status never blocks a raise.
TERMINAL_STATUSES = frozenset(
    {"resolved", "closed", "done", "deployed", "cancelled", "canceled", "wontfix"}
)

#: How many Hub reads one `raised` call has in flight (TheHub #61379): a cold
#: page of 200 subjects does not become 200 requests at once.
STATUS_READ_CONCURRENCY = 8

#: The audit action of a raise that was refused before anything reached TheHub.
REFUSED_ACTION = "hub_raise_refused"

#: A clock the tests move; the TTL is never slept.
_now = time.monotonic


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
    #: True when this subject was already raised and its Hub item is still open:
    #: nothing new was filed, and this is the existing item.
    already_raised: bool = False


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


def _repo_ids(request: Request) -> dict[str, str]:
    """Active repositories by full name, to their onboarding ids."""
    with request.app.state.db.session() as session:
        rows = session.execute(
            select(RepoOnboarding.github_repo_full_name, RepoOnboarding.id).where(
                RepoOnboarding.status == "active"
            )
        ).all()
    return {str(name): str(repo_id) for name, repo_id in rows}


async def _draft(request: Request, kind: str, subject: str) -> rh.Draft:
    catalog = request.app.state.catalog
    try:
        if kind == "lane":
            return await asyncio.to_thread(rh.lane_draft, catalog, subject)
        if kind == "finding":
            return await asyncio.to_thread(
                rh.finding_draft,
                DashboardQueries(catalog),
                catalog,
                subject,
                _repo_ids(request),
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


def _newest_raise(
    request: Request, kind: str, subject: str, hub_kind: str
) -> dict[str, Any] | None:
    """The newest audited raise of this subject as this Hub kind: its Hub id."""
    with request.app.state.db.session() as session:
        rows = session.execute(
            select(AuditLogEntry)
            .where(
                AuditLogEntry.action == rh.ACTION,
                AuditLogEntry.entity_type == kind,
                AuditLogEntry.entity_id == subject,
            )
            .order_by(AuditLogEntry.created_at.desc())
        ).scalars()
        for row in rows:
            detail = dict(row.detail or {})
            if detail.get("hub_kind") == hub_kind and isinstance(detail.get("hub_id"), int):
                return {"hub_id": detail["hub_id"], "title": str(detail.get("title") or "")}
    return None


def _limited(request: Request, actor: str, kind: str, subject: str) -> HTTPException | None:
    limiter = request.app.state.raise_limiter
    allowed, retry_after = limiter.check(actor)
    if allowed:
        return None
    _audit_refusal(request, actor, kind, subject, outcome="rate_limited")
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail=hourly_refusal("Raising in TheHub", actor, limiter.limit, retry_after),
        headers={"Retry-After": str(retry_after)},
    )


def _audit_refusal(
    request: Request, actor: str, kind: str, subject: str, *, outcome: str
) -> None:
    """A refused raise is recorded, under its own action: `hub_raised` rows are
    what link a subject to its Hub item, and a refusal has none."""
    database = request.app.state.db
    with database.session() as session:
        database.audit(
            session,
            actor=actor,
            action=REFUSED_ACTION,
            entity_type=kind,
            entity_id=subject,
            outcome=outcome,
        )


@router.post("/raise", response_model=RaiseOut, status_code=status.HTTP_201_CREATED)
async def raise_in_hub(
    request: Request,
    response: Response,
    body: RaiseIn,
    actor: WriterDep,
    principal: PrincipalDep,
) -> RaiseOut:
    """Open a Hub incident (room devops) or a backlog story for a lane, finding
    or health dependency, with MyKronos's evidence attached (TheHub #60911).
    The raise is audited with the caller's actor, kind and provenance, which is
    also how the row it came from finds its Hub id again.

    A subject whose earlier raise is still open in TheHub is not raised again:
    the answer is that item, with `already_raised` and a 200. Each actor may
    file `hub_filings_per_actor_per_hour` new items an hour (429 past it, audited
    as `hub_raise_refused`); a duplicate or a failure on TheHub's side does not
    spend it (TheHub #61379)."""
    hub = phase1._require_hub(request)
    draft = await _draft(request, body.kind, body.subject)
    # One at a time: the duplicate check and the audit that makes the next
    # check see this raise must not interleave with another request's.
    async with request.app.state.raise_lock:
        return await _raise_locked(request, response, hub, draft, body, actor, principal)


async def _raise_locked(
    request: Request,
    response: Response,
    hub: Any,
    draft: rh.Draft,
    body: RaiseIn,
    actor: str,
    principal: Any,
) -> RaiseOut:
    earlier = _newest_raise(request, body.kind, body.subject, body.raise_as)
    if earlier is not None:
        current = await _status(request, hub, body.raise_as, earlier["hub_id"], fresh=True)
        if current != "unknown" and current.lower() not in TERMINAL_STATUSES:
            response.status_code = status.HTTP_200_OK
            return RaiseOut(
                hub_kind=body.raise_as,
                hub_id=earlier["hub_id"],
                title=earlier["title"],
                already_raised=True,
            )
    refusal = _limited(request, actor, body.kind, body.subject)
    if refusal is not None:
        raise refusal
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
        # The hit was recorded by `_limited`; TheHub's failure gives it back.
        request.app.state.raise_limiter.refund(actor)
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
    created = outcome.body if isinstance(outcome.body, dict) else {}
    hub_id = created.get("id")
    if not outcome.ok or not isinstance(hub_id, int):
        request.app.state.raise_limiter.refund(actor)
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


async def _status(
    request: Request, hub: object, kind: str, hub_id: int, *, fresh: bool = False
) -> str:
    """`_hub_status`, reused for `STATUS_TTL_SECONDS`. Only a status that was
    read is kept: "unknown" is somebody reloading to change it. `fresh` skips
    the stored answer (a duplicate check must not act on a stale one)."""
    cache: dict[tuple[str, int], tuple[float, str]] | None = getattr(
        request.app.state, "raise_status_cache", None
    )
    if cache is None:
        cache = request.app.state.raise_status_cache = {}
    now = _now()
    key = (kind, hub_id)
    held = cache.get(key)
    if not fresh and held is not None and now - held[0] < STATUS_TTL_SECONDS:
        return held[1]
    value = await _hub_status(hub, kind, hub_id)
    if value != "unknown":
        if len(cache) >= _CACHE_LIMIT:
            for stale in [k for k, (at, _) in cache.items() if now - at >= STATUS_TTL_SECONDS]:
                cache.pop(stale, None)
            if len(cache) >= _CACHE_LIMIT:
                cache.clear()
        cache[key] = (now, value)
    return value


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
    if kind == "incident":
        value = body.get("status")
    elif body.get("bucket") == "done" or body.get("closed_at"):
        # TheHub closes a story by moving it to the done bucket and stamping
        # `closed_at`; its gate stays where it was (TheHub #61379).
        return "done"
    else:
        value = body.get("gate") or body.get("status")
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
    linked = [
        (entity_id, detail["hub_id"], str(detail.get("hub_kind") or ""), actor, at)
        for entity_id, detail, actor, at in entries
        if isinstance(detail.get("hub_id"), int)
    ]
    # Together rather than one after another, a few at a time, each through the TTL cache.
    gate = asyncio.Semaphore(STATUS_READ_CONCURRENCY)

    async def read(hub_kind: str, hub_id: int) -> str:
        async with gate:
            return await _status(request, hub, hub_kind, hub_id)

    statuses = await asyncio.gather(
        *(read(hub_kind, hub_id) for _, hub_id, hub_kind, _, _ in linked)
    )
    return RaisedOut(
        links=[
            RaisedLinkOut(
                subject=entity_id,
                hub_kind=hub_kind,
                hub_id=hub_id,
                status=state,
                raised_by=actor,
                raised_at=at.isoformat() if at else None,
            )
            for (entity_id, hub_id, hub_kind, actor, at), state in zip(
                linked, statuses, strict=True
            )
        ]
    )
