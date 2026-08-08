"""Knowledge Store API (spec 11 §7, spec 10 §2.4).

Reading learnings, writing retro notes, and generating the two reports.

Everything here is admin-gated except reading. A learning carries the free text
somebody typed while dismissing a finding in their own repository — usually
mundane, occasionally a frank assessment of a vendor or a colleague's code —
and it is not raw scan output, so spec 12 §5's rule does not automatically
cover it. Viewers can read; nothing here lets them write, promote, or purge.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field

from mykronos.adminauth import AdminDep, PrincipalDep
from mykronos.knowledge.capture import capture_retro_note
from mykronos.knowledge.promotion import (
    find_cross_project_candidates,
    render_policy_proposal,
)
from mykronos.knowledge.reports import (
    NotEnoughHistoryError,
    build_retro,
    build_trend,
    render_retro_markdown,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/knowledge", tags=["knowledge"])


class EntryOut(BaseModel):
    entry_id: str
    tier: str
    repo_full_name: str | None = None
    source_type: str
    subject: str
    source_ref: str
    text: str
    #: The *current* value, not the stored one. A caller comparing entries
    #: needs them decayed to the same instant or the comparison is meaningless.
    confidence: float
    stored_confidence: float
    sensitivity: str
    observations: int
    reasons: list[str]
    created_at: datetime
    last_confirmed_at: datetime
    has_reason: bool


class EntriesPage(BaseModel):
    tier: str
    entries: list[EntryOut]
    total: int
    active: int = Field(
        description=(
            "How many are still believed. The difference from `total` is the "
            "store's forgetting, which is a number worth seeing."
        )
    )


class RetroNote(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subject: str = Field(min_length=1, max_length=200)
    text: str = Field(
        min_length=1,
        max_length=5000,
        description="The learning itself. For a retro note the text *is* the reason.",
    )
    repo_full_name: str | None = Field(default=None, max_length=255)


class CandidateOut(BaseModel):
    subject: str
    source_type: str
    from_tier: str
    to_tier: str
    repos: list[str]
    project_count: int
    total_observations: int
    mean_confidence: float
    reasons: list[str]


def _entry_out(store: Any, entry: Any) -> EntryOut:
    return EntryOut(
        entry_id=entry.entry_id,
        tier=entry.tier,
        repo_full_name=entry.repo_full_name,
        source_type=entry.source_type,
        subject=entry.subject,
        source_ref=entry.source_ref,
        text=entry.text,
        confidence=round(store.decayed_confidence(entry), 3),
        stored_confidence=round(entry.confidence, 3),
        sensitivity=entry.sensitivity,
        observations=entry.observations,
        reasons=entry.reasons,
        created_at=entry.created_at,
        last_confirmed_at=entry.last_confirmed_at,
        has_reason=entry.has_reason,
    )


@router.get("/entries", response_model=EntriesPage)
async def list_entries(
    request: Request,
    principal: PrincipalDep,
    repo_full_name: Annotated[str | None, Query()] = None,
    source_type: Annotated[str | None, Query()] = None,
) -> EntriesPage:
    """Everything the platform has been told, with current confidence."""
    store = request.app.state.knowledge
    filters = {}
    if repo_full_name:
        filters["repo_full_name"] = repo_full_name
    if source_type:
        filters["source_type"] = source_type

    entries = store.list_entries(filters or None)
    active = {entry.entry_id for entry, _ in store.active_entries()}

    return EntriesPage(
        tier=store.tier,
        entries=[_entry_out(store, entry) for entry in entries],
        total=len(entries),
        active=sum(1 for entry in entries if entry.entry_id in active),
    )


@router.post("/notes", response_model=EntryOut, status_code=status.HTTP_201_CREATED)
async def add_note(request: Request, body: RetroNote, actor: AdminDep) -> EntryOut:
    """Write down something noticed in a retro (spec 11 §4).

    The only entry type with no machine-generated component. Admin-only
    because it writes into the same corpus that eventually influences Oracle's
    policy, and an unauthenticated way to inject a "learning" would be a
    quietly effective way to change how every repository is scored.
    """
    store = request.app.state.knowledge
    result = capture_retro_note(
        store,
        subject=body.subject,
        text=body.text,
        author=actor,
        repo_full_name=body.repo_full_name,
    )

    with request.app.state.db.session() as session:
        request.app.state.db.audit(
            session,
            actor=actor,
            action="knowledge.note",
            entity_type="knowledge_entry",
            entity_id=result.entry.entry_id,
            subject=body.subject,
            repo=body.repo_full_name,
        )

    return _entry_out(store, result.entry)


@router.get("/retro")
async def retro(
    request: Request,
    principal: PrincipalDep,
    period_days: Annotated[int, Query(ge=1, le=365)] = 14,
    fmt: Annotated[str, Query(pattern="^(json|markdown)$")] = "json",
) -> Any:
    """What was learned, reconfirmed and forgotten in one period (spec 11 §7)."""
    store = request.app.state.knowledge
    report = build_retro(store, period_days=period_days)

    if fmt == "markdown":
        from fastapi.responses import PlainTextResponse

        return PlainTextResponse(render_retro_markdown(report), media_type="text/markdown")

    return {
        "period_start": report.period_start,
        "period_end": report.period_end,
        "quiet": report.is_quiet,
        "new_entries": report.new_entries,
        "reconfirmed": report.reconfirmed,
        "decaying": report.decaying,
        "unreasoned": report.unreasoned,
        "promotion_candidates": [
            CandidateOut(
                subject=c.subject,
                source_type=c.source_type,
                from_tier=c.from_tier,
                to_tier=c.to_tier,
                repos=c.repos,
                project_count=c.project_count,
                total_observations=c.total_observations,
                mean_confidence=round(c.mean_confidence, 3),
                reasons=c.reasons,
            ).model_dump()
            for c in report.promotion_candidates
        ],
    }


@router.get("/trend")
async def trend(
    request: Request,
    principal: PrincipalDep,
    periods: Annotated[int, Query(ge=1, le=52)] = 4,
    period_days: Annotated[int, Query(ge=1, le=90)] = 14,
) -> dict[str, Any]:
    """Learning volume across several periods (spec 11 §7).

    A 422 with the reason, rather than a report, when there is too little
    history. spec 11 §10 requires the clear error: a trend report that quietly
    renders two points is more dangerous than none, because somebody will
    present it.
    """
    try:
        report = build_trend(
            request.app.state.knowledge, periods=periods, period_days=period_days
        )
    except NotEnoughHistoryError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc

    return {
        "periods": report.periods,
        "period_days": report.period_days,
        "direction": report.direction,
        "points": report.points,
    }


@router.get("/promotion-candidates")
async def promotion_candidates(
    request: Request,
    principal: PrincipalDep,
    min_projects: Annotated[int, Query(ge=2, le=50)] = 2,
    min_confidence: Annotated[float, Query(ge=0.0, le=1.0)] = 0.7,
) -> dict[str, Any]:
    """Patterns confirmed independently in enough repositories to generalise.

    `min_projects` starts at 2 and cannot be lowered to 1. Repeated dismissal
    within a single repository is one team's opinion held firmly, which is not
    evidence that a rule is noisy everywhere — and allowing 1 would turn this
    endpoint into a list of every entry.
    """
    store = request.app.state.knowledge
    candidates = find_cross_project_candidates(
        store, min_projects=min_projects, min_confidence=min_confidence
    )
    return {
        "candidates": [
            CandidateOut(
                subject=c.subject,
                source_type=c.source_type,
                from_tier=c.from_tier,
                to_tier=c.to_tier,
                repos=c.repos,
                project_count=c.project_count,
                total_observations=c.total_observations,
                mean_confidence=round(c.mean_confidence, 3),
                reasons=c.reasons,
            ).model_dump()
            for c in candidates
        ],
        "policy_proposal": render_policy_proposal(candidates),
        "note": (
            "Nothing here has been applied. Moving an entry between tiers is a "
            "human decision, and changing the Oracle policy is a pull request "
            "(spec 11 §2)."
        ),
    }
