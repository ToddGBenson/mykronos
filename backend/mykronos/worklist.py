"""Claiming and snoozing a queue row (spec 27 §3).

The triage queue could be filtered and dispositioned and groomed, and it had
no idea who was working on it. Two people triaging at once could not see each
other, and nothing recorded that triage had happened at all.

**Claim, not assign.** `Finding.owner` (spec 24 §1) says who is *answerable*
for a finding — copied from CODEOWNERS, stable, about the code. A claim says
who is *doing it now* — self-service, short-lived, about the week. Conflating
them would mean either a person cannot pick up a neighbouring team's work
without rewriting ownership, or ownership drifts every time somebody helps
out.

**Claims expire, visibly.** An abandoned claim that hid a row for ever would
be worse than no claim at all, and one that vanished silently would be
indistinguishable from work nobody started. The row keeps its expiry so the
queue can show it lapsing.

**A snooze is about the week, not about the vulnerability.** It never touches
`Finding.status`: a snoozed finding is still open, still scores, still goes
overdue. That separation is what stops "not now" becoming "not ever" — the
drift spec 24 §3 added expiry dates to prevent for acceptances.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from mykronos.db.models import TriageState
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

#: How long an unreleased claim stands. A week: long enough for somebody to
#: pick something up on Monday and finish it on Friday, short enough that a
#: claim made before a holiday does not hide a critical for a month.
DEFAULT_CLAIM_DAYS = 7

#: How close to lapsing a claim has to be before the queue says so.
CLAIM_WARNING_DAYS = 2


class WorklistError(ValueError):
    """Something a person needs to correct, not a server fault."""


@dataclass(frozen=True)
class RowState:
    """What the queue renders for one finding."""

    claimed_by: str | None = None
    claim_expires_at: datetime | None = None
    claim_lapsing: bool = False
    snoozed_until: date | None = None
    snooze_reason: str | None = None

    @property
    def snoozed(self) -> bool:
        return self.snoozed_until is not None


def _row(session: Session, finding_id: str) -> TriageState | None:
    return session.execute(
        select(TriageState).where(TriageState.finding_id == finding_id)
    ).scalars().first()


def _ensure(session: Session, finding_id: str, repo_full_name: str) -> TriageState:
    row = _row(session, finding_id)
    if row is None:
        row = TriageState(finding_id=finding_id, repo_full_name=repo_full_name)
        session.add(row)
        session.flush()
    return row


def claim(
    session: Session,
    finding_id: str,
    repo_full_name: str,
    *,
    by: str,
    days: int = DEFAULT_CLAIM_DAYS,
    now: datetime | None = None,
) -> RowState:
    """Take a row, unless somebody else already holds it.

    First write wins, and the loser is told who holds it. A silent overwrite
    here is two people fixing the same finding, which is the whole thing this
    exists to prevent.
    """
    if not by.strip():
        raise WorklistError("A claim needs a handle; an anonymous claim tells nobody anything.")

    moment = now or utcnow()
    row = _ensure(session, finding_id, repo_full_name)

    held = row.claimed_by and row.claim_expires_at and row.claim_expires_at > moment
    if held and row.claimed_by != by:
        raise WorklistError(
            f"{finding_id[:12]} is claimed by {row.claimed_by} until "
            f"{row.claim_expires_at:%Y-%m-%d}. Ask them, or wait for it to lapse."
        )

    row.claimed_by = by
    row.claimed_at = moment
    row.claim_expires_at = moment + timedelta(days=days)
    session.flush()
    return state_of(row, now=moment)


def release(session: Session, finding_id: str, *, now: datetime | None = None) -> RowState:
    """Hand a row back. Keeps the snooze, which is a separate decision."""
    row = _row(session, finding_id)
    if row is None:
        return RowState()
    row.claimed_by = None
    row.claimed_at = None
    row.claim_expires_at = None
    session.flush()
    return state_of(row, now=now)


def snooze(
    session: Session,
    finding_id: str,
    repo_full_name: str,
    *,
    until: date,
    reason: str,
    now: datetime | None = None,
) -> RowState:
    """Put a row down until a date, without deciding anything about it."""
    if not reason.strip():
        raise WorklistError(
            "A snooze needs a reason. A row that reappears with none is a "
            "deferral nobody can review."
        )
    moment = now or utcnow()
    if until <= moment.date():
        raise WorklistError(
            f"{until.isoformat()} is not in the future — the row would come "
            "straight back, which is a confusing way to learn you typed the "
            "wrong date."
        )

    row = _ensure(session, finding_id, repo_full_name)
    row.snoozed_until = until
    row.snooze_reason = reason.strip()
    session.flush()
    return state_of(row, now=moment)


def wake(session: Session, finding_id: str, *, now: datetime | None = None) -> RowState:
    """Bring a snoozed row back early. Keeps the claim."""
    row = _row(session, finding_id)
    if row is None:
        return RowState()
    row.snoozed_until = None
    row.snooze_reason = None
    session.flush()
    return state_of(row, now=now)


def state_of(row: TriageState | None, *, now: datetime | None = None) -> RowState:
    """Render one row's state, with expiry already applied.

    An expired claim reads as unclaimed here rather than being deleted: the
    stored row is what lets the queue say "lapsed" instead of quietly
    forgetting somebody meant to do this.
    """
    if row is None:
        return RowState()
    moment = now or utcnow()

    expired = row.claim_expires_at is not None and row.claim_expires_at <= moment
    claimed_by = None if expired else row.claimed_by
    lapsing = bool(
        claimed_by
        and row.claim_expires_at
        and row.claim_expires_at - moment <= timedelta(days=CLAIM_WARNING_DAYS)
    )

    still_snoozed = row.snoozed_until is not None and row.snoozed_until > moment.date()
    return RowState(
        claimed_by=claimed_by,
        claim_expires_at=row.claim_expires_at if claimed_by else None,
        claim_lapsing=lapsing,
        snoozed_until=row.snoozed_until if still_snoozed else None,
        snooze_reason=row.snooze_reason if still_snoozed else None,
    )


def states_for(
    session: Session, finding_ids: list[str], *, now: datetime | None = None
) -> dict[str, RowState]:
    """One query for a whole page, not one per row."""
    if not finding_ids:
        return {}
    rows = session.execute(
        select(TriageState).where(TriageState.finding_id.in_(finding_ids))
    ).scalars()
    return {row.finding_id: state_of(row, now=now) for row in rows}


def purge_for_repo(session: Session, repo_full_name: str) -> int:
    """Drop a repository's rows when it is offboarded.

    Queue state about a repository nobody scans any more is not work.
    """
    rows = session.execute(
        select(TriageState).where(TriageState.repo_full_name == repo_full_name)
    ).scalars().all()
    for row in rows:
        session.delete(row)
    return len(rows)


def as_dict(state: RowState) -> dict[str, Any]:
    return {
        "claimed_by": state.claimed_by,
        "claim_expires_at": state.claim_expires_at,
        "claim_lapsing": state.claim_lapsing,
        "snoozed_until": state.snoozed_until,
        "snooze_reason": state.snooze_reason,
    }
