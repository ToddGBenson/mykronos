"""Delegations that will not do what they look like they do (TheHub #61547).

Two facts about a live delegation that nothing else says before it costs a
person a pending queue:

**It cannot cover the platform reviewer.** The reviewer runs
`settings.reviewer_model` and is recorded as that family, so a delegation
naming another family (`claude-opus-5` while it runs `claude-opus-5-5`) lets
it approve nothing: every review it starts is refused with 409 and the
request waits, silently, for a person. The check asks
`engine._active_delegation` - the function the preflight's 409 and `decide`
ask - whether any delegation covers the reviewer for each of this one's
tiers, with the reviewer as `decide` will see it. So the notice and the
refusal cannot disagree: a tier another delegation covers is not reported.

**It expires within seven days.** Every duty alike (pull requests, risk
acceptances, finding dispositions). One notice per delegation, worded by its
expiry date rather than a countdown, so the same item stands unchanged from
the day it enters the window until it is renewed or lapses: once, not a new
line every morning. A delegation whose duty, tiers and families another
delegation already covers past its expiry is renewed, and says nothing.

A delegation with `approver_purposes` is for a person-minted credential
(TheHub #61158), never the platform reviewer, so only its expiry is read.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select

from mykronos.approvals.engine import (
    _active_delegation,
    approver_purposes,
    delegation_covers,
    delegation_live,
)
from mykronos.db.models import Delegation

#: How far ahead an expiring delegation is surfaced.
EXPIRY_LEAD = timedelta(days=7)


@dataclass(frozen=True)
class DelegationNotice:
    delegation_id: str
    duty: str
    tiers: tuple[str, ...]
    families: tuple[str, ...]
    #: Naive UTC, as stored.
    expires_at: datetime
    #: The model the reviewer runs, when this delegation cannot cover it;
    #: empty otherwise.
    reviewer_model: str = ""
    #: The tiers the reviewer cannot approve under any live delegation.
    uncovered_tiers: tuple[str, ...] = ()
    #: Within `EXPIRY_LEAD` of `expires_at`, with nothing renewing it.
    expiring: bool = False
    #: The reviewer runs in shadow mode, so the mismatch refuses nothing yet.
    shadow: bool = False

    @property
    def short_id(self) -> str:
        return self.delegation_id[:8]

    def _scope(self) -> str:
        return f"{self.duty} ({'+'.join(self.tiers)})"

    @property
    def what(self) -> str:
        parts = []
        if self.reviewer_model:
            parts.append(
                f"Delegation {self.short_id} for {self._scope()} names approver families "
                f"{list(self.families)}, but the platform reviewer runs {self.reviewer_model}"
            )
        if self.expiring:
            parts.append(
                ("It" if parts else f"Delegation {self.short_id} for {self._scope()}")
                + f" expires {self.expires_at:%Y-%m-%d %H:%M}Z"
            )
        return ". ".join(parts) + "."

    @property
    def so_what(self) -> str:
        parts = []
        if self.reviewer_model:
            scope = f"{self.duty} {'+'.join(self.uncovered_tiers)}"
            if self.shadow:
                # In shadow mode `run_review` skips the preflight: nothing is
                # refused yet, so say what going live would do.
                why = (
                    f"Once the reviewer is live it can approve no {scope} request: each "
                    "review it starts would be refused (409) and the request would wait "
                    "for a person."
                )
            else:
                why = (
                    f"The reviewer can approve no {scope} request: each review it starts "
                    "is refused (409) and the request waits for a person."
                )
            parts.append(f"{why} Propose a delegation naming {self.reviewer_model}.")
        if self.expiring:
            parts.append(
                f"After it lapses no {'/'.join(self.families)} agent approves {self._scope()}; "
                "propose its replacement before then, or let it lapse on purpose."
            )
        return " ".join(parts)


def _covered_at(rows: list[Delegation], d: Delegation, moment: datetime) -> bool:
    """Every (tier, family) of `d` is covered at `moment` by a delegation that
    would satisfy the same approvers: same duty and the same
    `approver_purposes`. A purpose-scoped delegation admits only a
    person-minted credential and a family-only one only the platform reviewer
    (`engine.decide`), so neither renews the other."""
    purposes = sorted(approver_purposes(d))
    successors = [
        o
        for o in rows
        if o.id != d.id and o.duty == d.duty and sorted(approver_purposes(o)) == purposes
    ]
    return all(
        any(delegation_covers(o, tier, family, moment) for o in successors)
        for tier in (d.tiers or [])
        for family in (d.approver_families or [])
    )


def notices(
    db: Any,
    *,
    now: datetime,
    reviewer_model: str | None,
    reviewer_mode: str = "live",
) -> list[DelegationNotice]:
    """One notice per live delegation that needs a person's attention.

    `now` is naive UTC, as delegations are stored. `reviewer_model` is the
    model the reviewer runs (`reviewer.reviewer_family`); None, or
    `reviewer_mode` off, skips the reviewer check: a reviewer that never runs
    needs no delegation.
    """
    from mykronos.approvals.reviewer import prospective_reviewer

    now = now.replace(tzinfo=None) if now.tzinfo else now
    model = (reviewer_model or "") if reviewer_mode != "off" else ""
    reviewer = prospective_reviewer(model) if model else None
    out: list[DelegationNotice] = []
    with db.session() as session:
        rows = list(
            session.execute(
                select(Delegation).order_by(Delegation.expires_at, Delegation.id)
            ).scalars()
        )
        for d in rows:
            if not delegation_live(d, now):
                continue
            uncovered: tuple[str, ...] = ()
            if reviewer is not None and not approver_purposes(d):
                uncovered = tuple(
                    tier
                    for tier in (d.tiers or [])
                    if _active_delegation(session, d.duty, tier, model, now, approver=reviewer)
                    is None
                )
            expiring = d.expires_at - now <= EXPIRY_LEAD and not _covered_at(
                rows, d, d.expires_at
            )
            if not uncovered and not expiring:
                continue
            out.append(
                DelegationNotice(
                    delegation_id=d.id,
                    duty=d.duty,
                    tiers=tuple(d.tiers or []),
                    families=tuple(d.approver_families or []),
                    expires_at=d.expires_at,
                    reviewer_model=model if uncovered else "",
                    uncovered_tiers=uncovered,
                    expiring=expiring,
                    shadow=bool(uncovered) and reviewer_mode == "shadow",
                )
            )
    return out
