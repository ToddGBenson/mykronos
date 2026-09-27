"""Trust is measured, not assumed (spec 34 §5.2).

`engine.decide` marks a share of delegated agent approvals as `sampled`. This
module is the other half: a person reviews each sampled decision after the
fact and records whether they agree, and a delegation whose agreement falls
below the policy threshold - or whose samples go unreviewed past the deadline
- is suspended until a person grants it again.

A disagreement does not undo the decision. Whether an approved action should
be reversed is its own call (revoking an acceptance, reverting a merge), made
by a person through that action's own route. What a disagreement changes is
how far the operator's trust in that approver extends next time.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from statistics import median
from typing import Any

from sqlalchemy import select

from mykronos.adminauth import Principal
from mykronos.approvals.engine import ApprovalError, _append_event
from mykronos.approvals.policy import ApprovalPolicy
from mykronos.db.models import ApprovalDecision, ApprovalRequest, Delegation
from mykronos.schemas import utcnow

AUTOMATION = "job:delegations"


@dataclass
class SweepResult:
    suspended: list[str] = field(default_factory=list)


def sample_queue(db: Any, *, limit: int = 200) -> list[dict[str, Any]]:
    """Sampled agent decisions no person has reviewed yet, oldest first."""
    with db.session() as session:
        rows = session.execute(
            select(ApprovalDecision, ApprovalRequest)
            .join(ApprovalRequest, ApprovalRequest.id == ApprovalDecision.request_id)
            .where(ApprovalDecision.sampled.is_(True), ApprovalDecision.sample_verdict.is_(None))
            .order_by(ApprovalDecision.created_at)
            .limit(limit)
        ).all()
        return [
            {
                "decision_id": d.id,
                "request_id": r.id,
                "duty": r.duty,
                "tier": r.tier,
                "subject_ref": r.subject_ref,
                "approver": d.approver,
                "family": (d.approver_provenance or {}).get("family"),
                "verdict": d.verdict,
                "rationale": d.rationale,
                "delegation_id": d.delegation_id,
                "decided_at": d.created_at,
            }
            for d, r in rows
        ]


def _agreement(session: Any, delegation_id: str, window: int) -> tuple[int, int]:
    """(agreed, reviewed) over the delegation's last `window` reviewed samples."""
    reviewed = list(
        session.execute(
            select(ApprovalDecision)
            .where(
                ApprovalDecision.delegation_id == delegation_id,
                ApprovalDecision.sample_verdict.is_not(None),
            )
            .order_by(ApprovalDecision.sample_reviewed_at.desc())
            .limit(window)
        ).scalars()
    )
    return sum(1 for d in reviewed if d.sample_verdict == "agree"), len(reviewed)


def _suspend(db: Any, session: Any, delegation: Delegation, reason: str) -> None:
    delegation.suspended_at = utcnow()
    delegation.suspended_reason = reason[:255]
    db.audit(
        session,
        actor=AUTOMATION,
        action="delegation.suspended",
        entity_type="delegation",
        entity_id=delegation.id,
        reason=reason,
    )


def record_sample_verdict(
    db: Any,
    policy: ApprovalPolicy,
    *,
    decision_id: str,
    reviewer: Principal,
    verdict: str,
    note: str = "",
) -> dict[str, Any]:
    """A person's verdict on one sampled agent decision; may suspend its delegation."""
    if not (reviewer.is_human and reviewer.may_write):
        raise ApprovalError(
            "Only a person reviews sampled agent decisions: an agent checking an "
            "agent is the thing the sample exists to check."
        )
    if verdict not in ("agree", "disagree"):
        raise ApprovalError("A sample verdict is agree or disagree.")
    if verdict == "disagree" and not note.strip():
        raise ApprovalError("Say why you disagree; the note is what the approver is measured on.")
    now = utcnow()
    with db.session() as session:
        decision = session.get(ApprovalDecision, decision_id)
        if decision is None or not decision.sampled:
            raise ApprovalError(f"No sampled decision {decision_id}.")
        if decision.sample_verdict is not None:
            raise ApprovalError(
                f"Decision {decision_id} was already reviewed by {decision.sample_reviewed_by}."
            )
        decision.sample_verdict = verdict
        decision.sample_reviewed_by = reviewer.actor
        decision.sample_reviewed_at = now
        _append_event(
            session,
            decision.request_id,
            f"sample.{verdict}",
            reviewer.actor,
            {"decision_id": decision.id, "note": note.strip()},
        )
        db.audit(
            session,
            actor=reviewer.actor,
            action=f"approval.sample_{verdict}",
            entity_type="approval_decision",
            entity_id=decision.id,
            request_id=decision.request_id,
            delegation_id=decision.delegation_id,
            note=note.strip(),
        )
        suspended = False
        agreed, reviewed = 0, 0
        if decision.delegation_id:
            session.flush()
            d = session.get(Delegation, decision.delegation_id)
            agreed, reviewed = _agreement(
                session, decision.delegation_id, policy.delegations.agreement_window
            )
            threshold = policy.delegations.suspend_below_agreement
            if (
                d is not None
                and d.suspended_at is None
                and reviewed
                and agreed / reviewed < threshold
            ):
                _suspend(
                    db,
                    session,
                    d,
                    f"sampled agreement {agreed}/{reviewed} is below {threshold:.0%}",
                )
                suspended = True
        return {
            "decision_id": decision_id,
            "verdict": verdict,
            "agreement": {"agreed": agreed, "reviewed": reviewed},
            "delegation_suspended": suspended,
        }


def sweep(db: Any, policy: ApprovalPolicy, *, now: datetime | None = None) -> SweepResult:
    """Suspend delegations whose sampled decisions have gone unreviewed too long.

    Trust that nobody is checking lapses on its own (spec 34 §5.2): a sample
    queue left alone past the deadline is treated like a failed check.
    """
    now = now or utcnow()
    deadline = now - timedelta(days=policy.delegations.unreviewed_sample_deadline_days)
    result = SweepResult()
    with db.session() as session:
        stale = session.execute(
            select(ApprovalDecision.delegation_id)
            .where(
                ApprovalDecision.sampled.is_(True),
                ApprovalDecision.sample_verdict.is_(None),
                ApprovalDecision.created_at < deadline,
                ApprovalDecision.delegation_id.is_not(None),
            )
            .distinct()
        ).scalars()
        for delegation_id in stale:
            d = session.get(Delegation, delegation_id)
            if d is None or d.suspended_at is not None or d.revoked_at is not None:
                continue
            _suspend(
                db,
                session,
                d,
                "sampled decisions unreviewed for more than "
                f"{policy.delegations.unreviewed_sample_deadline_days} days",
            )
            result.suspended.append(d.id)
    return result


def delegation_stats(db: Any, policy: ApprovalPolicy, delegation_id: str) -> dict[str, Any]:
    """What the governance page shows for one delegation (spec 34 §5.2)."""
    with db.session() as session:
        d = session.get(Delegation, delegation_id)
        if d is None:
            raise ApprovalError(f"No delegation {delegation_id}.")
        pairs = session.execute(
            select(ApprovalDecision, ApprovalRequest)
            .join(ApprovalRequest, ApprovalRequest.id == ApprovalDecision.request_id)
            .where(ApprovalDecision.delegation_id == delegation_id)
        ).all()
        decisions = [p[0] for p in pairs]
        seconds = [(dec.created_at - req.created_at).total_seconds() for dec, req in pairs]
        agreed, reviewed = _agreement(session, delegation_id, policy.delegations.agreement_window)
        by_verdict: dict[str, int] = {}
        for dec in decisions:
            by_verdict[dec.verdict] = by_verdict.get(dec.verdict, 0) + 1
        return {
            "delegation_id": d.id,
            "duty": d.duty,
            "tiers": list(d.tiers or []),
            "approver_families": list(d.approver_families or []),
            "decisions": len(decisions),
            "by_verdict": by_verdict,
            "reject_rate": (by_verdict.get("reject", 0) / len(decisions)) if decisions else None,
            "median_seconds_to_decision": median(seconds) if seconds else None,
            "sampled": sum(1 for dec in decisions if dec.sampled),
            "sample_queue": sum(
                1 for dec in decisions if dec.sampled and dec.sample_verdict is None
            ),
            "agreement": {
                "agreed": agreed,
                "reviewed": reviewed,
                "window": policy.delegations.agreement_window,
                "threshold": policy.delegations.suspend_below_agreement,
            },
            "suspended_at": d.suspended_at,
            "suspended_reason": d.suspended_reason,
            "revoked_at": d.revoked_at,
            "expires_at": d.expires_at,
        }
