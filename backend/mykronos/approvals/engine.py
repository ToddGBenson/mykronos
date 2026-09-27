"""The approval engine: requests, independent decisions, delegations (spec 34 §2-§5).

One mechanism for every governed action. A *duty* (risk acceptance, a PR merge,
an incident action) registers an adapter that turns a subject into a tier and
an evidence bundle; everything else - who may approve, whether they are
independent of the requester, how an approval is bound to what was approved,
and the tamper-evident history - lives here, once.

Three properties everything else rests on:

- **The requester is never an approver.** The one exception is the documented
  single-operator deviation (spec 33 §2.3): one *person* on both sides of a
  human tier, after that tier's cooling-off, re-stating the premise, flagged on
  the decision. It never extends to an agent.
- **An approval is of a digest.** The evidence bundle is frozen and hashed at
  creation; a decision records the digest it evaluated, and a decision against
  any other digest is refused.
- **The tier is computed, not claimed.** The adapter derives it from the
  subject; a requester cannot describe its change as routine.
"""

from __future__ import annotations

import hashlib
import json
import random
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from mykronos.adminauth import ActorKind, Principal
from mykronos.approvals.policy import ApprovalPolicy, Independence, Tier
from mykronos.db.models import ApprovalDecision, ApprovalEvent, ApprovalRequest, Delegation
from mykronos.schemas import utcnow


class ApprovalError(ValueError):
    """A request or decision the rules refuse. The message names the rule."""


@dataclass(frozen=True)
class Subject:
    """What a duty adapter returns: the tier and the frozen evidence."""

    tier: str
    evidence: dict[str, Any]


#: duty -> adapter(subject_ref, context) -> Subject. Registered by the modules
#: that own each duty; a duty with no adapter refuses requests rather than
#: trusting a tier the requester asserts.
Adapter = Callable[[str, dict[str, Any]], Subject]
_ADAPTERS: dict[str, Adapter] = {}


def register_adapter(duty: str, adapter: Adapter) -> None:
    _ADAPTERS[duty] = adapter


#: duty -> what to do, in the approving transaction, once a request of that
#: duty is approved (a delegation goes live; an acceptance becomes active).
OnApproved = Callable[[Session, ApprovalRequest], None]
_ON_APPROVED: dict[str, OnApproved] = {}


def register_on_approved(duty: str, handler: OnApproved) -> None:
    _ON_APPROVED[duty] = handler


#: duty -> the route that builds its evidence. The adapter for such a duty
#: trusts the context it is handed, because the platform built that context;
#: the generic `POST /api/approvals` must therefore refuse it, or a requester
#: could hand-build the evidence and with it the tier.
_DEDICATED_ROUTES: dict[str, str] = {}


def register_dedicated_route(duty: str, route: str) -> None:
    _DEDICATED_ROUTES[duty] = route


def dedicated_route(duty: str) -> str | None:
    return _DEDICATED_ROUTES.get(duty)


def canonical_digest(evidence: dict[str, Any]) -> str:
    """SHA-256 of the bundle in canonical form: sorted keys, no whitespace."""
    blob = json.dumps(evidence, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _snapshot(principal: Principal) -> dict[str, Any]:
    return {
        k: (v.isoformat() if isinstance(v, datetime) else v)
        for k, v in principal.provenance.items()
    }


# -- Independence (spec 34 §2) ------------------------------------------------


def independence_violations(
    *,
    requester_actor: str,
    requester_kind: str,
    requester_provenance: dict[str, Any],
    approver: Principal,
    rules: frozenset[Independence],
    single_operator_same_person_allowed: bool,
) -> list[str]:
    """Every rule the approver fails, each as a sentence naming the rule."""
    failed: list[str] = []
    r_instance = requester_provenance.get("instance")
    r_lineage = set(requester_provenance.get("lineage") or [])
    a_instance = approver.provenance.get("instance")
    a_lineage = set(approver.provenance.get("lineage") or [])

    same_actor = approver.actor == requester_actor
    if Independence.DISTINCT_PRINCIPAL in rules and same_actor:
        both_human = requester_kind == ActorKind.HUMAN.value and approver.is_human
        if not (both_human and single_operator_same_person_allowed):
            failed.append("distinct_principal: the approver is the requester.")

    if Independence.DISTINCT_INSTANCE in rules and r_instance and r_instance == a_instance:
        failed.append("distinct_instance: the same agent run cannot approve its own request.")

    if Independence.OUTSIDE_LINEAGE in rules and approver.is_agent and requester_kind == "agent":
        related = (
            (r_instance and r_instance in a_lineage)
            or (a_instance and a_instance in r_lineage)
            or bool(r_lineage & a_lineage)
        )
        if related:
            failed.append(
                "outside_lineage: the approver shares a lineage with the requester - "
                "a sub-agent, parent or sibling reviewing its own family's work."
            )

    if (
        Independence.FRESH_CONTEXT in rules
        and approver.is_agent
        and not approver.provenance.get("platform_started")
    ):
        failed.append(
                "fresh_context: only a reviewer run the platform started can attest it "
                "saw nothing but the evidence bundle (spec 34 §4.3)."
            )

    if (
        Independence.DIFFERENT_FAMILY in rules
        and approver.is_agent
        and requester_kind == "agent"
        and approver.provenance.get("family") == requester_provenance.get("family")
    ):
        failed.append("different_family: the approver runs the requester's model family.")

    if Independence.HUMAN in rules and not approver.is_human:
        failed.append("human: this tier must be approved by a person.")

    return failed


# -- The hash chain ----------------------------------------------------------


def _append_event(
    session: Session, request_id: str, event: str, actor: str, payload: dict[str, Any]
) -> ApprovalEvent:
    last = session.execute(
        select(ApprovalEvent)
        .where(ApprovalEvent.request_id == request_id)
        .order_by(ApprovalEvent.seq.desc())
        .limit(1)
    ).scalar_one_or_none()
    seq = (last.seq + 1) if last else 0
    prev = last.hash if last else ""
    created = utcnow()
    body = json.dumps(
        {
            "request_id": request_id,
            "seq": seq,
            "event": event,
            "actor": actor,
            "payload": payload,
            "prev_hash": prev,
            "created_at": created.isoformat(),
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    row = ApprovalEvent(
        request_id=request_id,
        seq=seq,
        event=event,
        actor=actor,
        payload=payload,
        prev_hash=prev,
        hash=hashlib.sha256(body.encode("utf-8")).hexdigest(),
        created_at=created,
    )
    session.add(row)
    session.flush()
    return row


def verify_chain(session: Session, request_id: str) -> tuple[bool, str]:
    """Recompute every hash for a request's history. (ok, reason)."""
    rows = list(
        session.execute(
            select(ApprovalEvent)
            .where(ApprovalEvent.request_id == request_id)
            .order_by(ApprovalEvent.seq)
        ).scalars()
    )
    prev = ""
    for expected_seq, row in enumerate(rows):
        if row.seq != expected_seq:
            return False, f"event {expected_seq} is missing"
        if row.prev_hash != prev:
            return False, f"event {row.seq} does not follow event {row.seq - 1}"
        body = json.dumps(
            {
                "request_id": row.request_id,
                "seq": row.seq,
                "event": row.event,
                "actor": row.actor,
                "payload": row.payload,
                "prev_hash": row.prev_hash,
                "created_at": row.created_at.isoformat(),
            },
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        if hashlib.sha256(body.encode("utf-8")).hexdigest() != row.hash:
            return False, f"event {row.seq} was altered"
        prev = row.hash
    return True, f"{len(rows)} event(s) verified"


# -- Requests ----------------------------------------------------------------


def create_request(
    db: Any,
    policy: ApprovalPolicy,
    *,
    duty: str,
    subject_ref: str,
    requested_by: Principal,
    statement: str = "",
    context: dict[str, Any] | None = None,
) -> ApprovalRequest:
    duty_policy = policy.duty(duty)
    if requested_by.kind.value not in duty_policy.requesters:
        raise ApprovalError(
            f"A {requested_by.kind.value} may not request '{duty}'; this duty accepts "
            f"requests from: {', '.join(sorted(duty_policy.requesters))}."
        )
    adapter = _ADAPTERS.get(duty)
    if adapter is None:
        raise ApprovalError(
            f"No adapter computes the tier for '{duty}' yet, and a tier the requester "
            "asserts is not accepted (spec 34 §3.2)."
        )
    subject = adapter(subject_ref, context or {})
    tier = duty_policy.tiers.get(subject.tier)
    if tier is None:
        raise ApprovalError(f"Duty '{duty}' has no tier '{subject.tier}'.")

    now = utcnow()
    with db.session() as session:
        if not _satisfiable(session, tier, duty, now):
            raise ApprovalError(
                f"No approver can satisfy '{duty}' tier '{tier.name}': it admits only "
                "agents under a delegation, and no active delegation covers it. Refused "
                "now rather than left pending forever (spec 34 §3.1)."
            )
        request = ApprovalRequest(
            duty=duty,
            tier=tier.name,
            subject_ref=subject_ref,
            evidence=subject.evidence,
            evidence_digest=canonical_digest(subject.evidence),
            requester_statement=statement,
            requested_by=requested_by.actor,
            requester_kind=requested_by.kind.value,
            requester_provenance=_snapshot(requested_by),
            state="pending",
            policy_version=policy.version,
            created_at=now,
            expires_at=now + timedelta(hours=policy.request_ttl_hours),
        )
        session.add(request)
        session.flush()
        _append_event(
            session,
            request.id,
            "requested",
            requested_by.actor,
            {
                "duty": duty,
                "tier": tier.name,
                "subject_ref": subject_ref,
                "evidence_digest": request.evidence_digest,
                "requester_kind": request.requester_kind,
            },
        )
        db.audit(
            session,
            actor=requested_by.actor,
            action="approval.requested",
            entity_type="approval_request",
            entity_id=request.id,
            duty=duty,
            tier=tier.name,
            subject_ref=subject_ref,
        )
        session.expunge(request)
        return request


def _satisfiable(session: Session, tier: Tier, duty: str, now: datetime) -> bool:
    if tier.admits("human"):
        return True
    return _active_delegation(session, duty, tier.name, None, now) is not None


def _active_delegation(
    session: Session, duty: str, tier: str, family: str | None, now: datetime
) -> Delegation | None:
    rows = session.execute(select(Delegation).where(Delegation.duty == duty)).scalars()
    for d in rows:
        if d.revoked_at or d.suspended_at or d.expires_at <= now:
            continue
        if tier not in (d.tiers or []):
            continue
        if family is not None and family not in (d.approver_families or []):
            continue
        return d
    return None


# -- Decisions ---------------------------------------------------------------


@dataclass(frozen=True)
class DecisionOutcome:
    request_id: str
    state: str
    decision_id: str
    same_person: bool
    sampled: bool


def decide(
    db: Any,
    policy: ApprovalPolicy,
    *,
    request_id: str,
    approver: Principal,
    verdict: str,
    rationale: str,
    evidence_digest: str,
    on_approved: Callable[[Session, ApprovalRequest], None] | None = None,
    rng: random.Random | None = None,
) -> DecisionOutcome:
    if verdict not in ("approve", "reject", "needs_info"):
        raise ApprovalError("verdict must be approve, reject or needs_info.")
    if not rationale.strip():
        raise ApprovalError(
            "A decision needs a rationale. An approver that can say yes without saying "
            "why is not a check (spec 34 §4.3)."
        )
    now = utcnow()
    with db.session() as session:
        request = session.get(ApprovalRequest, request_id)
        if request is None:
            raise ApprovalError(f"No approval request {request_id}.")
        if request.state != "pending":
            raise ApprovalError(f"Request {request_id} is {request.state}, not pending.")
        if request.expires_at <= now:
            request.state = "expired"
            _append_event(session, request.id, "expired", "platform", {})
            raise ApprovalError(f"Request {request_id} expired at {request.expires_at}.")
        if evidence_digest != request.evidence_digest:
            raise ApprovalError(
                "The decision names a different evidence digest from the request's. An "
                "approval is of exactly what was frozen, and this is not it."
            )

        # The one rule no policy can relax, checked first so the refusal names
        # it: an agent never approves its own request, whatever delegations or
        # tiers exist (spec 34 §3.1). The single-operator exception is for one
        # *person*, handled with the other independence rules below.
        if approver.actor == request.requested_by and not approver.is_human:
            raise ApprovalError(
                "Not independent of the requester: distinct_principal: the approver "
                "is the requester."
            )

        duty_policy = policy.duty(request.duty)
        tier = duty_policy.tiers[request.tier]
        approver_class = tier.admits(approver.kind.value)
        if approver_class is None:
            raise ApprovalError(
                f"'{request.duty}' tier '{tier.name}' does not admit a "
                f"{approver.kind.value} approver."
            )

        delegation: Delegation | None = None
        if approver.is_agent:
            delegation = _active_delegation(
                session, request.duty, tier.name, approver.provenance.get("family"), now
            )
            if delegation is None:
                raise ApprovalError(
                    f"No active delegation lets a {approver.provenance.get('family')} agent "
                    f"approve '{request.duty}' tier '{tier.name}' (spec 34 §5)."
                )

        same_person = approver.actor == request.requested_by
        allowed_same = (
            policy.single_operator
            and same_person
            and approver.is_human
            and request.requester_kind == ActorKind.HUMAN.value
        )
        violations = independence_violations(
            requester_actor=request.requested_by,
            requester_kind=request.requester_kind,
            requester_provenance=request.requester_provenance or {},
            approver=approver,
            rules=tier.independence,
            single_operator_same_person_allowed=allowed_same,
        )
        if violations:
            raise ApprovalError("Not independent of the requester: " + " ".join(violations))
        if allowed_same and verdict == "approve":
            ready_at = request.created_at + timedelta(hours=tier.cooling_off_hours)
            if now < ready_at:
                raise ApprovalError(
                    f"Same-person approval under single_operator must wait for the "
                    f"'{tier.name}' cooling-off: not before {ready_at.isoformat()}."
                )

        sampled = bool(
            approver.is_agent
            and delegation is not None
            and (rng or random).random() < float(delegation.sampling or 0)
        )
        decision = ApprovalDecision(
            request_id=request.id,
            approver=approver.actor,
            approver_kind=approver.kind.value,
            approver_provenance=_snapshot(approver),
            verdict=verdict,
            rationale=rationale.strip(),
            evidence_digest=evidence_digest,
            delegation_id=delegation.id if delegation else None,
            same_person=bool(allowed_same),
            sampled=sampled,
            created_at=now,
        )
        session.add(decision)
        session.flush()
        _append_event(
            session,
            request.id,
            f"decision.{verdict}",
            approver.actor,
            {
                "decision_id": decision.id,
                "approver_kind": approver.kind.value,
                "delegation_id": decision.delegation_id,
                "same_person": decision.same_person,
                "evidence_digest": evidence_digest,
            },
        )

        if verdict == "reject":
            request.state = "rejected"
            request.decided_at = now
        elif verdict == "approve":
            approvals = session.execute(
                select(ApprovalDecision).where(
                    ApprovalDecision.request_id == request.id,
                    ApprovalDecision.verdict == "approve",
                )
            ).scalars()
            if len({d.approver for d in approvals}) >= tier.quorum:
                request.state = "approved"
                request.decided_at = now
                _append_event(session, request.id, "approved", "platform", {})
                handler = on_approved or _ON_APPROVED.get(request.duty)
                if handler is not None:
                    handler(session, request)

        db.audit(
            session,
            actor=approver.actor,
            action=f"approval.{verdict}",
            entity_type="approval_request",
            entity_id=request.id,
            duty=request.duty,
            tier=request.tier,
            same_person=decision.same_person,
            delegation_id=decision.delegation_id,
        )
        return DecisionOutcome(
            request_id=request.id,
            state=request.state,
            decision_id=decision.id,
            same_person=decision.same_person,
            sampled=sampled,
        )


# -- Delegations (spec 34 §5) -------------------------------------------------


def delegation_grant_adapter(subject_ref: str, context: dict[str, Any]) -> Subject:
    """The grant itself is the evidence: what would be trusted, for how long."""
    proposal = context.get("proposal") or {}
    required = ("duty", "tiers", "approver_families", "expires_at")
    missing = [k for k in required if not proposal.get(k)]
    if missing:
        raise ApprovalError(f"A delegation proposal needs: {', '.join(missing)}.")
    return Subject(tier="any", evidence={"proposal": proposal})





def propose_delegation(
    db: Any,
    policy: ApprovalPolicy,
    *,
    requested_by: Principal,
    duty: str,
    tiers: list[str],
    approver_families: list[str],
    expires_at: datetime,
    sampling: float | None = None,
    constraints: dict[str, Any] | None = None,
    statement: str = "",
) -> ApprovalRequest:
    duty_policy = policy.duty(duty)
    for t in tiers:
        tier = duty_policy.tiers.get(t)
        if tier is None:
            raise ApprovalError(f"Duty '{duty}' has no tier '{t}'.")
        admits = tier.admits("agent")
        if admits is None or not admits.delegation_required:
            raise ApprovalError(
                f"'{duty}' tier '{t}' does not admit delegated agents; the policy file "
                "says who may approve it, and a delegation cannot widen that."
            )
    if not approver_families:
        raise ApprovalError("Name at least one model family the delegation trusts.")
    limit = utcnow() + timedelta(days=policy.delegations.max_days)
    if expires_at > limit:
        raise ApprovalError(
            f"A delegation may run at most {policy.delegations.max_days} days; trust that "
            "is never re-granted is trust nobody is checking."
        )
    proposal = {
        "duty": duty,
        "tiers": sorted(tiers),
        "approver_families": sorted(approver_families),
        "expires_at": expires_at.isoformat(),
        "sampling": policy.delegations.default_sampling if sampling is None else sampling,
        "constraints": constraints or {},
    }
    return create_request(
        db,
        policy,
        duty="delegation_grant",
        subject_ref=f"delegation:{duty}:{','.join(sorted(tiers))}",
        requested_by=requested_by,
        statement=statement,
        context={"proposal": proposal},
    )


def activate_delegation(session: Session, request: ApprovalRequest) -> None:
    """`on_approved` for `delegation_grant`: the approved proposal becomes live."""
    p = request.evidence["proposal"]
    session.add(
        Delegation(
            granted_by=request.requested_by,
            grant_request_id=request.id,
            duty=p["duty"],
            tiers=list(p["tiers"]),
            approver_families=list(p["approver_families"]),
            constraints=dict(p.get("constraints") or {}),
            sampling=float(p.get("sampling", 0.2)),
            expires_at=datetime.fromisoformat(p["expires_at"]),
        )
    )


def revoke_delegation(db: Any, *, delegation_id: str, revoked_by: Principal) -> None:
    if not (revoked_by.is_human and revoked_by.may_write):
        raise ApprovalError("Only a person may revoke a delegation.")
    with db.session() as session:
        d = session.get(Delegation, delegation_id)
        if d is None or d.revoked_at is not None:
            raise ApprovalError(f"No active delegation {delegation_id}.")
        d.revoked_at = utcnow()
        d.revoked_by = revoked_by.actor
        db.audit(
            session,
            actor=revoked_by.actor,
            action="delegation.revoked",
            entity_type="delegation",
            entity_id=delegation_id,
        )


register_adapter("delegation_grant", delegation_grant_adapter)
register_dedicated_route("delegation_grant", "/api/approvals/delegations")
register_on_approved("delegation_grant", activate_delegation)
