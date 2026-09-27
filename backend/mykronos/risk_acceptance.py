"""Risk acceptance as a governed decision (spec 33, phase 1).

A risk acceptance used to be `status = accepted_risk` written onto each finding
by whoever held the admin token. Here it is a record: a scope that chose the
findings, a deviation type saying what kind of claim is being made, a residual
risk rating that decides who must approve, premises, milestones, and a named
owner - approved through the spec 34 engine by someone other than the
requester.

**The tier is computed, not chosen.** Residual severity is likelihood x impact
(RA-3). For `vendor_dependency` and `operational_requirement` it can never be
lower than the worst scanner severity in scope - nothing in those claims lowers
the risk. Only `risk_adjustment`, which must name a premise the platform can
check, may rate the residual below the scanner. A requester cannot choose a low
tier to get an easier approver.

**The lake still carries the status.** On approval, the covered findings are
stamped `accepted_risk` with the record's expiry and reason code, so the Oracle,
the dashboard and `sweep_acceptances` keep working unchanged.
"""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from mykronos.adminauth import Principal
from mykronos.approvals.engine import (
    ApprovalError,
    Subject,
    _append_event,
    create_request,
    register_adapter,
    register_dedicated_route,
    register_on_approved,
)
from mykronos.approvals.policy import ApprovalPolicy
from mykronos.db.models import (
    ApprovalDecision,
    ApprovalRequest,
    AuditLogEntry,
    RiskAcceptance,
    ThreatIntelMatch,
    new_id,
)
from mykronos.fingerprint import image_repository
from mykronos.lake.catalog import Catalog
from mykronos.lake.mutate import locate_findings, update_findings
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

SEVERITIES = ("low", "medium", "high", "critical")
LEVELS = ("low", "moderate", "high", "very_high")
DEVIATION_TYPES = ("vendor_dependency", "risk_adjustment", "operational_requirement")
RESPONSES = ("accept", "transfer")
#: spec 33 §4.1. Monitors for these arrive in phase 3; phase 1 requires that a
#: `risk_adjustment` names at least one, so the premise is checkable the day
#: its monitor ships rather than prose that can never be re-evaluated.
PREMISE_TYPES = (
    "no_fixed_version",
    "port_not_published",
    "firewall_scope",
    "image_role",
    "container_command",
    "not_internet_facing",
    "not_kev_listed",
    "epss_below",
    "path_unreachable",
)
#: Statuses a record can still act in.
LIVE = ("active", "review_due")


class RiskAcceptanceError(ValueError):
    """A proposal the rules refuse. The message names the rule."""


# -- Binding to the lake -------------------------------------------------------

#: Set at startup. `on_approved` runs inside the engine's database transaction
#: and needs the lake too; passing it through the generic engine would teach
#: the engine about one duty's storage.
_CATALOG: Catalog | None = None


def bind(catalog: Catalog) -> None:
    global _CATALOG
    _CATALOG = catalog


def _catalog() -> Catalog:
    if _CATALOG is None:
        raise RuntimeError("risk_acceptance.bind(catalog) was never called.")
    return _CATALOG


# -- Residual risk (RA-3) ------------------------------------------------------


def residual_severity(likelihood: str, impact: str) -> str:
    """A 4x4 likelihood x impact matrix onto the scanner's severity scale."""
    try:
        score = LEVELS.index(likelihood) + LEVELS.index(impact)
    except ValueError as exc:
        raise RiskAcceptanceError(
            f"Likelihood and impact must each be one of {', '.join(LEVELS)}."
        ) from exc
    if score <= 1:
        return "low"
    if score <= 3:
        return "medium"
    if score <= 5:
        return "high"
    return "critical"


def _worst(severities: list[str]) -> str:
    ranked = [s for s in severities if s in SEVERITIES]
    return max(ranked, key=SEVERITIES.index) if ranked else "low"


def reason_code_for(deviation_type: str, compensating_controls: list[dict[str, Any]]) -> str:
    """The row-level reason code the lake and the Oracle already understand."""
    if deviation_type == "vendor_dependency":
        return "no_vendor_fix"
    if deviation_type == "operational_requirement":
        return "cost_exceeds_risk"
    return "compensating_control" if compensating_controls else "not_exploitable_here"


# -- Scope (spec 33 §1.2) ------------------------------------------------------


@dataclass(frozen=True)
class MatchedFinding:
    finding_id: str
    rule_id: str
    package: str
    severity: str
    location: str
    image: str
    fixed_version: str
    status: str


def validate_scope(scope: dict[str, Any]) -> None:
    capability = str(scope.get("capability") or "").strip()
    if not capability:
        raise RiskAcceptanceError("A scope names its capability.")
    if capability == "containers" and not scope.get("image"):
        raise RiskAcceptanceError(
            "A container scope names its image: a decision about one image must not "
            "cover another (D-127)."
        )
    wildcard_rules = scope.get("rule_ids") in (None, [], ["*"])
    if capability != "containers" and wildcard_rules and not scope.get("file_paths"):
        raise RiskAcceptanceError(
            "A code scope names its rules or its files; a scope matching every finding "
            "in a repository is refused (spec 33 §1.2)."
        )
    if scope.get("fixed_version", "any") not in ("absent", "present", "any"):
        raise RiskAcceptanceError("scope.fixed_version is absent, present or any.")


def match_scope(
    catalog: Catalog,
    repo: str,
    scope: dict[str, Any],
    statuses: tuple[str, ...] = ("open",),
) -> list[MatchedFinding]:
    validate_scope(scope)
    if not catalog.all_files("findings"):
        return []
    placeholders = ", ".join("?" for _ in statuses)
    rows = catalog.query(
        "SELECT finding_id, rule_id, coalesce(package_name, ''), lower(severity), "
        "       coalesce(file_path, ''), "
        "       coalesce(json_extract_string(raw_finding_json, '$.image'), ''), "
        "       coalesce(json_extract_string(raw_finding_json, '$.fixed_version'), ''), "
        "       status "
        "FROM findings WHERE repo_full_name = ? AND capability = ? "
        f"AND status IN ({placeholders})",
        [repo, scope["capability"], *statuses],
    )
    want_image = image_repository(scope["image"]) if scope.get("image") else None
    rules = set(scope.get("rule_ids") or ["*"])
    severities = set(scope.get("severities") or SEVERITIES)
    packages = set(scope.get("package_names") or [])
    paths = tuple(scope.get("file_paths") or [])
    fixed = scope.get("fixed_version", "any")
    out: list[MatchedFinding] = []
    for fid, rule, pkg, sev, path, image, fixed_version, status in rows:
        if want_image is not None and (not image or image_repository(image) != want_image):
            continue
        if "*" not in rules and rule not in rules:
            continue
        if sev not in severities:
            continue
        if packages and pkg not in packages:
            continue
        if paths and not str(path).startswith(paths):
            continue
        has_fix = bool(str(fixed_version).strip())
        if (fixed == "absent" and has_fix) or (fixed == "present" and not has_fix):
            continue
        out.append(
            MatchedFinding(
                finding_id=str(fid),
                rule_id=str(rule),
                package=str(pkg),
                severity=str(sev),
                location=str(path),
                image=str(image),
                fixed_version=str(fixed_version),
                status=str(status),
            )
        )
    return out


def _summary(matched: list[MatchedFinding]) -> dict[str, Any]:
    by_severity = Counter(m.severity for m in matched)
    by_package = Counter(m.package or m.location for m in matched)
    return {
        "findings": len(matched),
        "by_severity": dict(sorted(by_severity.items())),
        "top_packages": dict(by_package.most_common(15)),
        "with_fixed_version": sum(1 for m in matched if m.fixed_version.strip()),
        "images": sorted({image_repository(m.image) for m in matched if m.image}),
    }


# -- Validation ----------------------------------------------------------------


def _kev_listed(session: Session, rule_ids: set[str]) -> list[str]:
    cves = [r for r in rule_ids if r.upper().startswith("CVE-")]
    if not cves:
        return []
    rows = session.execute(
        select(ThreatIntelMatch.cve_id).where(
            ThreatIntelMatch.cve_id.in_(cves), ThreatIntelMatch.in_kev.is_(True)
        )
    ).scalars()
    return sorted(rows)


def _validate(
    *,
    policy: ApprovalPolicy,
    deviation_type: str,
    response: str,
    residual: str,
    premises: list[dict[str, Any]],
    milestones: list[dict[str, Any]],
    risk_owner: str,
    requested_until: date,
    renewal_count: int,
    legacy: bool,
) -> None:
    limits = policy.risk_acceptance
    if deviation_type not in DEVIATION_TYPES:
        raise RiskAcceptanceError(f"deviation_type is one of {', '.join(DEVIATION_TYPES)}.")
    if response not in RESPONSES:
        raise RiskAcceptanceError(
            f"response is one of {', '.join(RESPONSES)}; mitigate and avoid are POA&M "
            "items, not acceptances (spec 33 §1.3)."
        )
    owner = risk_owner.strip()
    if not owner or owner.startswith("agent:"):
        raise RiskAcceptanceError(
            "A risk acceptance names the person who answers for it; an agent or a blank "
            "is not a risk owner (spec 33 §1.1)."
        )
    if (
        deviation_type == "operational_requirement"
        and residual == "critical"
        and limits.refuse_critical_operational_requirement
    ):
        raise RiskAcceptanceError(
            "A critical residual risk cannot be an operational requirement: that is a "
            "conversation about the architecture, not an acceptance."
        )
    for p in premises:
        if p.get("type") not in PREMISE_TYPES:
            raise RiskAcceptanceError(
                f"Premise type '{p.get('type')}' is not one the platform can monitor: "
                f"{', '.join(PREMISE_TYPES)}."
            )
    if deviation_type == "risk_adjustment" and not premises and not legacy:
        raise RiskAcceptanceError(
            "A risk adjustment names at least one premise the platform can check. A "
            "control nobody can point at cannot be checked when it is removed."
        )
    if not any(m.get("ends_weakness") for m in milestones) and not legacy:
        raise RiskAcceptanceError(
            "At least one milestone must end the weakness (spec 33 §3): an acceptance "
            "with no way out is a deferral."
        )
    if renewal_count > limits.max_renewals.get(residual, 0):
        raise RiskAcceptanceError(
            f"A {residual} acceptance may be renewed {limits.max_renewals.get(residual, 0)} "
            "time(s). Beyond that the answer is remediation, avoidance or re-architecture."
        )
    if not legacy:
        cap = limits.max_duration_days.get(residual, 0)
        if requested_until > utcnow().date() + timedelta(days=cap):
            raise RiskAcceptanceError(
                f"A {residual} acceptance runs at most {cap} days; requested until "
                f"{requested_until.isoformat()}."
            )


# -- Proposing -----------------------------------------------------------------


def _snapshot(record: RiskAcceptance, matched: list[MatchedFinding]) -> dict[str, Any]:
    """The evidence an approver sees, frozen into the request's digest."""
    return {
        "risk_acceptance_id": record.id,
        "repo": record.repo_full_name,
        "scope": record.scope,
        "response": record.response,
        "deviation_type": record.deviation_type,
        "justification": record.justification,
        "residual": {
            "likelihood": record.residual_likelihood,
            "impact": record.residual_impact,
            "severity": record.residual_severity,
        },
        "premises": record.premises,
        "compensating_controls": record.compensating_controls,
        "milestones": record.milestones,
        "risk_owner": record.risk_owner,
        "requested_until": record.requested_until.isoformat() if record.requested_until else None,
        "legacy": record.legacy,
        "renews_id": record.renews_id,
        "renewal_count": record.renewal_count,
        "matched": _summary(matched),
        "covered_finding_ids": sorted(m.finding_id for m in matched),
    }


def _adapter(subject_ref: str, context: dict[str, Any]) -> Subject:
    snapshot = context.get("snapshot")
    if not snapshot or snapshot.get("risk_acceptance_id") != subject_ref:
        raise ApprovalError(
            "Risk acceptance requests are created through /api/risk-acceptances, which "
            "computes the tier from the record."
        )
    return Subject(tier=snapshot["residual"]["severity"], evidence=snapshot)


def propose(
    db: Any,
    catalog: Catalog,
    policy: ApprovalPolicy,
    *,
    requested_by: Principal,
    repo: str,
    scope: dict[str, Any],
    deviation_type: str,
    justification: str,
    residual_likelihood: str,
    residual_impact: str,
    risk_owner: str,
    requested_until: date,
    premises: list[dict[str, Any]] | None = None,
    compensating_controls: list[dict[str, Any]] | None = None,
    milestones: list[dict[str, Any]] | None = None,
    response: str = "accept",
    legacy: bool = False,
    renews: RiskAcceptance | None = None,
    statuses: tuple[str, ...] = ("open",),
    matched: list[MatchedFinding] | None = None,
) -> tuple[RiskAcceptance, ApprovalRequest]:
    if not justification.strip():
        raise RiskAcceptanceError("A justification says why this is true here.")
    premises = list(premises or [])
    controls = list(compensating_controls or [])
    milestones = list(milestones or [])
    if matched is None:
        matched = match_scope(catalog, repo, scope, statuses)
    else:
        validate_scope(scope)
    if not matched:
        raise RiskAcceptanceError("The scope matches no findings; there is nothing to accept.")

    residual = residual_severity(residual_likelihood, residual_impact)
    if deviation_type != "risk_adjustment":
        residual = max(residual, _worst([m.severity for m in matched]), key=SEVERITIES.index)
    renewal_count = (renews.renewal_count + 1) if renews else 0
    _validate(
        policy=policy,
        deviation_type=deviation_type,
        response=response,
        residual=residual,
        premises=premises,
        milestones=milestones,
        risk_owner=risk_owner,
        requested_until=requested_until,
        renewal_count=renewal_count,
        legacy=legacy,
    )
    if deviation_type == "vendor_dependency" and any(m.fixed_version.strip() for m in matched):
        raise RiskAcceptanceError(
            "A vendor dependency says no fix exists, and findings in this scope name one. "
            "Narrow the scope with fixed_version: absent, or choose another response."
        )
    with db.session() as session:
        kev = _kev_listed(session, {m.rule_id for m in matched})
    if kev and policy.risk_acceptance.refuse_kev_listed:
        raise RiskAcceptanceError(
            f"KEV-listed CVEs cannot be accepted, only mitigated: {', '.join(kev[:10])}."
        )

    record = RiskAcceptance(
        id=new_id(),
        repo_full_name=repo,
        scope=scope,
        covered_finding_ids=sorted(m.finding_id for m in matched),
        response=response,
        deviation_type=deviation_type,
        justification=justification.strip(),
        residual_likelihood=residual_likelihood,
        residual_impact=residual_impact,
        residual_severity=residual,
        premises=premises,
        compensating_controls=controls,
        milestones=milestones,
        risk_owner=risk_owner.strip(),
        requested_by=requested_by.actor,
        status="pending_approval",
        legacy=legacy,
        renews_id=renews.id if renews else None,
        renewal_count=renewal_count,
        requested_until=requested_until,
        first_effective_at=renews.first_effective_at if renews else None,
    )
    approval = create_request(
        db,
        policy,
        duty="risk_acceptance",
        subject_ref=record.id,
        requested_by=requested_by,
        statement=justification.strip(),
        context={"snapshot": _snapshot(record, matched)},
    )
    record.approval_request_id = approval.id
    with db.session() as session:
        session.add(record)
        db.audit(
            session,
            actor=requested_by.actor,
            action="risk_acceptance.requested",
            entity_type="risk_acceptance",
            entity_id=record.id,
            repo=repo,
            residual_severity=residual,
            deviation_type=deviation_type,
            findings=len(matched),
            legacy=legacy,
            approval_request_id=approval.id,
        )
        session.flush()
        session.expunge(record)
    return record, approval


# -- Approval ------------------------------------------------------------------


def _stamp_findings(record: RiskAcceptance) -> int:
    if not record.covered_finding_ids or record.expires_at is None:
        return 0
    catalog = _catalog()
    outcome = update_findings(
        catalog,
        locate_findings(catalog, list(record.covered_finding_ids)),
        "status = 'accepted_risk', accepted_until = ?, accepted_reason_code = ?, "
        "resolved_at = coalesce(resolved_at, ?)",
        [
            record.expires_at,
            reason_code_for(record.deviation_type, record.compensating_controls or []),
            utcnow(),
        ],
    )
    return outcome.count


def on_approved(session: Session, request: ApprovalRequest) -> None:
    record = session.get(RiskAcceptance, request.subject_ref)
    if record is None:
        raise ApprovalError(f"No risk acceptance {request.subject_ref}.")
    # Only the request the record was proposed with can activate it. Any
    # other request for the same record carries evidence - and a tier, and a
    # duration cap - that the platform did not compute from the record.
    if record.approval_request_id != request.id or record.status != "pending_approval":
        raise ApprovalError(
            f"Risk acceptance {record.id} was proposed with approval request "
            f"{record.approval_request_id} and is {record.status}; approving request "
            f"{request.id} cannot activate it."
        )
    policy_limits_days = _limits_days(request)
    now = utcnow()
    approver = session.execute(
        select(ApprovalDecision.approver)
        .where(ApprovalDecision.request_id == request.id, ApprovalDecision.verdict == "approve")
        .order_by(ApprovalDecision.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()
    cap = now.date() + timedelta(days=policy_limits_days)
    until = record.requested_until or cap
    record.expires_at = until if record.legacy else min(until, cap)
    record.review_by = record.expires_at - timedelta(days=_review_lead(request))
    record.status = "active"
    record.approved_by = approver
    record.effective_at = now
    record.first_effective_at = record.first_effective_at or now
    if record.renews_id:
        parent = session.get(RiskAcceptance, record.renews_id)
        if parent is not None and parent.status in LIVE:
            parent.status = "closed"
            parent.closed_at = now
            parent.closed_reason = f"renewed by {record.id}"
    stamped = _stamp_findings(record)
    logger.info("Risk acceptance %s active: %s finding(s) stamped", record.id, stamped)


#: The limits the approving policy carried, looked up at approval time.
_POLICY: ApprovalPolicy | None = None


def bind_policy(policy: ApprovalPolicy) -> None:
    global _POLICY
    _POLICY = policy


def _limits_days(request: ApprovalRequest) -> int:
    limits = _POLICY.risk_acceptance if _POLICY else None
    days = limits.max_duration_days if limits else {}
    return int(days.get(request.tier, 90))


def _review_lead(request: ApprovalRequest) -> int:
    return _POLICY.risk_acceptance.review_lead_days if _POLICY else 14


register_adapter("risk_acceptance", _adapter)
register_on_approved("risk_acceptance", on_approved)
register_dedicated_route("risk_acceptance", "/api/risk-acceptances")


# -- Revocation, renewal, the sweep ---------------------------------------------


def revoke(db: Any, *, record_id: str, revoked_by: Principal, reason: str) -> int:
    if not (revoked_by.is_human and revoked_by.may_write):
        raise RiskAcceptanceError("Only a person may revoke a risk acceptance.")
    if not reason.strip():
        raise RiskAcceptanceError("Revoking needs a reason.")
    with db.session() as session:
        record = session.get(RiskAcceptance, record_id)
        if record is None or record.status not in (*LIVE, "pending_approval"):
            raise RiskAcceptanceError(f"No live risk acceptance {record_id}.")
        was_live = record.status in LIVE
        record.status = "revoked"
        record.closed_at = utcnow()
        record.closed_reason = reason.strip()
        db.audit(
            session,
            actor=revoked_by.actor,
            action="risk_acceptance.revoked",
            entity_type="risk_acceptance",
            entity_id=record_id,
            reason=reason.strip(),
        )
        ids = list(record.covered_finding_ids or [])
    if not was_live or not ids:
        return 0
    catalog = _catalog()
    return update_findings(
        catalog,
        locate_findings(catalog, ids),
        "status = 'open', resolved_at = NULL, accepted_until = NULL, accepted_reason_code = NULL",
        [],
        only_if_status="accepted_risk",
    ).count


@dataclass
class SweepResult:
    not_approved: int = 0
    review_due: int = 0
    expired: int = 0
    closed: int = 0
    drift: int = 0


def sweep(db: Any, catalog: Catalog, *, today: date | None = None) -> SweepResult:
    """Record-level transitions, each audited (spec 33 §1.4, §7).

    The findings themselves are reopened by `sweep_acceptances` when their
    `accepted_until` passes; this moves the *decision* through its lifecycle
    and says so in the audit log, which the row-level sweep never did.
    """
    today = today or utcnow().date()
    result = SweepResult()
    with db.session() as session:
        result.not_approved = _close_unapproved(db, session)
        records = list(
            session.execute(select(RiskAcceptance).where(RiskAcceptance.status.in_(LIVE))).scalars()
        )
        for record in records:
            if record.expires_at and today >= record.expires_at:
                record.status = "expired"
                record.closed_at = utcnow()
                record.closed_reason = "reached expires_at without renewal"
                result.expired += 1
                _audit_sweep(db, session, record, "risk_acceptance.expired")
                continue
            covered = list(record.covered_finding_ids or [])
            if covered and catalog.all_files("findings"):
                placeholders = ", ".join("?" for _ in covered)
                remaining = catalog.query(
                    f"SELECT count(*) FROM findings WHERE finding_id IN ({placeholders}) "
                    "AND status IN ('open', 'accepted_risk')",
                    covered,
                )[0][0]
                if not remaining:
                    record.status = "closed"
                    record.closed_at = utcnow()
                    record.closed_reason = "every covered finding was remediated"
                    result.closed += 1
                    _audit_sweep(db, session, record, "risk_acceptance.closed")
                    continue
            if record.status == "active" and record.review_by and today >= record.review_by:
                record.status = "review_due"
                result.review_due += 1
                _audit_sweep(db, session, record, "risk_acceptance.review_due")
            drift = [
                m.finding_id
                for m in match_scope(catalog, record.repo_full_name, record.scope, ("open",))
                if m.finding_id not in set(covered)
            ]
            if sorted(drift) != sorted(record.drift_finding_ids or []):
                record.drift_finding_ids = sorted(drift)
                if drift:
                    result.drift += 1
                    _audit_sweep(
                        db, session, record, "risk_acceptance.scope_drift", count=len(drift)
                    )
    return result


def _close_unapproved(db: Any, session: Session) -> int:
    """Pending records whose approval request was rejected or ran out of time.

    Without this they stay `pending_approval` for good, and a pending record
    claims its findings: the legacy migration skips them and nothing can
    propose them again. A rejection is an answer, and an expiry is the
    absence of one; either way the record is not going to take effect.
    """
    now = utcnow()
    closed = 0
    pending = session.execute(
        select(RiskAcceptance, ApprovalRequest)
        .join(ApprovalRequest, ApprovalRequest.id == RiskAcceptance.approval_request_id)
        .where(RiskAcceptance.status == "pending_approval")
    ).all()
    for record, request in pending:
        if request.state == "pending" and request.expires_at <= now:
            # Recorded on the request's own chain, as `decide` would on a late
            # decision, so the chain says why it ended.
            request.state = "expired"
            _append_event(session, request.id, "expired", "job:risk-acceptances", {})
        if request.state not in ("rejected", "expired"):
            continue
        record.status = "not_approved"
        record.closed_at = now
        record.closed_reason = f"approval request {request.id} {request.state}"
        closed += 1
        _audit_sweep(
            db, session, record, "risk_acceptance.not_approved", request_state=request.state
        )
    return closed


def _audit_sweep(
    db: Any, session: Session, record: RiskAcceptance, action: str, **detail: Any
) -> None:
    db.audit(
        session,
        actor="job:risk-acceptances",
        action=action,
        entity_type="risk_acceptance",
        entity_id=record.id,
        repo=record.repo_full_name,
        **detail,
    )


# -- Migration of row-level acceptances (spec 33 §10) ---------------------------

_DEVIATION_FOR_CODE = {
    "no_vendor_fix": "vendor_dependency",
    "not_exploitable_here": "risk_adjustment",
    "compensating_control": "risk_adjustment",
    "cost_exceeds_risk": "operational_requirement",
    "other": "risk_adjustment",
}


@dataclass
class LegacyGroup:
    repo: str
    capability: str
    image: str
    location: str
    reason_code: str
    accepted_until: date | None
    severity: str
    findings: list[MatchedFinding]

    @property
    def key(self) -> str:
        return "|".join(
            [
                self.repo,
                self.capability,
                self.image or self.location,
                self.reason_code,
                self.accepted_until.isoformat() if self.accepted_until else "",
                self.severity,
            ]
        )


def legacy_groups(db: Any, catalog: Catalog, repo: str | None = None) -> list[LegacyGroup]:
    """Row-level acceptances not yet covered by any record, grouped into
    the few dozen decisions they really are."""
    if not catalog.all_files("findings"):
        return []
    with db.session() as session:
        claimed: set[str] = set()
        for ids in session.execute(
            select(RiskAcceptance.covered_finding_ids).where(
                RiskAcceptance.status.in_(("pending_approval", *LIVE))
            )
        ).scalars():
            claimed.update(ids or [])
    where = "status = 'accepted_risk'"
    params: list[Any] = []
    if repo:
        where += " AND repo_full_name = ?"
        params.append(repo)
    rows = catalog.query(
        "SELECT finding_id, repo_full_name, capability, rule_id, coalesce(package_name, ''), "
        "       lower(severity), coalesce(file_path, ''), "
        "       coalesce(json_extract_string(raw_finding_json, '$.image'), ''), "
        "       coalesce(json_extract_string(raw_finding_json, '$.fixed_version'), ''), "
        "       coalesce(accepted_reason_code, 'other'), accepted_until "
        f"FROM findings WHERE {where}",
        params,
    )
    groups: dict[str, LegacyGroup] = {}
    for fid, r, cap, rule, pkg, sev, path, image, fixed, code, until in rows:
        if str(fid) in claimed:
            continue
        image_key = image_repository(image) if image else ""
        location = "" if image_key else str(path)
        g = LegacyGroup(
            repo=str(r),
            capability=str(cap),
            image=image_key,
            location=location,
            reason_code=str(code),
            accepted_until=until,
            severity=str(sev) if sev in SEVERITIES else "low",
            findings=[],
        )
        groups.setdefault(g.key, g).findings.append(
            MatchedFinding(
                finding_id=str(fid),
                rule_id=str(rule),
                package=str(pkg),
                severity=str(sev),
                location=str(path),
                image=str(image),
                fixed_version=str(fixed),
                status="accepted_risk",
            )
        )
    return sorted(groups.values(), key=lambda g: (g.repo, g.severity, g.key))


def _legacy_justification(db: Any, finding_ids: list[str]) -> str:
    with db.session() as session:
        reasons = [
            (e.detail or {}).get("reason", "")
            for e in session.execute(
                select(AuditLogEntry)
                .where(
                    AuditLogEntry.action == "finding.status",
                    AuditLogEntry.entity_id.in_(finding_ids[:500]),
                )
                .order_by(AuditLogEntry.created_at.desc())
            ).scalars()
        ]
    reasons = [r for r in reasons if r]
    if not reasons:
        return "Migrated from row-level acceptances; no reason was recorded with them."
    common, _ = Counter(reasons).most_common(1)[0]
    return f"Migrated from {len(finding_ids)} row-level acceptance(s). Recorded reason: {common}"


def migrate_legacy(
    db: Any,
    catalog: Catalog,
    policy: ApprovalPolicy,
    *,
    requested_by: Principal,
    risk_owner: str,
    repo: str | None = None,
    severities: list[str] | None = None,
    dry_run: bool = True,
) -> list[dict[str, Any]]:
    """Propose one `pending_approval` legacy record per group. Findings are not
    touched: they keep their current acceptance until it expires or a person
    approves the record (spec 33 §10)."""
    out: list[dict[str, Any]] = []
    wanted = {s.lower() for s in severities} if severities else None
    for g in legacy_groups(db, catalog, repo):
        if wanted is not None and g.severity not in wanted:
            continue
        deviation = _DEVIATION_FOR_CODE.get(g.reason_code, "risk_adjustment")
        scope: dict[str, Any] = {
            "capability": g.capability,
            "severities": [g.severity],
            "rule_ids": sorted({m.rule_id for m in g.findings}),
        }
        if g.image:
            scope["image"] = g.image
        elif g.location:
            scope["file_paths"] = [g.location]
        premises = (
            [{"type": "no_fixed_version", "inferred": True}]
            if deviation == "vendor_dependency"
            else []
        )
        until = g.accepted_until or (utcnow().date() + timedelta(days=30))
        milestones = [
            {
                "title": "Re-assess this migrated acceptance with its evidence",
                "due": (until - timedelta(days=7)).isoformat(),
                "ends_weakness": False,
            },
            {
                "title": "Remediate, or renew with premises the platform can monitor",
                "due": until.isoformat(),
                "ends_weakness": True,
            },
        ]
        item = {
            "group": g.key,
            "findings": len(g.findings),
            "residual_severity": g.severity,
            "deviation_type": deviation,
            "accepted_until": until.isoformat(),
        }
        if not dry_run:
            record, approval = propose(
                db,
                catalog,
                policy,
                requested_by=requested_by,
                repo=g.repo,
                scope=scope,
                deviation_type=deviation,
                justification=_legacy_justification(db, [m.finding_id for m in g.findings]),
                residual_likelihood="moderate",
                residual_impact="moderate",
                risk_owner=risk_owner,
                requested_until=until,
                premises=premises,
                milestones=milestones,
                legacy=True,
                matched=g.findings,
            )
            item["risk_acceptance_id"] = record.id
            item["approval_request_id"] = approval.id
        out.append(item)
    return out


def serialize(record: RiskAcceptance) -> dict[str, Any]:
    def iso(v: Any) -> Any:
        return v.isoformat() if isinstance(v, (date, datetime)) else v

    return {
        "id": record.id,
        "repo": record.repo_full_name,
        "scope": record.scope,
        "findings": len(record.covered_finding_ids or []),
        "drift": len(record.drift_finding_ids or []),
        "response": record.response,
        "deviation_type": record.deviation_type,
        "justification": record.justification,
        "residual_severity": record.residual_severity,
        "residual_likelihood": record.residual_likelihood,
        "residual_impact": record.residual_impact,
        "premises": record.premises,
        "compensating_controls": record.compensating_controls,
        "milestones": record.milestones,
        "risk_owner": record.risk_owner,
        "requested_by": record.requested_by,
        "approved_by": record.approved_by,
        "approval_request_id": record.approval_request_id,
        "status": record.status,
        "legacy": record.legacy,
        "renews_id": record.renews_id,
        "renewal_count": record.renewal_count,
        "requested_until": iso(record.requested_until),
        "effective_at": iso(record.effective_at),
        "first_effective_at": iso(record.first_effective_at),
        "review_by": iso(record.review_by),
        "expires_at": iso(record.expires_at),
        "closed_at": iso(record.closed_at),
        "closed_reason": record.closed_reason,
        "created_at": iso(record.created_at),
    }
