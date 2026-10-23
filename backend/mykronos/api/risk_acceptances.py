"""Risk acceptance API (spec 33, phase 1).

`POST /api/risk-acceptances` proposes a scoped acceptance and opens its
approval request in the same call; the response names both. The acceptance
takes effect only when someone independent of the requester approves it
through `/api/approvals/{id}/decisions` (spec 34).
"""

from __future__ import annotations

from datetime import date
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from mykronos import premise_monitor, risk_evidence
from mykronos import risk_acceptance as ra
from mykronos.adminauth import HumanDep, PrincipalDep
from mykronos.approvals.engine import ApprovalError
from mykronos.approvals.policy import cached_policy
from mykronos.db.models import ApprovalRequest, RiskAcceptance

router = APIRouter(prefix="/api/risk-acceptances", tags=["risk-acceptance"])


def _policy(request: Request) -> Any:
    policy = cached_policy(request.app.state.settings.approval_policy_path)
    ra.bind_policy(policy)
    return policy


def _refused(exc: Exception) -> HTTPException:
    return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))


class ProposeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repo: str
    scope: dict[str, Any]
    deviation_type: str
    justification: str = Field(min_length=1, max_length=8000)
    residual_likelihood: str
    residual_impact: str
    risk_owner: str
    requested_until: date
    premises: list[dict[str, Any]] = Field(default_factory=list)
    compensating_controls: list[dict[str, Any]] = Field(default_factory=list)
    milestones: list[dict[str, Any]] = Field(default_factory=list)
    response: str = "accept"


class RenewIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    requested_until: date
    justification: str = Field(min_length=1, max_length=8000)
    premises: list[dict[str, Any]] | None = None
    milestones: list[dict[str, Any]] | None = None


class RevokeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1, max_length=2000)


class InterimReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    #: What was checked, and why the acceptance still stands.
    note: str = Field(min_length=1, max_length=2000)


class MigrateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    risk_owner: str
    repo: str | None = None
    #: Migrate in stages: a queue a person can decide inside the request TTL.
    severities: list[str] | None = None
    dry_run: bool = True


def _fresh_days(request: Request) -> int:
    return int(
        getattr(request.app.state.settings, "premise_fresh_days", premise_monitor.FRESH_DAYS)
    )


#: How many covered findings' scores the detail lists. The total is always
#: given; 3,647 ZAP findings are one decision, not a page of 3,647 rows.
SCORES_SHOWN = 50


def environmental_scores(session: Any, finding_ids: list[str]) -> dict[str, Any]:
    """Base and environmental CVSS for the covered findings, with their facts.

    Read from `EnvironmentalScore` (TheHub #60827): the current value per
    finding, with every fact the resolver weighed, applied or not. A covered
    finding with no row is unscored (no vector, or not yet computed) and is
    counted, not hidden: `total` is every covered finding, `scored` those with
    a row among the ones shown.
    """
    shown = sorted(finding_ids)[:SCORES_SHOWN]
    # The shared evidence model's read (TheHub #60901), as the Oracle makes it.
    by_id = risk_evidence.environmental_scores(session, finding_ids=shown)
    rows = [by_id[fid] for fid in sorted(by_id)]
    items = [
        {
            "finding_id": row.finding_id,
            "vector": row.vector,
            "vector_version": row.vector_version,
            "vector_source": row.vector_source,
            "base": row.base,
            "environmental": row.environmental,
            "base_band": row.base_band,
            "env_band": row.env_band,
            "scanner_severity": row.scanner_severity,
            "effective_severity": row.effective_severity,
            "facts": list(row.facts_json or []),
            "context_id": row.context_id,
            "computed_at": row.computed_at.isoformat() if row.computed_at else None,
        }
        for row in rows
    ]
    return {
        "available": True,
        "reason": "" if items else "No covered finding has an environmental score yet.",
        "total": len(finding_ids),
        "shown": len(shown),
        "scored": len(items),
        "items": items,
    }


def _decided_on(session: Any, record: RiskAcceptance) -> dict[str, Any] | None:
    """The `risk_evidence` block the approver signed, or None for a record
    proposed before the block existed."""
    if not record.approval_request_id:
        return None
    request = session.get(ApprovalRequest, record.approval_request_id)
    if request is None:
        return None
    block = (request.evidence or {}).get("risk_evidence")
    return dict(block) if isinstance(block, dict) else None


def _writer(principal: Any) -> None:
    if not principal.may_write:
        raise HTTPException(status_code=403, detail="Requires the 'admin' or 'agent' role.")


@router.post("", status_code=status.HTTP_201_CREATED)
async def propose(request: Request, body: ProposeIn, principal: PrincipalDep) -> dict[str, Any]:
    _writer(principal)
    try:
        record, approval = ra.propose(
            request.app.state.db,
            request.app.state.catalog,
            _policy(request),
            requested_by=principal,
            repo=body.repo,
            scope=body.scope,
            deviation_type=body.deviation_type,
            justification=body.justification,
            residual_likelihood=body.residual_likelihood,
            residual_impact=body.residual_impact,
            risk_owner=body.risk_owner,
            requested_until=body.requested_until,
            premises=body.premises,
            compensating_controls=body.compensating_controls,
            milestones=body.milestones,
            response=body.response,
            fresh_days=_fresh_days(request),
        )
    except (ra.RiskAcceptanceError, ApprovalError) as exc:
        raise _refused(exc) from exc
    return {
        "risk_acceptance": ra.serialize(record),
        "approval_request_id": approval.id,
        "tier": approval.tier,
        "evidence_digest": approval.evidence_digest,
        # #712: reasons the premise is doubtful, as the approver will see them.
        "flags": list((approval.evidence or {}).get("flags") or []),
        # Spec 33 §4: each premise as the monitor reads it today -
        # holds / failed / unverified, with the observations behind it.
        "premise_checks": list((approval.evidence or {}).get("premise_checks") or []),
    }


@router.get("")
async def list_acceptances(
    request: Request,
    principal: PrincipalDep,
    status_filter: str | None = None,
    repo: str | None = None,
) -> list[dict[str, Any]]:
    with request.app.state.db.session() as session:
        stmt = select(RiskAcceptance).order_by(RiskAcceptance.created_at.desc()).limit(500)
        if status_filter:
            stmt = stmt.where(RiskAcceptance.status == status_filter)
        if repo:
            stmt = stmt.where(RiskAcceptance.repo_full_name == repo)
        return [ra.serialize(r) for r in session.execute(stmt).scalars()]


@router.post("/migrate-legacy")
async def migrate(request: Request, body: MigrateIn, principal: PrincipalDep) -> dict[str, Any]:
    """Group row-level acceptances into proposed legacy records (spec 33 §10).
    Dry run by default. Nothing about the findings changes either way."""
    _writer(principal)
    try:
        groups = ra.migrate_legacy(
            request.app.state.db,
            request.app.state.catalog,
            _policy(request),
            requested_by=principal,
            risk_owner=body.risk_owner,
            repo=body.repo,
            severities=body.severities,
            dry_run=body.dry_run,
        )
    except (ra.RiskAcceptanceError, ApprovalError) as exc:
        raise _refused(exc) from exc
    return {
        "dry_run": body.dry_run,
        "groups": len(groups),
        "findings": sum(g["findings"] for g in groups),
        "items": groups,
    }


@router.get("/{record_id}")
async def get_acceptance(
    request: Request, record_id: str, principal: PrincipalDep
) -> dict[str, Any]:
    with request.app.state.db.session() as session:
        record = session.get(RiskAcceptance, record_id)
        if record is None:
            raise HTTPException(status_code=404, detail=f"No risk acceptance {record_id}.")
        fresh_days = _fresh_days(request)
        checks = premise_monitor.check_record(
            session, record, request.app.state.catalog, fresh_days=fresh_days
        )
        return {
            **ra.serialize(record),
            # Evaluated on read, so the page never shows yesterday's verdict:
            # holds / failed / unverified per premise, with the evidence.
            "premise_checks": [c.as_dict() for c in checks],
            "premise_fresh_days": fresh_days,
            # Each compensating control as the observations read it today
            # (TheHub #60902): verified / contradicted / unverified.
            "control_checks": ra.check_controls(
                session,
                record.repo_full_name,
                list(record.compensating_controls or []),
                fresh_days=fresh_days,
            ),
            "scores": environmental_scores(session, list(record.covered_finding_ids or [])),
            # What this decision was approved on (TheHub #60901): the shared
            # evidence model's block, frozen into the approval's evidence.
            "risk_evidence": _decided_on(session, record),
        }


@router.post("/{record_id}/renew", status_code=status.HTTP_201_CREATED)
async def renew(
    request: Request, record_id: str, body: RenewIn, principal: PrincipalDep
) -> dict[str, Any]:
    _writer(principal)
    with request.app.state.db.session() as session:
        parent = session.get(RiskAcceptance, record_id)
        if parent is None or parent.status not in ra.LIVE:
            raise HTTPException(status_code=409, detail=f"No live risk acceptance {record_id}.")
        session.expunge(parent)
    try:
        record, approval = ra.propose(
            request.app.state.db,
            request.app.state.catalog,
            _policy(request),
            requested_by=principal,
            repo=parent.repo_full_name,
            scope=parent.scope,
            deviation_type=parent.deviation_type,
            justification=body.justification,
            residual_likelihood=parent.residual_likelihood,
            residual_impact=parent.residual_impact,
            risk_owner=parent.risk_owner,
            requested_until=body.requested_until,
            premises=parent.premises if body.premises is None else body.premises,
            compensating_controls=parent.compensating_controls,
            milestones=parent.milestones if body.milestones is None else body.milestones,
            response=parent.response,
            renews=parent,
            statuses=("open", "accepted_risk"),
        )
    except (ra.RiskAcceptanceError, ApprovalError) as exc:
        raise _refused(exc) from exc
    return {"risk_acceptance": ra.serialize(record), "approval_request_id": approval.id}


@router.post("/{record_id}/revoke")
async def revoke(
    request: Request, record_id: str, body: RevokeIn, principal: HumanDep
) -> dict[str, Any]:
    try:
        reopened = ra.revoke(
            request.app.state.db, record_id=record_id, revoked_by=principal, reason=body.reason
        )
    except ra.RiskAcceptanceError as exc:
        raise _refused(exc) from exc
    return {"revoked": record_id, "findings_reopened": reopened}


@router.post("/{record_id}/interim-review")
async def interim_review(
    request: Request, record_id: str, body: InterimReviewIn, principal: HumanDep
) -> dict[str, Any]:
    """A person records the interim review an acceptance nothing watches owes
    (TheHub #60817): they looked again, and it still stands."""
    _policy(request)
    try:
        record = ra.record_interim_review(
            request.app.state.db, record_id=record_id, reviewed_by=principal, note=body.note
        )
    except ra.RiskAcceptanceError as exc:
        raise _refused(exc) from exc
    return {"risk_acceptance": ra.serialize(record)}
