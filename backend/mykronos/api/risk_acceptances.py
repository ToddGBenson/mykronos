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

from mykronos import risk_acceptance as ra
from mykronos.adminauth import HumanDep, PrincipalDep
from mykronos.approvals.engine import ApprovalError
from mykronos.approvals.policy import cached_policy
from mykronos.db.models import RiskAcceptance

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


class MigrateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    risk_owner: str
    repo: str | None = None
    #: Migrate in stages: a queue a person can decide inside the request TTL.
    severities: list[str] | None = None
    dry_run: bool = True


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
        )
    except (ra.RiskAcceptanceError, ApprovalError) as exc:
        raise _refused(exc) from exc
    return {
        "risk_acceptance": ra.serialize(record),
        "approval_request_id": approval.id,
        "tier": approval.tier,
        "evidence_digest": approval.evidence_digest,
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
        return ra.serialize(record)


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
