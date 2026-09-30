"""Approval API: requests, decisions, delegations (spec 34 §3-§5).

Every governed action goes through the same four routes. A requester creates a
request for a duty and a subject; the platform computes the tier and freezes
the evidence; an approver who is independent of the requester decides against
the digest they were shown; the history is hash-chained and verifiable.
"""

from __future__ import annotations

import asyncio
import dataclasses
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from mykronos.adminauth import HumanDep, PrincipalDep
from mykronos.approvals import pull_requests, reviewer, sampling
from mykronos.approvals.engine import (
    ApprovalError,
    create_request,
    decide,
    dedicated_route,
    propose_delegation,
    revoke_delegation,
    verify_chain,
)
from mykronos.approvals.policy import ApprovalPolicy, cached_policy
from mykronos.db.models import ApprovalDecision, ApprovalEvent, ApprovalRequest, Delegation
from mykronos.github.client import GitHubError

router = APIRouter(prefix="/api/approvals", tags=["approvals"])


def _policy(request: Request) -> ApprovalPolicy:
    return cached_policy(request.app.state.settings.approval_policy_path)


def _naive_utc(value: datetime) -> datetime:
    return value.astimezone(UTC).replace(tzinfo=None) if value.tzinfo else value


def _refused(exc: ApprovalError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))


class CreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    duty: str
    subject_ref: str = Field(max_length=255)
    statement: str = Field(
        default="",
        max_length=4000,
        description="The requester's own claim, carried beside the evidence and labelled "
        "as the requester's - never as evidence.",
    )
    context: dict[str, Any] = Field(default_factory=dict)


class DecisionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verdict: str = Field(pattern="^(approve|reject|needs_info)$")
    rationale: str = Field(min_length=1, max_length=8000)
    evidence_digest: str = Field(min_length=64, max_length=64)


class DecisionOut(BaseModel):
    id: str
    approver: str
    approver_kind: str
    verdict: str
    rationale: str
    evidence_digest: str
    delegation_id: str | None
    same_person: bool
    sampled: bool
    created_at: datetime


class RequestOut(BaseModel):
    id: str
    duty: str
    tier: str
    subject_ref: str
    state: str
    evidence_digest: str
    requested_by: str
    requester_kind: str
    requester_statement: str
    policy_version: str
    created_at: datetime
    expires_at: datetime
    decided_at: datetime | None
    decisions: list[DecisionOut] = Field(default_factory=list)


class EvidenceOut(BaseModel):
    """What an approver sees, and all an independent reviewer should see."""

    request_id: str
    duty: str
    tier: str
    evidence: dict[str, Any]
    evidence_digest: str
    requester_statement: str = Field(description="The requester's claim - not evidence.")


class ChainOut(BaseModel):
    ok: bool
    detail: str
    events: list[dict[str, Any]]


class DelegationIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    duty: str
    tiers: list[str] = Field(min_length=1)
    approver_families: list[str] = Field(min_length=1)
    expires_at: datetime
    sampling: float | None = Field(default=None, ge=0, le=1)
    constraints: dict[str, Any] = Field(default_factory=dict)
    statement: str = Field(default="", max_length=4000)


class DelegationOut(BaseModel):
    id: str
    duty: str
    tiers: list[str]
    approver_families: list[str]
    sampling: float
    granted_by: str
    grant_request_id: str
    created_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    suspended_at: datetime | None
    suspended_reason: str | None
    active: bool


def _request_out(session: Any, row: ApprovalRequest) -> RequestOut:
    decisions = session.execute(
        select(ApprovalDecision)
        .where(ApprovalDecision.request_id == row.id)
        .order_by(ApprovalDecision.created_at)
    ).scalars()
    return RequestOut(
        id=row.id,
        duty=row.duty,
        tier=row.tier,
        subject_ref=row.subject_ref,
        state=row.state,
        evidence_digest=row.evidence_digest,
        requested_by=row.requested_by,
        requester_kind=row.requester_kind,
        requester_statement=row.requester_statement,
        policy_version=row.policy_version,
        created_at=row.created_at,
        expires_at=row.expires_at,
        decided_at=row.decided_at,
        decisions=[
            DecisionOut(
                id=d.id,
                approver=d.approver,
                approver_kind=d.approver_kind,
                verdict=d.verdict,
                rationale=d.rationale,
                evidence_digest=d.evidence_digest,
                delegation_id=d.delegation_id,
                same_person=d.same_person,
                sampled=d.sampled,
                created_at=d.created_at,
            )
            for d in decisions
        ],
    )


def _require_writer(principal: Any) -> None:
    if not principal.may_write:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Approvals require the 'admin' or 'agent' role.",
        )


@router.post("", response_model=RequestOut, status_code=status.HTTP_201_CREATED)
async def create(request: Request, body: CreateRequest, principal: PrincipalDep) -> RequestOut:
    _require_writer(principal)
    route = dedicated_route(body.duty)
    if route is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"'{body.duty}' requests are created through {route}, which builds "
            "the evidence and the tier from the platform's own records.",
        )
    try:
        row = create_request(
            request.app.state.db,
            _policy(request),
            duty=body.duty,
            subject_ref=body.subject_ref,
            requested_by=principal,
            statement=body.statement,
            context=body.context,
        )
    except ApprovalError as exc:
        raise _refused(exc) from exc
    with request.app.state.db.session() as session:
        return _request_out(session, session.get(ApprovalRequest, row.id))


@router.get("", response_model=list[RequestOut])
async def list_requests(
    request: Request, principal: PrincipalDep, state: str | None = None, duty: str | None = None
) -> list[RequestOut]:
    with request.app.state.db.session() as session:
        stmt = select(ApprovalRequest).order_by(ApprovalRequest.created_at.desc()).limit(200)
        if state:
            stmt = stmt.where(ApprovalRequest.state == state)
        if duty:
            stmt = stmt.where(ApprovalRequest.duty == duty)
        return [_request_out(session, r) for r in session.execute(stmt).scalars()]


@router.get("/delegations", response_model=list[DelegationOut])
async def delegations(request: Request, principal: PrincipalDep) -> list[DelegationOut]:
    from mykronos.schemas import utcnow

    now = utcnow()
    with request.app.state.db.session() as session:
        rows = session.execute(select(Delegation).order_by(Delegation.created_at.desc())).scalars()
        return [
            DelegationOut(
                id=d.id,
                duty=d.duty,
                tiers=list(d.tiers or []),
                approver_families=list(d.approver_families or []),
                sampling=d.sampling,
                granted_by=d.granted_by,
                grant_request_id=d.grant_request_id,
                created_at=d.created_at,
                expires_at=d.expires_at,
                revoked_at=d.revoked_at,
                suspended_at=d.suspended_at,
                suspended_reason=d.suspended_reason,
                active=not (d.revoked_at or d.suspended_at) and d.expires_at > now,
            )
            for d in rows
        ]


@router.post("/delegations", response_model=RequestOut, status_code=status.HTTP_201_CREATED)
async def propose(request: Request, body: DelegationIn, principal: HumanDep) -> RequestOut:
    """Proposing a delegation is itself a `delegation_grant` request: a person asks,
    a person approves, and only then does the delegation exist."""
    try:
        row = propose_delegation(
            request.app.state.db,
            _policy(request),
            requested_by=principal,
            duty=body.duty,
            tiers=body.tiers,
            approver_families=body.approver_families,
            expires_at=_naive_utc(body.expires_at),
            sampling=body.sampling,
            constraints=body.constraints,
            statement=body.statement,
        )
    except ApprovalError as exc:
        raise _refused(exc) from exc
    with request.app.state.db.session() as session:
        return _request_out(session, session.get(ApprovalRequest, row.id))


@router.post("/delegations/{delegation_id}/revoke")
async def revoke(request: Request, delegation_id: str, principal: HumanDep) -> dict[str, str]:
    try:
        revoke_delegation(request.app.state.db, delegation_id=delegation_id, revoked_by=principal)
    except ApprovalError as exc:
        raise _refused(exc) from exc
    return {"revoked": delegation_id}


class PullRequestIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repo: str = Field(max_length=255)
    number: int = Field(ge=1)
    statement: str = Field(
        default="",
        max_length=4000,
        description="The requester's own account of the change, labelled as a claim.",
    )


async def _stamp(request: Request, request_id: str) -> None:
    """Post the `independent-review` check for a pull request request's new
    state. Never fails the decision: a failed post is recorded and retried."""
    await pull_requests.publish(
        request.app.state.db, _policy(request), request.app.state.github_factory, request_id
    )


@router.post("/pull-requests", response_model=RequestOut, status_code=status.HTTP_201_CREATED)
async def request_pull_request(
    request: Request, body: PullRequestIn, principal: PrincipalDep
) -> RequestOut:
    """Ask for an independent approval of one pull request at its current head
    (spec 34 §6.1). The platform reads the diff; the tier is its change class."""
    _require_writer(principal)
    github = pull_requests.client_for(
        request.app.state.db, request.app.state.github_factory, body.repo
    )
    if github is None:
        raise HTTPException(status_code=409, detail=f"{body.repo} is not onboarded.")
    try:
        row = await pull_requests.propose(
            request.app.state.db,
            _policy(request),
            github,
            requested_by=principal,
            repo=body.repo,
            number=body.number,
            statement=body.statement,
        )
    except ApprovalError as exc:
        raise _refused(exc) from exc
    except GitHubError as exc:
        raise HTTPException(status_code=502, detail=f"GitHub: {exc}") from exc
    await _stamp(request, row.id)
    with request.app.state.db.session() as session:
        return _request_out(session, session.get(ApprovalRequest, row.id))


class SampleVerdictIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verdict: str = Field(pattern="^(agree|disagree)$")
    note: str = Field(default="", max_length=4000)


@router.get("/samples")
async def samples(request: Request, principal: PrincipalDep) -> list[dict[str, Any]]:
    """Sampled agent decisions waiting for a person's after-the-fact review."""
    return sampling.sample_queue(request.app.state.db)


@router.post("/samples/{decision_id}")
async def sample_verdict(
    request: Request, decision_id: str, body: SampleVerdictIn, principal: HumanDep
) -> dict[str, Any]:
    try:
        return sampling.record_sample_verdict(
            request.app.state.db,
            _policy(request),
            decision_id=decision_id,
            reviewer=principal,
            verdict=body.verdict,
            note=body.note,
        )
    except ApprovalError as exc:
        raise _refused(exc) from exc


@router.get("/delegations/{delegation_id}/stats")
async def delegation_stats(
    request: Request, delegation_id: str, principal: PrincipalDep
) -> dict[str, Any]:
    try:
        return sampling.delegation_stats(request.app.state.db, _policy(request), delegation_id)
    except ApprovalError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/shadow-reviews")
async def shadow_reviews(request: Request, principal: PrincipalDep) -> dict[str, Any]:
    """The reviewer's shadow verdicts beside what a person decided (spec 34 §4.3).

    The track record a delegation should rest on: how often the reviewer and the
    operator agreed, and every case where they did not. Ordered before
    `/{request_id}` so the literal path is not read as a request id.
    """
    report = await asyncio.to_thread(reviewer.shadow_report, request.app.state.db)
    report["mode"] = reviewer.mode(request.app.state.settings)
    return report


@router.post("/{request_id}/independent-review")
async def independent_review(
    request: Request, request_id: str, principal: PrincipalDep
) -> dict[str, Any]:
    """Start a platform-started reviewer on one pending request (spec 34 §4.3).

    Anyone who may write can start one, the requester included: starting a
    review is not choosing the reviewer. The platform picks the model, the
    instructions and the evidence, and the reviewer's decision goes through the
    same rules as anyone's.
    """
    _require_writer(principal)
    try:
        outcome = await asyncio.to_thread(
            reviewer.run_review,
            request.app.state.db,
            _policy(request),
            request.app.state.settings,
            request_id=request_id,
            started_by=principal,
        )
    except reviewer.ReviewerUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        ) from exc
    except ApprovalError as exc:
        raise _refused(exc) from exc
    await _stamp(request, request_id)
    return dataclasses.asdict(outcome)


@router.get("/{request_id}", response_model=RequestOut)
async def get_request(request: Request, request_id: str, principal: PrincipalDep) -> RequestOut:
    with request.app.state.db.session() as session:
        row = session.get(ApprovalRequest, request_id)
        if row is None:
            raise HTTPException(status_code=404, detail=f"No approval request {request_id}.")
        return _request_out(session, row)


@router.get("/{request_id}/evidence", response_model=EvidenceOut)
async def evidence(request: Request, request_id: str, principal: PrincipalDep) -> EvidenceOut:
    with request.app.state.db.session() as session:
        row = session.get(ApprovalRequest, request_id)
        if row is None:
            raise HTTPException(status_code=404, detail=f"No approval request {request_id}.")
        return EvidenceOut(
            request_id=row.id,
            duty=row.duty,
            tier=row.tier,
            evidence=row.evidence,
            evidence_digest=row.evidence_digest,
            requester_statement=row.requester_statement,
        )


@router.post("/{request_id}/decisions", response_model=RequestOut)
async def decide_request(
    request: Request, request_id: str, body: DecisionIn, principal: PrincipalDep
) -> RequestOut:
    _require_writer(principal)
    try:
        decide(
            request.app.state.db,
            _policy(request),
            request_id=request_id,
            approver=principal,
            verdict=body.verdict,
            rationale=body.rationale,
            evidence_digest=body.evidence_digest,
        )
    except ApprovalError as exc:
        raise _refused(exc) from exc
    await _stamp(request, request_id)
    with request.app.state.db.session() as session:
        return _request_out(session, session.get(ApprovalRequest, request_id))


@router.get("/{request_id}/chain", response_model=ChainOut)
async def chain(request: Request, request_id: str, principal: PrincipalDep) -> ChainOut:
    with request.app.state.db.session() as session:
        ok, detail = verify_chain(session, request_id)
        events = session.execute(
            select(ApprovalEvent)
            .where(ApprovalEvent.request_id == request_id)
            .order_by(ApprovalEvent.seq)
        ).scalars()
        return ChainOut(
            ok=ok,
            detail=detail,
            events=[
                {
                    "seq": e.seq,
                    "event": e.event,
                    "actor": e.actor,
                    "payload": e.payload,
                    "hash": e.hash,
                    "prev_hash": e.prev_hash,
                    "created_at": e.created_at.isoformat(),
                }
                for e in events
            ],
        )
