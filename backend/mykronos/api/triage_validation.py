"""Safe validation against the demo environment (TheHub #60892, Triage T5).

`POST /api/dashboard/findings/{finding_id}/validations` - replay a DAST
finding's recorded GET/HEAD at the demo origin and record the verdict with
the request and response.

`POST /api/dashboard/findings/{finding_id}/validations/nuclei` - record a
nuclei template run that happened elsewhere, if its target was the demo and
the template is non-destructive.

`GET /api/dashboard/findings/{finding_id}/validations` - every validation of
the finding, newest first.

A refused validation answers 422 with a `code` and sends nothing. No
validation changes the finding: the verdict is evidence for whoever decides.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

from mykronos import validation
from mykronos.adminauth import Principal, PrincipalDep
from mykronos.dashboard import DashboardQueries
from mykronos.db.models import FindingValidation

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

Verdict = Literal["validated", "not_validated", "inconclusive"]
Source = Literal["zap_replay", "nuclei"]


class ValidationOut(BaseModel):
    """One validation: the verdict, and the request and response it rests on."""

    id: str
    finding_id: str
    source: Source
    template_id: str = ""
    #: Always `demo`: validation never targets production.
    environment: Literal["demo"] = "demo"
    target_origin: str
    verdict: Verdict
    reason: str
    request: dict[str, Any] = {}
    response: dict[str, Any] = {}
    requested_by: str
    created_at: datetime
    #: Validations are evidence; none changes the finding.
    applied: Literal[False] = False


class ValidationListOut(BaseModel):
    finding_id: str
    validations: list[ValidationOut]


class ReplayIn(BaseModel):
    """Nothing to choose: the request replayed is the one the scanner recorded."""


class NucleiIn(BaseModel):
    template_id: str = Field(min_length=1, max_length=255)
    template_tags: list[str] = Field(default_factory=list, max_length=64)
    target_url: str = Field(
        min_length=1,
        max_length=2048,
        description="The URL the template ran against. It must be on the demo origin.",
    )
    outcome: Literal["matched", "not_matched", "error"]
    request: str = Field(default="", max_length=65_536, description="The raw request sent.")
    response: str = Field(
        default="", max_length=262_144, description="The raw response received."
    )


def _out(row: FindingValidation) -> ValidationOut:
    return ValidationOut(
        id=row.id,
        finding_id=row.finding_id,
        source=row.source,  # type: ignore[arg-type]
        template_id=row.template_id,
        target_origin=row.target_origin,
        verdict=row.verdict,  # type: ignore[arg-type]
        reason=row.reason,
        request=row.request or {},
        response=row.response or {},
        requested_by=row.requested_by,
        created_at=row.created_at,
    )


def _finding(request: Request, finding_id: str) -> dict[str, Any]:
    row = DashboardQueries(request.app.state.catalog).finding(finding_id, include_raw=True)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"No finding {finding_id}."
        )
    return row


def _writer(principal: Principal) -> None:
    if not principal.may_write:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Running a validation is a write; a viewer cannot.",
        )


def _refused(refusal: validation.RefusedError) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        detail={"code": refusal.code, "message": refusal.message},
    )


def _store(
    request: Request,
    finding: dict[str, Any],
    result: validation.Result,
    *,
    source: str,
    template_id: str,
    principal: Principal,
) -> ValidationOut:
    with request.app.state.db.session() as session:
        row = validation.record(
            session,
            finding,
            result,
            source=source,
            template_id=template_id,
            requested_by=principal.actor,
            actor_kind=principal.kind.value,
        )
        request.app.state.db.audit(
            session,
            actor=principal.actor,
            action="finding.validation",
            entity_type="finding",
            entity_id=row.finding_id,
            validation_id=row.id,
            source=source,
            verdict=row.verdict,
            target_origin=row.target_origin,
        )
        return _out(row)


@router.post(
    "/findings/{finding_id}/validations",
    response_model=ValidationOut,
    status_code=status.HTTP_201_CREATED,
)
async def replay_on_demo(
    request: Request, finding_id: str, body: ReplayIn, principal: PrincipalDep
) -> ValidationOut:
    """Replay a DAST finding's recorded GET or HEAD at the demo origin.

    Only the recorded path and query are sent, re-based onto the demo, with
    no credentials and no redirect followed. RefusedError (422, nothing sent) when
    no demo is configured, the demo is a production origin, or the recorded
    request is not a GET or HEAD. The finding is not changed.
    """
    _writer(principal)
    finding = _finding(request, finding_id)
    settings = request.app.state.settings
    policy = validation.TargetPolicy.from_settings(settings)
    try:
        plan = validation.replay_plan(finding, policy)
        result = await validation.replay(
            plan,
            policy,
            timeout=float(getattr(settings, "validation_timeout_seconds", 15.0)),
            transport=getattr(request.app.state, "validation_transport", None),
        )
    except validation.RefusedError as refusal:
        raise _refused(refusal) from refusal
    return _store(
        request,
        finding,
        result,
        source=validation.ZAP_REPLAY,
        template_id=plan.template_id,
        principal=principal,
    )


@router.post(
    "/findings/{finding_id}/validations/nuclei",
    response_model=ValidationOut,
    status_code=status.HTTP_201_CREATED,
)
async def record_nuclei_run(
    request: Request, finding_id: str, body: NucleiIn, principal: PrincipalDep
) -> ValidationOut:
    """Record a nuclei template run against the demo, with its request and response.

    RefusedError (422, nothing recorded) when the target is a production origin or
    not the demo, or the template is tagged as destructive (intrusive, dos,
    fuzz, bruteforce). The finding is not changed.
    """
    _writer(principal)
    finding = _finding(request, finding_id)
    policy = validation.TargetPolicy.from_settings(request.app.state.settings)
    try:
        demo = validation.check_nuclei(
            policy, target_url=body.target_url, template_tags=body.template_tags
        )
    except validation.RefusedError as refusal:
        raise _refused(refusal) from refusal
    result = validation.nuclei_result(
        demo=demo,
        template_id=body.template_id,
        template_tags=body.template_tags,
        target_url=body.target_url,
        outcome=body.outcome,
        request=body.request,
        response=body.response,
    )
    return _store(
        request,
        finding,
        result,
        source=validation.NUCLEI,
        template_id=body.template_id,
        principal=principal,
    )


@router.get("/findings/{finding_id}/validations", response_model=ValidationListOut)
async def list_validations(
    request: Request, finding_id: str, principal: PrincipalDep
) -> ValidationListOut:
    """Every validation of one finding against the demo, newest first."""
    with request.app.state.db.session() as session:
        rows = validation.history(session, finding_id)
        return ValidationListOut(finding_id=finding_id, validations=[_out(r) for r in rows])
