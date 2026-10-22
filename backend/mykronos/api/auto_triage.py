"""Auto-triage: the digest, the undo, the sweep, and the VEX statements it
reads (TheHub #60888, D-169).

The lanes themselves live in `mykronos.auto_triage`; this is how a person
sees what they did and puts any of it back. Undo is one request with a
reason, open to any writer, agents included: like reopening, it only ever
adds tracking back. Recording a VEX statement is a person's act - it is
evidence one lane will close critical findings on, and an agent that cannot
close a critical itself (#713) must not be able to write the statement that
would.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from mykronos import auto_triage
from mykronos.adminauth import HumanDep, PrincipalDep
from mykronos.api.dashboard import (
    AutoTriageActionOut,
    AutoTriageDigestOut,
    auto_triage_digest_out,
)
from mykronos.db.models import AutoTriageAction, VexStatement
from mykronos.lake.maintenance import LANE_CLOSURE_LOCK
from mykronos.schemas import utcnow

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


class UndoIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(
        min_length=1,
        max_length=2000,
        description="Why the platform's verdict does not stand. Audited with the undo.",
    )


class ProposalOut(BaseModel):
    finding_id: str
    repo_full_name: str
    severity: str
    rule: str
    new_status: str
    summary: str
    evidence: dict[str, object]


class AutoTriageRunOut(BaseModel):
    dry_run: bool
    proposed: list[ProposalOut]
    applied: list[str] = Field(description="Ids of the actions written.")
    held_serious: int = Field(
        description=(
            "Critical or high findings a weak-evidence lane matched and left for "
            "a person: only a verified fix or a VEX statement closes those."
        )
    )
    disabled: dict[str, int] = Field(
        description="Lane -> findings it matched while its kill switch is off."
    )
    enabled: dict[str, bool]


@router.get("/auto-triage/digest", response_model=AutoTriageDigestOut)
async def auto_triage_digest(
    request: Request,
    principal: PrincipalDep,
    hours: Annotated[int, Query(ge=1, le=24 * 30)] = 24,
) -> AutoTriageDigestOut:
    """What the platform closed by itself in the last `hours`, by lane, each
    action with its evidence and its undo (TheHub #60888)."""
    return auto_triage_digest_out(request, hours=hours, repo=None)


@router.post("/auto-triage/actions/{action_id}/undo", response_model=AutoTriageActionOut)
async def undo_auto_triage(
    request: Request, action_id: str, body: UndoIn, principal: PrincipalDep
) -> AutoTriageActionOut:
    """Put the finding back exactly as the action found it (TheHub #60888).

    Restores the prior status, `resolved_at`, `accepted_until` and reason
    code; refused (409) if the finding no longer holds the status the action
    set, because then something else has decided since. The rule is never
    applied to that finding again.
    """
    if not principal.may_write:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Undoing an auto-triage action requires write access.",
        )
    reason = body.reason.strip()
    if not reason:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Undoing needs a reason.",
        )
    try:
        action = await asyncio.to_thread(
            auto_triage.undo,
            request.app.state.db,
            request.app.state.catalog,
            action_id,
            actor=principal.actor,
            reason=reason,
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except auto_triage.AutoTriageError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return AutoTriageActionOut.model_validate(action)


@router.get("/findings/{finding_id}/auto-triage", response_model=list[AutoTriageActionOut])
async def finding_auto_triage(
    request: Request, finding_id: str, principal: PrincipalDep
) -> list[AutoTriageActionOut]:
    """Every auto-triage action on one finding, newest first."""
    with request.app.state.db.session() as session:
        return [
            AutoTriageActionOut.model_validate(action)
            for action in session.execute(
                select(AutoTriageAction)
                .where(AutoTriageAction.finding_id == finding_id)
                .order_by(AutoTriageAction.applied_at.desc())
            ).scalars()
        ]


@router.post("/auto-triage/run", response_model=AutoTriageRunOut)
async def run_auto_triage(
    request: Request,
    principal: PrincipalDep,
    dry_run: Annotated[
        bool, Query(description="Report what the lanes would do and write nothing.")
    ] = True,
) -> AutoTriageRunOut:
    """Run the lanes now, rather than waiting for the hourly job.

    Defaults to a dry run: it closes findings, and the safe default for that
    is to show somebody first. The kill switches apply either way.
    """
    if not principal.may_write:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Running auto-triage requires write access.",
        )
    enabled = request.app.state.oracle_policy.auto_triage.enabled()

    def _run() -> auto_triage.SweepResult:
        with LANE_CLOSURE_LOCK:
            return auto_triage.sweep(
                request.app.state.db, request.app.state.catalog, enabled, dry_run=dry_run
            )

    result = await asyncio.to_thread(_run)
    return AutoTriageRunOut(
        dry_run=dry_run,
        proposed=[
            ProposalOut(
                finding_id=p.finding_id,
                repo_full_name=p.repo_full_name,
                severity=p.severity,
                rule=p.rule,
                new_status=p.new_status,
                summary=p.summary,
                evidence=p.evidence,
            )
            for p in result.proposals
        ],
        applied=result.applied,
        held_serious=result.held_serious,
        disabled=result.disabled,
        enabled=enabled,
    )


# --------------------------------------------------------------------------
# VEX statements
# --------------------------------------------------------------------------

VexStatus = Literal["not_affected", "affected", "fixed", "under_investigation"]
#: OpenVEX's justifications for `not_affected`.
VexJustification = Literal[
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
]


class VexStatementIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vulnerability_id: str = Field(min_length=1, max_length=128)
    package_name: str = Field(min_length=1, max_length=255)
    package_version: str | None = Field(
        default=None, max_length=128, description="Absent: every version."
    )
    repo_full_name: str | None = Field(
        default=None, max_length=255, description="Absent: every repository."
    )
    status: VexStatus
    justification: VexJustification | None = Field(
        default=None, description="Required for not_affected, as OpenVEX requires."
    )
    impact_statement: str = Field(default="", max_length=4000)
    source_kind: Literal["vendor", "vex"]
    source: str = Field(
        min_length=8,
        max_length=1000,
        description="Where it was said: a URL or a document reference anybody can go and read.",
    )


class VexStatementOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    vulnerability_id: str
    package_name: str
    package_version: str | None
    repo_full_name: str | None
    status: str
    justification: str
    impact_statement: str
    source_kind: str
    source: str
    recorded_by: str
    recorded_at: datetime
    revoked_at: datetime | None
    revoked_by: str | None


@router.get("/vex-statements", response_model=list[VexStatementOut])
async def list_vex_statements(
    request: Request,
    principal: PrincipalDep,
    include_revoked: Annotated[bool, Query()] = False,
) -> list[VexStatementOut]:
    with request.app.state.db.session() as session:
        query = select(VexStatement).order_by(VexStatement.recorded_at.desc())
        if not include_revoked:
            query = query.where(VexStatement.revoked_at.is_(None))
        return [VexStatementOut.model_validate(row) for row in session.execute(query).scalars()]


@router.post(
    "/vex-statements", response_model=VexStatementOut, status_code=status.HTTP_201_CREATED
)
async def record_vex_statement(
    request: Request, body: VexStatementIn, principal: HumanDep
) -> VexStatementOut:
    """Record a vendor's or a VEX document's statement (TheHub #60888).

    A person only: a `not_affected` statement is evidence the
    `vex_not_affected` lane closes critical findings on.
    """
    if body.status == "not_affected" and body.justification is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="A not_affected statement needs a justification (OpenVEX).",
        )
    with request.app.state.db.session() as session:
        row = VexStatement(
            vulnerability_id=body.vulnerability_id.strip().upper(),
            package_name=body.package_name.strip(),
            package_version=(body.package_version or "").strip() or None,
            repo_full_name=(body.repo_full_name or "").strip() or None,
            status=body.status,
            justification=body.justification or "",
            impact_statement=body.impact_statement,
            source_kind=body.source_kind,
            source=body.source.strip(),
            recorded_by=principal.actor,
            recorded_at=utcnow(),
        )
        session.add(row)
        session.flush()
        request.app.state.db.audit(
            session,
            actor=principal.actor,
            action="vex.recorded",
            entity_type="vex_statement",
            entity_id=row.id,
            vulnerability_id=row.vulnerability_id,
            package_name=row.package_name,
            status=row.status,
            source=row.source,
        )
        return VexStatementOut.model_validate(row)


@router.delete("/vex-statements/{statement_id}", response_model=VexStatementOut)
async def revoke_vex_statement(
    request: Request, statement_id: str, principal: HumanDep
) -> VexStatementOut:
    """Revoke a statement. Kept, so an action that cited it still shows what
    it cited; findings it already closed stay closed until undone."""
    with request.app.state.db.session() as session:
        row = session.get(VexStatement, statement_id)
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=f"No VEX statement {statement_id}."
            )
        if row.revoked_at is None:
            row.revoked_at = utcnow()
            row.revoked_by = principal.actor
            request.app.state.db.audit(
                session,
                actor=principal.actor,
                action="vex.revoked",
                entity_type="vex_statement",
                entity_id=row.id,
            )
        session.flush()
        return VexStatementOut.model_validate(row)
