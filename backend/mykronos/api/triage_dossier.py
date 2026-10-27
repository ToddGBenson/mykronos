"""The investigation dossier, and model proposals in shadow (TheHub #60893).

`GET /api/dashboard/findings/{finding_id}/dossier` - location, owner,
history, how the same rule was decided elsewhere, the cluster, and every
shadow proposal with its grade.

`POST /api/dashboard/findings/{finding_id}/model-proposals` - record what a
model proposed after reading the code. Recorded under `finding_disposition`
in shadow: the finding is not touched and no approval is raised.

`GET /api/dashboard/triage/model-proposals/grade` - each model's agreement
with the verdicts people recorded afterwards.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator

from mykronos import clusters, dossier, shadow_proposals
from mykronos.adminauth import PrincipalDep
from mykronos.api.triage_clusters import _pool
from mykronos.dashboard import DashboardQueries
from mykronos.logsafe import scrub

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

ProposedStatus = Literal["true_positive", "false_positive", "suppressed", "accepted_risk"]
Grade = Literal["agree", "disagree", "pending", "ineligible"]
#: A proposal's evidence is a list of what was read, not the code itself.
EVIDENCE_MAX_BYTES = 16_384


class DossierLocationOut(BaseModel):
    repo_full_name: str
    capability: str
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    symbol: str | None = None
    package_name: str | None = None
    package_version: str | None = None
    asset: str | None = None


class DossierOwnerOut(BaseModel):
    owner: str | None = None
    #: codeowners | risk_profile | repo_owner | ... ; null when nobody.
    owner_source: str | None = None


class DossierEventOut(BaseModel):
    at: datetime
    event: str
    actor: str
    detail: str = ""


class SimilarDispositionOut(BaseModel):
    finding_id: str
    repo_full_name: str
    #: The precedent's own repository id, for its record page's route; null
    #: when that repository is no longer onboarded.
    repo_id: str | None = None
    capability: str
    status: str
    resolved_at: datetime | None = None
    accepted_reason_code: str | None = None
    where: str | None = None
    reason: str | None = None
    decided_by: str | None = None


class DossierClusterOut(BaseModel):
    cluster_id: str
    kind: str
    reason: str
    count: int
    member_ids: list[str]


class ProposalOut(BaseModel):
    """One shadow proposal and how it graded. `applied` is always false."""

    id: str
    model: str
    proposed_status: ProposedStatus
    confidence: float | None = None
    rationale: str
    evidence: dict[str, Any] = {}
    proposed_by: str
    created_at: datetime
    applied: Literal[False] = False
    grade: Grade
    human_verdict: str | None = None
    human_actor: str | None = None
    verdict_at: datetime | None = None


class DossierOut(BaseModel):
    """What somebody reads before deciding (TheHub #60893)."""

    finding_id: str
    status: str
    severity: str
    title: str
    location: DossierLocationOut
    owner: DossierOwnerOut
    history: list[DossierEventOut]
    similar_dispositions: list[SimilarDispositionOut]
    #: Null when the finding is not open (clusters are of open findings).
    cluster: DossierClusterOut | None = None
    proposals: list[ProposalOut]
    proposals_mode: Literal["shadow"] = "shadow"


class ProposalIn(BaseModel):
    proposed_status: ProposedStatus
    rationale: str = Field(min_length=1, max_length=8000)
    model: str = Field(
        min_length=1,
        max_length=128,
        description="The exact model id that read the code; grades are per model.",
    )
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    evidence: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "What was read: files and line ranges, as the proposer reports them. "
            f"At most {EVIDENCE_MAX_BYTES} bytes as JSON."
        ),
    )

    @field_validator("evidence")
    @classmethod
    def _bounded(cls, value: dict[str, Any]) -> dict[str, Any]:
        # Stored on every proposal and returned on every dossier read.
        if len(json.dumps(value, default=str)) > EVIDENCE_MAX_BYTES:
            raise ValueError(f"evidence is larger than {EVIDENCE_MAX_BYTES} bytes as JSON")
        return value


class ModelGradeOut(BaseModel):
    model: str
    proposals: int
    graded: int
    agree: int
    disagree: int
    pending: int
    ineligible: int
    agreement_rate: float | None = None
    pairs: dict[str, int] = {}


class GradeReportOut(BaseModel):
    duty: str
    mode: Literal["shadow"]
    #: Proposals that changed a finding. Zero by construction.
    applied: int
    models: list[ModelGradeOut]
    interpretation: str


def _finding(request: Request, finding_id: str) -> dict[str, Any]:
    row = DashboardQueries(request.app.state.catalog).finding(finding_id)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"No finding {finding_id}."
        )
    return row


def _cluster_of(request: Request, finding_id: str) -> clusters.Cluster | None:
    pool, _truncated = _pool(request)
    for cluster in clusters.build(pool):
        if finding_id in cluster.member_ids:
            return cluster
    return None


@router.get("/findings/{finding_id}/dossier", response_model=DossierOut)
async def finding_dossier(
    request: Request, finding_id: str, principal: PrincipalDep
) -> DossierOut:
    """Location, owner, history, similar past dispositions, the cluster, and
    shadow model proposals with their grades - for one finding."""
    row = _finding(request, finding_id)
    cluster = _cluster_of(request, finding_id) if row.get("status") == "open" else None
    catalog = request.app.state.catalog
    with request.app.state.db.session() as session:
        events = dossier.history(session, row)
        precedents = dossier.similar(catalog, session, row)
        proposed = dossier.proposals(session, catalog, finding_id)
    return DossierOut(
        finding_id=finding_id,
        status=str(row.get("status") or ""),
        severity=str(row.get("severity") or ""),
        title=str(row.get("title") or ""),
        location=DossierLocationOut(**dossier.location(row)),
        owner=DossierOwnerOut(
            owner=row.get("owner") or None, owner_source=row.get("owner_source") or None
        ),
        history=[DossierEventOut(**e) for e in events],
        similar_dispositions=[SimilarDispositionOut(**s) for s in precedents],
        cluster=(
            DossierClusterOut(
                cluster_id=cluster.cluster_id,
                kind=cluster.kind,
                reason=cluster.reason,
                count=len(cluster.members),
                member_ids=cluster.member_ids,
            )
            if cluster is not None
            else None
        ),
        proposals=[ProposalOut(**p) for p in proposed],
    )


@router.post(
    "/findings/{finding_id}/model-proposals",
    response_model=ProposalOut,
    status_code=status.HTTP_201_CREATED,
)
async def record_model_proposal(
    request: Request, finding_id: str, body: ProposalIn, principal: PrincipalDep
) -> ProposalOut:
    """Record a model's proposed verdict, in shadow.

    Never applied: the finding's status does not change and no approval is
    requested. The proposal is graded later against the verdict a person
    records (`GET /api/dashboard/triage/model-proposals/grade`).
    """
    if not principal.may_write:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Recording a model proposal is a write; a viewer cannot.",
        )
    row = _finding(request, finding_id)
    cluster = _cluster_of(request, finding_id) if row.get("status") == "open" else None
    with request.app.state.db.session() as session:
        proposal = shadow_proposals.record(
            session,
            finding=row,
            proposed_status=body.proposed_status,
            rationale=body.rationale,
            model=body.model,
            confidence=body.confidence,
            evidence=body.evidence,
            proposed_by=principal.actor,
            actor_kind=principal.kind.value,
            cluster_id=cluster.cluster_id if cluster is not None else "",
        )
        request.app.state.db.audit(
            session,
            actor=principal.actor,
            action="finding.model_proposal",
            entity_type="finding",
            entity_id=finding_id,
            duty=shadow_proposals.DUTY,
            mode=shadow_proposals.MODE,
            proposal_id=proposal.id,
            proposed_status=body.proposed_status,
            model=body.model,
        )
        out = ProposalOut(
            id=proposal.id,
            model=proposal.model,
            proposed_status=body.proposed_status,
            confidence=proposal.confidence,
            rationale=proposal.rationale,
            evidence=proposal.evidence or {},
            proposed_by=proposal.proposed_by,
            created_at=proposal.created_at,
            grade="pending",
        )
    logger.info(
        "Shadow proposal %s on %s by %s (%s): not applied",
        scrub(body.proposed_status),
        scrub(finding_id[:12]),
        scrub(principal.actor),
        scrub(body.model),
    )
    return out


@router.get("/triage/model-proposals/grade", response_model=GradeReportOut)
async def grade_model_proposals(request: Request, principal: PrincipalDep) -> GradeReportOut:
    """How often each model's shadow proposals matched what a person decided."""
    with request.app.state.db.session() as session:
        report = shadow_proposals.grade(session, request.app.state.catalog)
    return GradeReportOut.model_validate(report)
