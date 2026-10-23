"""The triage queue by cluster, and one disposition for the cluster
(TheHub #60887, D-168).

`GET /api/dashboard/triage/clusters` is the queue grouped by `clusters.build`:
each cluster with its reason, its representative, its members, a count and
the worst severity among them. `POST .../clusters/{cluster_id}/disposition`
records one verdict for every member.

**The group is always the whole group.** Clusters are built over every open
finding in an active repository and the queue's filters only choose which
clusters are shown - a cluster appears when any member matches - never which
members a cluster has. Otherwise a person filtering to `severity=high` would
see three members, decide, and close the five mediums they never saw.

**A cluster disposition is the same decision as the status route, once per
member.** Each member goes through `apply_finding_status`, which writes its
own `finding.status` audit entry - here carrying the cluster id - plus the
knowledge capture and every refusal the single route has. And the governed
rule (#713) is applied to the cluster, not per row: when an agent's verdict
would need an approval on any member, the cluster raises **one** request under
`finding_disposition` covering every member, and nothing is applied until it
is approved. N requests for one decision would ask the approver the same
question N times, which is the waste clusters exist to remove.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import date
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field

from mykronos import clusters, finding_disposition
from mykronos.adminauth import PrincipalDep
from mykronos.api.dashboard import (
    HUMAN_DISPOSITIONS,
    AcceptanceReason,
    StatusChange,
    TriageItem,
    apply_finding_status,
)
from mykronos.approvals.engine import ApprovalError
from mykronos.approvals.engine import create_request as create_approval_request
from mykronos.approvals.policy import cached_policy as cached_approval_policy
from mykronos.dashboard import CORRELATION_CEILING, DashboardQueries
from mykronos.logsafe import scrub
from mykronos.schemas import Capability, FindingStatus, Severity

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/dashboard/triage", tags=["dashboard"])

ClusterKind = Literal["advisory", "location", "single"]


class ClusterOut(BaseModel):
    """Open findings one decision covers, and why (TheHub #60887)."""

    cluster_id: str = Field(
        description=(
            "A hash of the rule and its key, never of the members: stable across "
            "rescans that add or remove members."
        )
    )
    kind: ClusterKind
    reason: str = Field(description="Why these findings are one decision, in a sentence.")
    count: int
    max_severity: Severity
    repos: list[str]
    images: list[str] = Field(
        default_factory=list,
        description="Image repositories a container member was reported in.",
    )
    representative: TriageItem
    members: list[TriageItem] = Field(
        description="Every open member, worst first - including ones the filters did not match."
    )
    folded_ids: list[str] = Field(
        default_factory=list,
        description="Members that joined as a Debian TEMP- placeholder folded into its CVE.",
    )


class ClusterQueue(BaseModel):
    clusters: list[ClusterOut]
    total_clusters: int = Field(
        description="Clusters with at least one member matching the filters."
    )
    total_findings: int = Field(description="Open findings in those clusters.")
    truncated: bool = Field(description="Whether `limit` cut the list of clusters short.")
    pool_truncated: bool = Field(
        description=(
            "Whether the open findings clustered were capped. A capped pool can "
            "split a cluster, so it is said rather than hidden."
        )
    )


class ClusterDisposition(BaseModel):
    """One verdict for every member of a cluster."""

    model_config = ConfigDict(extra="forbid")

    status: FindingStatus
    reason: str = Field(
        min_length=1,
        max_length=2000,
        description="Required. One reason covering the cluster, recorded on every member.",
    )
    member_ids: list[str] | None = Field(
        default=None,
        max_length=CORRELATION_CEILING,
        description=(
            "The members the caller saw. When given, the disposition is refused "
            "(409) unless they are exactly the cluster's open members now - a "
            "decision covers what the person looked at, not what arrived since."
        ),
    )
    accepted_until: date | None = None
    indefinite: bool = False
    accepted_reason_code: AcceptanceReason | None = None


class ClusterDispositionOut(BaseModel):
    cluster_id: str
    status: str
    outcome: Literal["applied", "pending_approval"]
    applied: list[str] = Field(default_factory=list)
    refused: dict[str, str] = Field(default_factory=dict)
    approval_request_id: str | None = None
    tier: str | None = None


def _pool(request: Request, order: str = "severity") -> tuple[list[dict[str, Any]], bool]:
    """Every open finding in an active repository, decorated like the queue."""
    with request.app.state.db.session() as session:
        rows, _counts = DashboardQueries(request.app.state.catalog).triage_queue(
            session,
            limit=CORRELATION_CEILING,
            order=order,
            policy=request.app.state.oracle_policy,
            include_snoozed=True,
            store=request.app.state.knowledge,
        )
    return rows, len(rows) >= CORRELATION_CEILING


def _out(cluster: clusters.Cluster) -> ClusterOut:
    summary = cluster.as_dict()
    return ClusterOut(
        cluster_id=cluster.cluster_id,
        kind=cluster.kind,  # type: ignore[arg-type]
        reason=summary["reason"],
        count=summary["count"],
        max_severity=Severity(summary["max_severity"]),
        repos=summary["repos"],
        images=summary["images"],
        representative=TriageItem(**cluster.representative),
        members=[TriageItem(**member) for member in cluster.members],
        folded_ids=sorted(cluster.folded),
    )


@router.get("/clusters", response_model=ClusterQueue)
async def triage_clusters(
    request: Request,
    principal: PrincipalDep,
    severity: Annotated[Severity | None, Query()] = None,
    capability: Annotated[Capability | None, Query()] = None,
    rule_id: Annotated[str | None, Query(max_length=200)] = None,
    kev_only: Annotated[bool, Query()] = False,
    min_epss: Annotated[float | None, Query(ge=0.0, le=1.0)] = None,
    owner: Annotated[str | None, Query(max_length=255)] = None,
    order: Annotated[Literal["severity", "rank"], Query()] = "severity",
    include_snoozed: Annotated[bool, Query()] = False,
    claimed_by: Annotated[str | None, Query(max_length=255)] = None,
    triage: Annotated[
        Literal["true_positive", "likely_false_positive", "needs_human_judgment"] | None,
        Query(),
    ] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> ClusterQueue:
    """The triage queue, one row per cluster (TheHub #60887).

    Takes the queue's own filters. They choose clusters - one is listed when
    any member matches - and never trim a cluster's members, because the
    disposition beside it covers all of them.
    """
    pool, pool_truncated = _pool(request, order)
    with request.app.state.db.session() as session:
        matching, _counts = DashboardQueries(request.app.state.catalog).triage_queue(
            session,
            severity=severity.value if severity else None,
            capability=capability.value if capability else None,
            rule_id=rule_id,
            limit=CORRELATION_CEILING,
            kev_only=kev_only,
            min_epss=min_epss,
            owner=owner,
            order="severity",
            include_snoozed=include_snoozed,
            claimed_by=claimed_by,
            triage=triage,
            store=request.app.state.knowledge,
        )
    wanted = {str(row["finding_id"]) for row in matching}
    built = [c for c in clusters.build(pool) if wanted.intersection(c.member_ids)]
    if order == "rank":
        built.sort(
            key=lambda c: (
                -max(float(m.get("rank") or 0.0) for m in c.members),
                c.cluster_id,
            )
        )
    shown = built[:limit]
    return ClusterQueue(
        clusters=[_out(c) for c in shown],
        total_clusters=len(built),
        total_findings=sum(len(c.members) for c in built),
        truncated=len(built) > limit,
        pool_truncated=pool_truncated,
    )


@router.post("/clusters/{cluster_id}/disposition", response_model=ClusterDispositionOut)
async def disposition_cluster(
    request: Request, cluster_id: str, body: ClusterDisposition, principal: PrincipalDep
) -> ClusterDispositionOut:
    """One verdict for every open member of a cluster (TheHub #60887).

    Applied member by member through the status route's own path, each with
    its own audit entry naming the cluster. When the caller is an agent and
    any member is critical or high, nothing is applied: one approval request
    under `finding_disposition` covers the whole cluster, tiered by its worst
    governed member.
    """
    if not principal.may_write:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Dispositioning a cluster requires write access.",
        )
    if body.status not in HUMAN_DISPOSITIONS:
        allowed = ", ".join(sorted(s.value for s in HUMAN_DISPOSITIONS))
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"'{body.status.value}' is not a disposition. Allowed: {allowed}.",
        )
    reason = body.reason.strip()
    if not reason:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Dispositioning a cluster needs a reason; it is recorded on every member.",
        )

    pool, _truncated = _pool(request)
    cluster = clusters.find(clusters.build(pool), cluster_id)
    if cluster is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No cluster {cluster_id} has an open member.",
        )
    members = cluster.member_ids
    if body.member_ids is not None and sorted(set(body.member_ids)) != sorted(members):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Cluster {cluster_id} now has {len(members)} open member(s), not the "
                f"{len(set(body.member_ids))} you saw. Reload it and decide again: "
                "a disposition covers what was looked at."
            ),
        )

    # Each member at its governing severity: a member of a high or critical
    # toxic combination counts as one (review of #1018).
    governed = finding_disposition.governed_findings(principal, cluster.members)
    if governed:
        if body.status is FindingStatus.ACCEPTED_RISK:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "An agent may not accept the risk of a cluster holding a critical or "
                    "high finding directly (#713). Use POST /api/risk-acceptances."
                ),
            )
        settings = request.app.state.settings
        try:
            policy = cached_approval_policy(settings.approval_policy_path)
            created = await asyncio.to_thread(
                create_approval_request,
                request.app.state.db,
                policy,
                duty=finding_disposition.DUTY,
                subject_ref=cluster_id,
                requested_by=principal,
                statement=reason,
                context={
                    "status": body.status.value,
                    "reason": reason,
                    "finding_ids": members,
                    "cluster_reason": cluster.reason,
                },
            )
        except ApprovalError as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
        return ClusterDispositionOut(
            cluster_id=cluster_id,
            status=body.status.value,
            outcome="pending_approval",
            approval_request_id=created.id,
            tier=created.tier,
        )

    change = StatusChange(
        status=body.status,
        reason=reason,
        accepted_until=body.accepted_until,
        indefinite=body.indefinite,
        accepted_reason_code=body.accepted_reason_code,
    )
    applied: list[str] = []
    refused: dict[str, str] = {}
    for finding_id in members:
        try:
            await apply_finding_status(
                request,
                finding_id,
                change,
                principal,
                audit_extra={"cluster_id": cluster_id, "cluster_kind": cluster.kind},
            )
            applied.append(finding_id)
        except HTTPException as exc:
            refused[finding_id] = str(exc.detail)

    with request.app.state.db.session() as session:
        request.app.state.db.audit(
            session,
            actor=principal.actor,
            action="triage.cluster_disposition",
            entity_type="cluster",
            entity_id=cluster_id,
            new_status=body.status.value,
            reason=reason,
            cluster_reason=cluster.reason,
            applied=applied,
            refused=refused,
        )
    logger.info(
        "Cluster %s -> %s by %s: %d applied, %d refused",
        scrub(cluster_id),
        body.status.value,
        scrub(principal.actor),
        len(applied),
        len(refused),
    )
    return ClusterDispositionOut(
        cluster_id=cluster_id,
        status=body.status.value,
        outcome="applied",
        applied=applied,
        refused=refused,
    )
