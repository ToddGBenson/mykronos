"""The Product Owner console's phase 2 API (spec 35 §8).

Read-only views, plus one write: deciding an approval request in place, which
is the approvals engine's decision and not this module's (D-137). That write
needs the admin role and is audit-logged with its outcome, refusals included.

The repository, its manifest and its TheHub membership are resolved by the
phase 1 helpers in `api.product_owner`, so a story or request belongs to the
same repository here as it does on the Overview.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from mykronos import po_console as pc
from mykronos import product_owner as po
from mykronos.adminauth import PrincipalDep, Role
from mykronos.api import product_owner as phase1
from mykronos.approvals import pull_requests
from mykronos.approvals.engine import ApprovalError, decide
from mykronos.approvals.policy import PolicyError, cached_policy
from mykronos.db.models import ApprovalDecision, ApprovalRequest, Delegation, RepoOnboarding
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/dashboard", tags=["product-owner"])


def require_admin(principal: Any, verb: str) -> None:
    """The console's writes are the operator's (spec 35 §8.8): the `agent`
    role, which may write elsewhere, decides through the approvals API."""
    if principal.role is not Role.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"{verb} requires the 'admin' role; you have '{principal.role.value}'.",
        )


class PoHubStateOut(BaseModel):
    connected: bool
    error: str | None


def hub_state(request: Request) -> tuple[po.HubClient | None, PoHubStateOut]:
    hub = phase1._hub(request)
    if hub is None:
        return None, PoHubStateOut(connected=False, error="TheHub is not connected.")
    return hub, PoHubStateOut(connected=True, error=None)


async def repo_context(
    request: Request, repo_id: str
) -> tuple[str, str, po.ManifestState, str, bool]:
    """(full name, default branch, manifest state, tag, include_untagged)."""
    repo_full_name, branch, installation = phase1._onboarding(request, repo_id)
    state = await phase1._read_manifest(request, repo_full_name, branch, installation)
    tag, include_untagged, _ = phase1._membership(state, repo_full_name)
    return repo_full_name, branch, state, tag, include_untagged


async def member_stories(
    hub: po.HubClient, buckets: tuple[str, ...], tag: str, include_untagged: bool
) -> dict[str, list[dict[str, Any]]]:
    lists = await asyncio.gather(*(hub.list_stories(bucket) for bucket in buckets))
    return {
        bucket: [s for s in stories if po.belongs(s, tag, include_untagged)]
        for bucket, stories in zip(buckets, lists, strict=True)
    }


def gate_name(hub_gate: str, manifest: po.ProcessManifest | None) -> str | None:
    gate = po.gate_for({"gate": hub_gate}, manifest)
    return gate.name if gate is not None else None


# --------------------------------------------------------------------------
# Delivery (§8.1)
# --------------------------------------------------------------------------


class PoScanOut(BaseModel):
    capability: str | None
    status: str | None
    at: str | None
    run_url: str | None


class PoDeliveryDecisionOut(BaseModel):
    decision_type: str | None
    recommendation: str | None
    score: float | None
    evaluated_at: str | None
    gate_outcome: str | None
    human_override: str | None


class PoDeliveryRowOut(BaseModel):
    sha: str
    commit_url: str
    shipped: bool
    shipped_reason: str | None
    branches: list[str]
    pr_numbers: list[int]
    first_seen: str | None
    last_seen: str | None
    scans: list[PoScanOut]
    scan_failures: int
    decision: PoDeliveryDecisionOut | None
    #: running | not_recorded. MyKronos keeps only the running revision, so
    #: anything else is "not recorded", never "not deployed" (D-138).
    deployed: str


class PoDeploymentOut(BaseModel):
    #: The probe's status: not_configured | ok | unreachable | unparsed.
    probe_status: str
    running_revision: str | None
    observed_at: str | None


class PoDeliveryOut(BaseModel):
    repo_full_name: str
    default_branch: str
    days: int
    deployment: PoDeploymentOut
    shipped: list[PoDeliveryRowOut]
    not_shipped: list[PoDeliveryRowOut]
    #: Why the lists are empty, when they are empty for a reason.
    error: str | None


def _row_out(repo_full_name: str, row: pc.DeliveryRow) -> PoDeliveryRowOut:
    return PoDeliveryRowOut(
        sha=row.sha,
        commit_url=f"https://github.com/{repo_full_name}/commit/{row.sha}",
        shipped=row.shipped,
        shipped_reason=row.shipped_reason,
        branches=row.branches,
        pr_numbers=row.pr_numbers,
        first_seen=pc.iso(row.first_seen),
        last_seen=pc.iso(row.last_seen),
        scans=[PoScanOut(**scan) for scan in row.scans],
        scan_failures=row.scan_failures,
        decision=PoDeliveryDecisionOut(**row.decision) if row.decision else None,
        deployed=row.deployed,
    )


@router.get("/repos/{repo_id}/product-owner/delivery", response_model=PoDeliveryOut)
async def delivery(
    request: Request,
    repo_id: str,
    principal: PrincipalDep,
    days: int = Query(30, ge=1, le=180),
) -> PoDeliveryOut:
    """What shipped, by sha, joined to the Oracle decision and the running
    revision (spec 35 §8.1)."""
    repo_full_name, branch, _ = phase1._onboarding(request, repo_id)
    with request.app.state.db.session() as session:
        onboarding = session.get(RepoOnboarding, repo_id)
        revision = onboarding.deployed_revision if onboarding else None
        deployment = PoDeploymentOut(
            probe_status=str(onboarding.deployment_probe_status or "not_configured")
            if onboarding
            else "not_configured",
            running_revision=revision,
            observed_at=pc.iso(onboarding.deployed_revision_at) if onboarding else None,
        )
    since = pc.window_start(days)
    catalog = request.app.state.catalog
    error = None
    try:
        scans, decisions = await asyncio.gather(
            asyncio.to_thread(pc.scan_rows, catalog, repo_full_name, since),
            asyncio.to_thread(pc.decision_rows, catalog, repo_full_name, since),
        )
    except Exception:  # noqa: BLE001
        logger.warning("Delivery: the lake could not be read for %s", repo_full_name)
        scans, decisions, error = [], [], "The scan and decision record could not be read."
    rows = pc.build_delivery(repo_full_name, branch, scans, decisions, revision)
    return PoDeliveryOut(
        repo_full_name=repo_full_name,
        default_branch=branch,
        days=days,
        deployment=deployment,
        shipped=[_row_out(repo_full_name, r) for r in rows if r.shipped][:100],
        not_shipped=[_row_out(repo_full_name, r) for r in rows if not r.shipped][:50],
        error=error,
    )


# --------------------------------------------------------------------------
# Approvals inbox (§8.2)
# --------------------------------------------------------------------------


class PoApproverNeedOut(BaseModel):
    kind: str
    delegation_required: bool


class PoTierNeedsOut(BaseModel):
    approvers: list[PoApproverNeedOut]
    quorum: int
    independence: list[str]
    cooling_off_hours: float


class PoInboxDecisionOut(BaseModel):
    approver: str
    approver_kind: str
    verdict: str
    rationale: str
    created_at: str | None


class PoInboxItemOut(BaseModel):
    id: str
    duty: str
    tier: str
    subject_ref: str
    summary: str
    requested_by: str
    requester_kind: str
    #: The requester's claim, labelled as one (spec 34 §4.2).
    requester_statement: str
    created_at: str | None
    expires_at: str | None
    #: Pending but past its expiry. The engine will refuse a decision and
    #: mark it expired; shown so nobody is surprised by that.
    overdue: bool
    evidence_digest: str
    decisions: list[PoInboxDecisionOut]
    #: What the tier asks of an approver, from the policy. None when the
    #: policy no longer has the duty or tier.
    needs: PoTierNeedsOut | None


class PoInboxOut(BaseModel):
    repo_full_name: str
    #: Whether this caller sees the decide controls. The backend refuses a
    #: decision from anyone else regardless.
    can_decide: bool
    pending: list[PoInboxItemOut]
    #: Pending requests that name no repository, such as a delegation grant.
    #: Not decidable from a repository's tab (D-137).
    estate_wide_pending: int
    policy_version: str | None


def _policy(request: Request) -> Any:
    return cached_policy(request.app.state.settings.approval_policy_path)


@router.get("/repos/{repo_id}/product-owner/approvals", response_model=PoInboxOut)
async def approvals(request: Request, repo_id: str, principal: PrincipalDep) -> PoInboxOut:
    """This repository's pending spec 34 requests (spec 35 §8.2)."""
    repo_full_name, _, _ = phase1._onboarding(request, repo_id)
    try:
        policy = _policy(request)
    except Exception:  # noqa: BLE001
        logger.warning("The approval policy could not be loaded")
        policy = None
    now = utcnow()
    items: list[PoInboxItemOut] = []
    estate_wide = 0
    with request.app.state.db.session() as session:
        rows = session.execute(
            select(ApprovalRequest)
            .where(ApprovalRequest.state == "pending")
            .order_by(ApprovalRequest.expires_at)
            .limit(500)
        ).scalars()
        for row in rows:
            owner = pc.request_repo(row.duty, row.subject_ref, row.evidence)
            if owner is None:
                estate_wide += 1
                continue
            if not pc.same_repo(owner, repo_full_name):
                continue
            decisions = session.execute(
                select(ApprovalDecision)
                .where(ApprovalDecision.request_id == row.id)
                .order_by(ApprovalDecision.created_at)
            ).scalars()
            needs = pc.tier_needs(policy, row.duty, row.tier) if policy is not None else None
            items.append(
                PoInboxItemOut(
                    id=row.id,
                    duty=row.duty,
                    tier=row.tier,
                    subject_ref=row.subject_ref,
                    summary=pc.evidence_summary(row.duty, row.evidence),
                    requested_by=row.requested_by,
                    requester_kind=row.requester_kind,
                    requester_statement=row.requester_statement or "",
                    created_at=pc.iso(row.created_at),
                    expires_at=pc.iso(row.expires_at),
                    overdue=row.expires_at <= now,
                    evidence_digest=row.evidence_digest,
                    decisions=[
                        PoInboxDecisionOut(
                            approver=d.approver,
                            approver_kind=d.approver_kind,
                            verdict=d.verdict,
                            rationale=d.rationale,
                            created_at=pc.iso(d.created_at),
                        )
                        for d in decisions
                    ],
                    needs=PoTierNeedsOut(**needs) if needs else None,
                )
            )
    return PoInboxOut(
        repo_full_name=repo_full_name,
        can_decide=principal.role is Role.ADMIN,
        pending=items,
        estate_wide_pending=estate_wide,
        policy_version=getattr(policy, "version", None),
    )


class PoDecideIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verdict: str = Field(pattern="^(approve|reject|needs_info)$")
    rationale: str = Field(min_length=1, max_length=8000)
    #: The digest the row was rendered with. An approval is of what was seen
    #: (spec 34 §4.1), so this is never looked up again at decision time.
    evidence_digest: str = Field(min_length=64, max_length=64)


class PoDecideOut(BaseModel):
    request_id: str
    state: str
    decision_id: str
    same_person: bool
    sampled: bool


@router.post(
    "/repos/{repo_id}/product-owner/approvals/{request_id}/decision", response_model=PoDecideOut
)
async def decide_in_place(
    request: Request, repo_id: str, request_id: str, body: PoDecideIn, principal: PrincipalDep
) -> PoDecideOut:
    """Decide one of this repository's requests through the approvals engine.

    `approvals.engine.decide` runs every rule the duty's tier names, exactly as
    `/api/approvals/{id}/decisions` does (D-137). Its refusal is returned
    verbatim, and is audited like a decision that stood.
    """
    require_admin(principal, "Deciding an approval request")
    repo_full_name, _, _ = phase1._onboarding(request, repo_id)
    database = request.app.state.db
    with database.session() as session:
        row = session.get(ApprovalRequest, request_id)
        owner = pc.request_repo(row.duty, row.subject_ref, row.evidence) if row else None
        duty = row.duty if row else None
    if row is None or not pc.same_repo(owner, repo_full_name):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No approval request {request_id} for {repo_full_name}.",
        )

    def audit(outcome: str, **detail: Any) -> None:
        with database.session() as session:
            database.audit(
                session,
                actor=principal.actor,
                action="po.approval_decision",
                entity_type="approval_request",
                entity_id=request_id,
                repo_id=repo_id,
                repo_full_name=repo_full_name,
                duty=duty,
                verdict=body.verdict,
                outcome=outcome,
                **detail,
            )

    policy = _policy(request)
    try:
        outcome = decide(
            database,
            policy,
            request_id=request_id,
            approver=principal,
            verdict=body.verdict,
            rationale=body.rationale,
            evidence_digest=body.evidence_digest,
        )
    except (ApprovalError, PolicyError) as exc:
        audit("refused", engine_detail=str(exc))
        # The engine's own sentence: it names the rule that was not met.
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    await pull_requests.publish(database, policy, request.app.state.github_factory, request_id)
    audit(outcome.state, decision_id=outcome.decision_id, same_person=outcome.same_person)
    return PoDecideOut(
        request_id=outcome.request_id,
        state=outcome.state,
        decision_id=outcome.decision_id,
        same_person=outcome.same_person,
        sampled=outcome.sampled,
    )


# --------------------------------------------------------------------------
# Roles & agents (§8.3)
# --------------------------------------------------------------------------


class PoDeclaredGateOut(BaseModel):
    id: str
    name: str
    recommends: str
    approves: str
    story_gates: list[str]
    doc: str | None


class PoDelegationRefOut(BaseModel):
    id: str
    families: list[str]
    expires_at: str | None
    sampling: float


class PoEnforcedTierOut(BaseModel):
    duty: str
    tier: str
    approvers: list[str]
    quorum: int
    independence: list[str]
    cooling_off_hours: float
    #: yes | no_active_delegation | humans_only
    agent_now: str
    delegations: list[PoDelegationRefOut]


class PoRolesOut(BaseModel):
    repo_full_name: str
    manifest_state: str
    #: As the manifest declares them. Free text: nothing enforces these.
    declared: list[PoDeclaredGateOut]
    #: What the platform enforces, per duty and tier.
    enforced: list[PoEnforcedTierOut]
    policy_version: str | None
    single_operator: bool | None
    active_delegations: int
    error: str | None


@router.get("/repos/{repo_id}/product-owner/roles", response_model=PoRolesOut)
async def roles(request: Request, repo_id: str, principal: PrincipalDep) -> PoRolesOut:
    """Who the manifest says recommends and approves each gate, beside what
    the platform enforces and the delegations that exist (spec 35 §8.3)."""
    repo_full_name, _, state, _, _ = await repo_context(request, repo_id)
    manifest = state.manifest
    declared = [
        PoDeclaredGateOut(
            id=g.id,
            name=g.name,
            recommends=g.recommends,
            approves=g.approves,
            story_gates=list(g.story_gates),
            doc=g.doc,
        )
        for g in (manifest.gates if manifest else [])
    ]
    now = utcnow()
    try:
        policy = _policy(request)
    except Exception:  # noqa: BLE001
        logger.warning("The approval policy could not be loaded")
        return PoRolesOut(
            repo_full_name=repo_full_name,
            manifest_state=state.state,
            declared=declared,
            enforced=[],
            policy_version=None,
            single_operator=None,
            active_delegations=0,
            error="The approval policy could not be loaded.",
        )
    with request.app.state.db.session() as session:
        delegations = list(session.execute(select(Delegation)).scalars())
        enforced = pc.enforced_duties(policy, delegations, now)
        active = sum(1 for d in delegations if pc.delegation_active(d, now))
    return PoRolesOut(
        repo_full_name=repo_full_name,
        manifest_state=state.state,
        declared=declared,
        enforced=[PoEnforcedTierOut(**tier) for tier in enforced],
        policy_version=policy.version,
        single_operator=policy.single_operator,
        active_delegations=active,
        error=None,
    )


# --------------------------------------------------------------------------
# Retro (§8.4)
# --------------------------------------------------------------------------


class PoGateFailureOut(BaseModel):
    story_id: int
    title: str
    #: verification_rejected | run_aborted | deploy_failed | gate_check_failed
    kind: str
    hub_gate: str
    #: The repository's own name for that gate, when its manifest has one.
    gate_name: str | None
    detail: str
    at: str | None


class PoRetroStoryOut(BaseModel):
    id: int
    title: str
    size: str | None
    closed_at: str | None
    #: The Hub reads that failed for this story. Non-empty means unread, not
    #: clean.
    unread: list[str]
    failed_gates: list[str]


class PoRetroOut(BaseModel):
    repo_full_name: str
    hub: PoHubStateOut
    days: int
    #: Absent, not zero, when TheHub is not connected.
    closed: int | None
    sizes: dict[str, int]
    median_cycle_days: float | None
    failed_stories: int | None
    failures: list[PoGateFailureOut]
    no_acceptance_criteria: list[int]
    no_retrospective_note: list[int]
    carried_over: list[int]
    dry_runs: int | None
    shipped_runs: int | None
    unread: list[int]
    not_read: int
    summary: list[str]
    limitation: str
    stories: list[PoRetroStoryOut]


def failure_out(failure: pc.GateFailure, manifest: po.ProcessManifest | None) -> PoGateFailureOut:
    return PoGateFailureOut(
        story_id=failure.story_id,
        title=failure.title,
        kind=failure.kind,
        hub_gate=failure.hub_gate,
        gate_name=gate_name(failure.hub_gate, manifest),
        detail=failure.detail,
        at=failure.at,
    )


@router.get("/repos/{repo_id}/product-owner/retro", response_model=PoRetroOut)
async def retro(
    request: Request,
    repo_id: str,
    principal: PrincipalDep,
    days: int = Query(14, ge=1, le=90),
) -> PoRetroOut:
    """A computed retrospective of the stories closed in the window, and the
    gates they failed on the way (spec 35 §8.4, D-138)."""
    repo_full_name, _, state, tag, include_untagged = await repo_context(request, repo_id)
    hub, hub_out = hub_state(request)

    def empty(out: PoHubStateOut) -> PoRetroOut:
        return PoRetroOut(
            repo_full_name=repo_full_name,
            hub=out,
            days=days,
            closed=None,
            sizes={},
            median_cycle_days=None,
            failed_stories=None,
            failures=[],
            no_acceptance_criteria=[],
            no_retrospective_note=[],
            carried_over=[],
            dry_runs=None,
            shipped_runs=None,
            unread=[],
            not_read=0,
            summary=[],
            limitation=pc.RETRO_LIMITATION,
            stories=[],
        )

    if hub is None:
        return empty(hub_out)
    since = pc.window_start(days)
    try:
        buckets = await member_stories(hub, ("done", "sprint"), tag, include_untagged)
    except po.HubUnavailableError as exc:
        return empty(PoHubStateOut(connected=False, error=str(exc)))

    closed = [s for s in buckets["done"] if (at := pc.closed_at(s)) and at >= since]
    closed.sort(key=lambda s: pc.closed_at(s) or datetime.min, reverse=True)
    carried = [
        s
        for s in buckets["sprint"]
        if (entered := pc.parse_time(s.get("moved_at")) or pc.parse_time(s.get("created_at")))
        and entered < since
    ]
    evidence, not_read = await pc.evidence_for(hub, closed, ("runs", "notes", "deploys"))
    report = pc.build_retro(evidence, carried, days=days, not_read=not_read)
    manifest = state.manifest
    return PoRetroOut(
        repo_full_name=repo_full_name,
        hub=hub_out,
        days=days,
        closed=report["closed"],
        sizes=report["sizes"],
        median_cycle_days=report["median_cycle_days"],
        failed_stories=report["failed_stories"],
        failures=[failure_out(f, manifest) for f in report["failures"]],
        no_acceptance_criteria=report["no_acceptance_criteria"],
        no_retrospective_note=report["no_retrospective_note"],
        carried_over=report["carried_over"],
        dry_runs=report["dry_runs"],
        shipped_runs=report["shipped_runs"],
        unread=report["unread"],
        not_read=report["not_read"],
        summary=report["summary"],
        limitation=report["limitation"],
        stories=[PoRetroStoryOut(**s) for s in report["stories"]],
    )
