"""The agent work queue (spec 36 §2).

`GET /api/agent/work` answers the question an agent operating this platform
arrives with: what needs doing, in what order, and what could not be read. It
is a read. It starts nothing and changes nothing, so an agent may call it on
every loop; the actions it lists are existing routes that enforce their own
rules.

Gathering happens here and the reasoning in `mykronos.agent_work`, the same
split `briefing` uses: the module is pure and tested on its own, and this file
is the only place that talks to CI, the operational store and the lake.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy import select

from mykronos import agent_work, briefing, briefing_sources, playbooks
from mykronos.adminauth import Principal, PrincipalDep
from mykronos.dashboard import DashboardQueries
from mykronos.db.models import ApprovalDecision, ApprovalRequest, RepoOnboarding, RiskAcceptance
from mykronos.risk_acceptance import serialize as serialize_acceptance
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/agent", tags=["agent"])

#: Acceptances in these states can need attention; the rest are settled.
_ACCEPTANCE_STATES = ("active", "review_due", "premise_failed")


class WorkEvidenceOut(BaseModel):
    source: str
    ref: str
    detail: str


class WorkPreconditionOut(BaseModel):
    description: str
    met: bool | None
    blocked_by: str | None


class WorkActionOut(BaseModel):
    label: str
    method: str
    path: str
    effect: str
    #: The approval duty this call meets for the caller, or null when the
    #: route writes directly. Computed with the route's own rule.
    governed_by: str | None


class WorkCaveatOut(BaseModel):
    #: Stable; branch on this. See spec 36 §3.
    code: str
    detail: str


class WorkItemOut(BaseModel):
    item_id: str
    kind: str
    band: int
    title: str
    summary: str
    done_when: str
    repo_full_name: str
    severity: str | None
    weight: int
    evidence: list[WorkEvidenceOut]
    preconditions: list[WorkPreconditionOut]
    actions: list[WorkActionOut]
    caveats: list[WorkCaveatOut]
    #: `<kind>@<version>`: how to work this item. `GET /api/agent/playbooks/{kind}`.
    playbook: str


class WorkWaitingOut(BaseModel):
    kind: str
    ref: str
    repo_full_name: str
    detail: str


class WorkUnknownOut(BaseModel):
    source: str
    detail: str


class WorkQueueOut(BaseModel):
    generated_at: datetime
    actor: str
    actor_kind: str
    #: Ordered. Work from the top.
    items: list[WorkItemOut]
    #: Needs no action. Listed so it is not mistaken for work.
    waiting: list[WorkWaitingOut]
    #: Sources that could not be read. Not the same as nothing to report.
    unknown: list[WorkUnknownOut]


def _repo_ids(db: Any) -> dict[str, str]:
    with db.session() as session:
        rows = session.execute(
            select(RepoOnboarding.github_repo_full_name, RepoOnboarding.id)
        ).all()
    return {str(name): str(repo_id) for name, repo_id in rows}


def _acceptances(db: Any, repo: str | None) -> list[dict[str, Any]] | None:
    try:
        with db.session() as session:
            query = select(RiskAcceptance).where(RiskAcceptance.status.in_(_ACCEPTANCE_STATES))
            if repo:
                query = query.where(RiskAcceptance.repo_full_name == repo)
            return [serialize_acceptance(r) for r in session.execute(query).scalars()]
    except Exception:  # noqa: BLE001 - reported as unknown, not as none
        logger.debug("Could not read acceptances for the work queue")
        return None


def _own_requests(db: Any, principal: Principal) -> list[dict[str, Any]] | None:
    """The caller's pending approval requests, each with its latest decision."""
    try:
        with db.session() as session:
            requests = list(
                session.execute(
                    select(ApprovalRequest).where(
                        ApprovalRequest.requested_by == principal.actor,
                        ApprovalRequest.state == "pending",
                    )
                ).scalars()
            )
            out = []
            for req in requests:
                latest = session.execute(
                    select(ApprovalDecision)
                    .where(ApprovalDecision.request_id == req.id)
                    .order_by(ApprovalDecision.created_at.desc())
                    .limit(1)
                ).scalar_one_or_none()
                out.append(
                    {
                        "id": req.id,
                        "duty": req.duty,
                        "subject_ref": req.subject_ref,
                        "last_verdict": latest.verdict if latest else None,
                        "last_rationale": latest.rationale if latest else "",
                    }
                )
            return out
    except Exception:  # noqa: BLE001 - reported as unknown, not as none
        logger.debug("Could not read approval requests for the work queue")
        return None


def _triage_rows(request: Request, repo: str | None, limit: int) -> list[dict[str, Any]] | None:
    try:
        with request.app.state.db.session() as session:
            rows, _ = DashboardQueries(request.app.state.catalog).triage_queue(
                session,
                limit=limit if repo is None else max(limit * 10, 200),
                order="rank",
                policy=request.app.state.oracle_policy,
                store=request.app.state.knowledge,
            )
    except Exception:  # noqa: BLE001 - reported as unknown, not as none
        logger.debug("Could not read the triage queue for the work queue")
        return None
    if repo is not None:
        rows = [r for r in rows if r.get("repo_full_name") == repo][:limit]
    return rows


@router.get("/work", response_model=WorkQueueOut)
async def work(
    request: Request,
    principal: PrincipalDep,
    repo_id: Annotated[
        str | None,
        Query(description="Narrow the queue to one repository, by onboarding id."),
    ] = None,
    findings: Annotated[
        int,
        Query(ge=0, le=200, description="How many ranked findings to include."),
    ] = 25,
) -> WorkQueueOut:
    """What needs doing, in order, and what could not be read (spec 36 §2).

    Platform problems come first because a dead lane freezes every finding in
    it. Each item cites where it came from, names the approval duty its
    actions will meet, says what "done" will look like, and carries the
    caveats the platform knows about its kind. A source that could not be read
    is in `unknown`, never shown as an empty list.
    """
    state = request.app.state
    settings = state.settings
    # First, so a broken playbooks file fails the call before any gathering.
    playbook_version = _playbooks(request).version
    repo_ids = await asyncio.to_thread(_repo_ids, state.db)
    repo = None
    if repo_id is not None:
        from mykronos.api.dashboard import _resolve_repo

        repo = _resolve_repo(request, repo_id)

    default_branches, scanned_by = await asyncio.to_thread(
        briefing_sources.onboarding_maps, state.db
    )
    operational = await asyncio.to_thread(
        briefing_sources.gather, settings, state.db, state.catalog
    )
    report = await asyncio.to_thread(
        lambda: briefing.build(
            state.catalog,
            asset_id=repo,
            default_branches=default_branches,
            scanned_by=scanned_by,
            concourse_token=bool(settings.concourse_api_token),
            paused_jobs=operational.paused_jobs,
            failing_jobs=operational.failing_jobs,
            blocked_jobs=operational.blocked_jobs,
            unhealthy_jobs=operational.unhealthy_jobs,
            tokens=operational.tokens,
            toxic_combinations=operational.toxic_combinations,
            toxic_coverage=operational.toxic_coverage,
            exposure=operational.exposure,
        )
    )
    triage_rows = await asyncio.to_thread(_triage_rows, request, repo, findings)
    acceptances = await asyncio.to_thread(_acceptances, state.db, repo)
    own = await asyncio.to_thread(_own_requests, state.db, principal)

    queue = agent_work.build(
        report,
        principal,
        triage_rows=triage_rows,
        acceptances=acceptances,
        approval_requests=own,
        repo_ids=repo_ids,
        now=utcnow(),
        probe_interval_seconds=int(settings.exposure_probe_interval_seconds),
        playbook_version=playbook_version,
    )
    return WorkQueueOut.model_validate(dataclasses.asdict(queue))


# -- The track record (spec 36 §6, phase 4) -----------------------------------
#
# Kept to its own section, below the work queue, so the two grow without
# touching each other. The computation is `mykronos.agent_scorecard`; this is
# only the read and the response shape.


class ScorecardMetricOut(BaseModel):
    #: Stable; branch on this.
    name: str
    #: computed | no_data | unavailable. `no_data`: the source was read and
    #: the denominator is zero. `unavailable`: it could not be derived; `note`
    #: says why. Neither is zero.
    status: str
    source: str
    value: int | None
    denominator: int | None
    denominator_label: str
    rate: float | None
    breakdown: dict[str, int]
    note: str


class ScorecardDutyOut(BaseModel):
    duty: str
    requests: int
    by_state: dict[str, int]
    rejected: ScorecardMetricOut
    needs_info: ScorecardMetricOut


class ScorecardDelegationOut(BaseModel):
    delegation_id: str
    duty: str
    agreed: int
    reviewed: int
    window: int
    threshold: float
    below_threshold: bool | None
    suspended_at: datetime | None
    suspended_reason: str | None


class ScorecardGroupOut(BaseModel):
    family: str
    #: Null on a family's aggregate.
    instance: str | None
    actor: str
    instances: list[str]
    metrics: list[ScorecardMetricOut]
    requests_by_duty: list[ScorecardDutyOut]
    #: The delegations this group's approvals were made under, with the
    #: agreement that suspends them (spec 34 §5.2).
    delegations: list[ScorecardDelegationOut]


class ScorecardOut(BaseModel):
    generated_at: datetime
    agreement_window: int
    suspend_below_agreement: float
    policy_version: str
    families: list[ScorecardGroupOut]
    instances: list[ScorecardGroupOut]
    #: Disposition audit entries that name no actor kind: written before
    #: spec 34 §1, or by a CLI or script. No agent's record includes them.
    unattributed_dispositions: int | None
    #: Sources that could not be read. Not the same as an empty record.
    unknown: list[WorkUnknownOut]


@router.get("/scorecard", response_model=ScorecardOut)
async def scorecard(
    request: Request,
    principal: PrincipalDep,
    family: Annotated[
        str | None, Query(description="Only this model family, e.g. claude-opus-5.5.")
    ] = None,
    instance: Annotated[
        str | None, Query(description="Only this agent instance id.")
    ] = None,
) -> ScorecardOut:
    """An agent's track record, per model family and per instance (spec 36 §6).

    Readable by any principal: it is the record a delegation rests on (spec
    34 §5), and an agent deciding whether its own work is trusted should read
    the same numbers the operator does. It carries counts, never rationales or
    notes.

    Every metric names its source and its denominator. One the existing
    records cannot support is `unavailable` with the reason, never zero.
    """
    # Imported here rather than at the top so this section touches nothing
    # above it: the work queue and its playbooks change that block.
    from mykronos import agent_scorecard
    from mykronos.approvals.policy import cached_policy

    state = request.app.state
    policy = cached_policy(state.settings.approval_policy_path)
    now = utcnow()
    gathered = await asyncio.to_thread(
        agent_scorecard.gather, state.db, state.catalog, policy, now=now
    )
    card = agent_scorecard.compute(gathered, policy, now=now, family=family, instance=instance)
    return ScorecardOut.model_validate(dataclasses.asdict(card))


# ---------------------------------------------------------------------------
# Playbooks (spec 36 §5)
#
# Reads of `agent-playbooks-v1.yaml`, the reviewed file that says how each kind
# of item above is worked. Every item's `playbook` field names one of these.
# Any principal may read them: a playbook grants nothing, and a person reading
# what an agent was told to do is the point of keeping it in a file.


class PlaybookStepOut(BaseModel):
    id: str
    do: str
    #: What to confirm before moving on.
    check: str
    #: `METHOD /path` this step reads or calls; `{repo_id}` is the onboarding id.
    routes: list[str]
    #: Evidence outside this API: a gh command, a build log, the item's evidence.
    outside: list[str]
    #: For a diagnostic branch: what it means when the check finds the cause.
    if_found: str
    #: continue | repair | escalate | stop: what follows when `if_found` applies.
    then: str


class PlaybookEscalationOut(BaseModel):
    when: list[str]
    evidence: list[str]


class PlaybookOut(BaseModel):
    kind: str
    version: str
    #: `<kind>@<version>`, as a work item carries it.
    ref: str
    purpose: str
    #: Ordered. Work from the top.
    steps: list[PlaybookStepOut]
    stop_when: list[str]
    escalate: PlaybookEscalationOut
    never: list[str]


class PlaybookSetOut(BaseModel):
    version: str
    #: One per work-item kind, in band order.
    playbooks: list[PlaybookOut]


def _playbooks(request: Request) -> playbooks.Playbooks:
    try:
        return playbooks.cached_playbooks(request.app.state.settings.agent_playbooks_path)
    except playbooks.PlaybookError as exc:
        # Loud on purpose: a queue whose items name playbooks that cannot be
        # read is worse than no queue (spec 36 §5).
        logger.error("Agent playbooks could not be loaded: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"The agent playbooks could not be loaded: {exc}",
        ) from exc


def _playbook_out(book: playbooks.Playbook) -> PlaybookOut:
    return PlaybookOut.model_validate({**dataclasses.asdict(book), "ref": book.ref})


@router.get("/playbooks", response_model=PlaybookSetOut)
async def list_playbooks(request: Request, principal: PrincipalDep) -> PlaybookSetOut:
    """Every playbook, one per kind of work item, in band order (spec 36 §5)."""
    loaded = _playbooks(request)
    return PlaybookSetOut(
        version=loaded.version,
        playbooks=[_playbook_out(book) for book in loaded.playbooks.values()],
    )


@router.get("/playbooks/{kind}", response_model=PlaybookOut)
async def get_playbook(request: Request, kind: str, principal: PrincipalDep) -> PlaybookOut:
    """How to work one kind of item: ordered steps, the check between them,
    when to stop, and when to hand it to a person with what evidence."""
    book = _playbooks(request).get(kind)
    if book is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No playbook for kind {kind!r}. Kinds: {', '.join(agent_work.KINDS)}.",
        )
    return _playbook_out(book)
