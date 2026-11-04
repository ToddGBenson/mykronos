"""`GET /api/dashboard/today`: the run sheet's steps (TheHub #61141), and its actions.

The reasoning lives in `mykronos.runsheet`; this shapes it. The sheet is
read-only. Its two actions, Merge in order and Deploy (TheHub #61142), are
behind `runsheet_actions_enabled`, which defaults off, and are a person's
alone. Neither merges nor deploys: each re-checks and queues a request for
the host runner (`mykronos.runsheet_actions`).
"""

from __future__ import annotations

import dataclasses
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select

from mykronos import runsheet, runsheet_actions
from mykronos.adminauth import HumanDep, Principal, PrincipalDep
from mykronos.db.models import RunsheetRequest
from mykronos.schemas import utcnow

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

State = Literal["ready", "waiting", "blocked", "done", "unknown"]


class RunSheetItemOut(BaseModel):
    text: str
    state: State
    reason: str
    owner: str = Field(description="Whose move it is: you, an agent, Delivery, CI, the reviewer.")
    ref: str = Field(default="", description="A request id, `repo#number` or a story `#id`.")
    url: str = ""
    sha: str = Field(default="", description="For a pull request, the head it was judged at.")


class RunSheetStepOut(BaseModel):
    key: Literal["decide", "merge", "deploy", "tasks"]
    title: str
    state: State
    summary: str
    items: list[RunSheetItemOut]
    hidden: list[str] = Field(
        description="What was left out and why: superseded requests, drafts, done tasks."
    )
    status: Literal["ok", "partial", "unavailable"] = Field(
        description="Whether the step's sources were read. Anything but ok carries a reason."
    )
    reason: str
    notes: list[str] = Field(description="Guards the server cannot check, named, never guessed.")


class RunSheetOut(BaseModel):
    generated_at: datetime
    steps: list[RunSheetStepOut]
    actions_enabled: bool = Field(
        default=False,
        description=(
            "Whether Merge in order and Deploy answer (`runsheet_actions_enabled`, "
            "off by default). False: render no button (TheHub #61142)."
        ),
    )


@router.get("/today", response_model=RunSheetOut)
async def today(request: Request, principal: PrincipalDep) -> RunSheetOut:
    """Today's run sheet: decide, merge, deploy, tasks (TheHub #61141).

    What Start-Here computes, computed here: pending approvals minus the
    superseded ones, each open pull request's readiness, the production
    deploy's guards, and the operator's actions on the board. Every line has a
    state, a reason and an owner. A source that could not be read makes its
    step `partial` or `unavailable` with the reason, never an empty step.
    Red and silent lanes are the briefing's (`GET /api/dashboard/briefing`).
    Read-only.
    """
    now = utcnow()
    steps = await runsheet.gather(request.app.state, now)
    return RunSheetOut(
        generated_at=now,
        steps=[RunSheetStepOut.model_validate(dataclasses.asdict(s)) for s in steps],
        actions_enabled=_enabled(request),
    )


# -- Actions (TheHub #61142), shipped off ------------------------------------------


SHA = r"^[0-9a-f]{40}$"


class MergeAskIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repo_full_name: str = Field(min_length=3, max_length=255, pattern=r"^[\w.-]+/[\w.-]+$")
    number: int = Field(gt=0)
    head_sha: str = Field(pattern=SHA, description="The head the run sheet showed.")


class MergeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pull_requests: list[MergeAskIn] = Field(
        min_length=1, max_length=runsheet_actions.MAX_BATCH
    )
    acknowledged_host_guards: Literal[True] = Field(
        description="The operator read the guards only the host can check.",
    )


class MergeOutcomeOut(BaseModel):
    repo_full_name: str
    number: int
    head_sha: str
    result: Literal["accepted", "refused", "not_queued"]
    reason: str


class MergeQueuedOut(BaseModel):
    id: str
    state: Literal["queued"]
    outcomes: list[MergeOutcomeOut] = Field(description="In merge order: TheHub first.")
    notes: list[str]


class DeployIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sha: str = Field(pattern=SHA, description="The sha the Deploy step showed.")
    acknowledged_host_guards: Literal[True] = Field(
        description="The operator read the guards only the host can check.",
    )


class DeployQueuedOut(BaseModel):
    id: str
    state: Literal["queued"]
    sha: str
    notes: list[str]


def _enabled(request: Request) -> bool:
    return bool(getattr(request.app.state.settings, "runsheet_actions_enabled", False))


def _require_enabled(request: Request) -> None:
    if not _enabled(request):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Run sheet actions are switched off (runsheet_actions_enabled).",
        )


def _open_requests(request: Request, kind: str) -> int:
    with request.app.state.db.session() as session:
        return int(
            session.scalar(
                select(func.count())
                .select_from(RunsheetRequest)
                .where(
                    RunsheetRequest.kind == kind,
                    RunsheetRequest.state.in_(runsheet_actions.OPEN_STATES),
                )
            )
            or 0
        )


def _audit_all(
    request: Request, principal: Principal, action: str, entries: list[dict[str, Any]]
) -> None:
    database = request.app.state.db
    with database.session() as session:
        for detail in entries:
            database.audit(
                session,
                actor=principal.actor,
                action=action,
                entity_type="runsheet_request",
                entity_id=str(detail.get("request_id") or ""),
                **detail,
            )


@router.post(
    "/today/merge", response_model=MergeQueuedOut, status_code=status.HTTP_202_ACCEPTED
)
async def queue_merge(request: Request, body: MergeIn, principal: HumanDep) -> MergeQueuedOut:
    """Merge in order: queue the batch for the host runner (TheHub #61142). Off by default.

    A person only. Re-computes the Merge step and reads each pull request's
    live head now. Refuses the whole batch (409) if any one is not ready, is
    not at the head the sheet showed, has moved, is closed or stacked, or
    cannot be read, or if a batch is already queued. The server merges
    nothing: the runner merges each in this order with
    `--match-head-commit` and stops at the first failure.
    """
    _require_enabled(request)
    asks = [
        runsheet_actions.MergeAsk(p.repo_full_name, p.number, p.head_sha)
        for p in body.pull_requests
    ]
    if _open_requests(request, runsheet_actions.MERGE):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            {"reason": "A merge batch is already queued; one batch at a time.", "outcomes": []},
        )
    state = request.app.state
    step = await runsheet_actions.merge_view(state, utcnow())
    check = await runsheet_actions.check_batch(
        asks, step=step, client_for=runsheet_actions.reader_for(state)
    )
    outcomes = [MergeOutcomeOut.model_validate(dataclasses.asdict(o)) for o in check.outcomes]
    if not check.accepted:
        _audit_all(
            request,
            principal,
            "runsheet.merge_request",
            [{**o.model_dump(), "outcome": "refused"} for o in outcomes],
        )
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            {
                "reason": "The batch was refused; nothing was queued.",
                "outcomes": [o.model_dump() for o in outcomes],
            },
        )
    items = [
        {"repo_full_name": o.repo_full_name, "number": o.number, "head_sha": o.head_sha}
        for o in outcomes
    ]
    with state.db.session() as session:
        row = RunsheetRequest(
            kind=runsheet_actions.MERGE, items=items, requested_by=principal.actor
        )
        session.add(row)
        session.flush()
        request_id = row.id
    _audit_all(
        request,
        principal,
        "runsheet.merge_request",
        [{**item, "request_id": request_id, "outcome": "queued"} for item in items],
    )
    return MergeQueuedOut(
        id=request_id,
        state="queued",
        outcomes=outcomes,
        notes=[
            "Queued in this order. The runner merges each at exactly the head above "
            "and stops at the first failure.",
            runsheet_actions.HOST_NOTE,
        ],
    )


@router.post(
    "/today/deploy", response_model=DeployQueuedOut, status_code=status.HTTP_202_ACCEPTED
)
async def queue_deploy(
    request: Request, body: DeployIn, principal: HumanDep
) -> DeployQueuedOut:
    """Deploy: queue a production deploy of main for the host runner (TheHub #61142).

    Off by default, and a person only. Re-checks now: the Deploy step is
    ready, `sha` is main's head, Delivery succeeded, the deploy lanes are
    green, the risk gate said go, the backup window is clear, and no deploy is
    queued. Any failure is a 409 with the reason. The server deploys nothing.
    """
    _require_enabled(request)
    state = request.app.state
    step, facts = await runsheet_actions.deploy_view(state, utcnow())
    refusal = runsheet_actions.deploy_refusal(
        step, facts, body.sha, open_requests=_open_requests(request, runsheet_actions.DEPLOY)
    )
    if refusal:
        _audit_all(
            request,
            principal,
            "runsheet.deploy_request",
            [{"sha": body.sha, "outcome": "refused", "reason": refusal}],
        )
        raise HTTPException(status.HTTP_409_CONFLICT, refusal)
    with state.db.session() as session:
        row = RunsheetRequest(
            kind=runsheet_actions.DEPLOY, sha=body.sha, requested_by=principal.actor
        )
        session.add(row)
        session.flush()
        request_id = row.id
    _audit_all(
        request,
        principal,
        "runsheet.deploy_request",
        [{"sha": body.sha, "outcome": "queued", "request_id": request_id}],
    )
    return DeployQueuedOut(
        id=request_id,
        state="queued",
        sha=body.sha,
        notes=[runsheet_actions.HOST_NOTE],
    )
