"""`GET /api/dashboard/today`: the run sheet's steps (TheHub #61141).

The reasoning lives in `mykronos.runsheet`; this shapes it. Read-only.
"""

from __future__ import annotations

import dataclasses
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from mykronos import runsheet
from mykronos.adminauth import PrincipalDep
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
    )
