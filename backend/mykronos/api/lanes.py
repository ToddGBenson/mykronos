"""Retiring a scan lane on purpose, and reading every lane's state (TheHub #60816).

`lane_status` infers a lane retired when the configuration no longer lists
it. A lane still configured and deliberately unused needs a person to say so,
or it reads stale - correctly, because from the outside it looks exactly like
a broken one. These routes are that saying: a person retires a lane with a
reason, or restores one, and each is audited. Agents cannot: what counts as a
deliberately idle lane is the operator's call, and an agent that could retire
a lane could hide one it broke.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from mykronos import lane_status
from mykronos.adminauth import HumanDep
from mykronos.db.models import RetiredLane, capability_config_for
from mykronos.scan_run_report import ScanRunReport
from mykronos.schemas import utcnow

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


class LaneIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    #: The lane, as the check history's `lanes` names it. Null or empty for a
    #: part the lane does not have.
    tool_name: str | None = Field(default=None, max_length=100)
    job: str | None = Field(default=None, max_length=200)
    reason: str = Field(min_length=1, max_length=2000)


class RetiredLaneOut(BaseModel):
    id: str
    repo_full_name: str
    capability: str
    tool_name: str | None
    job: str | None
    reason: str
    retired_by: str
    retired_at: datetime
    restored_at: datetime | None
    restored_by: str | None


def _out(row: RetiredLane) -> RetiredLaneOut:
    return RetiredLaneOut(
        id=row.id,
        repo_full_name=row.repo_full_name,
        capability=row.capability,
        tool_name=row.tool_name or None,
        job=row.job or None,
        reason=row.reason,
        retired_by=row.retired_by,
        retired_at=row.retired_at,
        restored_at=row.restored_at,
        restored_by=row.restored_by,
    )


def retirements(session: Any, repo_full_name: str, capability: str) -> dict[
    tuple[str, str], lane_status.Retirement
]:
    """The lanes of one capability an operator has retired and not restored."""
    rows = session.scalars(
        select(RetiredLane).where(
            RetiredLane.repo_full_name == repo_full_name,
            RetiredLane.capability == capability,
            RetiredLane.restored_at.is_(None),
        )
    ).all()
    return {
        (row.tool_name, row.job): lane_status.Retirement(
            id=row.id, reason=row.reason, retired_by=row.retired_by, retired_at=row.retired_at
        )
        for row in rows
    }


def annotate(
    db: Any, repo_full_name: str, capability: str, lanes: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """`ScanRunReport.lanes` rows with their state (current | stale | retired)."""
    with db.session() as session:
        held = retirements(session, repo_full_name, capability)
        config = capability_config_for(session, repo_full_name, capability)
    return lane_status.with_states(
        lanes,
        repo_full_name=repo_full_name,
        capability=capability,
        config=config,
        retirements=held,
        now=utcnow(),
    )


def _lane_exists(request: Request, repo: str, capability: str, key: tuple[str, str]) -> bool:
    settings = request.app.state.settings
    report = ScanRunReport(request.app.state.catalog, settings.raw_dir, settings.datalake_dir)
    return any(
        lane_status.lane_key(lane.get("tool_name"), lane.get("job")) == key
        for lane in report.lanes(repo, capability)
    )


def _entity(repo: str, capability: str, key: tuple[str, str]) -> str:
    return f"{repo}|{capability}|{key[0]}|{key[1]}"


@router.post(
    "/repos/{repo_id}/checks/{capability}/lanes/retire",
    response_model=RetiredLaneOut,
    status_code=status.HTTP_201_CREATED,
)
async def retire_lane(
    request: Request, repo_id: str, capability: str, body: LaneIn, principal: HumanDep
) -> RetiredLaneOut:
    """A person says a lane is deliberately unused: it reads retired, not stale."""
    from mykronos.api.dashboard import _resolve_repo

    repo = _resolve_repo(request, repo_id)
    key = lane_status.lane_key(body.tool_name, body.job)
    if not any(key):
        raise HTTPException(status_code=422, detail="Name the lane: its tool, its job, or both.")
    if not _lane_exists(request, repo, capability, key):
        raise HTTPException(
            status_code=404,
            detail=f"No {capability} lane {key[1] or key[0]} has reported for {repo}.",
        )
    db = request.app.state.db
    with db.session() as session:
        if key in retirements(session, repo, capability):
            raise HTTPException(status_code=409, detail="That lane is already retired.")
        row = RetiredLane(
            repo_full_name=repo,
            capability=capability,
            tool_name=key[0],
            job=key[1],
            reason=body.reason.strip(),
            retired_by=principal.actor,
            retired_at=utcnow(),
        )
        session.add(row)
        session.flush()
        db.audit(
            session,
            actor=principal.actor,
            action="lane.retired",
            entity_type="scan_lane",
            entity_id=_entity(repo, capability, key),
            repo=repo,
            capability=capability,
            tool_name=key[0] or None,
            job=key[1] or None,
            reason=row.reason,
            retired_lane_id=row.id,
        )
        return _out(row)


@router.post(
    "/repos/{repo_id}/checks/{capability}/lanes/restore", response_model=RetiredLaneOut
)
async def restore_lane(
    request: Request, repo_id: str, capability: str, body: LaneIn, principal: HumanDep
) -> RetiredLaneOut:
    """Withdraw an operator's retirement: the lane is expected to report again."""
    from mykronos.api.dashboard import _resolve_repo

    repo = _resolve_repo(request, repo_id)
    key = lane_status.lane_key(body.tool_name, body.job)
    db = request.app.state.db
    with db.session() as session:
        held = retirements(session, repo, capability).get(key)
        if held is None:
            raise HTTPException(status_code=409, detail="That lane is not retired by an operator.")
        row = session.get(RetiredLane, held.id)
        assert row is not None
        row.restored_at = utcnow()
        row.restored_by = principal.actor
        db.audit(
            session,
            actor=principal.actor,
            action="lane.restored",
            entity_type="scan_lane",
            entity_id=_entity(repo, capability, key),
            repo=repo,
            capability=capability,
            tool_name=key[0] or None,
            job=key[1] or None,
            reason=body.reason.strip(),
            retired_lane_id=row.id,
        )
        session.flush()
        return _out(row)
