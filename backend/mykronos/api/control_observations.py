"""Reading a repository's control observations (TheHub #60826).

The write path is `POST /api/ingest/control-observations` (a collector's
token). This is the read: the newest observation per (subject, assertion),
each saying whether it is still fresh enough to count and whether its state is
evidence at all.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Request
from pydantic import BaseModel

from mykronos import control_observations
from mykronos.adminauth import PrincipalDep

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


class ControlObservationOut(BaseModel):
    id: str
    subject: str
    surface_id: str | None
    control_id: str | None
    assertion: str
    state: str
    vantage: str
    tool: str
    tool_version: str
    collected_at: datetime
    raw_ref: str
    collector: str
    detail: str
    evidence: dict[str, Any]
    #: Collected within `fresh_days`. A stale observation lowers nothing and
    #: contradicts nothing.
    fresh: bool
    #: `pass` or `fail`. The other three states establish nothing.
    is_evidence: bool


class ControlObservationsOut(BaseModel):
    observations: list[ControlObservationOut]
    fresh_days: int


@router.get(
    "/repos/{repo_id}/control-observations", response_model=ControlObservationsOut
)
async def repo_control_observations(
    request: Request, repo_id: str, principal: PrincipalDep
) -> ControlObservationsOut:
    """The latest observation per (subject, assertion) for one repository."""
    from mykronos.api.dashboard import _resolve_repo

    repo_full_name = _resolve_repo(request, repo_id)
    with request.app.state.db.session() as session:
        rows = control_observations.latest(session, repo_full_name)
        return ControlObservationsOut(
            observations=[
                ControlObservationOut(
                    id=row.id,
                    subject=row.subject,
                    surface_id=row.surface_id,
                    control_id=row.control_id,
                    assertion=row.assertion,
                    state=row.state,
                    vantage=row.vantage,
                    tool=row.tool,
                    tool_version=row.tool_version,
                    collected_at=row.collected_at,
                    raw_ref=row.raw_ref,
                    collector=row.collector,
                    detail=row.detail,
                    evidence=dict(row.evidence or {}),
                    fresh=control_observations.is_fresh(row),
                    is_evidence=row.state in control_observations.EVIDENCE_STATES,
                )
                for row in rows
            ],
            fresh_days=control_observations.FRESH_DAYS,
        )
