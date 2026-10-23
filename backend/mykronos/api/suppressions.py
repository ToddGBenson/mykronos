"""A repository's in-repo scanner suppressions, for its page (TheHub #60963).

Decision 60815, option B: the results the repository silenced at the source
are listed with who silenced what, where, why and until when -- separately
from findings, which they are not (spec 05 §7). Read-only; the only writer is
the ingest route, from a clean scan.
"""

from __future__ import annotations

from datetime import date, datetime

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from mykronos import scanner_suppressions
from mykronos.adminauth import PrincipalDep

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


class SuppressionOut(BaseModel):
    repo_full_name: str
    capability: str
    tool: str
    branch: str
    rule_id: str
    file_path: str | None
    line: int | None
    #: The author's reason as the tool reported it; empty when none was given.
    justification: str
    #: The declared expiry; null means none was declared.
    expires_at: date | None
    #: `expired` (the date has passed and the pragma still silences the
    #: result), `no_expiry` (none declared) or `active`.
    expiry_state: str
    kind: str
    status: str
    scan_run_id: str
    commit_sha: str
    recorded_at: datetime


class SuppressionsPage(BaseModel):
    repo_full_name: str
    suppressions: list[SuppressionOut]
    #: One sentence per suppression whose expiry has passed, naming it.
    lane_health: list[str]
    #: How many are in each expiry state.
    counts: dict[str, int] = Field(default_factory=dict)


@router.get("/repos/{repo_id}/suppressions", response_model=SuppressionsPage)
async def repo_suppressions(
    request: Request, repo_id: str, principal: PrincipalDep
) -> SuppressionsPage:
    """Results this repository silenced at the source, with their expiry.

    Not findings and never scored. Each row is what the scanner reported on
    the most recent clean scan of its tool and branch; a suppression whose
    declared expiry has passed is also stated in `lane_health`.
    """
    from mykronos.api.dashboard import _resolve_repo

    repo_full_name = _resolve_repo(request, repo_id)
    with request.app.state.db.session() as session:
        found = scanner_suppressions.listing(session, repo_full_name)
        return SuppressionsPage(
            repo_full_name=repo_full_name,
            suppressions=[
                SuppressionOut(
                    repo_full_name=row.repo_full_name,
                    capability=row.capability,
                    tool=row.tool,
                    branch=row.branch,
                    rule_id=row.rule_id,
                    file_path=row.file_path,
                    line=row.line,
                    justification=row.justification,
                    expires_at=row.expires_at,
                    expiry_state=state,
                    kind=row.kind,
                    status=row.status,
                    scan_run_id=row.scan_run_id,
                    commit_sha=row.commit_sha,
                    recorded_at=row.recorded_at,
                )
                for row, state in found.rows
            ],
            lane_health=found.lane_health,
            counts=found.counts,
        )
