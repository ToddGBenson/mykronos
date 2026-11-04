"""`GET /api/dashboard/repos/{repo_id}/suppressions`: what the repository
silenced itself, with each expiry (TheHub #60963, decision #60815 option B).

A read. The rows are recorded from the raw SARIF each lane archives
(`mykronos.suppressions`); none of them is a finding, and nothing here can
change a finding's disposition (spec 05 s7).
"""

from __future__ import annotations

from datetime import UTC, date, datetime

from fastapi import APIRouter, Request
from pydantic import BaseModel

from mykronos import suppressions
from mykronos.adminauth import PrincipalDep

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


class SuppressionOut(BaseModel):
    #: The SARIF run's tool name, e.g. "Semgrep OSS" or "checkov".
    tool: str
    capability: str
    rule_id: str
    file_path: str
    line: int | None
    #: `inSource` (a pragma in the file) or `external` (a config file).
    kind: str
    #: What the author wrote; empty when they gave nothing.
    justification: str
    #: Null: the suppression carries no end date.
    expires_at: date | None
    #: `expired` (the date has passed), `no_expiry`, or `active`.
    status: suppressions.Status
    last_seen_at: datetime


class SuppressionCountsOut(BaseModel):
    expired: int
    no_expiry: int
    active: int


class SuppressionsOut(BaseModel):
    repo_full_name: str
    #: Expired first, then those with no expiry, then live ones.
    suppressions: list[SuppressionOut]
    counts: SuppressionCountsOut


@router.get("/repos/{repo_id}/suppressions", response_model=SuppressionsOut)
def repo_suppressions(request: Request, repo_id: str, principal: PrincipalDep) -> SuppressionsOut:
    """In-repo scanner suppressions for one repository, with their expiry.

    Each row is a result the repository's own source or config silenced
    (`# nosemgrep`, `# checkov:skip=`, a SARIF suppression), as its newest
    scan reported it. Not findings: these never enter the findings table.
    """
    from mykronos.api.dashboard import _resolve_repo

    repo_full_name = _resolve_repo(request, repo_id)
    today = datetime.now(UTC).date()
    with request.app.state.db.session() as session:
        listed = suppressions.listing(session, repo_full_name, today)
        rows = [
            SuppressionOut(
                tool=item.row.tool,
                capability=item.row.capability,
                rule_id=item.row.rule_id,
                file_path=item.row.file_path,
                line=item.row.line,
                kind=item.row.kind,
                justification=item.row.justification,
                expires_at=item.row.expires_at,
                status=item.status,
                last_seen_at=item.row.last_seen_at,
            )
            for item in listed
        ]
    counts = {status: 0 for status in suppressions.STATUSES}
    for row in rows:
        counts[row.status] += 1
    return SuppressionsOut(
        repo_full_name=repo_full_name,
        suppressions=rows,
        counts=SuppressionCountsOut(**counts),
    )
