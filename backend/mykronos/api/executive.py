"""The executive report: one repository's posture, on one printable page.

`GET /api/dashboard/repos/{repo_id}/executive-summary` gathers what the other
tabs already measure -- see `mykronos.executive_summary` -- and adds the two
inputs that live in the operational database rather than the lake: this
repository's pending approvals, and its spec 33 acceptance decisions. A read,
open to any principal the other dashboard reads are open to.
"""

from __future__ import annotations

import dataclasses
import logging
from datetime import date, datetime

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select

from mykronos import executive_summary as es
from mykronos import po_console as pc
from mykronos.adminauth import PrincipalDep
from mykronos.auth import TokenRegistry
from mykronos.db.models import ApprovalRequest, RepoOnboarding, RiskAcceptance
from mykronos.logsafe import scrub
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


class ExecutiveTrendPointOut(BaseModel):
    days_ago: int
    at: datetime
    available: bool
    open_by_severity: dict[str, int] | None
    open_total: int | None


class ExecutiveDriverOut(BaseModel):
    capability: str
    kind: str
    name: str
    findings: int
    critical: int
    high: int


class ExecutiveFixBucketOut(BaseModel):
    key: str
    findings: int
    serious: int


class ExecutiveExpiryOut(BaseModel):
    on: date
    findings: int


class ExecutiveAcceptedOut(BaseModel):
    findings: int
    serious: int
    no_review_date: int
    overdue: int
    now_fixable: int
    next_expiries: list[ExecutiveExpiryOut]
    decisions_active: int
    decisions_review_due: int
    decisions_pending: int
    nearest_decision_expiry: date | None


class ExecutiveLaneOut(BaseModel):
    capability: str
    status: str
    last_run_at: datetime | None
    last_run_status: str | None
    last_success_at: datetime | None
    open_findings: int
    blocked_by: str
    consecutive_failures: int
    stale_reason: str


class ExecutiveProgressOut(BaseModel):
    days: int
    fixed: int
    fixed_serious: int
    false_positive: int
    accepted: int
    new: int
    new_serious: int
    reidentified: int
    window_starts: datetime | None


class ExecutiveDecisionOut(BaseModel):
    kind: str
    id: str
    duty: str
    summary: str
    created_at: datetime | None
    due: datetime | None
    overdue: bool


class ExecutiveSummaryOut(BaseModel):
    """One repository's security posture, every number read at request time."""

    model_config = ConfigDict(extra="forbid")

    repo_full_name: str
    generated_at: datetime
    open_by_severity: dict[str, int]
    open_total: int
    history_since: datetime | None
    trend: list[ExecutiveTrendPointOut]
    drivers: list[ExecutiveDriverOut]
    drivers_basis: str
    drivers_basis_total: int
    basis_by_capability: dict[str, int]
    fixability: list[ExecutiveFixBucketOut]
    closing_on_their_own: int
    accepted: ExecutiveAcceptedOut
    lanes: list[ExecutiveLaneOut]
    progress: ExecutiveProgressOut
    decisions: list[ExecutiveDecisionOut]
    gaps: list[str]


def _as_datetime(value: date | None) -> datetime | None:
    if value is None or isinstance(value, datetime):
        return value
    return datetime(value.year, value.month, value.day)


@router.get("/repos/{repo_id}/executive-summary", response_model=ExecutiveSummaryOut)
async def executive_summary(
    request: Request, repo_id: str, principal: PrincipalDep
) -> ExecutiveSummaryOut:
    """A plain-language posture summary of one repository, for printing.

    Severity, trend, what is driving it, how much can be fixed today, accepted
    risk, whether each scanner is running, recent progress and what is waiting
    on a person. Every count is read from the platform at request time, and
    what cannot be established is listed in `gaps` rather than estimated.
    """
    now = utcnow()
    gaps: list[str] = []
    with request.app.state.db.session() as session:
        row = session.get(RepoOnboarding, repo_id)
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=(
                    f"No repo {repo_id!r}. This takes the onboarding id from "
                    "/api/dashboard/portfolio, not an owner/repo name."
                ),
            )
        repo_full_name = row.github_repo_full_name
        default_branch = row.default_branch or ""
        # The repository page's own reading of "enabled": the installer's
        # ledger for Actions, the grants for everything else.
        enabled = set(row.enabled_capabilities or [])
        if row.scanned_by != "github_actions":
            enabled |= TokenRegistry(session).granted_capabilities(repo_full_name)

        acceptances = [
            {"status": record.status, "expires_at": record.expires_at}
            for record in session.execute(
                select(RiskAcceptance).where(RiskAcceptance.repo_full_name == repo_full_name)
            ).scalars()
        ]

        # The Product Owner inbox's scoping (spec 35 §8.2): a request belongs
        # to the repository its frozen evidence names.
        decisions: list[es.Decision] = []
        try:
            for request_row in session.execute(
                select(ApprovalRequest)
                .where(ApprovalRequest.state == "pending")
                .order_by(ApprovalRequest.expires_at)
                .limit(500)
            ).scalars():
                owner = pc.request_repo(
                    request_row.duty, request_row.subject_ref, request_row.evidence
                )
                if not pc.same_repo(owner, repo_full_name):
                    continue
                decisions.append(
                    es.Decision(
                        kind="approval",
                        id=request_row.id,
                        duty=request_row.duty,
                        summary=pc.evidence_summary(request_row.duty, request_row.evidence),
                        created_at=request_row.created_at,
                        due=request_row.expires_at,
                        overdue=request_row.expires_at <= now,
                    )
                )
        except Exception:  # noqa: BLE001
            logger.warning("Could not read pending approvals for %s", scrub(repo_full_name))
            gaps.append("Pending approvals could not be read, so none are listed.")

        for record in session.execute(
            select(RiskAcceptance).where(
                RiskAcceptance.repo_full_name == repo_full_name,
                RiskAcceptance.status.in_(("review_due", "needs_review")),
            )
        ).scalars():
            decisions.append(
                es.Decision(
                    kind="acceptance_review",
                    id=record.id,
                    duty="risk_acceptance",
                    summary=(record.justification or "")[:160],
                    created_at=record.created_at,
                    due=_as_datetime(record.expires_at or record.review_by),
                    overdue=bool(record.expires_at and record.expires_at <= now.date()),
                )
            )

    summary = es.build(
        request.app.state.catalog,
        repo_full_name,
        now=now,
        enabled=enabled,
        default_branch=default_branch,
        acceptance_records=acceptances,
        decisions=decisions,
        gaps=gaps,
    )
    return ExecutiveSummaryOut.model_validate(dataclasses.asdict(summary))
