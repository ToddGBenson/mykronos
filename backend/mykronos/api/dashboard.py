"""Dashboard API (spec 10 §4).

Read-only except for one endpoint: marking a finding as a false positive or
accepted risk. That write is the seed of the whole learning loop — spec 11 §4
turns it into a retro signal that eventually dampens the rule in Oracle's
policy — which is why it demands a reason.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from mykronos.adminauth import PrincipalDep
from mykronos.dashboard import DashboardQueries, PortfolioSummary
from mykronos.db.models import RepoOnboarding
from mykronos.knowledge.capture import capture_dismissal, safe_capture
from mykronos.lake.mutate import locate_findings, update_findings
from mykronos.logsafe import scrub
from mykronos.maturity import assess as maturity_assess
from mykronos.maturity import mean_time_to_fix, trend_series
from mykronos.pull_requests import open_pull_requests
from mykronos.schemas import Capability, FindingStatus, Severity, utcnow

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

#: Dispositions a human may set from the dashboard (spec 10 §2.2).
#:
#: `open` and `fixed` are deliberately absent: those are observations the
#: scanners and the reconciler own. Letting a person hand-set `fixed` would
#: put a claim in the lake that no scan supports, and mean-time-to-fix would
#: start measuring opinions.
HUMAN_DISPOSITIONS = {
    FindingStatus.FALSE_POSITIVE,
    FindingStatus.ACCEPTED_RISK,
    FindingStatus.SUPPRESSED,
}


class CapabilityStateOut(BaseModel):
    capability: str
    has_scanned: bool
    last_scan_at: datetime | None = None
    last_scan_status: str | None = None
    open_findings: int = 0


class PortfolioRowOut(BaseModel):
    repo_id: str
    repo_full_name: str
    status: str
    enabled_capabilities: list[str]
    pending_capabilities: list[str] | None
    severity_counts: dict[str, int]
    total_open: int
    last_scan_at: datetime | None
    awaiting_first_scan: bool
    is_stale: bool
    capability_states: list[CapabilityStateOut]
    risk_score: int | None = Field(
        default=None,
        description=(
            "Oracle's standing score from the latest portfolio decision. Null "
            "means not judged — deliberately not 0, which would read as "
            "'assessed, no risk'. Oracle is opt-in, so a repo that never "
            "enabled it stays null."
        ),
    )
    recommendation: str | None = None
    raw_risk_score: float | None = Field(
        default=None,
        description=(
            "Pre-clamp score. Ranking has to survive the clamp (D-018): two "
            "repos both displaying 100 still need an order."
        ),
    )
    risk_assessed_at: datetime | None = None


class PortfolioOut(BaseModel):
    summary: PortfolioSummary
    repos: list[PortfolioRowOut]


class TriageItem(BaseModel):
    """One row of the cross-portfolio work queue."""

    finding_id: str
    repo_id: str
    repo_full_name: str
    capability: str
    rule_id: str
    title: str
    severity: Severity
    file_path: str | None = None
    line_start: int | None = None
    package_name: str | None = None
    package_version: str | None = None
    first_seen_at: datetime | None = None
    repo_recommendation: str | None = Field(
        default=None,
        description=(
            "The repo's standing Oracle verdict, carried per row so the queue "
            "reads without cross-referencing the portfolio. The same critical "
            "means something different in a repo already called no_go."
        ),
    )


class TriageQueue(BaseModel):
    items: list[TriageItem]
    open_by_severity: dict[str, int]
    total_open: int
    truncated: bool = Field(
        description=(
            "Whether the limit cut the list short. A queue that silently stops "
            "at 100 reads as 'that is all of it'."
        ),
    )


class FindingOut(BaseModel):
    """One finding as the dashboard serves it.

    Modelled rather than passed through as a bare dict so the OpenAPI schema —
    and therefore the generated TypeScript — describes the real shape. A
    `dict[str, Any]` response types the whole frontend as `unknown` and pushes
    the guessing into a cast.

    `code_snippet` and `raw_finding_json` are null for viewer roles rather than
    absent. The security property is that the *value* is not transmitted
    (spec 12 §5); a stable key shape costs nothing and spares every caller an
    optional-property dance.
    """

    finding_id: str
    capability: str
    rule_id: str
    title: str
    description: str = ""
    severity: Severity
    cvss_score: float | None = None
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    symbol: str | None = None
    package_name: str | None = None
    package_version: str | None = None
    status: str
    fingerprint_version: str | None = None
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    resolved_at: datetime | None = None
    code_snippet: str | None = None
    raw_finding_json: Any = None


class FindingsPage(BaseModel):
    total: int
    limit: int
    offset: int
    findings: list[FindingOut]
    raw_output_included: bool = Field(
        description="False for viewer roles; raw output is admin-only (spec 12 §5)."
    )


class InsiderRiskOut(BaseModel):
    """One insider-risk assessment (spec 06 §3).

    `author_login` and `signal_breakdown` are null for non-admin callers
    rather than absent — a stable key shape, and the same choice made for raw
    output. `detail_included` on the page says which you are looking at, so
    "withheld" is never mistaken for "nothing recorded".
    """

    signal_id: str
    pr_number: int
    commit_sha: str
    insider_risk_score: int
    recommendation: str
    ai_authorship_flag: bool | None = Field(
        default=None,
        description=(
            "True if likely AI and undisclosed, false if evaluated and human, "
            "null if not evaluated (spec 06 §3)."
        ),
    )
    evaluated_at: datetime | None = None
    github_check_run_id: str | None = None
    author_login: str | None = None
    signal_breakdown: Any = None


class InsiderRiskPage(BaseModel):
    repo_full_name: str
    signals: list[InsiderRiskOut]
    detail_included: bool = Field(
        description=(
            "False for viewer roles. The author and the breakdown are withheld "
            "at the query layer, not hidden in the UI (spec 06 §9)."
        )
    )
    governance: str = Field(
        description=(
            "Served with the data on purpose. A consumer of this endpoint "
            "should not have to read spec 06 §9 to learn that these rows are "
            "not a per-person rating."
        )
    )


class SscsEvidenceOut(BaseModel):
    evidence_id: str
    commit_sha: str
    tag_or_release: str | None = None
    sbom_ref: str | None = None
    dependency_count: int = 0
    vulnerable_dependency_count: int = 0
    trust_score: int = 100
    raw_trust_score: float | None = Field(
        default=None,
        description=(
            "Pre-clamp. Ranking has to survive the floor at 0, the same way "
            "Oracle's raw_score survives the ceiling at 100 (D-018)."
        ),
    )
    provenance_json: Any = None
    ecosystems_json: Any = None
    evaluated_at: datetime | None = None


class SscsPage(BaseModel):
    repo_full_name: str
    evidence: list[SscsEvidenceOut]
    latest: SscsEvidenceOut | None = Field(
        default=None,
        description="Convenience for the header; the same row as evidence[0].",
    )


class StatusChange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: FindingStatus
    reason: str = Field(
        default="",
        max_length=2000,
        description=(
            "Why. spec 11 §4: a bare click with no reason is recorded but "
            "flagged low-confidence and barred from promotion, because reasons "
            "are what make a learning actionable rather than a statistic."
        ),
    )


class StatusChangeResult(BaseModel):
    finding_id: str
    status: str
    reason_supplied: bool
    retro_signal: str


class ChecksOut(BaseModel):
    total: int
    passed: int
    failed: int
    pending: int


class PullRequestOut(BaseModel):
    repo_full_name: str
    number: int
    url: str
    kind: str
    title: str
    draft: bool
    branch: str
    opened_at: datetime | None
    changed_files: int | None
    summary: str
    detail: str
    capabilities: list[str]
    finding_id: str | None
    human_edited: bool
    #: Null means the check-runs call failed, which is not the same answer as
    #: a repository that has no checks configured.
    checks: ChecksOut | None


class UnreachableRepoOut(BaseModel):
    repo_full_name: str
    reason: str


class PullRequestsPage(BaseModel):
    pull_requests: list[PullRequestOut]
    #: Reported rather than silently dropped: a shorter list of outstanding
    #: work reads as progress, and a failed API call is not progress.
    unreachable: list[UnreachableRepoOut]


def _queries(request: Request) -> DashboardQueries:
    return DashboardQueries(request.app.state.catalog)


@router.get("/portfolio", response_model=PortfolioOut)
async def portfolio(
    request: Request,
    principal: PrincipalDep,
    include_removed: Annotated[bool, Query()] = False,
) -> PortfolioOut:
    """The landing page (spec 10 §2.1)."""
    with request.app.state.db.session() as session:
        rows, summary = _queries(request).portfolio(
            session, include_removed=include_removed
        )

    return PortfolioOut(
        summary=summary,
        repos=[
            PortfolioRowOut(
                repo_id=row.repo_id,
                repo_full_name=row.repo_full_name,
                status=row.status,
                enabled_capabilities=row.enabled_capabilities,
                pending_capabilities=row.pending_capabilities,
                severity_counts=row.severity_counts,
                total_open=row.total_open,
                last_scan_at=row.last_scan_at,
                awaiting_first_scan=row.awaiting_first_scan,
                is_stale=row.is_stale,
                capability_states=[
                    CapabilityStateOut(**vars(state)) for state in row.capability_states
                ],
                risk_score=row.risk_score,
                recommendation=row.recommendation,
                raw_risk_score=row.raw_risk_score,
                risk_assessed_at=row.risk_assessed_at,
            )
            for row in rows
        ],
    )


@router.get("/pull-requests", response_model=PullRequestsPage)
async def pull_requests(request: Request, principal: PrincipalDep) -> PullRequestsPage:
    """Everything Mykronos has open across every repository (spec 10 §2).

    Read-only, and deliberately so. Each row links out to GitHub to review and
    merge; the platform offers no merge of its own. That is the same constraint
    spec 08 §3 makes structural for Patchwork, applied to the view: a page that
    could merge a change to your code is a page that has to be trusted
    differently from one that can only show it to you.
    """
    with request.app.state.db.session() as session:
        result = await open_pull_requests(
            session, request.app.state.catalog, request.app.state.github_factory
        )

    return PullRequestsPage(
        pull_requests=[
            PullRequestOut(
                repo_full_name=row.repo_full_name,
                number=row.number,
                url=row.url,
                kind=row.kind,
                title=row.title,
                draft=row.draft,
                branch=row.branch,
                opened_at=row.opened_at,
                changed_files=row.changed_files,
                summary=row.summary,
                detail=row.detail,
                capabilities=row.capabilities,
                finding_id=row.finding_id,
                human_edited=row.human_edited,
                checks=(
                    ChecksOut(**vars(row.checks)) if row.checks is not None else None
                ),
            )
            for row in result.pull_requests
        ],
        unreachable=[
            UnreachableRepoOut(repo_full_name=name, reason=reason)
            for name, reason in result.unreachable
        ],
    )


@router.get("/triage", response_model=TriageQueue)
async def triage(
    request: Request,
    principal: PrincipalDep,
    severity: Annotated[Severity | None, Query()] = None,
    capability: Annotated[Capability | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> TriageQueue:
    """What to work on next, across the whole portfolio (spec 10 §2.1).

    The portfolio table answers "which repo is worst". This answers "what do I
    do next" — the question somebody actually has on a Monday morning, and one
    a per-repo view makes you visit forty pages to answer.
    """
    with request.app.state.db.session() as session:
        items, counts = _queries(request).triage_queue(
            session,
            severity=severity.value if severity else None,
            capability=capability.value if capability else None,
            limit=limit,
        )

    return TriageQueue(
        items=[TriageItem(**item) for item in items],
        open_by_severity=counts,
        total_open=sum(counts.values()),
        truncated=len(items) >= limit,
    )


@router.get("/trends")
async def trends(
    request: Request,
    principal: PrincipalDep,
    repo_id: Annotated[str | None, Query()] = None,
    days: Annotated[int, Query(ge=7, le=730)] = 90,
    points: Annotated[int, Query(ge=2, le=60)] = 12,
) -> dict[str, Any]:
    """Portfolio or per-repo series over time (spec 10 §2.3, §4).

    Reconstructed from the rows already held rather than read from a rollup
    table. Left live rather than materialized, on the same rule as the
    portfolio aggregate (D-016): materialization buys speed with a staleness
    window and a refresh job, which is a bad trade for a query inside budget.
    """
    repo_full_name = _resolve_repo(request, repo_id) if repo_id else None
    catalog = request.app.state.catalog

    series = trend_series(catalog, repo_full_name, days=days, points=points)
    return {
        "scope": repo_full_name or "portfolio",
        "days": days,
        "mean_time_to_fix_days": mean_time_to_fix(catalog, repo_full_name),
        "points": [
            {
                "at": point.at,
                "open_critical": point.open_critical,
                "open_high": point.open_high,
                "open_total": point.open_total,
                "risk_score": point.risk_score,
                "trust_score": point.trust_score,
            }
            for point in series
        ],
        "note": (
            "Every point is a query over first_seen_at and resolved_at, not a "
            "stored snapshot, so any of them can be re-derived from the "
            "findings themselves (spec 10 §6)."
        ),
    }


@router.get("/maturity")
async def maturity(
    request: Request,
    principal: PrincipalDep,
    repo_id: Annotated[str | None, Query()] = None,
) -> dict[str, Any]:
    """Maturity tier per repo, with the working shown (spec 10 §2.3).

    Criteria measure evidence rather than switch positions: nothing here can
    be satisfied by changing configuration alone, and in particular no tier
    rewards turning Oracle's gate on. Spec 09 §6 makes that conditional on
    shadow-mode data, so the model asks whether the data exists instead.
    """
    model = request.app.state.maturity_model
    catalog = request.app.state.catalog
    store = request.app.state.knowledge

    if repo_id:
        targets = [_resolve_repo(request, repo_id)]
    else:
        with request.app.state.db.session() as session:
            targets = sorted(
                row.github_repo_full_name
                for row in session.execute(
                    select(RepoOnboarding).where(RepoOnboarding.status == "active")
                ).scalars()
            )

    assessments = [
        maturity_assess(catalog, repo, model, store=store) for repo in targets
    ]

    return {
        "model_version": model.version,
        "tiers": [
            {"id": t.id, "name": t.name, "summary": t.summary} for t in model.tiers
        ],
        "repos": [
            {
                "repo_full_name": a.repo_full_name,
                "tier_id": a.tier_id,
                "tier_name": a.tier_name,
                "tier_summary": a.tier_summary,
                "tier_index": a.tier_index,
                "total_tiers": a.total_tiers,
                "next_tier_name": a.next_tier_name,
                "criteria": [
                    {
                        "key": c.key,
                        "label": c.label,
                        "why": c.why,
                        "threshold": c.threshold,
                        "measured": c.measured,
                        "passed": c.passed,
                    }
                    for c in a.criteria
                ],
                "blocking": [
                    {"key": c.key, "label": c.label, "measured": c.measured,
                     "threshold": c.threshold, "why": c.why}
                    for c in a.blocking
                ],
            }
            for a in assessments
        ],
    }


@router.get("/repos/{repo_id}/insider-risk", response_model=InsiderRiskPage)
async def repo_insider_risk(
    request: Request,
    repo_id: str,
    principal: PrincipalDep,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> InsiderRiskPage:
    """Insider-risk assessments for one repo (spec 06 §9).

    Detail is admin-only, withheld at the query layer rather than hidden in the
    UI. A viewer sees the verdict per pull request — the same thing anyone who
    can see the Check Run already sees — and not the author, the breakdown, or
    the baseline comparison.
    """
    repo_full_name = _resolve_repo(request, repo_id)
    include_detail = principal.may_see_insider_risk

    return InsiderRiskPage(
        repo_full_name=repo_full_name,
        detail_included=include_detail,
        signals=[
            InsiderRiskOut(**signal)
            for signal in _queries(request).insider_risk(
                repo_full_name, include_detail=include_detail, limit=limit
            )
        ],
        governance=(
            "These rows are a review prompt about a change, not a rating of a "
            "person. Nothing here aggregates or ranks contributors, and rows "
            "are deleted after this repository's retention period (spec 06 §9)."
        ),
    )


@router.get("/repos/{repo_id}/sscs", response_model=SscsPage)
async def repo_sscs(
    request: Request,
    repo_id: str,
    principal: PrincipalDep,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> SscsPage:
    """Supply-chain evidence and trust-score history for one repo (spec 10 §9)."""
    repo_full_name = _resolve_repo(request, repo_id)
    evidence = _queries(request).sscs_evidence(repo_full_name, limit=limit)
    return SscsPage(
        repo_full_name=repo_full_name,
        evidence=[SscsEvidenceOut(**row) for row in evidence],
        latest=SscsEvidenceOut(**evidence[0]) if evidence else None,
    )


@router.get("/repos/{repo_id}/findings", response_model=FindingsPage)
async def repo_findings(
    request: Request,
    repo_id: str,
    principal: PrincipalDep,
    capability: Annotated[Capability | None, Query()] = None,
    severity: Annotated[Severity | None, Query()] = None,
    finding_status: Annotated[FindingStatus | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> FindingsPage:
    """Filterable finding list for one repo (spec 10 §2.2)."""
    repo_full_name = _resolve_repo(request, repo_id)

    findings, total = _queries(request).findings(
        repo_full_name,
        capability=capability.value if capability else None,
        severity=severity.value if severity else None,
        finding_status=finding_status.value if finding_status else None,
        limit=limit,
        offset=offset,
        include_raw=principal.may_see_raw_output,
    )
    return FindingsPage(
        total=total,
        limit=limit,
        offset=offset,
        findings=[FindingOut.model_validate(f) for f in findings],
        raw_output_included=principal.may_see_raw_output,
    )


@router.get("/repos/{repo_id}/scan-health")
async def scan_health(
    request: Request, repo_id: str, principal: PrincipalDep
) -> dict[str, Any]:
    """Per-capability run history and freshness (spec 10 §2.2).

    Auditable from the lake alone, which is the point of writing a ScanRun for
    every run including the ones that found nothing (spec 04 §7).
    """
    repo_full_name = _resolve_repo(request, repo_id)
    return {
        "repo_full_name": repo_full_name,
        "capabilities": _queries(request).scan_health(repo_full_name),
    }


@router.patch("/findings/{finding_id}/status", response_model=StatusChangeResult)
async def set_finding_status(
    request: Request, finding_id: str, body: StatusChange, principal: PrincipalDep
) -> StatusChangeResult:
    """Record a human disposition (spec 10 §2.2).

    Admin-only: this changes what Oracle will decide, so it is a write, not a
    view. Viewers can read every finding and change none of them.
    """
    if not principal.may_write:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Changing a finding's status requires the 'admin' role; you "
                f"have '{principal.role.value}'."
            ),
        )

    if body.status not in HUMAN_DISPOSITIONS:
        allowed = ", ".join(sorted(s.value for s in HUMAN_DISPOSITIONS))
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=(
                f"'{body.status.value}' is not a disposition a person may set. "
                f"Allowed: {allowed}. 'open' and 'fixed' are observations owned "
                "by the scanners and the reconciler — hand-setting 'fixed' would "
                "put a claim in the lake that no scan supports."
            ),
        )

    catalog = request.app.state.catalog
    existing = DashboardQueries(catalog).finding(finding_id)
    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"No finding {finding_id}."
        )

    outcome = update_findings(
        catalog,
        locate_findings(catalog, [finding_id]),
        "status = ?, resolved_at = ?",
        [body.status.value, utcnow()],
    )
    if not outcome.count:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The finding could not be updated; it may have just been compacted.",
        )

    # spec 12 §7: who changed a finding's disposition, and why.
    with request.app.state.db.session() as session:
        request.app.state.db.audit(
            session,
            actor=principal.actor,
            action="finding.status",
            entity_type="finding",
            entity_id=finding_id,
            repo=existing.get("repo_full_name"),
            capability=existing.get("capability"),
            new_status=body.status.value,
            reason=body.reason,
        )

    # spec 11 §4. Wrapped, because the disposition has already succeeded by
    # the time we get here — the lake is written — and failing the request
    # because a JSONL file could not be opened would undo a real thing to
    # protect a derived one.
    captured = safe_capture(
        capture_dismissal,
        request.app.state.knowledge,
        repo_full_name=str(existing.get("repo_full_name") or ""),
        rule_id=str(existing.get("rule_id") or ""),
        finding_id=finding_id,
        status=body.status.value,
        reason=body.reason,
        capability=str(existing.get("capability") or ""),
        actor=principal.actor,
    )

    if captured is None and body.status is not FindingStatus.FALSE_POSITIVE:
        # Not a failure: only a false positive says anything about the rule.
        # `accepted_risk` means the finding is real and we are living with it,
        # which is a statement about appetite, not detection quality.
        signal = f"recorded; '{body.status.value}' teaches nothing about the rule"
    elif captured is None:
        signal = "recorded, but the learning could not be stored — see the logs"
    elif not body.reason.strip():
        signal = (
            "recorded without a reason — low-confidence and barred from "
            "promotion or dampening (spec 11 §4)"
        )
    elif captured.reconfirmed:
        signal = (
            f"reconfirmed a known learning about {existing.get('rule_id')} "
            f"({captured.entry.observations} observations, confidence "
            f"{captured.entry.confidence:.2f})"
        )
    else:
        signal = f"recorded a new learning about {existing.get('rule_id')}"

    logger.info(
        "Finding %s -> %s by %s (%s)",
        scrub(finding_id),
        body.status.value,
        scrub(principal.actor),
        scrub(signal),
    )

    return StatusChangeResult(
        finding_id=finding_id,
        status=body.status.value,
        reason_supplied=bool(body.reason.strip()),
        retro_signal=signal,
    )


def _resolve_repo(request: Request, repo_id: str) -> str:
    """Map an onboarding id to its repo full name.

    Deliberately id-only. `owner/repo` contains a slash and cannot be a single
    path segment, and the alternatives — percent-encoding, which plenty of
    proxies normalise away, or a catch-all route — trade a real correctness
    risk for a convenience the callers do not need: every response that links
    here already carries `repo_id`.
    """
    from mykronos.db.models import RepoOnboarding

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
        return str(row.github_repo_full_name)
