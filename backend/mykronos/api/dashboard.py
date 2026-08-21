"""Dashboard API (spec 10 §4).

Read-only except for one endpoint: marking a finding as a false positive or
accepted risk. That write is the seed of the whole learning loop — spec 11 §4
turns it into a retro signal that eventually dampens the rule in Oracle's
policy — which is why it demands a reason.
"""

from __future__ import annotations

import logging
from datetime import date, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from mykronos.adminauth import PrincipalDep
from mykronos.ci import ConcourseClient, coverage, pipeline_name_for, reconcile
from mykronos.dashboard import DashboardQueries, PortfolioSummary
from mykronos.db.models import CapabilityGrant, RepoOnboarding, capability_config_for
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
    #: Where this repository lives and where it is built. On every row rather
    #: than only the drill-down page: "which pipeline produced this" is a
    #: question people ask from the portfolio, and answering it should not
    #: cost a navigation.
    github_url: str = ""
    pipeline_url: str | None = None
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
    cve_id: str | None = Field(
        default=None,
        description="Extracted from rule_id/title, if either names one (spec 17 §4.2).",
    )
    in_kev: bool | None = Field(
        default=None,
        description="Null when cve_id is null — see FindingGroupOut's field for the same rule.",
    )
    epss_score: float | None = Field(default=None, description="0-1, null if not scored yet.")


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
    #: Who this is addressed to, and where that answer came from (spec 24 §1).
    #: `owner_source` is codeowners | profile | manual | unresolved — the four
    #: are behaviourally different, and a bare null owner could be any of them.
    owner: str | None = None
    owner_source: str | None = None
    fingerprint_version: str | None = None
    #: Set only when `status == "superseded"` (spec 05 §5a) — the finding_id
    #: that replaced this record. Previously not selected at all, so a
    #: superseded row had no way to point at what replaced it (spec 17 §5.1).
    superseded_by: str | None = None
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


class FindingLocationOut(BaseModel):
    """One occurrence of a grouped finding.

    Every occurrence keeps its own `finding_id`, because a disposition is
    recorded against a finding and not against a group — accepting the risk of
    one instance of a rule is not accepting it everywhere it fires.
    """

    finding_id: str
    capability: str
    severity: Severity
    file_path: str | None = None
    line_start: int | None = None
    package_version: str | None = None
    first_seen_at: datetime | None = None


#: `classify()`'s own vocabulary (`patchwork/triage.py`) plus the
#: group-level `toxic_combination` `_group_findings` adds on top of it — the
#: same four values `FindingGroupOut.triage` already renders, now also a
#: filter (spec 18 §5.1).
TriageFilter = Literal[
    "true_positive", "likely_false_positive", "needs_human_judgment", "toxic_combination"
]


class FindingGroupOut(BaseModel):
    """One problem, however many times it was reported."""

    group_key: str
    rule_id: str
    title: str
    description: str | None = None
    severity: Severity = Field(
        description="The worst member's. Two scanners disagreeing about one "
        "CVE is common, and the lower number is never the safe one to show."
    )
    package_name: str | None = None
    cvss_score: float | None = None
    capabilities: list[str] = Field(
        description="Which scanners reported it. More than one is the "
        "cross-scanner duplicate this grouping exists to collapse."
    )
    occurrences: int
    locations: list[FindingLocationOut]
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    age_days: int | None = None
    triage: str = Field(
        description=(
            "Patchwork's own classification (`patchwork/triage.py`), plus "
            "`toxic_combination` for a group that cannot be judged alone."
        )
    )
    triage_rationale: str
    toxic_combination_ids: list[str] = []
    cve_id: str | None = Field(
        default=None,
        description="Extracted from rule_id/title, if either names one (spec 17 §4.2). "
        "Null means this group names no CVE at all — distinct from `in_kev: false`, "
        "which means one was found and checked.",
    )
    in_kev: bool | None = Field(
        default=None,
        description="Null when cve_id is null. Otherwise whether that CVE is in "
        "CISA's KEV catalog — false may mean 'checked, not listed' or 'not yet "
        "fetched', which `fetched_at` on GET /api/dashboard/threat-intel disambiguates.",
    )
    epss_score: float | None = Field(default=None, description="0-1, null if not scored yet.")
    fixable: bool | None = Field(
        default=None,
        description=(
            "Whether Patchwork produced a fix for any occurrence in this "
            "group (spec 19 §3.2). Read from what it actually did, not "
            "predicted — a fixer cannot say whether it applies without the "
            "file content, and a prediction would never self-correct. Null "
            "means nobody has looked yet, which is distinct from `false`: "
            "looked, and there is no mechanical fix."
        ),
    )


class ToxicCombinationMemberOut(BaseModel):
    finding_id: str
    capability: str
    rule_id: str
    title: str
    severity: Severity
    file_path: str | None = None


class ToxicCombinationOut(BaseModel):
    """A set of findings that together mean more than they do apart."""

    combination_id: str
    rule_id: str
    name: str
    severity: Severity
    rationale: str
    members: list[ToxicCombinationMemberOut]


class OpenFindingsPage(BaseModel):
    """The outstanding-work view for one repository."""

    repo_full_name: str
    finding_status: str = Field(
        description="Which status this is a view of. `open` unless asked."
    )
    total: int = Field(description="Findings of this status, before filters.")
    matching: int = Field(description="How many the severity/capability filters kept.")
    shown: int = Field(description="Occurrences actually returned, after the limit.")
    deduplicated: int = Field(
        description="How many rows the grouping removed — the size of the "
        "difference between the record and this view."
    )
    by_severity: dict[str, int]
    groups: list[FindingGroupOut]
    toxic_combinations: list[ToxicCombinationOut]
    truncated: bool


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
    blocking: bool = Field(
        default=False,
        description=(
            "Whether this repository's Aegis Check Run can fail a pull "
            "request, or is advisory (spec 06 §7, spec 20 §3.2). Per repo, "
            "and off by default. Stated here rather than left to the reader "
            "because the gap between what an admin configured and what a "
            "reviewer believes is happening is exactly where a governance "
            "note stops being one."
        ),
    )


class SscsEvidenceOut(BaseModel):
    evidence_id: str
    commit_sha: str
    tag_or_release: str | None = None
    sbom_ref: str | None = None
    dependency_count: int = 0
    vulnerable_dependency_count: int = 0
    #: Null means the scan resolved nothing, so nothing was assessed
    #: (spec 07 §5a). The old default here was 100 — a repository declaring
    #: version ranges rather than pinned versions got a perfect supply-chain
    #: score for a scan that inspected no dependencies at all.
    trust_score: int | None = None
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


class ThreatModelSupplyChainOut(BaseModel):
    """The dependency graph as a whole — context, not a finding (spec 18 §8)."""

    trust_score: int | None = None
    dependency_count: int = 0
    vulnerable_dependency_count: int = 0


class ThreatModelCategoryOut(BaseModel):
    stride: str = Field(description="One of STRIDE_CATEGORIES (dashboard.py).")
    findings: list[FindingGroupOut]


class ThreatModelOut(BaseModel):
    """A STRIDE-categorized attack-surface inventory (spec 18 §6)."""

    repo_full_name: str
    mapping_resolution: str = Field(
        description="Always 'capability' today — no Finding carries a "
        "structured CWE, so this is the finest resolution the data "
        "honestly supports. A future CWE-aware pass would report 'cwe' "
        "here instead, distinguishing the two rather than letting the "
        "frontend assume one silently became the other."
    )
    categories: list[ThreatModelCategoryOut]
    supply_chain: ThreatModelSupplyChainOut | None = None


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


class OwnerChange(BaseModel):
    """Reassign a finding by hand (spec 24 §1.2)."""

    model_config = ConfigDict(extra="forbid")

    owner: str | None = Field(
        default=None,
        max_length=255,
        description=(
            "A GitHub handle or team slug. Null hands the finding back to "
            "CODEOWNERS — the next scan re-resolves it, rather than the "
            "finding staying permanently unowned because somebody cleared "
            "the field."
        ),
    )


class OwnerChangeResult(BaseModel):
    finding_id: str
    owner: str | None
    owner_source: str


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
        rows, summary = _queries(request).portfolio(session, include_removed=include_removed)

    # The browser's Concourse, not this process's (see ConcourseClient): a
    # link to http://concourse:8080 resolves nowhere from a laptop.
    settings = request.app.state.settings
    concourse = (settings.concourse_external_url or settings.concourse_url or "").rstrip("/")
    team = settings.concourse_team

    def pipeline_url(repo_full_name: str) -> str | None:
        if not concourse:
            return None
        return f"{concourse}/teams/{team}/pipelines/{pipeline_name_for(repo_full_name)}"

    return PortfolioOut(
        summary=summary,
        repos=[
            PortfolioRowOut(
                repo_id=row.repo_id,
                repo_full_name=row.repo_full_name,
                status=row.status,
                github_url=f"https://github.com/{row.repo_full_name}",
                pipeline_url=pipeline_url(row.repo_full_name),
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
                checks=(ChecksOut(**vars(row.checks)) if row.checks is not None else None),
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
    rule_id: Annotated[str | None, Query(max_length=200)] = None,
    kev_only: Annotated[bool, Query()] = False,
    min_epss: Annotated[float | None, Query(ge=0.0, le=1.0)] = None,
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
            rule_id=rule_id,
            limit=limit,
            kev_only=kev_only,
            min_epss=min_epss,
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
                # Null for a single repo, where there is nothing to aggregate
                # (spec 21 §2). Present for the portfolio, where the mean
                # alone can be dragged by one very bad repository.
                "risk_score_median": point.risk_score_median,
                "repos_scored": point.repos_scored,
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

    assessments = [maturity_assess(catalog, repo, model, store=store) for repo in targets]

    return {
        "model_version": model.version,
        "tiers": [{"id": t.id, "name": t.name, "summary": t.summary} for t in model.tiers],
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
                    {
                        "key": c.key,
                        "label": c.label,
                        "measured": c.measured,
                        "threshold": c.threshold,
                        "why": c.why,
                    }
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

    with request.app.state.db.session() as session:
        aegis_config = capability_config_for(session, repo_full_name, "aegis")
    blocking = bool(aegis_config.get("blocking"))

    return InsiderRiskPage(
        repo_full_name=repo_full_name,
        detail_included=include_detail,
        blocking=blocking,
        signals=[
            InsiderRiskOut(**signal)
            for signal in _queries(request).insider_risk(
                repo_full_name, include_detail=include_detail, limit=limit
            )
        ],
        governance=(
            "These rows are a review prompt about a change, not a rating of a "
            "person. Nothing here aggregates or ranks contributors, and rows "
            "are deleted after this repository's retention period (spec 06 §9). "
            + (
                "This repository's Aegis Check Run is BLOCKING: a score at or "
                "above the threshold fails the pull request."
                if blocking
                else "This repository's Aegis Check Run is advisory — it never "
                "fails a pull request."
            )
        ),
    )


class CiJobOut(BaseModel):
    name: str
    status: str | None = Field(
        default=None,
        description=(
            "Concourse's own word: succeeded, failed, errored, aborted, "
            "pending. Null means the job has never finished a build, which is "
            "neither pass nor fail."
        ),
    )
    build_name: str | None = None
    build_url: str | None = None
    finished_at: datetime | None = None


class CiReportingOut(BaseModel):
    job: str
    capability: str
    built_at: datetime | None = None
    scanned_at: datetime | None = None
    state: str = Field(
        description=(
            "reporting: results arrived. silent: the job succeeded and its "
            "capability's newest scan run is older than that build, so "
            "something ran and did not report. never_reported: the job has "
            "succeeded and the lake has no successful run for it at all. "
            "not_run: no successful build to compare against."
        )
    )


class StageCoverageOut(BaseModel):
    stage: str
    enabled: bool
    state: str = Field(
        description=(
            "not_enabled: nobody asked for this stage here. no_job: enabled, "
            "and nothing in the pipeline produces it - the gap hardest to see "
            "otherwise, because the repository believes it is covered and no "
            "job disagrees. reporting / silent / never_reported / not_run "
            "carry their meaning from the cross-check."
        )
    )
    problem: bool


class CiPage(BaseModel):
    """Where this repository is built and scanned (spec 10 §2.2, spec 15 §4a)."""

    repo_full_name: str
    github_url: str
    github_actions_url: str
    pipeline: str | None = None
    pipeline_url: str | None = None
    jobs: list[CiJobOut] = Field(default_factory=list)
    failing: list[str] = Field(default_factory=list)
    stages: list[StageCoverageOut] = Field(
        default_factory=list,
        description=(
            "Every stage the platform covers, against what this repository "
            "actually has (PIP-6). A stage nobody enabled and a stage that is "
            "enabled and not answering both look like an absence, and only "
            "one of them is a problem."
        ),
    )
    reporting: list[CiReportingOut] = Field(
        default_factory=list,
        description=(
            "Each scanning job against the newest scan run it should have "
            "produced. A green pipeline and a stale capability are two facts "
            "that used to sit on different pages without contradicting each "
            "other."
        ),
    )
    unavailable: str | None = Field(
        default=None,
        description=(
            "Why there is no pipeline state, when there is none. 'No pipeline "
            "for this repo' and 'Concourse did not answer' are different "
            "facts, and a panel that conflates them teaches people to ignore "
            "it."
        ),
    )


@router.get("/vulnerability-management")
async def vulnerability_management(
    request: Request,
    principal: PrincipalDep,
    repo_id: Annotated[str | None, Query()] = None,
) -> dict[str, Any]:
    """What is outstanding, how old, and what was accepted (PIP-9).

    The platform could answer "what is open" from the beginning and never
    "how long has it been open, and what did we decide not to fix" — which
    are the two questions a vulnerability management programme is made of.

    Accepted risk is reported separately and never folded into a resolved
    count. It is a decision with an owner and a reason, and the reason is the
    part that decays: "no vendor fix" stops being true the day a vendor ships
    one, and this repository is currently carrying 243 acceptances that each
    said exactly that.
    """
    repo_full_name = _resolve_repo(request, repo_id) if repo_id else None
    return _queries(request).vulnerability_management(repo_full_name)


@router.get("/repos/{repo_id}/ci", response_model=CiPage)
async def repo_ci(request: Request, repo_id: str, principal: PrincipalDep) -> CiPage:
    """Links out to where this repository is built (spec 15 §4a).

    Deliberately a link rather than a mirror: Concourse's own UI is the
    authority on its state, and restating a build outcome here would create a
    second version of it to disagree with. What this adds is knowing *which*
    pipeline, from a page that is already about this repository.
    """
    repo_full_name = _resolve_repo(request, repo_id)
    settings = request.app.state.settings
    status = ConcourseClient(
        settings.concourse_url,
        team=settings.concourse_team,
        external_url=settings.concourse_external_url,
    ).status_for(repo_full_name)

    reported = reconcile(status.jobs, _queries(request).last_successful_scan_at(repo_full_name))

    with request.app.state.db.session() as session:
        row = session.execute(
            select(RepoOnboarding).where(RepoOnboarding.github_repo_full_name == repo_full_name)
        ).scalar_one_or_none()
        enabled = set(row.enabled_capabilities or []) if row else set()

        if row and row.scanned_by != "github_actions":
            # `enabled_capabilities` is the installer's ledger: capabilities
            # whose workflow-install PR merged. A Concourse-scanned repo never
            # merges one, so that ledger stays empty forever while scans
            # arrive anyway - this page showed every lane as not_enabled
            # while eleven were reporting (2026-08-15). For anything not
            # scanned by Actions, what may write IS what is enabled: the
            # capability grants.
            enabled |= set(
                session.execute(
                    select(CapabilityGrant.capability).where(
                        CapabilityGrant.repo_full_name == repo_full_name
                    )
                ).scalars()
            )

    return CiPage(
        repo_full_name=repo_full_name,
        github_url=f"https://github.com/{repo_full_name}",
        github_actions_url=f"https://github.com/{repo_full_name}/actions",
        pipeline=status.pipeline,
        pipeline_url=status.url,
        jobs=[
            CiJobOut(
                name=job.name,
                status=job.status,
                build_name=job.build_name,
                build_url=job.build_url,
                finished_at=job.finished_at,
            )
            for job in status.jobs
        ],
        failing=status.failing,
        stages=[
            StageCoverageOut(stage=c.stage, enabled=c.enabled, state=c.state, problem=c.problem)
            for c in coverage(enabled, reported)
        ],
        reporting=[
            CiReportingOut(
                job=r.job,
                capability=r.capability,
                built_at=r.built_at,
                scanned_at=r.scanned_at,
                state=r.state,
            )
            for r in reported
        ],
        unavailable=status.unavailable,
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


@router.get("/repos/{repo_id}/sscs/sbom")
async def repo_sbom(
    request: Request,
    repo_id: str,
    principal: PrincipalDep,
    evidence_id: Annotated[str, Query()],
) -> FileResponse:
    """The archived SBOM itself, not just its trust-score summary (spec 18 §8.2).

    Admin-only — `may_see_raw_output`, the same gate every other archived
    tool output already sits behind (spec 12 §5): an SBOM is raw output too,
    just one atlas produced rather than a scanner.
    """
    if not principal.may_see_raw_output:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Downloading an SBOM requires the 'admin' role; you have "
                f"'{principal.role.value}'."
            ),
        )

    repo_full_name = _resolve_repo(request, repo_id)
    row = _queries(request).sscs_evidence_row(repo_full_name, evidence_id)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No supply-chain evidence {evidence_id} for this repository.",
        )
    sbom_ref = row.get("sbom_ref")
    if not sbom_ref:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="This evidence row names no SBOM — one was never captured for it.",
        )

    settings = request.app.state.settings
    # Resolved and re-checked against the lake root before serving, even
    # though `sbom_ref` is this backend's own write, not client input — the
    # same belt-and-suspenders `_identifier`/`_safe_segment` apply elsewhere
    # to paths this platform builds itself (spec 18 §8.2).
    path = (settings.datalake_dir / str(sbom_ref)).resolve()
    lake_root = settings.datalake_dir.resolve()
    if lake_root not in path.parents:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="SBOM reference is invalid."
        )
    if not path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "This evidence row named an SBOM, but the file has since been "
                "pruned by retention (spec 05 §7) — the row itself is not lost, "
                "only the archived bytes."
            ),
        )

    return FileResponse(path, filename=path.name, media_type="application/json")


@router.get("/repos/{repo_id}/threat-model", response_model=ThreatModelOut)
async def repo_threat_model(
    request: Request, repo_id: str, principal: PrincipalDep
) -> ThreatModelOut:
    """A STRIDE-categorized attack-surface inventory for one repo (spec 18 §6).

    Composed from `open_findings`' own building blocks — `_finding_rows` and
    `_group_findings` — not a second grouping implementation reading the same
    table differently.
    """
    repo_full_name = _resolve_repo(request, repo_id)
    return ThreatModelOut.model_validate(_queries(request).threat_model(repo_full_name))


@router.get("/repos/{repo_id}/findings", response_model=FindingsPage)
async def repo_findings(
    request: Request,
    repo_id: str,
    principal: PrincipalDep,
    capability: Annotated[Capability | None, Query()] = None,
    severity: Annotated[Severity | None, Query()] = None,
    finding_status: Annotated[FindingStatus | None, Query()] = None,
    rule_id: Annotated[str | None, Query(max_length=200)] = None,
    first_seen_after: Annotated[datetime | None, Query()] = None,
    first_seen_before: Annotated[datetime | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> FindingsPage:
    """Filterable finding list for one repo (spec 10 §2.2, spec 17 §3)."""
    repo_full_name = _resolve_repo(request, repo_id)

    findings, total = _queries(request).findings(
        repo_full_name,
        capability=capability.value if capability else None,
        severity=severity.value if severity else None,
        finding_status=finding_status.value if finding_status else None,
        rule_id=rule_id,
        first_seen_after=first_seen_after,
        first_seen_before=first_seen_before,
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


@router.get("/repos/{repo_id}/open-findings", response_model=OpenFindingsPage)
async def repo_open_findings(
    request: Request,
    repo_id: str,
    principal: PrincipalDep,
    capability: Annotated[Capability | None, Query()] = None,
    severity: Annotated[Severity | None, Query()] = None,
    finding_status: Annotated[FindingStatus, Query()] = FindingStatus.OPEN,
    rule_id: Annotated[str | None, Query(max_length=200)] = None,
    kev_only: Annotated[bool, Query()] = False,
    min_epss: Annotated[float | None, Query(ge=0.0, le=1.0)] = None,
    triage: Annotated[TriageFilter | None, Query()] = None,
    fixable: Annotated[bool | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=2000)] = 400,
) -> OpenFindingsPage:
    """What is outstanding here, deduplicated, triaged and correlated.

    `findings` is the record — every row, every status, in the order the lake
    holds them. This is the view somebody works from, and it differs on three
    counts that all pull the same way: it shows open findings only, it collapses
    repeat reports of one problem into one row, and it names the toxic
    combinations, which are the findings that are dangerous precisely because
    each half looks unremarkable on its own.

    Raw tool output is not served here for anybody. The group is a decision to
    make; the bytes belong on the finding detail, behind the admin check that
    has always guarded them (spec 12 §5).
    """
    repo_full_name = _resolve_repo(request, repo_id)
    with request.app.state.db.session() as session:
        page = _queries(request).open_findings(
            repo_full_name,
            store=request.app.state.knowledge,
            capability=capability.value if capability else None,
            severity=severity.value if severity else None,
            rule_id=rule_id,
            finding_status=finding_status.value,
            limit=limit,
            session=session,
            kev_only=kev_only,
            min_epss=min_epss,
            triage=triage,
            fixable=fixable,
        )
    return OpenFindingsPage.model_validate(page)


@router.get("/repos/{repo_id}/scan-health")
async def scan_health(request: Request, repo_id: str, principal: PrincipalDep) -> dict[str, Any]:
    """Per-capability run history and freshness (spec 10 §2.2).

    Auditable from the lake alone, which is the point of writing a ScanRun for
    every run including the ones that found nothing (spec 04 §7).
    """
    repo_full_name = _resolve_repo(request, repo_id)
    return {
        "repo_full_name": repo_full_name,
        "capabilities": _queries(request).scan_health(repo_full_name),
    }


@router.get("/repos/{repo_id}/scan-runs/trend")
async def scan_run_trend(
    request: Request,
    repo_id: str,
    principal: PrincipalDep,
    capability: Annotated[str, Query()],
    days: Annotated[int, Query(ge=7, le=730)] = 90,
    points: Annotated[int, Query(ge=2, le=60)] = 12,
) -> dict[str, Any]:
    """One capability's pass rate over time (spec 19 §1.1) — the Harness
    tab's sparkline, same bucketed-not-reconstructed shape `/trends` uses
    for findings/risk, computed separately because a scan either ran in a
    window or it didn't; there is no open-ended state to replay.
    """
    repo_full_name = _resolve_repo(request, repo_id)
    return {
        "repo_full_name": repo_full_name,
        "capability": capability,
        "points": _queries(request).scan_run_trend(
            repo_full_name, capability, days=days, points=points
        ),
    }


@router.get("/findings/{finding_id}", response_model=FindingOut)
async def finding_detail(
    request: Request, finding_id: str, principal: PrincipalDep
) -> FindingOut:
    """One finding, by id.

    The dashboard groups repeat reports of a problem into one row, so the
    occurrence somebody clicks is routinely not in the first page of the flat
    list. Fetching it by id is the difference between a detail pane that always
    works and one that works for the first hundred findings.

    Raw output stays admin-only (spec 12 §5) — withheld at the query layer, so
    "not rendered" is never confused with "not sent".
    """
    record = DashboardQueries(request.app.state.catalog).finding(
        finding_id, include_raw=principal.may_see_raw_output
    )
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"No finding {finding_id}."
        )
    return FindingOut.model_validate(record)


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


@router.patch("/findings/{finding_id}/owner", response_model=OwnerChangeResult)
async def set_finding_owner(
    request: Request, finding_id: str, body: OwnerChange, principal: PrincipalDep
) -> OwnerChangeResult:
    """Reassign a finding (spec 24 §1.2).

    Admin-only, like the disposition endpoint next to it and for the same
    reason: it changes who is answerable for a piece of work, which is a write.

    A manual assignment survives re-scans — the compaction upsert refuses to
    overwrite `owner_source = 'manual'`. Clearing the owner is therefore not
    "nobody owns this" but "go back to asking CODEOWNERS", which is why the
    null case restores `unresolved` rather than writing a manual null that
    would freeze the finding out of resolution for ever.
    """
    if not principal.may_write:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Reassigning a finding requires the 'admin' role; you have "
                f"'{principal.role.value}'."
            ),
        )

    catalog = request.app.state.catalog
    existing = DashboardQueries(catalog).finding(finding_id)
    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"No finding {finding_id}."
        )

    owner = (body.owner or "").strip() or None
    source = "manual" if owner else "unresolved"

    outcome = update_findings(
        catalog,
        locate_findings(catalog, [finding_id]),
        "owner = ?, owner_source = ?",
        [owner, source],
    )
    if not outcome.count:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The finding could not be updated; it may have just been compacted.",
        )

    with request.app.state.db.session() as session:
        request.app.state.db.audit(
            session,
            actor=principal.actor,
            action="finding.owner",
            entity_type="finding",
            entity_id=finding_id,
            repo=existing.get("repo_full_name"),
            capability=existing.get("capability"),
            new_status=owner or "unassigned",
            reason="",
        )

    logger.info(
        "Finding %s owner -> %s by %s",
        scrub(finding_id),
        scrub(owner or "unassigned"),
        scrub(principal.actor),
    )

    return OwnerChangeResult(finding_id=finding_id, owner=owner, owner_source=source)


class ThreatIntelEntryOut(BaseModel):
    """One CVE, matched against every open finding that names it (spec 17 §4.4)."""

    cve_id: str
    in_kev: bool
    kev_added_at: date | None = None
    kev_due_date: date | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    fetched_at: datetime | None = None
    worst_severity: Severity
    repo_full_names: list[str]
    finding_count: int


@router.get("/threat-intel", response_model=list[ThreatIntelEntryOut])
async def threat_intel(request: Request, principal: PrincipalDep) -> list[dict[str, Any]]:
    """Every CVE currently matched to an open finding somewhere in the
    portfolio, KEV first then EPSS descending (spec 17 §4.4).

    A CVE with no `ThreatIntelMatch` row yet (the refresh job has not run, or
    ran before this finding existed) is still returned — `in_kev: false`,
    both scores null — rather than omitted. "Not yet fetched" and "fetched,
    not exploited" must not look the same, and omitting the row is exactly
    how they would.
    """
    with request.app.state.db.session() as session:
        return _queries(request).threat_intel(session)


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
