"""Dashboard API (spec 10 §4).

Read-only except for one endpoint: marking a finding as a false positive or
accepted risk. That write is the seed of the whole learning loop — spec 11 §4
turns it into a retro signal that eventually dampens the rule in Oracle's
policy — which is why it demands a reason.
"""

from __future__ import annotations

import logging
import time
from datetime import date, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from mykronos import controls, governance, incident, regression, worklist
from mykronos.adminauth import PrincipalDep
from mykronos.ci import (
    ActionsClient,
    ConcourseClient,
    PipelineStatus,
    StatusCache,
    capability_by_workflow,
    coverage,
    pipeline_name_for,
    reconcile,
)
from mykronos.dashboard import STRIDE_CATEGORIES, DashboardQueries, PortfolioSummary
from mykronos.db.models import (
    CapabilityGrant,
    RepoControl,
    RepoOnboarding,
    capability_config_for,
)
from mykronos.knowledge.capture import (
    capture_classification_rejected,
    capture_dismissal,
    safe_capture,
)
from mykronos.lake.mutate import locate_findings, update_findings
from mykronos.logsafe import scrub
from mykronos.maturity import assess as maturity_assess
from mykronos.maturity import mean_time_to_fix, throughput, trend_series
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
    enabled: bool = Field(
        default=True,
        description=(
            "Whether this repository asked for the capability. Every "
            "capability the platform has gets a row, so a stage nobody "
            "enabled is named rather than missing — `enabled: false` and "
            "`has_scanned: false` is 'not configured here', while "
            "`enabled: true` with `has_scanned: false` is enabled and silent, "
            "which is somebody's problem. They used to be the same absence."
        ),
    )
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
    synthetic: bool = Field(
        default=False,
        description=(
            "A seeded benchmark corpus (spec 23 §1.2). Scanned and browsable "
            "like any other repository, and counted in none of the summary "
            "totals beside it — which the row says, because a repository "
            "excluded from every number with nothing on the page explaining "
            "why is how somebody comes to distrust the numbers."
        ),
    )
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
            "The standing risk score from the latest portfolio decision. Null "
            "means not judged — deliberately not 0, which would read as "
            "'assessed, no risk'. Risk decisions are opt-in, so a repo that "
            "never enabled them stays null."
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


class ClaimRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    by: str = Field(
        min_length=1,
        max_length=255,
        description="A handle. An anonymous claim tells nobody anything.",
    )


class SnoozeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    until: date = Field(description="A date, not a timestamp — 'come back on Tuesday'.")
    reason: str = Field(
        min_length=1,
        max_length=2000,
        description=(
            "Required. A row that reappears with no reason recorded is a "
            "deferral nobody can review."
        ),
    )


class BatchRequest(BaseModel):
    """One action over a selection (spec 27 §3.1)."""

    model_config = ConfigDict(extra="forbid")

    finding_ids: list[str] = Field(min_length=1, max_length=100)
    action: Literal["claim", "release", "snooze", "wake"]
    by: str | None = None
    until: date | None = None
    reason: str = Field(
        default="",
        max_length=2000,
        description=(
            "Applied to every finding in the batch. Batching must not become "
            "a way to skip the reason field — see the endpoint."
        ),
    )


class BatchResult(BaseModel):
    applied: list[str]
    refused: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "finding_id -> why. A batch reports per-row outcomes rather than "
            "failing whole: one claimed row must not stop the other ninety-nine."
        ),
    )


class TriageStateOut(BaseModel):
    """Who holds this row, and until when (spec 27 §3)."""

    claimed_by: str | None = None
    claim_expires_at: datetime | None = None
    claim_lapsing: bool = False
    snoozed_until: date | None = None
    snooze_reason: str | None = None


class RankTermOut(BaseModel):
    """One contribution to a queue row's rank (spec 27 §1.1).

    Modelled rather than a bare dict for the reason `FindingOut`'s docstring
    gives: a `dict[str, Any]` types the whole frontend as `unknown` and pushes
    the guessing into a cast — and this is the field whose entire purpose is
    to be read.
    """

    key: str
    points: float
    detail: str


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
    triage: str = Field(
        default="needs_human_judgment",
        description=(
            "What the classifier concluded about this row, and why. Carried "
            "on every row rather than only when filtered, so a queue can show "
            "it without a second request (B-019)."
        ),
    )
    triage_rationale: str = Field(
        default="",
        description=(
            "The sentence behind the classification. spec 01 §6 makes an "
            "unexplained verdict a bug, and a row labelled 'needs human "
            "judgment' with nothing saying why is one."
        ),
    )
    first_seen_at: datetime | None = None
    repo_recommendation: str | None = Field(
        default=None,
        description=(
            "The repo's standing risk verdict, carried per row so the queue "
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
    owner: str | None = Field(
        default=None, description="From CODEOWNERS or the risk profile (spec 24 §1)."
    )
    due_state: str | None = Field(
        default=None, description="overdue | due_soon | on_track | no_target (spec 24 §2.4)."
    )
    effort: str | None = Field(
        default=None,
        description=(
            "one_click | small | investigation (spec 27 §2). Three bands, not "
            "an hour estimate: an estimate this platform cannot verify is a "
            "number nobody should plan against."
        ),
    )
    blast_radius_repos: int | None = Field(
        default=None, description="Repositories carrying a finding on this package."
    )
    rank: float | None = Field(
        default=None, description="Only when ordering by rank (spec 27 §1)."
    )
    state: TriageStateOut = Field(
        default_factory=TriageStateOut,
        description="Claim and snooze, from the operational store (spec 27 §3.2).",
    )
    rank_terms: list[RankTermOut] = Field(
        default_factory=list,
        description=(
            "Every term that produced `rank`, with its points and a sentence. "
            "A rank a person cannot argue with is a rank they will ignore."
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
    #: Who this is addressed to, and where that answer came from (spec 24 §1).
    #: `owner_source` is codeowners | profile | manual | unresolved — the four
    #: are behaviourally different, and a bare null owner could be any of them.
    owner: str | None = None
    owner_source: str | None = None
    #: When this is due and who set that date (spec 24 §2). `due_source` is
    #: kev | policy | manual; null means no target applies to this severity.
    due_at: datetime | None = None
    due_source: str | None = None
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
#: The `due` query filter (spec 24 §2.4). A Literal so a typo is a 422 with
#: the allowed values in it, rather than a silently empty list.
DueFilter = Literal["overdue", "due_soon", "on_track", "no_target"]

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
            "The auto-remediation classification (`patchwork/triage.py`), plus "
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
            "Whether auto-remediation produced a fix for any occurrence in this "
            "group (spec 19 §3.2). Read from what it actually did, not "
            "predicted — a fixer cannot say whether it applies without the "
            "file content, and a prediction would never self-correct. Null "
            "means nobody has looked yet, which is distinct from `false`: "
            "looked, and there is no mechanical fix."
        ),
    )
    due_at: datetime | None = Field(
        default=None,
        description=(
            "The soonest deadline among this group's occurrences (spec 24 §2). "
            "Null means no target applies — `info` findings, or a deployment "
            "with no remediation targets configured."
        ),
    )
    due_source: str | None = Field(
        default=None,
        description="kev | policy | manual. A KEV date on any occurrence wins.",
    )
    owner: str | None = Field(
        default=None,
        description=(
            "The owner, when every occurrence in this group has the same one "
            "(spec 24 §1). Null when they disagree — see `owner_split` — or "
            "when no CODEOWNERS rule matched."
        ),
    )
    owner_split: bool = Field(
        default=False,
        description=(
            "True when occurrences have different owners. One rule firing "
            "across two teams' files is one decision with two people "
            "answerable for it, and naming either would misroute half of it."
        ),
    )
    cwe_ids: list[str] = Field(
        default_factory=list,
        description="What the reporting tool declared, normalised (spec 28 §1).",
    )
    mapping_resolution: str | None = Field(
        default=None,
        description=(
            "How this row was placed in its STRIDE categories: `cwe` when the "
            "tool named one this platform maps, `capability` otherwise. Per "
            "row, because a repository is routinely mixed."
        ),
    )
    due_state: str = Field(
        default="no_target",
        description=(
            "overdue | due_soon | on_track | no_target. `no_target` is not "
            "'on track': it is unmeasured, and showing it as on track would "
            "report compliance nobody assessed."
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
            "Whether this repository's insider-risk Check Run can fail a pull "
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
            "the risk decision's raw_score survives the ceiling at 100 (D-018)."
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


class ControlOut(BaseModel):
    """A declared mitigation (spec 28 §3)."""

    control_id: str
    stride: str
    kind: str
    description: str = ""
    evidence_ref: str = ""
    evidence: str = Field(
        description=(
            "`referenced` when the control names a file, route, policy or "
            "test; `asserted` when it does not. Both are allowed — refusing "
            "the second would mean the register only ever holds the controls "
            "somebody had time to document — and the tab renders the second "
            "as the weaker claim it is."
        )
    )
    verified_by_capability: str = ""
    checkable: bool = Field(
        description=(
            "Whether any capability in this platform could contradict this "
            "control. False is stated rather than left implied: a control "
            "nothing can check is not a verified control."
        )
    )
    last_verified_at: datetime | None = None
    stale: bool = Field(
        description=(
            "Nobody has re-confirmed this in 90 days. A mitigation nobody has "
            "checked since last quarter is a belief, and the tab says which "
            "of the two it is showing."
        )
    )
    declared_by: str = ""
    declared_at: datetime


class ThreatModelCategoryOut(BaseModel):
    stride: str = Field(description="One of STRIDE_CATEGORIES (dashboard.py).")
    findings: list[FindingGroupOut]
    state: str = Field(
        default="findings_open",
        description=(
            "`findings_open` | `unmitigated` | `mitigated` | `unscanned` "
            "(spec 28 §4). `unscanned` is the one that matters: a category "
            "nothing has ever reported into used to render identically to a "
            "clean one, which made an absence of looking read as good news."
        ),
    )
    controls: list[ControlOut] = Field(default_factory=list)
    contradicted: bool = Field(
        default=False,
        description=(
            "Findings open *and* a control declared here. Shown rather than "
            "resolved: a control that exists while findings accumulate under "
            "it is either wrong, bypassed, or narrower than its description, "
            "and the platform has no basis to decide which."
        ),
    )
    reason: str = Field(default="", description="Why this category is in this state.")


class ThreatModelOut(BaseModel):
    """A STRIDE-categorized attack-surface inventory (spec 18 §6)."""

    repo_full_name: str
    mapping_resolution: str = Field(
        description=(
            "`cwe`, `capability`, or `mixed` (spec 28 §2). Until CWEs were "
            "read out of SARIF this was always `capability` — the finest "
            "resolution the data then supported. `mixed` is the common case "
            "now and is why every row carries its own: CodeQL tags its rules, "
            "Trivy does not, and a page-level label would be wrong for half "
            "of a real repository."
        )
    )
    unmapped_cwes: list[str] = Field(
        default_factory=list,
        description=(
            "CWEs the tools declared and `stride-map-v1.yaml` does not know. "
            "Those rows fall back to capability mapping and are named here so "
            "the gap gets closed by somebody adding a row, rather than "
            "resolving to whatever category looked closest."
        ),
    )
    categories: list[ThreatModelCategoryOut]
    nothing_scanned: bool = Field(
        default=False,
        description=(
            "No capability that feeds any STRIDE category has ever reported "
            "here. Said once at the top rather than six times (spec 28 §6): "
            "it is one fact about the repository, not six about its "
            "categories."
        ),
    )
    supply_chain: ThreatModelSupplyChainOut | None = None


#: What an acceptance rests on (spec 24 §3.2).
#:
#: The free text stays and is still what a person reads. The code is what
#: makes an acceptance machine-revisitable — and only one of these is a
#: premise a scan can contradict, which is why the sweep re-opens
#: `no_vendor_fix` and nothing else.
AcceptanceReason = Literal[
    "no_vendor_fix",
    "not_exploitable_here",
    "compensating_control",
    "cost_exceeds_risk",
    "other",
]


class ClassificationReview(BaseModel):
    """A person's verdict on what the classifier concluded (B-020)."""

    model_config = ConfigDict(extra="forbid")

    agrees: bool = Field(
        description=(
            "True confirms the classifier and dispositions the finding. False "
            "records that it was wrong and leaves the finding open."
        )
    )
    reason: str = Field(
        default="",
        max_length=2000,
        description=(
            "Why. Required when agreeing, because a dismissal without one is "
            "recorded as low-confidence and barred from promotion (spec 11 "
            "§4) -- and dampening, which these dispositions feed, needs the "
            "reason rather than the click."
        ),
    )


class ClassificationReviewResult(BaseModel):
    finding_id: str
    agreed: bool
    status: str
    recorded: str


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
    accepted_until: date | None = Field(
        default=None,
        description=(
            "Review date for an accepted risk (spec 24 §3.2). Required unless "
            "`indefinite` is set: an acceptance with no end is a decision "
            "nobody revisits, and this platform is currently carrying 243 of "
            "them that each said no vendor fix exists."
        ),
    )
    indefinite: bool = Field(
        default=False,
        description=(
            "Accept with no review date. Deliberately an explicit choice "
            "rather than the default — it is rarer than people expect once a "
            "date is the easy option."
        ),
    )
    accepted_reason_code: AcceptanceReason | None = Field(
        default=None,
        description="Required when accepting a risk. See `AcceptanceReason`.",
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
                synthetic=row.synthetic,
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
    spec 08 §3 makes structural for auto-remediation, applied to the view: a page that
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
    owner: Annotated[str | None, Query(max_length=255)] = None,
    order: Annotated[Literal["severity", "rank"], Query()] = "severity",
    include_snoozed: Annotated[bool, Query()] = False,
    claimed_by: Annotated[str | None, Query(max_length=255)] = None,
    triage: Annotated[
        Literal[
            "true_positive",
            "likely_false_positive",
            "needs_human_judgment",
            "toxic_combination",
        ]
        | None,
        Query(
            description=(
                "What the classifier concluded. The per-repository findings "
                "view has had this filter; the queue did not, so 'show me "
                "everything the machine could not judge' meant one request "
                "per repository (B-019). Every row carries `triage` whether "
                "or not this is set."
            )
        ),
    ] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> TriageQueue:
    """What to work on next, across the whole portfolio (spec 10 §2.1).

    The portfolio table answers "which repo is worst". This answers "what do I
    do next" — the question somebody actually has on a Monday morning, and one
    a per-repo view makes you visit forty pages to answer.

    `order=rank` applies spec 27 §1's weighted sum: severity describes the
    vulnerability class, and everything else on the row describes this
    instance of it. Severity ordering is kept and is still the default —
    "show me every critical" remains a legitimate question, and a queue that
    refuses to answer it is a worse queue.
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
            owner=owner,
            order=order,
            policy=request.app.state.oracle_policy,
            include_snoozed=include_snoozed,
            claimed_by=claimed_by,
            triage=triage,
            store=request.app.state.knowledge,
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

    # The seeded benchmark corpus is excluded from every portfolio aggregate
    # (spec 23 §1.2). Looked up here rather than inside `trend_series`:
    # which repositories are synthetic is a fact in the operational store, and
    # a lake query reaching into the database to find out would couple the two
    # in the one direction this codebase has kept clear.
    with request.app.state.db.session() as session:
        synthetic = [
            row.github_repo_full_name
            for row in session.query(RepoOnboarding).filter(
                RepoOnboarding.synthetic.is_(True)
            )
        ]

    series = trend_series(
        catalog, repo_full_name, days=days, points=points, exclude=synthetic
    )
    return {
        "scope": repo_full_name or "portfolio",
        "days": days,
        "mean_time_to_fix_days": mean_time_to_fix(catalog, repo_full_name),
        # Spec 31 §3's portfolio equivalent. Here rather than on a page of its
        # own because every other number on this page counts what is open, and
        # this is the one that counts what was learned — it is only legible
        # beside them.
        #
        # Not windowed by `days`, and deliberately: the other series are rates
        # over a period, while this is a standing property of everything ever
        # fixed. Clipping it to 90 days would make a repository's regression
        # tests expire from the number for having been written too long ago.
        "regression_coverage": regression.as_dict(
            regression.coverage(catalog, repo_full_name)
        ),
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
    rewards turning the risk-decision gate on. Spec 09 §6 makes that conditional on
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


def _finding_repo(request: Request, finding_id: str) -> str:
    record = DashboardQueries(request.app.state.catalog).finding(finding_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"No finding {finding_id}."
        )
    return str(record.get("repo_full_name") or "")


def _require_writer(principal: Any, verb: str) -> None:
    if not principal.may_write:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"{verb} requires the 'admin' role; you have "
                f"'{principal.role.value}'."
            ),
        )


@router.get("/triage/throughput")
async def triage_throughput(
    request: Request,
    principal: PrincipalDep,
    repo_id: Annotated[str | None, Query()] = None,
) -> dict[str, Any]:
    """What moved this week, against last (spec 27 §5).

    A queue with no memory of itself cannot tell a team clearing its backlog
    from one treading water: both look like a list of open findings. Every
    number is a query over `first_seen_at`, `resolved_at` and the verification
    outcomes — no rollup table, for the reason `trend_series` gives.

    Ordered before `/triage/{finding_id}/...` so the literal path is not
    shadowed by the parameterised one.
    """
    repo_full_name = _resolve_repo(request, repo_id) if repo_id else None
    return throughput(request.app.state.catalog, repo_full_name)


@router.post("/triage/{finding_id}/claim", response_model=TriageStateOut)
async def claim_finding(
    request: Request, finding_id: str, body: ClaimRequest, principal: PrincipalDep
) -> TriageStateOut:
    """Take a row (spec 27 §3.1).

    Distinct from `owner` (spec 24 §1): ownership says who is *answerable*,
    copied from CODEOWNERS; a claim says who is *doing it now*. Conflating
    them would mean either nobody can pick up a neighbouring team's work
    without rewriting ownership, or ownership drifts every time somebody
    helps out.

    First write wins. A silent overwrite here is two people fixing the same
    finding.
    """
    _require_writer(principal, "Claiming a finding")
    repo = _finding_repo(request, finding_id)
    with request.app.state.db.session() as session:
        try:
            state = worklist.claim(session, finding_id, repo, by=body.by.strip())
        except worklist.WorklistError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail=str(exc)
            ) from exc
    return TriageStateOut(**worklist.as_dict(state))


@router.delete("/triage/{finding_id}/claim", response_model=TriageStateOut)
async def release_finding(
    request: Request, finding_id: str, principal: PrincipalDep
) -> TriageStateOut:
    """Hand a row back. The snooze, if any, is a separate decision and stays."""
    _require_writer(principal, "Releasing a finding")
    with request.app.state.db.session() as session:
        state = worklist.release(session, finding_id)
    return TriageStateOut(**worklist.as_dict(state))


@router.post("/triage/{finding_id}/snooze", response_model=TriageStateOut)
async def snooze_finding(
    request: Request, finding_id: str, body: SnoozeRequest, principal: PrincipalDep
) -> TriageStateOut:
    """Put a row down until a date, deciding nothing about it (spec 27 §3.1).

    Deliberately not a `Finding.status`: a snoozed finding is still open,
    still scores in the risk decision, and still goes overdue if it goes
    overdue. That
    separation is what stops "not now" becoming "not ever".
    """
    _require_writer(principal, "Snoozing a finding")
    repo = _finding_repo(request, finding_id)
    with request.app.state.db.session() as session:
        try:
            state = worklist.snooze(
                session, finding_id, repo, until=body.until, reason=body.reason
            )
        except worklist.WorklistError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
            ) from exc
    return TriageStateOut(**worklist.as_dict(state))


@router.delete("/triage/{finding_id}/snooze", response_model=TriageStateOut)
async def wake_finding(
    request: Request, finding_id: str, principal: PrincipalDep
) -> TriageStateOut:
    """Bring a snoozed row back early. The claim, if any, stays."""
    _require_writer(principal, "Waking a finding")
    with request.app.state.db.session() as session:
        state = worklist.wake(session, finding_id)
    return TriageStateOut(**worklist.as_dict(state))


@router.post("/triage/batch", response_model=BatchResult)
async def triage_batch(
    request: Request, body: BatchRequest, principal: PrincipalDep
) -> BatchResult:
    """One action over a selection (spec 27 §3.1).

    Reports per row rather than failing whole: one row somebody else claimed
    must not stop the other ninety-nine.

    Batching does not relax what a single action requires. A snooze still
    needs a reason and a future date — spec 11 §4's reasons are what make the
    Knowledge Store worth anything, and a bulk path that skipped them would be
    the obvious way to stop having any.
    """
    _require_writer(principal, "Batch triage")

    applied: list[str] = []
    refused: dict[str, str] = {}
    with request.app.state.db.session() as session:
        for finding_id in body.finding_ids:
            try:
                if body.action == "claim":
                    if not (body.by or "").strip():
                        raise worklist.WorklistError("`by` is required to claim.")
                    repo = _finding_repo(request, finding_id)
                    worklist.claim(session, finding_id, repo, by=str(body.by).strip())
                elif body.action == "release":
                    worklist.release(session, finding_id)
                elif body.action == "snooze":
                    if body.until is None:
                        raise worklist.WorklistError("`until` is required to snooze.")
                    repo = _finding_repo(request, finding_id)
                    worklist.snooze(
                        session, finding_id, repo, until=body.until, reason=body.reason
                    )
                else:
                    worklist.wake(session, finding_id)
                applied.append(finding_id)
            except worklist.WorklistError as exc:
                refused[finding_id] = str(exc)
            except HTTPException as exc:
                refused[finding_id] = str(exc.detail)

    logger.info(
        "Batch %s over %d finding(s) by %s: %d applied, %d refused",
        body.action,
        len(body.finding_ids),
        scrub(principal.actor),
        len(applied),
        len(refused),
    )
    return BatchResult(applied=applied, refused=refused)


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
                "This repository's insider-risk Check Run is BLOCKING: a score "
                "at or above the threshold fails the pull request."
                if blocking
                else "This repository's insider-risk Check Run is advisory — it "
                "never fails a pull request."
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
            "failed: the lane ran and its last build did not succeed, so "
            "there is no successful build to measure the lake against - "
            "distinct from not_run, which used to absorb it and reads as "
            "'nobody has triggered this yet'. not_run: the job exists and "
            "has never run."
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
            "job disagrees. reporting / silent / never_reported / failed / "
            "not_run carry their meaning from the cross-check."
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


async def _ci_status(
    request: Request,
    repo_full_name: str,
    scanned_by: str,
    installation_id: int | None,
) -> PipelineStatus:
    """Where this repository is built, from whichever CI builds it.

    Concourse is read synchronously off the same host and is not cached — it
    was never expensive. Actions is a network round-trip against a shared
    installation rate limit, so it goes through `StatusCache` (spec 32 §7.1),
    which stores successes only.

    Neither branch raises. A repository with `scanned_by="none"` gets a
    `PipelineStatus` saying exactly that, rather than a Concourse lookup for
    a pipeline nobody claimed exists.
    """
    settings = request.app.state.settings

    if scanned_by == "github_actions":
        if installation_id is None:
            return PipelineStatus(
                repo_full_name=repo_full_name,
                pipeline=None,
                url=f"https://github.com/{repo_full_name}/actions",
                unavailable="This repository has no GitHub App installation to read.",
            )
        cache: StatusCache = request.app.state.ci_status_cache
        now = time.monotonic()
        cached = cache.get(repo_full_name, now=now)
        if cached is not None:
            return cached
        client = ActionsClient(
            request.app.state.github_factory.for_installation(installation_id),
            capability_by_workflow=capability_by_workflow(request.app.state.templates),
        )
        status = await client.status_for(repo_full_name)
        cache.put(repo_full_name, status, now=now)
        return status

    if scanned_by == "none":
        return PipelineStatus(
            repo_full_name=repo_full_name,
            pipeline=None,
            url=None,
            unavailable=(
                "This repository declares no scanner (scanned_by=none). Findings can "
                "still be uploaded by hand, and nothing runs on its own."
            ),
        )

    return ConcourseClient(
        settings.concourse_url,
        team=settings.concourse_team,
        external_url=settings.concourse_external_url,
    ).status_for(repo_full_name)


@router.get("/repos/{repo_id}/ci", response_model=CiPage)
async def repo_ci(request: Request, repo_id: str, principal: PrincipalDep) -> CiPage:
    """Links out to where this repository is built (spec 15 §4a).

    Deliberately a link rather than a mirror: Concourse's own UI is the
    authority on its state, and restating a build outcome here would create a
    second version of it to disagree with. What this adds is knowing *which*
    pipeline, from a page that is already about this repository.
    """
    repo_full_name = _resolve_repo(request, repo_id)

    with request.app.state.db.session() as session:
        row = session.execute(
            select(RepoOnboarding).where(RepoOnboarding.github_repo_full_name == repo_full_name)
        ).scalar_one_or_none()
        enabled = set(row.enabled_capabilities or []) if row else set()
        scanned_by = row.scanned_by if row else "concourse"
        installation_id = row.github_installation_id if row else None

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

    # Dispatch on `scanned_by`, the same split `scan_now` and fix
    # verification already use (spec 32 §7). Everything below this line is
    # unchanged and unaware of which CI answered: `reconcile` and `coverage`
    # were always about job names, statuses and timestamps.
    status = await _ci_status(request, repo_full_name, scanned_by, installation_id)

    reported = reconcile(status.jobs, _queries(request).last_successful_scan_at(repo_full_name))

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


class RegressionLinkRequest(BaseModel):
    """Pin a test to a finding (spec 31 §2)."""

    model_config = ConfigDict(extra="forbid")

    test_identifier: str = Field(
        min_length=1,
        max_length=500,
        description="A JUnit `classname.name`, as the runner reports it.",
    )
    capability: Literal["unit", "functional", "qa"] = Field(
        default="unit", description="Which lane runs it."
    )


class RegressionLinkResult(BaseModel):
    link_id: str
    finding_id: str
    test_identifier: str
    evidence: str


@router.post(
    "/findings/{finding_id}/regression-test", response_model=RegressionLinkResult
)
async def link_regression_test(
    request: Request,
    finding_id: str,
    body: RegressionLinkRequest,
    principal: PrincipalDep,
) -> RegressionLinkResult:
    """Record the test that would fail if this came back (spec 31 §2).

    Its own endpoint rather than a field on the disposition form, and the
    reason is a rule this platform already holds: `fixed` is not a disposition
    a person may set -- it is an observation the scanners and the reconciler
    own (`HUMAN_DISPOSITIONS`). Spec 31 §2 assumed somebody marks a finding
    fixed by hand and is offered the field there; nobody can, so the moment
    the spec described does not exist. What does exist is a person who has
    just written the test, and this is where they say so.

    Recorded as `asserted`. `demonstrated` is earned by watching the test fail
    against the vulnerable code and pass against the fixed code, never claimed
    through this route: the whole point of the distinction is that one is
    somebody's word and the other is evidence.
    """
    _require_writer(principal, "Linking a regression test")
    found = DashboardQueries(request.app.state.catalog).finding(finding_id)
    if found is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"No finding {finding_id}."
        )

    try:
        identifier = regression.record(
            request.app.state.buffer,
            repo_full_name=str(found.get("repo_full_name") or ""),
            finding_id=finding_id,
            test_identifier=body.test_identifier,
            capability=body.capability,
            linked_by=principal.actor,
        )
    except regression.RegressionError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc

    return RegressionLinkResult(
        link_id=identifier,
        finding_id=finding_id,
        test_identifier=body.test_identifier.strip(),
        evidence=regression.ASSERTED,
    )


@router.get("/repos/{repo_id}/regression-coverage")
async def regression_coverage(
    request: Request, repo_id: str, principal: PrincipalDep
) -> dict[str, Any]:
    """Which fixed vulnerabilities would we notice coming back? (spec 31 §3)

    The first number in this platform that measures a repository getting
    structurally safer rather than temporarily cleaner. Everything else counts
    what is open; this counts what was learned.
    """
    repo_full_name = _resolve_repo(request, repo_id)
    return {
        "repo_full_name": repo_full_name,
        **regression.as_dict(
            regression.coverage(request.app.state.catalog, repo_full_name)
        ),
    }


class AffectedRepoOut(BaseModel):
    """One repository's exposure to one package (spec 29 §2)."""

    repo_full_name: str
    repo_id: str = Field(
        default="",
        description=(
            "The onboarding id, for linking to the repository page — which "
            "accepts only this, never `owner/repo`. Empty where the exposure "
            "outlived the onboarding, in which case there is nothing to link "
            "to and the caller should render the name as plain text."
        ),
    )
    versions: list[str] = Field(
        default_factory=list,
        description=(
            "Every version present, not one. 'We have three copies and one is "
            "patched' is the actual state, and a single version would hide the "
            "two that are not."
        ),
    )
    ecosystem: str = ""
    matched_by: str = Field(
        default="name",
        description=(
            "`purl` is exact; `name` is a guess that is usually right. A "
            "package renamed upstream matches by name and not by purl, and a "
            "view that did not say which would present a guess as an identity."
        ),
    )
    commit_sha: str = ""
    observed_at: datetime | None = None
    open_findings: int = Field(
        default=0,
        description=(
            "Exposure and a finding are different facts: a repository can "
            "contain a vulnerable package with no finding, because its last "
            "scan predates the advisory."
        ),
    )
    highest_severity: str = ""
    fixed_version: str = ""
    recommendation: str = ""
    risk_score: int | None = None


class IncidentOut(BaseModel):
    """Are we affected by this? (spec 29 §2)"""

    query: str
    kind: str = Field(description="`cve`, `purl`, or `package`.")
    in_kev: bool | None = Field(
        default=None,
        description=(
            "Null means the CVE has not been checked against KEV, which is "
            "not the same as not being listed."
        ),
    )
    epss_score: float | None = None
    affected: list[AffectedRepoOut] = Field(default_factory=list)
    clear: list[str] = Field(
        default_factory=list,
        description="Repositories with an SBOM and no match — genuinely checked.",
    )
    not_checked: list[str] = Field(
        default_factory=list,
        description=(
            "Repositories with no SBOM in the lake. **Never a clean result.** "
            "Folding these in with `clear` would convert an absence of data "
            "into a statement of safety, which is the worst thing this view "
            "could do and the thing it would do by default."
        ),
    )
    note: str = ""


class ControlStateOut(BaseModel):
    """One change-governance control (spec 30 §2)."""

    key: str
    state: str = Field(
        description=(
            "`on`, `partial`, `off`, or `unknown`. Four rather than two: a "
            "single required approval is genuinely better than none and "
            "genuinely is not two, and `unknown` is a control the platform "
            "could not read — a permissions gap, never a red cross."
        )
    )
    detail: str = ""
    value: float | None = None
    prevents: list[str] = Field(
        default_factory=list,
        description=(
            "The insider-risk signals this control would have prevented. The link is "
            "the point of the panel: it turns a log of oddities into a "
            "diagnosis with a remedy the team can action themselves."
        ),
    )


class GovernanceOut(BaseModel):
    """A repository's change-governance posture (spec 30)."""

    repo_full_name: str
    read_at: datetime | None = None
    readable: bool = True
    unreadable_reason: str = ""
    source: str = Field(
        default="none",
        description=(
            "`branch_protection`, `ruleset`, `both`, or `none`. A repository "
            "governed entirely by rulesets would read as unprotected if only "
            "the older model were consulted."
        ),
    )
    governance_score: int | None = Field(
        default=None,
        description=(
            "Null where too little could be read to say. Scored over the "
            "controls that *were* read, so an unreadable repository has no "
            "score rather than a bad one."
        ),
    )
    controls: list[ControlStateOut] = Field(default_factory=list)
    merges: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Counts by repository over the window, never by author "
            "(spec 06 §9). Each is a statement about a control whose remedy "
            "is a settings change."
        ),
    )
    note: str = ""


@router.get("/repos/{repo_id}/governance", response_model=GovernanceOut)
async def repo_governance(
    request: Request, repo_id: str, principal: PrincipalDep
) -> GovernanceOut:
    """The controls that would catch a bad change (spec 30 §1, §2, §3).

    Read live rather than from a stored snapshot. Branch protection is
    configuration a person can change in the GitHub UI in ten seconds, and a
    panel that told somebody their repository still required two reviews after
    they had turned that off would be worse than no panel. The cost is one API
    call per view, which is the right trade for a read this small.

    Never raises on GitHub. An App without `administration: read` reports every
    control as unknown and names the permission — a permissions gap is not a
    security failure and is not scored as one.
    """
    repo_full_name = _resolve_repo(request, repo_id)
    with request.app.state.db.session() as session:
        row = (
            session.query(RepoOnboarding)
            .filter(RepoOnboarding.github_repo_full_name == repo_full_name)
            .one_or_none()
        )
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"{repo_full_name} is not onboarded.",
            )
        installation_id = row.github_installation_id
        default_branch = row.default_branch

    github = request.app.state.github_factory.for_installation(installation_id)
    posture = await governance.read(
        github,
        repo_full_name,
        default_branch,
        source_paths=_source_paths(request, repo_full_name),
    )
    # Stored on the way past, so Oracle can score it without an HTTP call of
    # its own (spec 30 §4). Only when the read succeeded: overwriting a good
    # reading with an unreadable one would let a permissions blip erase a
    # posture the platform had correctly established.
    if posture.readable:
        with request.app.state.db.session() as session:
            governance.remember(session, posture)

    body = governance.as_dict(posture)
    body["merges"] = governance.merge_counts(request.app.state.catalog, repo_full_name)
    return GovernanceOut.model_validate(body)


def _source_paths(request: Request, repo_full_name: str) -> list[str]:
    """Distinct file paths this repository has findings on.

    A proxy for "source paths", and the honest one available: the platform does
    not hold a file listing, and fetching a git tree per panel render would be
    a second API call to answer a question this already answers approximately.
    Stated wherever the coverage number is shown, because a coverage figure
    computed over the files scanners happen to have touched is not the same as
    one computed over the repository.
    """
    catalog = request.app.state.catalog
    if not catalog.all_files("findings"):
        return []
    rows = catalog.query(
        """
        SELECT DISTINCT file_path FROM findings
        WHERE asset_id = ? AND file_path IS NOT NULL AND trim(file_path) <> ''
        LIMIT 2000
        """,
        [repo_full_name],
    )
    return [str(r[0]) for r in rows]


@router.get("/incident", response_model=IncidentOut)
async def incident_lookup(
    request: Request,
    principal: PrincipalDep,
    q: Annotated[str, Query(min_length=1, max_length=300)],
) -> IncidentOut:
    """Are we affected by this? (spec 29 §2)

    A CVE, a package name, or a purl, answered across every onboarded
    repository. Nothing here is new information — the inventory, the findings,
    the risk verdicts and the KEV/EPSS matches are all already held. The only
    new thing is that they arrive together, joined by package name and ordered
    worst-first, which is the difference between answering this in ten seconds
    and answering it in twenty minutes across five tabs.

    A read, deliberately. The batch actions spec 29 §2.1 describes go through
    the existing story and auto-remediation paths and are triggered per repository by
    a person: the platform does not open forty pull requests because KEV
    published overnight.
    """
    with request.app.state.db.session() as session:
        view = incident.look_up(request.app.state.catalog, session, q)
    return IncidentOut.model_validate(incident.as_dict(view))


@router.get("/repos/{repo_id}/threat-model", response_model=ThreatModelOut)
async def repo_threat_model(
    request: Request, repo_id: str, principal: PrincipalDep
) -> ThreatModelOut:
    """A STRIDE-categorized attack-surface inventory for one repo (spec 18 §6).

    Composed from `open_findings`' own building blocks — `_finding_rows` and
    `_group_findings` — not a second grouping implementation reading the same
    table differently.

    Now also carries what *stops* the things it lists (spec 28 §3, §4). A
    threat model is made of four things and this had one; the declared
    controls are read here rather than fetched separately because a category's
    state is a fact about its findings and its controls together, and two
    calls could disagree about it.
    """
    repo_full_name = _resolve_repo(request, repo_id)
    with request.app.state.db.session() as session:
        declared = controls.for_repo(session, repo_full_name)
        page = _queries(request).threat_model(repo_full_name, controls=declared)
    return ThreatModelOut.model_validate(page)


class ControlRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    stride: str = Field(max_length=32)
    kind: str = Field(max_length=32)
    description: str = Field(default="", max_length=2_000)
    evidence_ref: str = Field(
        default="",
        max_length=512,
        description=(
            "A file path, a route, a policy document, a test id. Optional: a "
            "control without one is the weaker claim and is still worth "
            "having, because requiring it would mean the register only ever "
            "holds the controls somebody had time to document."
        ),
    )


@router.post("/repos/{repo_id}/controls", response_model=ControlOut)
async def declare_control(
    request: Request, repo_id: str, body: ControlRequest, principal: PrincipalDep
) -> ControlOut:
    """Declare a mitigation (spec 28 §3).

    Admin-authored, and the response never dresses that up as more. A declared
    control says *a person asserted this*, which is a weaker and clearer claim
    than a machine implying it — and it is useful the day it ships, where a
    register waiting on spec 23 §2's entry-point inventory stays unbuilt for a
    year.

    `verified_by_capability` is derived from the kind rather than accepted
    here: it says which capability could *contradict* this control, which is a
    property of what the control is, not something a declarer may choose. A
    control naming a capability that cannot see it would look checked and be
    nothing of the kind.
    """
    _require_writer(principal, "Declaring a control")
    repo_full_name = _resolve_repo(request, repo_id)
    database = request.app.state.db
    with database.session() as session:
        try:
            control = controls.declare(
                session,
                repo_full_name=repo_full_name,
                stride=body.stride,
                kind=body.kind,
                description=body.description,
                evidence_ref=body.evidence_ref,
                declared_by=principal.actor,
                known_categories=STRIDE_CATEGORIES,
            )
        except controls.ControlError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
            ) from exc
        database.audit(
            session,
            actor=principal.actor,
            action="control.declare",
            entity_type="repo_control",
            entity_id=control.id,
            repo_full_name=repo_full_name,
            stride=control.stride,
            kind=control.kind,
        )
        return ControlOut.model_validate(controls.as_dict(control))


@router.post("/repos/{repo_id}/controls/{control_id}/confirm", response_model=ControlOut)
async def confirm_control(
    request: Request, repo_id: str, control_id: str, principal: PrincipalDep
) -> ControlOut:
    """Somebody re-read it and it is still true.

    Its own action rather than an edit, because the thing being recorded is
    that a person looked — a mitigation nobody has checked since last quarter
    is a belief, and the tab has to be able to say which of the two it is
    showing.
    """
    _require_writer(principal, "Confirming a control")
    repo_full_name = _resolve_repo(request, repo_id)
    database = request.app.state.db
    with database.session() as session:
        try:
            control = controls.confirm(session, control_id)
        except controls.ControlError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
            ) from exc
        if control.repo_full_name != repo_full_name:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="That control belongs to another repository.",
            )
        database.audit(
            session,
            actor=principal.actor,
            action="control.confirm",
            entity_type="repo_control",
            entity_id=control.id,
            repo_full_name=repo_full_name,
        )
        return ControlOut.model_validate(controls.as_dict(control))


@router.delete("/repos/{repo_id}/controls/{control_id}", status_code=204)
async def withdraw_control(
    request: Request, repo_id: str, control_id: str, principal: PrincipalDep
) -> None:
    """Remove a control that is no longer true.

    Deleted rather than flagged withdrawn, unlike almost everything else here.
    A control is a claim about the present; a withdrawn one is not evidence of
    anything, and nobody needs to know that somebody once believed
    authentication was enforced. The audit entry records who removed it, which
    is the part that matters.
    """
    _require_writer(principal, "Withdrawing a control")
    repo_full_name = _resolve_repo(request, repo_id)
    database = request.app.state.db
    with database.session() as session:
        existing = session.get(RepoControl, control_id)
        if existing is None or existing.repo_full_name != repo_full_name:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="No such control."
            )
        controls.withdraw(session, control_id)
        database.audit(
            session,
            actor=principal.actor,
            action="control.withdraw",
            entity_type="repo_control",
            entity_id=control_id,
            repo_full_name=repo_full_name,
        )


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
    due: Annotated[DueFilter | None, Query()] = None,
    owner: Annotated[str | None, Query(max_length=255)] = None,
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
            due=due,
            owner=owner,
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


@router.post(
    "/findings/{finding_id}/classification-review",
    response_model=ClassificationReviewResult,
)
async def review_classification(
    request: Request,
    finding_id: str,
    body: ClassificationReview,
    principal: PrincipalDep,
) -> ClassificationReviewResult:
    """Confirm or reject what the classifier concluded (B-020).

    The classifier labels findings `likely_false_positive` and
    `needs_human_judgment` and deliberately cannot act on either: a machine
    that could set `false_positive` would eventually dismiss a real finding,
    silently. So the label waits for a person — and until this existed, the
    only way to answer it was to open the right repository, find the row and
    disposition it by hand, which is why 43 false positives have ever been
    recorded and all of them are sast or secrets.

    **Both answers are recorded, and that is the point.** Agreeing already
    left a trace: the finding changes status and the rule earns a dismissal
    observation that feeds dampening. Disagreeing left none, so a classifier
    calling real findings false positives was indistinguishable from one
    nobody had reviewed yet. A verdict nothing ever contradicts is a verdict
    nobody is checking.

    Rejection does not dampen anything and does not change the finding: it is
    a fact about the classifier, not about the rule. Quietening a rule because
    somebody said its finding was real would invert the loop.
    """
    if not principal.may_write:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Reviewing a classification requires the 'admin' role; you "
                f"have '{principal.role.value}'."
            ),
        )

    record = _queries(request).finding(finding_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No finding {finding_id!r}.",
        )

    repo_full_name = str(record.get("repo_full_name") or "")
    rule_id = str(record.get("rule_id") or "")
    from mykronos.patchwork.triage import classify

    classification, _ = classify(
        {
            "rule_id": rule_id,
            "severity": record.get("severity"),
            "capability": record.get("capability"),
        },
        repo_full_name,
        store=request.app.state.knowledge,
    )

    if not body.agrees:
        safe_capture(
            capture_classification_rejected,
            request.app.state.knowledge,
            repo_full_name=repo_full_name,
            rule_id=rule_id,
            finding_id=finding_id,
            classification=classification,
            reason=body.reason,
            actor=principal.actor,
        )
        return ClassificationReviewResult(
            finding_id=finding_id,
            agreed=False,
            # Untouched, deliberately. The person said it is real.
            status=str(record.get("status") or "open"),
            recorded="classifier rejection",
        )

    if classification != "likely_false_positive":
        # Agreeing with `needs_human_judgment` would mean dismissing a finding
        # the machine explicitly declined to judge, which is the one thing
        # this endpoint must not become a shortcut for.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"This finding is classified {classification!r}, not "
                "'likely_false_positive'. Agreeing here would dismiss a "
                "finding the classifier did not call a false positive; use "
                "the disposition endpoint and say why."
            ),
        )

    if not body.reason.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "Confirming a false positive needs a reason. A bare click is "
                "recorded as low-confidence and barred from promotion (spec 11 "
                "§4), and dampening reads the reason rather than the count."
            ),
        )

    # Delegated rather than reimplemented. The disposition path already does
    # the update, the audit entry, the knowledge capture and the retro signal,
    # and a second copy here is a second thing to keep in step -- this
    # endpoint's whole purpose is to be a shorter route to the same decision,
    # not a different one.
    await set_finding_status(
        request,
        finding_id,
        StatusChange(status=FindingStatus.FALSE_POSITIVE, reason=body.reason),
        principal,
    )
    return ClassificationReviewResult(
        finding_id=finding_id,
        agreed=True,
        status=FindingStatus.FALSE_POSITIVE.value,
        recorded="disposition and dismissal learning",
    )


@router.patch("/findings/{finding_id}/status", response_model=StatusChangeResult)
async def set_finding_status(
    request: Request, finding_id: str, body: StatusChange, principal: PrincipalDep
) -> StatusChangeResult:
    """Record a human disposition (spec 10 §2.2).

    Admin-only: this changes what the risk-decision engine will decide, so it
    is a write, not a view. Viewers can read every finding and change none of
    them.
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

    accepting = body.status is FindingStatus.ACCEPTED_RISK
    if accepting:
        if body.accepted_reason_code is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=(
                    "Accepting a risk requires `accepted_reason_code`. The free "
                    "text is what a person reads; the code is what lets a later "
                    "scan contradict the premise — 'no vendor fix' stops being "
                    "true the day a vendor ships one."
                ),
            )
        if body.accepted_until is None and not body.indefinite:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=(
                    "Accepting a risk requires either `accepted_until` or an "
                    "explicit `indefinite: true`. An acceptance with no end is "
                    "a decision nobody revisits."
                ),
            )
        if body.accepted_until is not None and body.accepted_until <= utcnow().date():
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=(
                    f"`accepted_until` is {body.accepted_until.isoformat()}, which "
                    "is not in the future. The next sweep would expire this "
                    "acceptance immediately."
                ),
            )
    elif body.accepted_until is not None or body.accepted_reason_code is not None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=(
                "`accepted_until` and `accepted_reason_code` only apply to "
                f"`accepted_risk`, not to '{body.status.value}'."
            ),
        )

    outcome = update_findings(
        catalog,
        locate_findings(catalog, [finding_id]),
        "status = ?, resolved_at = ?, accepted_until = ?, accepted_reason_code = ?",
        [
            body.status.value,
            utcnow(),
            body.accepted_until if accepting else None,
            body.accepted_reason_code if accepting else None,
        ],
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
