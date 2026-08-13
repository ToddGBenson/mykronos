"""Wire and storage schemas for the data lake.

Split deliberately into *Submission* models (what a workflow POSTs) and
*Record* models (what lands in Parquet). The server derives everything a
client must not control: `finding_id`, `fingerprint_version`, `first_seen_*`,
`last_seen_*`, `status`, and all ingestion timestamps.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

# --------------------------------------------------------------------------
# Enums — spec 05 §3
# --------------------------------------------------------------------------


class Capability(StrEnum):
    SAST = "sast"
    DAST = "dast"
    SECRETS = "secrets"
    CONTAINERS = "containers"
    IAC = "iac"
    CLOUD = "cloud"
    AEGIS = "aegis"
    ATLAS = "atlas"
    PATCHWORK = "patchwork"
    ORACLE = "oracle"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanStatus(StrEnum):
    SUCCESS = "success"
    NO_APPLICABLE_TARGETS = "no_applicable_targets"
    PARTIAL_FAILURE = "partial_failure"
    FAILURE = "failure"


class TriggeredBy(StrEnum):
    PULL_REQUEST = "pull_request"
    PUSH = "push"
    SCHEDULE = "schedule"
    WORKFLOW_DISPATCH = "workflow_dispatch"
    MANUAL = "manual"


class FindingStatus(StrEnum):
    OPEN = "open"
    FIXED = "fixed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    SUPPRESSED = "suppressed"
    #: Withdrawn because the adapter that produced it was wrong (spec 05 §5a).
    #: A statement about the record, not the vulnerability — which is very
    #: likely still open under a new id, named in `superseded_by`.
    #:
    #: Deliberately not `fixed`. That is the only input to mean-time-to-fix,
    #: so retiring mis-identified findings as fixed would report a mass
    #: remediation every time an adapter was corrected.
    SUPERSEDED = "superseded"


#: Statuses that mean the finding is no longer outstanding work. `superseded`
#: is here and `open` is not, but note that `superseded` is *also* excluded
#: from the resolved-work metrics — it is neither.
TERMINAL_STATUSES = frozenset(
    {
        FindingStatus.FIXED,
        FindingStatus.FALSE_POSITIVE,
        FindingStatus.ACCEPTED_RISK,
        FindingStatus.SUPPRESSED,
        FindingStatus.SUPERSEDED,
    }
)


def utcnow() -> datetime:
    """Naive UTC. All lake timestamps are UTC (spec 01 §6); stored naive so
    Parquet round-trips identically across readers."""
    return datetime.now(UTC).replace(tzinfo=None)


def _to_naive_utc(value: datetime) -> datetime:
    if value.tzinfo is not None:
        return value.astimezone(UTC).replace(tzinfo=None)
    return value


# --------------------------------------------------------------------------
# ScanRun — spec 05 §3
# --------------------------------------------------------------------------


class ScanRunSubmission(BaseModel):
    """POSTed at workflow start, and again at completion.

    The client owns `scan_run_id` (it generates a UUID before scanning so the
    findings batch can reference it). Re-POSTing the same id updates the row
    rather than creating a second one — see `docs/DECISIONS.md`, D-002.
    """

    model_config = ConfigDict(extra="forbid")

    scan_run_id: str = Field(min_length=1, max_length=64)
    repo_full_name: str = Field(min_length=3, max_length=255, pattern=r"^[^/\s]+/[^/\s]+$")
    capability: Capability
    tool_name: str = Field(min_length=1, max_length=100)
    tool_version: str = Field(default="", max_length=100)
    commit_sha: str = Field(min_length=1, max_length=64)
    branch: str = Field(min_length=1, max_length=255)
    pr_number: int | None = None
    triggered_by: TriggeredBy
    github_workflow_run_id: str = Field(default="", max_length=64)
    started_at: datetime
    completed_at: datetime | None = None
    scan_status: ScanStatus = ScanStatus.SUCCESS
    finding_count: int = Field(default=0, ge=0)
    raw_output_ref: str | None = Field(default=None, max_length=512)

    @field_validator("started_at", "completed_at")
    @classmethod
    def _naive_utc(cls, v: datetime | None) -> datetime | None:
        return None if v is None else _to_naive_utc(v)


# --------------------------------------------------------------------------
# Finding — spec 05 §3, §5
# --------------------------------------------------------------------------


class FindingSubmission(BaseModel):
    """One normalized finding as produced by an adapter (spec 04 §4).

    Note the absence of `finding_id`, `status`, and the `first_seen`/
    `last_seen` fields: those are the server's to assign. An adapter that
    could name its own finding_id could silently fork or merge identities.
    """

    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(min_length=1, max_length=255)
    title: str = Field(min_length=1, max_length=1000)
    description: str = Field(default="", max_length=100_000)
    severity: Severity
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)

    file_path: str | None = Field(default=None, max_length=2000)
    line_start: int | None = Field(default=None, ge=0)
    line_end: int | None = Field(default=None, ge=0)

    symbol: str | None = Field(
        default=None,
        max_length=500,
        description="Enclosing function/class/resource. Part of the fingerprint.",
    )
    code_snippet: str | None = Field(
        default=None,
        max_length=20_000,
        description=(
            "Source at the finding location, captured while the repo is checked out. "
            "Normalized and hashed into finding_id (spec 05 §5). Supplying this is what "
            "keeps the finding stable across unrelated edits."
        ),
    )

    package_name: str | None = Field(default=None, max_length=500)
    package_version: str | None = Field(default=None, max_length=200)

    raw_finding_json: dict[str, Any] = Field(
        default_factory=dict,
        description="Original tool record, preserved verbatim (spec 05 §3).",
    )


class FindingBatch(BaseModel):
    """A batch of findings for one scan run.

    `max_length` here is the spec 05 §6 backpressure ceiling; exceeding it is a
    422 from Pydantic rather than a partial ingest.

    Note what is and is not a field. `capability` must be declared, because one
    token now spans several capabilities (D-009) — the server checks it against
    the token's grant set. `repo_full_name` is *not* a field and never will be:
    it comes from the token, so there is nowhere to name another repo.
    """

    model_config = ConfigDict(extra="forbid")

    scan_run_id: str = Field(min_length=1, max_length=64)
    capability: Capability
    findings: list[FindingSubmission] = Field(default_factory=list, max_length=10_000)


# --------------------------------------------------------------------------
# Aegis — insider risk (spec 06)
# --------------------------------------------------------------------------


class SubSignal(BaseModel):
    """One contributing insider-risk signal, with the reason it fired.

    The rationale is required, not optional (spec 06 §6). A number with no
    reason attached is not something a person can dispute, and this score is
    about a person — see spec 06 §9.
    """

    model_config = ConfigDict(extra="forbid")

    key: str = Field(min_length=1, max_length=64)
    score: float = Field(ge=0.0, le=100.0)
    rationale: str = Field(
        min_length=1,
        max_length=2000,
        description="Plain-language statement of what was observed and why it scored.",
    )


class InsiderRiskSubmission(BaseModel):
    """What the Aegis workflow posts (spec 06 §3, §4).

    No `repo_full_name` and no `signal_id`: the repo comes from the token and
    the id is derived server-side from repo + PR + commit, so a re-run on an
    unchanged head commit upserts instead of appending.
    """

    model_config = ConfigDict(extra="forbid")

    pr_number: int = Field(ge=1)
    commit_sha: str = Field(min_length=1, max_length=64)
    author_login: str = Field(
        min_length=1,
        max_length=255,
        description=(
            "The GitHub login whose pull request was scored. Required: a score "
            "you cannot attribute is one nobody can challenge and nobody can "
            "delete on request (spec 06 §9)."
        ),
    )
    signals: list[SubSignal] = Field(default_factory=list, max_length=50)
    ai_authorship_flag: bool | None = Field(
        default=None,
        description=(
            "True if AI authorship is likely and undisclosed, false if "
            "evaluated and human, null if not evaluated. Null is the default "
            "because the classifier is opt-in (spec 06 §5)."
        ),
    )


# --------------------------------------------------------------------------
# Atlas — supply-chain evidence (spec 07)
# --------------------------------------------------------------------------


class EcosystemEvidence(BaseModel):
    """Per-ecosystem detail for one repo.

    A monorepo scans each ecosystem independently and sums into one evidence
    row (spec 07 §8); this is the detail the sum would otherwise destroy.
    """

    model_config = ConfigDict(extra="forbid")

    ecosystem: str = Field(min_length=1, max_length=64)
    tool_name: str = Field(default="", max_length=128)
    dependency_count: int = Field(default=0, ge=0)
    critical_vulns: int = Field(default=0, ge=0)
    high_vulns: int = Field(default=0, ge=0)
    medium_vulns: int = Field(default=0, ge=0)
    low_vulns: int = Field(default=0, ge=0)
    floating_versions: int = Field(
        default=0, ge=0, description="Dependencies not pinned to an exact version."
    )
    stale_dependencies: int = Field(
        default=0, ge=0, description="No release in 2+ years."
    )
    maintenance_data_available_for: int | None = Field(
        default=None,
        ge=0,
        description=(
            "Dependencies whose maintenance recency could actually be "
            "determined. Private-registry packages have none and are excluded "
            "from the stale ratio's denominator rather than counted as fresh "
            "or as stale (spec 07 §8). Null means the tool did not report it, "
            "in which case dependency_count is used."
        ),
    )


class SscsEvidenceSubmission(BaseModel):
    """What the Atlas workflow posts (spec 07 §3, §4).

    Counts rather than a trust score: the score is computed server-side from
    §5's formula so it is reproducible and cannot drift between the workflow's
    version of the arithmetic and the platform's.
    """

    model_config = ConfigDict(extra="forbid")

    commit_sha: str = Field(min_length=1, max_length=64)
    tag_or_release: str | None = Field(default=None, max_length=255)
    sbom_ref: str | None = Field(
        default=None,
        max_length=1000,
        description="Raw-output reference for the generated SBOM (spec 05 §7).",
    )
    ecosystems: list[EcosystemEvidence] = Field(default_factory=list, max_length=50)
    provenance: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Minimal SLSA-style statement: builder id, source repo and commit, "
            "workflow run id, timestamp. Straight from the runner's GITHUB_* "
            "environment."
        ),
    )


# --------------------------------------------------------------------------
# Responses
# --------------------------------------------------------------------------


class IngestAccepted(BaseModel):
    """A 200 from an ingestion endpoint is a durability guarantee (spec 05 §4)."""

    accepted: int
    scan_run_id: str | None = None
    buffered_at: datetime = Field(default_factory=utcnow)
    detail: str = "Written to the durability buffer."


class AegisAccepted(BaseModel):
    """The scored result, returned so the workflow can render it in its log.

    The recommendation is echoed rather than recomputed on the runner: one
    definition of the arithmetic, in the platform (spec 06 §4).
    """

    accepted: int
    signal_id: str
    insider_risk_score: int
    recommendation: str
    blocking: bool
    check_run_id: str | None = None
    check_run_error: str | None = None
    detail: str = "Written to the durability buffer."


class AtlasAccepted(BaseModel):
    accepted: int
    evidence_id: str
    #: Null when the scan resolved no dependencies (spec 07 §5a). The workflow
    #: prints this, so a repository that pinned nothing sees "not assessed"
    #: rather than a score it did not earn.
    trust_score: int | None
    raw_trust_score: float | None
    dependency_count: int
    vulnerable_dependency_count: int
    min_trust_score: int
    blocking: bool
    below_minimum: bool = Field(
        description=(
            "Whether the score is under this repo's configured floor. Reported "
            "even when blocking is off, so the workflow log says what would "
            "have happened."
        )
    )
    detail: str = "Written to the durability buffer."


class RawAccepted(BaseModel):
    """Archived raw tool output (spec 05 §7)."""

    raw_output_ref: str
    bytes_written: int


class HealthResponse(BaseModel):
    status: str
    datalake_writable: bool
    buffered_segments: int
    detail: str = ""
    #: Echoed back so a workflow's pre-scan probe also confirms what this
    #: token is scoped to and currently allowed to write.
    repo_full_name: str = ""
    granted_capabilities: list[str] = Field(default_factory=list)
