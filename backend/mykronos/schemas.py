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
# Responses
# --------------------------------------------------------------------------


class IngestAccepted(BaseModel):
    """A 200 from an ingestion endpoint is a durability guarantee (spec 05 §4)."""

    accepted: int
    scan_run_id: str | None = None
    buffered_at: datetime = Field(default_factory=utcnow)
    detail: str = "Written to the durability buffer."


class HealthResponse(BaseModel):
    status: str
    datalake_writable: bool
    buffered_segments: int
    detail: str = ""
    #: Echoed back so a workflow's pre-scan probe also confirms what this
    #: token is scoped to and currently allowed to write.
    repo_full_name: str = ""
    granted_capabilities: list[str] = Field(default_factory=list)
