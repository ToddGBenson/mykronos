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
    #: Spec 14. The first capability whose subject is not a repository, which
    #: is why findings carry an asset rather than a repo name (spec 14 §5).
    NETWORK = "network"

    #: Quality stages (D-046). These report a ScanRun and never a finding: a
    #: failing assertion is not a vulnerability, and giving it a severity
    #: would let a broken test raise a security risk score.
    UNIT = "unit"
    FUNCTIONAL = "functional"
    QA = "qa"

    #: Spec 04 §3, D-047. Prompt-injection surface, model provenance and
    #: evaluation coverage. Whether a *pull request* discloses AI authorship
    #: stays in Aegis: that is a question about a person.
    AI = "ai"


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
    #: A one-line summary an adapter had something specific to say (spec 19
    #: §1.2) — "3 of 10 test(s) failed", not a log dump. The full output is
    #: already archived via `raw_output_ref` for anyone who needs it. Null
    #: for the common case of nothing specific to add beyond `scan_status`.
    detail: str | None = Field(default=None, max_length=200)
    #: Coverage the runner reported, 0..1 (spec 31 §4). Null means the report
    #: did not carry it — a different fact from 0.0, which means the runner
    #: measured and found none, and the tab distinguishes them.
    line_coverage: float | None = Field(default=None, ge=0.0, le=1.0)
    branch_coverage: float | None = Field(default=None, ge=0.0, le=1.0)

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

    #: Where a network finding is, since it has no file (spec 14 §5). Part of
    #: the fingerprint: address and port rather than hostname, which is often
    #: absent, and not the service banner, which changes on every patch and
    #: would churn identity on exactly the events that should resolve a
    #: finding instead.
    address: str | None = Field(default=None, max_length=100)
    port: int | None = Field(default=None, ge=0, le=65535)

    cwe_ids: list[str] = Field(
        default_factory=list,
        max_length=20,
        description=(
            "CWE identifiers the *tool* declared, normalised to `CWE-89` form "
            "(spec 28 §1). A list, not a field: a rule legitimately maps to "
            "several, and picking one would be the adapter inventing "
            "precision. Empty means the tool said nothing — which is absent, "
            "not 'no CWE applies', and the STRIDE mapping depends on that "
            "distinction."
        ),
    )

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
    licenses_seen: dict[str, int] = Field(
        default_factory=dict,
        description=(
            "License identifier to component count, from the SBOM Syft "
            "already produces (spec 22 §1). Empty means the license pass did "
            "not run for this ecosystem — not that its components are "
            "unlicensed, which is what the `unknown` key means when the pass "
            "did run."
        ),
    )


class ReachabilitySubmission(BaseModel):
    """What the reachability analysis posts (spec 19 §2.1).

    Conclusions only, like every other runner-side analysis: which files
    nothing imports, and how many were read. No source, no import graph — the
    graph is an intermediate the platform has no use for, and shipping it
    would be sending repository structure somewhere it does not need to go.
    """

    model_config = ConfigDict(extra="forbid")

    language: str = Field(default="python", max_length=32)
    commit_sha: str = Field(default="", max_length=64)
    orphaned_paths: list[str] = Field(
        default_factory=list,
        max_length=5000,
        description=(
            "Repo-relative paths nothing in the repository imports, and that "
            "are not entry points. An empty list is a real answer — analysed, "
            "everything is imported from somewhere — and is not the same as "
            "the analysis never having run."
        ),
    )
    files_analysed: int = Field(
        default=0,
        ge=0,
        description=(
            "The denominator. Three orphaned files means something different "
            "out of twelve than out of twelve hundred."
        ),
    )
    files_unparseable: int = Field(
        default=0,
        ge=0,
        description=(
            "Never counted as orphaned: a file whose imports could not be "
            "read leaves everything it might import unproven too."
        ),
    )


class ProvenanceSignals(BaseModel):
    """How this repository builds, as the runner observed it (spec 29 §3).

    Every existing trust-score term is a fact about *dependencies*. Nothing
    scored the integrity of the repository's own outputs — whether its commits
    are signed, whether its artefacts carry a provenance attestation, whether
    what it deploys is pinned by digest rather than by a tag somebody can move
    underneath it.

    **Every field is nullable and null means "not determined", never "no".** A
    repository whose default branch this platform cannot read has not failed
    the signed-commits check; it has not been checked. Scoring the two the
    same way is how a permissions problem becomes a supply-chain verdict.

    Observations, not a score — the same division spec 07 §7 makes an
    acceptance criterion. The runner reports what it saw; the weighting lives
    in the platform, so it can change without a resync across every onboarded
    repository.
    """

    model_config = ConfigDict(extra="forbid")

    signed_commits_ratio: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description=(
            "Verified signatures as a fraction of commits on the default "
            "branch in the last 90 days. Null where the branch could not be "
            "read."
        ),
    )
    signed_commits_sampled: int = Field(
        default=0,
        ge=0,
        description=(
            "How many commits the ratio is over. A ratio of 1.0 across two "
            "commits is not the same claim as 1.0 across two hundred, and the "
            "term reports the sample so the number can be judged."
        ),
    )
    attestation_present: bool | None = Field(
        default=None,
        description=(
            "Whether a build provenance attestation exists for the published "
            "artefact. Presence only: verifying contents is a larger piece of "
            "work, and the field is named for exactly that reason so a "
            "repository never reads as `attested` on an attestation that does "
            "not verify (spec 29 §5)."
        ),
    )
    digest_pinned_deployment: bool | None = Field(
        default=None,
        description=(
            "Whether the deployed image is pinned by digest rather than by a "
            "tag somebody can move underneath it."
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
    provenance_signals: ProvenanceSignals = Field(
        default_factory=lambda: ProvenanceSignals(),
        description=(
            "How this repository builds (spec 29 §3). Distinct from "
            "`provenance` above, which records *this* build's identity: these "
            "are scored, and every one of them is absent by default so a "
            "repository that reports none scores exactly as it did before "
            "they existed."
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


class ReachabilityAccepted(BaseModel):
    accepted: int
    orphaned: int
    files_analysed: int
    note: str = (
        "Import reachability for Python only, and only 'does anything import "
        "this file' — not whether a function is called (spec 19 §2.1). A file "
        "not listed here is not proven reachable; it is simply not proven "
        "orphaned."
    )


class AtlasAccepted(BaseModel):
    accepted: int
    evidence_id: str
    #: How many resolved components went into the inventory (spec 29 §1).
    #: Zero for a submission carrying no SBOM ref, and for one whose archived
    #: SBOM could not be read — the evidence row is written either way, and
    #: the workflow log says which happened.
    components_recorded: int = 0
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


class NetassessSubmission(BaseModel):
    """One network-assessment run, pushed by the host that produced it
    (spec 32 §4.4).

    **Push rather than pull, and that is the whole design decision.** The scan
    runs on Windows under a Scheduled Task — a container cannot see LAN MAC
    addresses, which is measured rather than assumed — and the publisher that
    archives it to MinIO already runs there. Having the backend poll an object
    store instead would mean an S3 client it does not otherwise need, MinIO
    credentials it does not otherwise hold, and a schedule to guess at when the
    arrival is already an event somebody could just report.

    **Files, not an archive.** Two text files are what the judgement reads; a
    zip would mean unpacking attacker-controlled entries inside the ingestion
    path for no gain. The archive still goes to MinIO, which remains the
    history — this platform stores what it needs to compare against next week.
    """

    model_config = ConfigDict(extra="forbid")

    run_key: str = Field(
        min_length=1,
        max_length=255,
        description="The publisher's object name, e.g. `netassess-2026.8.9.zip`.",
    )
    inventory_csv: str = Field(
        default="",
        max_length=1_000_000,
        description="`inventory.csv` verbatim. Empty means the run enumerated nothing.",
    )
    network_status_md: str = Field(
        default="",
        max_length=1_000_000,
        description="`network-status.md` verbatim. Empty means the scan did not finish.",
    )


class NetassessAccepted(BaseModel):
    believable: bool
    problems: list[str] = Field(default_factory=list)
    host_count: int = 0
    hosts_appeared: list[str] = Field(default_factory=list)
    hosts_disappeared: list[str] = Field(default_factory=list)
    detail: str = ""


class LaneFailure(BaseModel):
    """A CI lane that failed without producing a ScanRun (spec 32 §11 q6).

    Every Concourse job carries `on_failure: *slack_alert`. On Actions most
    lanes need no equivalent, because `mykronos.upload` registers a ScanRun
    before it interprets anything and finalises in a `finally` — so a failed
    scan already reaches Slack through the ingestion path that records it.

    Two cases that path cannot cover, and this exists for both:

    *A lane with nothing to upload.* `delivery.yml` builds, publishes and
    promotes, and produces no findings by design — `ci.py` says its absence
    from the lake is not a fault. A failed build currently tells nobody.

    *A lane that died before its upload step.* A failed checkout or a failing
    fail-fast probe leaves no ScanRun, so the capability reads as never having
    run rather than as having broken.

    **This writes nothing to the lake.** It is a message, not evidence. A
    build failure is not a finding, has no severity, and must not reach a risk
    score — which is the same rule D-046 applies to test lanes, one step
    further out.
    """

    model_config = ConfigDict(extra="forbid")

    lane: str = Field(
        min_length=1,
        max_length=100,
        description="Which lane failed, as a person would name it: `publish`, `promote`.",
    )
    detail: str = Field(
        default="",
        max_length=1_000,
        description="What went wrong, in one or two lines. Rendered verbatim.",
    )
    commit_sha: str = Field(default="", max_length=100)
    run_url: str = Field(
        default="",
        max_length=500,
        description="Where to go and look. The whole point of the message.",
    )

    @field_validator("run_url")
    @classmethod
    def _http_url(cls, value: str) -> str:
        if value and not value.startswith(("http://", "https://")):
            raise ValueError("run_url must be an http(s) URL.")
        return value


class LaneFailureAccepted(BaseModel):
    notified: bool
    detail: str


class HealthResponse(BaseModel):
    status: str
    datalake_writable: bool
    buffered_segments: int
    detail: str = ""
    #: Echoed back so a workflow's pre-scan probe also confirms what this
    #: token is scoped to and currently allowed to write.
    repo_full_name: str = ""
    granted_capabilities: list[str] = Field(default_factory=list)
