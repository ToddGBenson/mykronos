"""Per-capability configuration schemas (spec 02 §3, spec 04 §5, §7).

Spec 04 §7 is the requirement that shapes this: *"A misconfigured tool fails
onboarding validation at the PATCH step, not silently at workflow run time."*
A typo'd tool name should fail the save, while the admin is looking at the
form — not three hours later as a red pipeline nobody connects to the change
that caused it.

These are Pydantic models rather than hand-written JSON Schema files. Spec 02
§3 asks for JSON Schema validation and that is what this provides — Pydantic
*is* the validator and emits JSON Schema for the UI to render a form from — but
with one definition instead of a schema file and a parser that can disagree.
"""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from mykronos.adapters.registry import supported_tools
from mykronos.schemas import Capability, Severity

#: Five or six whitespace-separated cron fields. Deliberately shallow: the
#: point is to catch "every day" typed into a cron box, not to reimplement a
#: scheduler.
_CRON = re.compile(r"^\s*(\S+\s+){4,5}\S+\s*$")

#: Every string in a capability's config is rendered into a GitHub Actions
#: workflow, and several land unquoted inside `run:` blocks — `tool_version`
#: becomes the tag in `docker run aquasec/trivy:<version>`, `aws_role_arn`
#: becomes a step input. The templates cannot escape their way out of this:
#: Jinja autoescaping is HTML escaping, which would corrupt YAML rather than
#: protect it (`installer/templates.py`). So the boundary is here, on the way
#: in, where the value is still a field somebody typed rather than a line in a
#: file about to be executed on a runner.
#:
#: The reachable path is admin-only, which lowers the severity and does not
#: remove it: an admin token is a credential, and "the attacker had to steal a
#: token first" is a poor last line of defence for arbitrary shell on a runner
#: holding `contents: write` to every onboarded repository.
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")

#: Shell and YAML metacharacters, for the fields that reach a command line.
#: A deny-list would be the wrong shape here — this is an allow-list of what a
#: version tag, an ARN or a path glob legitimately contains.
_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9._:@/+-]*$")

#: Azure subscription and tenant identifiers. A GUID and nothing else — see
#: `CloudConfig._guid_shape` for why this is checked rather than left to
#: `_SAFE_TOKEN`, which would accept a hyphenated string of any shape.
_GUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def _reject_control_characters(value: str, field: str) -> str:
    if _CONTROL_CHARS.search(value):
        raise ValueError(
            f"{field} contains a control character. These are rendered into a "
            "GitHub Actions workflow, where a newline is a new YAML line and "
            "potentially a new step."
        )
    return value


def _require_safe_token(value: str, field: str) -> str:
    _reject_control_characters(value, field)
    if not _SAFE_TOKEN.match(value):
        raise ValueError(
            f"{field} may only contain letters, digits and ._:@/+- — it is "
            "interpolated into a shell command in the generated workflow, so "
            "quotes, spaces and shell metacharacters are refused rather than "
            "escaped."
        )
    return value


class CapabilityConfigError(ValueError):
    """Configuration a human needs to correct before this can be saved."""


class BaseCapabilityConfig(BaseModel):
    """Fields every capability accepts (spec 04 §5)."""

    model_config = ConfigDict(extra="forbid")

    enabled_tool: str | None = Field(
        default=None,
        description="Overrides the capability default. Must have an adapter.",
    )
    tool_version: str | None = Field(
        default=None, max_length=64, description="Pinned tool version."
    )
    severity_threshold: Severity = Field(
        default=Severity.LOW,
        description=(
            "Findings below this are still ingested for trend data — they just "
            "never block (spec 04 §5)."
        ),
    )
    blocking: bool = Field(
        default=False,
        description=(
            "Off by default across every capability, platform-wide. Turning it "
            "on is a per-repo decision (spec 04 §5)."
        ),
    )
    paths_include: list[str] = Field(default_factory=list, max_length=200)
    paths_exclude: list[str] = Field(default_factory=list, max_length=200)
    schedule_cron: str | None = Field(default=None, max_length=120)
    timeout_minutes: int = Field(default=30, ge=1, le=360)

    @field_validator("schedule_cron")
    @classmethod
    def _cron_shape(cls, value: str | None) -> str | None:
        if value and not _CRON.match(value):
            raise ValueError(
                f"{value!r} is not a cron expression. Expected five fields, "
                "e.g. '17 3 * * 1' for 03:17 every Monday."
            )
        return value

    @field_validator("tool_version")
    @classmethod
    def _tool_version_is_a_tag(cls, value: str | None) -> str | None:
        """Interpolated into `docker run image:<version>` in three templates."""
        return None if value is None else _require_safe_token(value, "tool_version")

    @field_validator("paths_include", "paths_exclude")
    @classmethod
    def _paths_are_single_line(cls, value: list[str]) -> list[str]:
        for entry in value:
            _reject_control_characters(entry, "path pattern")
        return value


class SastConfig(BaseCapabilityConfig):
    languages: list[str] = Field(
        default_factory=list,
        max_length=20,
        description="CodeQL language matrix. Auto-detected when empty.",
    )
    queries: str = Field(default="security-extended", max_length=200)


class SecretsConfig(BaseCapabilityConfig):
    """No extra fields. Notably there is no way to disable redaction — see
    the Gitleaks adapter for why that is not configurable."""


class ContainersConfig(BaseCapabilityConfig):
    pass


class IacConfig(BaseCapabilityConfig):
    pass


class DastConfig(BaseCapabilityConfig):
    target_url: str = Field(
        default="",
        max_length=2000,
        description="Deployed environment to probe. DAST cannot run without it.",
    )

    @field_validator("target_url")
    @classmethod
    def _http_url(cls, value: str) -> str:
        if value and not value.startswith(("http://", "https://")):
            raise ValueError(
                f"target_url must be an http(s) URL, got {value!r}. DAST probes a "
                "running service, not a repository path."
            )
        # Rendered as an unquoted `TARGET_URL:` step env value, so a space or a
        # newline here becomes YAML rather than part of the URL.
        return _require_safe_token(value, "target_url")


class CloudConfig(BaseCapabilityConfig):
    """Cloud posture (spec 04 §3, spec 16 §9).

    Two providers, and no field saying which. That is deliberate: the scan runs
    against whichever set of coordinates is populated, so a subscription and an
    account can both be scanned from one repository's config without a third
    setting that can disagree with the other two.

    Nothing here is a credential. The AWS role is assumed via OIDC and the
    Azure principal's secret comes from the runner's credential store — spec 12
    §4.3 keeps cloud credentials out of the platform entirely, and these fields
    are the coordinates a scan needs to know *where* to look, not permission to
    look there.
    """

    aws_role_arn: str = Field(
        default="",
        max_length=2048,
        description=(
            "Role the scan assumes via OIDC. Mykronos never holds your cloud "
            "credentials (spec 12 §4.3)."
        ),
    )
    aws_region: str = Field(default="us-east-1", max_length=32)

    azure_subscription_id: str = Field(
        default="",
        max_length=64,
        description=(
            "Subscription Prowler scans. The service principal's client ID and "
            "secret are supplied by the runner and never stored here."
        ),
    )
    azure_tenant_id: str = Field(
        default="",
        max_length=64,
        description="Directory the service principal authenticates against.",
    )

    @field_validator("azure_subscription_id", "azure_tenant_id")
    @classmethod
    def _guid_shape(cls, value: str, info: Any) -> str:
        """Azure identifiers are GUIDs, and this is the narrowest useful check.

        Both land in a `prowler azure --subscription-ids <value>` command line
        in the generated pipeline, so the same reasoning as `aws_role_arn`
        applies — constrain on the way in rather than escape on the way out.
        A GUID is a stricter allow-list than `_SAFE_TOKEN`, so it is worth
        spending here: there is exactly one shape these can legitimately be.
        """
        if value and not _GUID.match(value):
            raise ValueError(
                f"{info.field_name} must be a GUID, got {value!r}. Azure "
                "subscription and tenant identifiers look like "
                "'00000000-0000-0000-0000-000000000000'."
            )
        return value

    @field_validator("aws_role_arn")
    @classmethod
    def _arn_shape(cls, value: str) -> str:
        if value and not value.startswith("arn:aws:iam::"):
            raise ValueError(
                f"aws_role_arn must be an IAM role ARN, got {value!r}. "
                "Expected 'arn:aws:iam::<account>:role/<name>'."
            )
        # The prefix check alone is not enough: it constrains how the value
        # starts and says nothing about the rest, which is rendered unquoted
        # into both a YAML step input and a `[ -z "..." ]` shell test.
        return _require_safe_token(value, "aws_role_arn")

    @field_validator("aws_region")
    @classmethod
    def _region_shape(cls, value: str) -> str:
        return _require_safe_token(value, "aws_region")


class AegisConfig(BaseCapabilityConfig):
    """Insider-risk gate (spec 06 §5).

    Two fields here carry more weight than their types suggest:
    `ai_classifier_url` is the only setting in the whole platform that causes
    repository content to leave the runner, and `retention_days` is what keeps
    a table of scores about named people from becoming a permanent record.
    """

    sensitive_paths: list[str] = Field(
        default_factory=lambda: [
            "**/auth/**",
            "**/*secret*",
            "**/.github/workflows/**",
            "**/iam/**",
        ],
        max_length=200,
    )

    @field_validator("sensitive_paths")
    @classmethod
    def _sensitive_paths_are_single_line(cls, value: list[str]) -> list[str]:
        """Rendered one per line into the workflow's own YAML list."""
        for entry in value:
            _reject_control_characters(entry, "sensitive path pattern")
        return value
    block_threshold: int = Field(
        default=80,
        ge=1,
        le=100,
        description=(
            "Score at or above which Aegis recommends blocking. No two "
            "signals can reach the default between them, so a block always "
            "requires at least three independent signals agreeing."
        ),
    )
    ai_disclosure_required: bool = Field(default=True)
    ai_classifier_url: str | None = Field(
        default=None,
        max_length=2048,
        description=(
            "Endpoint for the AI-authorship classifier. Null — the default — "
            "disables the signal entirely and no diff leaves the runner. There "
            "is deliberately no default endpoint: a deployment that changed no "
            "configuration must never be shipping its code to a third party "
            "(spec 12 §5.2)."
        ),
    )
    retention_days: int = Field(
        default=90,
        ge=1,
        le=3650,
        description=(
            "How long insider-risk rows are kept before the purge job deletes "
            "them (spec 06 §9). The signal's value is in reviewing the pull "
            "request it is about; after that it is only a record of somebody "
            "having been suspected."
        ),
    )

    @field_validator("ai_classifier_url")
    @classmethod
    def _classifier_url_shape(cls, value: str | None) -> str | None:
        if value and not value.startswith(("http://", "https://")):
            raise ValueError(
                f"ai_classifier_url must be an http(s) URL, got {value!r}. "
                "Leave it unset to disable AI-authorship classification."
            )
        return value


class AtlasConfig(BaseCapabilityConfig):
    """Supply-chain evidence (spec 07 §6)."""

    ecosystems: list[str] = Field(
        default_factory=list,
        max_length=20,
        description="Auto-detected when empty; set to force or limit the scan.",
    )
    sbom_format: str = Field(default="cyclonedx", max_length=32)
    min_trust_score: int = Field(
        default=50,
        ge=0,
        le=100,
        description="With blocking on, a release below this fails its workflow.",
    )

    @field_validator("sbom_format")
    @classmethod
    def _sbom_format_known(cls, value: str) -> str:
        if value not in {"cyclonedx", "spdx"}:
            raise ValueError(
                f"sbom_format must be 'cyclonedx' or 'spdx', got {value!r}."
            )
        return value


class PatchworkConfig(BaseCapabilityConfig):
    """Auto-remediation (spec 08 §5).

    Note what is *absent*: there is no `blocking` field with any meaning here,
    and no auto-merge setting. spec 08 §3 makes that a hard constraint rather
    than a default — Patchwork opens draft pull requests and a human merges
    them, and making that configurable would need a separately-reviewed design
    change, not a config key.
    """

    source_capabilities: list[str] = Field(
        default_factory=lambda: ["sast", "secrets", "containers", "iac"],
        max_length=10,
    )
    min_confidence_to_generate_fix: float = Field(
        default=0.7,
        ge=0.0,
        le=1.0,
        description=(
            "Below this a fix is not opened as a pull request. A "
            "possibly-wrong fix costs more review attention than no fix."
        ),
    )
    max_open_draft_prs_per_repo: int = Field(
        default=10,
        ge=1,
        le=100,
        description=(
            "Backpressure (spec 08 §5). A repository that wakes up to forty "
            "draft pull requests does not triage them, it turns the "
            "capability off."
        ),
    )
    auto_fix_min_severity: Literal["critical", "high", "medium", "low"] = Field(
        default="high",
        description=(
            "Severity floor for the *unprompted* batch sweep (spec 19 §4.5). "
            "`high` is what `classify()` hardcoded before this field existed, "
            "so the default changes nothing. Lower it once the fixer library "
            "covers a repo's medium findings reliably — the per-finding "
            "on-demand fix (spec 18 §7) is unaffected either way; it has "
            "never been severity-gated."
        ),
    )
    fix_generator_url: str | None = Field(
        default=None,
        max_length=2048,
        description=(
            "Endpoint for LLM-assisted fix generation. Null — the default — "
            "restricts Patchwork to its deterministic fixers and sends no "
            "source anywhere (spec 12 §5.2)."
        ),
    )

    @field_validator("fix_generator_url")
    @classmethod
    def _generator_url_shape(cls, value: str | None) -> str | None:
        if value and not value.startswith(("http://", "https://")):
            raise ValueError(
                f"fix_generator_url must be an http(s) URL, got {value!r}. "
                "Leave it unset to use only the deterministic fixers."
            )
        return value


class OracleConfig(BaseCapabilityConfig):
    """Risk gating (spec 09 §6).

    Almost everything about Oracle is global — the weights, the curve, the
    thresholds all live in the versioned policy file, because a per-repo
    scoring rule would make "the same finding scores the same everywhere"
    false and the portfolio incomparable.

    What *is* per-repo is whether a `no_go` fails the check run. That has to
    be settable through the API, and until Phase 6 it was not: Oracle had no
    schema at all, so `PATCH /api/repos/{id}/capabilities` refused any config
    for it and the only way to turn blocking on was to write the row by hand.
    """

    blocking: bool = Field(
        default=False,
        description=(
            "Whether a no_go fails the check run for this repository. Off "
            "platform-wide by default (spec 09 §6) — a red check nobody agreed "
            "to is how a security tool gets switched off in its first week."
        ),
    )


#: Every capability's per-repo configuration.
class NetworkConfig(BaseCapabilityConfig):
    """Network scanning (spec 14 §3).

    This is the only capability whose configuration is an authorization
    decision rather than a preference. Everything else here tunes how a scan
    runs; these fields decide whether it is allowed to run at all, and
    `mykronos.network.resolve` re-checks them immediately before the packets
    rather than trusting that they were valid when saved.

    An empty `cidr_ranges` scans nothing and is the default. A capability that
    starts pointed at something is a capability that scans something nobody
    chose.
    """

    cidr_ranges: list[str] = Field(
        default_factory=list,
        description=(
            "Exactly what may be scanned. No discovery outside these, no "
            "'whatever the host can reach', and no default. Empty scans "
            "nothing and is not an error."
        ),
    )
    authorization_reference: str = Field(
        default="",
        max_length=500,
        description=(
            "Who authorised this and where that is recorded - a ticket, a "
            "change record, a note. Mandatory before any range is scanned, "
            "and carried onto the audit record for every run, because 'who "
            "said this was allowed' is the first question asked afterwards "
            "and the hardest to reconstruct later."
        ),
    )
    external_scan_acknowledged: bool = Field(
        default=False,
        description=(
            "Required before any range outside RFC1918/RFC4193/loopback is "
            "scanned. A deliberate speed bump against the most likely serious "
            "mistake: 192.168.0.0/16 is a home lab and 192.169.0.0/16 is "
            "somebody else's network."
        ),
    )
    max_rate_pps: int = Field(
        default=100,
        ge=1,
        le=10_000,
        description=(
            "Packet rate ceiling, well below tool maximums. A security tool "
            "that knocks a device over has caused an incident, not prevented "
            "one (spec 14 §3.6)."
        ),
    )


class UnitConfig(BaseCapabilityConfig):
    """The repository's own unit suite (D-046).

    No tool field: a repository's test runner is decided by its language and
    its own conventions, not by this platform. What Mykronos records is that
    the suite ran, how it ended, and how many cases failed.
    """

    fail_build_on_failure: bool = Field(
        default=True,
        description=(
            "Whether a failing suite stops the pipeline. Separate from any "
            "risk score - a failing test is a reason not to ship, which the "
            "pipeline enforces, and not a reason to call the repository more "
            "dangerous (D-046)."
        ),
    )


class FunctionalConfig(BaseCapabilityConfig):
    """Functional tests against a deployed lower environment (D-046, PIP-2).

    The traffic these generate is the input to proxy-first DAST: functional
    tests already know how to log in and drive multi-step flows, which is the
    surface a spider starting at the login page never reaches.
    """

    target_environment: str = Field(
        default="demo",
        max_length=100,
        description=(
            "Which environment the suite runs against. Never production: the "
            "DAST lane that consumes this traffic sends attack requests, and "
            "an active scan writes data."
        ),
    )
    proxy_through_dast: bool = Field(
        default=True,
        description=(
            "Route the suite's HTTP through the DAST proxy so ZAP records an "
            "authenticated request corpus before it spiders (PIP-3). Turning "
            "this off does not break the functional run; it reduces DAST to "
            "what an unauthenticated crawl can find."
        ),
    )
    fail_build_on_failure: bool = Field(default=True)


class QaConfig(BaseCapabilityConfig):
    """Repository quality checks (D-046, spec 15 §1).

    The checks themselves belong to the repository - link integrity here,
    contract or schema checks elsewhere. Mykronos records that they ran and
    how they ended, and nothing about what they are.

    Produces no findings, for the same reason unit and functional do not: a
    broken documentation link is a defect and is not a vulnerability, and
    giving it a severity would put documentation drift into a security risk
    score.
    """

    fail_build_on_failure: bool = Field(
        default=True,
        description=(
            "Whether a failing QA check stops the pipeline. Separate from any "
            "risk score - the pipeline enforces quality, and the score stays "
            "about risk (D-046)."
        ),
    )


class AiConfig(BaseCapabilityConfig):
    """AI supply-chain and prompt-safety checks (D-047).

    Unlike unit, functional and QA this produces findings. A prompt injection
    that succeeds is a vulnerability, and an unpinned model is a supply-chain
    fact of the same kind as an unpinned dependency - both have a location, a
    severity meaning what it means everywhere else, and something to fix.
    """

    require_pinned_models: bool = Field(
        default=True,
        description=(
            "Report a model identifier with no version or date. The vendor "
            "moves these aliases, so the model a repository was evaluated "
            "against is not necessarily the one it ships."
        ),
    )
    require_evaluation_suite: bool = Field(
        default=True,
        description=(
            "Report a repository that calls a model and has no evaluation "
            "suite. A regression in an AI feature is silent by default, "
            "because it still returns something."
        ),
    )


CONFIG_MODELS: dict[str, type[BaseCapabilityConfig]] = {
    Capability.SAST.value: SastConfig,
    Capability.SECRETS.value: SecretsConfig,
    Capability.CONTAINERS.value: ContainersConfig,
    Capability.IAC.value: IacConfig,
    Capability.DAST.value: DastConfig,
    Capability.CLOUD.value: CloudConfig,
    Capability.AEGIS.value: AegisConfig,
    Capability.ATLAS.value: AtlasConfig,
    Capability.PATCHWORK.value: PatchworkConfig,
    Capability.ORACLE.value: OracleConfig,
    Capability.NETWORK.value: NetworkConfig,
    Capability.UNIT.value: UnitConfig,
    Capability.FUNCTIONAL.value: FunctionalConfig,
    Capability.QA.value: QaConfig,
    Capability.AI.value: AiConfig,
}


def configurable_capabilities() -> list[str]:
    return sorted(CONFIG_MODELS)


def config_schema(capability: str) -> dict[str, Any]:
    """JSON Schema for a capability's config, for the UI to render a form."""
    model = CONFIG_MODELS.get(capability)
    if model is None:
        raise CapabilityConfigError(
            f"'{capability}' has no configuration schema yet. Configurable: "
            f"{', '.join(configurable_capabilities())}."
        )
    schema = model.model_json_schema()
    schema["title"] = f"{capability} configuration"
    # The UI needs the valid tool list, and it is derived from the adapter
    # registry rather than duplicated here — one place decides what is
    # supported.
    tools = supported_tools(capability)
    if tools:
        schema.setdefault("properties", {}).setdefault("enabled_tool", {})["enum"] = tools
    return schema


def validate_config(capability: str, config: dict[str, Any]) -> dict[str, Any]:
    """Validate and normalise one capability's config block.

    Returns the normalised config (defaults applied) or raises
    `CapabilityConfigError` with a message aimed at the person who typed it.
    """
    model = CONFIG_MODELS.get(capability)
    if model is None:
        raise CapabilityConfigError(
            f"'{capability}' does not accept configuration yet. Configurable "
            f"capabilities: {', '.join(configurable_capabilities())}."
        )

    try:
        parsed = model.model_validate(config)
    except ValidationError as exc:
        raise CapabilityConfigError(_readable(capability, exc)) from exc

    tool = parsed.enabled_tool
    if tool is not None:
        allowed = supported_tools(capability)
        if tool not in allowed:
            # spec 04 §7 in one check: this is the failure that would
            # otherwise surface as a broken workflow hours later.
            raise CapabilityConfigError(
                f"'{tool}' is not a supported tool for {capability}. "
                f"Supported: {', '.join(allowed) or 'none'}."
            )

    return parsed.model_dump(mode="json", exclude_none=True)


def _readable(capability: str, exc: ValidationError) -> str:
    """Turn Pydantic's structure into something a person can act on."""
    parts: list[str] = []
    for error in exc.errors():
        field = ".".join(str(loc) for loc in error["loc"]) or "(root)"
        message = error["msg"].removeprefix("Value error, ")
        if error["type"] == "extra_forbidden":
            message = (
                "not a recognised setting for this capability. Check the "
                "spelling, or see GET /api/capabilities for the accepted fields."
            )
        parts.append(f"{field}: {message}")
    return f"Invalid {capability} configuration — " + "; ".join(parts)
