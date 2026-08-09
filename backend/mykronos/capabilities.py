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
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from mykronos.adapters.registry import supported_tools
from mykronos.schemas import Capability, Severity

#: Five or six whitespace-separated cron fields. Deliberately shallow: the
#: point is to catch "every day" typed into a cron box, not to reimplement a
#: scheduler.
_CRON = re.compile(r"^\s*(\S+\s+){4,5}\S+\s*$")


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
        return value


class CloudConfig(BaseCapabilityConfig):
    aws_role_arn: str = Field(
        default="",
        max_length=2048,
        description=(
            "Role the scan assumes via OIDC. Mykronos never holds your cloud "
            "credentials (spec 12 §4.3)."
        ),
    )
    aws_region: str = Field(default="us-east-1", max_length=32)

    @field_validator("aws_role_arn")
    @classmethod
    def _arn_shape(cls, value: str) -> str:
        if value and not value.startswith("arn:aws:iam::"):
            raise ValueError(
                f"aws_role_arn must be an IAM role ARN, got {value!r}. "
                "Expected 'arn:aws:iam::<account>:role/<name>'."
            )
        return value


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
