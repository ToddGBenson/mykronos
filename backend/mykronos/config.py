"""Runtime configuration.

Every value is overridable by environment variable with the `MYKRONOS_`
prefix. Defaults are the spec's documented defaults, cited inline, so that
drift between spec and behaviour is visible in one file.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="MYKRONOS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    datalake_dir: Path = Field(
        default=Path("datalake"),
        description="Root of the local data lake. spec 05 §2.",
    )

    compaction_interval_seconds: int = Field(
        default=300,
        ge=1,
        description="Buffer -> Parquet compaction cadence. Default 5 min, spec 05 §2.",
    )

    run_compaction_in_background: bool = Field(
        default=True,
        description="Disable in tests so compaction can be driven deterministically.",
    )

    max_findings_per_request: int = Field(
        default=10_000,
        ge=1,
        description="Max batch size. spec 05 §6.",
    )

    rate_limit_requests_per_minute: int = Field(
        default=100,
        ge=1,
        description="Per-token ingestion rate limit. spec 05 §6.",
    )

    database_url: str = Field(
        default="sqlite:///mykronos.db",
        description=(
            "Operational state: onboarding, capability config, ingestion tokens, "
            "audit log. Separate from the data lake by design (D-010)."
        ),
    )

    workflow_templates_dir: Path = Field(
        default_factory=lambda: Path(__file__).resolve().parents[2] / "workflow-templates",
        description=(
            "Template library the installer renders from (spec 03 §2). Lives at the "
            "repo root, not inside the package: templates ship into customer repos "
            "and are versioned independently of the service that renders them."
        ),
    )

    ingestion_api_url: str = Field(
        default="http://localhost:8000",
        description="Base URL rendered into workflow templates so repos can reach us.",
    )

    upload_action_ref: str = Field(
        default="ToddGBenson/mykronos/actions/upload-results@v1",
        description=(
            "Semver-pinned reference to the shared upload composite action "
            "(spec 04 §2). Never a branch: every onboarded repo depends on it."
        ),
    )

    token_overlap_hours: int = Field(
        default=24,
        ge=0,
        description=(
            "Dual-validity window during token rotation. A job that read the old "
            "secret before the swap still completes. spec 05 §4."
        ),
    )

    @property
    def buffer_dir(self) -> Path:
        return self.datalake_dir / "_buffer"

    @property
    def raw_dir(self) -> Path:
        """Archived original tool output. spec 05 §7."""
        return self.datalake_dir / "raw"

    @property
    def catalog_path(self) -> Path:
        return self.datalake_dir / "_manifest.duckdb"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
