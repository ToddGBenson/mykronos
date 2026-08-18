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

    max_raw_output_bytes: int = Field(
        default=50 * 1024 * 1024,
        ge=1,
        description=(
            "Ceiling on an archived raw tool output file (spec 05 §7). Exceeding it "
            "rejects only the archive copy; normalized findings are unaffected."
        ),
    )

    # --- Scheduled jobs -----------------------------------------------

    token_rotation_interval_seconds: int = Field(
        default=86_400,
        ge=1,
        description="Token rotation sweep. Daily is ample for a 90-day cycle.",
    )

    installation_sync_interval_seconds: int = Field(
        default=86_400,
        ge=1,
        description=(
            "Installation reconciliation (spec 02 §5.6). Daily, which is what "
            "spec 02 §8's 24-hour allowance implies."
        ),
    )

    absence_reconcile_interval_seconds: int = Field(
        default=3_600,
        ge=1,
        description=(
            "Sweep for findings absent from consecutive scans (spec 05 §5). "
            "Hourly: it only acts once two qualifying scans have run, so a "
            "shorter interval changes nothing."
        ),
    )

    portfolio_scoring_interval_seconds: int = Field(
        default=86_400,
        ge=1,
        description=(
            "Standing risk decision per Oracle-enabled repo (spec 09 §5). "
            "Daily: the inputs that move without a push — finding age, new "
            "advisories — move on the scale of days, and a portfolio score "
            "that churns hourly is one nobody trusts as a trend."
        ),
    )

    insider_risk_purge_interval_seconds: int = Field(
        default=86_400,
        ge=1,
        description=(
            "Retention sweep for insider-risk rows (spec 06 §9). Daily, "
            "matching the granularity of the retention window itself. This is "
            "the job that makes the retention policy real rather than stated."
        ),
    )

    threat_intel_refresh_interval_seconds: int = Field(
        default=86_400,
        ge=1,
        description=(
            "CISA KEV / FIRST EPSS refresh (spec 17 §4.3). Daily, matching "
            "both feeds' own publication cadence — a shorter interval would "
            "poll a source that has not changed."
        ),
    )

    insider_risk_default_retention_days: int = Field(
        default=90,
        ge=1,
        le=3650,
        description=(
            "Applied to any repo whose Aegis config does not set its own, and "
            "to rows whose repo has been offboarded. The absence of a setting "
            "is not consent to keep the data forever."
        ),
    )

    knowledge_half_life_days: int = Field(
        default=180,
        ge=1,
        description=(
            "Confidence half-life for Knowledge Store entries (spec 11 §5). "
            "An entry nobody reconfirms in this window is worth about half "
            "what it was, which is what stops a two-year-old opinion carrying "
            "the same weight as last week's."
        ),
    )

    stale_draft_sweep_interval_seconds: int = Field(
        default=21_600,
        ge=1,
        description=(
            "How often to close draft fixes whose finding is no longer open "
            "(spec 08 §8). Every six hours: a stale draft is a small "
            "annoyance that becomes a large one when there are nine of them, "
            "and closing is cheap."
        ),
    )

    run_jobs_in_background: bool = Field(
        default=True,
        description="Disable so tests and one-shot CLI runs drive jobs explicitly.",
    )

    # --- GitHub App (spec 02 §4) -------------------------------------

    github_app_id: str = Field(
        default="",
        description="Registered App's ID. Empty means GitHub calls are faked.",
    )

    github_app_private_key_path: Path | None = Field(
        default=None,
        description=(
            "PEM holding the App private key. The only long-lived secret in the "
            "system (spec 12 §2) -- never the database, never a log, never a repo."
        ),
    )

    github_fake_seed_repos: list[str] = Field(
        default_factory=list,
        description=(
            "Repos to pre-register in the in-memory GitHub, so the installer "
            "has something to act on before a real App exists. Ignored entirely "
            "once github_app_id is set -- it cannot mask a real 'repo not "
            "found', because with real credentials the fake is not used at all."
        ),
    )

    github_webhook_secret: str = Field(
        default="",
        description=(
            "Shared secret for X-Hub-Signature-256. Empty means webhooks are "
            "rejected: without it there is no way to tell GitHub from anyone who "
            "found the URL."
        ),
    )

    # --- Admin API (spec 12 §3, Phase 1 stub) --------------------------

    admin_token: str = Field(
        default="",
        description=(
            "Bearer token for the admin API. Empty disables the API entirely "
            "(503), so an unconfigured deployment is unusable rather than open. "
            "Replaced by SSO in Phase 7."
        ),
    )

    admin_identity: str = Field(
        default="admin",
        description="Actor name recorded in the audit log for admin actions.",
    )

    viewer_token: str = Field(
        default="",
        description=(
            "Read-only token. Viewers see findings but never raw tool output "
            "(spec 12 §5). Empty means no viewer access exists at all."
        ),
    )

    viewer_identity: str = Field(default="viewer", description="Audit-log actor name.")

    gate_token: str = Field(
        default="",
        description=(
            "Perimeter token for the whole host, presented as X-Hub-Token, a "
            "hub_token cookie, or ?_token= — the same scheme and the same "
            "value as the Hub's HUB_API_TOKEN, so one credential opens both. "
            "Empty disables the gate, which is correct on a laptop and wrong "
            "the moment this is reachable from the internet. It is a "
            "perimeter, not an authorisation model: admin and viewer are "
            "still decided by the tokens above."
        ),
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

    oracle_policy_path: Path = Field(
        default_factory=lambda: Path(__file__).resolve().parents[2] / "oracle-policy-v1.yaml",
        description=(
            "Versioned scoring policy (spec 09 §5). Lives at the repo root so it "
            "is reviewed as configuration in a pull request, not edited in a "
            "database."
        ),
    )

    mykronos_package_spec: str = Field(
        default=(
            "mykronos @ git+https://github.com/ToddGBenson/mykronos"
            "@v1#subdirectory=backend"
        ),
        description=(
            "pip requirement the Aegis and Atlas workflows install to get the "
            "signal collectors and adapters (spec 04 §4). Pinned to a tag for "
            "the same reason the upload action is: every onboarded repo "
            "depends on it, so it must never resolve to a moving branch."
        ),
    )

    github_bot_logins: list[str] = Field(
        default_factory=list,
        description=(
            "Commit author names that are Patchwork's own, used to tell its "
            "commits from a person's (spec 08 §3). Usually one entry: "
            "'<app-slug>[bot]'. "
            "Empty means nothing is recognised as ours, so every fix branch "
            "reads as human-edited and Patchwork stops refreshing it — which "
            "is the correct direction to be wrong in. A stale draft costs one "
            "unrefreshed fix; the opposite mistake overwrites somebody's "
            "commit."
        ),
    )

    maturity_model_path: Path = Field(
        default_factory=lambda: Path(__file__).resolve().parents[2] / "maturity-model-v1.yaml",
        description=(
            "Versioned maturity tiers (spec 10 §2.3). At the repository root "
            "beside the Oracle policy, for the same reason: a definition of "
            "'good' that can be edited in a database is one nobody can audit."
        ),
    )

    ingestion_api_url: str = Field(
        default="http://localhost:8100",
        description=(
            "Base URL rendered into workflow templates so repos can reach us. "
            "8100 rather than 8000 because the Hub already holds 8000 on the "
            "host this runs on. Must be publicly resolvable in any real "
            "deployment: GitHub-hosted runners POST findings to it, and "
            "unlike the webhook there is no fallback path if they cannot."
        ),
    )

    # --- Concourse (spec 15 §4a) ---------------------------------------

    concourse_url: str = Field(
        default="",
        description=(
            "Where this process reaches Concourse's API. Empty disables the "
            "integration, which is the right state for a deployment that has "
            "no Concourse -- the dashboard then says a repository has no "
            "pipeline rather than failing to ask."
        ),
    )

    concourse_external_url: str = Field(
        default="",
        description=(
            "Where a *browser* reaches Concourse, for the links the dashboard "
            "renders. Separate from concourse_url because they genuinely "
            "differ: this process reaches it by container name on a shared "
            "Docker network, and a person reaches it on localhost. Falls back "
            "to concourse_url when unset."
        ),
    )

    concourse_team: str = Field(
        default="main",
        description="Concourse team whose pipelines cover these repositories.",
    )

    concourse_api_token: str = Field(
        default="",
        description=(
            "Bearer token for triggering a Concourse build on demand (spec "
            "17 §2.5) — a write, unlike every anonymous read `ConcourseClient` "
            "otherwise makes (spec 15 §4a). Empty disables on-demand dispatch "
            "for Concourse-scanned repos; the read-only pipeline-status "
            "panel is unaffected. Sourced from the credential manager spec "
            "15 §6 already calls for, not hand-typed into a config file."
        ),
    )

    upload_action_ref: str = Field(
        default=(
            "ToddGBenson/mykronos/actions/upload-results@"
            "8b329fc5c1f739eab8ad40b8a7628da7cd1ee935"  # v1
        ),
        description=(
            "Commit-pinned reference to the shared upload composite action "
            "(spec 04 §2). A SHA, not a tag and never a branch. This is the "
            "ONE action that runs in every onboarded repository, with that "
            "repo's checkout on disk and its ingestion token in the "
            "environment — so it is the highest-value ref to hold immutable, "
            "not the one to exempt.\n\n"
            "The `mykronos-ref` input is derived from the part after `@`, so "
            "pinning here also pins the package the action installs; the two "
            "cannot drift.\n\n"
            "WHEN UPDATING: v1 is an ANNOTATED tag, so the tag-object SHA "
            "(926d214…) is NOT the commit. Dereference it — "
            "`gh api repos/ToddGBenson/mykronos/commits/v1 --jq .sha` — or you "
            "pin a valid-looking 40-char ref that never resolves as a commit."
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

    # --- Notification (spec 16 §14) ------------------------------------

    slack_webhook_url: str = Field(
        default="",
        description=(
            "Slack incoming webhook for the events in `mykronos.notify`. Empty "
            "— the default — disables notification entirely and nothing is "
            "posted anywhere. There is deliberately no default endpoint: a "
            "deployment that changed no configuration must not be sending its "
            "findings to a chat service (the rule spec 12 §5.2 applies to the "
            "AI classifier, for the same reason)."
        ),
    )

    slack_notify_min_severity: str = Field(
        default="high",
        pattern="^(critical|high|medium|low|info)$",
        description=(
            "Findings at or above this cause one summary message per ingested "
            "batch. Not per finding: a scan uploading four hundred criticals "
            "is one event a person needs to know about. Set to 'critical' if "
            "'high' proves too noisy — the failure mode of an alert channel is "
            "that people stop reading it, which costs more than it saves."
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
