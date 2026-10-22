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

    # --- Build provenance (#361) ---------------------------------------

    build_sha: str = Field(
        default="",
        description=(
            "The commit this image was built from, baked in by the Dockerfile "
            "at image build time and read back by `/healthz` for a caller "
            "presenting the perimeter token (D-157). Empty is a real "
            "and expected state -- a local `docker build`, an editable "
            "install, or the test suite -- and it must be reported as "
            "unknown rather than filled in with a guess. Nothing here may "
            "fall back to reading the working tree: the whole point is to "
            "describe the artifact that is *running*, and a running container "
            "has no working tree to consult. `mykronos.__version__` cannot "
            "serve this purpose. The pipeline's `build` job renames its wheel "
            "to carry `+<short-sha>`, but a wheel's version lives in its "
            "METADATA rather than its filename, and the image is built from a "
            "*separate* wheel that `backend/Dockerfile` compiles itself -- so "
            "the stamped artifact never reaches production and every "
            "deployment reports 0.1.0."
        ),
    )

    deployment_probe_interval_seconds: int = Field(
        default=1_800,
        ge=1,
        description=(
            "How often to ask each configured deployment what revision it is "
            "running (#361). Half-hourly, matching `fix_verification`: the "
            "question is whether a merge has reached production, and the "
            "interesting window is the one just after a deploy. Cheap enough "
            "to run at that rate -- one GET and one GitHub compare per "
            "repository. Also the age limit of the cached 'N commits behind' "
            "answer the briefing and dashboard read (#452)."
        ),
    )

    deployment_probe_timeout_seconds: float = Field(
        default=10.0,
        gt=0,
        description=(
            "Per-probe budget. Sized for a host that accepts the connection "
            "and then stalls, which is the failure that would otherwise hold "
            "the whole sweep open; a healthy probe answers in well under a "
            "second."
        ),
    )

    deployment_probe_tokens: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Which perimeter token the deployment probe presents, per origin "
            "(#452). A JSON object from `scheme://host[:port]` to a token, "
            "sent as `X-Hub-Token`, e.g. "
            '`{"http://mykronos-backend:8000": "@gate", '
            '"http://thehub-backend:8000": "@hub"}`. `@gate` means '
            "MYKRONOS_GATE_TOKEN and `@hub` means MYKRONOS_HUB_API_TOKEN, so "
            "neither secret is written down twice; anything else is the token "
            "itself. mykronos's `/healthz` and TheHub's `/health` serve "
            "`build.sha` only to a caller presenting their perimeter token "
            "(D-157, TheHub #60709), so without an entry the probe reads "
            "`unparsed` and production lag is unknown. Keyed by origin, never "
            "sent to an origin not listed: the two hosts' tokens differ (D-131), "
            "and a probe URL is admin-editable, so a single global token would "
            "hand whichever secret it is to whatever host the URL names. "
            "Redirects are not followed, for the same reason."
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

    carry_forward_interval_seconds: int = Field(
        default=3_600,
        ge=1,
        description=(
            "Link findings whose matched code changed to their replacements "
            "(spec 05 §5b). Hourly, alongside absence reconciliation: it only "
            "acts once a lane has scanned again, so running it more often "
            "changes nothing."
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

    weekly_digest_interval_seconds: int = Field(
        default=604_800,
        ge=1,
        description=(
            "The per-owner worklist digest (spec 27 §4). Weekly, matching what "
            "it is: a digest that arrived daily would be a notification, and a "
            "notification people receive daily about work that moves weekly is "
            "one they filter."
        ),
    )

    digest_enabled: bool = Field(
        default=False,
        description=(
            "Off unless a deployment opts in: this one messages people, and "
            "doing that the moment the platform is upgraded is not its "
            "decision to make."
        ),
    )

    auto_triage_interval_seconds: int = Field(
        default=3_600,
        ge=1,
        description=(
            "Runs the deterministic auto-triage lanes (TheHub #60888). Hourly: "
            "the evidence they read - verified fixes, VEX statements, a person's "
            "verdict on a duplicate, the import graph - changes at that pace, "
            "and each action is undoable whenever it lands."
        ),
    )

    fix_verification_interval_seconds: int = Field(
        default=1_800,
        ge=1,
        description=(
            "Dispatches a scan of each landed fix's merge commit and reads "
            "the verdict (spec 25 §1). Half-hourly: the dispatch should follow "
            "the merge closely enough to be about that change, and the "
            "resolver needs to run often enough to catch a scan that lands "
            "minutes later."
        ),
    )

    acceptance_sweep_interval_seconds: int = Field(
        default=86_400,
        ge=1,
        description=(
            "Expires acceptances past their review date and re-opens any "
            "accepted as 'no vendor fix' once a scan reports one (spec 24 §3). "
            "Daily, because `accepted_until` is a date — a shorter interval "
            "would re-read the same day repeatedly."
        ),
    )

    premise_monitor_interval_seconds: int = Field(
        default=86_400,
        ge=60,
        description=(
            "Re-evaluates every live risk acceptance's premises against fresh "
            "control observations and EPSS (spec 33 §4.2: daily, and after "
            "every observation ingest and threat-intel refresh)."
        ),
    )

    premise_fresh_days: int = Field(
        default=14,
        ge=1,
        le=90,
        description=(
            "How old an observation or EPSS score may be and still decide a "
            "premise. Older evidence leaves the premise `unverified`, never "
            "`holds` (the S5 rule, observation fresh <= 14 days)."
        ),
    )

    governance_sweep_interval_seconds: int = Field(
        default=21_600,
        ge=1,
        description=(
            "Re-reads every onboarded repository's change controls and records "
            "any that moved (spec 30). Six-hourly: a control coming off is a "
            "security regression somebody made deliberately, and detection "
            "that waits a day is detection somebody else finds first. Also "
            "what keeps the stored posture inside the 14-day staleness window "
            "Oracle scores against, which until now depended on a person "
            "opening the panel."
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
            "hub_token cookie, or ?_token= — the same scheme as the Hub's "
            "HUB_API_TOKEN but a different value (D-131; see `hub_api_token`). "
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

    approval_policy_path: Path = Field(
        default_factory=lambda: Path(__file__).resolve().parents[2] / "approval-policy-v1.yaml",
        description=(
            "Who may approve which governed actions (spec 34 §3). At the repo root "
            "and reviewed in a pull request, like the Oracle policy."
        ),
    )

    agent_playbooks_path: Path = Field(
        default_factory=lambda: Path(__file__).resolve().parents[2] / "agent-playbooks-v1.yaml",
        description=(
            "How an agent works each kind of item on its queue (spec 36 §5). At "
            "the repo root and reviewed in a pull request like the approval "
            "policy. A setting rather than a module-relative path for the reason "
            "`governance_policy_path` gives: from an installed wheel that path is "
            "the standard library, not the repository."
        ),
    )

    reviewer_model: str = Field(
        default="claude-opus-5-5",
        description=(
            "The model the platform-started independent reviewer runs (spec 34 §4.3). "
            "Recorded as the reviewer's family, so a delegation must name it. An "
            "exact model id, never a family alias: the reviewer's shadow-agreement "
            "numbers only compare against a fixed model, and moving it is a "
            "reviewed change (D-167)."
        ),
    )
    threat_model_sync_interval_seconds: int = Field(
        default=21_600,
        ge=300,
        description=(
            "How often every onboarded repository's `.sdlc/threat-model.yaml` "
            "is re-read and its rows synced (TheHub #60825, spec 28 §8). Six "
            "hours, like governance: the file changes by pull request, and "
            "`POST /repos/{id}/threat-model/sync` re-reads one on demand."
        ),
    )
    environment_rescore_interval_seconds: int = Field(
        default=86_400,
        ge=300,
        description=(
            "How often every repository's environmental CVSS scores are "
            "re-resolved from scratch (TheHub #60827). Daily, and required: the "
            "event triggers cover writes, but only a timed run notices a fact "
            "that lapsed, and a lapsed lowering fact must raise the score back."
        ),
    )
    exposure_probe_interval_seconds: int = Field(
        default=21_600,
        ge=300,
        description=(
            "How often every registered public endpoint is probed anonymously "
            "(mykronos.exposure). Six hours: exposure changes when somebody edits "
            "a tunnel or a gate, not by the minute."
        ),
    )
    reviewer_mode: str = Field(
        default="shadow",
        pattern="^(off|shadow|live)$",
        description=(
            "How the independent reviewer's verdicts count (spec 34 §4.3). `shadow` "
            "(default): it reviews pending requests and its verdict is recorded "
            "beside the request but never counts - the person still decides. "
            "`live`: its verdict goes through the approval engine and counts where "
            "a delegation allows. `off`: it never runs."
        ),
    )
    shadow_review_interval_seconds: int = Field(
        default=600,
        ge=60,
        description="How often shadow mode looks for pending requests to review.",
    )
    shadow_reviews_per_run: int = Field(
        default=3,
        ge=0,
        le=20,
        description=(
            "Reviews per shadow run. Each one is a paid model call, so a backlog "
            "drains over several runs instead of in one burst."
        ),
    )
    reviewer_api_key: str = Field(
        default="",
        repr=False,
        description=(
            "Anthropic API key for the independent reviewer. Empty falls back to "
            "ANTHROPIC_API_KEY; with neither, reviews are refused and requests wait "
            "for a person."
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
            "@8e2e41261b9f3695a1ab3616be2db7d8095cd486"  # v14
            "#subdirectory=backend"
        ),
        description=(
            "pip requirement the Aegis, Atlas, AI and SAST workflows install "
            "to get the signal collectors and adapters (spec 04 §4). Pinned "
            "to a tag for the same reason the upload action is: every "
            "onboarded repo depends on it, so it must never resolve to a "
            "moving branch. "
            "This sat at `v1` while the pipelines had moved to `v7` and the "
            "tag series had reached `v7` - the second half of D-051, in a "
            "setting nobody thought to look at. The cost was specific: the "
            "four templates that install this do so BEFORE the upload action "
            "runs, and `pip install` of an already-present package is a "
            "no-op, so a `v1` install here silently downgraded the uploader "
            "the action had been pinned to. `ai` and `atlas` then died on "
            "`--capability: invalid choice` - two capabilities that did not "
            "exist in v1 - while `sast` and `aegis` survived because v1 "
            "happened to know them. "
            "Keep this and `upload_action_ref` on the same tag. They install "
            "the same package into the same job, and the first one wins."
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

    governance_policy_path: Path = Field(
        default_factory=lambda: Path(__file__).resolve().parents[2]
        / "governance-policy-v1.yaml",
        description=(
            "Per-control governance weights (spec 30 §3). A setting rather "
            "than a bare module-relative path, and the distinction is not "
            "cosmetic: `Path(__file__).parents[2]` is the repository root "
            "from a checkout and `/usr/local/lib/python3.13` from an "
            "installed wheel. The deployed backend therefore looked for this "
            "beside the standard library, did not find it, logged "
            "'no score computed' at WARNING, and returned an empty weight "
            "table - so every governance score in production was computed "
            "from nothing while every test computed one correctly. Same "
            "shape as D-052: right in every checkout, wrong in every "
            "deployment, and quiet in both."
        ),
    )

    stride_map_path: Path = Field(
        default_factory=lambda: Path(__file__).resolve().parents[2]
        / "stride-map-v1.yaml",
        description=(
            "CWE-to-STRIDE taxonomy (spec 28 §2). Same packaging trap as "
            "`governance_policy_path`, and softer consequences by design - "
            "its loader treats absence as a real state rather than an error - "
            "but it was absent for the same wrong reason rather than the "
            "intended one."
        ),
    )

    environment_map_path: Path = Field(
        default_factory=lambda: Path(__file__).resolve().parents[2]
        / "environment-map-v1.yaml",
        description=(
            "Environmental CVSS mapping judgements (TheHub #60827): which "
            "statement about the system maps to which CVSS 3.1 metric, and how "
            "long a fact counts. Reviewed as governance policy, like the STRIDE "
            "map; the same packaging trap as `stride_map_path`."
        ),
    )

    cwe_vector_templates_path: Path = Field(
        default_factory=lambda: Path(__file__).resolve().parents[2]
        / "cwe-vector-templates-v1.yaml",
        description=(
            "CWE-class CVSS 3.1 base vectors that pre-fill an analyst's "
            "rule-vector proposal (TheHub #60832). They propose and never "
            "score: only a vector a person confirmed is used. Reviewed as "
            "governance policy; the same packaging trap as `stride_map_path`."
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

    ci_status_cache_seconds: float = Field(
        default=60.0,
        description=(
            "How long a GitHub Actions status read is reused before asking "
            "again (spec 32 §7.1). Reading Actions spends the installation's "
            "rate limit, which token rotation, the installer and Patchwork "
            "all share and all need more than a status panel does. Successes "
            "only are cached, so an outage is retried rather than pinned. "
            "Zero disables reuse, which is honest for a test and wasteful in "
            "a deployment."
        ),
    )

    vault_url: str = Field(
        default="",
        description=(
            "Where this process reaches Vault, for `mykronos self-check` "
            "(spec 32 §8.1). Read-only and unauthenticated: `/v1/sys/health` "
            "needs no token and reports whether Vault is sealed, which is the "
            "state that matters — it comes back sealed after every restart, "
            "and until somebody unseals it Concourse cannot resolve any "
            "`((var))`. Empty disables the check, which is right for a "
            "deployment with no Vault."
        ),
    )

    # --- Patchwork's image registry -----------------------------------

    patchwork_image_registry: str = Field(
        default="",
        description=(
            "Base URL of the image registry the image-refresh lanes publish "
            "patched `-p<YYYYMMDD>` images to, which Patchwork's "
            "bump-image-date fixer lists tags on (`GET /v2/<name>/tags/list`, "
            "anonymous and read-only). Plain HTTP is expected: the lanes reach "
            "the same registry with `--insecure`. Empty disables the fixer, "
            "and every patched-image finding then records that no registry is "
            "configured rather than that no newer snapshot exists."
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

    timeout_audit_interval_seconds: int = Field(
        default=86_400,
        ge=3_600,
        description=(
            "How often the pipeline timeout audit (mykronos.timeout_audit) reads "
            "live Concourse history and raises any cap that sits too close to "
            "its job's observed worst run (TheHub #60729). Daily: a cap goes "
            "tight over weeks of slower builds, not by the hour. Scheduled only "
            "when concourse_url is set."
        ),
    )

    gate_liveness_interval_seconds: int = Field(
        default=3_600,
        ge=600,
        description=(
            "How often the gate-liveness check (mykronos.gate_liveness) asks "
            "whether main's commits are still reaching a risk decision, and "
            "names the red lane upstream of oracle-gate when they are not "
            "(TheHub #60731). Scheduled only when concourse_url is set."
        ),
    )

    gate_liveness_stale_hours: float = Field(
        default=6.0,
        gt=0,
        description=(
            "How long the oldest commit after the last decided one may wait "
            "for a gate decision before gate-liveness raises it. The gate "
            "answers about 30 minutes after Delivery, so six hours is many "
            "missed runs, not one slow one."
        ),
    )

    dormant_lanes_interval_seconds: int = Field(
        default=3_600,
        ge=600,
        description=(
            "How often the dormant-lanes job (mykronos.dormant_lanes) checks "
            "whether today's notice has gone out. It posts at most once per "
            "UTC day: the first run of the day that reads Concourse sends it "
            "and later runs skip, restarts included. Hourly so an unreadable "
            "Concourse is retried within the day. Scheduled only when "
            "concourse_url is set."
        ),
    )

    dormant_lanes_threshold_hours: float = Field(
        default=72.0,
        gt=0,
        description=(
            "How long a Concourse job may be paused, or red on its last "
            "build, before the daily dormant-lanes notice lists it."
        ),
    )

    pipeline_definitions_dir: Path = Field(
        default_factory=lambda: Path(__file__).resolve().parents[2]
        / "deploy" / "concourse" / "pipelines",
        description=(
            "The committed Concourse pipeline files whose task caps the timeout "
            "audit grades. Read from disk because Concourse refuses an "
            "anonymous read of a pipeline's config (HTTP 401). The image copies "
            "them in; an empty or missing directory is reported as "
            "'could not audit', never as clean."
        ),
    )

    # --- TheHub, the system of record for work items (spec 35, D-133) ----

    hub_api_url: str = Field(
        default="http://host.docker.internal:8000",
        description=(
            "Where this process reaches TheHub's API, for the Product Owner "
            "tab's backlog and sprint (spec 35 §4.1). Empty disables the "
            "integration: the tab then says TheHub is not connected and shows "
            "the repository's declared process only."
        ),
    )

    hub_api_token: str = Field(
        default="",
        description=(
            "TheHub's own HUB_API_TOKEN, sent as X-Hub-Token. Not gate_token: "
            "spec 35 §4.1 assumed the two were one value, and D-131 records "
            "that they are not (checked 2026-10-08) -- so reusing gate_token "
            "would be refused by the Hub and would hand Mykronos's perimeter "
            "secret to another service. Empty disables the integration."
        ),
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
            "8e2e41261b9f3695a1ab3616be2db7d8095cd486"  # v14
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
            "This pin was stale, and stale in exactly the way D-051 "
            "describes. It named a commit whose `Capability` enum predates "
            "the quality stages, so `qa`, `unit`, `functional` and `ai` "
            "uploads died on `--capability: invalid choice` after the scan "
            "had already run — four capabilities the platform believed were "
            "enabled and which could never report. Worse, the commit it named "
            "carried a `# v1` comment and is not v1: it is untagged, so the "
            "comment described a pin nobody could verify by looking.\n\n"
            "WHEN UPDATING: v1 is an ANNOTATED tag, so the tag-object SHA "
            "(926d214…) is NOT the commit. Dereference it — "
            "`gh api repos/ToddGBenson/mykronos/commits/v1 --jq .sha` — or you "
            "pin a valid-looking 40-char ref that never resolves as a commit.\n\n"
            "It went stale a third way (#337): Concourse moved to v14 while "
            "this stayed on v8, which has no ShellCheck or PSScriptAnalyzer "
            "adapter, so the `sast-shell` and `sast-powershell` workflows "
            "failed at upload. `scripts/check_pinned_ref.py` now reads this "
            "commit's adapter registry and fails if any template's "
            "(capability, tool) is missing from it."
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

    slack_bot_token: str = Field(
        default="",
        description=(
            "Slack bot token (`xoxb-...`) for `chat.postMessage`. Preferred "
            "over `slack_webhook_url` and used instead of it when both are "
            "set, for the reason the Concourse pipelines already record: a "
            "webhook's secret lives in the URL path of the endpoint being "
            "called, so whatever holds the URL holds the credential, while a "
            "bot token lives in an `Authorization:` header that Vault can "
            "substitute at egress. This host already has one bot token that "
            "thehub and personal-soc resolve at team scope — reusing it means "
            "one Slack identity rather than three. Needs "
            "`slack_channel` set too; a token with no channel posts nowhere."
        ),
    )

    slack_channel: str = Field(
        default="",
        description=(
            "Channel id or name for `slack_bot_token`. Both are required "
            "together: a bot that cannot name a channel is configured and "
            "addressed to nobody, which is the state B-035 exists about."
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

    # --- The morning briefing DM (TheHub #60864) -----------------------

    briefing_dm_channel: str = Field(
        default="",
        description=(
            "Who the 07:00 briefing DM goes to: a Slack member id (`U...`), "
            "which `chat.postMessage` delivers as a direct message from the "
            "bot, or a channel id. Posted with `slack_bot_token`; an incoming "
            "webhook cannot address a person. Empty, the `briefing-dm` job "
            "records `skipped` with this name as the reason - never a quiet "
            "success."
        ),
    )

    briefing_dm_time: str = Field(
        default="07:00",
        pattern=r"^([01]\d|2[0-3]):[0-5]\d$",
        description=(
            "Local time (HH:MM, 24-hour, in `briefing_dm_timezone`) from which "
            "the day's briefing DM is due. Sent once per local day: a "
            "deployment that was down at 07:00 sends when it comes back."
        ),
    )

    briefing_dm_timezone: str = Field(
        default="America/Phoenix",
        description=(
            "IANA zone `briefing_dm_time` is read in. The estate's own: the "
            "Concourse scan windows use America/Phoenix. An unknown zone fails "
            "the job, visibly, rather than silently sending at a UTC 07:00."
        ),
    )

    dashboard_url: str = Field(
        default="",
        description=(
            "Where a browser reaches this dashboard, e.g. `https://mykronos."
            "example`. The briefing DM links to `<dashboard_url>/briefing`; a "
            "DM with no link to the page it summarises is skipped rather than "
            "sent."
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
