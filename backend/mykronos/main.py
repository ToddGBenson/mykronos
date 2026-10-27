"""FastAPI application.

Phase 0 exposes the Ingestion API only. Onboarding, the workflow installer,
Oracle and the dashboard query service mount onto this same app in later
phases (spec 01 §2 — one backend service, not a fleet).
"""

from __future__ import annotations

import asyncio
import logging
import random
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager, suppress
from typing import Any

from fastapi import FastAPI, Request

from mykronos import (
    __version__,
    auto_triage,
    briefing_dm,
    briefing_flash,
    environment,
    finding_disposition,
    logsafe,
    platform_health,
    premise_monitor,
    risk_acceptance,
    sprint_signal,
)
from mykronos.adminauth import (
    ActorKind,
    Principal,
    PrincipalContextReset,
    Role,
    current_principal,
)
from mykronos.api import refusals, validation_errors
from mykronos.api.agent import router as agent_router
from mykronos.api.agents import router as agents_router
from mykronos.api.approvals import router as approvals_router
from mykronos.api.auto_triage import router as auto_triage_router
from mykronos.api.briefing_daily import router as briefing_daily_router
from mykronos.api.briefing_weekly import router as briefing_weekly_router
from mykronos.api.control_observations import router as control_observations_router
from mykronos.api.dashboard import router as dashboard_router
from mykronos.api.executive import router as executive_router
from mykronos.api.exposure import router as exposure_router
from mykronos.api.ingest import router as ingest_router
from mykronos.api.knowledge import router as knowledge_router
from mykronos.api.lanes import router as lanes_router
from mykronos.api.libraries import router as libraries_router
from mykronos.api.oracle import router as oracle_router
from mykronos.api.patchwork import router as patchwork_router
from mykronos.api.po_console import router as po_console_router
from mykronos.api.po_estate import router as po_estate_router
from mykronos.api.po_review_queue import router as po_review_queue_router
from mykronos.api.product_owner import router as product_owner_router
from mykronos.api.repo_read import router as repo_read_router
from mykronos.api.repo_risk_acceptances import router as repo_risk_acceptances_router
from mykronos.api.repos import router as repos_router
from mykronos.api.risk_acceptances import router as risk_acceptances_router
from mykronos.api.rule_vectors import router as rule_vectors_router
from mykronos.api.triage import router as triage_router
from mykronos.api.triage_clusters import router as triage_clusters_router
from mykronos.api.webhooks import router as webhooks_router
from mykronos.approvals import pull_requests as approval_pull_requests
from mykronos.approvals import reviewer as approval_reviewer
from mykronos.approvals import sampling as approval_sampling
from mykronos.approvals.policy import PolicyError as ApprovalPolicyError
from mykronos.approvals.policy import cached_policy as cached_approval_policy
from mykronos.ci import ConcourseClient, StatusCache
from mykronos.config import Settings, get_settings
from mykronos.db import Database
from mykronos.db.models import JobRun
from mykronos.deployments import probe_tokens_from, run_probe_sweep
from mykronos.digest import send_all as send_digests
from mykronos.gate import PerimeterGate, presents_token
from mykronos.github.auth import AppCredentials
from mykronos.github.factory import (
    FakeGitHubClientFactory,
    GitHubClientFactory,
    RestGitHubClientFactory,
)
from mykronos.headers import SecurityHeaders
from mykronos.installer import TemplateLibrary
from mykronos.jobs import (
    BRIEFING_DM_JOB,
    BRIEFING_FLASH_JOB,
    CI_STALL_JOB,
    DORMANT_LANES_JOB,
    RECORDED_INTERVAL_SECONDS,
    SIGNAL_FILING_JOB,
    AcceptanceSweepResult,
    JobNotDue,
    JobSkipped,
    audit_pipeline_timeouts,
    check_gate_liveness,
    close_superseded_fixes,
    notify_ci_stall,
    notify_dormant_lanes,
    purge_expired_insider_risk,
    purge_orphaned_learnings,
    reconcile_installations,
    rotate_ingestion_tokens,
    score_portfolio,
    sweep_acceptances,
    sweep_governance,
    verify_merged_fixes,
)
from mykronos.knowledge import KnowledgeStore, default_store_dir
from mykronos.lake import (
    Catalog,
    WriteAheadBuffer,
    compact,
)
from mykronos.lake.maintenance import (
    LANE_CLOSURE_LOCK,
    carry_forward_exclusively,
    reconcile_after_linking,
)
from mykronos.libraries import http_fetch as http_library_fetch
from mykronos.logsafe import scrub
from mykronos.maturity import load_model as load_maturity_model
from mykronos.notify import SlackNotifier
from mykronos.oracle import load_policy
from mykronos.oracle.service import OracleService
from mykronos.ownership import OwnershipResolver
from mykronos.patchwork.image_date import RegistryTags
from mykronos.product_owner import HubClient
from mykronos.ratelimit import SlidingWindowLimiter
from mykronos.schemas import utcnow
from mykronos.threat_intel import refresh_job as refresh_threat_intel

logger = logging.getLogger(__name__)


def _record_run(
    db: Any, name: str, interval: int, error: str | None, *, skipped: str = ""
) -> None:
    """Write down that a job ran, and whether it worked.

    Best-effort and never raised out of: a health record that could take down
    the job it is recording would be worse than no health record. A failure to
    write it is logged and the job carries on.

    `skipped` is the third outcome (`jobs.JobSkipped`): due, and nothing done,
    for the reason given. It neither counts as a failure nor moves
    `last_succeeded_at`.
    """
    try:
        with db.session() as session:
            row = session.get(JobRun, name)
            if row is None:
                row = JobRun(name=name)
                session.add(row)
            row.last_run_at = utcnow()
            row.interval_seconds = interval
            row.skipped_reason = skipped[:2000]
            if skipped:
                row.consecutive_failures = 0
                row.last_error = ""
            elif error is None:
                row.last_succeeded_at = row.last_run_at
                row.consecutive_failures = 0
                row.last_error = ""
            else:
                row.consecutive_failures = int(row.consecutive_failures or 0) + 1
                row.last_error = error[:2000]
            session.commit()
    except Exception:  # noqa: BLE001
        logger.warning("Could not record the outcome of job %r", name)


#: How wide to spread the first run of each scheduled job across, in seconds.
#:
#: Every job now runs once shortly after startup instead of after a full
#: interval (#409). Firing twelve of them at t=0 would be its own outage --
#: several rewrite the same `findings` partitions, and that collision is what
#: took the acceptance sweep down for three days -- so each picks a random
#: offset in this window. Ninety seconds is long enough to decongest a boot and
#: short enough that a daily job still runs on a container that lives an hour.
_STARTUP_SPREAD_SECONDS = 90.0


async def _every(
    name: str, interval: int, run: Callable[[], Awaitable[None]], db: Any = None
) -> None:
    """Run `run` forever on an interval, surviving its failures.

    A scheduled job that dies on its first bad day and never runs again is a
    worse failure than the one that killed it — silent, and usually noticed
    weeks later. Everything except cancellation is logged and retried on the
    next tick.

    **Retrying is right, and it is also what makes the failure invisible.** A
    job that has thrown on every run for a fortnight looks, from outside,
    exactly like one that has never had a problem: the only evidence is a line
    in a log nobody tails. So each outcome is written down as well as logged,
    which is what the platform health surface reads.
    """
    # A short jittered delay, then run — rather than sleeping a whole interval
    # first (#409).
    #
    # Sleeping the interval first means a job does nothing for the first
    # `interval` of a container's life. For an hourly job that is a detail. For
    # a daily one on a container redeployed several times a day it is fatal:
    # every restart resets the clock, so a job whose interval exceeds the mean
    # uptime converges on never running at all. Six jobs here are daily and one
    # of them is `rotation`, the ingestion-token sweep. Measured 2026-09-16:
    # fifteen hours of uptime and not one daily job had run.
    #
    # Jittered, and spread over a window rather than all at zero, because
    # twelve jobs firing in the same second on boot is its own outage — and
    # several of them rewrite the same `findings` partitions, which is the
    # collision that took the acceptance sweep down for three days.
    await asyncio.sleep(_STARTUP_SPREAD_SECONDS * random.random())
    # Everything this job writes to the audit log is automation acting, and
    # says so (spec 34 §1). Set once: each job runs in its own task, so its
    # context is its own.
    current_principal.set(
        Principal(actor=f"job:{name}", role=Role.VIEWER, kind=ActorKind.AUTOMATION)
    )
    # What `job_runs` is told the cadence is. Usually the tick; a job that
    # ticks often and acts daily records the day (TheHub #60864).
    recorded = RECORDED_INTERVAL_SECONDS.get(name, interval)
    while True:
        try:
            await run()
        except asyncio.CancelledError:
            raise
        except JobNotDue:
            # Not a run: nothing is recorded, so the row stays the last time
            # the job actually did its work.
            pass
        except JobSkipped as skip:
            reason = scrub(str(skip), max_length=2000) or "skipped"
            logger.warning("Scheduled job %r skipped: %s", name, reason)
            if db is not None:
                _record_run(db, name, recorded, None, skipped=reason)
        except Exception as exc:
            logger.exception("Scheduled job %r failed; will retry in %ss", name, interval)
            if db is not None:
                _record_run(db, name, recorded, scrub(str(exc)) or exc.__class__.__name__)
        else:
            if db is not None:
                _record_run(db, name, recorded, None)
        await asyncio.sleep(interval)


#: How many times the acceptance sweep will re-run into a write conflict
#: before giving the day up.
_WRITE_CONFLICT_ATTEMPTS = 3


async def run_acceptance_sweep(
    catalog: Catalog, *, attempts: int = _WRITE_CONFLICT_ATTEMPTS
) -> AcceptanceSweepResult | None:
    """Run the acceptance sweep, surviving a concurrent rewrite (#409).

    In a thread: it rewrites partitions, same as the other sweeps.

    **Why a retry is safe here, which is not obvious.** The failure this
    absorbs is DuckDB's `Catalog write-write conflict on alter with
    "...View...findings"` — a conflict on the *view definition*, raised from
    `Catalog.refresh_views()` when another writer's `connect()` overlaps this
    one. It is metadata, not rows: nothing is left half-written by it. And
    `sweep_acceptances` re-reads every `accepted_risk` row from scratch on each
    attempt, then writes under `only_if_status='accepted_risk'`, so a row some
    other job has already moved is skipped rather than overwritten. A retry
    therefore cannot turn a collision into a lost update — which is the one
    thing that would make retrying worse than losing the day.

    It shares those partitions with `absences`, `carry-forward` and the
    compaction loop, and on a daily job one collision costs a whole day: this
    sweep last succeeded on 2026-09-13 and its next attempt lost to exactly
    that, leaving two acceptances live whose premise a scan had already
    contradicted (#409).

    **And the retry says so, at warning.** `_record_run` clears `last_error`
    and returns `consecutive_failures` to 0 on the eventual success, so a
    collision that was retried away leaves no trace in `job_runs` at all; this
    line is the only evidence it happened. At INFO it was no evidence either —
    the deployed logger sits at WARNING, measured on the running container. A
    sweep quietly retrying twice every day is the platform needing these jobs
    serialised, and #409 is what three days of the platform not saying so
    costs.
    """
    for attempt in range(attempts):
        try:
            return await asyncio.to_thread(sweep_acceptances, catalog)
        except Exception as exc:  # noqa: BLE001 — retried, then raised
            if "conflict" not in str(exc).lower() or attempt == attempts - 1:
                raise
            logger.warning(
                "Acceptance sweep hit a write conflict; retrying (%s/%s). It "
                "shares the `findings` partitions with absences, carry-forward "
                "and compaction; if this recurs they need serialising.",
                attempt + 1,
                attempts,
            )
            await asyncio.sleep(5 * (attempt + 1))
    return None  # pragma: no cover - unreachable; the loop returns or raises


async def _compaction_loop(app: FastAPI, interval: int) -> None:
    """Fold the buffer into Parquet on a timer (spec 05 §2).

    Runs in a thread so a large compaction cannot block the event loop and
    stall ingestion. Failures are logged and retried on the next tick — the
    buffer holds the data until a write is confirmed, so a failed run loses
    nothing.
    """
    while True:
        await asyncio.sleep(interval)
        try:
            result = await asyncio.to_thread(
                compact, app.state.catalog, app.state.buffer, db=app.state.db
            )
            if result.total_rows:
                logger.info(
                    "Compacted %s rows (%s inserted, %s updated) from %s segments",
                    result.total_rows,
                    sum(result.inserted.values()),
                    sum(result.updated.values()),
                    result.segments_consumed,
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Scheduled compaction failed; buffer retained, will retry")
        # After compaction, so an ingest's findings are in the lake before the
        # repository it dirtied is rescored (TheHub #60827). Separate from the
        # compaction's own error handling: a rescore failing loses nothing.
        try:
            rescored = await asyncio.to_thread(
                environment.drain, app.state.db, app.state.catalog
            )
            for outcome in rescored:
                logger.info("Environmental rescore: %s", outcome.summary())
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Environmental rescore after compaction failed")


def _build_github_factory(settings: Settings) -> GitHubClientFactory:
    """Real factory when the App is configured, in-memory otherwise.

    Booting without credentials is deliberate: the platform and its onboarding
    UI stay explorable before the App exists (spec 02 §4 is a manual one-time
    step). Anything that would really touch GitHub is recorded on the fake
    rather than silently doing nothing.
    """
    if settings.github_app_id and settings.github_app_private_key_path:
        credentials = AppCredentials.from_file(
            settings.github_app_id,
            settings.github_app_private_key_path,
            webhook_secret=settings.github_webhook_secret,
        )
        logger.info("GitHub App %s configured", settings.github_app_id)
        return RestGitHubClientFactory(credentials)

    logger.warning(
        "No GitHub App configured (MYKRONOS_GITHUB_APP_ID / "
        "MYKRONOS_GITHUB_APP_PRIVATE_KEY_PATH). GitHub calls are faked in memory; "
        "no real repository will be touched."
    )
    factory = FakeGitHubClientFactory()
    for repo in settings.github_fake_seed_repos:
        # A default branch, and something on it worth changing. Without both,
        # a seeded repo is unusable for the paths that matter: `create_branch`
        # refuses a base ref that does not exist, so the installer cannot open
        # a pull request, and Patchwork reads every file as absent and reports
        # each finding `superseded` — a confident-looking answer that is
        # entirely an artefact of the fixture.
        files = {
            "README.md": f"# {repo}\n",
            # Deliberately a version with a published advisory, so the
            # deterministic dependency fixer has something real to do.
            "requirements.txt": "requests==2.31.0\nurllib3==2.0.4\n",
        }
        seeded = factory.client.add_repo(repo, files=files)
        seeded.branches[seeded.default_branch] = dict(files)
        logger.info("Seeded in-memory repository %s", repo)
    return factory


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    # Before anything else logs. Untrusted text is scrubbed at the call sites
    # that handle it, but only the ones somebody remembered; this covers the
    # rest, including uvicorn's own request logging (spec 12 §8).
    logsafe.install()
    logsafe.demote_http_request_logs()
    app.state.catalog = Catalog(settings.datalake_dir)
    app.state.catalog.initialise()
    app.state.buffer = WriteAheadBuffer(settings.buffer_dir)
    app.state.db = Database(settings.database_url)
    # Spec 33: the risk-acceptance duty stamps findings in the lake when an
    # approval lands, and reads its limits from the approval policy.
    risk_acceptance.bind(app.state.catalog)
    # The guard reads toxic combinations as the risk decision does: KEV from
    # the database, escalation from the Oracle policy (review of #1018).
    finding_disposition.bind(
        app.state.catalog,
        db=app.state.db,
        oracle_policy_path=settings.oracle_policy_path,
    )
    # TheHub #60895: library vetting reads OSV and deps.dev; tests replace it.
    app.state.library_fetch = http_library_fetch
    try:
        risk_acceptance.bind_policy(cached_approval_policy(settings.approval_policy_path))
    except ApprovalPolicyError as exc:
        # Fail closed for approvals, not for the platform: every approval route
        # loads the same policy and refuses without it.
        logger.error("Approval policy unavailable; approvals will refuse: %s", exc)
    app.state.db.create_all()
    app.state.limiter = SlidingWindowLimiter(settings.rate_limit_requests_per_minute)
    app.state.templates = TemplateLibrary(settings.workflow_templates_dir)
    app.state.github_factory = _build_github_factory(settings)
    # Patchwork's bump-image-date reads tags here; None when unconfigured.
    app.state.image_registry = RegistryTags.from_settings(settings)
    # Held on the app rather than built per request, which is the whole point
    # of it (spec 32 §7.1): reading GitHub Actions state spends an
    # installation rate limit shared with token rotation, the installer and
    # Patchwork, and a repository page refreshed in a loop must not be what
    # stops a token rotating. Per-process, and successes only.
    app.state.ci_status_cache = StatusCache(settings.ci_status_cache_seconds)
    # Loaded once at startup and held: spec 09 §10 requires an evaluation
    # to use whichever version was active when it began, so the file
    # changing under a running request must not change its result.
    app.state.oracle_policy = load_policy(settings.oracle_policy_path)
    # Held from startup like the Oracle policy, and for the same reason: an
    # assessment should not change under a running request because somebody
    # saved the file.
    app.state.maturity_model = load_maturity_model(settings.maturity_model_path)
    # spec 11 §8: colocated with the lake, logically separate. Personal tier
    # is where every captured learning starts; promotion to team or org is a
    # human decision (spec 11 §2), never a side effect of writing one.
    # When this process came up. The health surface needs it to tell a job
    # whose interval has not elapsed since start-up from one that has stopped —
    # without it every long-interval job reads as late for a day after a deploy.
    app.state.started_at = utcnow()
    app.state.knowledge = KnowledgeStore(
        default_store_dir(settings.datalake_dir),
        tier="personal",
        half_life_days=settings.knowledge_half_life_days,
    )
    # Always constructed, even with no webhook configured. A notifier that is
    # present and disabled is one branch at the call site; a notifier that may
    # be absent from `app.state` is a `getattr` at every call site and an
    # AttributeError at the one that forgot (spec 16 §14).
    app.state.notifier = SlackNotifier(
        settings.slack_webhook_url,
        bot_token=settings.slack_bot_token,
        channel=settings.slack_channel,
    )
    # Said either way. A notifier that is addressed to nobody is the
    # state B-035 records, and a deployment that logs nothing about it
    # leaves 'notifications are on' and 'notifications go nowhere'
    # looking identical from the outside.
    if app.state.notifier.enabled:
        logger.info(
            "Slack notification is enabled (%s).", app.state.notifier.transport
        )
    else:
        logger.warning(
            "Slack notification is not configured: nothing this platform "
            "decides will reach anybody. Set MYKRONOS_SLACK_BOT_TOKEN and "
            "MYKRONOS_SLACK_CHANNEL, or MYKRONOS_SLACK_WEBHOOK_URL."
        )

    # Always constructed, for the reason the notifier above is: an ingest
    # handler that has to guard `hasattr(state, "ownership")` is one that will
    # forget. With no GitHub client reachable it resolves everything to
    # `unresolved`, which is a correct answer rather than a failure.
    app.state.ownership = OwnershipResolver()

    tasks: list[asyncio.Task[None]] = []

    if settings.run_compaction_in_background:
        tasks.append(
            asyncio.create_task(
                _compaction_loop(app, settings.compaction_interval_seconds),
                name="mykronos-compaction",
            )
        )

    if settings.run_jobs_in_background:

        async def _rotate() -> None:
            await rotate_ingestion_tokens(
                app.state.db,
                app.state.github_factory,
                overlap_hours=settings.token_overlap_hours,
                # Without this the job cannot tell whether a repository has a
                # second reader it is unable to deliver to (D-097).
                concourse=ConcourseClient(
                    settings.concourse_url,
                    team=settings.concourse_team,
                    external_url=settings.concourse_external_url,
                ),
            )

        async def _installations() -> None:
            await reconcile_installations(app.state.db, app.state.github_factory)

        async def _absences() -> None:
            # In a thread: it rewrites Parquet partitions and would otherwise
            # block ingestion for the duration.
            #
            # Carry-forward first, in the same thread and under one lock
            # (`lake/maintenance.py`, TheHub #60734): an exact link withdraws a
            # re-keyed finding as `superseded`, and on two independent timers
            # absence could close the same row as `fixed` first.
            result = await asyncio.to_thread(reconcile_after_linking, app.state.catalog)
            if result.carried.carried:
                logger.info("Carry-forward before absences: %s", result.carried.summary())

        async def _carry_forward() -> None:
            # In a thread, for the same reason as absences. Runs before it in
            # the list below rather than after, though the two are independent
            # timers: a finding withdrawn as `superseded` here is one the
            # absence reconciler will not later close as `fixed`, and `fixed`
            # is the number this platform is most careful about.
            result = await asyncio.to_thread(carry_forward_exclusively, app.state.catalog)
            if result.carried or result.stranded:
                logger.info("Carry-forward: %s", result.summary())

        async def _portfolio() -> None:
            await score_portfolio(
                app.state.db,
                OracleService(
                    app.state.catalog,
                    app.state.buffer,
                    app.state.oracle_policy,
                    app.state.knowledge,
                    db=app.state.db,
                ),
            )

        async def _retention() -> None:
            # In a thread: both rewrite files on disk, same as absences.
            await asyncio.to_thread(
                purge_expired_insider_risk,
                app.state.db,
                app.state.catalog,
                default_retention_days=settings.insider_risk_default_retention_days,
            )
            await asyncio.to_thread(
                purge_orphaned_learnings, app.state.db, app.state.knowledge
            )

        async def _auto_triage() -> None:
            # In a thread, under the lock every pass that closes findings
            # holds (`lake/maintenance.py`): `fix_verified` closes as `fixed`,
            # the same column absence reconciliation writes.
            enabled = app.state.oracle_policy.auto_triage.enabled()

            def _sweep() -> None:
                with LANE_CLOSURE_LOCK:
                    auto_triage.sweep(app.state.db, app.state.catalog, enabled)

            await asyncio.to_thread(_sweep)

        async def _verify_fixes() -> None:
            await verify_merged_fixes(
                app.state.db,
                app.state.catalog,
                app.state.buffer,
                app.state.github_factory,
                app.state.templates,
                settings,
            )

        async def _deployment_probe() -> None:
            # Awaited rather than threaded: it is a handful of HTTP GETs with
            # their own timeout, and the DB write at the end is four columns
            # on a few rows.
            # The perimeter tokens (D-157) per origin, and the App client for
            # the compare that turns a revision into "N commits behind" (#452).
            sweep = await run_probe_sweep(
                app.state.db,
                app.state.catalog,
                timeout=settings.deployment_probe_timeout_seconds,
                tokens=probe_tokens_from(settings),
                github_factory=app.state.github_factory,
                # Derived probes, and what each repository is missing (#60918).
                settings=settings,
            )
            for state in sweep.diverged:
                logger.warning(
                    "Deployment divergence: %s runs %s, newest scan was %s",
                    state.repo_full_name,
                    state.revision,
                    state.scanned_revision,
                )

        async def _digest() -> None:
            # Awaited rather than threaded. `send_all` puts its own lake
            # queries on a thread and awaits the posts, which is what a
            # coroutine notifier needs: handing the whole thing to
            # `to_thread` is how the sends came to be dropped un-awaited.
            await send_digests(app.state.catalog, app.state.notifier)

        async def _acceptances() -> None:
            result = await run_acceptance_sweep(app.state.catalog)
            # Logged, the way governance is. The counts were already computed
            # and thrown away, so a sweep that expired nothing and one that had
            # not run for three days produced identical evidence: none.
            if result is not None:
                summary = result.summary()
                if result.expired or result.reopened_by_fix:
                    logger.warning("Acceptance sweep: %s", summary)
                else:
                    logger.info("Acceptance sweep: %s", summary)
            # The decisions, not just the rows (spec 33 §1.4): review due,
            # expired, closed and scope drift, each audited.
            records = await asyncio.to_thread(
                risk_acceptance.sweep, app.state.db, app.state.catalog
            )
            if records.expired or records.review_due or records.drift or records.not_approved:
                logger.warning("Risk acceptance sweep: %s", records)
            # Delegations whose sampled decisions nobody has reviewed lapse
            # (spec 34 §5.2): trust that is not being checked is not kept.
            try:
                policy = cached_approval_policy(settings.approval_policy_path)
            except ApprovalPolicyError:
                return
            lapsed = await asyncio.to_thread(approval_sampling.sweep, app.state.db, policy)
            if lapsed.suspended:
                logger.warning("Delegations suspended, samples unreviewed: %s", lapsed.suspended)

        async def _pull_request_stamps() -> None:
            # Retries any `independent-review` check GitHub has not heard
            # about yet, and expires requests past their TTL (spec 34 §6.1).
            try:
                policy = cached_approval_policy(settings.approval_policy_path)
            except ApprovalPolicyError:
                return
            await approval_pull_requests.request_missing(
                app.state.db, policy, app.state.github_factory
            )
            await approval_pull_requests.publish_due(
                app.state.db, policy, app.state.github_factory
            )

        async def _library_checks() -> None:
            # The library-allowlist check on every open pull request head that
            # has none yet (TheHub #60898). Reports unless a person switched
            # the repository to blocking once its allowlist covered it.
            from mykronos import library_check

            posted = await library_check.sweep(
                app.state.db,
                app.state.catalog,
                app.state.github_factory,
                dashboard_url=settings.dashboard_url,
            )
            if posted:
                logger.info("Library checks posted: %s", ", ".join(posted))

        async def _library_facts() -> None:
            # Registry facts behind the EOL, abandoned and license-change
            # flags on the managed Libraries view (TheHub #60897).
            from mykronos import libraries

            result = await libraries.refresh_facts(
                app.state.db, app.state.catalog, fetch=app.state.library_fetch
            )
            logger.info("Library facts: %s", result)

        async def _shadow_reviews() -> None:
            # spec 34 §4.3 shadow mode: the reviewer reads pending requests and
            # its verdict is recorded, never counted. A no-op unless the mode is
            # `shadow` and a key is set, so the job is safe to always schedule.
            try:
                policy = cached_approval_policy(settings.approval_policy_path)
            except ApprovalPolicyError:
                return
            done = await asyncio.to_thread(
                approval_reviewer.shadow_sweep,
                app.state.db,
                policy,
                settings,
                limit=settings.shadow_reviews_per_run,
            )
            if done:
                logger.info(
                    "Shadow reviews: %s",
                    ", ".join(f"{o.request_id[:8]}={o.verdict}" for o in done),
                )

        async def _exposure() -> None:
            # What a public endpoint shows anyone who asks (mykronos.exposure).
            # A no-op with nothing registered.
            from mykronos import exposure

            await exposure.run_sweep(app.state.db)

        async def _governance() -> None:
            # Not in a thread: it is HTTP-bound, one call per repository, and
            # awaiting it lets the rest of the app serve while GitHub answers.
            result = await sweep_governance(app.state.db, app.state.github_factory)
            # Logged at warning only when something moved. A control coming off
            # is the one governance event worth waking somebody for; "nothing
            # changed" every six hours is how a log stops being read.
            #
            # `result.unreadable_controls` deliberately does not reach this
            # branch (#264). Both governance warnings this estate has ever sent
            # were failed reads of `codeowners_coverage`, and rationing only
            # works if what gets through is real. They still appear in the
            # summary, at `info`.
            if result.drifted:
                logger.warning("Governance sweep: %s", result.summary())
            else:
                logger.info("Governance sweep: %s", result.summary())

        async def _threat_model_sync() -> None:
            # `.sdlc/threat-model.yaml` from every default branch (spec 28 §8).
            # HTTP-bound, one call per repository, like governance.
            from mykronos import threat_model_manifest

            result = await threat_model_manifest.sweep(
                app.state.db, app.state.github_factory
            )
            logger.info("Threat-model sync: %s", result.summary())

        async def _environment() -> None:
            # Every repository's environmental CVSS from scratch (TheHub
            # #60827). The event triggers cover writes; only this notices a
            # fact that lapsed, so only this raises a score back. Raises if
            # any repository failed, so `job_runs` says so.
            results = await asyncio.to_thread(
                environment.rescore_all, app.state.db, app.state.catalog
            )
            changed = [r for r in results if r.context_changed or r.scored or r.removed]
            logger.info(
                "Environmental rescore: %s repositories, %s changed%s",
                len(results),
                len(changed),
                "".join(f"; {r.summary()}" for r in changed),
            )

        async def _stale_drafts() -> None:
            await close_superseded_fixes(
                app.state.db,
                app.state.catalog,
                app.state.buffer,
                app.state.github_factory,
            )

        async def _timeout_audit() -> None:
            # Live Concourse history against the committed caps (TheHub
            # #60729). A finding notifies; unread history raises, so this
            # job's row in `job_runs` reads `could not audit` and not clean.
            await audit_pipeline_timeouts(
                settings.concourse_url,
                settings.pipeline_definitions_dir,
                team=settings.concourse_team,
                notifier=app.state.notifier,
            )

        # The last signature sent, so a gate that stays stale is posted once
        # and again only when what it would say changes.
        gate_liveness_sent: dict[str, str | None] = {"signature": None}

        async def _gate_liveness() -> None:
            # Are main's commits still reaching a gate decision (TheHub
            # #60731)? Stale notifies and names the red upstream lane;
            # unreadable raises, so `job_runs` reads `could not check`.
            oracle = OracleService(
                app.state.catalog, app.state.buffer, app.state.oracle_policy
            )
            report = await check_gate_liveness(
                settings.concourse_url,
                oracle.decision_for_commit,
                threshold_hours=settings.gate_liveness_stale_hours,
                team=settings.concourse_team,
                notifier=app.state.notifier,
                already_sent=gate_liveness_sent["signature"],
            )
            gate_liveness_sent["signature"] = report.signature if report.stale else None

        async def _dormant_lanes() -> None:
            # Every pipeline's paused or long-red jobs, pushed once a UTC day
            # rather than waiting to be asked (agent_work, briefing). The day
            # is read from this job's own `job_runs` row, so a restart does
            # not post twice.
            await notify_dormant_lanes(
                ConcourseClient(
                    settings.concourse_url,
                    team=settings.concourse_team,
                    external_url=settings.concourse_external_url,
                ),
                db=app.state.db,
                notifier=app.state.notifier,
                threshold_hours=settings.dormant_lanes_threshold_hours,
            )

        async def _ci_stall() -> None:
            # Many lanes erroring together - a dead worker after a restart
            # (TheHub #60975). Once per stall episode; an undelivered notice
            # raises, so the next tick retries it.
            await notify_ci_stall(
                ConcourseClient(
                    settings.concourse_url,
                    team=settings.concourse_team,
                    external_url=settings.concourse_external_url,
                ),
                db=app.state.db,
                notifier=app.state.notifier,
            )

        async def _briefing_dm() -> None:
            # The 07:00 DM (TheHub #60864): due once a local day, read through
            # the briefing route so it says what the page says. Not due raises
            # JobNotDue and records nothing; no Slack for it raises JobSkipped.
            await briefing_dm.send_briefing_dm(
                settings, db=app.state.db, read=briefing_dm.route_reader(app)
            )

        async def _briefing_flash() -> None:
            # Same-day flash DM (TheHub #60865): only an exploited or critical
            # match to something shipped, each item once. Read through the
            # weekly route so the DM says what the Monday page says.
            await briefing_flash.send_flashes(
                settings, db=app.state.db, read=briefing_flash.route_reader(app)
            )

        async def _signal_filing() -> None:
            # Next-sprint candidates to TheHub's backlog (TheHub #60862),
            # once a UTC day, read through the briefing route so it files
            # what the page ranks. Already done today raises JobNotDue; no
            # TheHub raises JobSkipped, so the row reads `skipped`.
            await sprint_signal.file_signals(
                db=app.state.db,
                hub=getattr(app.state, "hub", None),
                read=briefing_dm.route_reader(app, actor=f"job:{SIGNAL_FILING_JOB}"),
            )

        async def _threat_intel() -> None:
            # In a thread: it makes a blocking HTTP call (spec 17 §4.3),
            # which would otherwise stall the event loop for every other
            # request while a public feed is slow to answer.
            result = await asyncio.to_thread(
                refresh_threat_intel, app.state.db, app.state.catalog
            )
            if not result.ok:
                logger.warning(
                    "Threat-intel refresh degraded: kev_error=%s epss_error=%s",
                    result.kev_error,
                    result.epss_error,
                )
            # An `epss_below` premise is decided by what this just refreshed
            # (spec 33 §4.2: after every relevant refresh). Its own job reports
            # its health; a failure here must not mark the refresh failing.
            try:
                await premise_monitor.run_and_notify(
                    app.state.db,
                    app.state.catalog,
                    app.state.notifier,
                    fresh_days=settings.premise_fresh_days,
                )
            except Exception:  # noqa: BLE001 - logged; premise-monitor reports health
                logger.exception("Premise monitor after the threat-intel refresh failed")

        async def _premise_monitor() -> None:
            # Spec 33 §4.2: every live acceptance's premises against fresh
            # observations and EPSS. A failed premise moves the acceptance to
            # premise_failed and reopens its findings; one that could not be
            # applied raises, so this job reads failing rather than clean.
            await premise_monitor.run_and_notify(
                app.state.db,
                app.state.catalog,
                app.state.notifier,
                fresh_days=settings.premise_fresh_days,
            )

        if settings.digest_enabled and not app.state.notifier.enabled:
            logger.warning(
                "Weekly digest is enabled and no Slack transport is configured, "
                "so it will build digests every %ss and deliver none. Set "
                "MYKRONOS_SLACK_WEBHOOK_URL, or MYKRONOS_SLACK_BOT_TOKEN with "
                "MYKRONOS_SLACK_CHANNEL - or unset MYKRONOS_DIGEST_ENABLED.",
                settings.weekly_digest_interval_seconds,
            )

        scheduled: list[str] = []
        for name, interval, run in (
            ("rotation", settings.token_rotation_interval_seconds, _rotate),
            ("stale-drafts", settings.stale_draft_sweep_interval_seconds, _stale_drafts),
            # Only against a real GitHub. With no App configured the factory
            # is the in-memory fake, which answers 404 for every installation
            # it was not seeded with - so the reconciler read every onboarded
            # repository as uninstalled and marked it `removed`. The demo seeds
            # four repositories with placeholder installation ids, and this
            # job removed all four seventeen seconds later, on every rebuild:
            # the portfolio came back empty and `demo-and-dast` refused to scan
            # an "unseeded" environment. It has passed once, ever.
            *(
                []
                if isinstance(app.state.github_factory, FakeGitHubClientFactory)
                else [
                    (
                        "installations",
                        settings.installation_sync_interval_seconds,
                        _installations,
                    )
                ]
            ),
            ("carry-forward", settings.carry_forward_interval_seconds, _carry_forward),
            ("absences", settings.absence_reconcile_interval_seconds, _absences),
            ("portfolio", settings.portfolio_scoring_interval_seconds, _portfolio),
            ("retention", settings.insider_risk_purge_interval_seconds, _retention),
            ("threat-intel", settings.threat_intel_refresh_interval_seconds, _threat_intel),
            ("acceptances", settings.acceptance_sweep_interval_seconds, _acceptances),
            (
                "premise-monitor",
                settings.premise_monitor_interval_seconds,
                _premise_monitor,
            ),
            ("governance", settings.governance_sweep_interval_seconds, _governance),
            # Only against a real GitHub, for the reason `installations` is:
            # the fake answers nothing for the demo's placeholder installs.
            *(
                []
                if isinstance(app.state.github_factory, FakeGitHubClientFactory)
                else [
                    (
                        "threat-model-sync",
                        settings.threat_model_sync_interval_seconds,
                        _threat_model_sync,
                    )
                ]
            ),
            ("pull-request-stamps", 120, _pull_request_stamps),
            # Against a real GitHub and the real registries only, for the
            # reason `installations` is: the demo's placeholders answer nothing.
            *(
                []
                if isinstance(app.state.github_factory, FakeGitHubClientFactory)
                else [
                    ("library-checks", 300, _library_checks),
                    ("library-facts", 86_400, _library_facts),
                ]
            ),
            ("exposure", settings.exposure_probe_interval_seconds, _exposure),
            ("environment", settings.environment_rescore_interval_seconds, _environment),
            # Only with a Concourse to read. Without one the job would fail
            # every day for a reason that is configuration, not a finding;
            # unscheduled, platform health reads it as disabled instead.
            *(
                [("timeout-audit", settings.timeout_audit_interval_seconds, _timeout_audit)]
                if settings.concourse_url
                else []
            ),
            *(
                [("gate-liveness", settings.gate_liveness_interval_seconds, _gate_liveness)]
                if settings.concourse_url
                else []
            ),
            *(
                [(DORMANT_LANES_JOB, settings.dormant_lanes_interval_seconds, _dormant_lanes)]
                if settings.concourse_url
                else []
            ),
            *(
                [(CI_STALL_JOB, settings.ci_stall_interval_seconds, _ci_stall)]
                if settings.concourse_url
                else []
            ),
            # Always scheduled: with no Slack configured for it, it records
            # `skipped` with the missing setting, rather than being absent
            # from platform health and reading as "nothing to say".
            (BRIEFING_DM_JOB, briefing_dm.TICK_SECONDS, _briefing_dm),
            (BRIEFING_FLASH_JOB, briefing_flash.TICK_SECONDS, _briefing_flash),
            # Always scheduled, for the same reason: without TheHub it records
            # `skipped` and says so.
            (SIGNAL_FILING_JOB, sprint_signal.TICK_SECONDS, _signal_filing),
            ("shadow-reviews", settings.shadow_review_interval_seconds, _shadow_reviews),
            ("fix-verification", settings.fix_verification_interval_seconds, _verify_fixes),
            # TheHub #60888. Hourly, and only lanes the policy enables.
            ("auto-triage", settings.auto_triage_interval_seconds, _auto_triage),
            (
                "deployment-probe",
                settings.deployment_probe_interval_seconds,
                _deployment_probe,
            ),
            # `digest_enabled` and the notifier's transport are separate
            # switches, and one without the other is silent (#412). A disabled
            # notifier is a supported state -- `digest.send_all` says so and is
            # right -- but a digest turned ON with nothing to send through is
            # somebody asking for delivery that cannot happen, and the only
            # symptom is an INFO line inside a job that reports success.
            #
            # Said once at startup rather than weekly at send time, because
            # that is when somebody is looking, and named with both switches
            # because neither is wrong on its own.
            # Off unless opted in: this job messages people.
            *(
                [("digest", settings.weekly_digest_interval_seconds, _digest)]
                if settings.digest_enabled
                else []
            ),
        ):
            scheduled.append(name)
            tasks.append(
                asyncio.create_task(
                    _every(name, interval, run, app.state.db),
                    name=f"mykronos-{name}",
                )
            )
        # Every job this deployment does not run - switched off by a setting,
        # or removed - reads as disabled rather than late.
        platform_health.mark_scheduled(app.state.db, scheduled)

    logger.info(
        "Mykronos %s ready — data lake at %s, %s background job(s)",
        __version__,
        settings.datalake_dir,
        len(tasks),
    )
    try:
        yield
    finally:
        for task in tasks:
            task.cancel()
        for task in tasks:
            with suppress(asyncio.CancelledError):
                await task
        # Final drain, so a clean shutdown leaves nothing sitting in the buffer.
        with suppress(Exception):
            await asyncio.to_thread(
                compact, app.state.catalog, app.state.buffer, db=app.state.db
            )
        app.state.db.close()


def create_app(settings: Settings | None = None) -> FastAPI:
    app = FastAPI(
        title="Mykronos Platform API",
        version=__version__,
        summary="Unified AppSec onboarding, scanning, risk-decision and dashboard platform.",
        description=(
            "Phase 0: the data lake and its single write path. "
            "See specs/05-datalake.md and specs/13-build-roadmap.md."
        ),
        lifespan=lifespan,
    )
    resolved = settings or get_settings()
    app.state.settings = resolved
    # TheHub, for the Product Owner tab (spec 35 §4.1). None when either the
    # URL or the token is empty, and the tab then says it is not connected.
    app.state.hub = HubClient.from_settings(resolved)
    app.include_router(ingest_router)
    app.include_router(dashboard_router)
    app.include_router(briefing_daily_router)
    app.include_router(briefing_weekly_router)
    app.include_router(control_observations_router)
    app.include_router(executive_router)
    app.include_router(rule_vectors_router)
    app.include_router(exposure_router)
    app.include_router(knowledge_router)
    app.include_router(oracle_router)
    app.include_router(patchwork_router)
    app.include_router(product_owner_router)
    app.include_router(po_console_router)
    app.include_router(po_estate_router)
    app.include_router(po_review_queue_router)
    app.include_router(repos_router)
    app.include_router(triage_router)
    app.include_router(triage_clusters_router)
    app.include_router(auto_triage_router)
    app.include_router(webhooks_router)
    app.include_router(agents_router)
    app.include_router(agent_router)
    app.include_router(approvals_router)
    app.include_router(risk_acceptances_router)
    app.include_router(repo_risk_acceptances_router)
    app.include_router(repo_read_router)
    app.include_router(lanes_router)
    app.include_router(libraries_router)
    # A refused upload is a 403 and a notification (B-062).
    refusals.install(app)
    # A body with NaN in a constrained float is a 422, not a 500.
    validation_errors.install(app)

    # Runs before routing: a request that cannot present the perimeter token
    # should not reach a handler at all, and should not be able to learn which
    # paths exist by the shape of the error.
    if resolved.gate_token:
        app.add_middleware(PerimeterGate, token=resolved.gate_token)
        logger.info("Perimeter gate enabled (X-Hub-Token)")
    else:
        logger.info(
            "Perimeter gate disabled — no MYKRONOS_GATE_TOKEN set. Fine "
            "locally; set it before exposing this host."
        )

    # Added last and therefore outermost — `add_middleware` inserts at the
    # front of the stack, so this wraps the gate rather than sitting behind
    # it. That is the whole point: the gate's own 401 is a response a browser
    # renders, and the scan that found this counted 404s and 405s among the
    # offending paths (B-025).
    app.add_middleware(SecurityHeaders)

    # Clears the authenticated principal at the start of every request. A
    # keep-alive connection is served by one task, so without this a principal
    # set by one request would still be visible to the next one on the same
    # connection - and an unauthenticated write would be attributed to
    # whoever came before it (spec 34 §1).
    app.add_middleware(PrincipalContextReset)

    @app.get("/healthz", tags=["ops"], summary="Unauthenticated liveness probe")
    async def healthz(request: Request) -> dict[str, Any]:
        """For infrastructure only. Deliberately reveals nothing about the
        lake — the authenticated /api/ingest/health is what workflows call.

        [D-157, TheHub #60722] The public body is `{"status": "ok"}` and
        nothing else. `/healthz` is exempt from the perimeter gate, so every
        key here is published to the internet, and `build.sha` (#361) told
        anyone which commit to diff to find what is not yet patched.

        `build` is still served to a caller that presents the perimeter token
        (`X-Hub-Token`, `hub_token` cookie, `?_token=`). deploy.ps1 does not
        need it: it reads `MYKRONOS_BUILD_SHA` from the container itself. The
        status code is 200 for every caller.

        `build.source` exists so the absent case cannot be misread. An image
        built without the build-arg reports `sha: null, source: "unknown"`
        rather than a version string that looks like an answer.
        """
        body: dict[str, Any] = {"status": "ok"}
        if presents_token(request, resolved.gate_token):
            sha = resolved.build_sha.strip()
            body["version"] = __version__
            body["build"] = {
                "sha": sha or None,
                "source": "image" if sha else "unknown",
            }
        return body

    return app


app = create_app()
