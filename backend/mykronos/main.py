"""FastAPI application.

Phase 0 exposes the Ingestion API only. Onboarding, the workflow installer,
Oracle and the dashboard query service mount onto this same app in later
phases (spec 01 §2 — one backend service, not a fleet).
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress

from fastapi import FastAPI

from mykronos import __version__
from mykronos.api.ingest import router as ingest_router
from mykronos.api.repos import router as repos_router
from mykronos.api.webhooks import router as webhooks_router
from mykronos.config import Settings, get_settings
from mykronos.db import Database
from mykronos.github.auth import AppCredentials
from mykronos.github.factory import (
    FakeGitHubClientFactory,
    GitHubClientFactory,
    RestGitHubClientFactory,
)
from mykronos.installer import TemplateLibrary
from mykronos.lake import Catalog, WriteAheadBuffer, compact
from mykronos.ratelimit import SlidingWindowLimiter

logger = logging.getLogger(__name__)


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
            result = await asyncio.to_thread(compact, app.state.catalog, app.state.buffer)
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
    return FakeGitHubClientFactory()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    app.state.catalog = Catalog(settings.datalake_dir)
    app.state.catalog.initialise()
    app.state.buffer = WriteAheadBuffer(settings.buffer_dir)
    app.state.db = Database(settings.database_url)
    app.state.db.create_all()
    app.state.limiter = SlidingWindowLimiter(settings.rate_limit_requests_per_minute)
    app.state.templates = TemplateLibrary(settings.workflow_templates_dir)
    app.state.github_factory = _build_github_factory(settings)

    task: asyncio.Task[None] | None = None
    if settings.run_compaction_in_background:
        task = asyncio.create_task(
            _compaction_loop(app, settings.compaction_interval_seconds),
            name="mykronos-compaction",
        )

    logger.info("Mykronos %s ready — data lake at %s", __version__, settings.datalake_dir)
    try:
        yield
    finally:
        if task is not None:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task
        # Final drain, so a clean shutdown leaves nothing sitting in the buffer.
        with suppress(Exception):
            await asyncio.to_thread(compact, app.state.catalog, app.state.buffer)
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
    app.state.settings = settings or get_settings()
    app.include_router(ingest_router)
    app.include_router(repos_router)
    app.include_router(webhooks_router)

    @app.get("/healthz", tags=["ops"], summary="Unauthenticated liveness probe")
    async def healthz() -> dict[str, str]:
        """For infrastructure only. Deliberately reveals nothing about the
        lake — the authenticated /api/ingest/health is what workflows call."""
        return {"status": "ok", "version": __version__}

    return app


app = create_app()
