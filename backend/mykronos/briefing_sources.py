"""The briefing's inputs that do not live in the lake (spec 36 §2).

`briefing.build` reads the lake and takes everything else as arguments: paused
and failing CI jobs, scheduled-job health, deferred token deliveries, toxic
combinations and public exposure. Until spec 36 only `mykronos briefing`
gathered them, inline in the CLI, so the API's briefing silently had none of
them and the agent work queue would have needed a third copy.

One gatherer, two callers. Every input keeps the CLI's contract: **`None` on
any failure, never an empty list.** `None` renders as "could not ask", an empty
list as "asked, and nothing is wrong", and those must not look the same — four
security lanes sat paused for thirty-two days behind exactly that gap (#401).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select

from mykronos import briefing as briefing_report
from mykronos.ci import ConcourseClient
from mykronos.db.models import RepoOnboarding

logger = logging.getLogger(__name__)


@dataclass
class OperationalInputs:
    """What `briefing.build` needs from outside the lake. `None` = not read."""

    paused_jobs: list[briefing_report.PausedLane] | None = None
    failing_jobs: list[briefing_report.FailingLane] | None = None
    unhealthy_jobs: list[Any] | None = None
    tokens: list[briefing_report.TokenDelivery] | None = None
    toxic_combinations: list[dict[str, Any]] | None = None
    toxic_coverage: dict[str, Any] | None = None
    exposure: list[dict[str, Any]] | None = None


def onboarding_maps(db: Any) -> tuple[dict[str, str], dict[str, str]]:
    """Each repository's default branch, and how its scans are dispatched.

    Both from the onboarding ledger rather than the lake. The lake only knows
    what a lane happened to scan, which is the thing B-046 checks; and the
    stalled-lane section printed `POST .../scan` for every repository without
    reading `scanned_by`, a request that answers 503 on a Concourse-scanned
    repository unless the deployment holds an API token (#278).
    """
    with db.session() as session:
        rows = session.execute(
            select(
                RepoOnboarding.github_repo_full_name,
                RepoOnboarding.default_branch,
                RepoOnboarding.scanned_by,
            )
        ).all()
    default_branches = {str(name): str(branch or "") for name, branch, _ in rows}
    scanned_by = {str(name): str(how or "") for name, _, how in rows}
    return default_branches, scanned_by


def gather(settings: Any, db: Any, catalog: Any) -> OperationalInputs:
    """Read every non-lake input once. Never raises: each one fails to `None`."""
    found = OperationalInputs()

    # Paused and failing CI jobs (#401, #306): one client, the same endpoint.
    # Kept as two lists because they mean different things -- a paused lane is
    # a decision somebody made, a failing one is a lane nobody has looked at.
    try:
        ci_client = ConcourseClient(
            settings.concourse_url,
            team=settings.concourse_team,
            external_url=settings.concourse_external_url,
        )
        if ci_client.configured:
            paused = ci_client.paused_jobs()
            found.paused_jobs = (
                None
                if paused is None
                else [
                    briefing_report.PausedLane(
                        pipeline=pipeline,
                        job=job.name,
                        last_status=job.status,
                        last_finished_at=job.finished_at,
                        build_url=job.build_url,
                    )
                    for pipeline, job in paused
                ]
            )
            failing = ci_client.failing_jobs()
            found.failing_jobs = (
                None
                if failing is None
                else [
                    briefing_report.FailingLane(
                        pipeline=pipeline,
                        job=job.name,
                        last_status=job.status,
                        last_finished_at=job.finished_at,
                        build_url=job.build_url,
                    )
                    for pipeline, job in failing
                ]
            )
    except Exception:  # noqa: BLE001 - a briefing must not die on CI
        logger.debug("Could not read CI job state")

    # Job health (#409). The assessment belongs to `platform_health`, which
    # the API surface already uses -- a second copy of "is this job late" is a
    # second thing to keep in step.
    try:
        from mykronos import platform_health
        from mykronos.db.models import JobRun
        from mykronos.schemas import utcnow

        now = utcnow()
        with db.session() as session:
            job_rows = list(session.execute(select(JobRun).order_by(JobRun.name)).scalars())
        assessed = [platform_health.assess_job(r, now=now) for r in job_rows]
        found.unhealthy_jobs = [j for j in assessed if j.status not in ("ok", "disabled")]
    except Exception:  # noqa: BLE001 - a briefing must not die on this
        logger.debug("Could not read job health")

    # Ingestion tokens the rotation sweep defers to a person (#263). The one
    # deferral this platform had was visible only in 30 hours of container logs.
    try:
        from mykronos.jobs import deliveries_awaiting_operator

        found.tokens = deliveries_awaiting_operator(db)
    except Exception:  # noqa: BLE001 - a briefing must not die on this
        logger.debug("Could not read token deliveries")

    # Toxic combinations: the same detection and severity the Oracle's risk
    # decision uses, worst first.
    try:
        from mykronos import toxic

        with db.session() as session:
            toxic_found = toxic.detect(catalog, session=session)
        order = {s: i for i, s in enumerate(reversed(toxic.SEVERITIES))}
        toxic_found.sort(key=lambda c: (order.get(c.severity, 9), c.repo_full_name))
        found.toxic_combinations = [c.to_dict() for c in toxic_found]
        found.toxic_coverage = toxic.coverage(catalog)
    except Exception:  # noqa: BLE001 - a briefing must not die on this
        logger.debug("Could not compute toxic combinations")

    # Public endpoints: the last anonymous probe of every registered URL.
    try:
        from mykronos import exposure as exposure_report

        found.exposure = exposure_report.summary(db)
    except Exception:  # noqa: BLE001 - a briefing must not die on this
        logger.debug("Could not read public endpoints")

    return found
