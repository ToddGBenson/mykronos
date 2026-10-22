"""Is the platform itself working?

This platform tells four repositories what is wrong with them, and had no
surface saying whether it was itself running. Everything it needed was already
being computed — `self_check` probes ingestion, Vault and Concourse, and every
scheduled job passes through one runner — and all of it went to a log file
nobody tails.

**A caught failure is the quiet kind.** `_every` catches every exception, logs
it, and retries on the next tick. That is the right behaviour and it means a
job which has thrown on every run for a fortnight is indistinguishable, from
outside, from one that has never had a problem.

**And the jobs whose silence matters most are the ones nothing else notices.**
If `reconcile-absences` stops, findings never close and every count on every
page drifts wrong in the reassuring direction — the same failure this codebase
keeps writing about in CI lanes, happening inside the platform instead. If
`acceptances` stops, an acceptance past its review date stays accepted for
ever. Neither raises anything anywhere; both look like a quiet week.

**Late is not the same as failing, and neither is the same as never having
run.** Three states, kept apart, because they need three different things done
about them: a job that is failing has an error to read, a job that is late has
a scheduler to check, and a job that has never run is a deployment that came up
without it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Literal

#: How far past its interval a job may drift before it is called late. Two
#: whole intervals, not one: a job that runs on a timer inside a process which
#: also serves requests will sometimes be a little behind, and a health page
#: that cries wolf on ordinary jitter is a health page people stop reading.
LATENESS_FACTOR = 2

Status = Literal["ok", "failing", "late", "never_ran", "unknown", "disabled", "skipped"]


@dataclass
class JobHealth:
    name: str
    status: Status
    detail: str
    last_succeeded_at: datetime | None = None
    consecutive_failures: int = 0


@dataclass
class DependencyHealth:
    name: str
    reachable: bool
    detail: str
    #: Whether this deployment has the dependency at all (B-014). One that is
    #: not configured is not one that failed, and does not degrade the page.
    configured: bool = True


@dataclass
class PlatformHealth:
    jobs: list[JobHealth] = field(default_factory=list)
    dependencies: list[DependencyHealth] = field(default_factory=list)

    @property
    def degraded(self) -> bool:
        """Anything a person should look at.

        `never_ran` is deliberately not degraded on its own: a job whose
        interval has not elapsed since this process started has not run and is
        not a problem, and the first minutes after every deploy would otherwise
        be red.
        """
        return any(job.status in ("failing", "late") for job in self.jobs) or any(
            dependency.configured and not dependency.reachable
            for dependency in self.dependencies
        )


def assess_ingestion(
    result: Any, *, hours_since_actions_upload: float | None
) -> DependencyHealth:
    """Is ingestion serving, judged by what it serves (TheHub #60905)?

    The probe asks the public URL from inside this network, and a host here
    cannot reach its own public hostname: hairpin NAT, measured 2026-09-12
    (`jobs.reachability_alert`). So on this host the probe fails on every
    load, and MyKronos Health read "Needs attention" permanently while GitHub
    runners - which reach this platform only through that URL - kept
    uploading.

    What ingestion serves is uploads. A scan run carrying a workflow run id
    came from a GitHub-hosted runner, through the public URL, so one inside
    `ACTIONS_UPLOAD_GRACE_HOURS` is evidence the in-network probe cannot give,
    and it outweighs that probe. Without it the probe's failure stands: no
    upload in the window, or no way to tell, is not permission to reassure.
    """
    from mykronos.jobs import ACTIONS_UPLOAD_GRACE_HOURS

    if result.reachable:
        return DependencyHealth(name="ingestion", reachable=True, detail=result.detail)
    if (
        hours_since_actions_upload is not None
        and hours_since_actions_upload <= ACTIONS_UPLOAD_GRACE_HOURS
    ):
        return DependencyHealth(
            name="ingestion",
            reachable=True,
            detail=(
                "Serving: a GitHub Actions scan run landed "
                f"{hours_since_actions_upload:.1f}h ago, and a GitHub runner can "
                "only reach this platform through its public URL. The probe from "
                "inside this network fails because of hairpin NAT, not an outage."
            ),
        )
    if hours_since_actions_upload is None:
        why = " No GitHub Actions upload on record, so nothing corroborates either way."
    else:
        why = (
            f" No GitHub Actions upload for {hours_since_actions_upload:.1f}h, "
            "which is consistent with an outage."
        )
    return DependencyHealth(name="ingestion", reachable=False, detail=result.detail + why)


def assess_job(row: Any, *, now: datetime, started_at: datetime | None = None) -> JobHealth:
    """One job's state, from its stored row.

    `started_at` is when this process came up. Without it a job with a
    twenty-four hour interval reads as `late` for the first day after every
    deploy, which would make the health page wrong precisely when somebody is
    most likely to look at it.
    """
    failures = int(row.consecutive_failures or 0)
    interval = int(row.interval_seconds or 0)
    last_success = row.last_succeeded_at

    if getattr(row, "scheduled", True) is False:
        # Switched off in this deployment. Its history stays readable, but a
        # job nobody runs is not late: it is a decision, not a fault.
        return JobHealth(
            name=row.name,
            status="disabled",
            detail="not scheduled in this deployment",
            last_succeeded_at=last_success,
        )

    if failures:
        return JobHealth(
            name=row.name,
            status="failing",
            detail=(
                f"{failures} consecutive failure{'s' if failures != 1 else ''}"
                + (f": {row.last_error}" if row.last_error else "")
            ),
            last_succeeded_at=last_success,
            consecutive_failures=failures,
        )

    skipped = getattr(row, "skipped_reason", "") or ""
    if skipped:
        # Due, and did nothing, for a reason somebody has to act on - the
        # briefing DM with no Slack configured for it (TheHub #60864). Not
        # `ok`, which would be the silent success this page exists against,
        # and not `failing`: nothing broke.
        return JobHealth(
            name=row.name,
            status="skipped",
            detail=f"skipped: {skipped}",
            last_succeeded_at=last_success,
        )

    if last_success is None:
        # Not yet late if its interval has not come round since start-up.
        if started_at is not None and interval:
            due = started_at + timedelta(seconds=interval * LATENESS_FACTOR)
            if now < due:
                return JobHealth(
                    name=row.name,
                    status="ok",
                    detail="has not been due since this process started",
                )
        return JobHealth(
            name=row.name,
            status="never_ran",
            detail="no successful run on record",
        )

    if interval:
        overdue = last_success + timedelta(seconds=interval * LATENESS_FACTOR)
        if now > overdue:
            late_by = now - last_success
            return JobHealth(
                name=row.name,
                status="late",
                detail=(
                    f"last succeeded {_ago(late_by)} ago, runs every "
                    f"{_duration(interval)}"
                ),
                last_succeeded_at=last_success,
            )

    return JobHealth(
        name=row.name,
        status="ok",
        detail=f"last succeeded {_ago(now - last_success)} ago",
        last_succeeded_at=last_success,
    )


def mark_scheduled(db: Any, names: list[str]) -> None:
    """Record which jobs this deployment runs; every other row is disabled.

    Rows are updated, never created: a job that has not run yet has no row,
    and gets one - scheduled - on its first tick.
    """
    from sqlalchemy import select

    from mykronos.db.models import JobRun

    wanted = set(names)
    with db.session() as session:
        for row in session.execute(select(JobRun)).scalars():
            row.scheduled = row.name in wanted


def _duration(seconds: int) -> str:
    if seconds >= 86_400:
        days = seconds // 86_400
        return f"{days} day{'s' if days != 1 else ''}"
    if seconds >= 3_600:
        hours = seconds // 3_600
        return f"{hours} hour{'s' if hours != 1 else ''}"
    minutes = max(seconds // 60, 1)
    return f"{minutes} minute{'s' if minutes != 1 else ''}"


def _ago(delta: timedelta) -> str:
    return _duration(int(delta.total_seconds()))
