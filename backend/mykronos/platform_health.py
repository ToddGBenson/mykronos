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

Status = Literal["ok", "failing", "late", "never_ran", "unknown"]


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
            not dependency.reachable for dependency in self.dependencies
        )


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
