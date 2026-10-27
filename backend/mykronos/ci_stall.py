"""Is Concourse stalled? Many lanes erroring together (TheHub #60975).

After a host or Docker restart the workers die on a stale cgroup and jobs
across the estate go `errored`. A sealed Vault has its own checks; a dead
worker has none, and the worker list is not readable anonymously. So the
stall is inferred from what *is* readable without a credential: the job
summaries, one request for the whole estate, each carrying its latest
finished build.

Every existing signal misses it. `platform_health` probes reachability, and a
Concourse whose every build errors is reachable. `ci_repeat` fires per lane,
after three builds of that lane. `dormant_lanes` waits 72 hours. A stall is
none of those: it is many lanes failing at once, on one cause that is not in
any of them.

THE RULE
--------
Red when at least `STALL_THRESHOLD` unpaused jobs have a latest finished
build that is `errored` and whose start times fit inside one
`STALL_WINDOW`. Otherwise green.

* **`errored`, never `failed`.** `failed` is a lane that ran and got a bad
  answer; a dead worker produces `errored`, a build that never reached a
  verdict. Mixing them would turn three honest scanner failures into a
  platform alarm.
* **Paused jobs do not count.** A paused job keeps its last build for ever,
  so a lane paused after erroring weeks ago would otherwise be a permanent
  member of every cluster.
* **`aborted` does not count.** Somebody cancelled it.
* **Together, not merely many.** The precedent is the keel stampede in
  `ci_repeat`'s docstring: ten lanes errored in the same minute. Two errored
  lanes twelve days apart -- the estate on 2026-10-22 -- are two unrelated
  lanes, and this reads green on them.

"Could not ask" is not green. With no Concourse configured, or the job list
unreadable, the status is `unknown`.

ONE NOTIFICATION PER EPISODE
----------------------------
An episode opens on the first red evaluation and closes on the next green
one, and is a row in `ci_stall_episodes`, so a restart does not forget it.
The notice is sent once per episode. It is marked sent only when the
notifier says it was delivered: a Slack that is not configured, or refuses
the post, leaves the episode unsent and the job says so (TheHub #59331 -
silence must never read as a delivered alert).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from sqlalchemy import select

from mykronos.db.models import CiStallEpisode

#: How many lanes erroring together make a stall. The smallest number that
#: is not a coincidence of two: the estate routinely carries one or two
#: errored lanes (a paused experiment, a flaky DAST target), and a stall
#: takes everything a worker was running.
STALL_THRESHOLD = 3

#: How close together their start times must be. A restart's stampede lands
#: within minutes (keel's ten lanes at 17:28 on 2026-09-08); an hour leaves
#: room for lanes on slower timers without merging unrelated days.
STALL_WINDOW = timedelta(minutes=60)

#: What to do, in order. Fixed text: the same three things every time, and
#: the order is the order that works - a re-trigger onto a dead worker or a
#: sealed Vault only errors again.
CHECKLIST: tuple[str, ...] = (
    "Restart the Concourse workers",
    "Check Vault is unsealed",
    "Re-trigger the errored jobs",
)

StallStatus = Literal["red", "green", "unknown"]

#: `link(team, pipeline, job, build)`: a browser URL for one build, or None.
Link = Callable[[str, str, str, str], str | None]


@dataclass(frozen=True)
class ErroredJob:
    pipeline: str
    job: str
    build: str | None
    started_at: datetime
    #: A link a browser can open, or None (`ci.browser_url`: never loopback).
    url: str | None = None


@dataclass(frozen=True)
class CiStall:
    status: StallStatus
    detail: str
    #: When red, the lanes in the window. Otherwise every unpaused lane whose
    #: latest build errored, so a green answer still shows what it weighed.
    jobs: list[ErroredJob] = field(default_factory=list)
    jobs_inspected: int = 0
    window_start: datetime | None = None
    window_end: datetime | None = None

    @property
    def red(self) -> bool:
        return self.status == "red"

    @property
    def key(self) -> str:
        """The episode's name: when its window opened."""
        return self.window_start.isoformat() if self.window_start else ""


def unknown(detail: str) -> CiStall:
    return CiStall(status="unknown", detail=detail)


def _epoch(value: object) -> datetime | None:
    if isinstance(value, int | float) and not isinstance(value, bool) and value > 0:
        return datetime.fromtimestamp(int(value), tz=UTC)
    return None


def errored_jobs(
    payload: list[dict[str, Any]],
    *,
    link: Link | None = None,
) -> tuple[list[ErroredJob], int]:
    """Unpaused jobs whose latest finished build errored, oldest first, and
    how many jobs were looked at.

    `link(team, pipeline, job, build)` builds a browser URL or returns None.
    A build with no start time cannot be placed in a window and is left out.
    """
    out: list[ErroredJob] = []
    inspected = 0
    for raw in payload:
        if not isinstance(raw, dict) or "name" not in raw:
            continue
        inspected += 1
        if raw.get("paused"):
            continue
        build = raw.get("finished_build")
        if not isinstance(build, dict) or build.get("status") != "errored":
            continue
        started = _epoch(build.get("start_time"))
        if started is None:
            continue
        pipeline = str(raw.get("pipeline_name") or "")
        job = str(raw["name"])
        name = str(build["name"]) if build.get("name") else None
        url = (
            link(str(raw.get("team_name") or ""), pipeline, job, name)
            if link is not None and name
            else None
        )
        out.append(
            ErroredJob(pipeline=pipeline, job=job, build=name, started_at=started, url=url)
        )
    out.sort(key=lambda j: (j.started_at, j.pipeline, j.job))
    return out, inspected


def _densest_window(jobs: list[ErroredJob]) -> list[ErroredJob]:
    """The most jobs whose start times fit in one `STALL_WINDOW`; on a tie,
    the latest such group. `jobs` is oldest first."""
    best: list[ErroredJob] = []
    left = 0
    for right, job in enumerate(jobs):
        while job.started_at - jobs[left].started_at > STALL_WINDOW:
            left += 1
        group = jobs[left : right + 1]
        if len(group) >= len(best):
            best = group
    return best


def assess(
    payload: list[dict[str, Any]],
    *,
    link: Link | None = None,
) -> CiStall:
    """Red or green, from the anonymous job summaries (`/api/v1/jobs`)."""
    errored, inspected = errored_jobs(payload, link=link)
    window = _densest_window(errored)
    minutes = int(STALL_WINDOW.total_seconds() // 60)
    if len(window) >= STALL_THRESHOLD:
        return CiStall(
            status="red",
            detail=(
                f"Concourse is stalled: {len(window)} lanes errored within "
                f"{minutes} minutes of each other. That is a worker or Vault, "
                "not the lanes."
            ),
            jobs=window,
            jobs_inspected=inspected,
            window_start=window[0].started_at,
            window_end=window[-1].started_at,
        )
    if not errored:
        detail = f"No unpaused lane's latest build errored ({inspected} jobs read)."
    else:
        detail = (
            f"{len(errored)} unpaused lane(s) errored, at most {len(window)} within "
            f"{minutes} minutes of each other; a stall takes {STALL_THRESHOLD} "
            f"({inspected} jobs read)."
        )
    return CiStall(status="green", detail=detail, jobs=errored, jobs_inspected=inspected)


def open_episode(session: Any) -> CiStallEpisode | None:
    row: CiStallEpisode | None = session.execute(
        select(CiStallEpisode)
        .where(CiStallEpisode.cleared_at.is_(None))
        .order_by(CiStallEpisode.opened_at.desc())
    ).scalars().first()
    return row


def observe(db: Any, stall: CiStall, *, now: datetime) -> CiStallEpisode | None:
    """Record one evaluation; return the open episode when red.

    Red with an episode open continues it. Red with none opens one. Green
    closes whatever is open, so the next red is a new episode. `unknown`
    changes nothing: not being able to ask is no evidence either way.
    """
    stamp = now.astimezone(UTC).replace(tzinfo=None)
    with db.session() as session:
        current = open_episode(session)
        if stall.status == "green":
            if current is not None:
                current.cleared_at = stamp
            return None
        if stall.status != "red":
            return current
        if current is None:
            current = CiStallEpisode(key=stall.key, opened_at=stamp)
            session.add(current)
        current.jobs = [f"{j.pipeline}/{j.job}" for j in stall.jobs]
        session.flush()
        return current


def mark_notified(db: Any, episode_id: str, *, now: datetime) -> None:
    with db.session() as session:
        row = session.get(CiStallEpisode, episode_id)
        if row is not None:
            row.notified_at = now.astimezone(UTC).replace(tzinfo=None)


def notice_lines(stall: CiStall) -> list[str]:
    """The Slack message body: one line per lane, then the checklist."""
    lines = [stall.detail]
    for job in stall.jobs:
        when = job.started_at.strftime("%Y-%m-%d %H:%M UTC")
        build = f" #{job.build}" if job.build else ""
        lines.append(
            f"- {job.pipeline}/{job.job}{build} errored, started {when}"
            + (f" {job.url}" if job.url else "")
        )
    lines.append("Do, in order:")
    lines.extend(f"{n}. {step}" for n, step in enumerate(CHECKLIST, start=1))
    lines.append("One notice per stall. MyKronos Health shows it until it clears.")
    return lines
