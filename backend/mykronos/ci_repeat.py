"""A lane that fails REPEATEDLY on the same cause (#59308).

`ConcourseClient.failing_jobs()` already answers "is this lane red right now".
It cannot answer the question this module exists for: **is this lane stuck?**
A lane that fails once and goes green on the retrigger is a flake, and this
estate has a documented allergy to being told about those. A lane that has
failed three times running on the same cause is not a flake; it is a lane
nobody is going to fix by waiting.

THE THRESHOLD IS MEASURED, NOT CHOSEN.
--------------------------------------
#59308 exists because "two consecutive failures" was a guess, and the story
refused to ship a guess. The measurement behind `REPEAT_THRESHOLD` is 35 days
of real build history read from `fly builds` on 2026-09-17: **5,926 builds
across 79 lanes and four pipelines (thehub, mykronos, personal-soc, keel),
651 of them failing.** Failure causes were attributed per build from the
Concourse build-events API, by blaming the step that actually exited non-zero
and discarding the `on_failure` Slack hook -- whose output is present in every
failing build and which, left in, made every failure look alike.

What a threshold of T would have fired on over those 35 days:

    T   alerts   per week   self-healed on      inside a >=3-lane
                            the very next run   simultaneous stampede
    2     72       14.4       11 (15%)                 13
    3     31        6.2        4 (13%)                  0     <-- chosen
    4     21        4.2        2 (10%)                  0
    5     15        3.0        0 ( 0%)                  0

**T=3 is the smallest threshold at which the stampede contributes nothing.**
That is the whole reason this number is 3 and not 2. #59083 established that
keel's ten jobs all `get: daily` with `trigger: true`, so one version lands
and all ten schedule at the same instant onto two workers. On 2026-09-08 at
17:28 that happened while Vault was sealed, and **ten keel lanes errored
simultaneously on one cause** -- build, compliance-daily, iac, lint,
platform-integrity, sast, sca, secrets, suppression-audit, test. At T=2 that
single incident mints ten alerts. Every one of those streaks is exactly two
builds long: by the third attempt Vault was unsealed and the stampede had
healed itself. T=3 sees none of it.

The knee does not depend on how finely causes are distinguished. Re-running
the measurement with the cause signature taken from one, two and three lines
of failing-step output, and again with no cause key at all, moves the alert
volume but not the knee: the >=3-lane stampede count is 13-17 at T=2 and
**zero at T=3** in every variant.

T=5 is not chosen despite a 0% self-heal rate: going from T=3 to T=5 drops 12
genuine stuck lanes to avoid 4 false ones, and costs two further failed builds
of delay on every real incident.

WHY THE CAUSE KEY HERE IS COARSE, AND WHAT THAT COSTS
-----------------------------------------------------
`ci.py` states a deliberate property: *it reads the job list, never build
logs*, because logs carry scanner output and, until CNC-2 lands, resolved
`((var))` values. Attributing a cause precisely means reading build events,
which carry those same log payloads. **This module does not do that**, and so
its cause key is the coarsest one available from build metadata alone: the
build's status class.

That is not a fudge, it is the axis AC4 of #59308 names -- `errored` (the lane
broke before it reached a verdict) and `failed` (it ran and the answer was
bad) never merge into one streak, because a scanner's honest refusal is not
the same event as a worker losing Vault. It is measurably weaker than a real
cause key, and the cost is recorded rather than glossed: over the same 35
days, the status-class key fires 50 times (10.0/week) where a log-derived
cause key fires 31 (6.2/week), and only 42% of the extra alerts are genuinely
one cause for all three builds.

Closing that gap means relaxing a documented security property, which is the
operator's call and not this module's. It is filed as its own story.

THE CLEAR-CHECK IS SATISFIABLE, AND THAT WAS MEASURED TOO
----------------------------------------------------------
AC2 asks for "a clear-check that can actually be satisfied, so it does not
join the monotonic queues this estate keeps finding". This sweep holds no
state: it reports the streak a lane is in *right now*, recomputed from the
live build list, so an incident stops being reported the moment one build
lands that is not the same kind of failure. Over the measured window, 46 of
50 incidents (92%) cleared, median 4.5 hours from the alert to the clearing
build. The four that never cleared -- mykronos/pin-check red for 24 straight
builds over 48 hours, thehub/functional-dast, mykronos/demo-and-dast,
personal-soc/netassess-ingest -- are precisely the lanes this alert exists to
name.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime

logger = logging.getLogger(__name__)

#: Three consecutive same-class failures. See the module docstring: this is
#: the smallest threshold at which keel's ten-lane Vault stampede of
#: 2026-09-08 contributes zero alerts, measured over 5,926 builds.
REPEAT_THRESHOLD = 3

#: Statuses that mean the lane ran and did not succeed. Deliberately the same
#: pair as `ConcourseClient.FAILED_STATUSES`, and deliberately kept apart from
#: each other as streak keys -- see AC4 in the module docstring.
FAILURE_STATUSES: frozenset[str] = frozenset({"failed", "errored"})

#: Statuses that break a streak without being a failure. `aborted` is somebody
#: cancelling -- a decision with a person behind it, which `ci.py` already
#: refuses to count as a failure. It does not extend a streak and it does not
#: clear one: it is simply not evidence either way, so it is skipped over.
NEUTRAL_STATUSES: frozenset[str] = frozenset({"aborted"})


@dataclass(frozen=True)
class RepeatIncident:
    """One lane, stuck on one kind of failure, right now."""

    pipeline: str
    job: str
    #: "failed" or "errored" -- the cause key, as coarse as build metadata
    #: allows. Never a mixture: see the module docstring.
    cause: str
    #: How many consecutive builds of this lane failed this way. Always >=
    #: the threshold the sweep ran with.
    count: int
    first_build: str | None = None
    last_build: str | None = None
    first_at: datetime | None = None
    last_at: datetime | None = None
    url: str | None = None

    @property
    def key(self) -> tuple[str, str, str]:
        """One incident per lane per cause (AC2). Two sweeps of an unchanged
        lane produce the same key, so a caller deduping on it never mints a
        second alert for a streak it has already reported."""
        return (self.pipeline, self.job, self.cause)

    @property
    def hours(self) -> float | None:
        if self.first_at is None or self.last_at is None:
            return None
        return (self.last_at - self.first_at).total_seconds() / 3600.0


@dataclass(frozen=True)
class RepeatSweep:
    """The result of a sweep, *and what it looked at to get there*.

    `lanes_inspected` and `builds_inspected` are not diagnostics, they are the
    point. This estate's recurring defect is that a control which reports
    nothing looks exactly like a control which reports fine, and a detector
    whose discovery step quietly narrowed to zero lanes returns a blameless
    empty list. Carrying the subject count in the result means a caller -- and
    a test -- can assert a floor on what was examined, so "found nothing"
    cannot be confused with "looked at nothing".
    """

    incidents: list[RepeatIncident]
    #: Every lane the sweep accounted for, including the ones whose latest
    #: build had already succeeded. This is the floor a caller asserts on.
    lanes_inspected: int
    builds_inspected: int
    threshold: int
    #: Lanes whose build history could not be read. Reported, not silently
    #: dropped: an unreadable lane is not a healthy one.
    unreadable: list[str]
    #: Of `lanes_inspected`, how many had their build history fetched. The
    #: rest were ruled out by their latest build having succeeded, which is
    #: sound (a trailing failure streak requires the latest finished build to
    #: be a failure) and is the difference between a 30-second command and a
    #: five-minute one. Recorded separately so the shortcut is auditable
    #: rather than invisible.
    histories_read: int = 0

    @property
    def complete(self) -> bool:
        return not self.unreadable


def _finished(build: dict[str, object]) -> str | None:
    """The status of a build that has finished, or None if it has not.

    A running build is not evidence of anything yet. Treating it as a
    non-failure would clear a real incident the moment a retrigger started,
    which is the one moment the lane is most likely still broken.
    """
    status = build.get("status")
    if not isinstance(status, str):
        return None
    if status in ("started", "pending", "running"):
        return None
    return status


def trailing_streak(
    builds: list[dict[str, object]],
) -> tuple[str, list[dict[str, object]]] | None:
    """The run of same-cause failures a lane is in *right now*, newest first.

    `builds` must be newest-first, which is the order Concourse's
    `/jobs/:job/builds` returns. Returns None if the lane's most recent
    finished build did not fail -- i.e. the lane is not currently stuck.
    """
    ordered = [b for b in builds if _finished(b) not in (None, *NEUTRAL_STATUSES)]
    if not ordered:
        return None
    first = _finished(ordered[0])
    if first not in FAILURE_STATUSES:
        return None
    run: list[dict[str, object]] = []
    for build in ordered:
        if _finished(build) != first:
            break
        run.append(build)
    return str(first), run


def _at(build: dict[str, object]) -> datetime | None:
    raw = build.get("start_time") or build.get("end_time")
    if isinstance(raw, int | float) and raw:
        return datetime.fromtimestamp(int(raw), tz=UTC)
    return None


def incident_for(
    pipeline: str,
    job: str,
    builds: list[dict[str, object]],
    *,
    threshold: int = REPEAT_THRESHOLD,
    pipeline_url: str = "",
) -> RepeatIncident | None:
    """The incident this lane is in, or None if it is not stuck."""
    streak = trailing_streak(builds)
    if streak is None:
        return None
    cause, run = streak
    if len(run) < threshold:
        return None
    newest, oldest = run[0], run[-1]
    return RepeatIncident(
        pipeline=pipeline,
        job=job,
        cause=cause,
        count=len(run),
        first_build=str(oldest.get("name")) if oldest.get("name") else None,
        last_build=str(newest.get("name")) if newest.get("name") else None,
        first_at=_at(oldest),
        last_at=_at(newest),
        url=f"{pipeline_url}/jobs/{job}" if pipeline_url else None,
    )


def sweep(
    client: object,
    *,
    threshold: int = REPEAT_THRESHOLD,
    history: int = 10,
) -> RepeatSweep | None:
    """Every lane across every pipeline that is stuck on one cause right now.

    `None` -- never an empty sweep -- when Concourse cannot be reached at all,
    for the reason `failing_jobs()` gives: "nothing is stuck" and "could not
    ask" must not render the same.

    `history` is how many recent builds each lane is asked for. It must exceed
    the threshold or the sweep can never see a streak long enough to fire,
    which is checked rather than assumed: that mistake is invisible in the
    output -- it just reports nothing, forever.
    """
    if threshold < 2:
        raise ValueError(f"a threshold below 2 is not a repeat: {threshold!r}")
    if history <= threshold:
        raise ValueError(
            f"history={history} cannot observe a streak of {threshold}; "
            "it would silently never fire"
        )

    pipelines = client.pipelines()  # type: ignore[attr-defined]
    if pipelines is None:
        return None

    incidents: list[RepeatIncident] = []
    unreadable: list[str] = []
    lanes = 0
    seen_builds = 0
    histories = 0
    for pipeline in pipelines:
        jobs = client.job_last_statuses(pipeline)  # type: ignore[attr-defined]
        if jobs is None:
            unreadable.append(pipeline)
            continue
        for job, last in sorted(jobs.items()):
            lanes += 1
            # A trailing failure streak requires the latest finished build to
            # be a failure, so a lane that is green right now cannot be in
            # one and its history need not be fetched. `aborted` and "never
            # finished a build" are NOT ruled out: an abort does not clear a
            # streak, so the failure underneath it still counts.
            if last is not None and last not in FAILURE_STATUSES | NEUTRAL_STATUSES:
                continue
            builds = client.job_builds(pipeline, job, limit=history)  # type: ignore[attr-defined]
            if builds is None:
                unreadable.append(f"{pipeline}/{job}")
                continue
            histories += 1
            seen_builds += len(builds)
            found = incident_for(
                pipeline,
                job,
                builds,
                threshold=threshold,
                pipeline_url=client.pipeline_url(pipeline),  # type: ignore[attr-defined]
            )
            if found is not None:
                incidents.append(found)

    incidents.sort(key=lambda i: (-i.count, i.pipeline, i.job))
    return RepeatSweep(
        incidents=incidents,
        lanes_inspected=lanes,
        builds_inspected=seen_builds,
        threshold=threshold,
        unreadable=unreadable,
        histories_read=histories,
    )


def render(result: RepeatSweep | None) -> str:
    """Plain text for the CLI. States what was inspected even when nothing was
    found, so an empty answer is readable as an answer rather than a shrug."""
    if result is None:
        return "Concourse could not be reached, so no lane was checked for repeat failures."

    lines: list[str] = []
    if not result.incidents:
        lines.append(
            f"No lane has failed {result.threshold} times running on the same "
            f"cause ({result.lanes_inspected} lanes, {result.histories_read} "
            f"histories read, {result.builds_inspected} builds inspected)."
        )
    else:
        plural = "" if len(result.incidents) == 1 else "s"
        lines.append(
            f"{len(result.incidents)} lane{plural} stuck on one cause for "
            f"{result.threshold}+ consecutive builds ({result.lanes_inspected} "
            f"lanes, {result.histories_read} histories read, "
            f"{result.builds_inspected} builds inspected):"
        )
        for inc in result.incidents:
            span = "" if inc.hours is None else f", {inc.hours:.1f}h"
            lines.append(
                f"  {inc.pipeline}/{inc.job}  {inc.cause} x{inc.count} "
                f"(builds {inc.first_build}..{inc.last_build}{span})"
            )
            if inc.url:
                lines.append(f"      {inc.url}")

    if result.unreadable:
        plural = "" if len(result.unreadable) == 1 else "s"
        named = ", ".join(sorted(result.unreadable))
        lines.append(
            f"Could not read {len(result.unreadable)} lane{plural}, "
            f"so this answer is partial: {named}"
        )
    if result.lanes_inspected == 0:
        lines.append(
            "WARNING: no lane was inspected at all. This is a broken sweep, not a clean estate."
        )
    return "\n".join(lines)
