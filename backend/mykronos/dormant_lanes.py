"""Which Concourse lanes have been off or red for days, across every pipeline.

Paused and failing lanes are already listed in two places. `agent_work` lists
`ci_job_paused` items, and `mykronos briefing` reports paused lanes. Both only
answer when somebody asks. Four security lanes sat paused for thirty-two days
(#401), and `netassess-ingest` failed on its timer for five weeks before
anybody did. A lane that is off is silent by construction, so nothing in the
lane can report it.

This is the push. One daily notification lists every job, in every pipeline
visible anonymously, that is:

* **paused** for longer than the threshold, measured from Concourse's
  `paused_at`. A paused job with no `paused_at` is listed with "since unknown"
  rather than dropped, because it is still switched off;
* **paused as a whole pipeline** for longer than the threshold;
* **red**: not paused, its last finished build `failed` or `errored`, and red
  for longer than the threshold. The clock starts at Concourse's
  `transition_build`, the build where the job last changed status, so a lane
  that has failed every hour for a week counts from a week ago, not from its
  last failure. Without a transition build, the last finished build is the
  clock.

`aborted` is not red, for `ConcourseClient.FAILED_STATUSES`'s reason: an abort
is somebody cancelling.

"Dormant", not "stale": `briefing.stale_lanes` (B-046) already means a green
lane scanning a commit that stopped moving, which is a different failure.

Pure apart from the injected client. That is `ConcourseClient` in production,
which reads anonymously and returns None for anything it could not read. A
pipeline that could not be read is listed as unreadable, never as clean.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

#: The same pair `ConcourseClient.FAILED_STATUSES` and `gate_liveness` use.
RED_STATUSES = frozenset({"failed", "errored"})


class LaneSource(Protocol):
    """The reads this module needs. `ConcourseClient` provides all three."""

    def pipeline_records(self) -> list[dict[str, Any]] | None: ...

    def jobs(self, pipeline: str) -> list[dict[str, Any]] | None: ...

    def pipeline_url(self, pipeline: str) -> str: ...


@dataclass(frozen=True)
class DormantLane:
    pipeline: str
    #: Empty for a paused pipeline, which is a lane-sized fact one level up.
    job: str
    #: `paused`, `pipeline paused`, `failed` or `errored`.
    state: str
    #: When it went into this state. None means Concourse did not say.
    since: datetime | None
    build: str | None = None
    url: str = ""

    def line(self, now: datetime) -> str:
        where = f"{self.pipeline}/{self.job}" if self.job else self.pipeline
        if self.since is None:
            age = "since unknown"
        else:
            days = (now - self.since).total_seconds() / 86_400
            age = f"for {days:.1f} days (since {self.since:%Y-%m-%d %H:%M} UTC)"
        build = f", last build {self.build}" if self.build else ""
        link = f" {self.url}" if self.url else ""
        return f"{where}: {self.state} {age}{build}.{link}"


@dataclass
class DormantLanesReport:
    threshold_hours: float
    lanes: list[DormantLane] = field(default_factory=list)
    pipelines_read: list[str] = field(default_factory=list)
    unreadable: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return not self.unreadable

    def lines(self, now: datetime) -> list[str]:
        out = [lane.line(now) for lane in self.lanes]
        if self.unreadable:
            out.append(
                "Could not read: " + "; ".join(self.unreadable)
                + ". These were not checked, which is not the same as clean."
            )
        return out


def _epoch(value: Any) -> datetime | None:
    # Concourse sends epoch seconds, and a large negative sentinel for a build
    # that has not ended.
    if isinstance(value, bool) or not isinstance(value, int | float) or value <= 0:
        return None
    return datetime.fromtimestamp(value, tz=UTC)


def _build(raw: Any) -> dict[str, Any]:
    return raw if isinstance(raw, dict) else {}


def _red_since(job: dict[str, Any]) -> datetime | None:
    finished = _build(job.get("finished_build"))
    transition = _build(job.get("transition_build"))
    # The transition build is the first build of the current status. It counts
    # only when it has that status too: otherwise it describes another run.
    if transition.get("status") == finished.get("status"):
        since = _epoch(transition.get("end_time")) or _epoch(transition.get("start_time"))
        if since is not None:
            return since
    return _epoch(finished.get("end_time")) or _epoch(finished.get("start_time"))


def find(source: LaneSource, *, now: datetime, threshold_hours: float) -> DormantLanesReport:
    """Every lane off or red for longer than `threshold_hours`. Never raises."""
    report = DormantLanesReport(threshold_hours=threshold_hours)
    limit = threshold_hours * 3600

    def old(since: datetime | None) -> bool:
        return since is None or (now - since).total_seconds() > limit

    pipelines = source.pipeline_records()
    if pipelines is None:
        report.unreadable.append("the Concourse pipeline list")
        return report

    for record in pipelines:
        if not isinstance(record, dict) or not record.get("name"):
            continue
        name = str(record["name"])
        url = source.pipeline_url(name)
        if record.get("paused"):
            since = _epoch(record.get("paused_at"))
            if old(since):
                report.lanes.append(DormantLane(name, "", "pipeline paused", since, url=url))
        jobs = source.jobs(name)
        if jobs is None:
            report.unreadable.append(f"{name} jobs")
            continue
        report.pipelines_read.append(name)
        for job in jobs:
            if not isinstance(job, dict) or not job.get("name"):
                continue
            job_name = str(job["name"])
            finished = _build(job.get("finished_build"))
            build = str(finished["name"]) if finished.get("name") else None
            job_url = f"{url}/jobs/{job_name}"
            if job.get("paused"):
                since = _epoch(job.get("paused_at"))
                if old(since):
                    report.lanes.append(
                        DormantLane(name, job_name, "paused", since, build, job_url)
                    )
                continue
            status = finished.get("status")
            if status in RED_STATUSES:
                since = _red_since(job)
                # A red build with no timestamps at all is not evidence of
                # age. It is left for the next day's read, not guessed at.
                if since is not None and old(since):
                    report.lanes.append(
                        DormantLane(name, job_name, str(status), since, build, job_url)
                    )
    report.lanes.sort(key=lambda lane: (lane.since or datetime.min.replace(tzinfo=UTC)))
    return report
