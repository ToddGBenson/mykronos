"""Is the risk gate still deciding anything? (TheHub #60731)

Eight MyKronos deploys in a row, 2026-10-05 to 10-12, shipped with no risk
decision. Each one printed a NOT JUDGED banner in `deploy.ps1` and appended a
line to `deploy-risk-log.jsonl`, and nothing read either across runs. The cause
was one red lane: `lint-and-types` sits upstream of every scan lane, and so of
`oracle-gate`, and Concourse moves a commit on only through `passed:`. Nothing
reached the gate, and a single read of the pipeline's job state would have said
which lane was in the way.

This is that read, done on a schedule. It walks the `mykronos` pipeline's
`source` versions newest first until it finds a commit the gate has decided.
When the oldest commit after that one has been waiting more than the threshold,
it names every job upstream of `oracle-gate` whose latest finished build failed,
errored or is paused. If none is in that state, it says so.

**The clock is the OLDEST unjudged commit, not the newest.** Concourse scores
only the newest commit that passed every lane, so commits it skips stay
unjudged even when main is green. Measuring the head's age would reset the
clock on every merge, and a pipeline that is red all day while people keep
merging would never alarm. The oldest commit after the last decision has been
waiting the whole time.

**The deploy ledger is not read.** `deploy-risk-log.jsonl` lives beside
`deploy.ps1` on the host, and the backend container mounts only its data volume
and the GitHub App key. The ledger's "three unjudged deploys" condition is
therefore not checked here. It measures the same failure later: a deploy is
unjudged because the gate stopped deciding, which is what this checks directly.

Pure apart from the injected `fetch` (one Concourse API path, the same shape
`timeout_audit` takes) and `lookup` (one sha's newest decision, or None). Every
read here is anonymous: the job list carries each job's `inputs[].passed`, so
the upstream graph comes from the live pipeline and not a committed file.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

#: Reads one Concourse API path and returns the parsed JSON. Raises on failure.
Fetch = Callable[[str], Any]
#: The newest risk decision filed against a sha, or None if nothing scored it.
Lookup = Callable[[str], dict[str, Any] | None]

PIPELINE = "mykronos"
GATE_JOB = "oracle-gate"
#: The git resource every lane gets with `passed:`. Its versions are main's
#: commits as Concourse saw them, newest first.
SOURCE_RESOURCE = "source"
#: How far back to look for a decided commit. A window with none in it is
#: reported as such, with the oldest commit in it as a lower bound on the wait.
VERSION_WINDOW = 50
#: The same pair `ConcourseClient.FAILED_STATUSES` uses. `aborted` is somebody
#: cancelling, not a lane that is broken.
RED_STATUSES = frozenset({"failed", "errored"})


@dataclass(frozen=True)
class Lane:
    """One job upstream of the gate that is stopping commits reaching it."""

    job: str
    #: `failed`, `errored`, or `paused`.
    state: str
    build: str | None = None

    def line(self) -> str:
        return f"{self.job} ({self.state}" + (f", build {self.build})" if self.build else ")")


@dataclass
class GateLivenessReport:
    threshold_hours: float
    head: str | None = None
    #: The newest commit, walking back from main's head, with a decision.
    last_judged: str | None = None
    last_judged_verdict: str | None = None
    #: Commits newer than `last_judged`, newest first.
    unjudged: list[str] = field(default_factory=list)
    #: True when no commit in the window had a decision.
    window_exhausted: bool = False
    #: When the pipeline first started a build of the oldest unjudged commit.
    waiting_since: datetime | None = None
    #: Measured against `waiting_since`; None when there is nothing waiting.
    waited_hours: float | None = None
    #: Upstream jobs in the way. Read only when the gate is stale.
    red_lanes: list[Lane] = field(default_factory=list)
    gate_status: str | None = None
    #: Whether the job state was read. False with `stale` means the lane is
    #: unnamed because it could not be read, not because none is red.
    lanes_read: bool = False
    unreadable: list[str] = field(default_factory=list)

    @property
    def stale(self) -> bool:
        return self.waited_hours is not None and self.waited_hours > self.threshold_hours

    @property
    def complete(self) -> bool:
        return not self.unreadable

    @property
    def verdict(self) -> str:
        if self.stale:
            return "stale"
        if not self.complete:
            return "could not check"
        return "live"

    @property
    def signature(self) -> str:
        """What a repeat notification would say. The same signature twice is
        the same news, and an hourly job that re-posts it trains people to
        ignore the channel."""
        oldest = self.unjudged[-1] if self.unjudged else ""
        return f"{oldest}|{','.join(lane.line() for lane in self.red_lanes)}|{self.lanes_read}"

    def lines(self) -> list[str]:
        """The notification body. Only meaningful when `stale`."""
        oldest = (self.unjudged[-1] if self.unjudged else "?")[:12]
        waited = f"{self.waited_hours or 0:.1f}h (threshold {self.threshold_hours:g}h)"
        if self.window_exhausted:
            first = (
                f"None of main's last {len(self.unjudged)} commits has a gate decision; "
                f"the oldest of them, {oldest}, has waited at least {waited}."
            )
        else:
            first = (
                f"main has {len(self.unjudged)} commit(s) newer than the last judged one; "
                f"the oldest, {oldest}, has waited {waited}."
            )
        out = [first]
        if self.last_judged:
            out.append(
                f"Newest judged commit: {self.last_judged[:12]} ({self.last_judged_verdict})."
            )
        if not self.lanes_read:
            out.append(
                f"Could not read the {PIPELINE} job state, so the lane in the way is "
                "not named. That is not the same as none being red."
            )
        elif self.red_lanes:
            out.append(
                f"Upstream of {GATE_JOB}, latest build not green: "
                + "; ".join(lane.line() for lane in self.red_lanes)
                + f". Nothing gets past these to {GATE_JOB}."
            )
        else:
            out.append(
                f"No job upstream of {GATE_JOB} is failing, errored or paused on its "
                f"latest build. {GATE_JOB} itself last finished: {self.gate_status or 'never'}. "
                "Check whether its decision reached the lake."
            )
        out.append("Every deploy of these commits ships unjudged (deploy.ps1 fails open, D-126).")
        return out


def effective_verdict(record: dict[str, Any]) -> str:
    """The recommendation that stands, as `/decisions/by-commit` reports it."""
    recommendation = str(record.get("recommendation") or "?")
    override = record.get("human_override")
    if isinstance(override, dict) and override.get("accepted_recommendation"):
        return f"{override['accepted_recommendation']} (overridden from {recommendation})"
    return recommendation


def upstream_of(jobs: list[dict[str, Any]], target: str) -> list[str]:
    """Every job `target` depends on through `passed:`, transitively, in the
    order Concourse lists them."""
    passed: dict[str, set[str]] = {}
    for job in jobs:
        names: set[str] = set()
        for entry in job.get("inputs") or []:
            if isinstance(entry, dict):
                names.update(str(n) for n in entry.get("passed") or [])
        passed[str(job.get("name"))] = names
    seen: set[str] = set()
    frontier = list(passed.get(target, set()))
    while frontier:
        name = frontier.pop()
        if name in seen:
            continue
        seen.add(name)
        frontier.extend(passed.get(name, set()))
    return [str(job.get("name")) for job in jobs if job.get("name") in seen]


def _first_started(builds: Any) -> datetime | None:
    starts = [
        int(b["start_time"])
        for b in builds or []
        if isinstance(b, dict) and isinstance(b.get("start_time"), int | float) and b["start_time"]
    ]
    return datetime.fromtimestamp(min(starts), tz=UTC) if starts else None


def check(
    fetch: Fetch,
    lookup: Lookup,
    *,
    threshold_hours: float,
    now: datetime,
    team: str = "main",
    pipeline: str = PIPELINE,
) -> GateLivenessReport:
    """Read Concourse and the decision store, and say whether the gate is live.

    Never raises. Anything unread lands in `report.unreadable`, and a report
    with anything there is `could not check` unless it is already `stale`.
    """
    report = GateLivenessReport(threshold_hours=threshold_hours)
    base = f"/api/v1/teams/{team}/pipelines/{pipeline}"
    try:
        versions = fetch(f"{base}/resources/{SOURCE_RESOURCE}/versions?limit={VERSION_WINDOW}")
        if not isinstance(versions, list):
            raise ValueError("not a version list")
    except Exception as exc:  # noqa: BLE001 - recorded, never raised
        report.unreadable.append(f"{pipeline}/{SOURCE_RESOURCE} versions: {exc}")
        return report

    commits: list[tuple[str, Any]] = []
    for entry in versions:
        version = entry.get("version") if isinstance(entry, dict) else None
        ref = version.get("ref") if isinstance(version, dict) else None
        if isinstance(ref, str) and ref:
            commits.append((ref, entry.get("id")))
    if not commits:
        report.unreadable.append(f"{pipeline}/{SOURCE_RESOURCE} has no versions")
        return report
    report.head = commits[0][0]

    waiting: list[tuple[str, Any]] = []
    for sha, version_id in commits:
        try:
            record = lookup(sha)
        except Exception as exc:  # noqa: BLE001 - a lake that cannot answer is not "unjudged"
            report.unreadable.append(f"decision lookup for {sha[:12]}: {exc}")
            return report
        if record is not None:
            report.last_judged = sha
            report.last_judged_verdict = effective_verdict(record)
            break
        waiting.append((sha, version_id))
    else:
        report.window_exhausted = True
    report.unjudged = [sha for sha, _ in waiting]
    if not waiting:
        return report

    # Oldest first: the first of them the pipeline started on is the clock.
    for sha, version_id in reversed(waiting):
        try:
            builds = fetch(
                f"{base}/resources/{SOURCE_RESOURCE}/versions/{version_id}/input_to"
            )
        except Exception as exc:  # noqa: BLE001 - recorded, never raised
            report.unreadable.append(f"builds of {sha[:12]}: {exc}")
            return report
        started = _first_started(builds)
        if started is not None:
            report.waiting_since = started
            report.waited_hours = (now - started).total_seconds() / 3600
            break

    if report.stale:
        _read_lanes(fetch, base, pipeline, report)
    return report


def _read_lanes(fetch: Fetch, base: str, pipeline: str, report: GateLivenessReport) -> None:
    try:
        jobs = fetch(f"{base}/jobs")
        if not isinstance(jobs, list):
            raise ValueError("not a job list")
    except Exception as exc:  # noqa: BLE001 - recorded, never raised
        report.unreadable.append(f"{pipeline} jobs: {exc}")
        return
    jobs = [job for job in jobs if isinstance(job, dict)]
    by_name = {str(job.get("name")): job for job in jobs}
    if GATE_JOB not in by_name:
        report.unreadable.append(f"{pipeline} has no {GATE_JOB} job")
        return
    report.lanes_read = True
    gate_build = by_name[GATE_JOB].get("finished_build")
    report.gate_status = gate_build.get("status") if isinstance(gate_build, dict) else None
    for name in upstream_of(jobs, GATE_JOB):
        job = by_name[name]
        build = job.get("finished_build")
        build = build if isinstance(build, dict) else {}
        status = build.get("status")
        build_name = str(build["name"]) if build.get("name") else None
        if job.get("paused"):
            report.red_lanes.append(Lane(name, "paused", build_name))
        elif status in RED_STATUSES:
            report.red_lanes.append(Lane(name, str(status), build_name))
