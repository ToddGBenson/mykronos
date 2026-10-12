"""Every configured task timeout against what the job has actually taken.

PS-7 says the numbers come from measurement, "comfortably above the worst
observed run", not from a target. A cap below the observed worst case does not
make a slow job fast, it makes a working job red.

The audit itself, with no I/O of its own: the caller hands it a `fetch` that
reads one Concourse API path. Two callers exist. `scripts/audit_pipeline_timeouts.py`
is the by-hand run and prints the report; the `timeout-audit` scheduled job in
`mykronos.jobs` is the daily run against live Concourse (TheHub #60729). It
lives in the package rather than the script because the scheduled job runs in
the backend image, which carries the package and not `scripts/`.

**An audit that could not read is not a clean audit.** It used to print "could
not read" beside a pipeline and then, with nothing observed, finish on "every
cap clears its observed worst run with margin" and exit 0 -- the same sentence
and the same exit code as a genuinely healthy estate. Everything unread is now
recorded in `TimeoutAuditReport.unreadable`, and a report with anything in it
is `could not audit`, never clean.
"""

from __future__ import annotations

import math
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

#: Reads one Concourse API path and returns the parsed JSON. Raises on any
#: failure; the audit records the failure rather than propagating it.
Fetch = Callable[[str], Any]

HOOKS = {"preflight", "report-to-hub", "notify-slack"}
#: A failed build within this fraction of its cap is a timeout signature.
#: Not proof -- a job can fail at minute 59 of a 60m cap for its own reasons --
#: but it is the one sample the "worst SUCCESSFUL run" metric can never see,
#: and the jobs that matter most here are exactly the ones that never succeed.
TIMEOUT_MARGIN = 0.95

#: A cap must clear its job's worst observed run by at least this much. It is
#: the audit's pass threshold and it is also the floor used when SETTING a cap,
#: so a number chosen to satisfy this check is not one the check re-flags.
HEADROOM_FLOOR = 1.3

#: How far above its own routine worst a job's outlier run actually sits,
#: measured rather than assumed: the 90th percentile of `worst / p90` across
#: every job in the estate with at least ten successful builds.
#:
#: MEASURED 2026-09-18 over 53 such jobs: p50 2.65x, p75 4.02x, p90 5.10x,
#: p95 5.21x, max 8.16x. Recorded here because it is what the caps raised by
#: #60002 were derived from -- `cap >= max(p90 x OUTLIER_RATIO, worst x
#: HEADROOM_FLOOR)` -- and a derivation nobody can re-run is a round number
#: with a story attached. Re-measure it before leaning on it again; the estate
#: it describes is four pipelines whose jobs change.
OUTLIER_RATIO = 5.10

#: OUTLIER_RATIO was measured over jobs with at least this many successful
#: builds, so `suggested_cap` only applies it to such jobs. Below it, a p90 is
#: the worst run under another name and multiplying it by 5.1 is not a
#: measurement.
OUTLIER_MIN_SAMPLES = 10

#: Suggested caps round UP to this many minutes. Rounding up keeps the
#: suggestion above `worst x HEADROOM_FLOOR`, so it is never one the audit
#: would flag again the next day.
SUGGESTION_STEP_MINUTES = 5

#: `(pipeline, job)` -> why this job is flagged and is NOT being given a bigger
#: cap. A waiver, not a suppression: the job still appears in the report, with
#: this reason beside it, and the run still says what it found.
#:
#: The bar for an entry is that raising the cap would be the WRONG FIX, not
#: that raising it is inconvenient. A cap exists to stop a hung task holding a
#: worker, so a hang is precisely the case where a bigger number makes things
#: worse: the job fails either way and burns the difference.
#:
#: `test_timeout_audit.py` holds these to the same rule
#: `ACKNOWLEDGED_UNMAPPED_JOBS` is held to -- every waiver must name a job that
#: exists in a pipeline file. A waiver outliving its job starts excusing a
#: future job that reuses the name.
#:
#: Empty since #60653. Its one entry waived `thehub/insider` (build #25 hung
#: at an SSH host-key prompt, fixed by #496/#499), and that job is deleted.
TIMEOUT_WAIVERS: dict[tuple[str, str], str] = {}


def observed_label(kind: str) -> str:
    """What the minutes beside a problem actually measure.

    Every row used to say "worst successful", including rows whose number came
    from a FAILED build that ran to its cap. Those are opposite facts and the
    reader acts on them differently.
    """
    return "worst successful" if kind == "headroom" else "a failed build ran"


def seconds(text: str) -> int | None:
    total, found = 0, False
    for value, unit in re.findall(r"(\d+)([hms])", text):
        total += int(value) * {"h": 3600, "m": 60, "s": 1}[unit]
        found = True
    return total if found else None


def to_minutes(text: str) -> int | None:
    value = seconds(text)
    return value // 60 if value is not None else None


def walk(node: Any, visit: Callable[[dict[str, Any]], None]) -> None:
    if isinstance(node, dict):
        visit(node)
        for value in node.values():
            walk(value, visit)
    elif isinstance(node, list):
        for value in node:
            walk(value, visit)


def p90(durations: list[int]) -> int | None:
    """Nearest-rank 90th percentile, or None for no samples."""
    if not durations:
        return None
    ordered = sorted(durations)
    return ordered[max(0, math.ceil(0.9 * len(ordered)) - 1)]


def suggested_cap(observed_seconds: int, successes: list[int]) -> int:
    """The job cap, in minutes, the #60002 derivation gives for this history.

    `max(p90 x OUTLIER_RATIO, observed x HEADROOM_FLOOR)`, rounded up to
    SUGGESTION_STEP_MINUTES. `observed_seconds` is the worst successful run
    for a headroom finding and the longest clock-killed build for a timeout
    finding -- a lower bound in that case, since the cap is what ended it.
    """
    floor = observed_seconds / 60 * HEADROOM_FLOOR
    routine = p90(successes) if len(successes) >= OUTLIER_MIN_SAMPLES else None
    if routine is not None:
        floor = max(floor, routine / 60 * OUTLIER_RATIO)
    step = SUGGESTION_STEP_MINUTES
    return max(step, math.ceil(floor / step) * step)


@dataclass(frozen=True)
class Problem:
    pipeline: str
    job: str
    cap: int
    observed_minutes: int
    kind: str
    suggested_cap: int

    def line(self) -> str:
        return (
            f"{self.pipeline}/{self.job}: cap {self.cap}m vs "
            f"{observed_label(self.kind)} {self.observed_minutes}m, "
            f"suggest {self.suggested_cap}m"
        )


@dataclass
class TimeoutAuditReport:
    problems: list[Problem] = field(default_factory=list)
    #: Every pipeline or job whose history could not be read, with why.
    unreadable: list[str] = field(default_factory=list)
    pipelines: list[str] = field(default_factory=list)
    capped_jobs: int = 0

    @property
    def waived(self) -> list[Problem]:
        return [p for p in self.problems if (p.pipeline, p.job) in TIMEOUT_WAIVERS]

    @property
    def unwaived(self) -> list[Problem]:
        return [p for p in self.problems if (p.pipeline, p.job) not in TIMEOUT_WAIVERS]

    @property
    def complete(self) -> bool:
        """Whether every capped job's history was read. False is never clean."""
        return not self.unreadable

    @property
    def verdict(self) -> str:
        if self.unwaived:
            return "caps to raise"
        if not self.complete:
            return "could not audit"
        return "clean"


@dataclass
class _History:
    worst: dict[str, int] = field(default_factory=dict)
    successes: dict[str, list[int]] = field(default_factory=dict)
    failed: dict[str, list[int]] = field(default_factory=dict)


def _observed(fetch: Fetch, team: str, pipeline: str, report: TimeoutAuditReport,
              emit: Callable[[str], None]) -> _History:
    """Successful and failed build durations per job, from Concourse.

    The original metric was the worst successful run, which is structurally
    blind to the jobs this audit exists for: `thehub/functional-dast` has eight
    builds and no successes. Failed durations are kept so a build killed by the
    clock is counted.
    """
    history = _History()
    try:
        jobs = fetch(f"/api/v1/teams/{team}/pipelines/{pipeline}/jobs")
    except Exception as exc:  # noqa: BLE001 - an unreachable Concourse is reported, not raised
        emit(f"  (could not read {pipeline}: {exc})")
        report.unreadable.append(f"{pipeline}: {exc}")
        return history

    for job in jobs:
        name = job.get("name")
        if not name:
            continue
        try:
            builds = fetch(
                f"/api/v1/teams/{team}/pipelines/{pipeline}/jobs/{name}/builds?limit=100"
            )
        except Exception as exc:  # noqa: BLE001 - one unreadable job is not the audit
            emit(f"  (could not read builds for {pipeline}/{name}: {exc})")
            report.unreadable.append(f"{pipeline}/{name}: {exc}")
            continue
        for build in builds:
            start, end = build.get("start_time"), build.get("end_time")
            if not start or not end:
                continue
            duration = int(end) - int(start)
            if build.get("status") == "succeeded":
                history.worst[name] = max(history.worst.get(name, 0), duration)
                history.successes.setdefault(name, []).append(duration)
            elif build.get("status") == "failed":
                history.failed.setdefault(name, []).append(duration)
    return history


def audit(
    pipeline_dir: Path,
    fetch: Fetch,
    *,
    team: str = "main",
    emit: Callable[[str], None] = lambda _line: None,
) -> TimeoutAuditReport:
    """Audit every pipeline file in `pipeline_dir` against Concourse history.

    `emit` receives the human-readable table, line by line; the scheduled job
    passes nothing and reads the returned report instead.
    """
    report = TimeoutAuditReport()
    paths = sorted(Path(pipeline_dir).glob("*.yml"))
    if not paths:
        # A missing directory reads as an estate with no caps, which is the
        # one thing that must never be reported as "every cap clears".
        report.unreadable.append(f"no pipeline definitions found in {pipeline_dir}")
        return report

    for path in paths:
        pipeline = path.stem
        report.pipelines.append(pipeline)
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        history = _observed(fetch, team, pipeline, report, emit)
        sampled = sum(len(v) for v in history.successes.values())
        emit("=" * 72)
        emit(f"{pipeline}   ({sampled} successful builds sampled)")
        emit("=" * 72)
        emit(f"{'job':<18}{'cap':<8}{'worst ok':<11}{'n':<5}headroom")
        emit("-" * 72)
        for job in document.get("jobs") or []:
            _audit_job(pipeline, job, history, report, emit)
        emit("")
    return report


def _audit_job(pipeline: str, job: dict[str, Any], history: _History,
               report: TimeoutAuditReport, emit: Callable[[str], None]) -> None:
    name = job["name"]
    caps: list[tuple[str, int]] = []

    def visit(node: dict[str, Any]) -> None:
        task = node.get("task")
        if isinstance(task, str) and task not in HOOKS and node.get("timeout"):
            minutes = to_minutes(node["timeout"])
            if minutes is not None:
                caps.append((task, minutes))

    walk(job.get("plan") or [], visit)
    if not caps:
        return
    report.capped_jobs += 1
    # The job's own cap is the sum of its task caps, since they run in
    # sequence; compare that against the whole job's wall clock.
    total_cap = sum(minutes for _, minutes in caps)
    # Against the LARGEST single task cap as well as the sum. A task timeout
    # fires on its own task, so a job whose caps sum to 145m dies at 120m when
    # its 120m task overruns -- and 120 is nowhere near 95% of 145.
    # `thehub/functional-dast` build 8 ran 120.4m against a 120m
    # `functional-and-scan` cap, and the sum-only test missed it.
    #
    # This does NOT catch every timeout. `thehub/cloud-posture` build 1 errored
    # with `timeout exceeded` at 13.6m against a 60m task cap: the step that
    # timed out was a resource GET. Resource-get timeouts are a different audit.
    biggest = max((m for _, m in caps), default=0)
    near_cap = [
        d for d in history.failed.get(name, [])
        if (total_cap and d / 60 >= total_cap * TIMEOUT_MARGIN)
        or (biggest and d / 60 >= biggest * TIMEOUT_MARGIN)
    ]
    successes = history.successes.get(name, [])
    seen = history.worst.get(name)
    if seen is None:
        if near_cap:
            emit(
                f"{name:<18}{total_cap:<8}{'never ok':<11}{0:<5}"
                f"!! {len(near_cap)} failed build(s) ran to the cap"
            )
            report.problems.append(Problem(
                pipeline, name, total_cap, round(max(near_cap) / 60), "timeout",
                suggested_cap(max(near_cap), successes),
            ))
        else:
            emit(f"{name:<18}{total_cap:<8}{'no data':<11}{0:<5}-")
        return
    seen_min = seen / 60
    ratio = total_cap / seen_min if seen_min else 99
    flags: list[tuple[str, str, int, int]] = []
    if ratio < 1.0:
        flags.append(("headroom", "!! CAP BELOW OBSERVED WORST", round(seen_min), seen))
    elif ratio < HEADROOM_FLOOR:
        flags.append(("headroom", "!  under 30% headroom", round(seen_min), seen))
    # A job already carrying a headroom flag still reports its timeouts.
    # `mykronos/publish-frontend` had THREE builds killed by the clock and the
    # audit once printed only "under 30% headroom" about it. A tight cap is a
    # risk; a cap that has already fired is a build that died for a reason
    # unrelated to what it was checking. Both are reported.
    if near_cap:
        flags.append((
            "timeout",
            f"!! {len(near_cap)} failed build(s) ran to the cap",
            round(max(near_cap) / 60),
            max(near_cap),
        ))
    for kind, _text, observed_minutes, observed_seconds in flags:
        report.problems.append(Problem(
            pipeline, name, total_cap, observed_minutes, kind,
            suggested_cap(observed_seconds, successes),
        ))
    shown = "  " + "  ".join(text for _, text, _, _ in flags) if flags else ""
    emit(f"{name:<18}{total_cap:<8}{round(seen_min):<11}{len(successes):<5}{ratio:.1f}x{shown}")


def render(report: TimeoutAuditReport, emit: Callable[[str], None]) -> int:
    """The report's closing section, and the exit code a CLI should return.

    0 clean, 1 caps to raise, 2 could not audit. A run with both findings and
    unread history exits 1 and prints both: the findings are real either way.
    """
    if report.waived:
        emit("Waived, with the reason recorded:")
        for problem in report.waived:
            emit(f"  {problem.line()}")
            emit(f"      {TIMEOUT_WAIVERS[(problem.pipeline, problem.job)]}")
        emit("")
    if report.unwaived:
        emit("Caps to raise:")
        for problem in report.unwaived:
            emit(f"  {problem.line()}")
    if not report.complete:
        emit("could not audit -- this is NOT a clean result. Unread:")
        for entry in report.unreadable:
            emit(f"  {entry}")
    if report.unwaived:
        return 1
    if not report.complete:
        return 2
    emit("every cap clears its observed worst run with margin")
    return 0
