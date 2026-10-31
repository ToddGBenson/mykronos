"""TheHub's jobs queue in three serial lanes, not one (TheHub #60928, D-172).

Every build and scan job in `thehub.yml` shared `serial_groups: [worker]`, so a
commit's six scanners, its unit tier and its DAST ran one after another: 62-81
minutes from commit to the last scan (525152ee +81m, 3f392e89 +78m). The
acceptance criterion is under 30 minutes.

These tests do not grep for group names. They read the pipeline as Concourse
would - triggers, `passed:` constraints and serial groups - and replay one
develop commit through it with the durations Concourse itself measured, so a
future edit that puts a scanner back behind the unit tier fails here with the
projected minutes in the message.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
PIPELINE = ROOT / "deploy" / "concourse" / "pipelines" / "thehub.yml"

TARGET_MINUTES = 30.0

# Median duration, in minutes, of the last 50 SUCCEEDED builds of each job,
# read anonymously from Concourse (/api/v1/teams/main/pipelines/thehub/jobs/
# <job>/builds?limit=50) on 2026-10-22. Run time only: a build's start_time is
# set when it leaves the serial queue, so these do not include waiting.
P50 = {
    "unit": 19.0,
    "qa": 2.0,
    "build": 5.4,
    "containers": 4.3,
    "secrets": 2.35,
    "sast": 5.9,
    "dependencies": 3.85,
    "iac": 2.1,
    "ai-models": 1.9,
    "prompt-evals": 2.75,
    "remediate": 1.8,
    "oracle-gate": 1.6,
    "deploy-demo": 5.75,
    "api-inventory": 1.5,
    "functional-demo": 3.45,
    "dast-demo": 2.1,
}

# post-merge is on the half-hourly clock and grades develop's tip, so it runs
# the unit tier on the commit that just landed: in 7d83e24c, 370e0b5e and
# f06b2fc4 it ran inside that commit's window. Replayed at its p90 (15.4m),
# arriving at the same instant as the commit, which is the worst place for it.
POST_MERGE_P90 = 15.4

# Jobs that have never carried a serial group, and are not heavy: the pipeline
# applier, two short gate/deploy steps that wait on the scanners anyway, and
# cloud-posture, which runs off-host against a cloud API.
UNSERIALISED = {"set-pipeline", "oracle-gate", "deploy-demo", "cloud-posture"}

# The ceiling on concurrent heavy jobs. One lane was 1 (the OOM that killed the
# quickstart container was 7 at once, on one worker that was also the web
# node). Three lanes across two 3g workers (6g until D-174) is the most this
# change claims.
MAX_LANES = 3

# TheHub #61106. Not a lane: a second group on the jobs that run TheHub's FULL
# pytest suite, so two of them never run at once. unit #360 and post-merge
# #1623 were SIGKILLed for memory ten hours apart with no test failing, because
# the two suites sat in different lanes. Every job in it stays in exactly one
# lane, so the group can only make jobs wait and never adds concurrency.
MEMORY_GROUP = "pytest-memory"
FULL_SUITES = {"unit", "post-merge"}


def _doc() -> dict[str, Any]:
    doc: dict[str, Any] = yaml.safe_load(PIPELINE.read_text(encoding="utf-8"))
    return doc


def _jobs() -> dict[str, dict[str, Any]]:
    return {job["name"]: job for job in _doc()["jobs"]}


def _groups() -> dict[str, list[str]]:
    return {g["name"]: g["jobs"] for g in _doc()["groups"]}


def _source_get(job: dict[str, Any]) -> dict[str, Any] | None:
    for step in job.get("plan", []):
        if step.get("get") == "source" and step.get("trigger"):
            found: dict[str, Any] = step
            return found
    return None


def _per_commit() -> dict[str, list[str]]:
    """Every job a develop commit triggers, mapped to the jobs it waits on."""
    out: dict[str, list[str]] = {}
    for name, job in _jobs().items():
        step = _source_get(job)
        if step is not None:
            out[name] = list(step.get("passed", []))
    return out


def _scanners() -> set[str]:
    """The `security` group's jobs that a commit triggers: the "last scan"."""
    return set(_groups()["security"]) & set(_per_commit())


def _replay(with_post_merge: bool) -> tuple[dict[str, float], dict[str, float]]:
    """Replay one commit through the serial groups. Returns (start, end) minutes.

    Concourse runs a job once every job in its `passed:` list has finished, and
    never two jobs that share a serial group at the same time. Among jobs
    waiting on the same lane, the one that became ready first goes first, then
    pipeline order - the order is immaterial to when a lane drains.
    """
    jobs = _jobs()
    order = list(jobs)
    deps = _per_commit()
    dur = dict(P50)
    if with_post_merge:
        deps["post-merge"] = []
        dur["post-merge"] = POST_MERGE_P90
    missing = set(deps) - set(dur)
    assert not missing, f"no measured duration for per-commit job(s) {sorted(missing)}"

    groups = {n: set(jobs[n].get("serial_groups") or []) for n in deps}
    start: dict[str, float] = {}
    end: dict[str, float] = {}
    busy_until: dict[str, float] = {}
    pending = set(deps)
    while pending:
        ready = [n for n in pending if all(d in end for d in deps[n])]
        assert ready, f"unsatisfiable passed: constraints among {sorted(pending)}"

        def earliest(n: str) -> float:
            t = max((end[d] for d in deps[n]), default=0.0)
            return max([t] + [busy_until.get(g, 0.0) for g in groups[n]])

        name = min(ready, key=lambda n: (earliest(n), order.index(n)))
        start[name] = earliest(name)
        end[name] = start[name] + dur[name]
        for g in groups[name]:
            busy_until[g] = end[name]
        pending.remove(name)
    return start, end


def _last_scan(with_post_merge: bool) -> tuple[float, str]:
    _, end = _replay(with_post_merge)
    last = max(_scanners(), key=lambda n: end[n])
    return end[last], last


def _timeline(with_post_merge: bool) -> str:
    start, end = _replay(with_post_merge)
    jobs = _jobs()
    return "\n".join(
        f"  {n:16} {start[n]:5.1f} -> {end[n]:5.1f}  {jobs[n].get('serial_groups')}"
        for n in sorted(start, key=lambda n: start[n])
    )


# -- the acceptance criterion, projected --------------------------------------


def test_a_commit_is_fully_scanned_in_under_30_minutes() -> None:
    minutes, last = _last_scan(with_post_merge=False)
    assert minutes < TARGET_MINUTES, (
        f"last scan ({last}) finishes {minutes:.1f}m after the commit at median "
        f"durations; the target is under {TARGET_MINUTES:.0f}m.\n"
        + _timeline(with_post_merge=False)
    )


def test_a_post_merge_grading_the_same_commit_delays_it_by_at_most_its_own_run() -> None:
    """Was "does not push it past 30". Since #61106 post-merge and `unit` may not
    run at once, so a post-merge already under way when a commit lands holds that
    commit's unit tier for up to its own run. That is the price of never having
    two full suites in memory together; what must not happen is any delay
    BEYOND that run - post-merge must not also queue in front of build,
    containers or a scanner."""
    without, _ = _last_scan(with_post_merge=False)
    minutes, last = _last_scan(with_post_merge=True)
    assert minutes <= without + POST_MERGE_P90 + 1e-9, (
        f"with post-merge's p90 run arriving alongside the commit, the last scan "
        f"({last}) finishes at {minutes:.1f}m, more than {without:.1f}m plus that "
        f"run's {POST_MERGE_P90}m.\n" + _timeline(with_post_merge=True)
    )


def test_the_full_pytest_suites_never_run_at_once() -> None:
    """#61106 AC1, replayed: post-merge arriving with the commit, where it overlapped."""
    start, end = _replay(with_post_merge=True)
    (a, b) = sorted(FULL_SUITES)
    assert end[a] <= start[b] or end[b] <= start[a], (
        f"{a} {start[a]:.1f}->{end[a]:.1f} overlaps {b} {start[b]:.1f}->{end[b]:.1f}\n"
        + _timeline(with_post_merge=True)
    )


def test_only_the_full_suites_share_the_memory_group() -> None:
    """A light job in it would queue behind a 19-minute suite for no memory saved."""
    jobs = _jobs()
    members = {n for n, j in jobs.items() if MEMORY_GROUP in (j.get("serial_groups") or [])}
    assert members == FULL_SUITES


def test_the_unit_tier_does_not_queue_behind_a_scanner() -> None:
    """unit -> build -> containers is the critical path; nothing else may lengthen it."""
    jobs = _jobs()
    chain = set(jobs["unit"].get("serial_groups") or [])
    for scanner in _scanners() - {"containers"}:
        shared = chain & set(jobs[scanner].get("serial_groups") or [])
        assert not shared, f"{scanner} shares serial group {sorted(shared)} with unit"


# -- the lanes ----------------------------------------------------------------


def test_dast_has_its_own_lane() -> None:
    """The story's one stated design constraint: DAST never queues with a scanner."""
    jobs = _jobs()
    groups = _groups()
    dast = {n for n in jobs if n.startswith("dast-")} | {"api-inventory", "functional-demo"}
    assert dast <= set(groups["demo"]) | set(groups["prod"]) | set(groups["security"])

    lanes = {tuple(jobs[n].get("serial_groups") or []) for n in dast}
    assert len(lanes) == 1, f"DAST jobs are split across {sorted(lanes)}"
    (lane,) = lanes
    assert lane, "DAST jobs must still be serialised among themselves"
    for scanner in _scanners():
        shared = set(lane) & set(jobs[scanner].get("serial_groups") or [])
        assert not shared, f"{scanner} shares the DAST lane {sorted(shared)}"


def test_every_heavy_job_is_still_in_exactly_one_lane() -> None:
    """Splitting the queue must not unbound it: no job escapes serialisation."""
    for name, job in _jobs().items():
        if name in UNSERIALISED:
            continue
        lanes = [g for g in job.get("serial_groups") or [] if g != MEMORY_GROUP]
        assert len(lanes) == 1, f"{name} has serial lanes {lanes}; expected exactly one"


def test_no_more_than_three_heavy_jobs_can_run_at_once() -> None:
    lanes = {
        g for job in _jobs().values() for g in job.get("serial_groups") or [] if g != MEMORY_GROUP
    }
    assert 1 < len(lanes) <= MAX_LANES, f"serial lanes: {sorted(lanes)}"
