"""Heavy lanes of different pipelines never share a worker (TheHub #61607).

Two workers, 3g each, on a Docker VM that cannot give them more. At 06:00Z on
2026-11-13 worker-2 held eight lanes of both pipelines at 2.998/3 GiB while
worker-1 sat at 670 MiB, and thehub/unit #389 and mykronos/unit #496 were
SIGKILLed under their own budgets: the worker ran out, not the task. serial_groups
serialise within one pipeline only, and placement counts containers, not
memory.

The fix is placement by worker tag. Concourse's rules, which shape every
assertion here: a tagged worker runs only steps that name its tags, and an
untagged step runs only on an untagged worker. So exactly one worker stays
untagged (every default stays schedulable), and each pipeline's heavy jobs
name one placement - a tag set that is some worker's - distinct from every
other pipeline's. `tags` is a step modifier, not a job key, so a job is
placed by tagging every task in its plan; that also keeps one task's outputs
on the worker the next task runs on.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CONCOURSE = ROOT / "deploy" / "concourse"
COMPOSE = CONCOURSE / "docker-compose.yml"
PIPELINES = ("mykronos", "thehub", "personal-soc")

# The jobs that hold a lot of memory for a long time: the suites, the
# scanners and the image builds by name, and any job that sets a memory-guard
# budget, which is itself the statement that the job is big.
HEAVY_NAMES = frozenset({"unit", "sast", "containers", "build"})

# Where each pipeline's heavy jobs run. Empty is worker-1, the untagged one.
PLACEMENT: dict[str, frozenset[str]] = {
    "thehub": frozenset({"thehub"}),
    "mykronos": frozenset(),
    "personal-soc": frozenset(),
}


def _load(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _tasks(steps: Any) -> Iterator[dict[str, Any]]:
    """Every task step in a plan, through do / in_parallel / try / aggregate.

    Hooks (ensure, on_success, on_failure, on_error, on_abort) are skipped on
    purpose: they are short report steps and run untagged on worker-1.
    """
    if isinstance(steps, dict):
        steps = steps.get("steps", [])
    for step in steps or []:
        if not isinstance(step, dict):
            continue
        if "task" in step:
            yield step
        for key in ("do", "aggregate", "in_parallel"):
            if key in step:
                yield from _tasks(step[key])
        if "try" in step:
            yield from _tasks([step["try"]])


def _is_heavy(job: dict[str, Any]) -> bool:
    return job["name"] in HEAVY_NAMES or "MEMORY_BUDGET_MB" in yaml.safe_dump(job.get("plan"))


def _heavy_jobs(pipeline: str) -> list[dict[str, Any]]:
    doc = _load(CONCOURSE / "pipelines" / f"{pipeline}.yml")
    return [job for job in doc["jobs"] if _is_heavy(job)]


def _worker_tags() -> dict[str, frozenset[str]]:
    services = _load(COMPOSE)["services"]
    workers: dict[str, frozenset[str]] = {}
    for name, service in services.items():
        if service.get("command") != "worker":
            continue
        tag = str((service.get("environment") or {}).get("CONCOURSE_TAG") or "")
        workers[name] = frozenset(t.strip() for t in tag.split(",") if t.strip())
    return workers


def test_the_declared_placement_covers_every_pipeline() -> None:
    assert set(PLACEMENT) == set(PIPELINES)


def test_the_heavy_jobs_are_found() -> None:
    """A walker that found nothing would pass every test below."""
    names = {job["name"] for job in _heavy_jobs("thehub")}
    assert {"unit", "sast", "containers", "build", "post-merge", "pr-gates"} <= names
    assert {"unit", "sast", "containers", "build"} <= {j["name"] for j in _heavy_jobs("mykronos")}


@pytest.mark.parametrize("pipeline", PIPELINES)
def test_every_task_of_a_heavy_job_names_its_pipelines_placement(pipeline: str) -> None:
    want = PLACEMENT[pipeline]
    wrong = [
        f"{job['name']}/{task['task']}: tags {sorted(task.get('tags') or [])}"
        for job in _heavy_jobs(pipeline)
        for task in _tasks(job.get("plan"))
        if frozenset(task.get("tags") or []) != want
    ]
    assert not wrong, f"{pipeline} heavy tasks must carry tags {sorted(want)}: {wrong}"


def test_no_two_pipelines_heavy_jobs_share_a_placement() -> None:
    placed = [PLACEMENT[p] for p in PIPELINES if _heavy_jobs(p)]
    assert len(placed) == len(set(placed)), placed


def test_exactly_one_worker_is_untagged() -> None:
    """Every resource check, resource type and light job is untagged: with
    no untagged worker they would all wait for a worker forever."""
    untagged = [name for name, tags in _worker_tags().items() if not tags]
    assert len(untagged) == 1, _worker_tags()


def test_every_placement_is_a_worker_and_every_worker_tag_is_a_placement() -> None:
    workers = set(_worker_tags().values())
    placements = {PLACEMENT[p] for p in PIPELINES if _heavy_jobs(p)}
    assert placements <= workers, (placements, workers)
    assert {tags for tags in workers if tags} <= placements, (placements, workers)


def _mem_limit_mb(value: str) -> int:
    match = re.fullmatch(r"(\d+(?:\.\d+)?)([gm])", str(value).strip().lower())
    assert match, value
    number, unit = float(match.group(1)), match.group(2)
    return int(number * 1024) if unit == "g" else int(number)


def test_the_unit_budget_leaves_room_in_its_worker() -> None:
    """thehub's unit memory-guard budget and mykronos's unit `-n 2` (#61607).

    2048: the last four green thehub/unit runs peaked at 1263-1330 MiB, and
    512 MiB of the worker stays for the preflight and hook steps beside it.
    """
    worker_mb = _mem_limit_mb(_load(COMPOSE)["x-worker"]["mem_limit"])
    unit = next(job for job in _heavy_jobs("thehub") if job["name"] == "unit")
    budgets = [
        int(task["params"]["MEMORY_BUDGET_MB"])
        for task in _tasks(unit["plan"])
        if "MEMORY_BUDGET_MB" in (task.get("params") or {})
    ]
    assert budgets == [2048]
    assert budgets[0] <= worker_mb - 512

    unit = next(job for job in _heavy_jobs("mykronos") if job["name"] == "unit")
    pytest_task = next(task for task in _tasks(unit["plan"]) if task["task"] == "pytest")
    script = "\n".join(pytest_task["config"]["run"]["args"])
    assert re.search(r"pytest -q -n 2 ", script), "mykronos unit runs pytest -n 2"
