"""CI yields to production on the shared Docker VM (TheHub #61009, D-174).

TheHub's Concourse tasks run on the same Docker VM as `thehub-backend`. On
2026-10-23 uncapped test load on that VM starved production's uvicorn workers
into a restart storm (TheHub #61001), and D-172's three lanes mean up to three
heavy task containers at once. These tests hold the two things that give
production precedence, and the one thing that would stop every task.

What was measured on 2026-10-26, and why the tests say what they say:

* Task `container_limits.cpu` is applied. Guardian on the live workers' cgroup
  v2 turns 512 shares into `cpu.weight` 59. But a task's cgroup is nested
  inside its worker's container, so that weight only ranks a task against the
  worker's own processes and sibling tasks - never against `thehub-backend`.
* Task `container_limits.memory` is NOT applied: it is fatal. The worker keeps
  its own processes in its cgroup root, so the memory controller cannot be
  delegated to `/sys/fs/cgroup/garden` (it is in threaded mode), and runc
  refuses to create the container: "cannot enter cgroupv2 /sys/fs/cgroup/garden
  with domain controllers -- it is in threaded mode". A memory limit on one
  task fails that task every time; CONCOURSE_DEFAULT_TASK_MEMORY_LIMIT on the
  web node would fail every task of every pipeline.
* Precedence over production therefore lives on the worker containers, which
  are siblings of `thehub-backend` under Docker: `cpu_shares` 256 is
  `cpu.weight` 35 against production's 100 (174 once TheHub #539's 2048
  lands), and `oom_score_adj` is inherited by every task process because
  garden sets none of its own.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
PIPELINE = ROOT / "deploy" / "concourse" / "pipelines" / "thehub.yml"
COMPOSE = ROOT / "deploy" / "concourse" / "docker-compose.yml"

# Docker's default weight. `thehub-backend` declares no cpu_shares today
# (cpu.weight 100) and TheHub #539 raises it to 2048 (cpu.weight 174), so
# anything below 1024 is below production's either way.
PRODUCTION_CPU_SHARES = 1024

# The Docker VM had 11.68 GiB on 2026-10-26 (`docker info`). Both workers
# peaked at their full 6g, so CI alone could ask for more memory than the VM
# has. The workers together must leave room for production.
VM_MEMORY_BYTES = int(11.68 * 1024**3)


def _tasks(node: Any, where: str) -> Iterator[tuple[str, dict[str, Any]]]:
    """Every task step under `node`, hooks included, with anchors expanded."""
    if isinstance(node, dict):
        if "task" in node:
            yield f"{where} task:{node['task']}", node
        for key, value in node.items():
            yield from _tasks(value, f"{where}/{key}")
    elif isinstance(node, list):
        for i, value in enumerate(node):
            yield from _tasks(value, f"{where}[{i}]")


def _run_tasks() -> list[tuple[str, dict[str, Any]]]:
    doc = yaml.safe_load(PIPELINE.read_text(encoding="utf-8"))
    out = []
    for job in doc["jobs"]:
        for where, step in _tasks(job, job["name"]):
            if "file" in step or "run" in (step.get("config") or {}):
                out.append((where, step))
    return out


def _limits(step: dict[str, Any]) -> dict[str, Any] | None:
    """The limits Concourse applies: the step's, else its config's."""
    found = step.get("container_limits")
    if found is None:
        found = (step.get("config") or {}).get("container_limits")
    return found


def _bytes(value: str | int) -> int:
    if isinstance(value, int):
        return value
    m = re.fullmatch(r"(\d+)([kmg]?)b?", str(value).strip().lower())
    assert m, f"unreadable memory size {value!r}"
    return int(m.group(1)) * {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3}[m.group(2)]


def _workers() -> dict[str, dict[str, Any]]:
    services = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))["services"]
    return {n: s for n, s in services.items() if s.get("command") == "worker"}


def test_the_pipeline_has_run_tasks_to_check() -> None:
    # A walker that finds nothing would pass every test below.
    assert len(_run_tasks()) > 100


def test_every_task_declares_container_limits() -> None:
    missing = [where for where, step in _run_tasks() if not _limits(step)]
    assert not missing, (
        f"{len(missing)} task(s) in thehub.yml declare no container_limits, so they "
        f"run at full weight beside production (TheHub #61009): {missing[:10]}"
    )


def test_every_task_weighs_less_than_production() -> None:
    heavy = [
        (where, (_limits(step) or {}).get("cpu"))
        for where, step in _run_tasks()
        if not isinstance((_limits(step) or {}).get("cpu"), int)
        or not 0 < (_limits(step) or {})["cpu"] < PRODUCTION_CPU_SHARES
    ]
    assert not heavy, (
        f"container_limits.cpu must be CPU shares between 1 and {PRODUCTION_CPU_SHARES - 1}: "
        f"{heavy[:10]}"
    )


def test_no_task_sets_a_memory_limit_the_workers_cannot_apply() -> None:
    capped = [where for where, step in _run_tasks() if "memory" in (_limits(step) or {})]
    assert not capped, (
        "container_limits.memory makes runc refuse the task container on these "
        "guardian workers ('cannot enter cgroupv2 /sys/fs/cgroup/garden with "
        "domain controllers -- it is in threaded mode'), so the task fails on "
        "every run. Memory is capped on the worker containers instead "
        f"(D-174): {capped[:10]}"
    )


def test_there_are_workers_to_check() -> None:
    assert len(_workers()) >= 2


def test_workers_yield_cpu_to_production() -> None:
    weights = {n: s.get("cpu_shares") for n, s in _workers().items()}
    assert all(isinstance(w, int) and 0 < w < PRODUCTION_CPU_SHARES for w in weights.values()), (
        "every Concourse worker needs cpu_shares below production's "
        f"{PRODUCTION_CPU_SHARES}; task weights cannot reach across the "
        f"worker's cgroup (D-174): {weights}"
    )


def test_workers_die_before_production_on_an_oom() -> None:
    adj = {n: s.get("oom_score_adj") for n, s in _workers().items()}
    assert all(isinstance(a, int) and a > 0 for a in adj.values()), (
        "every Concourse worker needs a positive oom_score_adj, which its task "
        f"processes inherit, so the VM's OOM killer takes CI first: {adj}"
    )


def test_workers_cannot_swap_or_outgrow_the_vm() -> None:
    workers = _workers()
    limits = {n: _bytes(s["mem_limit"]) for n, s in workers.items()}
    swaps = {n: _bytes(s.get("memswap_limit", 0)) for n, s in workers.items()}
    assert swaps == limits, (
        "memswap_limit must equal mem_limit, or Docker lets each worker add as "
        f"much swap again as its RAM cap: mem={limits} memswap={swaps}"
    )
    assert sum(limits.values()) < VM_MEMORY_BYTES, (
        f"the workers' mem_limits add up to {sum(limits.values()) / 1024**3:.1f} GiB, "
        f"more than the {VM_MEMORY_BYTES / 1024**3:.2f} GiB VM production shares"
    )
