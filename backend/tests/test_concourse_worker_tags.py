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

TheHub #61659 (D-181) adds workers on another host, tagged `linux`, that can
reach the internet and nothing on this one: not the MyKronos backend, the
registry, SILO or TheHub. So placement is per task for them, not per job. A
task named in REMOTE_COMPUTE carries exactly `linux` and must be compute
only: no params (so no credential and no host address reaches the remote
host), no host address anywhere in the step, an image fetched by a `get` of a
public registry image, and not privileged. Every other task keeps its job's
placement. Concourse streams the remote task's inputs and outputs, so the
upload or report that follows on the host still reads them. `get` and `put`
steps stay untagged (D-181 point 3).
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

# The remote workers' tag: what install-concourse-worker.sh registers them with.
REMOTE_TAG = "linux"
INSTALLER = CONCOURSE / "linux-worker" / "install-concourse-worker.sh"

# (pipeline, job, task) that run on the remote workers (TheHub #61659). Each
# is a whole task whose result leaves in an output for a host step to read,
# and each is NON-GATING: a tagged step never falls back to an untagged
# worker, so with the remote host off it waits out its timeout. A lane that
# gates a merge or a delivery (`pr-gates`, or anything in a `passed:` chain)
# stays on this host until a remote host is always on or a second tagged
# worker runs here (review of mykronos #1169).
REMOTE_COMPUTE: frozenset[tuple[str, str, str]] = frozenset(
    {
        ("thehub", "image-refresh", "build"),
    }
)

# Any pipeline var. Workers never resolve vars; the web node puts the value in
# the step, so a var on a remote step is a value on the remote host. `((.:x))`
# is a local var (`load_var`), set inside the build, and is allowed.
PIPELINE_VAR = re.compile(r"\(\((?!\.:)[^)]*\)\)")

# Reading or writing an image registry from inside a task: the registry the
# pipelines use is on this host, and its address can arrive as data (plan.tsv)
# rather than as a var, as image-refresh/scan's `trivy image --insecure` does.
REGISTRY_IO = re.compile(
    r"--insecure|trivy image (?!--input)|\bcrane\b|\bskopeo\b|docker (pull|push)|--push\b",
    re.IGNORECASE,
)

# Anything that names a service on this host. Garden task containers reach the
# host only through Docker Desktop's gateway, by a pipeline var or a literal.
HOST_ONLY = re.compile(
    r"192\.168\.65\.254|host\.docker\.internal|localhost|127\.0\.0\.1"
    r"|\(\((registry|mykronos-url|thehub-url|thehub-[a-z-]*-url|minio-endpoint)\)\)",
    re.IGNORECASE,
)


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
    """Except the REMOTE_COMPUTE tasks, which the remote-worker tests below place."""
    want = PLACEMENT[pipeline]
    wrong = [
        f"{job['name']}/{task['task']}: tags {sorted(task.get('tags') or [])}"
        for job in _heavy_jobs(pipeline)
        for task in _tasks(job.get("plan"))
        if (pipeline, job["name"], task["task"]) not in REMOTE_COMPUTE
        and frozenset(task.get("tags") or []) != want
    ]
    assert not wrong, f"{pipeline} heavy tasks must carry tags {sorted(want)}: {wrong}"


# ── the remote `linux` workers (TheHub #61659, D-181) ─────────────────────

_HOOKS = ("on_success", "on_failure", "on_error", "on_abort", "ensure")


def _every_step(steps: Any) -> Iterator[dict[str, Any]]:
    """Every step of a plan, hooks included: a remote tag hides nowhere."""
    if isinstance(steps, dict):
        steps = [steps]
    for step in steps or []:
        if not isinstance(step, dict):
            continue
        yield step
        for key in ("do", "aggregate", "in_parallel"):
            if key in step:
                inner = step[key]
                yield from _every_step(inner.get("steps", []) if isinstance(inner, dict) else inner)
        if "try" in step:
            yield from _every_step([step["try"]])
        for hook in _HOOKS:
            if hook in step:
                yield from _every_step([step[hook]])


def _job_steps(job: dict[str, Any]) -> Iterator[dict[str, Any]]:
    yield from _every_step(job.get("plan"))
    for hook in _HOOKS:
        if hook in job:
            yield from _every_step([job[hook]])


def _remote_tagged(pipeline: str) -> set[tuple[str, str, str]]:
    doc = _load(CONCOURSE / "pipelines" / f"{pipeline}.yml")
    found = set()
    for job in doc["jobs"]:
        for step in _job_steps(job):
            if REMOTE_TAG not in (step.get("tags") or []):
                continue
            # A task by its name, any other step by kind: a tagged get or put
            # can never match a declared task (D-181: they stay on the host).
            if "task" in step:
                found.add((pipeline, job["name"], step["task"]))
            else:
                kind = next((k for k in ("get", "put") if k in step), "step")
                found.add((pipeline, job["name"], f"{kind}:{step.get(kind)}"))
    return found


def _remote_task_faults(step: dict[str, Any], images: dict[str, str]) -> list[str]:
    """Why `step` could not run on a host that reaches only the internet.

    Judged with its hooks, run.args and step-level `vars:` included: whatever
    the step carries reaches the remote host's build plan.
    """
    faults = []
    if frozenset(step.get("tags") or []) != {REMOTE_TAG}:
        faults.append(f"tags {sorted(step.get('tags') or [])}, not exactly [{REMOTE_TAG}]")
    if step.get("params"):
        faults.append(f"params {sorted(step['params'])}: a credential or host address would travel")
    if step.get("privileged"):
        faults.append("privileged")
    if "file" in step:
        faults.append("a task file: its config is not reviewable here")
    text = yaml.safe_dump(step)
    named = HOST_ONLY.search(text)
    if named:
        faults.append(f"names a host service: {named.group(0)}")
    var = PIPELINE_VAR.search(text)
    if var:
        faults.append(f"carries a pipeline var: {var.group(0)}")
    registry = REGISTRY_IO.search(text)
    if registry:
        faults.append(f"reads or writes a registry: {registry.group(0)}")
    if "/kaniko/executor" in text and "--no-push" not in text:
        faults.append("kaniko without --no-push pushes to the registry")
    config = step.get("config") or {}
    if "image_resource" in config:
        faults.append("an image_resource: the image is not one of the pipeline's public gets")
    image = step.get("image")
    if image not in images:
        faults.append(f"image {image!r} is not a registry-image resource")
    else:
        repository = images[image]
        first = repository.split("/")[0]
        # A var, a host:port, or this host: not a registry the remote host reaches.
        if "((" in repository or ":" in first or HOST_ONLY.search(repository):
            faults.append(f"image {image!r} is {repository!r}, not a public registry")
    return faults


def _registry_images(doc: dict[str, Any]) -> dict[str, str]:
    return {
        r["name"]: str((r.get("source") or {}).get("repository", ""))
        for r in doc.get("resources", [])
        if r.get("type") == "registry-image"
    }


def test_the_remote_tag_is_the_one_the_installer_registers() -> None:
    assert f'TAG="{REMOTE_TAG}"' in INSTALLER.read_text(encoding="utf-8")
    assert REMOTE_TAG not in set().union(*_worker_tags().values()), (
        "a compose worker on this host carries the remote tag; its steps could land on either"
    )


def test_exactly_the_declared_remote_tasks_carry_the_remote_tag() -> None:
    """Both ways: a declared task that lost its tag, and any step that gained
    one without being reviewed as compute only (hooks, gets and puts included)."""
    tagged = set().union(*(_remote_tagged(p) for p in PIPELINES))
    # Pinned literally as well: widening the list is a reviewed change here.
    assert {("thehub", "image-refresh", "build")} == REMOTE_COMPUTE
    assert tagged == set(REMOTE_COMPUTE), {
        "tagged, not declared": sorted(tagged - REMOTE_COMPUTE),
        "declared, not tagged": sorted(REMOTE_COMPUTE - tagged),
    }


@pytest.mark.parametrize("where", sorted(REMOTE_COMPUTE), ids="/".join)
def test_a_remote_task_is_compute_only(where: tuple[str, str, str]) -> None:
    pipeline, job_name, task_name = where
    doc = _load(CONCOURSE / "pipelines" / f"{pipeline}.yml")
    job = next(j for j in doc["jobs"] if j["name"] == job_name)
    steps = [s for s in _job_steps(job) if s.get("task") == task_name]
    assert len(steps) == 1, f"{job_name}/{task_name}: {len(steps)} steps by that name"
    faults = _remote_task_faults(steps[0], _registry_images(doc))
    assert not faults, f"{job_name}/{task_name} cannot run on a remote worker: {faults}"


def test_the_compute_only_check_can_fail() -> None:
    """The checker refuses each way a task can need the host."""
    images = {"python": "python", "local": "((registry))/thehub"}
    ok: dict[str, Any] = {
        "task": "t",
        "tags": [REMOTE_TAG],
        "image": "python",
        "config": {"platform": "linux"},
    }
    assert _remote_task_faults(ok, images) == []
    bad: list[dict[str, Any]] = [
        {**ok, "params": {"MYKRONOS_URL": "((mykronos-url))"}},
        {**ok, "tags": [REMOTE_TAG, "thehub"]},
        {**ok, "privileged": True},
        {**ok, "image": "local"},
        {**ok, "config": {"image_resource": {"source": {"repository": "curlimages/curl"}}}},
        {**ok, "config": {"run": {"path": "curl", "args": ["http://192.168.65.254:8100/api"]}}},
        {**ok, "config": {"run": {"path": "curl", "args": ["http://host.docker.internal:8000"]}}},
        # A var anywhere: run.args, step-level vars, a hook.
        {**ok, "config": {"run": {"path": "sh", "args": ["-c", "echo ((thehub-token))"]}}},
        {**ok, "vars": {"token": "((hub-deploy-token))"}},
        {**ok, "ensure": {"task": "upload", "params": {"T": "((thehub-ingestion-token))"}}},
        # A registry read whose address is data, not a var (image-refresh/scan).
        {**ok, "config": {"run": {"path": "sh", "args": ["-c", 'trivy image --insecure "$c"']}}},
        {**ok, "config": {"run": {"path": "sh", "args": ["-c", "/kaniko/executor -d x"]}}},
    ]
    local = {**ok, "config": {"run": {"path": "sh", "args": ["-c", "echo ((.:sha))"]}}}
    assert _remote_task_faults(local, images) == [], "a local var is set inside the build"
    for step in bad:
        assert _remote_task_faults(step, images), step


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
