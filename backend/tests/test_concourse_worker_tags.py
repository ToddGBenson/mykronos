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

The operator decision of 2026-11-16 ("heavy jobs to Linux") moved gating
suites and scans too, which the first rule could not admit as written: a
suite has literal params (a pip cache path, a memory budget) and two of
TheHub's run in TheHub's own image from the local registry. So the rule is
now about what reaches the remote host, not about the shape of the step: no
pipeline var except the non-secret ones in REMOTE_VARS and no build-local
`((.:x))` var, no param that names a credential, no host or LAN address (a
task-local Postgres or Redis on the task's own 127.0.0.1 is not one), only
the inputs REMOTE_INPUTS allows it, and an image that is a public `get` or
TheHub's image as an artifact `fetch-image` made on this host.

The review of mykronos #1177 (operator decision 2026-11-16, ~03:20Z) puts the
laptops inside the CI trust boundary for gating verdicts WITH host-side
checks, which the tests at the end hold: no TheHub git history reaches them
(a tree from `export-tree` / `export-pr`), the registry never faces the LAN
(`fetch-image`), and a gating remote task's exit code is decided on this
host (`linux-verdict`, post-merge's `report-verdict`).
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
# pr-gates since TheHub #62416: its integration task (and so its
# MEMORY_BUDGET_MB) left the pull request, but its `pick` holds the deploy
# key, so its host steps keep the placement check of a heavy job.
HEAVY_NAMES = frozenset({"unit", "sast", "containers", "build", "pr-gates"})

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
# worker, and in Concourse 8.3.3 a task waits for a worker indefinitely,
# before its own `timeout:` starts. So each sits in a `do:` or `try:` that
# carries the timeout: the wrapper bounds the wait for a worker too, and with
# the remote host offline the run fails after that timeout. A lane that gates
# a merge or a delivery (`pr-gates`, or anything in a `passed:` chain) stays
# on this host until a remote host is always on or a second tagged worker
# runs here (review of mykronos #1169).
#
# The operator overrode that last rule on 2026-11-16 ("heavy jobs to Linux"):
# gating lanes move too, and what keeps an offline remote host from reading
# as a red verdict is in the pipelines (`linux_probe` and `linux_absent` in
# thehub.yml, the timed wrappers everywhere), not in staying here.
REMOTE_COMPUTE: frozenset[tuple[str, str, str]] = frozenset(
    {
        ("thehub", "image-refresh", "build"),
        ("thehub", "post-merge", "linux-worker-probe"),
        ("thehub", "post-merge", "grade"),
        ("thehub", "pr-gates", "linux-worker-probe"),
        ("thehub", "pr-gates", "gates"),
        ("thehub", "gate-smoke", "gates"),
        ("thehub", "container-tiers", "linux-worker-probe"),
        ("thehub", "container-tiers", "tiers"),
        ("mykronos", "coverage", "pytest-cov"),
        ("mykronos", "time-travel", "pytest-time-travel"),
        ("mykronos", "sast", "semgrep"),
        ("mykronos", "dependencies", "osv-scanner"),
        ("mykronos", "coverage", "linux-worker-probe"),
        ("mykronos", "time-travel", "linux-worker-probe"),
        ("mykronos", "sast", "linux-worker-probe"),
        ("mykronos", "dependencies", "linux-worker-probe"),
        # TheHub #61951: the gating lanes, a linux worker first and this host
        # when none finishes them (test_mykronos_gating_lanes_on_linux.py).
        ("mykronos", "unit", "linux-worker-probe"),
        ("mykronos", "unit", "pytest"),
        ("mykronos", "frontend", "linux-worker-probe"),
        ("mykronos", "frontend", "dump-openapi"),
        ("mykronos", "frontend", "lint-types-build"),
        # TheHub #62325: thehub's `unit` the same way, on export-tree's tree
        # (test_thehub_unit_on_linux.py).
        ("thehub", "unit", "linux-worker-probe"),
        ("thehub", "unit", "pytest-on-linux"),
    }
)

# The pipeline vars a remote step may carry, from vars/*.yml: none is a
# credential and none names a host service. `thehub-branch` is #1178's: the
# branch name, used by this pipeline's host steps. `remote-registry`, also
# #1178's, is not allowed: the review of #1177 keeps the registry off the LAN,
# and nothing in any pipeline references it.
REMOTE_VARS = frozenset({"thehub-branch", "time-travel-offset", "mykronos-ref"})
# A param whose name says it is a credential, whatever its value.
CREDENTIAL_PARAM = re.compile(r"TOKEN|SECRET|PASSWORD|PRIVATE_KEY|API_KEY", re.IGNORECASE)
# A service a task starts for itself and reaches on its own loopback (the
# suites' Postgres and Redis): not this host, wherever the task runs.
TASK_LOCAL = re.compile(r"(localhost|127\.0\.0\.1):(5432|6379)\b")

# Any pipeline var. Workers never resolve vars; the web node puts the value in
# the step, so a var on a remote step is a value on the remote host. A
# build-local `((.:x))` (`load_var`) counts too since the review of #1177: its
# value was read on this host from a file, and a remote task takes what it
# needs as an input instead, where REMOTE_INPUTS can see it.
# Matched by content: a var name has no spaces or operators, so shell
# arithmetic `$((attempt + 1))` is not one. A `$` in front changes nothing:
# Concourse interpolates `$((token))` all the same.
PIPELINE_VAR = re.compile(r"\(\([-/.:@\"\w]+\)\)")

# Reading or writing an image registry from inside a task: the registry the
# pipelines use is on this host, and its address can arrive as data (plan.tsv)
# rather than as a var, as image-refresh/scan's `trivy image --insecure` does.
# `trivy image` is allowed only with `--input` (a tarball) in the same command.
REGISTRY_IO = re.compile(
    r"--insecure|\bcrane\b|\bskopeo\b|\bdocker (pull|push)\b|--push\b",
    re.IGNORECASE,
)
# `trivy ... image` (global flags may come first) reads a registry unless the
# same simple command, not just the same line, names `--input` (a tarball).
SIMPLE_COMMAND_BREAK = re.compile(r"\n|;|&&|\|\||\|")
TRIVY_IMAGE = re.compile(r"\btrivy\b(\s+-\S+)*\s+image\b")

# Anything that names a service on this host. Garden task containers reach the
# host only through Docker Desktop's gateway, by a pipeline var or a literal.
# Any RFC 1918 address names the LAN, this host's 192.168.0.x included: a
# remote task has no business dialling it.
HOST_ONLY = re.compile(
    r"192\.168\.65\.254|host\.docker\.internal|localhost|127\.0\.0\.1"
    r"|\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b"
    r"|\b192\.168\.\d{1,3}\.\d{1,3}\b"
    r"|\(\((registry|mykronos-url|thehub-url|thehub-[a-z-]*-url|minio-endpoint)\)\)",
    re.IGNORECASE,
)

# The artifacts this host makes for a remote task, and the task that makes
# each: a tree with no git history, the commit beside it, and TheHub's image.
HOST_MADE = {
    "tree": "export-tree",
    "commit": "export-tree",
    "pr-tree": "export-pr",
    "thehub-image": "fetch-image",
}
# The images a remote task may run that are not a public registry-image get.
HOST_IMAGES = frozenset({"thehub-image"})

# Exactly what each remote task is given: input name -> the artifact mapped
# to it (None: the input's own name). A TheHub `get` (git history) is never
# one; `live-pipeline` is mykronos's public pipelines repo.
REMOTE_INPUTS: dict[tuple[str, str, str], dict[str, str | None]] = {
    ("thehub", "image-refresh", "build"): {"source": "tree", "refresh": None},
    ("thehub", "post-merge", "linux-worker-probe"): {},
    ("thehub", "post-merge", "grade"): {"source": "tree", "commit": None},
    ("thehub", "pr-gates", "linux-worker-probe"): {},
    ("thehub", "pr-gates", "gates"): {"pr": "pr-tree", "live-pipeline": None},
    ("thehub", "gate-smoke", "gates"): {"pr": "pr-tree", "live-pipeline": None},
    ("thehub", "container-tiers", "linux-worker-probe"): {},
    ("thehub", "container-tiers", "tiers"): {"source": "tree", "commit": None},
    # #1178's mykronos lanes: `source` is mykronos's own git get. Its history
    # is public, unlike TheHub's (#398), so it may reach the laptops as is.
    ("mykronos", "coverage", "linux-worker-probe"): {},
    ("mykronos", "coverage", "pytest-cov"): {"source": None},
    ("mykronos", "time-travel", "linux-worker-probe"): {},
    ("mykronos", "time-travel", "pytest-time-travel"): {"source": None},
    ("mykronos", "sast", "linux-worker-probe"): {},
    ("mykronos", "sast", "semgrep"): {"source": None},
    ("mykronos", "dependencies", "linux-worker-probe"): {},
    ("mykronos", "dependencies", "osv-scanner"): {"source": None},
    ("mykronos", "unit", "linux-worker-probe"): {},
    ("mykronos", "unit", "pytest"): {"source": None},
    ("mykronos", "frontend", "linux-worker-probe"): {},
    ("mykronos", "frontend", "dump-openapi"): {"source": None},
    # The schema dump-openapi wrote on the same worker.
    ("mykronos", "frontend", "lint-types-build"): {"source": None, "contract": None},
    ("thehub", "unit", "linux-worker-probe"): {},
    ("thehub", "unit", "pytest-on-linux"): {"source": "tree", "commit": None},
}

# The gating remote tasks, and the host step after each that decides the
# job's exit code from what the task wrote.
HOST_DECIDES = {
    ("thehub", "post-merge", "grade"): "report-verdict",
    ("thehub", "pr-gates", "gates"): "linux-verdict",
    ("thehub", "gate-smoke", "gates"): "linux-verdict",
    ("thehub", "container-tiers", "tiers"): "linux-verdict",
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
    if step.get("timeout"):
        faults.append(
            "a task-level timeout starts after a worker is chosen, so it does not bound "
            "the wait for one: put the timeout on a wrapping do/try"
        )
    if frozenset(step.get("tags") or []) != {REMOTE_TAG}:
        faults.append(f"tags {sorted(step.get('tags') or [])}, not exactly [{REMOTE_TAG}]")
    for name in step.get("params") or {}:
        if CREDENTIAL_PARAM.search(str(name)):
            faults.append(f"param {name}: a credential would travel")
    if step.get("privileged"):
        faults.append("privileged")
    if "file" in step:
        faults.append("a task file: its config is not reviewable here")
    # Every string the step carries, with shell line continuations joined so
    # one command reads as one line.
    text = "\n".join(_strings(step)).replace("\\\n", " ")
    config = step.get("config") or {}
    named = HOST_ONLY.search(TASK_LOCAL.sub("", text))
    if named:
        faults.append(f"names a host service: {named.group(0)}")
    for var in PIPELINE_VAR.finditer(text):
        name = var.group(0)[2:-2].strip('"')
        if name not in REMOTE_VARS:
            faults.append(f"carries a pipeline var: {var.group(0)}")
    registry = REGISTRY_IO.search(text)
    if registry:
        faults.append(f"reads or writes a registry: {registry.group(0)}")
    for command in SIMPLE_COMMAND_BREAK.split(text):
        if TRIVY_IMAGE.search(command) and "--input" not in command:
            faults.append(f"reads a registry: {command.strip()[:60]}")
    if "/kaniko/executor" in text and "--no-push" not in text:
        faults.append("kaniko without --no-push pushes to the registry")
    if "image_resource" in config:
        faults.append(
            "an image_resource is fetched by the remote worker: use one of the "
            "pipeline's public gets, or an image `fetch-image` made on this host"
        )
        return faults
    image = step.get("image")
    if image in HOST_IMAGES:
        return faults
    if image not in images:
        faults.append(f"image {image!r} is not a registry-image resource")
    else:
        repository = images[image]
        first = repository.split("/")[0]
        # A var, a host:port, or this host: not a registry the remote host reaches.
        if "((" in repository or ":" in first or HOST_ONLY.search(repository):
            faults.append(f"image {image!r} is {repository!r}, not a public registry")
    return faults


def _strings(node: Any) -> Iterator[str]:
    if isinstance(node, dict):
        for value in node.values():
            yield from _strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from _strings(value)
    elif node is not None:
        yield str(node)


def _timeout_wrapped(steps: Any, task_name: str, wrapped: bool = False) -> bool | None:
    """Whether `task_name` sits inside a `do:` or `try:` carrying `timeout`.

    None when the task is not found under `steps`.
    """
    if isinstance(steps, dict):
        steps = [steps]
    for step in steps or []:
        if not isinstance(step, dict):
            continue
        if step.get("task") == task_name:
            return wrapped
        # Only the body is timed: a wrapper's hooks run outside its deadline,
        # so they inherit `wrapped`, not `here`. A null timeout is none.
        here = wrapped or bool(step.get("timeout") and ("do" in step or "try" in step))
        children: list[tuple[Any, bool]] = []
        for key in ("do", "aggregate", "in_parallel"):
            if key in step:
                inner = step[key]
                body = inner.get("steps", []) if isinstance(inner, dict) else inner
                children.append((body, here))
        if "try" in step:
            children.append(([step["try"]], here))
        for hook in _HOOKS:
            if hook in step:
                children.append(([step[hook]], wrapped))
        for child, timed in children:
            found = _timeout_wrapped(child, task_name, timed)
            if found is not None:
                return found
    return None


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
    # #1177's 9 TheHub steps, #1178's 8 mykronos steps, #61951's 5 and
    # #62325's 2, less pr-gates' `integration` (#62416).
    assert len(REMOTE_COMPUTE) == 23
    assert ("thehub", "image-refresh", "build") in REMOTE_COMPUTE
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


@pytest.mark.parametrize("where", sorted(REMOTE_COMPUTE), ids="/".join)
def test_a_remote_task_is_bounded_by_a_wrapping_timeout(where: tuple[str, str, str]) -> None:
    """A task's own timeout does not cover the wait for a worker (8.3.3
    task_step: FindOrSelectWorker before MaybeTimeout), so with the remote
    host asleep an unwrapped task would hold its serial group forever."""
    pipeline, job_name, task_name = where
    doc = _load(CONCOURSE / "pipelines" / f"{pipeline}.yml")
    job = next(j for j in doc["jobs"] if j["name"] == job_name)
    assert _timeout_wrapped(job["plan"], task_name) is True, (
        f"{job_name}/{task_name} must sit in a `do:` or `try:` that carries `timeout:`"
    )


def test_the_wrapping_timeout_check_can_fail() -> None:
    task = {"task": "t", "tags": [REMOTE_TAG]}
    assert _timeout_wrapped([{"do": [task], "timeout": "20m"}], "t") is True
    assert _timeout_wrapped([{"try": task, "timeout": "20m"}], "t") is True
    assert _timeout_wrapped([{**task, "timeout": "20m"}], "t") is False
    assert _timeout_wrapped([{"do": [task]}], "t") is False
    assert _timeout_wrapped([{"do": [task], "timeout": "20m"}], "other") is None
    # A wrapper's hooks run outside its deadline.
    other = {"task": "x"}
    assert _timeout_wrapped([{"do": [other], "timeout": "20m", "ensure": task}], "t") is False
    assert _timeout_wrapped([{"do": [other], "timeout": "20m", "on_failure": task}], "t") is False
    # A null or empty timeout is none.
    assert _timeout_wrapped([{"do": [task], "timeout": None}], "t") is False
    assert _timeout_wrapped([{"do": [task], "timeout": ""}], "t") is False


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
        {**ok, "config": {"run": {"path": "sh", "args": ["-c", "echo $((thehub-token))"]}}},
        {**ok, "vars": {"token": "((hub-deploy-token))"}},
        {**ok, "ensure": {"task": "upload", "params": {"T": "((thehub-ingestion-token))"}}},
        # A registry read whose address is data, not a var (image-refresh/scan).
        {**ok, "config": {"run": {"path": "sh", "args": ["-c", 'trivy image --insecure "$c"']}}},
        {**ok, "config": {"run": {"path": "sh", "args": ["-c", "/kaniko/executor -d x"]}}},
        {**ok, "config": {"run": {"path": "sh", "args": ["-c", "trivy image --quiet img:1"]}}},
        {**ok, "config": {"run": {"path": "sh", "args": ["-c", "trivy -q image reg/x"]}}},
        # --input in the same line but another simple command
        {**ok, "config": {"run": {"args": ["-c", 'trivy image "$c" || echo --input']}}},
        {**ok, "config": {"run": {"path": "sh", "args": ["-c", "crane copy a b"]}}},
        {**ok, "config": {"run": {"path": "sh", "args": ["-c", "skopeo inspect docker://a"]}}},
        {**ok, "config": {"run": {"path": "sh", "args": ["-c", "docker pull a"]}}},
        {**ok, "config": {"run": {"path": "sh", "args": ["-c", "buildah --push a"]}}},
        # A task-level timeout does not bound the wait for a worker.
        {**ok, "timeout": "20m"},
        # A credential by name, and any image_resource: the remote worker
        # would fetch it, and the local registry never faces the LAN.
        {**ok, "params": {"HUB_DEPLOY_TOKEN": "x"}},
        {
            **ok,
            "image": None,
            "config": {"image_resource": {"source": {"repository": "((registry))/thehub"}}},
        },
        {**ok, "image": None, "config": {"image_resource": {"source": {"repository": "x/y"}}}},
        # A task-local service is fine, a host port on loopback is not.
        {**ok, "config": {"run": {"path": "sh", "args": ["-c", "curl localhost:8100"]}}},
        # Review of #1177: a build-local var, and any LAN address.
        {**ok, "config": {"run": {"path": "sh", "args": ["-c", "echo ((.:sha))"]}}},
        {**ok, "params": {"EXPECTED_SHA": "((.:sha))"}},
        {**ok, "config": {"run": {"path": "sh", "args": ["-c", "curl 192.168.0.14:5000/v2/"]}}},
        {**ok, "config": {"run": {"path": "sh", "args": ["-c", "curl http://10.0.0.5/"]}}},
        {**ok, "config": {"run": {"path": "sh", "args": ["-c", "ping 172.20.1.1"]}}},
        {**ok, "image": "thehub"},  # an artifact this host did not make
        # #1178's case, still refused: the remote registry is a var no remote
        # step may carry.
        {**ok, "config": {"run": {"path": "sh", "args": ["-c", "curl ((remote-registry))/v2/"]}}},
    ]
    def run(script: str) -> dict[str, Any]:
        return {**ok, "config": {"run": {"path": "sh", "args": ["-c", script]}}}

    allowed = [
        run("attempt=$((attempt + 1))"),  # shell arithmetic
        run("trivy image --quiet --input x.tar"),  # a tarball, not a registry
        run("trivy image \\\n  --quiet \\\n  --input x.tar"),  # one command, three lines
        run("/kaniko/executor --destination r/x:1 --no-push --tar-path i.tar"),
        # 2026-11-16: literal params, a non-secret var, a task-local Postgres,
        # and TheHub's image as the artifact `fetch-image` made on this host.
        {**ok, "params": {"PIP_CACHE_DIR": "/pipcache", "MEMORY_BUDGET_MB": "2560"}},
        {**ok, "params": {"TIME_TRAVEL_OFFSET": "((time-travel-offset))"}},
        run("export DATABASE_URL=postgresql://postgres:test@localhost:5432/thehub_test"),
        {**ok, "image": "thehub-image"},
        run("printf '%s' 1.2.3.4 > version"),  # not a private address
    ]
    for step in allowed:
        assert _remote_task_faults(step, images) == [], step
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


# ── what a remote task is given and what this host takes back (review of #1177)


def _job(where: tuple[str, str, str]) -> dict[str, Any]:
    doc = _load(CONCOURSE / "pipelines" / f"{where[0]}.yml")
    return next(j for j in doc["jobs"] if j["name"] == where[1])


def _remote_step(where: tuple[str, str, str]) -> dict[str, Any]:
    return next(s for s in _job_steps(_job(where)) if s.get("task") == where[2])


def _input_faults(step: dict[str, Any], allowed: dict[str, str | None]) -> list[str]:
    """Inputs or mappings that are not exactly what REMOTE_INPUTS allows."""
    faults = []
    names = [str(i.get("name")) for i in (step.get("config") or {}).get("inputs") or []]
    mapping = dict(step.get("input_mapping") or {})
    for name in names:
        if name not in allowed:
            faults.append(f"input {name!r} is not one this task is allowed")
    for name, want in allowed.items():
        if name in names and mapping.get(name) != want:
            faults.append(f"input {name!r} maps {mapping.get(name)!r}, not {want!r}")
    for name in mapping:
        if name not in allowed:
            faults.append(f"input_mapping {name!r} is not an allowed input")
    return faults


def test_every_remote_task_has_an_input_list() -> None:
    assert set(REMOTE_INPUTS) == set(REMOTE_COMPUTE)


@pytest.mark.parametrize("where", sorted(REMOTE_COMPUTE), ids="/".join)
def test_a_remote_task_is_given_only_its_allowed_inputs(where: tuple[str, str, str]) -> None:
    """In particular never a TheHub `get`: its .git is the repo's history."""
    faults = _input_faults(_remote_step(where), REMOTE_INPUTS[where])
    assert not faults, f"{'/'.join(where)}: {faults}"


@pytest.mark.parametrize("where", sorted(REMOTE_COMPUTE), ids="/".join)
def test_what_this_host_makes_for_a_remote_task_is_made_in_its_job(
    where: tuple[str, str, str],
) -> None:
    step = _remote_step(where)
    used = {v for v in REMOTE_INPUTS[where].values() if v} | {
        n for n in REMOTE_INPUTS[where] if REMOTE_INPUTS[where][n] is None
    }
    if step.get("image") in HOST_IMAGES:
        used.add(str(step["image"]))
    tasks = [s.get("task") for s in _job_steps(_job(where))]
    for artifact in sorted(used & set(HOST_MADE)):
        maker = HOST_MADE[artifact]
        assert maker in tasks, f"{'/'.join(where)} uses {artifact!r}, which no {maker} makes"


def test_the_input_check_can_fail() -> None:
    allowed: dict[str, str | None] = {"source": "tree", "commit": None}
    ok = {"input_mapping": {"source": "tree"},
          "config": {"inputs": [{"name": "source"}, {"name": "commit"}]}}
    assert _input_faults(ok, allowed) == []
    for bad in (
        {"config": {"inputs": [{"name": "source"}]}},  # the raw git get
        {"input_mapping": {"source": "tree"}, "config": {"inputs": [{"name": "source"},
                                                                   {"name": "secrets"}]}},
        {"input_mapping": {"source": "tree", "commit": "source"},
         "config": {"inputs": [{"name": "source"}, {"name": "commit"}]}},
    ):
        assert _input_faults(bad, allowed), bad


@pytest.mark.parametrize("where", sorted(REMOTE_COMPUTE), ids="/".join)
def test_a_gated_remote_task_writes_ran_rc_on_exit(where: tuple[str, str, str]) -> None:
    """`linux_absent` reads the FILE ran/rc: a registered `ran` directory alone
    can be a deadline or a cancel, not a run (review of #1177)."""
    if where == ("thehub", "image-refresh", "build"):
        pytest.skip("not gating, and not wrapped in linux_absent")
    step = _remote_step(where)
    outputs = {o.get("name") for o in (step.get("config") or {}).get("outputs") or []}
    text = "\n".join(_strings(step.get("config")))
    if where[2] == "linux-worker-probe":
        # Never `ran`: the probe's would outlive a remote task that timed out
        # and read as that task having exited 0.
        assert outputs == {"probed"} and "> probed/rc" in text, where
        return
    assert "ran" in outputs, f"{'/'.join(where)} declares no `ran` output"
    assert re.search(r"trap '[^']*(ran|RAN_DIR)/rc[^']*' EXIT|> ran/rc", text), (
        f"{'/'.join(where)} never writes ran/rc"
    )


def test_linux_absent_reads_the_rc_file_not_the_directory() -> None:
    anchors = _load(CONCOURSE / "pipelines" / "thehub.yml")["anchors"]
    script = "\n".join(_strings(anchors["linux_absent"]))
    assert "[ -s ran/rc ]" in script
    assert "[ -d ran ]" not in script


@pytest.mark.parametrize("where", sorted(HOST_DECIDES), ids="/".join)
def test_this_host_decides_a_gating_remote_tasks_exit_code(where: tuple[str, str, str]) -> None:
    """The step after the remote task's wrapper is the host-side decider, and
    it runs on this host."""
    plan = _job(where)["plan"]
    holder = next(i for i, s in enumerate(plan) if any(x.get("task") == where[2]
                                                       for x in _every_step([s])))
    after = plan[holder + 1] if holder + 1 < len(plan) else {}
    assert after.get("task") == HOST_DECIDES[where], (
        f"{'/'.join(where)}: the step after it is {after.get('task')!r}, not {HOST_DECIDES[where]}"
    )
    assert REMOTE_TAG not in (after.get("tags") or [])


def test_no_task_reaches_the_registry_from_a_remote_worker() -> None:
    """The local registry is published on 127.0.0.1 only, with no auth (B-054,
    D-109). No remote task names it, and no image_resource of one points at
    it: `fetch-image` pulls it here."""
    for where in sorted(REMOTE_COMPUTE):
        text = "\n".join(_strings(_remote_step(where)))
        assert "((registry))" not in text and "remote-registry" not in text, where
