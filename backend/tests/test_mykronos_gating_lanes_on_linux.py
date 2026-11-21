"""mykronos.yml's gating lanes run on a linux worker first (TheHub #61951).

The host's worker-1 used 2.5 GB while `unit` and `frontend` ran and twice held
a MyKronos deploy at the Docker VM's 4096 MB floor. So their compute moves to
the remote `linux` workers, and only the upload stays here. These lanes gate
everything behind them (`passed: [unit, ..., frontend]`), so, unlike the
scans #1178 moved, an offline laptop must not stop the risk gate: the tag is
a preference, not a pin. Concourse has no fallback from a tagged step, so the
pipeline makes one:

* the remote task follows the 5m probe in one timed `do:`, so with no linux
  worker the `do:` ends at the probe;
* `linux-finished` then reads `ran/rc`, and when no linux worker wrote one it
  fails, and `on_failure` runs the same task, untagged, on this host. When it
  cannot read `ran` at all (the worker that holds it was lost) it errors, and
  `on_error` runs that copy instead: once either way (review of #1213);
* `ran/rc` is written only once setup (apt, pip, npm) is done, so a remote
  network fault falls back here instead of failing the gate, and a signal
  (the wrapper timeout's SIGTERM) writes none, so a run cut off at its cap
  falls back too (review of #1213);
* `remote-result` decides on this host either way, and the upload runs here.

The deploy-time jobs need this host's Docker engine and registry, and
`oracle-gate` is one call to the MyKronos API: none of them is moved.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import signal
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
PIPELINE = ROOT / "deploy" / "concourse" / "pipelines" / "mykronos.yml"
HOST = "0123456789abcdef0123456789abcdef01234567"

# job -> its remote tasks, in plan order
MOVED = {
    "unit": ("pytest",),
    "frontend": ("dump-openapi", "lint-types-build"),
}
# remote task -> its copy on this host
ON_THIS_HOST = {
    ("unit", "pytest"): "pytest-on-this-host",
    ("frontend", "dump-openapi"): "dump-openapi-on-this-host",
    ("frontend", "lint-types-build"): "lint-types-build-on-this-host",
}
# The task whose `ran/rc` and commit `remote-result` reads, per job.
DECIDED = {"unit": "pytest", "frontend": "lint-types-build"}
# The jobs that must stay on this host: the Docker engine and the registry,
# or (oracle-gate) the MyKronos API, which no remote worker can reach.
STAY = ("promote", "build", "publish-backend", "publish-frontend", "demo-and-dast", "oracle-gate")
SETUP = ("apt-get install", "pip install", "npm ci")
HOOKS = ("on_success", "on_failure", "on_error", "on_abort", "ensure")


def _doc() -> dict[str, Any]:
    doc: dict[str, Any] = yaml.safe_load(PIPELINE.read_text(encoding="utf-8"))
    return doc


def _job(name: str) -> dict[str, Any]:
    return next(j for j in _doc()["jobs"] if j["name"] == name)


def _steps(node: Any) -> Iterator[dict[str, Any]]:
    """Every step under `node`, hooks included."""
    if isinstance(node, list):
        for item in node:
            yield from _steps(item)
    elif isinstance(node, dict):
        yield node
        for key in ("do", "in_parallel", "aggregate", "try", *HOOKS):
            if key in node:
                yield from _steps(node[key])


def _task(job: str, name: str) -> dict[str, Any]:
    # By identity: a YAML alias (one fallback under two hooks) is one task.
    found = list({id(s): s for s in _steps(_job(job)["plan"]) if s.get("task") == name}.values())
    assert len(found) == 1, f"{job}/{name}: {len(found)} tasks by that name"
    return found[0]


def _script(step: dict[str, Any]) -> str:
    return str(step["config"]["run"]["args"][-1])


def _holder(plan: list[dict[str, Any]], task: str) -> int:
    return next(i for i, s in enumerate(plan) if any(x.get("task") == task for x in _steps(s)))


# -- where each task runs ----------------------------------------------------


@pytest.mark.parametrize("where", sorted(ON_THIS_HOST), ids="/".join)
def test_a_gating_lanes_compute_runs_on_a_linux_worker(where: tuple[str, str]) -> None:
    assert _task(*where).get("tags") == ["linux"], f"{'/'.join(where)} is not on a linux worker"


@pytest.mark.parametrize("job", STAY)
def test_a_job_that_needs_this_host_never_names_the_linux_tag(job: str) -> None:
    tagged = [s.get("task") or s.get("get") or s.get("put") for s in _steps(_job(job)["plan"])
              if "linux" in (s.get("tags") or [])]
    assert not tagged, f"{job} needs this host, yet {tagged} would run on a linux worker"


@pytest.mark.parametrize("job", sorted(MOVED))
def test_the_upload_stays_on_this_host_and_the_remote_task_carries_no_credential(
    job: str,
) -> None:
    for name in MOVED[job]:
        step = _task(job, name)
        assert "mykronos.upload" not in _script(step), f"{job}/{name} uploads from a laptop"
        assert not any("TOKEN" in k or "MYKRONOS_URL" in k for k in step.get("params") or {})
    uploads = [s for s in _steps(_job(job)["plan"]) if "mykronos.upload" in str(s.get("config"))]
    assert uploads, f"{job} no longer uploads its result"
    for step in uploads:
        assert not step.get("tags"), f"{job}/{step['task']}: the upload must run on this host"
        assert "MYKRONOS_TOKEN" in (step.get("params") or {})
        # This host's commit, never the file a laptop wrote.
        assert "/commit)" not in _script(step) and "rev-parse HEAD)" in _script(step)


# -- the plan: probe, remote, fallback, this host decides --------------------


@pytest.mark.parametrize("job", sorted(MOVED))
def test_the_remote_tasks_start_only_once_a_linux_worker_took_the_probe(job: str) -> None:
    plan = _job(job)["plan"]
    wrapper = plan[_holder(plan, MOVED[job][0])]
    assert set(wrapper) == {"try"}, f"{job}: the remote tasks are not in a bare `try:`"
    body = wrapper["try"]
    assert body.get("timeout") and isinstance(body.get("do"), list), (
        f"{job}: the `try:` body must be one timed `do:` (the wait for a worker counts)"
    )
    first, *rest = body["do"]
    # The probe, in its own 5m wrapper: when it times out the `do:` ends here.
    assert first.get("timeout") == "5m"
    assert [s.get("task") for s in first["do"]] == ["linux-worker-probe"]
    assert "linux" in first["do"][0]["tags"]
    assert [s.get("task") for s in rest] == list(MOVED[job])


def _fallback(job: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """The step after the remote run, and the `linux-finished` inside it."""
    plan = _job(job)["plan"]
    after = plan[_holder(plan, MOVED[job][0]) + 1]
    assert set(after) == {"try"}, f"{job}: the fallback must not fail the build itself"
    body = after["try"]
    assert [s.get("task") for s in body.get("do") or []] == ["linux-finished"], (
        f"{job}: linux-finished must sit alone in a `do:` (its on_error inside, "
        "on_failure outside, so this host runs the lane once)"
    )
    return after, body["do"][0]


@pytest.mark.parametrize("job", sorted(MOVED))
def test_this_host_runs_the_lane_when_no_linux_worker_finished_it(job: str) -> None:
    after, check = _fallback(job)
    assert check.get("task") == "linux-finished" and not check.get("tags")
    assert check["params"]["LINUX_STEP"] == f"{job}/{DECIDED[job]}"
    # [review of #1213] A lost worker holds `ran`: linux-finished cannot stream
    # it and ERRORS, and on_failure never runs on an error (on_failure.go).
    fallback = after["try"].get("on_failure")
    assert fallback is not None and check.get("on_error") == fallback, (
        f"{job}: the same copy must run on linux-finished's failure and on its error"
    )
    assert "on_failure" not in check, f"{job}: on_failure beside on_error can run it twice"
    copies = fallback.get("do", [fallback])
    assert [c.get("task") for c in copies] == [ON_THIS_HOST[(job, n)] for n in MOVED[job]]
    for copy, name in zip(copies, MOVED[job], strict=True):
        remote = _task(job, name)
        assert not copy.get("tags"), f"{copy['task']} must run on this host"
        # A host task's own timeout bounds its run; it needs no wrapper.
        assert copy.get("timeout"), f"{copy['task']} has no timeout"
        same = {k: v for k, v in copy.items() if k not in {"task", "tags", "timeout"}}
        assert same == {k: v for k, v in remote.items() if k not in {"task", "tags"}}, (
            f"{copy['task']} is not {job}/{name} with the tag removed"
        )


# Concourse 8.3.3's rules for the steps the fallback is made of, from its
# source: one step's hooks nest in atc/steps.go's StepPrecedence order
# (on_error outside on_failure); on_failure.go runs its hook on a failure,
# never on an error; on_error.go runs its hook on an error and still returns
# the error; try_step.go turns a failure or an error into success; a `do:`
# stops at the first step that fails or errors.
OUTCOME = {"succeeded": (True, False), "failed": (False, False), "errored": (False, True)}


def _concourse(step: dict[str, Any], outcome: dict[str, tuple[bool, bool]],
               ran: list[str]) -> tuple[bool, bool]:
    """Run `step` by those rules: (succeeded, errored). Records each task run."""
    if "on_error" in step:
        ok, err = _concourse({k: v for k, v in step.items() if k != "on_error"}, outcome, ran)
        if err:
            _concourse(step["on_error"], outcome, ran)
        return ok, err
    if "on_failure" in step:
        ok, err = _concourse({k: v for k, v in step.items() if k != "on_failure"}, outcome, ran)
        if ok or err:
            return ok, err
        return False, _concourse(step["on_failure"], outcome, ran)[1]
    if "try" in step:
        _concourse(step["try"], outcome, ran)
        return True, False
    if "do" in step:
        for sub in step["do"]:
            ok, err = _concourse(sub, outcome, ran)
            if err or not ok:
                return ok, err
        return True, False
    ran.append(step["task"])
    return outcome[step["task"]]


@pytest.mark.parametrize("here", sorted(OUTCOME))
@pytest.mark.parametrize("finished", sorted(OUTCOME))
@pytest.mark.parametrize("job", sorted(MOVED))
def test_this_host_runs_the_lane_once_unless_linux_finished_passed(
    job: str, finished: str, here: str
) -> None:
    """`errored` is the lost worker (review of #1213): linux-finished cannot
    stream a `ran` that lives on it. A copy here that errors must not run
    again, and nothing in this step may stop the build."""
    after, _ = _fallback(job)
    outcome = {"linux-finished": OUTCOME[finished]}
    outcome |= {ON_THIS_HOST[(job, n)]: OUTCOME[here] for n in MOVED[job]}
    ran: list[str] = []
    assert _concourse(after, outcome, ran) == (True, False)
    first = ON_THIS_HOST[(job, MOVED[job][0])]
    assert ran.count(first) == (0 if finished == "succeeded" else 1), (
        f"linux-finished {finished}, this host's copy {here}: ran {ran}"
    )


@pytest.mark.parametrize("job", sorted(MOVED))
def test_this_host_decides_what_either_run_is_worth(job: str) -> None:
    plan = _job(job)["plan"]
    i = _holder(plan, MOVED[job][0])
    decide, checked = plan[i + 2], plan[i + 3]
    assert decide.get("task") == "remote-result" and not decide.get("tags")
    assert decide["params"]["LINUX_STEP"] == f"{job}/{DECIDED[job]}"
    assert decide["params"].get("HOST_FALLBACK") == "1"
    assert checked.get("file") == "checked/ok" and "load_var" in checked


@pytest.mark.parametrize("where", sorted(ON_THIS_HOST), ids="/".join)
def test_ran_rc_is_written_only_once_setup_is_done(where: tuple[str, str]) -> None:
    """An apt, pip or npm failure judged nothing on this commit: on a laptop
    it leaves no ran/rc, so this host runs the lane instead."""
    script = _script(_task(*where))
    lines = [ln.strip() for ln in script.splitlines() if not ln.strip().startswith("#")]
    trap = next((i for i, ln in enumerate(lines) if ln.startswith("trap ") and "RAN_DIR/rc" in ln),
                None)
    assert trap is not None, f"{'/'.join(where)} never writes ran/rc"
    setup = [i for i, ln in enumerate(lines) if any(s in ln for s in SETUP)]
    assert setup and max(setup) < trap, f"{'/'.join(where)} writes ran/rc before its setup ends"
    assert any(o["name"] == "ran" for o in _task(*where)["config"]["outputs"])
    # [review of #1213] The signal trap first: a SIGTERM between the two
    # lines would otherwise run the EXIT trap and write ran/rc.
    term = next((i for i, ln in enumerate(lines) if ln.startswith("trap ") and "TERM" in ln),
                None)
    assert term is not None and term < trap, (
        f"{'/'.join(where)}: a signal must clear the EXIT trap, set before it"
    )


def test_the_contract_dump_writes_ran_rc_only_when_it_failed() -> None:
    """A good dump leaves `ran` empty for lint-types-build to fill: a stale
    0 would read as a finished lane when the build was cut short."""
    script = _script(_task("frontend", "dump-openapi"))
    assert '[ "$rc" -eq 0 ] || printf' in script


def test_the_built_commit_is_reported_for_remote_result() -> None:
    script = _script(_task("frontend", "lint-types-build"))
    assert "../.git/ref ../../verdict/commit" in script
    assert "git -C .. rev-parse HEAD > ../../results/commit" in _script(_task("unit", "pytest"))


@pytest.mark.parametrize(
    ("job", "minutes"),
    # max(2 x p95, p95 + 10m) over the job's succeeded builds (#1178's rule
    # for a remote wrapper): unit 64.7m, frontend 12.3m, read 2026-11-21.
    [("unit", 130), ("frontend", 25)],
)
def test_the_remote_wrapper_is_capped_by_the_measured_rule(job: str, minutes: int) -> None:
    plan = _job(job)["plan"]
    assert plan[_holder(plan, MOVED[job][0])]["try"]["timeout"] == f"{minutes}m"


# -- the scripts, executed ---------------------------------------------------


def _sh() -> str:
    found = shutil.which("bash") or shutil.which("sh")
    if found is None:
        pytest.skip("no POSIX shell on this host")
    return found


@pytest.mark.parametrize(
    ("rc", "code"),
    [("0\n", 0), ("1\n", 0), ("", 1), (None, 1)],
    ids=["finished-green", "finished-red", "empty-ran", "no-ran"],
)
def test_linux_finished_falls_back_only_when_no_rc_was_written(
    tmp_path: Path, rc: str | None, code: int
) -> None:
    step = _doc()["anchors"]["linux_finished"]
    assert step["task"] == "linux-finished" and step.get("timeout")
    assert step["config"]["inputs"] == [{"name": "ran", "optional": True}]
    if rc is not None:
        (tmp_path / "ran").mkdir()
        if rc:
            (tmp_path / "ran" / "rc").write_text(rc, encoding="ascii")
    proc = subprocess.run(
        [_sh(), "-c", _script(step)],
        cwd=tmp_path,
        env={**os.environ, "LINUX_STEP": "unit/pytest"},
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == code, proc.stdout + proc.stderr
    assert "unit/pytest" in proc.stdout


# -- a run cut off at its cap (review of #1213) ------------------------------
#
# A wrapper timeout makes Concourse 8.3.3 send SIGTERM to every process in the
# task's container, SIGKILL 10s later, and register the task's outputs
# whatever happened (atc/exec/task_step.go). Before the fix, bash's EXIT trap
# ran on the SIGTERM with `$?` = the last finished command's status, 0, so
# `ran/rc` read 0, linux-finished passed, and this host never ran the lane.
# These run each gating script as its task does (`bash -ec`), its tools
# stubbed on PATH, and signal its process group as Garden signals the
# container. Two paths outside the task's directory, /etc/apt and /tmp, are
# moved into the test's own.

_STUB_HEAD = (
    "#!/bin/sh\n"
    '_long() { [ "$STUB_MODE" = hang ] || return 0; : > "$STUB_STARTED"; exec sleep 120; }\n'
)
_STUBS = {
    "apt-get": "exit 0",
    "pip": "exit 0",
    "git": 'echo "$HOST_SHA"',
    "npm": '[ "$1 $2" = "run build" ] && _long\nexit 0',
    "npx": 'out=\nwhile [ $# -gt 0 ]; do [ "$1" = -o ] && out=$2; shift; done\n'
           'cp lib/api-types.d.ts "$out"',
    "python": 'case "$1" in\n'
              '  ../scripts/memory_kill.py) [ "$2" = run ] && _long; exit 0 ;;\n'
              '  scripts/dump_openapi.py) _long; [ "$STUB_MODE" = fail ] && exit 3\n'
              '    echo "{}" > "$2" ;;\n'
              "esac\n"
              "exit 0",
}
# task -> the stub mode in which the script runs to its end, and the ran/rc
# that end writes (a good dump writes none, so its control is a failed one)
_FINISHED = {
    ("unit", "pytest"): ("done", "0"),
    ("frontend", "dump-openapi"): ("fail", "3"),
    ("frontend", "lint-types-build"): ("done", "0"),
}


# POSIX only; the tests that send it skip where there are no process groups.
_SIGKILL = getattr(signal, "SIGKILL", signal.SIGTERM)


def _signal_group(pgid: int, sig: int) -> None:
    """Every process in the group, as Garden signals a container's."""
    with contextlib.suppress(ProcessLookupError):
        os.kill(-pgid, sig)


def _run_cut_off(tmp_path: Path, where: tuple[str, str], mode: str) -> tuple[Path, str]:
    """Run the task's script; in `hang` mode, SIGTERM it in its long step.
    Returns the task directory and the shell's output."""
    if not hasattr(os, "killpg") or shutil.which("bash") is None:
        pytest.skip("needs bash and POSIX process groups (CI runs this on linux)")
    stubs, work, scratch = tmp_path / "bin", tmp_path / "task", tmp_path / "scratch"
    for d in (stubs, scratch, work / "source" / "backend", work / "source" / "scripts",
              work / "source" / "frontend" / "lib", work / "source" / ".git",
              *(work / o for o in ("ran", "judged", "results", "verdict", "contract"))):
        d.mkdir(parents=True, exist_ok=True)
    for name, body in _STUBS.items():
        (stubs / name).write_text(_STUB_HEAD + body + "\n", encoding="ascii")
        (stubs / name).chmod(0o755)
    (work / "source" / ".git" / "ref").write_text(HOST + "\n", encoding="ascii")
    (work / "source" / "frontend" / "lib" / "api-types.d.ts").write_text("x\n", encoding="ascii")
    (work / "contract" / "openapi.json").write_text("{}\n", encoding="ascii")
    step = _task(*where)
    script = _script(step).replace("/tmp/", f"{scratch}/")
    script = script.replace("/etc/apt/apt.conf.d/", f"{scratch}/")
    started = scratch / "started"
    env = {
        **os.environ,
        **{k: str(v) for k, v in (step.get("params") or {}).items()},
        "PATH": f"{stubs}{os.pathsep}{os.environ.get('PATH', '')}",
        "STUB_MODE": mode,
        "STUB_STARTED": str(started),
        "HOST_SHA": HOST,
    }
    proc = subprocess.Popen(
        ["bash", "-ec", script], cwd=work, env=env, start_new_session=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        if mode == "hang":
            deadline = time.monotonic() + 30
            while not started.exists() and proc.poll() is None and time.monotonic() < deadline:
                time.sleep(0.05)
            assert started.exists(), "the script never reached its long step"
            _signal_group(proc.pid, signal.SIGTERM)  # the wrapper timeout
            try:
                out = proc.communicate(timeout=10)[0]  # Garden's grace period
            except subprocess.TimeoutExpired:
                _signal_group(proc.pid, _SIGKILL)
                out = proc.communicate(timeout=10)[0]
        else:
            out = proc.communicate(timeout=60)[0]
    finally:
        if proc.poll() is None:
            _signal_group(proc.pid, _SIGKILL)
            proc.communicate(timeout=10)
    return work, out


def _linux_finished(work: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["sh", "-c", _script(_doc()["anchors"]["linux_finished"])],
        cwd=work, env={**os.environ, "LINUX_STEP": "the lane"},
        capture_output=True, text=True, timeout=60,
    )


@pytest.mark.parametrize("where", sorted(ON_THIS_HOST), ids="/".join)
def test_a_run_cut_off_at_its_cap_leaves_no_ran_rc_so_this_host_runs_it(
    tmp_path: Path, where: tuple[str, str]
) -> None:
    work, out = _run_cut_off(tmp_path, where, "hang")
    rc_file = work / "ran" / "rc"
    rc = rc_file.read_text(encoding="ascii").strip() if rc_file.exists() else None
    assert rc is None, f"{'/'.join(where)} wrote ran/rc={rc!r} on SIGTERM:\n{out}"
    assert _linux_finished(work).returncode == 1, "linux-finished must fall back to this host"


@pytest.mark.parametrize("where", sorted(ON_THIS_HOST), ids="/".join)
def test_the_same_run_left_to_finish_writes_ran_rc(tmp_path: Path, where: tuple[str, str]) -> None:
    """The harness reaches the trap: without this, the test above could pass
    on a script that died before it."""
    mode, want = _FINISHED[where]
    work, out = _run_cut_off(tmp_path, where, mode)
    assert (work / "ran" / "rc").read_text(encoding="ascii").strip() == want, out
    assert _linux_finished(work).returncode == 0


def _report_gate() -> str:
    """The frontend report's lines up to the decision whether to report."""
    report = _job("frontend")["plan"]
    hook = next(s["ensure"] for s in report if s.get("task") == "remote-result")
    assert hook.get("task") == "report" and not hook.get("tags")
    names = {i["name"]: i.get("optional", False) for i in hook["config"]["inputs"]}
    assert names == {"source": False, "verdict": True, "ran": True, "checked": True}, names
    lines = _script(hook).splitlines()
    end = next(i for i, ln in enumerate(lines) if "esac" in ln)
    start = next(i for i, ln in enumerate(lines) if "case " in ln and "ran/rc" in ln)
    return "\n".join(lines[start : end + 1])


@pytest.mark.parametrize(
    ("rc", "ok", "reported"),
    [
        ("0", True, True),  # checked on this host
        ("1", False, True),  # ran and failed: a verdict without the commit check
        ("0", False, False),  # refused by remote-result
        (None, False, False),  # nothing finished anywhere
        ("x", False, False),  # not an exit code
    ],
)
def test_the_frontend_report_uploads_a_verdict_and_nothing_else(
    tmp_path: Path, rc: str | None, ok: bool, reported: bool
) -> None:
    for name in ("ran", "checked"):
        (tmp_path / name).mkdir()
    if rc is not None:
        (tmp_path / "ran" / "rc").write_text(rc + "\n", encoding="ascii")
    if ok:
        (tmp_path / "checked" / "ok").write_text(HOST + "\n", encoding="ascii")
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("no bash on this host")
    # The task's own shell: `bash -ec` and `set -uo pipefail`.
    proc = subprocess.run(
        [bash, "-ec", f"set -uo pipefail\n{_report_gate()}\necho REPORTED"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert ("REPORTED" in proc.stdout) is reported, proc.stdout


def _remote_result(tmp_path: Path, rc: str | None) -> subprocess.CompletedProcess[str]:
    script = _doc()["anchors"]["remote_result"]["config"]["run"]["args"][-1]
    (tmp_path / "source" / ".git").mkdir(parents=True)
    (tmp_path / "source" / ".git" / "HEAD").write_text(HOST + "\n", encoding="ascii")
    (tmp_path / "checked").mkdir()
    if rc is not None:
        (tmp_path / "ran").mkdir()
        (tmp_path / "ran" / "rc").write_text(rc + "\n", encoding="ascii")
    env = {"PATH": "", "LINUX_STEP": "unit/pytest", "COMMIT_FILE": "commit"}
    return subprocess.run(
        [sys.executable, "-I", "-c", script],
        cwd=tmp_path,
        env={**env, "HOST_FALLBACK": "1"},
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_remote_result_says_this_hosts_run_failed_too(tmp_path: Path) -> None:
    proc = _remote_result(tmp_path, None)
    assert proc.returncode == 0 and not (tmp_path / "checked" / "ok").exists()
    assert "this host's own run" in proc.stdout, proc.stdout
    assert "fly workers" not in proc.stdout, "a fallback lane needs no linux worker to re-run"
    # Review of #1213, finding 3: a lock the commit broke fails setup here
    # every time, so the hint must not promise that a re-run fixes it.
    assert "fix the commit" in proc.stdout, proc.stdout


def test_remote_result_does_not_claim_a_linux_worker_ran_a_fallback_lane(tmp_path: Path) -> None:
    """Review of #1213: with HOST_FALLBACK the failed run may be this host's."""
    proc = _remote_result(tmp_path, "1")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "exited 1" in proc.stdout and "ran on a linux worker" not in proc.stdout, proc.stdout
