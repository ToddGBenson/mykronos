"""thehub.yml's `unit` runs on a linux worker first (TheHub #62325).

TheHub's unit suite ran on worker-2, the host lane a TheHub production freeze
loads, and failed there five times running: three at the 90m cap, one SIGKILL
in the 3 GiB cgroup, and two at the soft timeout with the suite at 4,747 s.
So its compute moves to the remote `linux` workers, as mykronos #1213 did for
MyKronos's `unit` (TheHub #61951), and the same rules hold:

* `unit` gates build, containers, Oracle and both deploys, so an offline
  laptop must not stop them: the tag is a preference, not a pin. The remote
  task follows the 5m probe in one timed `do:`;
* `linux-finished` reads `ran/rc`; when no linux worker wrote one it fails,
  and `on_failure` runs the same task on this host; when it cannot read `ran`
  at all (a lost worker) it errors, and `on_error` runs that copy instead.
  Once either way;
* `ran/rc` is written only once apt and pip are done, and never on a signal,
  so a laptop's network fault and a run cut off at its cap both run here;
* this host decides (`linux-verdict`, bound to the commit `export-tree`
  exported) and uploads (`upload-unit`, the only step with the token).

What is thehub.yml's own: TheHub's history never reaches a laptop (#398), so
both copies run on `export-tree`'s tree, with the commit beside it, and the
copy here keeps worker-2's placement and #1222's limits (100m, 4800 s).
"""

from __future__ import annotations

import contextlib
import os
import shutil
import signal
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
PIPELINE = ROOT / "deploy" / "concourse" / "pipelines" / "thehub.yml"
HOST = "0123456789abcdef0123456789abcdef01234567"
HOOKS = ("on_success", "on_failure", "on_error", "on_abort", "ensure")
SETUP = ("apt-get install", "pip install")


def _doc() -> dict[str, Any]:
    doc: dict[str, Any] = yaml.safe_load(PIPELINE.read_text(encoding="utf-8"))
    return doc


def _unit() -> dict[str, Any]:
    return next(j for j in _doc()["jobs"] if j["name"] == "unit")


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


def _task(name: str) -> dict[str, Any]:
    # By identity: a YAML alias (one copy under two hooks) is one task.
    found = list({id(s): s for s in _steps(_unit()["plan"]) if s.get("task") == name}.values())
    assert len(found) == 1, f"unit/{name}: {len(found)} tasks by that name"
    return found[0]


def _script(step: dict[str, Any]) -> str:
    return str(step["config"]["run"]["args"][-1])


def _holder(plan: list[dict[str, Any]], task: str) -> int:
    return next(i for i, s in enumerate(plan) if any(x.get("task") == task for x in _steps(s)))


# -- where each task runs ----------------------------------------------------


def test_the_suite_runs_on_a_linux_worker() -> None:
    assert _task("pytest").get("tags") == ["linux"]


def test_the_suite_is_given_the_tree_and_the_commit_never_the_git_get() -> None:
    """TheHub's history has held secrets (#398): no `.git` reaches a laptop."""
    step = _task("pytest")
    assert step.get("input_mapping") == {"source": "tree"}
    names = [i["name"] for i in step["config"]["inputs"]]
    assert names == ["source", "commit"], names
    plan = _unit()["plan"]
    export = _holder(plan, "export-tree")
    assert export < _holder(plan, "pytest")
    assert plan[export].get("tags") == ["thehub"]


def test_the_suite_carries_no_credential_and_does_not_upload() -> None:
    step = _task("pytest")
    params = step.get("params") or {}
    assert not any("TOKEN" in k or k.startswith("MYKRONOS_") for k in params), sorted(params)
    assert "SCANNED_BRANCH" not in params
    script = _script(step)
    assert "mykronos.upload" not in script and "MYKRONOS_INSTALL_UPLOADER" not in script
    # No git history to ask: the commit is the file this host exported.
    assert "git rev-parse" not in script


def test_the_upload_runs_on_this_host_with_this_hosts_commit() -> None:
    uploads = [s for s in _steps(_unit()["plan"]) if "mykronos.upload" in str(s.get("config"))]
    assert [s.get("task") for s in uploads] == ["upload-unit"]
    (step,) = uploads
    assert step.get("tags") == ["thehub"], "the upload must run on this host"
    assert "MYKRONOS_TOKEN" in (step.get("params") or {})
    names = {i["name"] for i in step["config"]["inputs"]}
    assert {"source", "results", "ran", "commit"} <= names, names
    script = _script(step)
    # This host's commit, from its own checkout, never a file a laptop wrote.
    assert '--commit-sha "$(git rev-parse HEAD)"' in script


# -- the plan: probe, remote, fallback, this host decides --------------------


def _remote() -> dict[str, Any]:
    plan = _unit()["plan"]
    return plan[_holder(plan, "pytest")]


def test_the_suite_starts_only_once_a_linux_worker_took_the_probe() -> None:
    wrapper = _remote()
    assert set(wrapper) == {"try"}, "the remote run is not in a bare `try:`"
    body = wrapper["try"]
    assert body.get("timeout") and isinstance(body.get("do"), list), (
        "the `try:` body must be one timed `do:` (the wait for a worker counts)"
    )
    first, *rest = body["do"]
    assert first.get("timeout") == "5m"
    assert [s.get("task") for s in first["do"]] == ["linux-worker-probe"]
    assert first["do"][0]["tags"] == ["linux"]
    # No linux_absent hook: no linux worker is not an outage here, it is a
    # run on this host.
    assert not any(h in first for h in HOOKS)
    assert [s.get("task") for s in rest] == ["pytest"]


def test_the_remote_wrapper_is_capped_by_the_measured_rule() -> None:
    """max(2 x p95, p95 + 10m), #1178's rule: the suite's p95 on this host is
    #434's 4,747 s (79.1m), so 2 x 79.1 = 158.2, rounded up to 160m. It also
    covers what the task allows itself: 5m probe, a cold pip cache on a
    worker that has none (~45m), 4,800 s of unit and 600 s of security."""
    assert _remote()["try"]["timeout"] == "160m"


def _fallback() -> tuple[dict[str, Any], dict[str, Any]]:
    plan = _unit()["plan"]
    after = plan[_holder(plan, "pytest") + 1]
    assert set(after) == {"try"}, "the fallback must not fail the build itself"
    body = after["try"]
    assert [s.get("task") for s in body.get("do") or []] == ["linux-finished"], (
        "linux-finished must sit alone in a `do:` (its on_error inside, "
        "on_failure outside, so this host runs the suite once)"
    )
    return after, body["do"][0]


def test_this_host_runs_the_suite_when_no_linux_worker_finished_it() -> None:
    after, check = _fallback()
    assert check.get("tags") == ["thehub"]
    assert check["params"]["LINUX_STEP"] == "unit/pytest"
    fallback = after["try"].get("on_failure")
    assert fallback is not None and check.get("on_error") == fallback, (
        "the same copy must run on linux-finished's failure and on its error"
    )
    assert "on_failure" not in check, "on_failure beside on_error can run it twice"
    assert fallback.get("task") == "pytest-on-this-host"
    # This host's placement: worker-2, as before (test_concourse_worker_tags).
    assert fallback.get("tags") == ["thehub"]
    # #1222's cap, unchanged: the copy here is the job as it ran before.
    assert fallback.get("timeout") == "100m"
    remote = _task("pytest")
    same = {k: v for k, v in fallback.items() if k not in {"task", "tags", "timeout"}}
    assert same == {k: v for k, v in remote.items() if k not in {"task", "tags"}}, (
        "pytest-on-this-host is not unit/pytest with this host's tag and cap"
    )


# Concourse 8.3.3's rules for the steps the fallback is made of (see
# test_mykronos_gating_lanes_on_linux.py): one step's hooks nest with
# on_error outside on_failure; on_failure runs on a failure, never on an
# error; on_error runs on an error and still returns it; try turns either
# into success; a `do:` stops at the first step that fails or errors.
OUTCOME = {"succeeded": (True, False), "failed": (False, False), "errored": (False, True)}


def _concourse(step: dict[str, Any], outcome: dict[str, tuple[bool, bool]],
               ran: list[str]) -> tuple[bool, bool]:
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
def test_this_host_runs_the_suite_once_unless_linux_finished_passed(
    finished: str, here: str
) -> None:
    plan = _unit()["plan"]
    after = plan[_holder(plan, "pytest") + 1]
    outcome = {"linux-finished": OUTCOME[finished], "pytest-on-this-host": OUTCOME[here]}
    ran: list[str] = []
    assert _concourse(after, outcome, ran) == (True, False)
    assert ran.count("pytest-on-this-host") == (0 if finished == "succeeded" else 1), ran


def test_this_host_decides_and_then_uploads() -> None:
    plan = _unit()["plan"]
    decide = plan[_holder(plan, "pytest") + 2]
    assert decide.get("task") == "linux-verdict" and decide.get("tags") == ["thehub"]
    assert decide.get("input_mapping") == {"expect": "commit"}
    assert decide["params"] == {"EXPECT": "sha", "LINUX_STEP": "unit/pytest",
                                "HOST_FALLBACK": "1"}
    # The upload runs whatever the verdict: a red suite still reports, as it
    # did when the upload sat before the exit in one task.
    assert decide["ensure"].get("task") == "upload-unit"
    assert plan[-1] is decide, "nothing after the verdict may stop the upload"


def test_linux_finished_is_the_anchor_mykronos_uses() -> None:
    ours = _doc()["anchors"]["linux_finished"]
    theirs = yaml.safe_load(
        (PIPELINE.parent / "mykronos.yml").read_text(encoding="utf-8")
    )["anchors"]["linux_finished"]
    # The same script; only the name of the step that checks next differs.
    assert ours["config"]["run"]["args"][:-1] == theirs["config"]["run"]["args"][:-1]
    assert _script(ours) == _script(theirs).replace("remote-result", "linux-verdict")
    assert ours["config"]["inputs"] == theirs["config"]["inputs"] == [
        {"name": "ran", "optional": True}
    ]
    assert ours.get("tags") == ["thehub"] and ours.get("timeout")


# -- the script --------------------------------------------------------------


def _lines(script: str) -> list[str]:
    return [ln.strip() for ln in script.splitlines() if not ln.strip().startswith("#")]


def test_ran_rc_is_written_only_once_setup_is_done_and_never_on_a_signal() -> None:
    step = _task("pytest")
    lines = _lines(_script(step))
    trap = next((i for i, ln in enumerate(lines) if ln.startswith("trap ") and "RAN_DIR/rc" in ln
                 and ln.endswith("EXIT")), None)
    assert trap is not None, "unit/pytest never writes ran/rc"
    setup = [i for i, ln in enumerate(lines) if any(s in ln for s in SETUP)]
    assert setup and max(setup) < trap, "ran/rc is written before apt and pip are done"
    term = next((i for i, ln in enumerate(lines)
                 if ln == "trap 'trap - EXIT; exit 143' TERM INT HUP"), None)
    assert term is not None and term < trap, "a signal must clear the EXIT trap, set before it"
    outputs = {o["name"]: o for o in step["config"]["outputs"]}
    assert {"ran", "results", "infra", "notify"} <= set(outputs), sorted(outputs)
    assert outputs["infra"].get("path") == "memory-infra"
    assert 'head -c 64 commit/sha > "$RAN_DIR/commit"' in _script(step)


def test_the_limits_hold_on_both_paths() -> None:
    """One script on both paths: the soft timeouts, and the memory guard
    sized by the suite's real length (#1222 review N1: 2760 was the old one)."""
    script = _script(_task("pytest"))
    assert "SOFT_TIMEOUT_S=4800" in script
    assert "SEC_SOFT_TIMEOUT_S=600" in script
    assert "MEMORY_GUARD_EXPECTED_S=4300" in script
    assert "MEMORY_GUARD_EXPECTED_S=2760" not in script
    # #1222 review N5: a pytest that ignores SIGINT is killed, not waited on.
    assert script.count('timeout -s INT -k 60s "${') == 2, "both tiers' soft timeouts need -k"
    assert 'timeout -s INT "${' not in script


def test_the_suite_writes_its_report_where_upload_unit_reads_it() -> None:
    script = _script(_task("pytest"))
    assert "/tmp/results" not in script
    assert '--junitxml="$RESULTS/unit.xml"' in script
    assert '--junitxml="$RESULTS/security.xml"' in script
    upload = _script(_task("upload-unit"))
    assert "--results-path ../../results" in upload


# -- the scripts, executed ---------------------------------------------------


def _sh() -> str:
    found = shutil.which("bash")
    if found is None:
        pytest.skip("no bash on this host")
    return found


def test_linux_verdict_says_this_hosts_run_failed_too(tmp_path: Path) -> None:
    """With HOST_FALLBACK and no ran/rc both runs failed their setup: a
    re-run needs no linux worker, and a broken requirements file needs a
    fixed commit."""
    script = _script(_doc()["anchors"]["linux_verdict"])
    (tmp_path / "infra").mkdir()
    proc = subprocess.run(
        [_sh(), "-c", script], cwd=tmp_path,
        env={**os.environ, "LINUX_STEP": "unit/pytest", "EXPECT": "sha", "HOST_FALLBACK": "1"},
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    reason = (tmp_path / "infra" / "reason").read_text(encoding="utf-8")
    assert "this host's own run" in reason and "fix the commit" in reason, reason
    assert "fly workers" not in reason


def test_linux_verdict_without_host_fallback_is_unchanged(tmp_path: Path) -> None:
    script = _script(_doc()["anchors"]["linux_verdict"])
    (tmp_path / "infra").mkdir()
    proc = subprocess.run(
        [_sh(), "-c", script], cwd=tmp_path,
        env={**os.environ, "LINUX_STEP": "pr-gates/gates", "EXPECT": "sha"},
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 1
    reason = (tmp_path / "infra" / "reason").read_text(encoding="utf-8")
    assert "ran/rc is not an exit code" in reason and "this host's own run" not in reason


def _upload_gate() -> str:
    """upload-unit's lines up to the uploader install: the decision to send."""
    lines = _script(_task("upload-unit")).splitlines()
    end = next(i for i, ln in enumerate(lines) if "MYKRONOS_INSTALL_UPLOADER" in ln)
    return "\n".join(lines[:end])


@pytest.mark.parametrize(
    ("rc", "commit", "report", "sent"),
    [
        ("0", HOST, True, True),  # green, this host's commit
        ("1", HOST, True, True),  # red: a verdict still reports
        ("137", HOST, True, True),  # killed for memory: the junit as before
        ("0", "f" * 40, True, False),  # another commit: linux-verdict refused it
        (None, HOST, True, False),  # nothing finished anywhere
        ("x", HOST, True, False),  # not an exit code
        ("1", HOST, False, False),  # setup failed after the trap: no report
    ],
)
def test_upload_unit_sends_only_a_checked_report(
    tmp_path: Path, rc: str | None, commit: str, report: bool, sent: bool
) -> None:
    for name in ("ran", "commit", "results"):
        (tmp_path / name).mkdir()
    (tmp_path / "commit" / "sha").write_text(HOST + "\n", encoding="ascii")
    (tmp_path / "ran" / "commit").write_text(commit + "\n", encoding="ascii")
    if rc is not None:
        (tmp_path / "ran" / "rc").write_text(rc + "\n", encoding="ascii")
    if report:
        (tmp_path / "results" / "unit.xml").write_text("<testsuites/>\n", encoding="ascii")
    stubs = tmp_path / "bin"
    stubs.mkdir()
    (stubs / "apt-get").write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
    (stubs / "apt-get").chmod(0o755)
    script = _upload_gate().replace("/etc/apt/apt.conf.d/", f"{tmp_path.as_posix()}/")
    proc = subprocess.run(
        [_sh(), "-ec", f"{script}\necho SENDING"], cwd=tmp_path,
        env={**os.environ, "PATH": f"{stubs.as_posix()}{os.pathsep}{os.environ.get('PATH', '')}"},
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert ("SENDING" in proc.stdout) is sent, proc.stdout


# -- a run cut off at its cap (review of #1213) ------------------------------
#
# A wrapper timeout makes Concourse send SIGTERM to the task's processes and
# register its outputs anyway; an EXIT trap alone then wrote ran/rc=0 and the
# fallback never ran. The unit script is run as its task runs it (`bash -ec`),
# every tool it calls stubbed on PATH, and its process group signalled in the
# long step.

_STUB_HEAD = (
    "#!/bin/sh\n"
    '_long() { [ "$STUB_MODE" = hang ] || return 0; : > "$STUB_STARTED"; exec sleep 120; }\n'
)
_STUBS = {
    "apt-get": "exit 0",
    "pip": "exit 0",
    "node": "echo v20.0.0",
    "service": "exit 0",
    "pg_ctlcluster": "exit 0",
    # psql's counts: enum types, users and tables, all over their floors.
    "su": "cat >/dev/null 2>&1 || true\necho 60",
    "python": 'case "$1" in\n'
              '  -c) case "$2" in *memory-guard*) _long ;; *secrets*) echo t ;; esac ;;\n'
              "esac\n"
              "exit 0",
}


_SIGKILL = getattr(signal, "SIGKILL", signal.SIGTERM)


def _signal_group(pgid: int, sig: int) -> None:
    with contextlib.suppress(ProcessLookupError):
        os.kill(-pgid, sig)


def _run_unit(tmp_path: Path, mode: str) -> tuple[Path, str]:
    if not hasattr(os, "killpg") or shutil.which("bash") is None:
        pytest.skip("needs bash and POSIX process groups (CI runs this on linux)")
    stubs, work, scratch = tmp_path / "bin", tmp_path / "task", tmp_path / "scratch"
    backend = work / "source" / "backend"
    for d in (stubs, scratch, scratch / "postgresql" / "17", backend / "tests" / "unit",
              backend / "db" / "migrations", work / "source" / "config", work / "commit",
              *(work / o for o in ("ran", "results", "memory-infra", "notify"))):
        d.mkdir(parents=True, exist_ok=True)
    for name, body in _STUBS.items():
        (stubs / name).write_text(_STUB_HEAD + body + "\n", encoding="ascii")
        (stubs / name).chmod(0o755)
    (backend / "db" / "migrations" / "001.sql").write_text("select 1;\n", encoding="ascii")
    for name in ("lifecycle_pipelines.yaml", "hub-config.yaml"):
        (work / "source" / "config" / name).write_text("{}\n", encoding="ascii")
    (work / "commit" / "sha").write_text(HOST + "\n", encoding="ascii")
    step = _task("pytest")
    script = _script(step).replace("/tmp/", f"{scratch}/")
    script = script.replace("/etc/apt/apt.conf.d/", f"{scratch}/")
    script = script.replace("/usr/lib/postgresql", f"{scratch}/postgresql")
    started = scratch / "started"
    env = {
        **os.environ,
        **{k: str(v) for k, v in (step.get("params") or {}).items()},
        "PATH": f"{stubs}{os.pathsep}{os.environ.get('PATH', '')}",
        "STUB_MODE": mode,
        "STUB_STARTED": str(started),
    }
    proc = subprocess.Popen(
        ["bash", "-ec", script], cwd=work, env=env, start_new_session=True,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        if mode == "hang":
            deadline = time.monotonic() + 30
            while not started.exists() and proc.poll() is None and time.monotonic() < deadline:
                time.sleep(0.05)
            assert started.exists(), "the script never reached pytest"
            _signal_group(proc.pid, signal.SIGTERM)  # the wrapper timeout
            try:
                out = proc.communicate(timeout=10)[0]
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


def _linux_finished(work: Path) -> int:
    return subprocess.run(
        ["sh", "-c", _script(_doc()["anchors"]["linux_finished"])],
        cwd=work, env={**os.environ, "LINUX_STEP": "unit/pytest"},
        capture_output=True, text=True, timeout=60,
    ).returncode


def test_a_suite_cut_off_at_its_cap_leaves_no_ran_rc_so_this_host_runs_it(
    tmp_path: Path,
) -> None:
    work, out = _run_unit(tmp_path, "hang")
    rc_file = work / "ran" / "rc"
    rc = rc_file.read_text(encoding="ascii").strip() if rc_file.exists() else None
    assert rc is None, f"unit/pytest wrote ran/rc={rc!r} on SIGTERM:\n{out}"
    assert _linux_finished(work) == 1, "linux-finished must fall back to this host"


def test_the_same_suite_left_to_finish_writes_ran_rc_and_the_commit(tmp_path: Path) -> None:
    """The harness reaches the trap: without this the test above could pass
    on a script that died before it."""
    work, out = _run_unit(tmp_path, "done")
    assert (work / "ran" / "rc").read_text(encoding="ascii").strip() == "0", out
    assert (work / "ran" / "commit").read_text(encoding="ascii").strip() == HOST, out
    assert _linux_finished(work) == 0
