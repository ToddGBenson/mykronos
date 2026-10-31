"""A full pytest suite killed for memory is an outage, not a red commit (TheHub #61106).

thehub/unit #360 (`Killed ... pytest tests/security`, no security.xml) and
thehub/post-merge #1623 (`PYTEST_RC=137 with no pytest summary`) were the
kernel picking a victim under host memory pressure, ten hours apart, with no
test failing. Both were reported as test failures, so the risk gate refused a
green commit until somebody re-ran it by hand.

`container_limits.memory` is refused by runc on these workers (D-174,
test_thehub_task_limits.py), so the budget is the `memory_guard` anchor, run
around each pytest tier. These tests EXECUTE that anchor and the end of
`unit`'s script as they stand in thehub.yml, and run the job's own Hub and
check reporters against the marker the guard leaves.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.test_hub_failure_reports_carry_reason import _hook
from tests.test_hub_failure_reports_carry_reason import _run as _run_hub_report
from tests.test_uploader_install_retry import _run_check

PIPELINE = Path(__file__).resolve().parents[2] / "deploy" / "concourse" / "pipelines" / "thehub.yml"
GUARD_CALL = 'python -c "$MEMORY_GUARD"'
OOM = "killed: out of memory"
HAS_PROC = Path("/proc/self/stat").exists()


def _doc() -> dict[str, Any]:
    return yaml.safe_load(PIPELINE.read_text(encoding="utf-8"))


def _guard() -> str:
    return str(_doc()["anchors"]["memory_guard"])


def _task(job: str, name: str) -> dict[str, Any]:
    plan = next(j for j in _doc()["jobs"] if j["name"] == job)["plan"]
    return next(s for s in plan if s.get("task") == name)


def _script(task: dict[str, Any]) -> str:
    return str(task["config"]["run"]["args"][-1])


def _run_guard(
    tmp_path: Path, child: str, budget_mb: int = 2560
) -> subprocess.CompletedProcess[str]:
    env = {
        **os.environ,
        "MEMORY_BUDGET_MB": str(budget_mb),
        "MEMORY_GUARD_DIR": str(tmp_path / "oom"),
        "MEMORY_GUARD_LABEL": "pytest tests/unit",
        "MEMORY_GUARD_INTERVAL_S": "0.1",
    }
    return subprocess.run(
        [sys.executable, "-c", _guard(), sys.executable, "-c", child],
        env=env, cwd=tmp_path, capture_output=True, text=True, timeout=60,
    )


# -- the guard, executed -----------------------------------------------------


@pytest.mark.parametrize("code", [0, 1, 3])
def test_an_ordinary_exit_passes_through_and_leaves_no_marker(tmp_path: Path, code: int) -> None:
    r = _run_guard(tmp_path, f"import sys; sys.exit({code})")

    assert r.returncode == code, r.stderr
    assert not (tmp_path / "oom").exists()
    assert "memory-guard: pytest tests/unit exited" in r.stdout, "every run prints its peak"


def test_a_sigkill_it_did_not_cause_is_named_as_out_of_memory(tmp_path: Path) -> None:
    """#1623's shape: exit 137 and no summary. The worker's cgroup got there first."""
    r = _run_guard(tmp_path, "import sys; sys.exit(137)")

    assert r.returncode == 137
    reason = (tmp_path / "oom" / "reason").read_text(encoding="utf-8")
    assert reason.startswith("INFRASTRUCTURE, NOT A VERDICT: " + OOM)
    assert "pytest tests/unit" in reason and "kernel OOM killer" in reason
    assert (tmp_path / "oom" / "exit_code").read_text(encoding="utf-8").strip() == "137"


@pytest.mark.skipif(not HAS_PROC, reason="the budget is measured from /proc (Linux)")
def test_a_suite_over_its_budget_is_killed_by_the_guard_and_says_so(tmp_path: Path) -> None:
    """The budget counts the whole session: here the memory is held by a grandchild."""
    holder = (
        "import time; b = bytearray(300 * 1024 * 1024); "
        "b[::4096] = b'x' * len(b[::4096]); time.sleep(120)"
    )
    child = f"import subprocess, sys; subprocess.run([sys.executable, '-c', {holder!r}])"

    r = _run_guard(tmp_path, child, budget_mb=100)

    assert r.returncode == 137, r.stdout + r.stderr
    reason = (tmp_path / "oom" / "reason").read_text(encoding="utf-8")
    assert reason.startswith("INFRASTRUCTURE, NOT A VERDICT: " + OOM)
    assert "over this task's 100 MiB budget" in reason
    assert "memory-guard stopped it" in reason


@pytest.mark.skipif(not HAS_PROC, reason="the budget is measured from /proc (Linux)")
def test_a_suite_inside_its_budget_is_left_alone(tmp_path: Path) -> None:
    r = _run_guard(tmp_path, "import time; b = bytearray(20 * 1024 * 1024); time.sleep(0.5)")

    assert r.returncode == 0, r.stderr
    assert not (tmp_path / "oom").exists()
    assert "unmeasured" not in r.stdout


# -- wiring --------------------------------------------------------------------

GUARDED = {("unit", "pytest"), ("post-merge", "grade")}


@pytest.mark.parametrize("job,name", sorted(GUARDED))
def test_every_full_suite_runs_under_the_guard_with_a_budget(job: str, name: str) -> None:
    task = _task(job, name)
    params = task["params"]
    assert params.get("MEMORY_GUARD") == _guard(), f"{job}/{name} is not given the guard"
    assert int(params["MEMORY_BUDGET_MB"]) > 0
    lines = _script(task).splitlines()
    runs = [i for i, line in enumerate(lines) if "python -m pytest tests/" in line]
    assert runs, f"{job}/{name} runs no pytest tier"
    for i in runs:
        window = "\n".join(lines[max(0, i - 2) : i + 1])
        assert GUARD_CALL in window, (
            f"{job}/{name} runs pytest outside the guard: {lines[i].strip()!r}"
        )


@pytest.mark.parametrize("job,name", sorted(GUARDED))
def test_the_guarded_task_publishes_infra_for_its_hooks(job: str, name: str) -> None:
    outs = {o["name"]: o for o in _task(job, name)["config"]["outputs"]}
    assert outs["infra"]["path"] == "memory-infra"
    assert "memory-infra/reason" in _script(_task(job, name))


def test_post_merge_catches_the_kill_before_the_classifier() -> None:
    """#1623: the classifier read RC=137 with no summary as a red develop."""
    script = _script(_task("post-merge", "grade"))
    assert script.index("/tmp/run1.oom/reason") < script.index('classify "$RC1"')
    assert script.index("/tmp/run2.oom/reason") < script.index('classify "$RC2"')


# -- unit's verdict, executed --------------------------------------------------

_START = "UNIT_OOM=false"


def _unit_tail() -> str:
    script = _script(_task("unit", "pytest"))
    return script[script.index(_START) :]


def _run_unit_tail(
    tmp_path: Path, rc: int, sec_rc: int, oom: tuple[str, ...]
) -> subprocess.CompletedProcess[str]:
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("bash is required to execute unit's script")
    guard = tmp_path / "memory-guard"
    for tier in oom:
        (guard / tier).mkdir(parents=True)
        (guard / tier / "reason").write_text(
            f"INFRASTRUCTURE, NOT A VERDICT: {OOM} - pytest tests/{tier} reached 2600 MiB.\n",
            encoding="utf-8",
        )
    prelude = (
        "set -euo pipefail\n"
        "git() { echo 0123456789ab; }\n"
        f'rc={rc}; sec_rc={sec_rc}; upload_rc=0; MEMGUARD="{guard.as_posix()}"; '
        f'TASK_ROOT="{tmp_path.as_posix()}"\n'
    )
    return subprocess.run(
        [bash, "-s"], input=prelude + _unit_tail(), cwd=tmp_path,
        capture_output=True, text=True, timeout=30,
    )


@pytest.mark.parametrize(
    "rc,sec_rc,oom",
    [(137, 0, ("unit",)), (0, 137, ("security",)), (137, 137, ("unit", "security"))],
)
def test_unit_killed_for_memory_publishes_the_reason_and_exits_137(
    tmp_path: Path, rc: int, sec_rc: int, oom: tuple[str, ...]
) -> None:
    r = _run_unit_tail(tmp_path, rc, sec_rc, oom)

    assert r.returncode == 137, r.stdout + r.stderr
    reason = (tmp_path / "memory-infra" / "reason").read_text(encoding="utf-8")
    assert reason.startswith("INFRASTRUCTURE, NOT A VERDICT: " + OOM)
    assert (tmp_path / "memory-infra" / "exit_code").read_text(encoding="utf-8").strip() == "137"
    message = (tmp_path / "notify" / "message.txt").read_text(encoding="utf-8")
    assert OOM in message and "not a test failure" in message and "INFRASTRUCTURE" not in message


@pytest.mark.parametrize(
    "rc,sec_rc,oom,expected",
    [
        (1, 137, ("security",), 1),  # a real unit failure beside a killed security tier
        (137, 1, ("unit",), 1),  # a real security failure beside a killed unit tier
        (137, 0, (), 137),  # 137 with no guard reason is not claimed as memory
        (0, 0, (), 0),
    ],
)
def test_a_real_verdict_is_never_downgraded_to_an_outage(
    tmp_path: Path, rc: int, sec_rc: int, oom: tuple[str, ...], expected: int
) -> None:
    r = _run_unit_tail(tmp_path, rc, sec_rc, oom)

    assert r.returncode == expected, r.stdout + r.stderr
    assert not (tmp_path / "memory-infra").exists()


# -- what TheHub and the check are told ----------------------------------------


def _oom_marker(tmp_path: Path) -> str:
    reason = f"INFRASTRUCTURE, NOT A VERDICT: {OOM} - pytest tests/security was SIGKILLed."
    (tmp_path / "infra").mkdir()
    (tmp_path / "infra" / "reason").write_text(reason + "\n", encoding="utf-8")
    (tmp_path / "infra" / "exit_code").write_text("137\n", encoding="utf-8")
    return reason


@pytest.mark.parametrize("job", ["unit", "post-merge"])
def test_the_hub_hears_errored_with_137_and_the_reason(tmp_path: Path, job: str) -> None:
    reason = _oom_marker(tmp_path)

    (body,) = _run_hub_report(tmp_path, _hook(job, "failed"))

    assert body["status"] == "errored", body
    assert body["exit_code"] == 137
    assert body["log_tail"].startswith(reason)
    if "meta" in body:  # the real jq; the fallback stub builds no meta
        assert body["meta"]["infrastructure"] is True


def test_an_install_outage_marker_still_reports_75(tmp_path: Path) -> None:
    """The exit_code file is optional: #61007's marker carries none."""
    (tmp_path / "infra").mkdir()
    (tmp_path / "infra" / "reason").write_text(
        "INFRASTRUCTURE, NOT A VERDICT: no scan ran.\n", encoding="utf-8"
    )

    (body,) = _run_hub_report(tmp_path, _hook("unit", "failed"))

    assert body["status"] == "errored"
    assert body["exit_code"] == 75


def test_the_check_is_cancelled_not_failed(tmp_path: Path) -> None:
    _oom_marker(tmp_path)

    r, bodies = _run_check(tmp_path, JOB="unit")

    assert r.returncode == 0, r.stdout + r.stderr
    assert [b["conclusion"] for b in bodies] == ["cancelled"]
    assert OOM in r.stdout
