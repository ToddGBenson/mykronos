"""A lane killed for memory re-runs itself once before it reports (TheHub #61606).

thehub/unit #389 and mykronos/unit #496 died with exit 137 ("INFRASTRUCTURE, NOT
A VERDICT") and waited for a person, because Concourse never re-runs a job
without a new commit. Both memory wrappers now re-run the guarded command once,
after waiting for MemAvailable, when and only when it exited 137:

- mykronos.yml: `python ../scripts/memory_kill.py run -- <cmd>` (this file
  executes `run_with_retry` and the real command line);
- thehub.yml: the `memory_guard` anchor (this file executes it as it stands).

A real failure (exit 1, 2, 5) never retries. Not Concourse `attempts:`, which
would double every genuinely red lane.
"""

from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
PIPELINES = ROOT / "deploy" / "concourse" / "pipelines"
SCRIPT = ROOT / "scripts" / "memory_kill.py"
WRAP = "memory_kill.py run --"


def _load() -> Any:
    spec = importlib.util.spec_from_file_location("memory_kill_under_test", SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


mk = _load()


def _script_of(doc: dict[str, Any], job: str, task: str) -> str:
    plan = next(j for j in doc["jobs"] if j["name"] == job)["plan"]
    t = next(s for s in _walk(plan) if s.get("task") == task)
    return str(t["config"]["run"]["args"][-1])


def _walk(steps: Any) -> Any:
    """Every step dict in a plan, however deep (in_parallel, do, try, hooks)."""
    if isinstance(steps, list):
        for s in steps:
            yield from _walk(s)
    elif isinstance(steps, dict):
        yield steps
        for v in steps.values():
            if isinstance(v, (list, dict)):
                yield from _walk(v)


# -- run_with_retry, executed ------------------------------------------------


class _Fake:
    def __init__(self, *codes: int) -> None:
        self.codes = list(codes)
        self.runs = 0
        self.slept: list[float] = []
        self.now = 0.0

    def call(self, cmd: Any) -> int:
        self.runs += 1
        return self.codes.pop(0)

    def sleep(self, s: float) -> None:
        self.slept.append(s)
        self.now += s

    def clock(self) -> float:
        return self.now


def _retry(fake: _Fake, avail: Any = lambda: 9999) -> int:
    return int(
        mk.run_with_retry(
            ["python", "-m", "pytest"],
            budget_mb=1000,
            call=fake.call,
            available=avail,
            sleep=fake.sleep,
            clock=fake.clock,
        )
    )


def test_137_then_0_exits_0_and_says_it_re_ran_once(capsys: pytest.CaptureFixture[str]) -> None:
    fake = _Fake(137, 0)
    assert _retry(fake) == 0
    assert fake.runs == 2
    assert "re-ran once" in capsys.readouterr().out


def test_137_then_137_reports_as_today_plus_re_ran_once(
    capsys: pytest.CaptureFixture[str],
) -> None:
    fake = _Fake(137, 137)
    assert _retry(fake) == 137
    assert fake.runs == 2, "one re-run, never a third"
    err = capsys.readouterr().err
    assert "INFRASTRUCTURE, NOT A VERDICT: killed: out of memory" in err
    assert "re-ran once" in err


@pytest.mark.parametrize("rc", [1, 2, 5])
def test_a_real_failure_never_retries(rc: int) -> None:
    fake = _Fake(rc)
    assert _retry(fake) == rc
    assert fake.runs == 1


def test_a_pass_never_retries() -> None:
    fake = _Fake(0)
    assert _retry(fake) == 0
    assert fake.runs == 1


def test_137_then_a_real_failure_returns_that_failure() -> None:
    assert _retry(_Fake(137, 1)) == 1


def test_it_waits_for_memory_then_runs_again() -> None:
    fake = _Fake(137, 0)
    readings = iter([100, 200, 5000])
    assert _retry(fake, avail=lambda: next(readings)) == 0
    assert len(fake.slept) == 2, "polled until MemAvailable passed the budget"


def test_it_waits_at_most_five_minutes_then_runs_anyway() -> None:
    fake = _Fake(137, 0)
    assert _retry(fake, avail=lambda: 10) == 0
    assert fake.runs == 2
    assert 300 <= sum(fake.slept) <= 305


def test_a_signal_death_is_returned_as_137_like_a_shell_does() -> None:
    code = "import os, signal; os.kill(os.getpid(), signal.SIGKILL)"
    if sys.platform == "win32":
        pytest.skip("no SIGKILL on Windows")
    assert mk._call([sys.executable, "-c", code]) == 137


def test_the_cli_returns_the_command_exit_code(tmp_path: Path) -> None:
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "run", "--", sys.executable, "-c", "import sys; sys.exit(5)"],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        timeout=60,
    )
    assert r.returncode == 5


# -- the thehub memory_guard anchor, executed ---------------------------------


def _guard() -> str:
    doc = yaml.safe_load((PIPELINES / "thehub.yml").read_text(encoding="utf-8"))
    return str(doc["anchors"]["memory_guard"])


def _run_guard(
    tmp_path: Path,
    child: str,
    soft: str | None = "1000",
    budget: str = "0",
    wait: str = "0",
    expected: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Budget 0 means no budget kill: a real one would race the scripted exit on Linux."""
    env = {
        **os.environ,
        "MEMORY_BUDGET_MB": budget,
        "MEMORY_GUARD_DIR": str(tmp_path / "oom"),
        "MEMORY_GUARD_LABEL": "pytest tests/unit",
        "MEMORY_GUARD_INTERVAL_S": "0.05",
        "MEMORY_GUARD_RETRY_WAIT_S": wait,
    }
    env.pop("MEMORY_GUARD_SOFT_TIMEOUT_S", None)
    env.pop("MEMORY_GUARD_EXPECTED_S", None)
    if expected is not None:
        env["MEMORY_GUARD_EXPECTED_S"] = expected
    if soft is not None:
        env["MEMORY_GUARD_SOFT_TIMEOUT_S"] = soft
    return subprocess.run(
        [sys.executable, "-c", _guard(), sys.executable, "-c", child],
        env=env,
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )


def _counting(first: int, second: int) -> str:
    return (
        "import os, sys\n"
        "n = int(open('runs').read()) if os.path.exists('runs') else 0\n"
        "open('runs', 'w').write(str(n + 1))\n"
        f"sys.exit({first} if n == 0 else {second})\n"
    )


def test_thehub_guard_137_then_0_exits_0_and_says_it_re_ran_once(tmp_path: Path) -> None:
    r = _run_guard(tmp_path, _counting(137, 0))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "re-ran once" in r.stdout
    assert (tmp_path / "runs").read_text() == "2"
    assert not (tmp_path / "oom").exists(), "a recovered kill leaves no infra marker"


def test_thehub_guard_137_then_137_reports_as_today_plus_re_ran_once(tmp_path: Path) -> None:
    r = _run_guard(tmp_path, _counting(137, 137))
    assert r.returncode == 137
    assert (tmp_path / "runs").read_text() == "2"
    reason = (tmp_path / "oom" / "reason").read_text(encoding="utf-8")
    assert reason.startswith("INFRASTRUCTURE, NOT A VERDICT: killed: out of memory")
    assert "re-ran once" in reason


@pytest.mark.parametrize("rc", [1, 2, 5])
def test_thehub_guard_a_real_failure_never_retries(tmp_path: Path, rc: int) -> None:
    r = _run_guard(tmp_path, _counting(rc, 0))
    assert r.returncode == rc
    assert (tmp_path / "runs").read_text() == "1"
    assert not (tmp_path / "oom").exists()


def test_thehub_guard_without_a_soft_timeout_never_re_runs(tmp_path: Path) -> None:
    """pr-gates/integration and the container tiers set none: a kill reports as today."""
    r = _run_guard(tmp_path, _counting(137, 0), soft=None)
    assert r.returncode == 137
    assert (tmp_path / "runs").read_text() == "1"
    assert "re-run: no: this task has no soft timeout" in r.stdout
    assert "re-ran once" not in (tmp_path / "oom" / "reason").read_text(encoding="utf-8")


def test_thehub_guard_no_time_left_means_no_re_run(tmp_path: Path) -> None:
    """The first run used the soft timeout up; a wait and a second run cannot fit."""
    child = "import sys, time\nopen('runs', 'a').write('x')\ntime.sleep(1.2)\nsys.exit(137)\n"
    r = _run_guard(tmp_path, child, soft="2")
    assert r.returncode == 137
    assert (tmp_path / "runs").read_text() == "x", "one run only"
    assert "re-run: no:" in r.stdout and "soft timeout are left" in r.stdout
    assert "re-ran once" not in (tmp_path / "oom" / "reason").read_text(encoding="utf-8")


def test_thehub_guard_time_left_means_a_re_run(tmp_path: Path) -> None:
    r = _run_guard(tmp_path, _counting(137, 0), soft="1000")
    assert "re-run: yes (second run sized at 0s)." in r.stdout
    assert r.returncode == 0


def test_thehub_guard_an_early_kill_is_sized_by_the_expected_run(tmp_path: Path) -> None:
    """Killed at once, but the tier normally runs 2760s and only 1000s are left: no re-run."""
    r = _run_guard(tmp_path, _counting(137, 0), soft="1000", expected="2760")
    assert r.returncode == 137
    assert (tmp_path / "runs").read_text() == "1"
    assert "a second run of 2760s" in r.stdout and "re-run: no:" in r.stdout


def test_thehub_guard_an_expected_run_that_fits_is_re_run(tmp_path: Path) -> None:
    r = _run_guard(tmp_path, _counting(137, 0), soft="4200", expected="2760")
    assert r.returncode == 0
    assert "re-run: yes (second run sized at 2760s)." in r.stdout
    assert (tmp_path / "runs").read_text() == "2"


@pytest.mark.skipif(not Path("/proc/self/stat").exists(), reason="measured from /proc")
def test_thehub_guard_does_not_retry_its_own_budget_kill(tmp_path: Path) -> None:
    holder = (
        "import time\nopen('runs', 'a').write('x')\n"
        "b = bytearray(200 * 1024 * 1024); b[::4096] = b'x' * len(b[::4096]); time.sleep(120)\n"
    )
    r = _run_guard(tmp_path, holder, budget="50", soft="1000")
    assert r.returncode == 137, r.stdout + r.stderr
    assert (tmp_path / "runs").read_text() == "x", "it would be killed at the same point"
    reason = (tmp_path / "oom" / "reason").read_text(encoding="utf-8")
    assert "memory-guard stopped it" in reason and "re-ran once" not in reason


@pytest.mark.skipif(not Path("/proc/self/stat").exists(), reason="POSIX signals")
def test_thehub_guard_stops_waiting_on_sigterm(tmp_path: Path) -> None:
    import signal
    import time

    env = {
        **os.environ,
        "MEMORY_BUDGET_MB": "999999999",  # MemAvailable never passes it: the wait runs its length
        "MEMORY_GUARD_DIR": str(tmp_path / "oom"),
        "MEMORY_GUARD_INTERVAL_S": "0.05",
        "MEMORY_GUARD_RETRY_WAIT_S": "120",
        "MEMORY_GUARD_SOFT_TIMEOUT_S": "100000",
    }
    proc = subprocess.Popen(
        [sys.executable, "-c", _guard(), sys.executable, "-c", "import sys; sys.exit(137)"],
        env=env,
        cwd=tmp_path,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    time.sleep(2.0)  # the child is long dead; the guard is in its wait
    proc.send_signal(signal.SIGTERM)
    out, _ = proc.communicate(timeout=20)
    assert proc.returncode == 137
    assert "not re-running" in out


# -- the xdist worker death (exit 1, only crashed workers) -----------------------


def _crash_report(path: Path, *, real_failure: bool = False) -> None:
    msg = "worker 'gw3' crashed while running 'tests/test_x.py::test_a'"
    extra = '<testcase classname="t" name="b"><failure message="assert 1">x</failure></testcase>'
    path.write_text(
        '<testsuites><testsuite><testcase classname="t" name="a">'
        f'<failure message="{msg}">node down</failure></testcase>'
        f'{extra if real_failure else ""}</testsuite></testsuites>',
        encoding="utf-8",
    )


def _retry_cmd(fake: _Fake, cmd: list[str], **kw: Any) -> int:
    return int(
        mk.run_with_retry(
            cmd, call=fake.call, available=lambda: 9999, sleep=fake.sleep, clock=fake.clock, **kw
        )
    )


def test_exit_1_with_only_crashed_workers_re_runs_once(tmp_path: Path) -> None:
    junit = tmp_path / "unit.xml"
    _crash_report(junit)
    fake = _Fake(1, 0)
    assert _retry_cmd(fake, ["python", "-m", "pytest", f"--junitxml={junit}"]) == 0
    assert fake.runs == 2


def test_exit_1_with_a_real_failure_beside_a_crash_never_retries(tmp_path: Path) -> None:
    junit = tmp_path / "unit.xml"
    _crash_report(junit, real_failure=True)
    fake = _Fake(1)
    assert _retry_cmd(fake, ["pytest", f"--junitxml={junit}"]) == 1
    assert fake.runs == 1


def test_exit_1_without_a_report_never_retries(tmp_path: Path) -> None:
    fake = _Fake(1)
    assert _retry_cmd(fake, ["pytest", f"--junitxml={tmp_path / 'none.xml'}"]) == 1
    assert fake.runs == 1


def test_the_wrapper_does_not_re_run_when_the_time_does_not_fit(
    capsys: pytest.CaptureFixture[str],
) -> None:
    class Slow(_Fake):
        def call(self, cmd: Any) -> int:
            self.now += 2000  # the first run took 2000s
            return super().call(cmd)

    fake = Slow(137, 0)
    assert _retry_cmd(fake, ["pytest"], max_s=3600, wait_s=300) == 137
    assert fake.runs == 1
    assert "no re-run" in capsys.readouterr().out


# -- every heavy task goes through the wrapper --------------------------------

# The mykronos tasks that run the suite, mypy or ruff, and the number of
# heavy command lines each must route through the wrapper.
MYKRONOS_HEAVY = {
    ("unit", "pytest"): ["python -m pytest"],
    ("coverage", "pytest-cov"): ["python -m pytest"],
    ("time-travel", "pytest-time-travel"): ["python -m pytest -q -n 4"],
    ("lint-and-types", "ruff-and-mypy"): ["python -m ruff", "python -m mypy"],
}
HEAVY = re.compile(r"python -m (pytest|mypy|ruff)\b")


def _doc(name: str) -> dict[str, Any]:
    return yaml.safe_load((PIPELINES / f"{name}.yml").read_text(encoding="utf-8"))


def _find_task(doc: dict[str, Any], job: str) -> list[tuple[str, str]]:
    plan = next(j for j in doc["jobs"] if j["name"] == job)["plan"]
    return [
        (s["task"], str(s["config"]["run"]["args"][-1]))
        for s in _walk(plan)
        if "task" in s and isinstance(s.get("config"), dict) and "run" in s["config"]
    ]


@pytest.mark.parametrize("job,task", sorted(MYKRONOS_HEAVY))
def test_every_mykronos_heavy_command_runs_under_the_wrapper(job: str, task: str) -> None:
    doc = _doc("mykronos")
    scripts = dict(_find_task(doc, job))
    assert task in scripts, f"{job} has no {task} task"
    lines = [ln.strip() for ln in scripts[task].splitlines()]
    for needle in MYKRONOS_HEAVY[(job, task)]:
        hits = [ln for ln in lines if needle in ln and not ln.startswith("#")]
        assert hits, f"{job}/{task} no longer runs {needle}"
        for ln in hits:
            if "tests/test_time_travel_canary.py" in ln:
                continue  # the two-test canary, not the suite
            assert WRAP in ln, f"{job}/{task} runs {needle} outside the wrapper: {ln}"


def test_no_mykronos_suite_runs_pytest_unwrapped_in_a_memory_job() -> None:
    """A new heavy line in a memory job must not slip past the list above."""
    doc = _doc("mykronos")
    for job in ("unit", "coverage", "time-travel", "lint-and-types"):
        for task, script in _find_task(doc, job):
            for ln in script.splitlines():
                s = ln.strip()
                if s.startswith("#") or not HEAVY.search(s):
                    continue
                if "tests/test_time_travel_canary.py" in s or "import " in s:
                    continue
                assert WRAP in s, f"{job}/{task}: {s}"


def test_thehub_heavy_tasks_go_through_the_guard() -> None:
    """Every task given MEMORY_GUARD calls it, or hands it to the repo's tier runner.

    The tier runner (`CONTAINER_TIERS_OUT`, in TheHub's own scripts) takes the
    guard from the environment, so it gets the retry from the same anchor.
    """
    doc = _doc("thehub")
    guarded = 0
    for job in doc["jobs"]:
        for step in _walk(job["plan"]):
            params = step.get("params") or {}
            if "task" not in step or "MEMORY_GUARD" not in params:
                continue
            guarded += 1
            assert params["MEMORY_GUARD"] == _guard(), f"{job['name']}/{step['task']}"
            script = str(step["config"]["run"]["args"][-1])
            assert 'python -c "$MEMORY_GUARD"' in script or "CONTAINER_TIERS_OUT" in script, (
                f"{job['name']}/{step['task']} is given the guard and never runs it"
            )
    assert guarded >= 4


def test_personal_soc_has_no_memory_heavy_task() -> None:
    """personal-soc runs a PowerShell harness; if it ever grows a pytest, wrap it."""
    text = (PIPELINES / "personal-soc.yml").read_text(encoding="utf-8")
    code = [ln for ln in text.splitlines() if not ln.strip().startswith("#")]
    assert not [ln for ln in code if HEAVY.search(ln)], "wrap it in scripts/memory_kill.py run"
