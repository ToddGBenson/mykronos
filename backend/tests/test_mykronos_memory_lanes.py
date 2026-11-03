"""mykronos unit and lint-and-types killed for memory: an outage, not a red commit (#61117).

2026-10-31 18:45Z: unit #479 (pytest -n 6) and lint-and-types #462 (mypy)
started in the same second on one worker, which D-174 caps at 3 GiB, and both
were SIGKILLed. On 2026-11-02 unit #484, #485 and #486 each ran 8,907-8,909
tests green and went red on 1-3 "failures" that were `[gwN] node down: Not
properly terminated` - xdist workers killed from outside - and lint #466 died
on `Killed python -m mypy`. Every one went red as FAILED, which Start-Here and
the overnight loop treat as a real result and stop on; they re-trigger an
ERRORED build once.

So:

- the jobs that run the full suite or mypy share one serial group, so two of
  them never hold one 3 GiB worker at once;
- `unit` runs fewer xdist workers, because #485 and #486 were killed with
  lint not running at all;
- a run that was killed for memory and reached no other verdict skips its
  upload, says it is not a test failure, and the build ERRORS on the step
  after it, instead of failing.

The classifier is executed against JUnit reports shaped like #485's and #486's,
and the end of each task's script is executed as it stands in the pipeline.

TheHub #61210: coverage #8 ran 8,583 tests green and went red on one "worker
'gw5' crashed" at -n 6, because `coverage` had the serial group but not the
rest. It now runs the same bounded worker count, classifier and ERRORED step
as `unit`, and both suites declare `container_limits` (CPU shares only: a
memory limit makes runc refuse the task on these workers, D-174).
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
PIPELINE = ROOT / "deploy" / "concourse" / "pipelines" / "mykronos.yml"
SCRIPT = ROOT / "scripts" / "memory_kill.py"

MEMORY_GROUP = "pytest-memory"
# Every job that runs the full backend suite, plus mypy, which #462 and #466
# showed is big enough to tip a worker that is also running the suite.
MEMORY_JOBS = {"unit", "coverage", "time-travel", "lint-and-types"}
# The step that turns "no verdict" into ERRORED. Its name is what the build
# page shows as the errored step, so it says what to do.
ERRORED_STEP = "killed-for-memory-not-a-test-failure-re-run"
MAX_UNIT_WORKERS = 4
LINT = ("lint-and-types", "ruff-and-mypy")
# The full-suite tasks that classify a memory kill (TheHub #61210 added coverage).
SUITES = [("unit", "pytest"), ("coverage", "pytest-cov")]
# Docker's default weight, production's (test_thehub_task_limits.py).
PRODUCTION_CPU_SHARES = 1024

CRASH = "worker 'gw{n}' crashed while running 'tests/test_x.py::test_{n}'"


def _doc() -> dict[str, Any]:
    doc: dict[str, Any] = yaml.safe_load(PIPELINE.read_text(encoding="utf-8"))
    return doc


def _job(name: str) -> dict[str, Any]:
    return next(j for j in _doc()["jobs"] if j["name"] == name)


def _task(job: str, name: str) -> dict[str, Any]:
    return next(s for s in _job(job)["plan"] if s.get("task") == name)


def _script(task: dict[str, Any]) -> str:
    return str(task["config"]["run"]["args"][-1])


def _junit(path: Path, *, crashes: int = 0, real: int = 0, passed: int = 5) -> Path:
    cases = [f'<testcase classname="t" name="ok{i}"/>' for i in range(passed)]
    # The two shapes pytest's junitxml writes for an xdist crash report
    # (when="???"): append_error wraps it as `failed on setup with "<msg>"`,
    # which is what #485 recorded, and append_failure writes it bare. The body
    # is str(longrepr), the same message.
    for n in range(crashes):
        msg = CRASH.format(n=n)
        if n % 2 == 0:
            tag, attr = "error", f"failed on setup with &quot;{msg}&quot;"
        else:
            tag, attr = "failure", msg
        cases.append(
            f'<testcase classname="t" name="crash{n}"><{tag} message="{attr}">'
            f"{msg}</{tag}></testcase>"
        )
    for n in range(real):
        cases.append(
            f'<testcase classname="t" name="real{n}"><failure message="AssertionError: 1 != 2">'
            "assert 1 == 2</failure></testcase>"
        )
    path.write_text(
        '<?xml version="1.0" encoding="utf-8"?><testsuites><testsuite name="pytest">'
        + "".join(cases)
        + "</testsuite></testsuites>",
        encoding="utf-8",
    )
    return path


def _classify(*args: str) -> str:
    if not SCRIPT.exists():
        pytest.fail(f"{SCRIPT.relative_to(ROOT)} does not exist: nothing classifies a memory kill")
    out = subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert out.returncode == 0, out.stderr
    return out.stdout.strip()


class TestTheyNeverShareAWorker:
    def test_every_memory_job_is_in_the_memory_group(self) -> None:
        missing = {
            name
            for name in MEMORY_JOBS
            if MEMORY_GROUP not in (_job(name).get("serial_groups") or [])
        }
        assert not missing, (
            f"{sorted(missing)} can run beside another full suite or mypy on one 3 GiB "
            f"worker: put them in serial group {MEMORY_GROUP!r} (unit #479 + lint #462)"
        )

    def test_the_reason_is_stated_beside_the_group(self) -> None:
        text = PIPELINE.read_text(encoding="utf-8")
        assert "#61117" in text and MEMORY_GROUP in text

    @pytest.mark.parametrize(("job", "task"), SUITES)
    def test_the_suite_runs_few_enough_workers_to_fit(self, job: str, task: str) -> None:
        script = _script(_task(job, task))
        line = next(x for x in script.splitlines() if "python -m pytest" in x)
        n = int(line.split(" -n ", 1)[1].split()[0])
        assert n <= MAX_UNIT_WORKERS, (
            f"{job} runs pytest -n {n}; #485 and #486 lost xdist workers to memory with "
            "lint not running, and coverage #8 lost gw5 at -n 6 (TheHub #61210), so the "
            "group alone does not fit it in 3 GiB"
        )

    @pytest.mark.parametrize(("job", "task"), SUITES)
    def test_the_suite_declares_cpu_limits_below_production(self, job: str, task: str) -> None:
        step = _task(job, task)
        limits = step.get("container_limits") or (step.get("config") or {}).get(
            "container_limits"
        )
        assert limits, f"{job}/{task} declares no container_limits (TheHub #61210)"
        cpu = limits.get("cpu")
        assert isinstance(cpu, int) and 0 < cpu < PRODUCTION_CPU_SHARES, (
            f"{job}/{task} container_limits.cpu must be CPU shares between 1 and "
            f"{PRODUCTION_CPU_SHARES - 1}: {limits}"
        )
        assert "memory" not in limits, (
            "container_limits.memory makes runc refuse the task container on these "
            "guardian workers (D-174, test_thehub_task_limits.py): the task would fail "
            "every run"
        )


class TestTheClassifier:
    def test_only_crashed_workers_is_a_memory_kill(self, tmp_path: Path) -> None:
        junit = _junit(tmp_path / "unit.xml", crashes=2)
        reason = _classify("pytest", "--rc", "1", "--junit", str(junit))
        assert "INFRASTRUCTURE, NOT A VERDICT" in reason
        assert "not a test failure" in reason and "re-run" in reason

    def test_a_real_failure_beside_a_crash_is_a_verdict(self, tmp_path: Path) -> None:
        # #486: two crashed workers and one real failure. The failure stands.
        junit = _junit(tmp_path / "unit.xml", crashes=2, real=1)
        assert _classify("pytest", "--rc", "1", "--junit", str(junit)) == ""

    def test_a_failure_that_quotes_the_reason_is_a_verdict(self, tmp_path: Path) -> None:
        # Review B1 on #1084: a real failure of a test in this file carries the
        # classifier's own output - the reason string, and a crash line - in
        # its body. Only the structured xdist message attribute is a crash.
        quoted = (
            "INFRASTRUCTURE, NOT A VERDICT: killed: out of memory - 2 xdist worker(s) were "
            "killed from outside (node down: Not properly terminated) and no test failed "
            "on its own. worker 'gw1' crashed while running 'tests/test_x.py::test_1'"
        )
        junit = tmp_path / "unit.xml"
        junit.write_text(
            '<?xml version="1.0" encoding="utf-8"?><testsuites><testsuite name="pytest">'
            '<testcase classname="t" name="quotes">'
            '<failure message="AssertionError: assert 99 == 0">'
            f"{quoted}</failure></testcase>"
            '<testcase classname="t" name="mentions">'
            "<failure message=\"AssertionError: worker 'gw1' crashed while running 'x'\">"
            "assert False</failure></testcase>"
            "</testsuite></testsuites>",
            encoding="utf-8",
        )
        assert _classify("pytest", "--rc", "1", "--junit", str(junit)) == ""

    def test_a_real_xdist_crash_report_is_a_memory_kill(self, tmp_path: Path) -> None:
        # The report pytest-xdist itself writes when a worker dies, so the
        # classifier is held to the real shape and not only to this file's.
        pytest.importorskip("xdist")
        (tmp_path / "test_dies.py").write_text(
            "import os\n\ndef test_ok():\n    pass\n\n"
            "def test_dies():\n    os._exit(9)\n",
            encoding="utf-8",
        )
        junit = tmp_path / "unit.xml"
        run = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-n", "2",
             "--max-worker-restart=0", f"--junitxml={junit}", "test_dies.py"],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert run.returncode == 1, run.stdout + run.stderr
        assert "crashed while running" in junit.read_text(encoding="utf-8")
        reason = _classify("pytest", "--rc", str(run.returncode), "--junit", str(junit))
        assert "INFRASTRUCTURE, NOT A VERDICT" in reason

    def test_a_plain_failure_is_a_verdict(self, tmp_path: Path) -> None:
        junit = _junit(tmp_path / "unit.xml", real=1)
        assert _classify("pytest", "--rc", "1", "--junit", str(junit)) == ""

    def test_a_pass_is_a_verdict(self, tmp_path: Path) -> None:
        junit = _junit(tmp_path / "unit.xml")
        assert _classify("pytest", "--rc", "0", "--junit", str(junit)) == ""

    def test_pytest_itself_sigkilled_is_a_memory_kill(self, tmp_path: Path) -> None:
        # `Killed  python -m pytest -q -n 6` (#479): no report was written.
        reason = _classify("pytest", "--rc", "137", "--junit", str(tmp_path / "absent.xml"))
        assert "INFRASTRUCTURE, NOT A VERDICT" in reason

    def test_a_missing_report_on_a_plain_failure_is_a_verdict(self, tmp_path: Path) -> None:
        assert _classify("pytest", "--rc", "2", "--junit", str(tmp_path / "absent.xml")) == ""

    def test_mypy_sigkilled_is_a_memory_kill(self) -> None:
        # `Killed  python -m mypy mykronos` (#462, #466).
        reason = _classify("lint", "--rc-ruff", "0", "--rc-mypy", "137")
        assert "INFRASTRUCTURE, NOT A VERDICT" in reason and "mypy" in reason

    def test_both_killed_reads_as_plural(self) -> None:
        reason = _classify("lint", "--rc-ruff", "137", "--rc-mypy", "137")
        assert "ruff and mypy were SIGKILLed" in reason

    def test_a_ruff_failure_beside_a_killed_mypy_is_a_verdict(self) -> None:
        assert _classify("lint", "--rc-ruff", "1", "--rc-mypy", "137") == ""

    def test_a_mypy_error_is_a_verdict(self) -> None:
        assert _classify("lint", "--rc-ruff", "0", "--rc-mypy", "1") == ""


def _tail(job: str, task: str) -> str:
    """The script from the classifier call to the line that records a verdict."""
    lines = _script(_task(job, task)).splitlines()
    start = next((i for i, x in enumerate(lines) if "memory_kill.py" in x), None)
    assert start is not None, f"{job}/{task} never asks scripts/memory_kill.py for a verdict"
    end = next((i for i in range(start, len(lines)) if "judged/verdict" in lines[i]), None)
    assert end is not None, f"{job}/{task} never records judged/verdict after the classifier"
    return "\n".join(lines[start : end + 1])


def _run_tail(
    tmp_path: Path, job: str, task: str, prelude: str, classifier: str | None = None
) -> tuple[int, str, bool]:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("no bash on this host")
    # The task's layout: cwd source/backend, the repo's scripts beside it,
    # outputs two levels up.
    backend = tmp_path / "source" / "backend"
    backend.mkdir(parents=True)
    (tmp_path / "source" / "scripts").mkdir()
    if classifier is None:
        shutil.copy(SCRIPT, tmp_path / "source" / "scripts" / "memory_kill.py")
    else:
        (tmp_path / "source" / "scripts" / "memory_kill.py").write_text(classifier)
    (tmp_path / "results").mkdir()
    (tmp_path / "judged").mkdir()
    body = f"set -e\n{prelude}\n{_tail(job, task)}\necho REACHED-THE-UPLOAD\n"
    out = subprocess.run(
        [bash, "-c", body],
        cwd=backend,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    return out.returncode, out.stdout + out.stderr, (tmp_path / "judged" / "verdict").exists()


class TestTheJobErrorsInsteadOfFailing:
    @pytest.mark.parametrize(("job", "task"), [*SUITES, LINT])
    def test_the_task_records_a_verdict_and_the_next_step_reads_it(
        self, job: str, task: str
    ) -> None:
        plan = _job(job)["plan"]
        i = next(n for n, s in enumerate(plan) if s.get("task") == task)
        outputs = {o["name"] for o in plan[i]["config"].get("outputs") or []}
        assert "judged" in outputs, f"{job}/{task} has no `judged` output for the verdict"
        after = plan[i + 1] if i + 1 < len(plan) else {}
        assert after.get("load_var") == ERRORED_STEP and after.get("file") == "judged/verdict", (
            f"{job}: the step after {task} must be `load_var: {ERRORED_STEP}` reading "
            "judged/verdict, so a run with no verdict ERRORS instead of failing"
        )

    @pytest.mark.parametrize(("job", "task"), SUITES)
    def test_the_suite_killed_for_memory_records_no_verdict_and_skips_the_upload(
        self, tmp_path: Path, job: str, task: str
    ) -> None:
        if not SCRIPT.exists():
            pytest.fail("scripts/memory_kill.py does not exist")
        junit = _junit(tmp_path / "pre.xml", crashes=3)
        prelude = f"rc=1\nmkdir -p ../../results && cp '{junit.as_posix()}' ../../results/unit.xml"
        rc, out, judged = _run_tail(tmp_path / "t", job, task, prelude)
        assert rc == 0, out
        assert not judged, "killed for memory, yet a verdict was recorded: no error"
        assert "REACHED-THE-UPLOAD" not in out, "a run that measured nothing was uploaded"
        assert "not a test failure" in out

    def test_coverage_8_one_crashed_worker_is_not_a_verdict(self, tmp_path: Path) -> None:
        # TheHub #61210, coverage #8: 8,583 passed and one "worker 'gw5'
        # crashed", nothing failing on its own.
        junit = _junit(tmp_path / "pre.xml", crashes=1, passed=50)
        prelude = f"rc=1\nmkdir -p ../../results && cp '{junit.as_posix()}' ../../results/unit.xml"
        rc, out, judged = _run_tail(tmp_path / "t", "coverage", "pytest-cov", prelude)
        assert rc == 0 and not judged and "REACHED-THE-UPLOAD" not in out, out
        assert "INFRASTRUCTURE, NOT A VERDICT" in out, out

    @pytest.mark.parametrize(("job", "task"), SUITES)
    def test_the_suite_with_a_real_failure_records_it(
        self, tmp_path: Path, job: str, task: str
    ) -> None:
        if not SCRIPT.exists():
            pytest.fail("scripts/memory_kill.py does not exist")
        junit = _junit(tmp_path / "pre.xml", crashes=2, real=1)
        prelude = f"rc=1\nmkdir -p ../../results && cp '{junit.as_posix()}' ../../results/unit.xml"
        rc, out, judged = _run_tail(tmp_path / "t", job, task, prelude)
        assert rc == 0 and judged and "REACHED-THE-UPLOAD" in out, out

    def test_lint_with_mypy_killed_records_no_verdict(self, tmp_path: Path) -> None:
        if not SCRIPT.exists():
            pytest.fail("scripts/memory_kill.py does not exist")
        rc, out, judged = _run_tail(tmp_path, *LINT, "rc_ruff=0\nrc_mypy=137")
        assert rc == 0, out
        assert not judged and "REACHED-THE-UPLOAD" not in out, out

    def test_lint_with_a_mypy_error_records_it(self, tmp_path: Path) -> None:
        if not SCRIPT.exists():
            pytest.fail("scripts/memory_kill.py does not exist")
        rc, out, judged = _run_tail(tmp_path, *LINT, "rc_ruff=0\nrc_mypy=1")
        assert rc == 0 and judged and "REACHED-THE-UPLOAD" in out, out

    # Review F2 on #1084: the classifier is an extra step after the verdict.
    # If it cannot run, the run goes on as if it had said nothing, with a
    # warning, rather than turning a green suite red under `bash -e`.
    BROKEN = "raise RuntimeError('classifier broke')\n"

    @pytest.mark.parametrize(("job", "task"), SUITES)
    def test_the_suite_goes_on_when_the_classifier_breaks(
        self, tmp_path: Path, job: str, task: str
    ) -> None:
        prelude = "rc=0\nmkdir -p ../../results"
        rc, out, judged = _run_tail(tmp_path, job, task, prelude, self.BROKEN)
        assert rc == 0 and judged and "REACHED-THE-UPLOAD" in out, out
        assert "::warning::" in out, out

    def test_lint_goes_on_when_the_classifier_breaks(self, tmp_path: Path) -> None:
        rc, out, judged = _run_tail(tmp_path, *LINT, "rc_ruff=0\nrc_mypy=0", self.BROKEN)
        assert rc == 0 and judged and "REACHED-THE-UPLOAD" in out, out
        assert "::warning::" in out, out
