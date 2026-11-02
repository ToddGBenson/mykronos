"""The nightly time-travel unit run (TheHub #61109).

#1034's 30-day NVD retry window was a time bomb: a test retired a row at a
fixed date and read the backlog on the real clock, so `unit` went red on main
the night the window passed and held fourteen lanes behind it. Review cannot
see a test that only breaks N days later; a run with the clock moved forward
can.

Two halves, tested separately:

- the job in `pipelines/mykronos.yml`: nightly, under libfaketime at the
  pipeline var `time-travel-offset`, gating nothing and uploading nothing;
- `scripts/time_travel_report.py`: a red run is one open Hub story, kept
  current in place, never one per night.
"""

from __future__ import annotations

import importlib.util
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
PIPELINE = ROOT / "deploy" / "concourse" / "pipelines" / "mykronos.yml"
VARS = ROOT / "deploy" / "concourse" / "vars" / "mykronos.yml"
SET_PIPELINE = ROOT / "deploy" / "concourse" / "set-pipeline.ps1"
SCRIPT = ROOT / "scripts" / "time_travel_report.py"

JOB = "time-travel"


@pytest.fixture(scope="module")
def tt():
    spec = importlib.util.spec_from_file_location("time_travel_report", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["time_travel_report"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def pipeline() -> dict[str, Any]:
    return yaml.safe_load(PIPELINE.read_text(encoding="utf-8"))


def _job(pipeline: dict[str, Any]) -> dict[str, Any]:
    jobs = {j["name"]: j for j in pipeline["jobs"]}
    assert JOB in jobs, "pipelines/mykronos.yml has no time-travel job"
    return jobs[JOB]


SUITE_TASK = "pytest-time-travel"
FILING_TASK = "file-hub-story"
CANARY = "tests/test_time_travel_canary.py"


def _task(job: dict[str, Any], name: str) -> dict[str, Any]:
    tasks = [s for s in job["plan"] if s.get("task") == name]
    assert len(tasks) == 1, f"time-travel should have one task named {name}"
    return tasks[0]


def _script(job: dict[str, Any], name: str = SUITE_TASK) -> str:
    return _task(job, name)["config"]["run"]["args"][-1]


def _all_scripts(job: dict[str, Any]) -> str:
    return "\n".join(
        s["config"]["run"]["args"][-1] for s in job["plan"] if "task" in s and "config" in s
    )


def _lines(script: str) -> list[str]:
    return [line.strip() for line in script.splitlines() if line.strip()]


# ---------------------------------------------------------------------------
# The job
# ---------------------------------------------------------------------------


class TestTheJob:
    def test_it_runs_nightly_on_the_clock_and_not_on_a_push(self, pipeline) -> None:
        job = _job(pipeline)
        triggers = [s["get"] for s in job["plan"] if s.get("trigger")]
        assert triggers == ["nightly"]
        source = next(s for s in job["plan"] if s.get("get") == "source")
        # The newest commit whose real-clock suite passed: a red night is then
        # about time and nothing else.
        assert source.get("passed") == ["unit"]

    def test_the_suite_runs_under_libfaketime_at_the_offset_var(self, pipeline) -> None:
        job = _job(pipeline)
        task = _task(job, SUITE_TASK)
        assert task["params"]["TIME_TRAVEL_OFFSET"] == "((time-travel-offset))"
        script = _script(job)
        assert "apt-get install -y -qq git faketime" in script
        # One definition of the faketime invocation, which the canary and the
        # suite both go through, so they cannot drift apart. `-m`: the
        # multi-threaded library, for xdist's execnet threads, asyncio, DuckDB.
        lines = _lines(script)
        faketime = [line for line in lines if "faketime -" in line]
        assert faketime == ['under_faketime() { faketime -m -f "$TIME_TRAVEL_OFFSET" "$@"; }']
        for line in lines:
            if "-m pytest" in line:
                assert "under_faketime python -m pytest" in line, line

    def test_a_canary_proves_the_clock_moved_before_the_suite_runs(self, pipeline) -> None:
        # Finding 1 of the #1056 review: without this, an unshifted clock is a
        # green night, and a green night is a false all-clear.
        lines = _lines(_script(_job(pipeline)))
        real_now = next(i for i, x in enumerate(lines) if "TIME_TRAVEL_REAL_NOW=" in x)
        assert lines[real_now] == 'export TIME_TRAVEL_REAL_NOW="$(date +%s)"'
        suite = next(i for i, x in enumerate(lines) if "--junitxml" in x)
        main = next(i for i, x in enumerate(lines) if CANARY in x and "-n 0" in x)
        worker = next(i for i, x in enumerate(lines) if CANARY in x and "-n 2" in x)
        assert real_now < main < suite and real_now < worker < suite
        assert "TIME_TRAVEL_CANARY_IN_WORKER=0" in lines[main]
        assert "TIME_TRAVEL_CANARY_IN_WORKER=1" in lines[worker]
        failed = "\n".join(lines[worker:suite])
        assert "::error::time-travel CANARY" in failed and "exit 1" in failed

    def test_a_source_older_than_the_canary_is_named_as_such(self, pipeline) -> None:
        # TheHub #61230: builds 1 and 2 got `source` at 603e0f0, the newest
        # commit to pass `unit` then, which predates #1056 and so has no
        # canary file. pytest said "file or directory not found" and the job
        # blamed the clock. The tree is checked first, and its own error names
        # the commit and never the clock.
        lines = _lines(_script(_job(pipeline)))
        guard = next(i for i, x in enumerate(lines) if x == f"if [ ! -f {CANARY} ]; then")
        first_canary = next(i for i, x in enumerate(lines) if CANARY in x and "pytest" in x)
        assert guard < first_canary
        block = "\n".join(lines[guard : lines.index("fi", guard) + 1])
        assert "::error::time-travel SOURCE" in block and "exit 1" in block
        assert "$commit" in block and "clock" not in block.lower()

    def test_the_source_guard_runs_and_names_the_commit(self, pipeline, tmp_path) -> None:
        # The guard itself, run the way the job runs it: from backend/ in a
        # checkout, once without the canary file and once with it.
        bash = shutil.which("bash")
        if bash is None:
            pytest.skip("no bash on this machine")
        lines = _lines(_script(_job(pipeline)))
        start = next(i for i, x in enumerate(lines) if x.startswith("commit="))
        guard = next(i for i, x in enumerate(lines) if x == f"if [ ! -f {CANARY} ]; then")
        snippet = "\n".join(lines[start : lines.index("fi", guard) + 1]) + "\necho GUARD-PASSED\n"
        repo = tmp_path / "source"
        (repo / "backend" / "tests").mkdir(parents=True)
        git = ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
        subprocess.run([*git, "init", "-q"], check=True)
        subprocess.run([*git, "commit", "-q", "--allow-empty", "-m", "old"], check=True)
        sha = subprocess.run(
            [*git, "rev-parse", "--short=12", "HEAD"], check=True, capture_output=True, text=True
        ).stdout.strip()

        def run() -> subprocess.CompletedProcess:
            return subprocess.run(
                [bash, "-ec", snippet],
                cwd=repo / "backend",
                capture_output=True,
                text=True,
                timeout=60,
            )

        old = run()
        assert old.returncode == 1, old.stdout + old.stderr
        assert sha in old.stdout and "GUARD-PASSED" not in old.stdout
        assert "clock did not move" not in old.stdout

        (repo / "backend" / CANARY).write_text("", encoding="utf-8")
        new = run()
        assert new.returncode == 0, new.stdout + new.stderr
        assert "GUARD-PASSED" in new.stdout

    def test_the_canary_checks_python_and_duckdb(self) -> None:
        text = (ROOT / "backend" / CANARY).read_text(encoding="utf-8")
        assert "def test_python_reads_the_moved_clock" in text
        assert "def test_duckdb_reads_the_moved_clock" in text
        assert "def test_it_ran_where_the_job_said" in text

    def test_the_hub_token_never_reaches_pytest_or_pip(self, pipeline) -> None:
        # Finding 2: the token is TheHub's, and a public job's suite and its
        # dependencies are exactly what should not hold it. Only the filing
        # task has it, and that task runs the reporter and nothing else.
        job = _job(pipeline)
        for step in job["plan"]:
            if "task" not in step:
                continue
            params = step.get("params") or {}
            script = step["config"]["run"]["args"][-1]
            if "HUB_STORY_TOKEN" in params or "HUB_URL" in params:
                assert step["task"] == FILING_TASK, step["task"]
                assert "pytest" not in script and "pip " not in script
        filing = _task(job, FILING_TASK)
        assert filing["params"]["HUB_STORY_TOKEN"] == "((hub-story-token))"
        assert "HUB_STORY_TOKEN" not in (_task(job, SUITE_TASK).get("params") or {})

    def test_the_install_and_the_filing_run_on_the_real_clock(self, pipeline) -> None:
        # pip under a moved clock can refuse a certificate that is valid today,
        # and the story must say when it was really filed.
        script = _all_scripts(_job(pipeline))
        for line in script.splitlines():
            if "pip install" in line or "time_travel_report.py" in line:
                assert "faketime" not in line, line

    def test_the_offset_is_longer_than_the_nvd_retry_window(self) -> None:
        # The window that made #1034's bomb. This guards that one window only,
        # and the pipeline's comment says so: a longer window elsewhere
        # (credential rotation is 90 days) is a bomb this offset cannot reach.
        offset = yaml.safe_load(VARS.read_text(encoding="utf-8"))["time-travel-offset"]
        match = re.fullmatch(r"\+(\d+)d", str(offset))
        assert match, f"time-travel-offset should read +<days>d, not {offset!r}"
        from mykronos import threat_intel

        assert int(match.group(1)) > threat_intel.NVD_RETRY_DAYS

    def test_the_offset_is_in_both_vars_sources(self) -> None:
        # vars/mykronos.yml feeds the self-applying set-pipeline job and
        # set-pipeline.ps1 the hand apply; a var in one only is a pipeline that
        # applies differently depending on who applied it.
        offset = yaml.safe_load(VARS.read_text(encoding="utf-8"))["time-travel-offset"]
        assert f'"time-travel-offset: {offset}"' in SET_PIPELINE.read_text(encoding="utf-8")

    def test_it_gates_nothing(self, pipeline) -> None:
        for job in pipeline["jobs"]:
            for step in job.get("plan", []):
                assert JOB not in (step.get("passed") or []), (
                    f"{job['name']} waits on time-travel: a red night would hold a real lane"
                )

    def test_it_reports_nothing_to_mykronos(self, pipeline) -> None:
        # An upload as `unit` would put tomorrow's failures on today's lane.
        assert "mykronos.upload" not in _all_scripts(_job(pipeline))

    def test_it_exits_with_the_suites_code_not_the_filings(self, pipeline) -> None:
        job = _job(pipeline)
        suite = _script(job)
        assert "|| rc=$?" in suite
        assert 'echo "$rc" > ../../results/rc' in suite
        filing = _script(job, FILING_TASK)
        assert 'rc="$(cat results/rc)"' in filing
        assert filing.rstrip().endswith('exit "$rc"')

    def test_it_is_in_a_group(self, pipeline) -> None:
        assert any(JOB in g["jobs"] for g in pipeline["groups"])


# ---------------------------------------------------------------------------
# The canary, run the way the job runs it
# ---------------------------------------------------------------------------

DAY = 86400


def _canary(
    real_now: float | None, *, workers: int, in_worker: str
) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if not k.startswith("PYTEST_")}
    env.update(
        TIME_TRAVEL_REAL_NOW="" if real_now is None else str(int(real_now)),
        TIME_TRAVEL_OFFSET="+45d",
        TIME_TRAVEL_CANARY_IN_WORKER=in_worker,
    )
    argv = ["-q", "-p", "no:cacheprovider", "-n", str(workers), CANARY]
    return subprocess.run(
        [sys.executable, "-m", "pytest", *argv],
        cwd=ROOT / "backend",
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )


class TestTheCanary:
    # No libfaketime here, so the "moved" clock is simulated the other way
    # round: a real epoch given as 46 days ago is what a +45d clock looks like.

    @pytest.mark.parametrize(("workers", "in_worker"), [(0, "0"), (2, "1")])
    def test_it_fails_on_an_unshifted_clock(self, workers: int, in_worker: str) -> None:
        result = _canary(time.time(), workers=workers, in_worker=in_worker)
        assert result.returncode == 1, result.stdout
        out = result.stdout
        assert "time.time() reads" in out and "DuckDB now() reads" in out
        assert "the clock did not move" in out

    @pytest.mark.parametrize(("workers", "in_worker"), [(0, "0"), (2, "1")])
    def test_it_passes_on_a_moved_clock(self, workers: int, in_worker: str) -> None:
        result = _canary(time.time() - 46 * DAY, workers=workers, in_worker=in_worker)
        assert result.returncode == 0, result.stdout
        assert "3 passed" in result.stdout

    def test_it_fails_when_it_did_not_run_where_the_job_said(self) -> None:
        result = _canary(time.time() - 46 * DAY, workers=0, in_worker="1")
        assert result.returncode == 1, result.stdout
        assert "asked for an xdist worker" in result.stdout

    @pytest.mark.parametrize(("workers", "in_worker"), [(0, "0"), (2, "1")])
    def test_it_fails_rather_than_skips_when_the_job_lost_the_real_epoch(
        self, workers: int, in_worker: str
    ) -> None:
        # Re-review of #1056: a skipped canary is pytest exit 0, so an edit
        # that dropped or moved the export would make the canary pass on
        # nothing. Asked to run (IN_WORKER set) without an epoch, it fails.
        result = _canary(None, workers=workers, in_worker=in_worker)
        assert result.returncode == 1, result.stdout
        assert "skipped" not in result.stdout
        assert "TIME_TRAVEL_REAL_NOW is empty" in result.stdout


# ---------------------------------------------------------------------------
# The report
# ---------------------------------------------------------------------------


def _junit(tmp_path: Path, *, passed: int, failed: list[str], errored: list[str] = ()) -> Path:
    cases = [f'<testcase classname="tests.test_a" name="test_ok_{i}"/>' for i in range(passed)]
    for name in failed:
        cls, _, test = name.partition("::")
        cases.append(f'<testcase classname="{cls}" name="{test}"><failure message="x"/></testcase>')
    for name in errored:
        cls, _, test = name.partition("::")
        cases.append(f'<testcase classname="{cls}" name="{test}"><error message="x"/></testcase>')
    path = tmp_path / "unit.xml"
    path.write_text(
        f'<testsuites><testsuite name="pytest">{"".join(cases)}</testsuite></testsuites>',
        encoding="utf-8",
    )
    return path


class FakeHub:
    def __init__(self, stories: list[dict[str, Any]] | None = None) -> None:
        self.stories = stories or []
        self.writes: list[tuple[str, str, dict[str, Any] | None]] = []

    def __call__(self, method: str, path: str, body: dict[str, Any] | None):
        if method == "GET":
            bucket = re.search(r"bucket=(\w+)", path).group(1)
            return 200, [s for s in self.stories if s.get("bucket") == bucket]
        self.writes.append((method, path, body))
        if method == "POST":
            story = {**body, "id": 900 + len(self.stories), "closed_at": None}
            self.stories.append(story)
            return 200, story
        story_id = int(path.rsplit("/", 1)[1])
        story = next(s for s in self.stories if s["id"] == story_id)
        story.update(body)
        return 200, story


BOMB = (
    "tests.test_threat_intel.TestTheBacklogIsReported"
    "::test_it_counts_both_queues_and_the_rows_given_up"
)
OTHER = "tests.test_credentials::test_it_expires_in_thirty_days"


class TestTheReport:
    def test_it_names_each_failing_and_erroring_test(self, tt, tmp_path) -> None:
        run = tt.read_report(_junit(tmp_path, passed=3, failed=[BOMB], errored=[OTHER]))
        assert run.tests == 5
        assert run.failing == tuple(sorted([BOMB, OTHER]))

    def test_a_missing_report_is_an_error_not_a_green_run(self, tt, tmp_path) -> None:
        argv = ["--junit", str(tmp_path / "absent.xml"), "--offset", "+45d", "--commit", "abc"]
        assert tt.main(argv) == 2

    def test_an_empty_report_is_an_error_not_a_green_run(self, tt, tmp_path) -> None:
        path = tmp_path / "unit.xml"
        path.write_text("<testsuites><testsuite/></testsuites>", encoding="utf-8")
        with pytest.raises(tt.ReportError):
            tt.read_report(path)

    def test_a_green_run_writes_nothing(self, tt, tmp_path) -> None:
        hub = FakeHub()
        run = tt.read_report(_junit(tmp_path, passed=4, failed=[]))
        tt.report(run, hub, offset="+45d", commit="abc")
        assert hub.writes == []

    def test_a_red_run_files_one_backlog_story_naming_each_test(self, tt, tmp_path) -> None:
        hub = FakeHub()
        run = tt.read_report(_junit(tmp_path, passed=2, failed=[BOMB, OTHER]))
        tt.report(run, hub, offset="+45d", commit="abc1234")
        assert [(m, p) for m, p, _ in hub.writes] == [("POST", "/api/dev/stories")]
        body = hub.writes[0][2]
        assert body["bucket"] == "backlog"
        assert body["source_ref"] == tt.SOURCE_REF
        assert "repo:mykronos" in body["tags"]
        assert f"`{BOMB}`" in body["detail"] and f"`{OTHER}`" in body["detail"]
        assert "now+45d" in body["detail"] and "abc1234" in body["detail"]

    def test_the_same_failures_the_next_night_write_nothing(self, tt, tmp_path) -> None:
        hub = FakeHub()
        run = tt.read_report(_junit(tmp_path, passed=2, failed=[BOMB]))
        tt.report(run, hub, offset="+45d", commit="abc")
        tt.report(run, hub, offset="+45d", commit="def")
        assert len(hub.writes) == 1
        assert len(hub.stories) == 1

    def test_changed_failures_rewrite_the_open_story_in_place(self, tt, tmp_path) -> None:
        hub = FakeHub()
        first = tt.read_report(_junit(tmp_path, passed=2, failed=[BOMB]))
        tt.report(first, hub, offset="+45d", commit="a")
        story_id = hub.stories[0]["id"]
        second = tt.read_report(_junit(tmp_path, passed=2, failed=[BOMB, OTHER]))
        tt.report(second, hub, offset="+45d", commit="b")
        assert [(m, p) for m, p, _ in hub.writes][1] == ("PATCH", f"/api/dev/stories/{story_id}")
        assert len(hub.stories) == 1
        assert tt.listed_tests(hub.stories[0]["detail"]) == tuple(sorted([BOMB, OTHER]))

    def test_a_story_found_in_another_open_bucket_is_still_the_one(self, tt, tmp_path) -> None:
        run = tt.read_report(_junit(tmp_path, passed=1, failed=[BOMB]))
        hub = FakeHub(
            [{"id": 7, "bucket": "sprint", "closed_at": None, "source_ref": tt.SOURCE_REF,
              "detail": tt.story_detail(run, offset="+45d", commit="x")}]
        )
        tt.report(run, hub, offset="+45d", commit="y")
        assert hub.writes == []

    def test_a_closed_story_is_not_reused(self, tt, tmp_path) -> None:
        run = tt.read_report(_junit(tmp_path, passed=1, failed=[BOMB]))
        hub = FakeHub(
            [{"id": 7, "bucket": "backlog", "closed_at": "2026-10-30T00:00:00Z",
              "source_ref": tt.SOURCE_REF,
              "detail": tt.story_detail(run, offset="+45d", commit="x")}]
        )
        tt.report(run, hub, offset="+45d", commit="y")
        assert [m for m, _, _ in hub.writes] == ["POST"]

    def test_a_refusal_is_an_error(self, tt, tmp_path) -> None:
        def refuse(method, path, body):
            return (200, []) if method == "GET" else (422, {"detail": "no"})

        run = tt.read_report(_junit(tmp_path, passed=1, failed=[BOMB]))
        with pytest.raises(tt.HubError):
            tt.report(run, refuse, offset="+45d", commit="a")

    def test_red_with_no_hub_credential_says_so(
        self, tt, tmp_path, monkeypatch, capsys
    ) -> None:
        monkeypatch.delenv("HUB_URL", raising=False)
        monkeypatch.delenv("HUB_STORY_TOKEN", raising=False)
        path = _junit(tmp_path, passed=1, failed=[BOMB])
        assert tt.main(["--junit", str(path), "--offset", "+45d", "--commit", "a"]) == 3
        out = capsys.readouterr()
        assert BOMB in out.out
        assert "not filed" in out.err
