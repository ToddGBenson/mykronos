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
import re
import sys
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


def _script(job: dict[str, Any]) -> str:
    tasks = [s for s in job["plan"] if "task" in s and s["task"] != "preflight"]
    assert len(tasks) == 1
    return tasks[0]["config"]["run"]["args"][-1]


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
        task = next(s for s in job["plan"] if s.get("task") == "pytest-time-travel")
        assert task["params"]["TIME_TRAVEL_OFFSET"] == "((time-travel-offset))"
        script = _script(job)
        assert "apt-get install -y -qq git faketime" in script
        pytest_lines = [line for line in script.splitlines() if "-m pytest" in line]
        assert len(pytest_lines) == 1
        assert pytest_lines[0].lstrip().startswith('faketime -f "$TIME_TRAVEL_OFFSET"')

    def test_the_install_and_the_filing_run_on_the_real_clock(self, pipeline) -> None:
        # pip under a moved clock can refuse a certificate that is valid today,
        # and the story must say when it was really filed.
        script = _script(_job(pipeline))
        for line in script.splitlines():
            if "pip install" in line or "time_travel_report.py" in line:
                assert "faketime" not in line, line

    def test_the_offset_is_longer_than_the_longest_window(self) -> None:
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
        assert "mykronos.upload" not in _script(_job(pipeline))

    def test_it_exits_with_the_suites_code_not_the_filings(self, pipeline) -> None:
        script = _script(_job(pipeline))
        assert "|| rc=$?" in script
        assert script.rstrip().endswith('exit "$rc"')

    def test_it_is_in_a_group(self, pipeline) -> None:
        assert any(JOB in g["jobs"] for g in pipeline["groups"])


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
