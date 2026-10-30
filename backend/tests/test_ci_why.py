"""Why a failing CI job failed (TheHub #60913).

The CI page named failing jobs and nothing more, so the answer to "why" was
always somewhere else. These pin the three things that make the answer worth
showing on this page: it names the step and the error the job raised, it
never carries other log output (logs here can hold resolved secrets), and it
degrades to "reason unavailable" instead of failing the page.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest

from mykronos import ci_why
from mykronos.ci import JobStatus
from mykronos.ci_why import (
    MAX_EXPLAINED,
    ConcourseWhyReader,
    FailureWhy,
    WhyCache,
    clean,
    explain_failures,
    github_why,
    step_names,
    why_from_events,
    why_from_run,
)
from mykronos.github.client import (
    CheckAnnotation,
    FakeGitHubClient,
    GitHubError,
    WorkflowJob,
    WorkflowRun,
    WorkflowStep,
)

REPO = "example-org/example-repo"
BUILD_URL = "http://ci.example.test/teams/main/pipelines/p/jobs/sast/builds/7"

PLAN = {
    "schema": "exec.v2",
    "plan": {
        "id": "a0",
        "on_failure": {
            "step": {"id": "a9", "task": {"name": "notify"}},
        },
        "do": [
            {"id": "a1", "get": {"name": "source", "type": "git"}},
            {"id": "a2", "task": {"name": "scan"}},
            {"id": "a3", "task": {"name": "upload"}},
        ],
    },
}


def _event(kind: str, data: dict[str, Any]) -> list[str]:
    return ["event: event", "data: " + json.dumps({"event": kind, "data": data}), ""]


def _log(origin: str, payload: str) -> list[str]:
    return _event("log", {"origin": {"id": origin}, "payload": payload})


def _finish(origin: str, status: int, kind: str = "finish-task") -> list[str]:
    return _event(kind, {"origin": {"id": origin}, "exit_status": status})


def _stream(*parts: list[str]) -> list[str]:
    lines: list[str] = []
    for part in parts:
        lines.extend(part)
    return [*lines, "event: end", ""]


class TestCleaning:
    @pytest.mark.parametrize(
        "secret",
        [
            "ghs_" + "A" * 36,
            "github_pat_" + "B" * 30,
            "mka_" + "c" * 20,
            "hvs." + "D" * 24,
            "AKIA" + "E" * 16,
        ],
    )
    def test_a_credential_shape_is_masked(self, secret: str) -> None:
        cleaned = clean(f"upload refused for {secret} today")

        assert secret not in cleaned
        assert "[redacted]" in cleaned

    def test_a_key_value_secret_keeps_its_name_and_loses_its_value(self) -> None:
        cleaned = clean("HUB_TOKEN=s3cr3t-value-here failed")

        assert "s3cr3t-value-here" not in cleaned
        assert "HUB_TOKEN=[redacted]" in cleaned

    def test_credentials_in_a_url_are_masked(self) -> None:
        cleaned = clean("fatal: could not read https://user:hunter22@git.example.test/x")

        assert "hunter22" not in cleaned

    def test_escapes_and_control_characters_do_not_survive(self) -> None:
        cleaned = clean("\x1b[31mred\x1b[0m\x07 text")

        assert cleaned == "red text"

    def test_it_is_bounded(self) -> None:
        assert len(clean("x" * 5000)) <= ci_why.MAX_MESSAGE_LENGTH


class TestConcourseEvents:
    def test_step_names_cover_the_whole_plan_hooks_included(self) -> None:
        names = step_names(PLAN)

        assert names == {"a1": "source", "a2": "scan", "a3": "upload", "a9": "notify"}

    def test_the_failed_step_and_its_exit_code(self) -> None:
        why = why_from_events(
            step_names(PLAN),
            _stream(
                _finish("a1", 0, "finish-get"),
                _log("a2", "scanning 41 files\n"),
                _finish("a2", 2),
                _log("a9", "posting to slack\n"),
                _finish("a9", 0),
            ),
            url=BUILD_URL,
        )

        assert why.source == "concourse"
        assert why.step == "scan"
        assert why.exit_code == 2
        assert why.messages == ()
        assert why.url == BUILD_URL
        assert why.unavailable is None

    def test_an_error_log_line_is_never_returned(self) -> None:
        """Operator decision on #1037: no build log text leaves this module,
        `::error` lines included, until Concourse redacts secrets. The step
        and exit code are still reported."""
        line = "semgrep exited 2: rule pack missing"
        why = why_from_events(
            step_names(PLAN),
            _stream(
                _log("a2", f"::error::{line}\n::error file=x.py,line=3::second\n"),
                _finish("a2", 2),
            ),
            url=BUILD_URL,
        )

        shown = json.dumps([why.step, why.messages, why.note, why.unavailable])
        assert why.messages == ()
        assert line not in shown
        assert "second" not in shown
        assert why.step == "scan"
        assert why.exit_code == 2

    def test_no_other_log_line_is_ever_returned(self) -> None:
        """Logs here can carry resolved `((var))` values: only `::error`
        lines are author-chosen, so only they may leave this module."""
        leaked = "export HUB_TOKEN_VALUE_THAT_MUST_NOT_SHOW"
        why = why_from_events(
            step_names(PLAN),
            _stream(_log("a2", f"{leaked}\nerror: boom\n"), _finish("a2", 1)),
            url=BUILD_URL,
        )

        shown = json.dumps([why.step, why.messages, why.note, why.unavailable])
        assert leaked not in shown
        assert "boom" not in shown
        assert why.step == "scan"
        assert why.exit_code == 1
        assert why.messages == ()
        assert why.note and "not shown" in why.note

    def test_a_concourse_error_event_is_cleaned(self) -> None:
        token = "ghs_" + "Z" * 36
        why = why_from_events(
            step_names(PLAN),
            _stream(
                _event("error", {"origin": {"id": "a2"}, "message": f"push with {token} refused"})
            ),
            url=BUILD_URL,
        )

        assert why.messages and token not in why.messages[0]
        assert why.messages[0].startswith("push with")

    def test_the_first_failure_is_the_failure_not_a_hook_after_it(self) -> None:
        why = why_from_events(
            step_names(PLAN),
            _stream(_finish("a2", 137), _finish("a9", 1)),
            url=BUILD_URL,
        )

        assert why.step == "scan"
        assert why.exit_code == 137

    def test_a_concourse_error_event_explains_a_step_without_an_exit_code(self) -> None:
        why = why_from_events(
            step_names(PLAN),
            _stream(_event("error", {"origin": {"id": "a3"}, "message": "timeout exceeded"})),
            url=BUILD_URL,
        )

        assert why.step == "upload"
        assert why.exit_code is None
        assert why.messages == ("timeout exceeded",)

    def test_an_image_fetch_is_named_after_its_step(self) -> None:
        why = why_from_events(
            step_names(PLAN), _stream(_finish("a2/image-get", 1, "finish-get")), url=None
        )

        assert why.step == "scan (image-get)"

    def test_a_stream_past_its_cap_is_unavailable_not_wrong(self) -> None:
        noise = _log("a2", "progress\n")
        why = why_from_events(
            step_names(PLAN), _stream(*([noise] * 50), _finish("a2", 1)), url=None, max_lines=40
        )

        assert why.unavailable and "40 lines" in why.unavailable
        assert why.step is None


class FakeResponse:
    def __init__(self, payload: object, status: int = 200, lines: list[str] | None = None):
        self._payload = payload
        self.status = status
        self._lines = lines or []

    def raise_for_status(self) -> None:
        if self.status >= 400:
            raise RuntimeError(f"HTTP {self.status}")

    def json(self) -> object:
        return self._payload

    def iter_lines(self):
        yield from self._lines

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class TestConcourseReader:
    def _wire(self, monkeypatch, *, plan: object, events: list[str] | Exception) -> list[str]:
        seen: list[str] = []

        def fake_get(url: str, timeout: float = 0) -> FakeResponse:
            seen.append(url)
            if isinstance(plan, Exception):
                raise plan
            return FakeResponse(plan)

        def fake_stream(method: str, url: str, headers=None, timeout: float = 0):
            seen.append(url)
            if isinstance(events, Exception):
                raise events
            return FakeResponse(None, lines=events)

        monkeypatch.setattr("mykronos.ci_why.httpx2.get", fake_get)
        monkeypatch.setattr("mykronos.ci_why.httpx2.stream", fake_stream)
        return seen

    def test_it_reads_the_plan_and_the_events_of_that_build(self, monkeypatch) -> None:
        seen = self._wire(monkeypatch, plan=PLAN, events=_stream(_finish("a2", 3)))

        why = ConcourseWhyReader("http://concourse:8080").why("1948916", url=BUILD_URL)

        assert why.step == "scan" and why.exit_code == 3
        assert seen == [
            "http://concourse:8080/api/v1/builds/1948916/plan",
            "http://concourse:8080/api/v1/builds/1948916/events",
        ]

    def test_an_unreadable_plan_is_a_reason_unavailable(self, monkeypatch) -> None:
        self._wire(monkeypatch, plan=RuntimeError("connection refused"), events=[])

        why = ConcourseWhyReader("http://concourse:8080").why("12", url=BUILD_URL)

        assert why.unavailable == "Concourse did not return this build's plan"
        assert why.url == BUILD_URL

    def test_unreadable_events_are_a_reason_unavailable(self, monkeypatch) -> None:
        self._wire(monkeypatch, plan=PLAN, events=RuntimeError("401 Unauthorized"))

        why = ConcourseWhyReader("http://concourse:8080").why("12", url=BUILD_URL)

        assert why.unavailable == "Concourse did not return this build's events"

    def test_a_build_id_that_is_not_a_number_is_never_put_in_a_url(self, monkeypatch) -> None:
        seen = self._wire(monkeypatch, plan=PLAN, events=[])

        why = ConcourseWhyReader("http://concourse:8080").why("../teams", url=None)

        assert why.unavailable
        assert seen == []


def _job(conclusion: str, *, steps: tuple[WorkflowStep, ...] = (), job_id: int = 77) -> WorkflowJob:
    return WorkflowJob(
        id=job_id,
        name="demo-and-dast",
        conclusion=conclusion,
        url=f"https://github.com/{REPO}/actions/runs/5/job/{job_id}",
        steps=steps,
    )


DAST_STEPS = (
    WorkflowStep(name="Checkout", conclusion="success", number=1),
    WorkflowStep(name="Run ZAP baseline", conclusion="failure", number=2),
    WorkflowStep(name="Upload", conclusion="skipped", number=3),
)


class TestActionsRun:
    def test_the_dast_spider_annotation_is_the_reason(self) -> None:
        """The case the story was written from."""
        why = why_from_run(
            [_job("success", job_id=1), _job("failure", steps=DAST_STEPS)],
            [
                CheckAnnotation(level="failure", message="spider did not reach 100% within 600s"),
                CheckAnnotation(
                    level="failure", message="Process completed with exit code 1.", path=".github"
                ),
            ],
            run_url=f"https://github.com/{REPO}/actions/runs/5",
        )

        assert why.source == "github"
        assert why.step == "demo-and-dast: Run ZAP baseline"
        assert why.exit_code == 1
        assert why.messages == ("spider did not reach 100% within 600s",)
        assert why.url.endswith("/job/77")

    def test_an_annotation_keeps_its_file_and_line(self) -> None:
        why = why_from_run(
            [_job("failure", steps=DAST_STEPS)],
            [CheckAnnotation(level="failure", message="E501", path="app/x.py", line=12)],
            run_url=None,
        )

        assert why.messages == ("app/x.py:12: E501",)

    def test_only_the_runner_exit_line_means_no_message_and_says_so(self) -> None:
        why = why_from_run(
            [_job("failure", steps=DAST_STEPS)],
            [CheckAnnotation(level="failure", message="Process completed with exit code 2.")],
            run_url=None,
        )

        assert why.exit_code == 2
        assert why.messages == ()
        assert why.note

    def test_a_run_with_no_failed_job_is_unavailable(self) -> None:
        why = why_from_run([_job("success")], [], run_url=None)

        assert why.unavailable


def _github(**repo: Any) -> FakeGitHubClient:
    github = FakeGitHubClient()
    github.add_repo(REPO, **repo)
    return github


class TestGithubWhy:
    async def test_it_reads_the_jobs_then_the_failed_jobs_annotations(self) -> None:
        github = _github(
            run_jobs={5: [_job("failure", steps=DAST_STEPS)]},
            annotations={77: [CheckAnnotation(level="failure", message="spider stalled")]},
        )

        why = await github_why(github, REPO, 5, run_url=None)

        assert why.messages == ("spider stalled",)
        assert ("check_run_annotations", f"{REPO}#77") in github.calls

    async def test_unreadable_annotations_still_name_the_step(self, monkeypatch) -> None:
        github = _github(run_jobs={5: [_job("failure", steps=DAST_STEPS)]})

        async def refuse(*args: object, **kwargs: object) -> list[CheckAnnotation]:
            raise GitHubError("403", status=403)

        monkeypatch.setattr(github, "check_run_annotations", refuse)

        why = await github_why(github, REPO, 5, run_url=None)

        assert why.step == "demo-and-dast: Run ZAP baseline"
        assert why.unavailable is None
        assert why.note == "GitHub did not return this job's annotations."

    async def test_an_unreadable_run_is_a_reason_unavailable(self, monkeypatch) -> None:
        github = _github()

        async def refuse(*args: object, **kwargs: object) -> list[WorkflowJob]:
            raise GitHubError("rate limited", status=403)

        monkeypatch.setattr(github, "workflow_run_jobs", refuse)

        why = await github_why(github, REPO, 5, run_url="https://github.com/x")

        assert why.unavailable == "GitHub did not return this run's jobs"
        assert why.url == "https://github.com/x"


def _failed(name: str, build_id: str | None) -> JobStatus:
    return JobStatus(
        name=name,
        status="failed",
        build_name="7",
        build_url=f"https://ci.example.test/{name}",
        finished_at=datetime(2026, 10, 1, tzinfo=UTC),
        build_id=build_id,
    )


class CountingReader(ConcourseWhyReader):
    def __init__(self, answer: FailureWhy) -> None:
        super().__init__("http://concourse:8080")
        self.answer = answer
        self.calls: list[str] = []

    def why(self, build_id: str, *, url: str | None) -> FailureWhy:
        self.calls.append(build_id)
        return self.answer


class TestExplainFailures:
    async def test_only_failed_jobs_are_explained(self) -> None:
        reader = CountingReader(FailureWhy(source="concourse", step="scan"))
        green = JobStatus("unit", "succeeded", "3", None, None, build_id="9")

        out = await explain_failures(
            REPO,
            [green, _failed("sast", "10")],
            source="concourse",
            cache=WhyCache(),
            concourse=reader,
        )

        assert set(out) == {"sast"}
        assert reader.calls == ["10"]

    async def test_a_build_is_read_once_and_then_served_from_the_cache(self) -> None:
        reader = CountingReader(FailureWhy(source="concourse", step="scan"))
        cache = WhyCache()

        for _ in range(3):
            out = await explain_failures(
                REPO, [_failed("sast", "10")], source="concourse", cache=cache, concourse=reader
            )

        assert reader.calls == ["10"]
        assert out["sast"].step == "scan"

    async def test_a_failed_lookup_is_not_cached(self) -> None:
        reader = CountingReader(FailureWhy(source="concourse", unavailable="down"))
        cache = WhyCache()

        for _ in range(2):
            await explain_failures(
                REPO, [_failed("sast", "10")], source="concourse", cache=cache, concourse=reader
            )

        assert reader.calls == ["10", "10"]

    async def test_the_number_looked_up_per_request_is_capped(self) -> None:
        reader = CountingReader(FailureWhy(source="concourse", step="scan"))
        jobs = [_failed(f"lane-{i}", str(100 + i)) for i in range(MAX_EXPLAINED + 3)]

        out = await explain_failures(
            REPO, jobs, source="concourse", cache=WhyCache(), concourse=reader
        )

        assert len(reader.calls) == MAX_EXPLAINED
        assert len(out) == MAX_EXPLAINED + 3
        assert out[f"lane-{MAX_EXPLAINED}"].unavailable.startswith("not looked up")

    async def test_no_build_id_and_no_reader_are_reasons_not_errors(self) -> None:
        out = await explain_failures(
            REPO,
            [_failed("sast", None), _failed("iac", "4")],
            source="concourse",
            cache=WhyCache(),
            concourse=None,
        )

        assert out["sast"].unavailable and "build id" in out["sast"].unavailable
        assert out["iac"].unavailable and "Concourse" in out["iac"].unavailable

    async def test_github_without_an_installation_is_a_reason(self) -> None:
        out = await explain_failures(
            REPO, [_failed("sast", "5")], source="github", cache=WhyCache(), github=None
        )

        assert out["sast"].source == "github"
        assert out["sast"].unavailable

    def test_the_cache_is_bounded(self) -> None:
        cache = WhyCache(limit=2)
        for i in range(3):
            cache.put(("concourse", REPO, str(i)), FailureWhy(source="concourse", step="s"))

        assert cache.get(("concourse", REPO, "0")) is None
        assert cache.get(("concourse", REPO, "2")) is not None


class TestTheEndpoint:
    def test_a_failing_actions_lane_says_why(self, client, admin_auth, github) -> None:
        from tests.conftest import REPO as ONBOARDED
        from tests.test_onboarding import onboard

        onboard(client, admin_auth, scanned_by="github_actions")
        repo = github.repos[ONBOARDED]
        repo.files[".github/workflows/mykronos-sast.yml"] = "name: sast\n"
        repo.workflow_runs = {
            "mykronos-sast.yml": WorkflowRun(
                workflow_file="mykronos-sast.yml",
                conclusion="failure",
                run_number=12,
                url=f"https://github.com/{ONBOARDED}/actions/runs/5",
                finished_at=datetime(2026, 10, 1, tzinfo=UTC),
                run_id=5,
            )
        }
        repo.run_jobs = {5: [_job("failure", steps=DAST_STEPS)]}
        repo.annotations = {
            77: [
                CheckAnnotation(level="failure", message="spider did not reach 100% within 600s"),
                CheckAnnotation(level="failure", message="Process completed with exit code 1."),
            ]
        }
        portfolio = client.get("/api/dashboard/portfolio", headers=admin_auth).json()
        repo_id = portfolio["repos"][0]["repo_id"]

        page = client.get(f"/api/dashboard/repos/{repo_id}/ci", headers=admin_auth).json()

        jobs = {j["name"]: j for j in page["jobs"]}
        assert page["failing"] == ["sast"]
        assert jobs["sast"]["why"] == {
            "source": "github",
            "step": "demo-and-dast: Run ZAP baseline",
            "exit_code": 1,
            "messages": ["spider did not reach 100% within 600s"],
            "url": f"https://github.com/{REPO}/actions/runs/5/job/77",
            "note": None,
            "unavailable": None,
        }
