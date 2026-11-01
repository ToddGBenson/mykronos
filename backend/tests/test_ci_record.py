"""A failing job's recent record: n of its last 10 builds failed (TheHub #60913).

The reason a job failed says what broke this time. Beside it, the CI page has
to say whether this is the first red build in weeks or the tenth in a row,
because those call for different responses. These pin that the record is
counted from the job's own finished builds, for both Concourse and GitHub
Actions lanes, and that a CI which will not answer costs the page a
"record unavailable" line, never an error.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from mykronos.ci import ConcourseClient, JobStatus
from mykronos.ci_why import (
    MAX_EXPLAINED,
    RECENT_WINDOW,
    RecentRecord,
    RecordCache,
    recent_records,
    record_from_statuses,
)
from mykronos.github.client import (
    FakeGitHubClient,
    GitHubError,
    RestGitHubClient,
    WorkflowRun,
)

REPO = "example-org/example-repo"


def _failed(name: str, build_id: str | None = "10", workflow_file: str = "") -> JobStatus:
    return JobStatus(
        name=name,
        status="failed",
        build_name="7",
        build_url=f"https://ci.example.test/{name}",
        finished_at=datetime(2026, 10, 1, tzinfo=UTC),
        build_id=build_id,
        workflow_file=workflow_file,
    )


class TestCounting:
    def test_failed_and_errored_builds_count_as_failed(self) -> None:
        record = record_from_statuses(
            ["failed", "succeeded", "errored", "succeeded", "aborted", "failed"]
        )

        assert record == RecentRecord(failed=3, of=6)

    def test_only_the_last_ten_finished_builds_are_counted(self) -> None:
        record = record_from_statuses(["failed"] * 4 + ["succeeded"] * 20)

        assert record.of == RECENT_WINDOW == 10
        assert record.failed == 4

    def test_builds_that_have_not_finished_are_not_builds_yet(self) -> None:
        record = record_from_statuses(
            ["started", "pending", "failed", None, "skipped", "succeeded"]
        )

        assert record == RecentRecord(failed=1, of=2)

    def test_no_finished_build_is_unavailable_not_zero_of_zero(self) -> None:
        record = record_from_statuses(["started"])

        assert record.unavailable
        assert record.of == 0


class FakeConcourse(ConcourseClient):
    def __init__(self, builds: dict[str, list[dict[str, object]] | None]) -> None:
        super().__init__("http://concourse:8080")
        self.builds = builds
        self.calls: list[tuple[str, str, int]] = []

    def job_builds(
        self, pipeline: str, job: str, *, limit: int = 10
    ) -> list[dict[str, object]] | None:
        self.calls.append((pipeline, job, limit))
        return self.builds.get(job)


def _builds(*statuses: str) -> list[dict[str, object]]:
    return [{"id": 100 + i, "name": str(50 - i), "status": s} for i, s in enumerate(statuses)]


class TestConcourseLanes:
    async def test_a_concourse_lane_counts_its_own_builds(self) -> None:
        concourse = FakeConcourse({"sast": _builds("started", "failed", "failed", "succeeded")})

        out = await recent_records(
            REPO,
            [_failed("sast")],
            source="concourse",
            cache=RecordCache(),
            pipeline="example-repo",
            concourse=concourse,
        )

        assert out["sast"] == RecentRecord(failed=2, of=3)
        pipeline, job, limit = concourse.calls[0]
        assert (pipeline, job) == ("example-repo", "sast")
        # Asks for more than the window, since unfinished builds are skipped.
        assert limit > RECENT_WINDOW

    async def test_only_failed_jobs_get_a_record(self) -> None:
        concourse = FakeConcourse({"sast": _builds("failed"), "unit": _builds("succeeded")})
        green = JobStatus("unit", "succeeded", "3", None, None, build_id="9")

        out = await recent_records(
            REPO,
            [green, _failed("sast")],
            source="concourse",
            cache=RecordCache(),
            pipeline="example-repo",
            concourse=concourse,
        )

        assert set(out) == {"sast"}

    async def test_an_unreadable_build_list_is_a_record_unavailable(self) -> None:
        concourse = FakeConcourse({"sast": None})

        out = await recent_records(
            REPO,
            [_failed("sast")],
            source="concourse",
            cache=RecordCache(),
            pipeline="example-repo",
            concourse=concourse,
        )

        assert out["sast"].unavailable == "Concourse did not return this job's builds"

    async def test_no_concourse_or_no_pipeline_is_a_reason_not_an_error(self) -> None:
        out = await recent_records(
            REPO, [_failed("sast")], source="concourse", cache=RecordCache(), pipeline=None
        )

        assert out["sast"].unavailable


class TestCaching:
    async def test_a_build_is_counted_once_and_then_served_from_the_cache(self) -> None:
        concourse = FakeConcourse({"sast": _builds("failed", "succeeded")})
        cache = RecordCache()

        for _ in range(3):
            out = await recent_records(
                REPO,
                [_failed("sast", "10")],
                source="concourse",
                cache=cache,
                pipeline="p",
                concourse=concourse,
            )

        assert len(concourse.calls) == 1
        assert out["sast"] == RecentRecord(failed=1, of=2)

    async def test_a_newer_build_is_counted_again(self) -> None:
        concourse = FakeConcourse({"sast": _builds("failed", "succeeded")})
        cache = RecordCache()

        for build_id in ("10", "11"):
            await recent_records(
                REPO,
                [_failed("sast", build_id)],
                source="concourse",
                cache=cache,
                pipeline="p",
                concourse=concourse,
            )

        assert len(concourse.calls) == 2

    async def test_a_failed_lookup_is_not_cached(self) -> None:
        concourse = FakeConcourse({"sast": None})
        cache = RecordCache()

        for _ in range(2):
            await recent_records(
                REPO,
                [_failed("sast")],
                source="concourse",
                cache=cache,
                pipeline="p",
                concourse=concourse,
            )

        assert len(concourse.calls) == 2

    async def test_the_number_looked_up_per_request_is_capped(self) -> None:
        jobs = [_failed(f"lane-{i}", str(100 + i)) for i in range(MAX_EXPLAINED + 2)]
        concourse = FakeConcourse({job.name: _builds("failed") for job in jobs})

        out = await recent_records(
            REPO, jobs, source="concourse", cache=RecordCache(), pipeline="p", concourse=concourse
        )

        assert len(concourse.calls) == MAX_EXPLAINED
        assert out[f"lane-{MAX_EXPLAINED}"].unavailable.startswith("not looked up")

    def test_the_cache_is_bounded(self) -> None:
        cache = RecordCache(limit=2)
        for i in range(3):
            cache.put(("concourse", REPO, "sast", str(i)), RecentRecord(failed=1, of=1))

        assert cache.get(("concourse", REPO, "sast", "0")) is None
        assert cache.get(("concourse", REPO, "sast", "2")) is not None


def _run(n: int, conclusion: str) -> WorkflowRun:
    return WorkflowRun(
        workflow_file="mykronos-sast.yml",
        conclusion=conclusion,
        run_number=n,
        url=f"https://github.com/{REPO}/actions/runs/{n}",
        finished_at=datetime(2026, 10, 1, tzinfo=UTC),
        run_id=n,
    )


class TestActionsLanes:
    async def test_an_actions_lane_counts_its_workflows_runs(self) -> None:
        github = FakeGitHubClient()
        conclusions = ["failure", "timed_out", "success", "cancelled", "skipped", "success"]
        github.add_repo(
            REPO,
            run_history={
                "mykronos-sast.yml": [_run(20 - i, c) for i, c in enumerate(conclusions)]
            },
        )

        out = await recent_records(
            REPO,
            [_failed("sast", "20", workflow_file="mykronos-sast.yml")],
            source="github",
            cache=RecordCache(),
            github=github,
        )

        # failure and timed_out failed; the skipped run never ran.
        assert out["sast"] == RecentRecord(failed=2, of=5)
        assert ("workflow_runs", f"{REPO}/mykronos-sast.yml") in github.calls

    async def test_an_unreadable_run_list_is_a_record_unavailable(self, monkeypatch) -> None:
        github = FakeGitHubClient()
        github.add_repo(REPO)

        async def refuse(*args: object, **kwargs: object) -> list[WorkflowRun]:
            raise GitHubError("rate limited", status=403)

        monkeypatch.setattr(github, "workflow_runs", refuse)

        out = await recent_records(
            REPO,
            [_failed("sast", "20", workflow_file="mykronos-sast.yml")],
            source="github",
            cache=RecordCache(),
            github=github,
        )

        assert out["sast"].unavailable == "GitHub did not return this workflow's runs"

    @pytest.mark.parametrize("workflow_file", ["", "../../user", "a/b.yml", "x.yml?per_page=1"])
    async def test_a_workflow_file_that_is_not_a_plain_name_is_never_requested(
        self, workflow_file: str
    ) -> None:
        github = FakeGitHubClient()
        github.add_repo(REPO)

        out = await recent_records(
            REPO,
            [_failed("sast", "20", workflow_file=workflow_file)],
            source="github",
            cache=RecordCache(),
            github=github,
        )

        assert out["sast"].unavailable
        assert not [c for c in github.calls if c[0] == "workflow_runs"]

    async def test_github_without_an_installation_is_a_reason(self) -> None:
        out = await recent_records(
            REPO,
            [_failed("sast", "5", workflow_file="mykronos-sast.yml")],
            source="github",
            cache=RecordCache(),
            github=None,
        )

        assert out["sast"].unavailable

    async def test_the_rest_client_asks_for_one_workflows_completed_runs(self) -> None:
        seen: dict[str, Any] = {}

        async def fake_json(method: str, path: str, **kwargs: Any) -> Any:
            seen.update(method=method, path=path, **kwargs)
            return {
                "workflow_runs": [
                    {
                        "id": 9,
                        "path": ".github/workflows/mykronos-sast.yml",
                        "conclusion": "failure",
                        "run_number": 3,
                        "html_url": "https://github.com/x/runs/9",
                        "updated_at": "2026-10-01T00:00:00Z",
                    },
                    "not a run",
                ]
            }

        client = RestGitHubClient.__new__(RestGitHubClient)
        client._json = fake_json  # type: ignore[method-assign]

        runs = await client.workflow_runs(REPO, "mykronos-sast.yml", limit=10)

        assert seen["method"] == "GET"
        assert seen["path"] == f"/repos/{REPO}/actions/workflows/mykronos-sast.yml/runs"
        assert seen["params"] == {"per_page": 10, "status": "completed"}
        assert seen["timeout"]
        assert [(r.run_id, r.conclusion) for r in runs] == [(9, "failure")]


class TestTheEndpoint:
    def test_a_failing_actions_lane_shows_its_recent_record(
        self, client, admin_auth, github
    ) -> None:
        from tests.conftest import REPO as ONBOARDED
        from tests.test_onboarding import onboard

        onboard(client, admin_auth, scanned_by="github_actions")
        repo = github.repos[ONBOARDED]
        repo.files[".github/workflows/mykronos-sast.yml"] = "name: sast\n"
        latest = WorkflowRun(
            workflow_file="mykronos-sast.yml",
            conclusion="failure",
            run_number=12,
            url=f"https://github.com/{ONBOARDED}/actions/runs/5",
            finished_at=datetime(2026, 10, 1, tzinfo=UTC),
            run_id=5,
        )
        repo.workflow_runs = {"mykronos-sast.yml": latest}
        repo.run_history = {
            "mykronos-sast.yml": [latest]
            + [_run(4 - i, c) for i, c in enumerate(["failure", "success", "failure"])]
        }
        portfolio = client.get("/api/dashboard/portfolio", headers=admin_auth).json()
        repo_id = portfolio["repos"][0]["repo_id"]

        page = client.get(f"/api/dashboard/repos/{repo_id}/ci", headers=admin_auth).json()

        jobs = {j["name"]: j for j in page["jobs"]}
        assert jobs["sast"]["recent"] == {
            "failed": 3,
            "of": 4,
            "window": RECENT_WINDOW,
            "unavailable": None,
        }
