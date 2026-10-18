"""A ScanRun records the CI job that produced it (#449).

`dast-demo` and `dast-staging` are two Concourse jobs scanning two
environments under one capability, and every run either recorded was
identical in the lake: same tool, branch, trigger, empty workflow run id.
These cover the field end to end -- the uploader sends it, the API accepts
it, the lake keeps it -- and that nothing older breaks: a payload without it
is still accepted, and a new uploader talking to a backend that predates it
still records the run.

Staleness is deliberately untouched; keying it on the lane waits on #380.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient

from mykronos.lake.catalog import Catalog
from mykronos.upload import JOB_ENV_VARS, UploadError, build_parser, resolve_job, upload
from tests.conftest import post_scan
from tests.test_upload import RecordingClient, make_args
from tests.test_upload import results as results  # noqa: F401  (fixture)
from tests.test_upload import workspace as workspace  # noqa: F401  (fixture)


@pytest.fixture
def no_job_env(monkeypatch: pytest.MonkeyPatch) -> None:
    # CI itself sets GITHUB_JOB, which would otherwise leak into every case.
    for name in JOB_ENV_VARS:
        monkeypatch.delenv(name, raising=False)


# -- where the uploader gets the name ----------------------------------------


class TestResolveJob:
    def test_the_flag_wins(self) -> None:
        env = {"MYKRONOS_JOB": "env-job", "GITHUB_JOB": "gh"}
        assert resolve_job("dast-demo", env) == "dast-demo"

    @pytest.mark.parametrize(
        "env,expected",
        [
            (
                {"MYKRONOS_JOB": "dast-staging", "GITHUB_JOB": "gh", "BUILD_JOB_NAME": "b"},
                "dast-staging",
            ),
            ({"GITHUB_JOB": "sast-powershell", "BUILD_JOB_NAME": "b"}, "sast-powershell"),
            ({"BUILD_JOB_NAME": "unit"}, "unit"),
            ({"MYKRONOS_JOB": "  ", "GITHUB_JOB": "sast"}, "sast"),
        ],
    )
    def test_then_the_environment_in_order(self, env: dict[str, str], expected: str) -> None:
        assert resolve_job(None, env) == expected

    def test_nothing_says_means_none_not_empty(self) -> None:
        assert resolve_job(None, {}) is None
        assert resolve_job("", {}) is None

    def test_the_cli_accepts_it_and_defaults_to_unset(self) -> None:
        base = [
            "--capability",
            "sast",
            "--tool",
            "semgrep",
            "--results-path",
            "r",
            "--ingestion-url",
            "http://x",
            "--token",
            "t",
            "--repo",
            "a/b",
            "--commit-sha",
            "abc",
            "--branch",
            "main",
        ]
        assert build_parser().parse_args(base).job is None
        assert build_parser().parse_args([*base, "--job", "dast-demo"]).job == "dast-demo"


# -- the uploader sends it ---------------------------------------------------


@pytest.mark.usefixtures("no_job_env")
class TestUploadSendsIt:
    def test_both_posts_carry_the_job(self, results: Path, workspace: Path) -> None:  # noqa: F811
        client = RecordingClient()
        upload(make_args(results, workspace, job="dast-demo"), client=client)
        bodies = client.bodies_for("/api/ingest/scan-run")
        assert len(bodies) == 2
        assert [b["job"] for b in bodies] == ["dast-demo", "dast-demo"]

    def test_from_the_environment_a_concourse_task_sets(
        self,
        results: Path,
        workspace: Path,
        monkeypatch: pytest.MonkeyPatch,  # noqa: F811
    ) -> None:
        monkeypatch.setenv("MYKRONOS_JOB", "dast-staging")
        client = RecordingClient()
        upload(make_args(results, workspace), client=client)
        assert {b["job"] for b in client.bodies_for("/api/ingest/scan-run")} == {"dast-staging"}

    def test_no_job_omits_the_key_entirely(self, results: Path, workspace: Path) -> None:  # noqa: F811
        """Absent, not null: the same omit-when-absent rule as `detail`."""
        client = RecordingClient()
        upload(make_args(results, workspace), client=client)
        for body in client.bodies_for("/api/ingest/scan-run"):
            assert "job" not in body


class OlderBackend(RecordingClient):
    """A backend that predates `job`: ScanRunSubmission forbids extra keys."""

    def __init__(self, error: str) -> None:
        super().__init__()
        self.error = error

    def post(self, path: str, *, json_body: Any = None, content: Any = None, params: Any = None):
        if path == "/api/ingest/scan-run" and json_body and "job" in json_body:
            self.calls.append((path, json_body, params))
            raise UploadError(f"{path} failed and will not be retried — HTTP 422: {self.error}")
        return super().post(path, json_body=json_body, content=content, params=params)


_EXTRA_FORBIDDEN = json.dumps(
    {
        "detail": [
            {
                "type": "extra_forbidden",
                "loc": ["body", "job"],
                "msg": "Extra inputs are not permitted",
            }
        ]
    }
)


@pytest.mark.usefixtures("no_job_env")
class TestAnOlderBackend:
    def test_the_run_is_still_recorded_without_the_job(
        self, results: Path, workspace: Path
    ) -> None:  # noqa: F811
        client = OlderBackend(_EXTRA_FORBIDDEN)
        upload(make_args(results, workspace, job="dast-demo"), client=client)
        bodies = client.bodies_for("/api/ingest/scan-run")
        accepted = [b for b in bodies if "job" not in b]
        # Registered and finalised, both without the field; refused once only.
        assert len(accepted) == 2
        assert sum(1 for b in bodies if "job" in b) == 1
        assert accepted[1]["scan_status"] == "success"

    def test_a_422_about_something_else_is_not_swallowed(
        self,
        results: Path,
        workspace: Path,  # noqa: F811
    ) -> None:
        other = json.dumps({"detail": [{"type": "missing", "loc": ["body", "commit_sha"]}]})
        client = OlderBackend(other)
        with pytest.raises(UploadError):
            upload(make_args(results, workspace, job="dast-demo"), client=client)


# -- the API accepts it and the lake keeps it --------------------------------


class TestIngestStoresIt:
    def test_it_reaches_the_lake(
        self, client: TestClient, auth: dict[str, str], catalog: Catalog, run_compaction
    ) -> None:
        assert post_scan(client, auth, job="dast-demo").status_code < 300
        run_compaction()
        assert catalog.query("SELECT job FROM scan_runs") == [("dast-demo",)]

    def test_an_old_payload_without_it_is_accepted_and_stored_as_null(
        self, client: TestClient, auth: dict[str, str], catalog: Catalog, run_compaction
    ) -> None:
        assert post_scan(client, auth).status_code < 300
        run_compaction()
        assert catalog.query("SELECT job FROM scan_runs") == [(None,)]

    def test_a_later_post_without_it_does_not_blank_it(
        self, client: TestClient, auth: dict[str, str], catalog: Catalog, run_compaction
    ) -> None:
        """Register with a job, compact, then finalise from a caller without one."""
        assert post_scan(client, auth, job="dast-staging", scan_status="success").status_code < 300
        run_compaction()
        assert post_scan(client, auth, completed_at="2026-10-17T12:00:00").status_code < 300
        run_compaction()
        ((job, completed),) = catalog.query("SELECT job, completed_at FROM scan_runs")
        assert job == "dast-staging"
        assert completed is not None

    def test_it_is_bounded(self, client: TestClient, auth: dict[str, str]) -> None:
        assert post_scan(client, auth, job="x" * 201).status_code == 422


# -- the pipelines pass it ---------------------------------------------------

_UPLOAD = re.compile(r"(?<![\w=/.-])(?:(MYKRONOS_JOB=(\S+)) )?python3? -m mykronos\.upload\b")


def _pipelines() -> Path:
    for parent in Path(__file__).resolve().parents:
        d = parent / "deploy" / "concourse" / "pipelines"
        if (d / "thehub.yml").is_file():
            return d
    pytest.fail("deploy/concourse/pipelines not found above this test")


@pytest.mark.parametrize("name", ["thehub", "mykronos", "personal-soc"])
def test_every_concourse_upload_names_its_own_job(name: str) -> None:
    doc = yaml.safe_load((_pipelines() / f"{name}.yml").read_text(encoding="utf-8"))
    seen = 0

    def walk(node: Any, job: str) -> None:
        nonlocal seen
        if isinstance(node, dict):
            for v in node.values():
                walk(v, job)
        elif isinstance(node, list):
            for v in node:
                walk(v, job)
        elif isinstance(node, str) and "mykronos.upload" in node:
            for line in node.splitlines():
                if line.lstrip().startswith("#"):
                    continue
                for m in _UPLOAD.finditer(line):
                    seen += 1
                    assert m.group(2) == job, (
                        f"{name}/{job}: an upload does not set "
                        f"MYKRONOS_JOB={job}: {line.strip()[:90]}"
                    )

    for job in doc["jobs"]:
        walk(job, job["name"])
    assert seen >= 4, f"{name}: expected upload invocations, found {seen}"
