"""A portfolio cell whose last run failed is red, not green.

The landing page's capability grid drew a cell solid green when the capability
had EVER scanned (`has_scanned`), however its last run ended. A lane failing
on every build, or a scanner erroring on every run, still read as coverage.
`last_run_failed` is the latest state: the last scan run did not succeed, OR
the lane that produces the capability last failed/errored - which catches the
job that broke before it uploaded anything, and so never wrote a failed run.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from mykronos import ci
from mykronos.ci import (
    ACTIONS,
    MYKRONOS,
    THEHUB,
    JobStatus,
    LaneResult,
    latest_lane_by_capability,
)
from mykronos.dashboard import CapabilityState, scan_failed, with_lanes
from tests.conftest import post_scan
from tests.test_onboarding import onboard

T0 = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)
T1 = datetime(2026, 10, 20, 14, 3, tzinfo=UTC)


def job(name: str, status: str | None, at: datetime | None, *, paused: bool = False) -> JobStatus:
    return JobStatus(
        name=name,
        status=status,
        build_name="336" if status else None,
        build_url=f"http://ci/{name}/336" if status else None,
        finished_at=at,
        paused=paused,
    )


class TestLatestLaneByCapability:
    def test_a_failing_job_beats_a_newer_green_sibling(self) -> None:
        """mykronos's `unit` is produced by `unit` and the weekly `coverage`.
        A green coverage run after a red unit build does not make unit green."""
        lanes = latest_lane_by_capability(
            MYKRONOS, [job("unit", "failed", T0), job("coverage", "succeeded", T1)]
        )
        assert lanes["unit"].job == "unit"
        assert lanes["unit"].failed is True
        assert lanes["unit"].ci == "concourse"

    def test_errored_is_a_failure_and_aborted_is_not(self) -> None:
        assert latest_lane_by_capability(THEHUB, [job("sast", "errored", T0)])["sast"].failed
        assert not latest_lane_by_capability(THEHUB, [job("sast", "aborted", T0)])["sast"].failed

    def test_with_none_failing_the_newest_is_reported(self) -> None:
        lanes = latest_lane_by_capability(
            MYKRONOS, [job("unit", "succeeded", T0), job("coverage", "succeeded", T1)]
        )
        assert lanes["unit"].job == "coverage"
        assert lanes["unit"].failed is False

    def test_paused_unfinished_and_unmapped_jobs_colour_nothing(self) -> None:
        lanes = latest_lane_by_capability(
            THEHUB,
            [
                job("sast", "failed", T0, paused=True),
                job("unit", None, None),
                job("not-a-mapped-job", "failed", T0),
            ],
        )
        assert lanes == {}

    def test_actions_lanes_say_where_they_ran(self) -> None:
        lanes = latest_lane_by_capability(ACTIONS, [job("sast", "failed", T1)])
        assert lanes["sast"].ci == "github_actions"
        assert lanes["sast"].build_name == "336"


def lane(status: str) -> LaneResult:
    return LaneResult(
        ci="concourse",
        pipeline="thehub",
        job="sast",
        status=status,
        build_name="336",
        build_url="http://ci/sast/336",
        finished_at=T1,
    )


class TestLastRunFailed:
    @pytest.mark.parametrize(
        ("status", "failed"),
        [
            ("success", False),
            ("no_applicable_targets", False),
            ("reported", False),
            (None, False),
            ("failure", True),
            ("partial_failure", True),
            ("something-new", True),
        ],
    )
    def test_scan_status(self, status: str | None, failed: bool) -> None:
        assert scan_failed(status) is failed

    def test_a_failed_lane_is_red_even_when_the_last_scan_succeeded(self) -> None:
        """The job broke after (or instead of) uploading: the last run it
        wrote is green, the lane is not."""
        states = [CapabilityState("sast", has_scanned=True, last_scan_status="success")]
        with_lanes(states, {"sast": lane("failed")})
        assert states[0].last_run_failed is True
        assert states[0].lane_job == "sast"
        assert states[0].lane_build_name == "336"

    def test_a_failed_scan_is_red_even_when_the_lane_succeeded(self) -> None:
        states = [CapabilityState("sast", has_scanned=True, last_scan_status="failure")]
        with_lanes(states, {"sast": lane("succeeded")})
        assert states[0].last_run_failed is True

    def test_green_only_when_both_halves_succeeded(self) -> None:
        states = [CapabilityState("sast", has_scanned=True, last_scan_status="success")]
        with_lanes(states, {"sast": lane("succeeded")})
        assert states[0].last_run_failed is False

    def test_unknown_lanes_fall_back_to_the_scan(self) -> None:
        states = [CapabilityState("sast", has_scanned=True, last_scan_status="success")]
        with_lanes(states, None)
        assert states[0].last_run_failed is False
        assert states[0].lane_status is None


class FakeResponse:
    def __init__(self, payload: object, status: int = 200) -> None:
        self._payload = payload
        self.status = status

    def raise_for_status(self) -> None:
        if self.status >= 400:
            raise RuntimeError(f"HTTP {self.status}")

    def json(self) -> object:
        return json.loads(json.dumps(self._payload))


class TestPortfolioApi:
    def test_a_failed_scan_run_is_reported_as_last_run_failed(
        self, client: TestClient, admin_auth: dict[str, str], auth, run_compaction
    ) -> None:
        onboard(client, admin_auth, scanned_by="concourse")
        post_scan(client, auth, scan_status="failure")
        run_compaction()

        row = client.get("/api/dashboard/portfolio", headers=admin_auth).json()["repos"][0]
        states = {s["capability"]: s for s in row["capability_states"]}

        assert states["sast"]["has_scanned"] is True
        assert states["sast"]["last_run_failed"] is True
        assert states["dast"]["last_run_failed"] is False

    def test_a_failing_concourse_lane_is_reported_with_its_build(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        auth,
        run_compaction,
        monkeypatch,
    ) -> None:
        """The scan succeeded; the lane's last build failed. Red, and the
        build is named so the cell can say which one."""
        onboard(client, admin_auth, scanned_by="concourse")
        post_scan(client, auth)
        run_compaction()

        monkeypatch.setitem(ci.CAPABILITY_BY_JOB, ("payments-api", "sast"), "sast")
        routes = {
            "/api/v1/pipelines": [{"name": "payments-api"}],
            "/pipelines/payments-api/jobs": [
                {
                    "name": "sast",
                    "finished_build": {
                        "name": "336",
                        "status": "failed",
                        "end_time": int(T1.timestamp()),
                    },
                }
            ],
        }

        def fake_get(url: str, timeout: float = 0) -> FakeResponse:
            for suffix, payload in routes.items():
                if url.endswith(suffix):
                    return FakeResponse(payload)
            return FakeResponse(None, status=404)

        monkeypatch.setattr("mykronos.ci.httpx2.get", fake_get)
        monkeypatch.setattr(client.app.state.settings, "concourse_url", "http://concourse:8080")

        row = client.get("/api/dashboard/portfolio", headers=admin_auth).json()["repos"][0]
        sast = {s["capability"]: s for s in row["capability_states"]}["sast"]

        assert sast["last_scan_status"] == "success"
        assert sast["last_run_failed"] is True
        assert sast["lane_ci"] == "concourse"
        assert sast["lane_pipeline"] == "payments-api"
        assert sast["lane_job"] == "sast"
        assert sast["lane_status"] == "failed"
        assert sast["lane_build_name"] == "336"
        assert sast["lane_finished_at"] is not None

    def test_an_unreachable_concourse_leaves_lanes_unknown_and_the_page_up(
        self, client: TestClient, admin_auth: dict[str, str], auth, monkeypatch
    ) -> None:
        onboard(client, admin_auth, scanned_by="concourse")

        def down(url: str, timeout: float = 0) -> FakeResponse:
            raise RuntimeError("connection refused")

        monkeypatch.setattr("mykronos.ci.httpx2.get", down)
        monkeypatch.setattr(client.app.state.settings, "concourse_url", "http://concourse:8080")

        response = client.get("/api/dashboard/portfolio", headers=admin_auth)
        assert response.status_code == 200
        states = {s["capability"]: s for s in response.json()["repos"][0]["capability_states"]}
        assert states["sast"]["lane_status"] is None
        assert states["sast"]["last_run_failed"] is False
