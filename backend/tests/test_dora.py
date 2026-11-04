"""DORA metrics per repository, from data MyKronos already holds (TheHub #60912).

"Accelerate delivery" and "improve reliability" could not be measured in
Mykronos: `/api/dashboard/trends` gives mean time to fix findings and
nothing about delivery. The four DORA metrics are computed here from
TheHub's deploy record and the lake's first-seen time of each commit, over
30 and 90 days. A metric that cannot be computed says which input it
lacks. It is never 0, because a 0 that means "not measured" reads as
"perfect" or "dead".

Every test pins the clock: these are time windows.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

import httpx2
import pytest
from fastapi.testclient import TestClient

from tests.conftest import REPO
from tests.po_support import FakeHub, attach_hub, onboard

NOW = datetime(2026, 11, 1, 12, 0, 0)


def run(
    sha: str,
    *,
    days_ago: float,
    minutes: float = 30,
    status: str = "success",
    trigger: str = "deploy_sh",
    deploy: str | None = "success",
    rollback: str | None = None,
) -> dict[str, Any]:
    """One TheHub deploy run, in `/api/devops/deploys`'s shape.

    `deploy` is deploy.sh's production stage. `deploy_target` is only its
    target selection, which every run passes before it builds anything
    (review of #1117), so it is set here to show it does not count.
    """
    started = NOW - timedelta(days=days_ago)
    stages: dict[str, str] = {"start": "success", "deploy_target": "success", "build": "success"}
    if deploy is not None:
        stages["deploy"] = deploy
    if rollback is not None:
        stages["rollback"] = rollback
    return {
        "id": abs(hash((sha, days_ago))) % 100000,
        "deploy_id": sha,
        # deploy.sh records 12 characters; the lake stores 40.
        "sha": sha[:12],
        "branch": "develop",
        "started_at": started.isoformat() + "+00:00",
        "finished_at": (started + timedelta(minutes=minutes)).isoformat() + "+00:00",
        "final_status": status,
        "trigger_source": trigger,
        "stage_summary": stages,
    }


def source(items: list[dict[str, Any]], *, covers_from: datetime | None = None) -> Any:
    from mykronos import dora

    return dora.DeploySource(
        runs=dora.parse_runs(items), lacks=None, covers_from=covers_from
    )


def compute(src: Any, first_seen: dict[str, datetime] | None = None) -> dict[int, dict[str, Any]]:
    from mykronos import dora

    windows = dora.compute(now=NOW, deploys=src, first_seen=first_seen or {})
    return {w.days: w.model_dump() for w in windows}


class TestDeployFrequency:
    def test_production_deploys_per_week(self) -> None:
        items = [run(f"{i:040x}", days_ago=i * 4 + 1) for i in range(6)]  # 1..21 days ago
        # Not production deploys: a CI run, and an attempt that never reached
        # the target.
        items.append(run("e" * 40, days_ago=2, trigger="concourse"))
        # Died in build: it never reached production, so it is neither a
        # deploy nor a change failure.
        items.append(run("f" * 40, days_ago=3, status="failed", deploy=None))
        # deploy skipped (nothing to ship): not a deploy.
        items.append(run("9" * 40, days_ago=4, deploy="skipped"))
        out = compute(source(items))
        assert out[30]["deploy_frequency"]["value"] == pytest.approx(6 / (30 / 7), abs=0.01)
        assert out[30]["deploy_frequency"]["sample"] == 6
        assert out[30]["deploy_frequency"]["lacks"] is None

    def test_a_record_that_does_not_reach_the_window_start_is_not_enough_data(self) -> None:
        items = [run("a" * 40, days_ago=5)]
        out = compute(source(items, covers_from=NOW - timedelta(days=40)))
        assert out[30]["deploy_frequency"]["value"] is not None
        ninety = out[90]["deploy_frequency"]
        assert ninety["value"] is None
        assert "2026-09-22" in ninety["lacks"]

    def test_an_old_success_with_no_deploy_stage_cannot_be_judged(self) -> None:
        # Before deploy.sh recorded a `deploy` stage, a successful run says
        # nothing about whether it reached production. The record is judged
        # only from after the newest such run.
        items = [run("a" * 40, days_ago=5), run("b" * 40, days_ago=12, deploy=None)]
        out = compute(source(items))
        assert out[30]["deploy_frequency"]["value"] is None
        assert "2026-10-20" in out[30]["deploy_frequency"]["lacks"]
        assert "deploy stage" in out[30]["deploy_frequency"]["lacks"]

    def test_the_real_stage_shape(self) -> None:
        # Two runs as TheHub recorded them on 2026-11-03 (stage_summary
        # trimmed to the stages that decide): one shipped clean, one
        # shipped, failed integration tests and rolled back.
        clean = {
            "sha": "fee0e58e55d0",
            "trigger_source": "deploy_sh",
            "final_status": "success",
            "started_at": "2026-10-30T22:57:59.818863+00:00",
            "finished_at": "2026-10-30T23:43:04.808272+00:00",
            "stage_summary": {
                "start": "success", "build": "success", "risk_gate": "success",
                "deploy": "success", "smoke": "success", "integration_tests": "success",
                "finish": "success",
            },
        }
        rolled_back = {
            "sha": "a173e383ea08",
            "trigger_source": "deploy_sh",
            "final_status": "failed",
            "started_at": "2026-10-30T22:42:55.642372+00:00",
            "finished_at": "2026-10-30T22:58:00.881349+00:00",
            "stage_summary": {
                "start": "success", "build": "success", "deploy": "success",
                "integration_tests": "failed", "rollback": "success", "finish": "failed",
            },
        }
        refused = {
            "sha": "eb3dab826a1c",
            "trigger_source": "deploy_sh",
            "final_status": "failed",
            "started_at": "2026-10-31T04:14:16.559354+00:00",
            "finished_at": "2026-10-31T04:14:54.955742+00:00",
            "stage_summary": {
                "ci_pause": "warned", "deploy_target": "failed", "finish": "failed",
                "start": "success",
            },
        }
        out = compute(source([clean, rolled_back, refused]))[30]
        assert out["deploy_frequency"]["sample"] == 2
        assert out["change_failure_rate"]["value"] == pytest.approx(50.0)
        # The rollback recovered at the clean deploy that followed it.
        assert out["recovery_time"]["value"] == pytest.approx(
            (23 + 43 / 60 + 4.8 / 3600) - (22 + 58 / 60 + 0.88 / 3600), abs=0.01
        )

    def test_no_deploy_record_is_not_zero(self) -> None:
        from mykronos import dora

        src = dora.DeploySource(runs=None, lacks="no deploy record for this repository")
        out = compute(src)
        for days in (30, 90):
            for metric in ("deploy_frequency", "lead_time", "change_failure_rate", "recovery_time"):
                assert out[days][metric]["value"] is None, metric
                assert out[days][metric]["lacks"] == "no deploy record for this repository"


class TestLeadTime:
    def test_the_median_from_first_seen_to_running(self) -> None:
        items = [
            run("a" * 40, days_ago=3, minutes=60),
            run("b" * 40, days_ago=2, minutes=60),
            run("c" * 40, days_ago=1, minutes=60),
        ]
        # Hours from first seen to the deploy finishing: 2, 5 and 9.
        first_seen = {
            "a" * 40: NOW - timedelta(days=3) + timedelta(hours=1) - timedelta(hours=2),
            "b" * 40: NOW - timedelta(days=2) + timedelta(hours=1) - timedelta(hours=5),
            "c" * 40: NOW - timedelta(days=1) + timedelta(hours=1) - timedelta(hours=9),
        }
        lead = compute(source(items), first_seen)[30]["lead_time"]
        assert lead["value"] == pytest.approx(5.0)
        assert lead["unit"] == "hours"
        assert lead["sample"] == 3

    def test_a_short_deployed_sha_matches_its_full_first_seen(self) -> None:
        items = [run("a" * 40, days_ago=3, minutes=60)]
        first_seen = {"a" * 40: NOW - timedelta(days=3) - timedelta(hours=2)}
        assert compute(source(items), first_seen)[30]["lead_time"]["value"] == pytest.approx(3.0)

    def test_an_empty_sha_matches_nothing(self) -> None:
        from mykronos import dora

        assert dora._first_seen({"a" * 40: NOW}, "") is None
        assert dora._first_seen({"": NOW}, "abc") is None

    def test_a_deployed_commit_never_scanned_says_so(self) -> None:
        lead = compute(source([run("a" * 40, days_ago=3)]), {})[30]["lead_time"]
        assert lead["value"] is None
        assert "first-seen" in lead["lacks"]

    def test_no_deploy_in_the_window_says_so(self) -> None:
        lead = compute(source([run("a" * 40, days_ago=60)]))[30]["lead_time"]
        assert lead["value"] is None
        assert "no production deploy" in lead["lacks"]


class TestChangeFailureAndRecovery:
    def test_a_failure_after_the_target_or_a_rollback_is_a_change_failure(self) -> None:
        items = [
            run("a" * 40, days_ago=10),
            run("b" * 40, days_ago=8, status="failed"),  # failed after reaching deploy
            run("c" * 40, days_ago=6, status="success", rollback="success"),
            run("d" * 40, days_ago=4),
        ]
        out = compute(source(items))[30]
        assert out["change_failure_rate"]["value"] == pytest.approx(50.0)
        assert out["change_failure_rate"]["sample"] == 4

    def test_recovery_is_the_time_to_the_next_good_deploy(self) -> None:
        failed = run("b" * 40, days_ago=8, status="failed", minutes=10)
        good = run("d" * 40, days_ago=8 - 3 / 24, minutes=10)  # 3 hours later
        recovery = compute(source([failed, good]))[30]["recovery_time"]
        assert recovery["value"] == pytest.approx(3.0)
        assert recovery["sample"] == 1

    def test_no_failure_means_nothing_to_recover_from_not_zero(self) -> None:
        recovery = compute(source([run("a" * 40, days_ago=2)]))[30]["recovery_time"]
        assert recovery["value"] is None
        assert "no change failure" in recovery["lacks"]

    def test_a_failure_not_yet_recovered_says_so(self) -> None:
        recovery = compute(source([run("b" * 40, days_ago=2, status="failed")]))[30][
            "recovery_time"
        ]
        assert recovery["value"] is None
        assert "not yet" in recovery["lacks"]


# -- The endpoint ----------------------------------------------------------------


class DeployHub(FakeHub):
    """FakeHub that also serves TheHub's deploy record, a page at a time."""

    def __init__(self, items: list[dict[str, Any]]) -> None:
        super().__init__([])
        self.items = sorted(items, key=lambda r: r["started_at"], reverse=True)

    def handler(self, request: httpx2.Request) -> httpx2.Response:
        if request.url.path == "/api/devops/deploys" and request.url.path not in self.failing:
            self.calls.append((request.method, request.url.path, None))
            limit = int(request.url.params.get("limit", 50))
            offset = int(request.url.params.get("offset", 0))
            page = self.items[offset : offset + limit]
            return httpx2.Response(200, json={"items": page, "limit": limit, "offset": offset})
        return super().handler(request)


@pytest.fixture
def pinned(monkeypatch: pytest.MonkeyPatch) -> None:
    from mykronos import dora

    monkeypatch.setattr(dora, "utcnow", lambda: NOW)


def _dora(client: TestClient, repo_id: str, headers: dict[str, str]) -> dict[str, Any]:
    response = client.get(f"/api/dashboard/repos/{repo_id}/product-owner/dora", headers=headers)
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


class TestTheEndpoint:
    def test_thehub_is_measured_from_its_deploy_record(
        self,
        client: TestClient,
        viewer_auth: dict[str, str],
        buffer: Any,
        run_compaction: Callable[[], Any],
        pinned: None,
    ) -> None:
        hub_repo = "example-org/TheHub"
        repo_id = onboard(client, repo=hub_repo)
        # The record reaches back past 90 days, so both windows are covered.
        items = [run("a" * 40, days_ago=2), run("b" * 40, days_ago=200)]
        attach_hub(client, DeployHub(items))
        buffer.append(
            "scan_runs",
            [
                {
                    "scan_run_id": "s-a",
                    "repo_full_name": hub_repo,
                    "capability": "sast",
                    "tool_name": "codeql",
                    "tool_version": "2",
                    "commit_sha": "a" * 40,
                    "branch": "develop",
                    "pr_number": None,
                    "triggered_by": "push",
                    "github_workflow_run_id": "1",
                    "started_at": NOW - timedelta(days=2, hours=4),
                    "completed_at": NOW - timedelta(days=2, hours=4),
                    "scan_status": "success",
                    "finding_count": 0,
                    "raw_output_ref": None,
                    "ingested_at": NOW - timedelta(days=2, hours=4),
                }
            ],
        )
        run_compaction()

        body = _dora(client, repo_id, viewer_auth)

        assert body["repo_full_name"] == hub_repo
        windows = {w["days"]: w for w in body["windows"]}
        assert set(windows) == {30, 90}
        assert windows[30]["deploy_frequency"]["sample"] == 1
        assert windows[30]["deploy_frequency"]["value"] == pytest.approx(7 / 30, abs=0.01)
        # First seen 4h before the deploy started, which ran 30 minutes.
        assert windows[30]["lead_time"]["value"] == pytest.approx(4.5)
        assert windows[30]["change_failure_rate"]["value"] == 0.0
        assert "no change failure" in windows[30]["recovery_time"]["lacks"]

    def test_a_repository_without_a_deploy_record_lacks_one(
        self, client: TestClient, viewer_auth: dict[str, str], pinned: None
    ) -> None:
        repo_id = onboard(client, repo=REPO)
        attach_hub(client, DeployHub([run("a" * 40, days_ago=2)]))

        body = _dora(client, repo_id, viewer_auth)

        for window in body["windows"]:
            for metric in ("deploy_frequency", "lead_time", "change_failure_rate", "recovery_time"):
                assert window[metric]["value"] is None
                assert "no deploy record" in window[metric]["lacks"]

    def test_thehub_unreadable_is_not_enough_data(
        self, client: TestClient, viewer_auth: dict[str, str], pinned: None
    ) -> None:
        repo_id = onboard(client, repo="example-org/TheHub")
        hub = DeployHub([run("a" * 40, days_ago=2)])
        hub.failing.add("/api/devops/deploys")
        attach_hub(client, hub)

        body = _dora(client, repo_id, viewer_auth)

        frequency = body["windows"][0]["deploy_frequency"]
        assert frequency["value"] is None
        assert "could not be read" in frequency["lacks"]

    def test_an_empty_record_says_no_deploys_recorded(
        self, client: TestClient, viewer_auth: dict[str, str], pinned: None
    ) -> None:
        repo_id = onboard(client, repo="example-org/TheHub")
        attach_hub(client, DeployHub([]))

        lacks = _dora(client, repo_id, viewer_auth)["windows"][0]["deploy_frequency"]["lacks"]

        assert "no deploys recorded" in lacks
        assert "reaches back" not in lacks

    def test_thehub_not_connected_says_so(
        self, client: TestClient, viewer_auth: dict[str, str], pinned: None
    ) -> None:
        repo_id = onboard(client, repo="example-org/TheHub")
        client.app.state.hub = None  # type: ignore[attr-defined]

        body = _dora(client, repo_id, viewer_auth)

        assert "not connected" in body["windows"][0]["deploy_frequency"]["lacks"]
