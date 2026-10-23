"""Concourse is stalled: many lanes erroring together (TheHub #60975).

After a host or Docker restart the workers die and jobs across the estate go
`errored`. Nothing said so: reachability checks pass, per-lane alerts wait
for three builds of one lane, and the dormant-lanes notice waits 72 hours.

These pin:

* the rule - red when >= 3 unpaused jobs' latest finished build errored with
  start times inside one 60-minute window; `failed`, `aborted` and paused jobs
  do not count, and neither do errors spread over hours;
* the estate as it was on 2026-10-23 (a fixture of the live anonymous
  `/api/v1/jobs` list, trimmed to the fields read) reads green - its two
  errored lanes started 13 days apart and one of them is paused;
* one notice per stall episode, persisted, and marked sent only on delivery;
* GET /api/dashboard/platform-health carries the check, and a stall degrades
  the page.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from mykronos import ci_stall, jobs, main, platform_health
from mykronos.ci import ConcourseClient
from mykronos.config import Settings
from mykronos.db import Database
from mykronos.notify import Notification

NOW = datetime(2026, 10, 23, 18, 0, tzinfo=UTC)
LIVE = Path(__file__).parent / "data" / "concourse" / "jobs-2026-10-23.json"


def at(minutes_ago: float) -> int:
    return int((NOW - timedelta(minutes=minutes_ago)).timestamp())


def job(
    name: str,
    status: str | None = "errored",
    *,
    started: float = 10,
    paused: bool = False,
    pipeline: str = "keel",
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "name": name,
        "team_name": "main",
        "pipeline_name": pipeline,
        "paused": paused or None,
    }
    if status is not None:
        start = at(started)
        out["finished_build"] = {
            "id": 1,
            "name": "7",
            "status": status,
            "start_time": start,
            "end_time": start + 30,
        }
    return out


def stampede(count: int = 3, *, status: str = "errored", spread: float = 5) -> list[dict[str, Any]]:
    return [job(f"lane-{n}", status, started=10 + n * spread) for n in range(count)]


class Recorder:
    def __init__(self, *, delivers: bool = True, enabled: bool = True) -> None:
        self.sent: list[Notification] = []
        self._delivers = delivers
        self._enabled = enabled

    @property
    def enabled(self) -> bool:
        return self._enabled

    async def send(self, note: Notification) -> bool:
        self.sent.append(note)
        return self._delivers


class Stub(ConcourseClient):
    """The real client's link-building, a served job list."""

    def __init__(self, payload: list[dict[str, Any]] | None, external_url: str = "") -> None:
        super().__init__("http://concourse:8080", external_url=external_url)
        self.payload = payload

    def all_jobs(self) -> list[dict[str, object]] | None:
        return self.payload  # type: ignore[return-value]


class TestTheRule:
    def test_three_errored_within_an_hour_is_red(self) -> None:
        stall = ci_stall.assess(stampede(3))

        assert stall.status == "red"
        assert [j.job for j in stall.jobs] == ["lane-2", "lane-1", "lane-0"]
        assert "Concourse is stalled" in stall.detail

    def test_two_errored_is_green(self) -> None:
        stall = ci_stall.assess(stampede(2))

        assert stall.status == "green"
        assert len(stall.jobs) == 2, "green still lists what it weighed"

    def test_three_spread_over_three_hours_is_green(self) -> None:
        stall = ci_stall.assess(stampede(3, spread=90))

        assert stall.status == "green"

    def test_the_window_is_sixty_minutes_inclusive(self) -> None:
        assert ci_stall.assess(stampede(3, spread=30)).status == "red"
        assert ci_stall.assess(stampede(3, spread=31)).status == "green"

    def test_three_failed_is_green(self) -> None:
        assert ci_stall.assess(stampede(3, status="failed")).status == "green"

    def test_three_errored_of_which_one_paused_is_green(self) -> None:
        lanes = stampede(3)
        lanes[1]["paused"] = True

        assert ci_stall.assess(lanes).status == "green"

    def test_aborted_builds_are_ignored(self) -> None:
        lanes = [*stampede(2), job("cancelled", "aborted", started=12)]

        assert ci_stall.assess(lanes).status == "green"

    def test_a_cluster_inside_a_noisy_estate_is_found(self) -> None:
        lanes = [
            job("old-1", started=60 * 24 * 12),
            job("old-2", started=60 * 24 * 3),
            *stampede(4),
            job("green", "succeeded"),
            job("never-ran", None),
        ]

        stall = ci_stall.assess(lanes)

        assert stall.status == "red"
        assert {j.job for j in stall.jobs} == {"lane-0", "lane-1", "lane-2", "lane-3"}
        assert stall.jobs_inspected == 8

    def test_todays_live_job_list_is_green(self) -> None:
        payload = json.loads(LIVE.read_text(encoding="utf-8"))

        stall = platform_health.assess_ci_stall(payload)

        assert stall.status == "green"
        assert stall.jobs_inspected == 79
        # The paused cloud-posture lane is not even weighed; dast-demo is the
        # one unpaused errored lane, alone.
        assert [(j.pipeline, j.job) for j in stall.jobs] == [("thehub", "dast-demo")]

    def test_an_unreadable_job_list_is_unknown_not_green(self) -> None:
        assert platform_health.assess_ci_stall(None).status == "unknown"

    def test_a_stall_degrades_platform_health(self) -> None:
        assert platform_health.PlatformHealth(ci_stalled=True).degraded
        assert not platform_health.PlatformHealth(ci_stalled=False).degraded


class TestLinks:
    def test_no_loopback_link_is_printed(self) -> None:
        client = Stub(stampede(3), external_url="http://localhost:8080")

        stall = ci_stall.assess(stampede(3), link=client.build_url)

        assert all(j.url is None for j in stall.jobs)
        assert "localhost" not in "\n".join(ci_stall.notice_lines(stall))

    def test_a_browser_url_links_each_build(self) -> None:
        client = Stub(stampede(3), external_url="https://ci.example.org")

        stall = ci_stall.assess(stampede(3), link=client.build_url)

        assert stall.jobs[0].url == (
            "https://ci.example.org/teams/main/pipelines/keel/jobs/lane-2/builds/7"
        )


class TestOneNoticePerEpisode:
    @pytest.fixture
    def db(self, settings: Settings) -> Any:
        database = Database(settings.database_url)
        database.create_all()
        yield database
        database.close()

    async def run(self, db: Database, payload: Any, notifier: Recorder, minutes: int = 0) -> None:
        await jobs.notify_ci_stall(
            Stub(payload), db=db, notifier=notifier, now=NOW + timedelta(minutes=minutes)
        )

    async def test_a_second_red_evaluation_sends_nothing(self, db: Database) -> None:
        notifier = Recorder()

        await self.run(db, stampede(3), notifier)
        await self.run(db, stampede(3), notifier, 10)
        await self.run(db, stampede(4), notifier, 20)

        assert len(notifier.sent) == 1
        note = notifier.sent[0]
        assert note.title == "Concourse is stalled"
        text = note.render()
        assert "keel/lane-0" in text
        assert "Restart the Concourse workers" in text
        assert "Check Vault is unsealed" in text
        assert "Re-trigger the errored jobs" in text

    async def test_green_then_red_again_sends_a_new_one(self, db: Database) -> None:
        notifier = Recorder()

        await self.run(db, stampede(3), notifier)
        await self.run(db, stampede(1), notifier, 10)
        await self.run(db, stampede(3), notifier, 20)

        assert len(notifier.sent) == 2

    async def test_the_episode_survives_a_restart(self, db: Database, settings: Settings) -> None:
        notifier = Recorder()
        await self.run(db, stampede(3), notifier)

        reopened = Database(settings.database_url)
        reopened.create_all()
        try:
            await self.run(reopened, stampede(3), notifier, 10)
        finally:
            reopened.close()

        assert len(notifier.sent) == 1

    async def test_an_undelivered_notice_is_retried(self, db: Database) -> None:
        refusing = Recorder(delivers=False)
        with pytest.raises(jobs.CiStallIncompleteError):
            await self.run(db, stampede(3), refusing)

        working = Recorder()
        await self.run(db, stampede(3), working, 10)
        await self.run(db, stampede(3), working, 20)

        assert len(refusing.sent) == 1
        assert len(working.sent) == 1

    async def test_no_slack_is_skipped_not_delivered(self, db: Database) -> None:
        with pytest.raises(jobs.JobSkipped):
            await self.run(db, stampede(3), Recorder(enabled=False))

        with db.session() as session:
            episode = ci_stall.open_episode(session)
            assert episode is not None and episode.notified_at is None

    async def test_green_sends_nothing(self, db: Database) -> None:
        notifier = Recorder()

        await self.run(db, json.loads(LIVE.read_text(encoding="utf-8")), notifier)

        assert notifier.sent == []

    async def test_an_unreadable_concourse_raises(self, db: Database) -> None:
        with pytest.raises(jobs.CiStallIncompleteError):
            await self.run(db, None, Recorder())


class TestItIsScheduled:
    def _scheduled(self, settings: Settings, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
        captured: dict[str, Any] = {}

        async def record(name: str, interval: int, job: Any, db: Any = None) -> None:
            captured[name] = (interval, job)

        monkeypatch.setattr(main, "_every", record)
        with TestClient(main.create_app(settings)):
            pass
        return captured

    def test_it_runs_every_ten_minutes_with_a_concourse(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = settings.model_copy(update={
            "run_jobs_in_background": True, "concourse_url": "http://concourse:8080",
        })
        assert self._scheduled(settings, monkeypatch)[jobs.CI_STALL_JOB][0] == 600

    def test_without_a_concourse_it_is_not_scheduled(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = settings.model_copy(update={
            "run_jobs_in_background": True, "concourse_url": "",
        })
        assert jobs.CI_STALL_JOB not in self._scheduled(settings, monkeypatch)


class TestThePage:
    def _page(
        self,
        settings: Settings,
        admin_auth: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
        payload: list[dict[str, Any]] | None,
    ) -> dict[str, Any]:
        from mykronos.api import dashboard

        async def checks(_settings: object) -> list[tuple[str, jobs.ReachabilityResult]]:
            return [("concourse", jobs.ReachabilityResult(url="c", reachable=True))]

        monkeypatch.setattr(dashboard, "jobs_self_check", checks)
        monkeypatch.setattr(ConcourseClient, "all_jobs", lambda _self: payload)
        settings = settings.model_copy(update={"concourse_url": "http://concourse:8080"})
        with TestClient(main.create_app(settings)) as client:
            response = client.get("/api/dashboard/platform-health", headers=admin_auth)
        assert response.status_code == 200
        body: dict[str, Any] = response.json()
        return body

    def test_a_stall_is_on_the_page_and_degrades_it(
        self, settings: Settings, admin_auth: dict[str, str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        body = self._page(settings, admin_auth, monkeypatch, stampede(3))

        stall = body["ci_stall"]
        assert stall["status"] == "red"
        assert [j["job"] for j in stall["jobs"]] == ["lane-2", "lane-1", "lane-0"]
        assert all(j["started_at"] for j in stall["jobs"])
        assert stall["checklist"] == [
            "Restart the Concourse workers",
            "Check Vault is unsealed",
            "Re-trigger the errored jobs",
        ]
        assert stall["notified_at"] is None
        assert body["degraded"] is True

    def test_todays_estate_is_green_on_the_page(
        self, settings: Settings, admin_auth: dict[str, str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        payload = json.loads(LIVE.read_text(encoding="utf-8"))

        body = self._page(settings, admin_auth, monkeypatch, payload)

        assert body["ci_stall"]["status"] == "green"
        assert body["degraded"] is False

    def test_an_unreadable_concourse_is_unknown(
        self, settings: Settings, admin_auth: dict[str, str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        body = self._page(settings, admin_auth, monkeypatch, None)

        assert body["ci_stall"]["status"] == "unknown"

    def test_without_a_concourse_it_is_unknown(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        body = client.get("/api/dashboard/platform-health", headers=admin_auth).json()

        assert body["ci_stall"]["status"] == "unknown"
        assert body["ci_stall"]["checklist"]
