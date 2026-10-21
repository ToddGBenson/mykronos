"""Paused and long-red Concourse lanes are pushed once a day, not only when asked.

`agent_work` lists `ci_job_paused` items and `mykronos briefing` reports paused
lanes, but both only answer when somebody asks. These pin the push:

* a job paused for more than the threshold is listed, in every pipeline, and so
  is one red on its last build for more than the threshold, measured from the
  transition build;
* younger pauses and failures, `aborted`, and green jobs are not listed;
* one post per UTC day. The day is read from the job's own `job_runs` row, so
  a second run, or a restart, the same day posts nothing;
* an undelivered post or an unreadable Concourse raises, so the run reads
  `could not check` and the day stays open.

The Concourse client is a stub that serves the shapes the live API returned
on 2026-10-20: `paused_at` on a paused job, and `transition_build` beside
`finished_build`.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from mykronos import dormant_lanes, jobs, main
from mykronos.config import Settings
from mykronos.db import Database
from mykronos.notify import Notification

NOW = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)
DAY = 86_400


def ago(hours: float) -> int:
    return int((NOW - timedelta(hours=hours)).timestamp())


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


def build(name: str, status: str, ended_hours_ago: float) -> dict[str, Any]:
    end = ago(ended_hours_ago)
    return {"name": name, "status": status, "start_time": end - 60, "end_time": end}


def job(
    name: str,
    status: str | None = "succeeded",
    *,
    ended: float = 1,
    red_since: float | None = None,
    paused_hours: float | None = None,
    paused_at_missing: bool = False,
) -> dict[str, Any]:
    out: dict[str, Any] = {"name": name, "paused": None}
    if status is not None:
        out["finished_build"] = build("9", status, ended)
        out["transition_build"] = build("4", status, red_since if red_since else ended)
    if paused_hours is not None or paused_at_missing:
        out["paused"] = True
        out["paused_by"] = "mykronos"
        if not paused_at_missing:
            out["paused_at"] = ago(paused_hours or 0)
    return out


class StubConcourse:
    def __init__(
        self,
        pipelines: dict[str, list[dict[str, Any]] | None] | None,
        *,
        paused_pipelines: dict[str, float] | None = None,
    ) -> None:
        self._pipelines = pipelines
        self._paused = paused_pipelines or {}
        self.reads = 0

    def pipeline_records(self) -> list[dict[str, Any]] | None:
        self.reads += 1
        if self._pipelines is None:
            return None
        return [
            {"name": name, "paused": name in self._paused,
             **({"paused_at": ago(self._paused[name])} if name in self._paused else {})}
            for name in self._pipelines
        ]

    def jobs(self, pipeline: str) -> list[dict[str, Any]] | None:
        assert self._pipelines is not None
        return self._pipelines[pipeline]

    def pipeline_url(self, pipeline: str) -> str:
        return f"http://ci/teams/main/pipelines/{pipeline}"


def estate() -> StubConcourse:
    return StubConcourse({
        "mykronos": [
            job("unit"),
            job("demo-and-dast", "succeeded", ended=200, paused_hours=100),
            job("young-pause", "succeeded", paused_hours=10),
            # Failing every hour for a week: counted from the transition.
            job("netassess-ingest", "failed", ended=1, red_since=24 * 7),
            job("fresh-failure", "failed", ended=2, red_since=2),
            job("aborted-long-ago", "aborted", ended=200),
        ],
        "thehub": [
            job("cloud-posture", "errored", ended=80, red_since=80),
            job("never-built", None),
            job("unknown-pause", "succeeded", paused_at_missing=True),
        ],
    })


def names(report: dormant_lanes.DormantLanesReport) -> set[str]:
    return {f"{lane.pipeline}/{lane.job}:{lane.state}" for lane in report.lanes}


class TestFind:
    def test_it_lists_long_pauses_and_long_red_lanes_across_pipelines(self) -> None:
        report = dormant_lanes.find(estate(), now=NOW, threshold_hours=72)

        assert names(report) == {
            "mykronos/demo-and-dast:paused",
            "mykronos/netassess-ingest:failed",
            "thehub/cloud-posture:errored",
            "thehub/unknown-pause:paused",
        }
        assert report.complete

    def test_red_is_counted_from_the_transition_build_not_the_last_failure(self) -> None:
        report = dormant_lanes.find(estate(), now=NOW, threshold_hours=72)
        [lane] = [lane for lane in report.lanes if lane.job == "netassess-ingest"]

        assert lane.since == datetime.fromtimestamp(ago(24 * 7), tz=UTC)
        assert "for 7.0 days" in lane.line(NOW)

    def test_a_paused_pipeline_is_listed(self) -> None:
        source = StubConcourse({"keel": [job("atlas")]}, paused_pipelines={"keel": 96})

        report = dormant_lanes.find(source, now=NOW, threshold_hours=72)

        assert names(report) == {"keel/:pipeline paused"}

    def test_an_unreadable_pipeline_is_named_not_skipped(self) -> None:
        source = StubConcourse({"mykronos": [job("unit")], "thehub": None})

        report = dormant_lanes.find(source, now=NOW, threshold_hours=72)

        assert not report.complete
        assert report.unreadable == ["thehub jobs"]
        assert report.pipelines_read == ["mykronos"]


class TestNotify:
    async def test_it_posts_one_notification_naming_every_dormant_lane(self) -> None:
        notifier = Recorder()

        await jobs.notify_dormant_lanes(
            estate(), db=None, notifier=notifier, threshold_hours=72, now=NOW
        )

        [note] = notifier.sent
        assert note.level == "warning"
        assert note.title.startswith("4 Concourse lane(s)")
        for lane in ("mykronos/demo-and-dast", "mykronos/netassess-ingest",
                     "thehub/cloud-posture", "thehub/unknown-pause"):
            assert lane in note.detail
        assert "young-pause" not in note.detail
        assert "fresh-failure" not in note.detail

    async def test_a_healthy_estate_posts_nothing(self) -> None:
        notifier = Recorder()
        source = StubConcourse({"mykronos": [job("unit")]})

        report = await jobs.notify_dormant_lanes(
            source, db=None, notifier=notifier, threshold_hours=72, now=NOW
        )

        assert report is not None and report.lanes == []
        assert notifier.sent == []

    async def test_an_unreachable_concourse_is_could_not_check(self) -> None:
        notifier = Recorder()

        with pytest.raises(jobs.DormantLanesIncompleteError, match="could not check"):
            await jobs.notify_dormant_lanes(
                StubConcourse(None), db=None, notifier=notifier, threshold_hours=72, now=NOW
            )
        assert notifier.sent == []

    async def test_an_undelivered_post_raises_so_the_day_stays_open(self) -> None:
        with pytest.raises(jobs.DormantLanesIncompleteError, match="not delivered"):
            await jobs.notify_dormant_lanes(
                estate(), db=None, notifier=Recorder(delivers=False),
                threshold_hours=72, now=NOW,
            )

    async def test_a_notifier_with_no_transport_is_not_a_failure(self) -> None:
        notifier = Recorder(enabled=False)

        report = await jobs.notify_dormant_lanes(
            estate(), db=None, notifier=notifier, threshold_hours=72, now=NOW
        )

        assert report is not None and len(report.lanes) == 4
        assert notifier.sent == []


class TestOncePerDay:
    @pytest.fixture
    def db(self, settings: Settings) -> Any:
        database = Database(settings.database_url)
        database.create_all()
        yield database
        database.close()

    async def run_like_every(self, db: Database, notifier: Recorder, now: datetime) -> None:
        """What `_every` does around the job: run it, then record the outcome."""
        try:
            await jobs.notify_dormant_lanes(
                estate(), db=db, notifier=notifier, threshold_hours=72, now=now
            )
        except jobs.DormantLanesIncompleteError as exc:
            main._record_run(db, jobs.DORMANT_LANES_JOB, 3_600, str(exc))
        else:
            main._record_run(db, jobs.DORMANT_LANES_JOB, 3_600, None)

    async def test_hourly_runs_and_a_restart_post_once_a_day(
        self, db: Database, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        notifier = Recorder()
        # `_record_run` stamps utcnow(); pin it to the run's own clock.
        clock = {"now": NOW}
        monkeypatch.setattr(main, "utcnow", lambda: clock["now"].replace(tzinfo=None))

        for hour in range(5):  # four hourly ticks and a restart's boot run
            clock["now"] = NOW + timedelta(hours=hour)
            await self.run_like_every(db, notifier, clock["now"])
        assert len(notifier.sent) == 1

        clock["now"] = NOW + timedelta(days=1)
        await self.run_like_every(db, notifier, clock["now"])
        assert len(notifier.sent) == 2, "the next UTC day posts again"

    async def test_a_failed_delivery_is_retried_the_same_day(
        self, db: Database, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        clock = {"now": NOW}
        monkeypatch.setattr(main, "utcnow", lambda: clock["now"].replace(tzinfo=None))
        failing = Recorder(delivers=False)

        await self.run_like_every(db, failing, NOW)
        working = Recorder()
        clock["now"] = NOW + timedelta(hours=1)
        await self.run_like_every(db, working, clock["now"])

        assert len(failing.sent) == 1
        assert len(working.sent) == 1


class TestItIsScheduled:
    def _scheduled(self, settings: Settings, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
        from fastapi.testclient import TestClient

        captured: dict[str, Any] = {}

        async def record(name: str, interval: int, job: Any, db: Any = None) -> None:
            captured[name] = (interval, job)

        monkeypatch.setattr(main, "_every", record)
        with TestClient(main.create_app(settings)):
            pass
        return captured

    def test_it_runs_hourly_against_the_configured_concourse(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = settings.model_copy(update={
            "run_jobs_in_background": True,
            "concourse_url": "http://concourse:8080",
            "concourse_team": "main",
        })
        calls: list[tuple[Any, ...]] = []

        async def fake_notify(source: Any, **kwargs: Any) -> None:
            calls.append((source.base_url, source.team, kwargs["threshold_hours"],
                          kwargs["db"] is not None))

        monkeypatch.setattr(main, "notify_dormant_lanes", fake_notify)
        scheduled = self._scheduled(settings, monkeypatch)

        interval, run = scheduled[jobs.DORMANT_LANES_JOB]
        assert interval == 3_600

        import asyncio

        asyncio.run(run())
        assert calls == [("http://concourse:8080", "main", 72.0, True)]

    def test_without_a_concourse_it_is_not_scheduled(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = settings.model_copy(update={
            "run_jobs_in_background": True, "concourse_url": "",
        })
        assert jobs.DORMANT_LANES_JOB not in self._scheduled(settings, monkeypatch)
