"""A gate that stops deciding is raised, naming the lane in the way (TheHub #60731).

Eight deploys in a row, 2026-10-05..10-12, shipped unjudged behind a red
`lint-and-types`, and nothing said so across runs. These pin:

* the staleness threshold, measured from the OLDEST unjudged commit;
* naming the red lane upstream of `oracle-gate`, or saying none is;
* an unreachable Concourse is `could not check`, recorded as a failed run,
  and never `live`;
* a stale gate is posted once, not every hour.

Concourse is faked from the shapes the live API returned on 2026-10-12: the
job list carries `inputs[].passed`, and `source` versions carry only a `ref`.
"""

from __future__ import annotations

import socket
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from mykronos import gate_liveness, jobs, main
from mykronos.config import Settings
from mykronos.notify import Notification

NOW = datetime(2026, 10, 12, 18, 0, tzinfo=UTC)
BASE = "/api/v1/teams/main/pipelines/mykronos"
UPSTREAM = ["unit", "lint-and-types", "qa-spec-links", "frontend"]
SCANS = ["secrets", "dependencies", "sast", "insider", "containers", "iac"]


class Recorder:
    def __init__(self) -> None:
        self.sent: list[Notification] = []

    @property
    def enabled(self) -> bool:
        return True

    async def send(self, note: Notification) -> bool:
        self.sent.append(note)
        return True


def _job(name: str, status: str | None, passed: list[str] | None = None,
         *, paused: bool = False) -> dict[str, Any]:
    return {
        "name": name,
        "paused": paused or None,
        "finished_build": {"name": "368", "status": status} if status else None,
        "inputs": [{"name": "python"}, {"name": "source", "passed": passed}],
    }


def pipeline_jobs(**status: str) -> list[dict[str, Any]]:
    """The live mykronos graph, every job green unless named."""
    out = [_job(n, status.get(n.replace("-", "_"), "succeeded")) for n in UPSTREAM]
    out += [_job(n, status.get(n, "succeeded"), UPSTREAM) for n in SCANS if n != "containers"]
    out += [_job("build", "succeeded", UPSTREAM)]
    out += [_job(n, "succeeded", ["build"]) for n in ("publish-backend", "publish-frontend")]
    out += [_job("containers", status.get("containers", "succeeded"),
                 ["publish-backend", "publish-frontend"])]
    out += [_job("oracle-gate", status.get("oracle_gate", "succeeded"), SCANS)]
    # Not upstream of the gate: red here must never be named.
    out += [_job("pin-check", "failed"), _job("promote", "failed", ["oracle-gate"])]
    return out


def fake_concourse(
    shas: list[str],
    started: dict[str, datetime | None],
    *,
    jobs_payload: list[dict[str, Any]] | None = None,
    fail: str | None = None,
) -> gate_liveness.Fetch:
    """`shas` newest first; `started[sha]` is when its first build began."""
    routes: dict[str, Any] = {
        f"{BASE}/resources/source/versions?limit={gate_liveness.VERSION_WINDOW}": [
            {"id": 1000 + i, "version": {"ref": sha}, "enabled": True}
            for i, sha in enumerate(shas)
        ],
        f"{BASE}/jobs": jobs_payload if jobs_payload is not None else pipeline_jobs(),
    }
    for i, sha in enumerate(shas):
        when = started.get(sha)
        routes[f"{BASE}/resources/source/versions/{1000 + i}/input_to"] = (
            [{"name": "1", "job_name": "unit", "start_time": int(when.timestamp())}]
            if when else []
        )

    def fetch(path: str) -> Any:
        if fail and fail in path:
            raise ConnectionError("[Errno 111] Connection refused")
        return routes[path]

    return fetch


def decided(*shas: str, verdict: str = "go") -> gate_liveness.Lookup:
    def lookup(sha: str) -> dict[str, Any] | None:
        return {"recommendation": verdict, "human_override": None} if sha in shas else None

    return lookup


def sha(n: int) -> str:
    return f"{n:x}".rjust(40, "a")


def check(fetch: gate_liveness.Fetch, lookup: gate_liveness.Lookup,
          threshold: float = 6.0) -> gate_liveness.GateLivenessReport:
    return gate_liveness.check(fetch, lookup, threshold_hours=threshold, now=NOW)


class TestTheThreshold:
    def test_head_judged_is_live(self) -> None:
        report = check(fake_concourse([sha(3), sha(2)], {}), decided(sha(3)))

        assert report.verdict == "live"
        assert report.unjudged == []
        assert report.last_judged == sha(3)

    def test_under_the_threshold_is_live(self) -> None:
        shas = [sha(3), sha(2), sha(1)]
        report = check(
            fake_concourse(shas, {sha(2): NOW - timedelta(hours=5, minutes=59)}),
            decided(sha(1)),
        )

        assert report.verdict == "live"
        assert report.unjudged == [sha(3), sha(2)]

    def test_over_the_threshold_is_stale(self) -> None:
        shas = [sha(3), sha(2), sha(1)]
        report = check(
            fake_concourse(shas, {sha(2): NOW - timedelta(hours=6, minutes=1)}),
            decided(sha(1)),
        )

        assert report.verdict == "stale"
        assert report.waited_hours == pytest.approx(6.0167, abs=1e-3)

    def test_the_clock_is_the_oldest_unjudged_commit_not_the_head(self) -> None:
        """A head merged ten minutes ago must not reset a wait that began hours ago."""
        shas = [sha(4), sha(3), sha(2), sha(1)]
        report = check(
            fake_concourse(shas, {
                sha(4): NOW - timedelta(minutes=10),
                sha(3): NOW - timedelta(hours=3),
                sha(2): NOW - timedelta(hours=9),
            }),
            decided(sha(1)),
        )

        assert report.stale
        assert report.waiting_since == NOW - timedelta(hours=9)

    def test_the_threshold_is_configurable(self) -> None:
        shas = [sha(2), sha(1)]
        fetch = fake_concourse(shas, {sha(2): NOW - timedelta(hours=2)})

        assert not check(fetch, decided(sha(1)), threshold=6).stale
        assert check(fetch, decided(sha(1)), threshold=1).stale

    def test_no_decision_in_the_whole_window_is_stale_and_says_so(self) -> None:
        shas = [sha(3), sha(2), sha(1)]
        report = check(fake_concourse(shas, {sha(1): NOW - timedelta(days=7)}), decided())

        assert report.stale and report.window_exhausted
        assert "None of main's last 3 commits has a gate decision" in report.lines()[0]

    def test_an_override_is_the_verdict_named(self) -> None:
        def lookup(s: str) -> dict[str, Any] | None:
            if s != sha(1):
                return None
            return {"recommendation": "no_go",
                    "human_override": {"accepted_recommendation": "go"}}

        report = check(
            fake_concourse([sha(2), sha(1)], {sha(2): NOW - timedelta(hours=8)}), lookup
        )

        assert f"Newest judged commit: {sha(1)[:12]} (go (overridden from no_go))." in (
            report.lines()
        )


class TestTheRedLaneIsNamed:
    def _stale(self, jobs_payload: list[dict[str, Any]]) -> gate_liveness.GateLivenessReport:
        return check(
            fake_concourse([sha(2), sha(1)], {sha(2): NOW - timedelta(hours=8)},
                           jobs_payload=jobs_payload),
            decided(sha(1)),
        )

    def test_lint_and_types_red_is_named(self) -> None:
        """The 2026-10-05..12 case: one red lane upstream of every scan."""
        report = self._stale(pipeline_jobs(lint_and_types="failed"))

        assert [lane.job for lane in report.red_lanes] == ["lint-and-types"]
        body = "\n".join(report.lines())
        assert (
            "Upstream of oracle-gate, latest build not green: lint-and-types (failed, build 368)"
        ) in body

    def test_a_red_lane_two_hops_up_is_named(self) -> None:
        """containers <- publish-backend <- build <- unit: transitive, not just direct."""
        payload = pipeline_jobs()
        for job in payload:
            if job["name"] == "publish-backend":
                job["finished_build"]["status"] = "errored"

        assert [lane.line() for lane in self._stale(payload).red_lanes] == [
            "publish-backend (errored, build 368)"
        ]

    def test_a_paused_upstream_lane_is_named(self) -> None:
        payload = pipeline_jobs()
        for job in payload:
            if job["name"] == "sast":
                job["paused"] = True

        assert [(lane.job, lane.state) for lane in self._stale(payload).red_lanes] == [
            ("sast", "paused")
        ]

    def test_red_jobs_not_upstream_of_the_gate_are_not_named(self) -> None:
        """pin-check and promote are red in the fixture and are not in the way."""
        assert self._stale(pipeline_jobs()).red_lanes == []

    def test_none_red_says_so(self) -> None:
        report = self._stale(pipeline_jobs(oracle_gate="failed"))

        body = "\n".join(report.lines())
        assert "No job upstream of oracle-gate is failing, errored or paused" in body
        assert "oracle-gate itself last finished: failed" in body


class TestCouldNotCheckIsNeverLive:
    def test_unreachable_concourse_is_could_not_check(self) -> None:
        report = check(fake_concourse([sha(1)], {}, fail="/versions"), decided())

        assert report.verdict == "could not check"
        assert not report.stale

    def test_a_decision_store_that_throws_is_could_not_check_not_unjudged(self) -> None:
        def broken(_sha: str) -> dict[str, Any] | None:
            raise RuntimeError("lake locked")

        report = check(fake_concourse([sha(1)], {sha(1): NOW - timedelta(days=1)}), broken)

        assert report.verdict == "could not check"

    def test_stale_with_unreadable_jobs_does_not_claim_none_are_red(self) -> None:
        report = check(
            fake_concourse([sha(2), sha(1)], {sha(2): NOW - timedelta(hours=8)}, fail="/jobs"),
            decided(sha(1)),
        )

        assert report.stale and not report.complete
        body = "\n".join(report.lines())
        assert "not named" in body
        assert "No job upstream" not in body

    async def test_the_job_raises_and_does_not_notify(self) -> None:
        notifier = Recorder()

        with pytest.raises(jobs.GateLivenessIncompleteError, match="could not check"):
            await jobs.check_gate_liveness(
                "http://concourse.invalid:8080", decided(), threshold_hours=6,
                notifier=notifier, fetch=fake_concourse([sha(1)], {}, fail="/versions"),
                now=NOW,
            )

        assert notifier.sent == []

    async def test_the_real_fetch_against_a_closed_port_is_could_not_check(self) -> None:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            closed = probe.getsockname()[1]

        with pytest.raises(jobs.GateLivenessIncompleteError, match="could not check"):
            await jobs.check_gate_liveness(
                f"http://127.0.0.1:{closed}", decided(), threshold_hours=6
            )

    async def test_stale_notifies_before_the_incomplete_run_fails(self) -> None:
        notifier = Recorder()

        with pytest.raises(jobs.GateLivenessIncompleteError):
            await jobs.check_gate_liveness(
                "", decided(sha(1)), threshold_hours=6, notifier=notifier, now=NOW,
                fetch=fake_concourse([sha(2), sha(1)], {sha(2): NOW - timedelta(hours=8)},
                                     fail="/jobs"),
            )

        [note] = notifier.sent
        assert "not named" in note.detail

    async def test_the_failure_is_what_job_runs_records(self, settings: Settings) -> None:
        from mykronos.db import Database
        from mykronos.db.models import JobRun

        db = Database(settings.database_url)
        db.create_all()
        try:
            await jobs.check_gate_liveness(
                "", decided(), threshold_hours=6, now=NOW,
                fetch=fake_concourse([sha(1)], {}, fail="/versions"),
            )
        except jobs.GateLivenessIncompleteError as exc:
            main._record_run(db, "gate-liveness", 3_600, str(exc))

        try:
            with db.session() as session:
                row = session.get(JobRun, "gate-liveness")
                assert row is not None
                assert row.last_succeeded_at is None
                assert row.last_error.startswith("could not check")
        finally:
            db.close()


class TestTheNotification:
    def _fetch(self, **status: str) -> gate_liveness.Fetch:
        return fake_concourse(
            [sha(2), sha(1)], {sha(2): NOW - timedelta(hours=8)},
            jobs_payload=pipeline_jobs(**status),
        )

    async def test_stale_sends_one_warning_naming_the_lane(self) -> None:
        notifier = Recorder()

        report = await jobs.check_gate_liveness(
            "", decided(sha(1)), threshold_hours=6, notifier=notifier, now=NOW,
            fetch=self._fetch(lint_and_types="failed"),
        )

        [note] = notifier.sent
        assert note.level == "warning"
        assert "lint-and-types (failed" in note.detail
        assert report.verdict == "stale"

    async def test_the_same_news_is_not_reposted(self) -> None:
        notifier = Recorder()
        first = await jobs.check_gate_liveness(
            "", decided(sha(1)), threshold_hours=6, notifier=notifier, now=NOW,
            fetch=self._fetch(lint_and_types="failed"),
        )
        await jobs.check_gate_liveness(
            "", decided(sha(1)), threshold_hours=6, notifier=notifier,
            now=NOW + timedelta(hours=1), fetch=self._fetch(lint_and_types="failed"),
            already_sent=first.signature,
        )
        assert len(notifier.sent) == 1

        await jobs.check_gate_liveness(
            "", decided(sha(1)), threshold_hours=6, notifier=notifier,
            now=NOW + timedelta(hours=2), fetch=self._fetch(sast="failed"),
            already_sent=first.signature,
        )
        assert len(notifier.sent) == 2, "a different red lane is different news"

    async def test_live_is_quiet(self) -> None:
        notifier = Recorder()

        report = await jobs.check_gate_liveness(
            "", decided(sha(2)), threshold_hours=6, notifier=notifier, now=NOW,
            fetch=self._fetch(),
        )

        assert report.verdict == "live"
        assert notifier.sent == []


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

        async def fake_check(url: str, lookup: Any, **kwargs: Any) -> Any:
            calls.append((url, kwargs["threshold_hours"], kwargs["team"], kwargs["already_sent"]))
            return gate_liveness.GateLivenessReport(threshold_hours=6.0)

        monkeypatch.setattr(main, "check_gate_liveness", fake_check)
        scheduled = self._scheduled(settings, monkeypatch)

        interval, job = scheduled["gate-liveness"]
        assert interval == 3_600

        import asyncio

        asyncio.run(job())
        assert calls == [("http://concourse:8080", 6.0, "main", None)]

    def test_without_a_concourse_it_is_not_scheduled(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = settings.model_copy(update={
            "run_jobs_in_background": True, "concourse_url": "",
        })
        assert "gate-liveness" not in self._scheduled(settings, monkeypatch)
