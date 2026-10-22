"""Next-sprint candidates ranked and filed to TheHub's backlog (TheHub #60862).

The acceptance criteria: the ranking is explainable per item, filing makes no
duplicate stories, and the success metric is computed weekly. TheHub is
`FakeHub` behind `httpx2.MockTransport`; no real story is ever created.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx2
import pytest

from mykronos import (
    briefing,
    briefing_dm,
    briefing_sources,
    daily_briefing,
    delivery_sources,
    jobs,
    main,
    product_owner,
    sprint_signal,
)
from mykronos.briefing import ProductionLag, StalledLane
from mykronos.db.models import JobRun
from mykronos.delivery_sources import BoardRead
from mykronos.schemas import utcnow
from tests.conftest import REPO, finding_payload
from tests.po_support import FakeHub, attach_hub, story
from tests.test_daily_briefing import _everything_read, _get, _scan, _section
from tests.test_onboarding import onboard


@pytest.fixture(autouse=True)
def _fresh_cache() -> Any:
    delivery_sources.clear_cache()
    yield
    delivery_sources.clear_cache()


@pytest.fixture
def gathered(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    holder: dict[str, Any] = {"inputs": _everything_read()}
    monkeypatch.setattr(briefing_sources, "gather", lambda *_args: holder["inputs"])
    return holder


class FilingHub(FakeHub):
    """`FakeHub`, plus the story create the filing job makes."""

    def __init__(self, stories: list[dict[str, Any]], *, refuse: int = 0) -> None:
        super().__init__(stories)
        self.created: list[dict[str, Any]] = []
        #: How many creates to refuse first, with a 400 TheHub authored.
        self.refuse = refuse

    def handler(self, request: httpx2.Request) -> httpx2.Response:
        if request.method == "POST" and request.url.path == "/api/dev/stories":
            body = json.loads(request.content)
            self.calls.append(("POST", request.url.path, body))
            if self.refuse:
                self.refuse -= 1
                return httpx2.Response(400, json={"detail": "Invalid bucket: nope"})
            new = story(id=1000 + len(self.created), gate="intake", **{
                k: body[k] for k in ("title", "detail", "bucket", "tags", "source_ref")
            })
            self.stories[new["id"]] = new
            self.created.append(body)
            return httpx2.Response(200, json=new)
        return super().handler(request)


def _report(**overrides: Any) -> briefing.Briefing:
    values: dict[str, Any] = {"generated_at": utcnow(), "total_open": 0}
    values.update(overrides)
    return briefing.Briefing(**values)


def _lane(**overrides: Any) -> StalledLane:
    values: dict[str, Any] = {
        "repo_full_name": REPO, "capability": "sast", "reason": "failing",
        "consecutive_failures": 3, "streak_capped": False, "last_success": None,
        "detail": "", "open_findings": 1, "last_scan_run_id": "run-x",
    }
    values.update(overrides)
    return StalledLane(**values)


# ---------------------------------------------------------------------------
# The ranking
# ---------------------------------------------------------------------------


class TestRanking:
    def test_score_is_risk_times_exposure_over_effort_with_each_factor(
        self, client, admin_auth, auth, run_compaction, catalog
    ) -> None:
        onboard(client, admin_auth)
        _scan(client, auth, "run-1", [
            finding_payload(),
            finding_payload(rule_id="CWE-79", title="Reflected XSS", severity="medium",
                            file_path="web/view.py", line_start=3),
        ])
        run_compaction()
        report = _report(production_lag=[ProductionLag(repo_full_name=REPO, status="at_head")])

        ranked = sprint_signal.rank(catalog, report, [REPO])

        assert ranked, "two open findings rank as candidates"
        for c in ranked:
            assert c.score == round(c.risk_removed * c.exposure / c.effort, 2)
            assert c.exposure == sprint_signal.DEPLOYED
            assert "deployed" in c.exposure_basis
            assert c.effort_basis and c.risk_basis
            explained = c.explain()
            assert explained.startswith(f"Score {c.score:g} = risk removed")
            assert c.exposure_basis in explained and c.effort_basis in explained
        assert [c.score for c in ranked] == sorted((c.score for c in ranked), reverse=True)
        critical = next(c for c in ranked if "critical" in c.risk_basis)
        assert critical.risk_removed == sprint_signal.SEVERITY_WEIGHT["critical"]

    def test_signal_keys_are_stable_and_distinct(self) -> None:
        a = sprint_signal.signal_key(REPO, "fix", "upgrade:urllib3")
        assert a == sprint_signal.signal_key(REPO, "fix", "upgrade:urllib3")
        assert a != sprint_signal.signal_key(REPO, "fix", "upgrade:requests")
        assert a != sprint_signal.signal_key("o/other", "fix", "upgrade:urllib3")
        assert len(a) == 16

    @pytest.mark.parametrize(
        ("report", "factor"),
        [
            (_report(exposure=[{"repo_full_name": REPO, "url": "https://x"}]),
             sprint_signal.INTERNET),
            (_report(production_lag=[ProductionLag(repo_full_name=REPO, status="behind")]),
             sprint_signal.DEPLOYED),
            (_report(), sprint_signal.NOT_DEPLOYED),
            (None, sprint_signal.NOT_DEPLOYED),
        ],
    )
    def test_exposure(self, report: Any, factor: float) -> None:
        value, basis = sprint_signal.exposure_of(report, REPO)
        assert value == factor
        assert basis
        if report is None:
            assert basis.startswith("not measured")

    def test_a_lane_repair_removes_the_risk_it_holds(
        self, client, admin_auth, auth, run_compaction, catalog
    ) -> None:
        onboard(client, admin_auth)
        _scan(client, auth, "run-1", [finding_payload()])
        run_compaction()

        ranked = sprint_signal.rank(catalog, _report(stalled=[_lane()]), [REPO])

        lane = next(c for c in ranked if c.kind == "lane")
        assert lane.title.startswith("Repair the sast lane (failing)")
        assert lane.risk_basis == {"critical": 1}
        assert lane.effort == sprint_signal.LANE_REPAIR_EFFORT
        assert lane.ref == ""


class TestOnThePage:
    def test_overall_section_ranks_with_factors_and_feeds_the_focus(
        self, client, admin_auth, auth, run_compaction, gathered
    ) -> None:
        onboard(client, admin_auth)
        attach_hub(client, FilingHub([story(id=5, bucket="sprint")]))
        _scan(client, auth, "run-1", [finding_payload()])
        run_compaction()

        body = _get(client, admin_auth)

        section = _section(body, "next_sprint")
        assert section["status"] == "ok", section["reason"]
        assert section["lines"], "a candidate is on the page"
        for line, factors in zip(section["lines"], section["data"]["candidates"], strict=False):
            assert line["work"] == "story"
            assert line["so_what"].startswith("Score ")
            for name in ("risk_removed", "exposure", "effort", "score", "signal_key",
                         "risk_basis", "exposure_basis", "effort_basis"):
                assert name in factors
        assert section["data"]["formula"] == sprint_signal.FORMULA
        assert section["data"]["weights"]["severity"]["critical"] == 10.0
        metric = section["data"]["success_metric"]
        assert metric["weeks"][0]["current"] is True
        assert metric["weeks"][0]["sprint_stories"] == 1

        focus = _section(body, "suggested_focus")
        top = [line["what"] for line in section["lines"][: sprint_signal.FOCUS_TOP]]
        assert focus["data"]["next_sprint_top"] == top
        assert all(what in [line["what"] for line in focus["lines"]] for what in top)

    def test_without_thehub_it_still_ranks_and_says_what_it_could_not_do(
        self, client, admin_auth, auth, run_compaction, gathered
    ) -> None:
        onboard(client, admin_auth)
        _scan(client, auth, "run-1", [finding_payload()])
        run_compaction()

        section = _section(_get(client, admin_auth), "next_sprint")

        assert section["status"] == "partial"
        assert "TheHub is not connected" in section["reason"]
        assert "weekly briefing-signal share needs TheHub" in section["reason"]
        assert section["data"]["success_metric"] is None
        assert section["lines"]

    def test_unreadable_lake_is_unavailable(self, monkeypatch, catalog) -> None:
        def _broken(*_args: Any, **_kwargs: Any) -> Any:
            raise RuntimeError("io")

        monkeypatch.setattr(sprint_signal, "rank", _broken)
        section = daily_briefing.next_sprint_section(
            catalog, _Db(), None, now=utcnow(), as_of=None
        )
        assert section.status == "unavailable"
        assert "RuntimeError" in section.reason

    def test_a_filed_story_is_left_out_by_its_key(
        self, client, admin_auth, auth, run_compaction, catalog
    ) -> None:
        onboard(client, admin_auth)
        _scan(client, auth, "run-1", [finding_payload()])
        run_compaction()
        first = daily_briefing.next_sprint_candidates(
            catalog, None, REPO, as_of=None, board=BoardRead(stories={}, as_of=utcnow())
        )
        key = first.data["candidates"][0]["signal_key"]
        board = BoardRead(
            stories={"backlog": [story(id=77, title="Renamed by a person",
                                       tags=[sprint_signal.SIGNAL_TAG,
                                             sprint_signal.key_tag(key)])]},
            as_of=utcnow(),
        )

        again = daily_briefing.next_sprint_candidates(
            catalog, None, REPO, as_of=None, board=board
        )

        assert key not in [c["signal_key"] for c in again.data["candidates"]]
        assert again.data["already_on_board"][0]["story"] == "TheHub #77"


class _Db:
    """A database whose every session fails, for the unreadable case."""

    def session(self) -> Any:
        raise RuntimeError("db")


# ---------------------------------------------------------------------------
# The weekly success metric
# ---------------------------------------------------------------------------


class TestWeeklyMetric:
    def test_share_and_risk_removed_this_week_and_last(self) -> None:
        now = datetime(2026, 10, 21, 12, tzinfo=UTC)  # a Wednesday
        tagged = {"tags": [sprint_signal.SIGNAL_TAG]}
        board = BoardRead(
            stories={
                "sprint": [
                    story(id=1, bucket="sprint", **tagged),
                    story(id=2, bucket="sprint"),
                    story(id=3, bucket="sprint"),
                ],
                "done": [
                    story(id=4, bucket="done", closed_at="2026-10-20T09:00:00",
                          detail="MyKronos signal `0123456789abcdef`; risk removed 20.",
                          **tagged),
                    story(id=5, bucket="done", closed_at="2026-10-14T09:00:00",
                          detail="MyKronos signal `fedcba9876543210`; risk removed 7.5."),
                    story(id=6, bucket="done", closed_at="2026-10-15T09:00:00"),
                    story(id=7, bucket="done", closed_at="2026-10-01T09:00:00", **tagged),
                ],
            },
            as_of=now,
        )

        this_week, last_week = sprint_signal.weekly_metric(board, now=now)["weeks"]

        assert this_week["week_start"] == "2026-10-19"
        assert this_week["sprint_stories"] == 4
        assert this_week["briefing_signal_stories"] == 2
        assert this_week["share"] == 0.5
        assert this_week["risk_removed"] == 20.0
        # Story 5 carries a key in its detail: filed by the job, tag removed.
        assert last_week["week_start"] == "2026-10-12"
        assert last_week["sprint_stories"] == 2
        assert last_week["briefing_signal_stories"] == 1
        assert last_week["risk_removed"] == 7.5

    def test_an_empty_week_has_no_share(self) -> None:
        board = BoardRead(stories={}, as_of=utcnow())
        week = sprint_signal.weekly_metric(board, now=utcnow())["weeks"][0]
        assert week["share"] is None and week["sprint_stories"] == 0


# ---------------------------------------------------------------------------
# Filing
# ---------------------------------------------------------------------------


class TestFiling:
    @pytest.fixture
    def estate(self, client, admin_auth, auth, run_compaction, gathered) -> Any:
        onboard(client, admin_auth)
        _scan(client, auth, "run-1", [
            finding_payload(),
            finding_payload(rule_id="CWE-79", title="Reflected XSS", severity="high",
                            file_path="web/view.py", line_start=3),
        ])
        run_compaction()
        return client

    async def test_files_ranked_candidates_with_three_options(self, estate) -> None:
        hub = FilingHub([])
        attach_hub(estate, hub)

        result = await sprint_signal.file_signals(
            db=None, hub=estate.app.state.hub, read=briefing_dm.route_reader(estate.app)
        )

        assert result.filed and len(hub.created) == len(result.filed)
        assert len(hub.created) <= sprint_signal.FILE_LIMIT
        for body in hub.created:
            assert body["bucket"] == "backlog"
            assert sprint_signal.SIGNAL_TAG in body["tags"]
            assert any(t.startswith(sprint_signal.KEY_TAG_PREFIX) for t in body["tags"])
            assert body["source_ref"].startswith(sprint_signal.KEY_TAG_PREFIX)
            assert body["source_kind"] == sprint_signal.SOURCE_KIND
            assert body["acceptance_criteria"]
            detail = body["detail"]
            for option in ("1. **Pull it into the next sprint**",
                           "2. **Leave it in the backlog**", "3. **Accept the risk.**"):
                assert option in detail
            assert "**Recommendation:**" in detail
            assert "Score " in detail and "risk removed" in detail

    async def test_a_second_run_files_nothing_new(self, estate) -> None:
        hub = FilingHub([])
        attach_hub(estate, hub)
        read = briefing_dm.route_reader(estate.app)
        first = await sprint_signal.file_signals(db=None, hub=estate.app.state.hub, read=read)

        # The page's board read is cached and has not seen the new stories;
        # the job reads the board fresh and must not file them again.
        second = await sprint_signal.file_signals(db=None, hub=estate.app.state.hub, read=read)

        assert first.filed
        assert second.filed == []
        assert len(second.skipped) >= len(first.filed)
        assert len(hub.created) == len(first.filed)

    async def test_skips_what_b3s_matcher_says_is_a_story(self, estate, catalog) -> None:
        ranked = daily_briefing.next_sprint_candidates(
            catalog, None, REPO, as_of=None, board=BoardRead(stories={}, as_of=utcnow())
        )
        fix_refs = [c["ref"] for c in ranked.data["candidates"] if c["ref"]]
        assert fix_refs
        hub = FilingHub([
            story(id=40 + i, bucket="sprint", title="Somebody filed this by hand",
                  detail=f"Covers {ref}.", tags=[])
            for i, ref in enumerate(fix_refs)
        ])
        attach_hub(estate, hub)

        result = await sprint_signal.file_signals(
            db=None, hub=estate.app.state.hub, read=briefing_dm.route_reader(estate.app)
        )

        assert not any(body.get("source_ref", "").endswith(tuple(fix_refs))
                       for body in hub.created)
        for body in hub.created:
            assert all(ref not in body["detail"] for ref in fix_refs)
        assert result.filed == [] or all(f["title"].startswith("Repair") for f in result.filed)

    async def test_without_thehub_it_is_skipped_with_the_reason(self, estate) -> None:
        with pytest.raises(jobs.JobSkipped, match="TheHub is not connected"):
            await sprint_signal.file_signals(
                db=None, hub=None, read=briefing_dm.route_reader(estate.app)
            )

    async def test_once_a_day(self, estate) -> None:
        db = estate.app.state.db
        now = datetime.now(UTC)
        main._record_run(db, jobs.SIGNAL_FILING_JOB, 86_400, None)
        with pytest.raises(jobs.JobNotDue):
            await sprint_signal.file_signals(
                db=db, hub=None, read=briefing_dm.route_reader(estate.app), now=now
            )

    async def test_a_refusal_fails_the_run_after_trying_the_rest(self, estate) -> None:
        hub = FilingHub([], refuse=1)
        attach_hub(estate, hub)

        with pytest.raises(sprint_signal.SignalFilingError, match="Invalid bucket"):
            await sprint_signal.file_signals(
                db=None, hub=estate.app.state.hub, read=briefing_dm.route_reader(estate.app)
            )
        posts = [c for c in hub.calls if c[0] == "POST"]
        assert len(posts) == len(hub.created) + 1
        assert hub.created, "the next candidate was still filed"

    async def test_the_client_files_to_the_backlog_only(self) -> None:
        hub = FilingHub([])
        client = product_owner.HubClient(
            "http://hub.test", "hub-secret", transport=httpx2.MockTransport(hub.handler)
        )
        with pytest.raises(ValueError, match="backlog only"):
            await client.create_story({"title": "x", "bucket": "sprint"})
        assert hub.calls == []


class TestRecordedLikeEveryJob:
    def test_skipped_without_thehub_shows_in_health(self, client, gathered) -> None:
        db = client.app.state.db
        try:
            import asyncio

            asyncio.run(sprint_signal.file_signals(
                db=db, hub=None, read=briefing_dm.route_reader(client.app)
            ))
        except jobs.JobSkipped as skip:
            main._record_run(db, jobs.SIGNAL_FILING_JOB,
                             jobs.RECORDED_INTERVAL_SECONDS[jobs.SIGNAL_FILING_JOB],
                             None, skipped=str(skip))
        with db.session() as session:
            row = session.get(JobRun, jobs.SIGNAL_FILING_JOB)
            assert row is not None
            assert "TheHub is not connected" in row.skipped_reason
            assert row.interval_seconds == 86_400
            assert row.last_succeeded_at is None

    def test_it_is_scheduled_and_reads_the_route(self, settings, monkeypatch) -> None:
        import asyncio

        from fastapi.testclient import TestClient

        captured: dict[str, Any] = {}

        async def record(name: str, interval: int, job: Any, db: Any = None) -> None:
            captured[name] = (interval, job)

        calls: list[dict[str, Any]] = []

        async def fake_file(**kwargs: Any) -> None:
            calls.append(kwargs)

        monkeypatch.setattr(main, "_every", record)
        monkeypatch.setattr(sprint_signal, "file_signals", fake_file)
        with TestClient(main.create_app(settings.model_copy(
            update={"run_jobs_in_background": True}
        ))):
            pass

        interval, run = captured[jobs.SIGNAL_FILING_JOB]
        assert interval == sprint_signal.TICK_SECONDS
        asyncio.run(run())
        [call] = calls
        assert call["db"] is not None and callable(call["read"])


def test_week_starts_monday_utc() -> None:
    monday = sprint_signal._week_start(datetime(2026, 10, 25, 23, tzinfo=UTC))
    assert monday == datetime(2026, 10, 19)
    assert monday + timedelta(days=7) == datetime(2026, 10, 26)
