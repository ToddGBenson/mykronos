"""The 07:00 briefing DM (TheHub #60864).

Pinned here:

* **when** - due from the configured local time, in the configured zone, once
  per local day; a restart or another tick the same day sends nothing, and a
  deployment that was down at 07:00 sends when it comes back;
* **what** - the counts of merges, decisions and stories (each line once,
  suggested focus not double-counted), the top three focus lines, every
  section that could not be read named with its reason, one line per product
  (including one that could not be read), and the link to `/briefing` first;
* **not configured** - recorded `skipped` with the missing setting's name,
  never a success, and sent the same day once the setting arrives;
* **recorded like every job** - `_every` records nothing for a tick that is
  not due, `skipped` for a skip, a failure for an undelivered DM, and a day as
  the interval, so platform health can call a missed morning late.

No test sends anything to Slack: the notifier is a recorder throughout.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from mykronos import briefing_dm, briefing_sources, jobs, main, platform_health
from mykronos.api.briefing_daily import DailyBriefingOut
from mykronos.config import Settings
from mykronos.db import Database
from mykronos.db.models import JobRun
from mykronos.notify import Notification

#: 2026-10-21 in Phoenix (UTC-7, no DST): 07:00 local is 14:00 UTC.
SEVEN_LOCAL = datetime(2026, 10, 21, 14, 0, tzinfo=UTC)
PAGE = "https://mykronos.example/briefing"


class Recorder:
    """A notifier that keeps what it was given and sends nothing anywhere."""

    def __init__(self, *, delivers: bool = True) -> None:
        self.sent: list[Notification] = []
        self._delivers = delivers

    @property
    def enabled(self) -> bool:
        return True

    async def send(self, note: Notification) -> bool:
        self.sent.append(note)
        return self._delivers


def configured(settings: Settings, **overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "slack_bot_token": "xoxb-test-not-a-token",
        "briefing_dm_channel": "U0TODD",
        "dashboard_url": "https://mykronos.example/",
        "briefing_dm_time": "07:00",
        "briefing_dm_timezone": "America/Phoenix",
    }
    values.update(overrides)
    return settings.model_copy(update=values)


def line(what: str, work: str, *, so_what: str = "it matters", ref: str = "",
         repo: str = "") -> dict[str, Any]:
    return {"what": what, "so_what": so_what, "work": work, "repo_full_name": repo, "ref": ref}


def section(key: str, title: str, status: str = "ok", *, reason: str = "",
            lines: list[dict[str, Any]] | None = None,
            data: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "key": key, "title": title, "status": status, "source": "test",
        "as_of": "2026-10-21T13:00:00" if status != "unavailable" else None,
        "reason": reason, "lines": lines or [], "data": data or {},
    }


def overall_fixture() -> DailyBriefingOut:
    """The overall page as B2 serves it before B3: two board sections not
    built, the trust section unreadable, and work in the rest."""
    merge = line("Patchwork fix for lodash is approved", "merge",
                 so_what="Merging it closes 3 highs", ref="https://github.com/o/r/pull/7")
    decision = line("Acceptance RA-12 expires in 3 days", "decision",
                    so_what="Renew it or let it lapse", ref="/api/risk-acceptances/12")
    kev = line("CVE-2026-1111 introduced in o/thehub (sca)", "story",
               so_what="It is on CISA's KEV list", ref="f-1", repo="o/thehub")
    epss = line("CVE-2026-2222 introduced in o/thehub (sca)", "story",
                so_what="EPSS 40%", ref="f-2", repo="o/thehub")
    return DailyBriefingOut.model_validate({
        "generated_at": "2026-10-21T14:00:00",
        "scope": "overall",
        "repo_full_name": None,
        "sections": [
            section("needs_you_today", "Needs you today", "not_available",
                    reason="Reads TheHub's board and GitHub: B3 (TheHub #60861)."),
            section("production_truth", "Production truth", lines=[merge]),
            section("trust", "Can we trust our signals", "unavailable",
                    reason="The lake could not be read: catalog locked."),
            section("risk_delta", "Risk delta", lines=[kev, epss]),
            section("acceptances", "Acceptances", lines=[decision]),
            section("sprint_health", "Sprint health", "not_available",
                    reason="Reads TheHub's board: B3 (TheHub #60861)."),
            # Re-ranks the lines above, plus one duplicate: none of it is
            # counted twice.
            section("suggested_focus", "Suggested focus", "partial",
                    reason="Ranked without the board.",
                    lines=[decision, merge, kev, epss]),
        ],
    })


def product_fixture(repo: str, *, introduced: int, closed: int,
                    deploy_lines: list[dict[str, Any]] | None = None,
                    lanes_status: str = "ok") -> DailyBriefingOut:
    return DailyBriefingOut.model_validate({
        "generated_at": "2026-10-21T14:00:00",
        "scope": "product",
        "repo_full_name": repo,
        "sections": [
            section("deploy_and_health", "Deploy and health", lines=deploy_lines or []),
            section("findings_delta", "Findings delta",
                    data={"window_hours": 24, "introduced": {"total": introduced},
                          "closed": {"total": closed}},
                    lines=[line(f"{introduced} critical/high finding(s) introduced in {repo}.",
                                "story", repo=repo)] if introduced else []),
            section("capability_lanes", "Capability lanes", lanes_status,
                    reason="" if lanes_status == "ok" else "scan_runs unreadable"),
            section("next_sprint_candidates", "Next-sprint candidates"),
        ],
    })


def products_fixture() -> list[briefing_dm.ProductRead]:
    return [
        briefing_dm.ProductRead(
            "o/mykronos", product_fixture("o/mykronos", introduced=0, closed=4)
        ),
        briefing_dm.ProductRead(
            "o/thehub",
            product_fixture(
                "o/thehub", introduced=2, closed=1, lanes_status="unavailable",
                deploy_lines=[line("Production runs a3f9c1, 4 commits behind main", "merge")],
            ),
        ),
        briefing_dm.ProductRead("o/personal-soc", error="404: no repo"),
    ]


def sample_dm() -> str:
    note = briefing_dm.compose(
        overall_fixture(), products_fixture(), url=PAGE,
        local_now=SEVEN_LOCAL.astimezone(briefing_dm.schedule_from(configured(Settings())).zone),
    )
    return note.render()


# ---------------------------------------------------------------------------
# When
# ---------------------------------------------------------------------------


class TestSchedule:
    @pytest.fixture
    def schedule(self, settings: Settings) -> briefing_dm.Schedule:
        return briefing_dm.schedule_from(configured(settings))

    def test_it_is_read_in_the_configured_zone(self, schedule) -> None:
        # 07:00 in Phoenix is 14:00 UTC; 07:00 UTC is midnight there.
        assert not schedule.due(datetime(2026, 10, 21, 7, 0, tzinfo=UTC), None)
        assert not schedule.due(SEVEN_LOCAL - timedelta(minutes=1), None)
        assert schedule.due(SEVEN_LOCAL, None)

    def test_once_per_local_day(self, schedule) -> None:
        sent = SEVEN_LOCAL + timedelta(minutes=3)
        assert not schedule.due(SEVEN_LOCAL + timedelta(hours=5), sent)
        # 23:59 local is 06:59 UTC the next day: still the same local day.
        assert not schedule.due(datetime(2026, 10, 22, 6, 59, tzinfo=UTC), sent)
        assert schedule.due(SEVEN_LOCAL + timedelta(days=1), sent)

    def test_a_deployment_down_at_seven_sends_when_it_returns(self, schedule) -> None:
        yesterday = SEVEN_LOCAL - timedelta(days=1)
        assert schedule.due(SEVEN_LOCAL + timedelta(hours=4), yesterday)

    def test_the_time_is_configurable(self, settings: Settings) -> None:
        schedule = briefing_dm.schedule_from(
            configured(settings, briefing_dm_time="06:30", briefing_dm_timezone="UTC")
        )
        assert schedule.due(datetime(2026, 10, 21, 6, 30, tzinfo=UTC), None)
        assert not schedule.due(datetime(2026, 10, 21, 6, 29, tzinfo=UTC), None)

    def test_an_unknown_zone_fails_naming_the_setting(self, settings: Settings) -> None:
        with pytest.raises(ValueError, match="MYKRONOS_BRIEFING_DM_TIMEZONE"):
            briefing_dm.schedule_from(configured(settings, briefing_dm_timezone="Mars/Olympus"))

    def test_a_malformed_time_is_refused_by_the_setting(self) -> None:
        with pytest.raises(ValueError):
            Settings(briefing_dm_time="7am")


# ---------------------------------------------------------------------------
# What
# ---------------------------------------------------------------------------


class TestCompose:
    def test_the_link_comes_first(self) -> None:
        text = sample_dm()
        head, first, *_ = text.split("\n")
        assert "Morning briefing, Wed 21 Oct" in head
        assert first == f"<{PAGE}|Open the full briefing>"

    def test_counts_each_line_once_and_not_the_focus_list(self) -> None:
        counts = briefing_dm.work_counts(overall_fixture().sections)
        assert dict(counts) == {"merge": 1, "decision": 1, "story": 2}
        assert "\n*Needs you:* 1 merge, 1 decision, 2 stories.\n" in sample_dm()

    def test_the_top_three_focus_lines_in_order(self) -> None:
        text = sample_dm()
        assert "1. [decision] Acceptance RA-12 expires in 3 days - Renew it or let it lapse" in text
        assert "2. [merge] Patchwork fix for lodash is approved" in text
        assert "3. [story] CVE-2026-1111" in text
        focus = text.split("*Suggested focus:*")[1].split("*Not read:*")[0]
        assert "CVE-2026-2222" not in focus
        assert "4. " not in focus

    def test_every_unread_section_is_named_with_its_reason(self) -> None:
        text = sample_dm()
        rows = text.split("\n")
        not_read = "\n".join(rows[rows.index("*Not read:*") + 1:rows.index("*Products:*")])
        assert "Needs you today (not built yet: Reads TheHub's board and GitHub" in not_read
        assert "Can we trust our signals (unavailable: The lake could not be read" in not_read
        assert "Sprint health (not built yet:" in not_read
        # A partial section is on the page, with its reason; the DM names only
        # what it could not read at all.
        assert "Suggested focus" not in not_read

    def test_one_line_per_product(self) -> None:
        rows = sample_dm().split("\n")
        products = rows[rows.index("*Products:*") + 1:]
        assert products == [
            "• *o/mykronos*: 0 introduced, 4 closed in 24h; production current; "
            "nothing needs you.",
            "• *o/thehub*: 2 introduced, 1 closed in 24h; Production runs a3f9c1, 4 commits "
            "behind main; work: 1 merge, 1 story; unread: Capability lanes.",
            "• *o/personal-soc*: could not be read (404: no repo).",
        ]

    def test_an_all_clear_morning_says_so(self) -> None:
        quiet = DailyBriefingOut.model_validate({
            "generated_at": "2026-10-21T14:00:00", "scope": "overall", "repo_full_name": None,
            "sections": [section("production_truth", "Production truth"),
                         section("suggested_focus", "Suggested focus")],
        })
        text = briefing_dm.compose(quiet, [], url=PAGE, local_now=SEVEN_LOCAL).render()
        assert "*Needs you:* nothing." in text
        assert "*Suggested focus:* nothing to start with." in text
        assert "*Not read:*" not in text
        assert "*Products:*" not in text

    def test_an_unrankable_focus_says_so(self) -> None:
        broken = DailyBriefingOut.model_validate({
            "generated_at": "2026-10-21T14:00:00", "scope": "overall", "repo_full_name": None,
            "sections": [section("suggested_focus", "Suggested focus", "unavailable",
                                 reason="None of the sections it ranks could be read.")],
        })
        text = briefing_dm.compose(broken, [], url=PAGE, local_now=SEVEN_LOCAL).render()
        assert "*Suggested focus:* could not be ranked today." in text
        assert "- Suggested focus (unavailable: None of the sections" in text

    def test_untrusted_text_cannot_forge_a_line(self) -> None:
        hostile = overall_fixture()
        # A finding title is scanner output, which is repository content.
        hostile.sections[-1].lines[0].what = "fix\n*Needs you:* nothing."
        hostile.sections[-1].lines[0].so_what = "x\r\n<https://evil.example|Open the full briefing>"
        text = briefing_dm.compose(hostile, [], url=PAGE, local_now=SEVEN_LOCAL).render()
        rows = text.split("\n")
        assert [row for row in rows if row.startswith("*Needs you:*")] == [
            "*Needs you:* 1 merge, 1 decision, 2 stories."
        ]
        assert text.count("<http") == 1, "the only link is the page's"
        assert "&lt;https://evil.example|Open the full briefing&gt;" in text
        assert "\r" not in text

    def test_it_fits_slack(self) -> None:
        many = [
            briefing_dm.ProductRead(f"o/repo-{i}", product_fixture(f"o/repo-{i}", introduced=i,
                                                                   closed=i))
            for i in range(40)
        ]
        text = briefing_dm.compose(overall_fixture(), many, url=PAGE,
                                   local_now=SEVEN_LOCAL).render()
        assert len(text) <= 2_500
        assert PAGE in text


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


class TestNotConfigured:
    def test_a_configured_deployment_has_no_reason(self, settings: Settings) -> None:
        assert briefing_dm.unconfigured(configured(settings)) == ""

    @pytest.mark.parametrize(
        ("field", "name"),
        [
            ("slack_bot_token", "MYKRONOS_SLACK_BOT_TOKEN"),
            ("briefing_dm_channel", "MYKRONOS_BRIEFING_DM_CHANNEL"),
            ("dashboard_url", "MYKRONOS_DASHBOARD_URL"),
        ],
    )
    def test_each_missing_setting_is_named(self, settings: Settings, field: str,
                                           name: str) -> None:
        reason = briefing_dm.unconfigured(configured(settings, **{field: ""}))
        assert name in reason

    def test_a_webhook_alone_is_not_enough(self, settings: Settings) -> None:
        reason = briefing_dm.unconfigured(configured(
            settings, slack_bot_token="", slack_webhook_url="https://hooks.example/x"
        ))
        assert "webhook cannot DM a person" in reason

    def test_the_page_url_takes_the_base_with_or_without_a_slash(
        self, settings: Settings
    ) -> None:
        assert briefing_dm.page_url(configured(settings)) == PAGE
        assert briefing_dm.page_url(
            configured(settings, dashboard_url="https://mykronos.example")
        ) == PAGE


# ---------------------------------------------------------------------------
# The job
# ---------------------------------------------------------------------------


@pytest.fixture
def db(settings: Settings) -> Any:
    database = Database(settings.database_url)
    database.create_all()
    yield database
    database.close()


def reader(products: dict[str, DailyBriefingOut] | None = None) -> briefing_dm.BriefingReader:
    async def read(repo_id: str | None) -> DailyBriefingOut:
        if repo_id is None:
            return overall_fixture()
        if products is None or repo_id not in products:
            raise RuntimeError(f"no briefing for {repo_id}")
        return products[repo_id]

    return read


class TestSend:
    async def test_before_the_time_nothing_is_due(self, settings, db) -> None:
        notifier = Recorder()
        with pytest.raises(jobs.JobNotDue):
            await briefing_dm.send_briefing_dm(
                configured(settings), db=db, read=reader(), notifier=notifier,
                now=SEVEN_LOCAL - timedelta(minutes=5),
            )
        assert notifier.sent == []

    async def test_due_and_configured_sends_once(self, settings, db) -> None:
        notifier = Recorder()
        note = await briefing_dm.send_briefing_dm(
            configured(settings), db=db, read=reader(), notifier=notifier, now=SEVEN_LOCAL,
        )
        assert notifier.sent == [note]
        assert PAGE in note.render()

    async def test_not_configured_is_skipped_never_sent(self, settings, db) -> None:
        notifier = Recorder()
        with pytest.raises(jobs.JobSkipped, match="MYKRONOS_BRIEFING_DM_CHANNEL"):
            await briefing_dm.send_briefing_dm(
                configured(settings, briefing_dm_channel=""), db=db, read=reader(),
                notifier=notifier, now=SEVEN_LOCAL,
            )
        assert notifier.sent == []

    async def test_an_undelivered_dm_fails(self, settings, db) -> None:
        with pytest.raises(briefing_dm.BriefingDmUndeliveredError):
            await briefing_dm.send_briefing_dm(
                configured(settings), db=db, read=reader(),
                notifier=Recorder(delivers=False), now=SEVEN_LOCAL,
            )

    async def test_an_unreadable_product_is_a_line_not_a_lost_dm(
        self, settings, db, client, admin_auth
    ) -> None:
        from tests.test_onboarding import onboard

        repo_id = onboard(client, admin_auth).json()["id"]
        notifier = Recorder()
        await briefing_dm.send_briefing_dm(
            configured(settings), db=client.app.state.db, read=reader({}),
            notifier=notifier, now=SEVEN_LOCAL,
        )
        [note] = notifier.sent
        assert f"no briefing for {repo_id}" in note.render()

    async def test_the_default_notifier_posts_as_the_bot_to_the_dm_target(
        self, settings, db, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        built: list[dict[str, Any]] = []

        class FakeSlack(Recorder):
            def __init__(self, **kwargs: Any) -> None:
                super().__init__()
                built.append(kwargs)

        monkeypatch.setattr(briefing_dm, "SlackNotifier", FakeSlack)
        await briefing_dm.send_briefing_dm(
            configured(settings), db=db, read=reader(), now=SEVEN_LOCAL
        )
        assert built == [{"bot_token": "xoxb-test-not-a-token", "channel": "U0TODD"}]


class TestRecordedLikeEveryJob:
    """What `_every` writes to `job_runs` around the job."""

    async def tick(self, settings: Settings, db: Database, notifier: Recorder,
                   now: datetime) -> None:
        """`_every`'s handling of one run, without its sleeps."""
        recorded = jobs.RECORDED_INTERVAL_SECONDS[jobs.BRIEFING_DM_JOB]
        try:
            await briefing_dm.send_briefing_dm(
                settings, db=db, read=reader(), notifier=notifier, now=now
            )
        except jobs.JobNotDue:
            pass
        except jobs.JobSkipped as skip:
            main._record_run(db, jobs.BRIEFING_DM_JOB, recorded, None, skipped=str(skip))
        except Exception as exc:  # noqa: BLE001
            main._record_run(db, jobs.BRIEFING_DM_JOB, recorded, str(exc))
        else:
            main._record_run(db, jobs.BRIEFING_DM_JOB, recorded, None)

    @pytest.fixture
    def clock(self, monkeypatch: pytest.MonkeyPatch) -> dict[str, datetime]:
        clock = {"now": SEVEN_LOCAL}
        monkeypatch.setattr(main, "utcnow", lambda: clock["now"].astimezone(UTC).replace(
            tzinfo=None))
        return clock

    def row(self, db: Database) -> JobRun | None:
        with db.session() as session:
            return session.get(JobRun, jobs.BRIEFING_DM_JOB)

    async def test_ticks_and_a_restart_send_once_a_day(self, settings, db, clock) -> None:
        settings = configured(settings)
        notifier = Recorder()
        start = SEVEN_LOCAL - timedelta(hours=2)
        # Every five minutes from 05:00 to 23:55 local, with a restart's boot
        # run at 09:00 in the middle of it.
        ticks = [start + timedelta(minutes=5 * i) for i in range(228)]
        ticks.insert(48, SEVEN_LOCAL + timedelta(hours=2))
        for moment in ticks:
            clock["now"] = moment
            await self.tick(settings, db, notifier, moment)
            if moment < SEVEN_LOCAL:
                assert self.row(db) is None, "a tick that is not due records nothing"
        assert len(notifier.sent) == 1

        clock["now"] = SEVEN_LOCAL + timedelta(days=1)
        await self.tick(settings, db, notifier, clock["now"])
        assert len(notifier.sent) == 2, "the next local day sends again"

        row = self.row(db)
        assert row is not None and row.interval_seconds == 86_400

    async def test_skipped_reads_skipped_then_sends_once_configured(
        self, settings, db, clock
    ) -> None:
        notifier = Recorder()
        await self.tick(configured(settings, slack_bot_token=""), db, notifier, SEVEN_LOCAL)

        row = self.row(db)
        assert row is not None
        health = platform_health.assess_job(row, now=SEVEN_LOCAL.replace(tzinfo=None))
        assert health.status == "skipped"
        assert "MYKRONOS_SLACK_BOT_TOKEN" in health.detail
        assert row.last_succeeded_at is None and row.consecutive_failures == 0

        later = SEVEN_LOCAL + timedelta(hours=3)
        clock["now"] = later
        await self.tick(configured(settings), db, notifier, later)
        assert len(notifier.sent) == 1
        row = self.row(db)
        assert row is not None and row.skipped_reason == ""
        assert platform_health.assess_job(row, now=later.replace(tzinfo=None)).status == "ok"

    async def test_a_failed_send_reads_failing_and_retries_the_same_day(
        self, settings, db, clock
    ) -> None:
        settings = configured(settings)
        await self.tick(settings, db, Recorder(delivers=False), SEVEN_LOCAL)
        row = self.row(db)
        assert row is not None
        assert platform_health.assess_job(
            row, now=SEVEN_LOCAL.replace(tzinfo=None)
        ).status == "failing"

        working = Recorder()
        clock["now"] = SEVEN_LOCAL + timedelta(minutes=5)
        await self.tick(settings, db, working, clock["now"])
        assert len(working.sent) == 1

    async def test_a_missed_morning_reads_late(self, settings, db, clock) -> None:
        await self.tick(configured(settings), db, Recorder(), SEVEN_LOCAL)
        row = self.row(db)
        assert row is not None
        three_days = (SEVEN_LOCAL + timedelta(days=3)).replace(tzinfo=None)
        assert platform_health.assess_job(row, now=three_days).status == "late"


class TestTheRealRunner:
    """`main._every` itself, for one tick of each outcome."""

    async def one_tick(self, db: Database, run: Any, monkeypatch: pytest.MonkeyPatch,
                       name: str = jobs.BRIEFING_DM_JOB) -> None:
        monkeypatch.setattr(main, "_STARTUP_SPREAD_SECONDS", 0.0)
        ran = asyncio.Event()

        async def wrapped() -> None:
            try:
                await run()
            finally:
                ran.set()

        task = asyncio.create_task(main._every(name, 3_600, wrapped, db))
        await asyncio.wait_for(ran.wait(), 5)
        await asyncio.sleep(0.05)  # let `_every` record before it sleeps
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    async def test_not_due_records_nothing(self, db, monkeypatch) -> None:
        async def run() -> None:
            raise jobs.JobNotDue

        await self.one_tick(db, run, monkeypatch)
        with db.session() as session:
            assert session.get(JobRun, jobs.BRIEFING_DM_JOB) is None

    async def test_skipped_records_the_reason_and_the_day(self, db, monkeypatch) -> None:
        async def run() -> None:
            raise jobs.JobSkipped("MYKRONOS_BRIEFING_DM_CHANNEL not set.")

        await self.one_tick(db, run, monkeypatch)
        with db.session() as session:
            row = session.get(JobRun, jobs.BRIEFING_DM_JOB)
            assert row is not None
            assert row.skipped_reason == "MYKRONOS_BRIEFING_DM_CHANNEL not set."
            assert row.interval_seconds == 86_400
            assert row.last_succeeded_at is None

    async def test_other_jobs_record_their_tick(self, db, monkeypatch) -> None:
        async def run() -> None:
            return None

        await self.one_tick(db, run, monkeypatch, name="absences")
        with db.session() as session:
            row = session.get(JobRun, "absences")
            assert row is not None and row.interval_seconds == 3_600


class TestItIsScheduled:
    def test_it_ticks_every_five_minutes_and_reads_the_route(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from fastapi.testclient import TestClient

        captured: dict[str, Any] = {}

        async def record(name: str, interval: int, job: Any, db: Any = None) -> None:
            captured[name] = (interval, job)

        calls: list[dict[str, Any]] = []

        async def fake_send(settings_: Settings, **kwargs: Any) -> None:
            calls.append(kwargs)

        monkeypatch.setattr(main, "_every", record)
        monkeypatch.setattr(briefing_dm, "send_briefing_dm", fake_send)
        with TestClient(main.create_app(settings.model_copy(
            update={"run_jobs_in_background": True}
        ))):
            pass

        interval, run = captured[jobs.BRIEFING_DM_JOB]
        assert interval == briefing_dm.TICK_SECONDS == 300
        asyncio.run(run())
        [call] = calls
        assert call["db"] is not None and callable(call["read"])


class TestThroughTheRoute:
    """The DM reads the page's own route, so B3's sections reach it unchanged."""

    @pytest.fixture
    def gathered(self, monkeypatch: pytest.MonkeyPatch) -> None:
        inputs = briefing_sources.OperationalInputs(
            paused_jobs=[], failing_jobs=[], blocked_jobs=[], workflow_blocked_jobs=[],
            unhealthy_jobs=[], tokens=[], toxic_combinations=[], toxic_coverage={},
            exposure=[], production_lag=[],
        )
        monkeypatch.setattr(briefing_sources, "gather", lambda *_args: inputs)

    async def test_the_overall_and_each_product(self, client, admin_auth, settings,
                                                gathered) -> None:
        from tests.conftest import REPO
        from tests.test_onboarding import onboard

        onboard(client, admin_auth)
        read = briefing_dm.route_reader(client.app)
        overall = await read(None)
        page = client.get("/api/briefing/daily", headers=admin_auth).json()
        assert [s.key for s in overall.sections] == [s["key"] for s in page["sections"]]

        notifier = Recorder()
        await briefing_dm.send_briefing_dm(
            configured(settings), db=client.app.state.db, read=read, notifier=notifier,
            now=SEVEN_LOCAL,
        )
        [note] = notifier.sent
        text = note.render()
        assert f"• *{REPO}*:" in text
        # Whatever the route says it could not read, the DM names.
        for unread_section in overall.sections:
            if unread_section.status in ("unavailable", "not_available"):
                assert f"{unread_section.title} (" in text
