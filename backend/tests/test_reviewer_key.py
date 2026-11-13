"""The platform reviewer's model key is probed hourly (TheHub #61614).

On the night of 2026-11-13 every independent-review start answered 503 with a
401 from the model API for over an hour, and nothing alerted. These tests pin
what the probe records for ok / 401 / timeout, that the alert is sent once per
state and the recovery once, that the pending list and the 503 say so, and
that the stored row carries no part of the key.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import anthropic
import httpx2
import pytest
from fastapi.testclient import TestClient

from mykronos import platform_health, reviewer_key
from mykronos.config import Settings
from mykronos.db import Database
from mykronos.db.models import ReviewerKeyProbe
from mykronos.jobs import JobSkipped
from mykronos.notify import Notification
from tests.test_reviewer import (  # noqa: F401 - fixtures and helpers
    FakeAnthropic,
    _delegate,
    _mint,
    _request,
    _review,
    model,
    tiered,
)

SECRET = "sk-ant-test-secret-value"
NOW = datetime(2026, 11, 13, 4, 0, tzinfo=UTC)
URL = "https://api.anthropic.com/v1/models"


def _status_error(status: int) -> anthropic.APIStatusError:
    response = httpx2.Response(status, request=httpx2.Request("GET", URL))
    cls = {401: anthropic.AuthenticationError, 403: anthropic.PermissionDeniedError}.get(
        status, anthropic.InternalServerError
    )
    return cls(f"status {status}", response=response, body=None)


class FakeModels:
    def __init__(self, error: Exception | None) -> None:
        self.error = error
        self.calls: list[dict[str, Any]] = []

    def list(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return SimpleNamespace(data=[])


def api(error: Exception | None = None) -> Any:
    return SimpleNamespace(models=FakeModels(error))


def timeout() -> Exception:
    return anthropic.APITimeoutError(request=httpx2.Request("GET", URL))


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


@pytest.fixture
def db(settings: Settings) -> Any:
    database = Database(settings.database_url)
    database.create_all()
    yield database
    database.close()


@pytest.fixture
def configured() -> Any:
    return SimpleNamespace(
        reviewer_api_key=SECRET, reviewer_mode="live", reviewer_model="claude-opus-5-5"
    )


async def probe(
    db: Database, configured: Any, notifier: Recorder, error: Exception | None, minutes: int = 0
) -> reviewer_key.ProbeResult:
    return await reviewer_key.probe_reviewer_key(
        db,
        configured,
        notifier=notifier,
        client=api(error),
        now=NOW + timedelta(minutes=minutes),
    )


class TestWhatTheProbeRecords:
    async def test_a_working_key_is_ok(self, db: Database, configured: Any) -> None:
        notifier = Recorder()
        result = await probe(db, configured, notifier, None)
        row = reviewer_key.current(db)
        assert (result.state, row.state, row.http_status, row.model) == (
            "ok", "ok", 200, "claude-opus-5-5",
        )
        assert notifier.sent == []

    @pytest.mark.parametrize("status", [401, 403])
    async def test_a_refused_key_is_refused(
        self, db: Database, configured: Any, status: int
    ) -> None:
        await probe(db, configured, Recorder(), _status_error(status))
        row = reviewer_key.current(db)
        assert (row.state, row.http_status) == ("refused", status)

    async def test_a_timeout_is_unreachable(self, db: Database, configured: Any) -> None:
        await probe(db, configured, Recorder(), timeout())
        row = reviewer_key.current(db)
        assert (row.state, row.http_status) == ("unreachable", None)

    async def test_a_server_error_is_unreachable_not_refused(
        self, db: Database, configured: Any
    ) -> None:
        await probe(db, configured, Recorder(), _status_error(503))
        assert reviewer_key.current(db).state == "unreachable"

    async def test_the_row_holds_no_part_of_the_key(self, db: Database, configured: Any) -> None:
        await probe(db, configured, Recorder(), _status_error(401))
        row = reviewer_key.current(db)
        stored = " ".join(str(getattr(row, c.name)) for c in ReviewerKeyProbe.__table__.columns)
        assert SECRET not in stored and SECRET[:6] not in stored
        health = platform_health.assess_reviewer_key(row)
        assert SECRET not in health.detail and SECRET[:6] not in health.detail

    async def test_it_needs_a_key_and_a_reviewer(
        self, db: Database, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # No key in the environment, so this can never reach the real API.
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        with pytest.raises(JobSkipped):
            await reviewer_key.probe_reviewer_key(
                db,
                SimpleNamespace(reviewer_api_key="", reviewer_mode="live", reviewer_model=""),
                notifier=Recorder(),
                client=None,
            )
        assert reviewer_key.current(db).state == "off"
        with pytest.raises(JobSkipped):
            await reviewer_key.probe_reviewer_key(
                db,
                SimpleNamespace(reviewer_api_key=SECRET, reviewer_mode="off", reviewer_model=""),
                notifier=Recorder(),
                client=api(),
            )


class TestHealthRow:
    async def test_the_row_carries_state_and_as_of(self, db: Database, configured: Any) -> None:
        await probe(db, configured, Recorder(), _status_error(401))
        row = platform_health.assess_reviewer_key(reviewer_key.current(db))
        assert row.name == "platform reviewer key"
        assert row.reachable is False
        assert row.detail == "refused (HTTP 401) as of 2026-11-13 04:00Z"

    async def test_ok_reads_reachable(self, db: Database, configured: Any) -> None:
        await probe(db, configured, Recorder(), None)
        row = platform_health.assess_reviewer_key(reviewer_key.current(db))
        assert row.reachable and row.detail.startswith("ok")

    def test_before_the_first_probe_the_row_is_not_configured(self) -> None:
        row = platform_health.assess_reviewer_key(None)
        assert row.configured is False

    def test_the_page_lists_it(self, client: TestClient, admin_auth: dict[str, str]) -> None:
        names = [
            d["name"]
            for d in client.get("/api/dashboard/platform-health", headers=admin_auth).json()[
                "dependencies"
            ]
        ]
        assert "platform reviewer key" in names


class TestOneAlertPerState:
    async def test_a_refusal_alerts_once_however_long_it_lasts(
        self, db: Database, configured: Any
    ) -> None:
        notifier = Recorder()
        for hour in range(3):
            await probe(db, configured, notifier, _status_error(401), minutes=60 * hour)
        assert len(notifier.sent) == 1
        note = notifier.sent[0]
        assert note.level == "critical"
        assert "refused (HTTP 401) since 2026-11-13 04:00Z" in note.render()
        assert SECRET not in note.render()

    async def test_recovery_is_announced_once(self, db: Database, configured: Any) -> None:
        notifier = Recorder()
        await probe(db, configured, notifier, timeout())
        await probe(db, configured, notifier, None, minutes=60)
        await probe(db, configured, notifier, None, minutes=120)
        assert [n.title for n in notifier.sent] == [
            "The platform reviewer's model key is not working",
            "The platform reviewer's model key works again",
        ]

    async def test_a_key_that_was_always_ok_never_speaks(
        self, db: Database, configured: Any
    ) -> None:
        notifier = Recorder()
        for hour in range(3):
            await probe(db, configured, notifier, None, minutes=60 * hour)
        assert notifier.sent == []

    async def test_an_undelivered_alert_is_retried(self, db: Database, configured: Any) -> None:
        refusing = Recorder(delivers=False)
        with pytest.raises(reviewer_key.ReviewerKeyProbeIncompleteError):
            await probe(db, configured, refusing, _status_error(401))
        delivering = Recorder()
        await probe(db, configured, delivering, _status_error(401), minutes=60)
        assert len(delivering.sent) == 1
        # And the way back says so, because the refusal was in the end announced.
        await probe(db, configured, delivering, None, minutes=120)
        assert len(delivering.sent) == 2

    async def test_a_refusal_with_no_slack_is_skipped_not_green(
        self, db: Database, configured: Any
    ) -> None:
        with pytest.raises(JobSkipped):
            await probe(db, configured, Recorder(enabled=False), _status_error(401))
        assert reviewer_key.current(db).state == "refused"


class TestApprovalsSurface:
    def _record(
        self,
        client: TestClient,
        state: str,
        status: int | None,
        as_of: datetime | None = None,
    ) -> None:
        # Fresh by default: a row older than two probe intervals is ignored.
        as_of = as_of or datetime.now(UTC).replace(tzinfo=None)
        with client.app.state.db.session() as session:
            session.add(
                ReviewerKeyProbe(
                    id=1,
                    state=state,
                    as_of=as_of,
                    since=datetime(2026, 11, 13, 3, 48),
                    model="claude-opus-5-5",
                    http_status=status,
                )
            )

    def test_pending_items_say_the_reviewer_is_unavailable(
        self, client, admin_auth, tiered  # noqa: F811
    ) -> None:
        author = _mint(client, admin_auth)
        _request(client, {"Authorization": f"Bearer {author['token']}"})
        self._record(client, "refused", 401)

        items = client.get("/api/approvals?state=pending", headers=admin_auth).json()

        assert items and all(i["reviewer_available"] is False for i in items)
        assert items[0]["reviewer_unavailable_since"].startswith("2026-11-13T03:48")

    def test_pending_items_are_available_when_ok_or_unprobed(
        self, client, admin_auth, tiered  # noqa: F811
    ) -> None:
        author = _mint(client, admin_auth)
        _request(client, {"Authorization": f"Bearer {author['token']}"})
        items = client.get("/api/approvals?state=pending", headers=admin_auth).json()
        assert items[0]["reviewer_available"] is True
        self._record(client, "ok", 200)
        items = client.get("/api/approvals?state=pending", headers=admin_auth).json()
        assert items[0]["reviewer_available"] is True
        assert items[0]["reviewer_unavailable_since"] is None

    def test_a_skipped_probe_replaces_a_stale_refusal_with_off(
        self, client, admin_auth, tiered  # noqa: F811
    ) -> None:
        author = _mint(client, admin_auth)
        _request(client, {"Authorization": f"Bearer {author['token']}"})
        self._record(client, "refused", 401)
        db = client.app.state.db
        assert client.get("/api/approvals?state=pending", headers=admin_auth).json()[0][
            "reviewer_available"
        ] is False

        with pytest.raises(JobSkipped):
            asyncio.run(
                reviewer_key.probe_reviewer_key(
                    db,
                    SimpleNamespace(
                        reviewer_api_key=SECRET, reviewer_mode="off", reviewer_model=""
                    ),
                    notifier=Recorder(),
                )
            )

        assert reviewer_key.current(db).state == "off"
        items = client.get("/api/approvals?state=pending", headers=admin_auth).json()
        assert items[0]["reviewer_available"] is None
        assert items[0]["reviewer_unavailable_since"] is None
        queue = client.get(
            "/api/dashboard/product-owner/review-queue", headers=admin_auth
        ).json()
        assert queue["reviewer"]["unavailable_since"] is None
        health = client.get("/api/dashboard/platform-health", headers=admin_auth).json()
        row = next(d for d in health["dependencies"] if d["name"] == "platform reviewer key")
        assert row["detail"].startswith("off")

    def test_a_row_older_than_two_intervals_is_ignored(
        self, client, admin_auth, tiered, model  # noqa: F811
    ) -> None:
        _delegate(client)
        model(error=_status_error(401))
        author = _mint(client, admin_auth)
        request = _request(client, {"Authorization": f"Bearer {author['token']}"})
        stale = datetime.now(UTC).replace(tzinfo=None) - timedelta(seconds=2 * 3600 + 60)
        self._record(client, "refused", 401, as_of=stale)

        items = client.get("/api/approvals?state=pending", headers=admin_auth).json()
        assert items[0]["reviewer_available"] is True
        assert items[0]["reviewer_unavailable_since"] is None
        queue = client.get(
            "/api/dashboard/product-owner/review-queue", headers=admin_auth
        ).json()
        assert queue["reviewer"]["unavailable_since"] is None
        response = _review(client, {"Authorization": f"Bearer {author['token']}"}, request)
        assert response.status_code == 503
        assert "hourly probe" not in response.text

    def test_the_review_queue_carries_the_banner_time(
        self, client, admin_auth, tiered  # noqa: F811
    ) -> None:
        self._record(client, "unreachable", None)
        queue = client.get(
            "/api/dashboard/product-owner/review-queue", headers=admin_auth
        ).json()
        assert queue["reviewer"]["unavailable_since"] == "2026-11-13 03:48Z"

    def test_the_503_names_the_probe(
        self, client, admin_auth, tiered, model  # noqa: F811
    ) -> None:
        _delegate(client)
        model(error=_status_error(401))
        author = _mint(client, admin_auth)
        request = _request(client, {"Authorization": f"Bearer {author['token']}"})
        self._record(client, "refused", 401)

        response = _review(client, {"Authorization": f"Bearer {author['token']}"}, request)

        assert response.status_code == 503
        assert "the hourly probe has reported refused since 2026-11-13 03:48Z" in response.text

    def test_the_503_stays_plain_when_the_probe_is_ok(
        self, client, admin_auth, tiered, model  # noqa: F811
    ) -> None:
        _delegate(client)
        model(error=_status_error(401))
        author = _mint(client, admin_auth)
        request = _request(client, {"Authorization": f"Bearer {author['token']}"})

        response = _review(client, {"Authorization": f"Bearer {author['token']}"}, request)

        assert response.status_code == 503
        assert "hourly probe" not in response.text


def test_the_job_is_scheduled_hourly(settings: Settings) -> None:
    assert settings.reviewer_key_probe_interval_seconds == 3600
    assert Path(reviewer_key.__file__).exists()


def test_main_registers_the_probe_job(
    monkeypatch: pytest.MonkeyPatch, settings: Settings
) -> None:
    import mykronos.main as main

    names: list[str] = []

    def record(name: str, interval: int, run: Any, db: Any = None) -> Any:
        names.append(name)

        async def _idle() -> None:
            return None

        return _idle()

    monkeypatch.setattr(main, "_every", record)
    with TestClient(main.create_app(settings.model_copy(update={"run_jobs_in_background": True}))):
        pass
    assert reviewer_key.REVIEWER_KEY_JOB in names
