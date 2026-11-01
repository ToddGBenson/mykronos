"""An incident a day before a credential lapses unrenewed (TheHub #61104).

The calendar (`GET /api/credentials/expiring`) says what lapses soon; this job
turns "nobody renewed it" into a Hub incident 24 hours ahead. TheHub is a
`httpx2.MockTransport` here: no real incident is ever opened. Every test runs
on a fixed clock (`NOW`), never the real date (#1034).
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta
from typing import Any

import httpx2
import pytest

from mykronos import credential_expiry_incidents as cei
from mykronos import jobs, main, product_owner
from mykronos.auth import TokenRegistry, hash_token
from mykronos.db.models import AgentCredential, IngestionToken

NOW = datetime(2026, 11, 1, 12, 0, 0)
REPO = "example-org/payments-api"


class FakeHub:
    """Answers the two incident writes the job makes, and records them."""

    def __init__(self, *, refuse: int = 0) -> None:
        self.calls: list[tuple[str, str, dict[str, Any], str]] = []
        self.refuse = refuse

    def handler(self, request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content) if request.content else {}
        self.calls.append(
            (request.method, request.url.path, body, request.headers.get("X-Hub-Token", ""))
        )
        if request.method == "POST" and request.url.path == "/api/incidents":
            if self.refuse:
                self.refuse -= 1
                return httpx2.Response(400, json={"detail": "invalid room 'nope'"})
            return httpx2.Response(200, json={"id": 700 + len(self.opened) - 1, **body})
        if request.method == "POST" and request.url.path.endswith("/comment"):
            return httpx2.Response(200, json={"id": 1, "text": body.get("text")})
        return httpx2.Response(404, json={"detail": "not found"})

    @property
    def opened(self) -> list[dict[str, Any]]:
        return [c[2] for c in self.calls if c[:2] == ("POST", "/api/incidents")]

    @property
    def comments(self) -> list[tuple[str, dict[str, Any]]]:
        return [(c[1], c[2]) for c in self.calls if c[1].endswith("/comment")]


def _hub(fake: FakeHub) -> product_owner.HubClient:
    return product_owner.HubClient(
        "http://hub.test", "hub-secret", transport=httpx2.MockTransport(fake.handler)
    )


def _agent(
    session,
    *,
    actor: str = "agent:test:root",
    expires: datetime,
    lineage: list[str] | None = None,
    revoked: bool = False,
    purpose: str = "",
    on_behalf_of: str = "the-operator",
) -> str:
    plaintext = f"mka_{actor}_{expires.isoformat()}"
    row = AgentCredential(
        token_sha256=hash_token(plaintext),
        actor=actor,
        on_behalf_of=on_behalf_of,
        expires_at=expires,
        lineage=lineage or [],
        purpose=purpose,
    )
    if revoked:
        row.revoked_at = NOW
    session.add(row)
    session.flush()
    return plaintext


@pytest.fixture
def app(client):
    client.app.state.clock = lambda: NOW
    return client.app


async def _run(app, fake: FakeHub | None) -> cei.IncidentResult:
    return await cei.raise_incidents(
        db=app.state.db,
        hub=_hub(fake) if fake is not None else None,
        read=cei.route_reader(app),
        now=NOW,
    )


class TestADayAhead:
    async def test_a_credential_a_day_from_lapsing_opens_one_incident(self, app) -> None:
        with app.state.db.session() as session:
            _agent(session, expires=NOW + timedelta(hours=20))
        fake = FakeHub()
        result = await _run(app, fake)

        [incident] = fake.opened
        assert result.opened == [incident["title"].split(": ", 1)[1]]
        assert incident["room"] == "devops"
        assert incident["severity"] == "error"
        assert incident["source_capability"] == cei.SOURCE_CAPABILITY
        assert incident["source_ref"].startswith("credential-expiry:agent:test:root (")
        assert "20h" in incident["title"]
        assert "POST /api/agents/credentials" in incident["detail"], "the renewal step"
        assert "the-operator" in incident["detail"], "the owner"
        assert fake.calls[0][3] == "hub-secret"

    async def test_one_further_out_than_a_day_opens_nothing(self, app) -> None:
        with app.state.db.session() as session:
            _agent(session, expires=NOW + timedelta(hours=30))
        fake = FakeHub()
        result = await _run(app, fake)
        assert fake.opened == []
        assert result.opened == []

    async def test_the_next_tick_does_not_open_it_again(self, app) -> None:
        with app.state.db.session() as session:
            _agent(session, expires=NOW + timedelta(hours=20))
        fake = FakeHub()
        await _run(app, fake)
        again = await _run(app, fake)
        assert len(fake.opened) == 1
        assert again.opened == []

    async def test_a_lapse_in_the_last_day_opens_one_and_says_it_lapsed(self, app) -> None:
        with app.state.db.session() as session:
            _agent(session, expires=NOW - timedelta(hours=3))
        fake = FakeHub()
        await _run(app, fake)
        [incident] = fake.opened
        assert incident["title"].startswith("Credential lapsed 3h ago")

    async def test_a_lapse_older_than_a_day_does_not_page(self, app) -> None:
        # It is still on the calendar (and Start-Here's list); paging for it a
        # day late would only page for every old lapse on the first deploy.
        with app.state.db.session() as session:
            _agent(session, expires=NOW - timedelta(hours=30))
        fake = FakeHub()
        await _run(app, fake)
        assert fake.opened == []


class TestNobodyRenewed:
    async def test_a_renewed_credential_opens_nothing(self, app) -> None:
        with app.state.db.session() as session:
            _agent(session, expires=NOW - timedelta(hours=1))
            _agent(session, expires=NOW + timedelta(days=7))
        fake = FakeHub()
        await _run(app, fake)
        assert fake.opened == []

    async def test_a_renewal_after_the_incident_comments_on_it_once(self, app) -> None:
        with app.state.db.session() as session:
            _agent(session, expires=NOW - timedelta(hours=1))
        fake = FakeHub()
        await _run(app, fake)
        [incident] = fake.opened
        with app.state.db.session() as session:
            _agent(session, expires=NOW + timedelta(days=7))

        renewed = await _run(app, fake)
        await _run(app, fake)

        [(path, body)] = fake.comments
        assert path == "/api/incidents/700/comment"
        assert "no longer on the expiry list" in body["text"]
        assert renewed.cleared == [incident["source_ref"]]
        assert len(fake.opened) == 1

    async def test_a_role_renewed_early_does_not_page_for_the_old_credential(
        self, app
    ) -> None:
        # The renewal rule is "mint the next one 48 hours ahead". Every mint is
        # a new actor, and the old credential stays live until it lapses, so
        # the calendar still lists it in its last day. That is not "nobody
        # renewed it".
        with app.state.db.session() as session:
            _agent(session, actor="agent:test:old", purpose="author",
                   expires=NOW + timedelta(hours=20))
            _agent(session, actor="agent:test:new", purpose=" Author ",
                   expires=NOW + timedelta(days=6))
        fake = FakeHub()
        await _run(app, fake)
        assert fake.opened == []

    async def test_another_role_or_person_or_a_sub_agent_is_not_a_renewal(
        self, app
    ) -> None:
        with app.state.db.session() as session:
            _agent(session, actor="agent:test:old", purpose="author",
                   expires=NOW + timedelta(hours=20))
            _agent(session, actor="agent:test:ux", purpose="ux",
                   expires=NOW + timedelta(days=6))
            _agent(session, actor="agent:test:else", purpose="author",
                   on_behalf_of="someone-else", expires=NOW + timedelta(days=6))
            _agent(session, actor="agent:test:kid", purpose="author",
                   lineage=["agent:test:ux"], expires=NOW + timedelta(days=6))
            _agent(session, actor="agent:test:gone", purpose="author",
                   revoked=True, expires=NOW + timedelta(days=6))
        fake = FakeHub()
        await _run(app, fake)
        [incident] = fake.opened
        assert "agent:test:old" in incident["title"]

    async def test_a_renewal_that_lapses_inside_the_day_is_no_renewal(self, app) -> None:
        with app.state.db.session() as session:
            _agent(session, actor="agent:test:old", purpose="author",
                   expires=NOW + timedelta(hours=10))
            _agent(session, actor="agent:test:new", purpose="author",
                   expires=NOW + timedelta(hours=12))
        fake = FakeHub()
        await _run(app, fake)
        assert len(fake.opened) == 2

    async def test_a_sub_agents_credential_never_pages(self, app) -> None:
        # A sub-agent's credential is short-lived by design and its parent's
        # to replace; paging for each one would page all day.
        with app.state.db.session() as session:
            _agent(
                session,
                actor="agent:test:child",
                expires=NOW + timedelta(hours=2),
                lineage=["parent-instance"],
            )
        fake = FakeHub()
        await _run(app, fake)
        assert fake.opened == []

    async def test_ingestion_tokens_are_left_to_the_rotation_job(self, app) -> None:
        with app.state.db.session() as session:
            TokenRegistry(session).issue(REPO)
            token = session.query(IngestionToken).one()
            token.rotate_after = NOW + timedelta(hours=5)
            session.flush()
        fake = FakeHub()
        await _run(app, fake)
        assert fake.opened == []


class TestDeclaredCredentials:
    async def test_a_declared_date_is_read_through_the_route(self, app, tmp_path) -> None:
        declared = tmp_path / "calendar.yaml"
        declared.write_text(
            "version: 1\ncredentials:\n"
            "  - name: ci-token\n    kind: ci-token\n    owner: operator\n"
            f"    expires_at: '{(NOW + timedelta(hours=10)).isoformat()}'\n"
            "    renewal_step: Log in again and store the new token.\n",
            encoding="utf-8",
        )
        app.state.settings = app.state.settings.model_copy(
            update={"credential_expiry_path": declared}
        )
        fake = FakeHub()
        await _run(app, fake)
        [incident] = fake.opened
        assert incident["source_ref"].startswith("credential-expiry:ci-token@")
        assert "Log in again and store the new token." in incident["detail"]
        assert "declared" in incident["detail"]


class TestFailures:
    async def test_without_thehub_it_is_skipped_with_the_reason(self, app) -> None:
        with pytest.raises(jobs.JobSkipped, match="TheHub is not connected"):
            await _run(app, None)

    async def test_a_refusal_fails_the_job_and_the_next_tick_tries_again(self, app) -> None:
        with app.state.db.session() as session:
            _agent(session, expires=NOW + timedelta(hours=20))
        fake = FakeHub(refuse=1)
        with pytest.raises(cei.CredentialIncidentError, match="invalid room"):
            await _run(app, fake)
        await _run(app, fake)
        assert len(fake.opened) == 2, "refused once, then opened"
        assert await _run(app, fake) == cei.IncidentResult()

    async def test_no_token_or_hash_reaches_the_hub(self, app) -> None:
        with app.state.db.session() as session:
            plaintext = _agent(session, expires=NOW + timedelta(hours=20))
        fake = FakeHub()
        await _run(app, fake)
        sent = json.dumps(fake.opened)
        assert plaintext not in sent
        assert hash_token(plaintext) not in sent
        assert hash_token(plaintext)[:12] not in sent


class TestScheduled:
    def test_it_is_scheduled_hourly_and_reads_the_route(self, settings, monkeypatch) -> None:
        from fastapi.testclient import TestClient

        captured: dict[str, Any] = {}

        async def record(name: str, interval: int, job: Any, db: Any = None) -> None:
            captured[name] = (interval, job)

        calls: list[dict[str, Any]] = []

        async def fake_raise(**kwargs: Any) -> None:
            calls.append(kwargs)

        monkeypatch.setattr(main, "_every", record)
        monkeypatch.setattr(cei, "raise_incidents", fake_raise)
        with TestClient(
            main.create_app(settings.model_copy(update={"run_jobs_in_background": True}))
        ):
            pass

        interval, run = captured[jobs.CREDENTIAL_EXPIRY_INCIDENTS_JOB]
        assert interval == cei.TICK_SECONDS == 3600
        asyncio.run(run())
        [call] = calls
        assert call["db"] is not None and callable(call["read"])

    async def test_the_hub_client_opens_an_incident_and_comments(self) -> None:
        fake = FakeHub()
        hub = _hub(fake)
        opened = await hub.open_incident({"room": "devops", "severity": "error", "title": "t"})
        commented = await hub.comment_incident(700, "renewed")
        assert opened.ok and opened.body["id"] == 700
        assert commented.ok
        assert [c[:2] for c in fake.calls] == [
            ("POST", "/api/incidents"),
            ("POST", "/api/incidents/700/comment"),
        ]
