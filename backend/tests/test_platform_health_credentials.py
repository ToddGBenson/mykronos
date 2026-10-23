"""Credential state on MyKronos Health (TheHub #60974).

The rotation sweep already decides which ingestion tokens a person must handle
(`jobs.deliveries_awaiting_operator`, #263) and agent credentials already carry
an expiry (spec 34). Neither reached a page. These tests pin three things:

- the two ingestion-token states stay apart, and only ``due`` tells anybody
  to rotate - an ``unverified`` token is a reason to check that scans arrive,
  and rotating it is how a repository goes dark (D-097);
- an agent credential is listed inside a 14-day window and not outside it;
- the page carries state and dates only: no hash, hash prefix or plaintext,
  because it is served on an internet-exposed dashboard.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from mykronos import platform_health
from mykronos.auth import TokenRegistry, hash_token
from mykronos.db.models import AgentCredential
from mykronos.schemas import utcnow
from tests.test_jobs import age_token, onboard

DUE_REPO = "example-org/due-service"
UNVERIFIED_REPO = "example-org/unverified-service"

#: The only fields a credential row may carry. Pinned as a set so a field added
#: later (an id, a label, a lineage) has to be argued for here first.
ALLOWED_FIELDS = {
    "kind",
    "repo_full_name",
    "actor",
    "state",
    "rotate_after",
    "expires_at",
    "days_until_due",
    "action",
}


def _issue_due_and_unverified(db: Any) -> list[str]:
    """One due token and one never-confirmed token; returns both plaintexts."""
    onboard(db, repo=DUE_REPO, scanned_by="concourse")
    onboard(db, repo=UNVERIFIED_REPO, scanned_by="concourse")
    with db.session() as session:
        registry = TokenRegistry(session)
        due_plaintext = registry.issue(DUE_REPO)
        registry.mark_secret_synced(DUE_REPO)
        unverified_plaintext = registry.issue(UNVERIFIED_REPO)
    age_token(db, DUE_REPO, days=95)
    return [due_plaintext, unverified_plaintext]


def _agent(db: Any, *, actor: str, days: float, revoked: bool = False) -> str:
    """An agent credential expiring `days` from now; returns its stored hash."""
    now = utcnow()
    digest = hash_token(f"mka_test-{actor}-{days}")
    with db.session() as session:
        session.add(
            AgentCredential(
                token_sha256=digest,
                actor=actor,
                family="test-family",
                lineage=[],
                on_behalf_of="operator",
                purpose="author",
                minted_by="operator",
                minted_at=now,
                expires_at=now + timedelta(days=days),
                revoked_at=now if revoked else None,
            )
        )
    return digest


def _credentials(client: Any, auth: dict[str, str]) -> list[dict[str, Any]]:
    response = client.get("/api/dashboard/platform-health", headers=auth)
    assert response.status_code == 200, response.text
    body = response.json()
    assert "credentials" in body
    return body["credentials"]


class TestIngestionTokens:
    def test_a_due_token_is_listed_with_its_rotation_date(self, client, admin_auth) -> None:
        _issue_due_and_unverified(client.app.state.db)

        rows = {r["repo_full_name"]: r for r in _credentials(client, admin_auth)}

        due = rows[DUE_REPO]
        assert due["kind"] == "ingestion_token"
        assert due["state"] == "due"
        assert due["rotate_after"]
        assert due["days_until_due"] < 0
        assert due["actor"] is None
        assert due["action"] == (
            "rotate by hand (Concourse-scanned repos cannot receive a rotated token, D-086)"
        )

    def test_an_unverified_token_is_listed_with_the_do_not_rotate_action(
        self, client, admin_auth
    ) -> None:
        _issue_due_and_unverified(client.app.state.db)

        rows = {r["repo_full_name"]: r for r in _credentials(client, admin_auth)}

        unverified = rows[UNVERIFIED_REPO]
        assert unverified["state"] == "unverified"
        assert unverified["days_until_due"] > 80
        assert unverified["action"] == (
            "check that scans are arriving - do not rotate (D-097)"
        )
        # The one instruction D-097 forbids: "rotate" appears only negated.
        assert "rotate" not in unverified["action"].replace("do not rotate", "")


class TestAgentCredentials:
    def test_one_expiring_in_13_days_is_listed(self, client, admin_auth) -> None:
        _agent(client.app.state.db, actor="agent:test-family:aaaa1111", days=13)

        rows = [r for r in _credentials(client, admin_auth) if r["kind"] == "agent_credential"]

        assert [r["actor"] for r in rows] == ["agent:test-family:aaaa1111"]
        assert rows[0]["state"] == "expiring"
        assert rows[0]["expires_at"]
        assert rows[0]["repo_full_name"] is None
        assert 12.9 < rows[0]["days_until_due"] <= 13

    def test_one_expiring_in_15_days_is_not_listed(self, client, admin_auth) -> None:
        _agent(client.app.state.db, actor="agent:test-family:bbbb2222", days=15)

        assert _credentials(client, admin_auth) == []

    def test_revoked_and_already_expired_credentials_are_not_listed(
        self, client, admin_auth
    ) -> None:
        """Neither can be used, so neither needs anything doing."""
        db = client.app.state.db
        _agent(db, actor="agent:test-family:cccc3333", days=3, revoked=True)
        _agent(db, actor="agent:test-family:dddd4444", days=-1)

        assert _credentials(client, admin_auth) == []


class TestNothingSecretLeaves:
    def test_no_hash_prefix_or_plaintext_appears_in_the_response(
        self, client, admin_auth
    ) -> None:
        db = client.app.state.db
        plaintexts = _issue_due_and_unverified(db)
        agent_digest = _agent(db, actor="agent:test-family:eeee5555", days=2)

        response = client.get("/api/dashboard/platform-health", headers=admin_auth)
        text = response.text

        rows = response.json()["credentials"]
        assert len(rows) == 3
        digests = [hash_token(p) for p in plaintexts] + [agent_digest]
        for plaintext in plaintexts:
            assert plaintext not in text
        for digest in digests:
            assert digest not in text
            # A prefix is how a hash is usually "shortened" for display.
            assert digest[:8] not in text
            assert digest[:12] not in text
        assert "token_sha256" not in text
        assert "mka_" not in text
        for row in rows:
            assert set(row) == ALLOWED_FIELDS

    def test_a_viewer_reads_the_same_rows(self, client, viewer_auth) -> None:
        """Same dependency as the rest of the route: no wider, no narrower."""
        _issue_due_and_unverified(client.app.state.db)

        assert {r["state"] for r in _credentials(client, viewer_auth)} == {
            "due",
            "unverified",
        }


class TestNoRows:
    def test_an_empty_estate_returns_an_empty_list(self, client, admin_auth) -> None:
        assert _credentials(client, admin_auth) == []


class TestTheWindow:
    """The 14-day boundary, decided without a clock race."""

    def test_the_window_is_fourteen_days(self) -> None:
        assert platform_health.AGENT_EXPIRY_WINDOW == timedelta(days=14)
