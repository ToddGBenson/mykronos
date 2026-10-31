"""One list of when each credential expires (TheHub #61104).

On 2026-10-30 an agent credential lapsed mid-task with nothing to warn of it.
Every test here runs on a fixed clock (`NOW`), never the real date: a window
that reads the system clock makes fixed-date tests fail days later (#1034).
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select

from mykronos import cli, credential_expiry
from mykronos.auth import TokenRegistry, hash_token
from mykronos.config import Settings
from mykronos.db import Database
from mykronos.db.models import AgentCredential, IngestionToken, RepoReadToken

NOW = datetime(2026, 11, 1, 12, 0, 0)
REPO = "example-org/payments-api"

REPO_ROOT = Path(__file__).resolve().parents[2]


def _agent(session, *, actor="agent:test:aaaa", expires, revoked=False) -> str:
    plaintext = f"mka_{actor}_{expires.isoformat()}"
    row = AgentCredential(
        token_sha256=hash_token(plaintext),
        actor=actor,
        on_behalf_of="the-operator",
        expires_at=expires,
    )
    if revoked:
        row.revoked_at = NOW
    session.add(row)
    session.flush()
    return plaintext


def _names(rows) -> list[str]:
    return [r["name"] for r in rows]


class TestAgentCredentials:
    def test_one_expiring_inside_the_window_is_listed_with_its_hours(self, client) -> None:
        with client.app.state.db.session() as session:
            _agent(session, expires=NOW + timedelta(hours=10))
            _agent(session, actor="agent:test:far", expires=NOW + timedelta(days=6))
            found = credential_expiry.agent_credentials(session, NOW)
        rows = credential_expiry.expiring(found, NOW, 48)
        assert len(rows) == 1
        assert rows[0]["hours_left"] == 10.0
        assert rows[0]["source"] == "observed"
        assert rows[0]["kind"] == "agent-credential"
        assert rows[0]["owner"] == "the-operator"
        assert "POST /api/agents/credentials" in rows[0]["renewal_step"]

    def test_one_that_expired_yesterday_shows_as_expired(self, client) -> None:
        with client.app.state.db.session() as session:
            _agent(session, expires=NOW - timedelta(days=1))
            found = credential_expiry.agent_credentials(session, NOW)
        [row] = credential_expiry.expiring(found, NOW, 48)
        assert row["expired"] is True
        assert row["hours_left"] == -24.0

    def test_a_revoked_one_is_a_decision_not_a_lapse(self, client) -> None:
        with client.app.state.db.session() as session:
            _agent(session, expires=NOW - timedelta(hours=1), revoked=True)
            assert credential_expiry.agent_credentials(session, NOW) == []

    def test_an_expired_one_with_a_live_replacement_is_not_listed(self, client) -> None:
        with client.app.state.db.session() as session:
            _agent(session, expires=NOW - timedelta(hours=1))
            _agent(session, expires=NOW + timedelta(days=7))
            found = credential_expiry.agent_credentials(session, NOW)
        assert credential_expiry.expiring(found, NOW, 48) == []

    def test_an_old_lapse_ages_off_the_list(self, client) -> None:
        with client.app.state.db.session() as session:
            days = credential_expiry.EXPIRED_LOOKBACK_DAYS + 1
            _agent(session, expires=NOW - timedelta(days=days))
            assert credential_expiry.agent_credentials(session, NOW) == []


class TestReadTokens:
    def test_an_expiring_read_token_is_listed_and_a_revoked_one_is_not(self, client) -> None:
        with client.app.state.db.session() as session:
            session.add(
                RepoReadToken(
                    token_sha256=hash_token("mkr_one"),
                    repo_full_name=REPO,
                    minted_by="the-operator",
                    expires_at=NOW + timedelta(hours=5),
                )
            )
            session.add(
                RepoReadToken(
                    token_sha256=hash_token("mkr_two"),
                    repo_full_name="example-org/other",
                    expires_at=NOW + timedelta(hours=5),
                    revoked_at=NOW,
                )
            )
            session.flush()
            found = credential_expiry.read_tokens(session, NOW)
        [row] = credential_expiry.expiring(found, NOW, 48)
        assert REPO in row["name"]
        assert row["kind"] == "repo-read-token"
        assert row["hours_left"] == 5.0


class TestIngestionTokens:
    def test_an_active_token_is_dated_by_its_rotate_by(self, client) -> None:
        with client.app.state.db.session() as session:
            TokenRegistry(session).issue(REPO)
            token = session.scalars(select(IngestionToken)).one()
            token.rotate_after = NOW + timedelta(hours=30)
            session.flush()
            found = credential_expiry.ingestion_tokens(session, NOW)
        [row] = credential_expiry.expiring(found, NOW, 48)
        assert row["kind"] == "ingestion-token"
        assert row["hours_left"] == 30.0
        assert f"rotate-token {REPO}" in row["renewal_step"]

    def test_a_superseded_token_is_dated_by_the_end_of_its_overlap(self, client) -> None:
        with client.app.state.db.session() as session:
            TokenRegistry(session).issue(REPO)
            token = session.scalars(select(IngestionToken)).one()
            token.status = "superseded"
            token.expires_at = NOW - timedelta(hours=2)
            token.rotate_after = NOW + timedelta(days=90)
            session.flush()
            found = credential_expiry.ingestion_tokens(session, NOW)
        [row] = credential_expiry.expiring(found, NOW, 48)
        assert row["kind"] == "ingestion-token-overlap"
        assert row["expired"] is True

    def test_a_token_rotated_long_ago_is_not_listed(self, client) -> None:
        with client.app.state.db.session() as session:
            TokenRegistry(session).issue(REPO)
            token = session.scalars(select(IngestionToken)).one()
            token.rotate_after = NOW + timedelta(days=80)
            session.flush()
            found = credential_expiry.ingestion_tokens(session, NOW)
        assert credential_expiry.expiring(found, NOW, 48) == []


class TestDeclared:
    def _file(self, tmp_path: Path, body: str) -> Path:
        path = tmp_path / "declared.yaml"
        path.write_text(body, encoding="utf-8")
        return path

    def test_a_declared_entry_carries_its_date_and_says_declared(self, tmp_path) -> None:
        path = self._file(
            tmp_path,
            "credentials:\n"
            "  - name: fly\n    kind: ci-token\n    owner: op\n"
            "    expires_at: 2026-11-02\n    renewal_step: log in again\n",
        )
        [entry] = credential_expiry.load_declared(path)
        rows = credential_expiry.expiring([entry], NOW, 48)
        assert rows[0]["source"] == "declared"
        assert rows[0]["hours_left"] == 12.0
        assert rows[0]["renewal_step"] == "log in again"

    def test_rotate_by_is_accepted_in_place_of_expires_at(self, tmp_path) -> None:
        path = self._file(
            tmp_path,
            "credentials:\n"
            "  - name: key\n    kind: k\n    owner: op\n"
            "    rotate_by: '2026-10-31T12:00:00Z'\n    renewal_step: rotate\n",
        )
        [entry] = credential_expiry.load_declared(path)
        [row] = credential_expiry.expiring([entry], NOW, 48)
        assert row["expired"] is True

    def test_an_undated_entry_is_reported_not_dropped(self, tmp_path) -> None:
        path = self._file(
            tmp_path,
            "credentials:\n  - name: x\n    kind: k\n    owner: op\n    renewal_step: r\n",
        )
        entries = credential_expiry.load_declared(path)
        assert credential_expiry.expiring(entries, NOW, 48) == []
        assert credential_expiry.undated(entries) == ["x"]

    @pytest.mark.parametrize(
        "body",
        [
            "credentials:\n  - name: x\n    kind: k\n    owner: o\n"
            "    renewal_step: r\n    token: abc\n",
            "credentials:\n  - name: x\n    kind: k\n    owner: o\n",
            "credentials:\n  - name: x\n    kind: k\n    owner: o\n    renewal_step: r\n"
            "  - name: x\n    kind: k\n    owner: o\n    renewal_step: r\n",
        ],
    )
    def test_a_file_with_a_stray_field_a_gap_or_a_duplicate_is_refused(
        self, tmp_path, body
    ) -> None:
        with pytest.raises(credential_expiry.CredentialFileError):
            credential_expiry.load_declared(self._file(tmp_path, body))

    def test_a_missing_file_is_an_empty_list(self, tmp_path) -> None:
        assert credential_expiry.load_declared(tmp_path / "nope.yaml") == []

    def test_the_committed_file_loads_and_names_the_unobservable_four(self) -> None:
        entries = credential_expiry.load_declared(REPO_ROOT / "credential-expiry-v1.yaml")
        assert {e.name for e in entries} >= {
            "concourse-fly-token",
            "google-oauth-tasks-calendar",
            "github-app-private-key",
            "vault-service-token",
        }
        assert all(e.source == "declared" for e in entries)

    def test_the_committed_file_holds_no_address_or_secret_shaped_text(self) -> None:
        text = (REPO_ROOT / "credential-expiry-v1.yaml").read_text(encoding="utf-8")
        for needle in ("http://", "https://", "ghp_", "mka_", "mkr_", "BEGIN ", "192.168."):
            assert needle not in text


class TestTheRoute:
    def _fix_clock(self, client) -> None:
        client.app.state.clock = lambda: NOW

    def test_it_lists_expired_and_expiring_and_hides_the_rest(self, client, admin_auth) -> None:
        self._fix_clock(client)
        with client.app.state.db.session() as session:
            _agent(session, actor="agent:test:gone", expires=NOW - timedelta(days=1))
            _agent(session, actor="agent:test:soon", expires=NOW + timedelta(hours=20))
            _agent(session, actor="agent:test:later", expires=NOW + timedelta(days=5))
        body = client.get(
            "/api/credentials/expiring", params={"within_hours": 48}, headers=admin_auth
        ).json()
        by_name = {c["name"].split(" (")[0]: c for c in body["credentials"]}
        assert set(by_name) == {"agent:test:gone", "agent:test:soon"}
        assert by_name["agent:test:gone"]["expired"] is True
        assert by_name["agent:test:gone"]["hours_left"] == -24.0
        assert by_name["agent:test:soon"]["hours_left"] == 20.0
        assert body["credentials"][0]["name"].startswith("agent:test:gone"), "soonest first"
        assert "concourse-fly-token" in body["undated"]

    def test_the_window_is_the_query_parameter(self, client, admin_auth) -> None:
        self._fix_clock(client)
        with client.app.state.db.session() as session:
            _agent(session, expires=NOW + timedelta(hours=60))
        narrow = client.get("/api/credentials/expiring?within_hours=48", headers=admin_auth)
        wide = client.get("/api/credentials/expiring?within_hours=72", headers=admin_auth)
        assert narrow.json()["credentials"] == []
        assert len(wide.json()["credentials"]) == 1

    def test_it_needs_a_credential_and_a_viewer_is_refused(
        self, client, viewer_auth
    ) -> None:
        assert client.get("/api/credentials/expiring").status_code == 401
        assert (
            client.get("/api/credentials/expiring", headers=viewer_auth).status_code == 403
        )

    def test_no_secret_or_hash_is_ever_in_the_response(self, client, admin_auth) -> None:
        """Mint real credentials of every observed kind, then look for the
        plaintext, the stored hash and any hash fragment anywhere in the body."""
        self._fix_clock(client)
        minted = client.post(
            "/api/agents/credentials", json={"family": "claude-opus-5.5"}, headers=admin_auth
        ).json()["token"]
        read_token = client.post(
            "/api/repo-read/tokens",
            json={"repo_full_name": REPO, "label": "t"},
            headers=admin_auth,
        )
        secrets_ = [minted]
        if read_token.status_code == 201:
            secrets_.append(read_token.json()["token"])
        with client.app.state.db.session() as session:
            ingestion = TokenRegistry(session).issue(REPO)
            secrets_.append(ingestion)
            # Make every kind fall inside a huge window, whatever the minting dates.
            for row in session.scalars(select(AgentCredential)):
                row.expires_at = NOW + timedelta(hours=1)
            for row in session.scalars(select(RepoReadToken)):
                row.expires_at = NOW + timedelta(hours=1)
            for row in session.scalars(select(IngestionToken)):
                row.rotate_after = NOW + timedelta(hours=1)
            digests = [hash_token(s) for s in secrets_]
        response = client.get("/api/credentials/expiring?within_hours=48", headers=admin_auth)
        assert response.status_code == 200
        kinds = {c["kind"] for c in response.json()["credentials"]}
        assert "agent-credential" in kinds and "ingestion-token" in kinds
        text = json.dumps(response.json())
        for secret in secrets_:
            assert secret not in text
        for digest in digests:
            assert digest not in text and digest[:12] not in text
        assert "token_sha256" not in text
        assert "sha256" not in text.lower()
        assert set(response.json()["credentials"][0]) == {
            "name", "kind", "owner", "expires_at", "hours_left", "expired",
            "renewal_step", "source",
        }


class TestTheCommand:
    def test_it_prints_the_same_list_as_a_table(
        self, settings: Settings, monkeypatch, capsys
    ) -> None:
        db = Database(settings.database_url)
        db.create_all()
        soon = NOW + timedelta(hours=3)
        with db.session() as session:
            _agent(session, actor="agent:cli:one", expires=soon)
        db.close()
        monkeypatch.setattr(cli, "get_settings", lambda: settings)
        monkeypatch.setattr("mykronos.schemas.utcnow", lambda: NOW)

        assert cli.main(["credentials", "expiring", "--within-hours", "48"]) == 0
        out = capsys.readouterr().out
        assert "agent:cli:one" in out
        assert "observed" in out
        assert "hours left" in out
        assert "No date declared for" in out

    def test_json_output_has_the_api_fields(
        self, settings: Settings, monkeypatch, capsys
    ) -> None:
        db = Database(settings.database_url)
        db.create_all()
        with db.session() as session:
            _agent(session, actor="agent:cli:two", expires=NOW + timedelta(hours=3))
        db.close()
        monkeypatch.setattr(cli, "get_settings", lambda: settings)
        monkeypatch.setattr("mykronos.schemas.utcnow", lambda: NOW)

        assert cli.main(["credentials", "expiring", "--json"]) == 0
        [row] = json.loads(capsys.readouterr().out)
        assert row["source"] == "observed"
        assert "token_sha256" not in row
