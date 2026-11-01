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


def _agent(
    session,
    *,
    actor="agent:test:aaaa",
    expires,
    revoked=False,
    purpose="",
    on_behalf_of="the-operator",
    lineage=None,
) -> str:
    plaintext = f"mka_{actor}_{expires.isoformat()}"
    row = AgentCredential(
        token_sha256=hash_token(plaintext),
        actor=actor,
        on_behalf_of=on_behalf_of,
        expires_at=expires,
        purpose=purpose,
        lineage=list(lineage or []),
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

    def test_each_row_names_the_role_it_was_minted_for(self, client) -> None:
        # TheHub #61147: one credential per role, so the calendar must say which.
        with client.app.state.db.session() as session:
            _agent(
                session,
                actor="agent:test:sec1",
                purpose="secrets",
                expires=NOW + timedelta(hours=10),
            )
            found = credential_expiry.agent_credentials(session, NOW)
        [row] = credential_expiry.expiring(found, NOW, 48)
        assert row["name"].startswith("agent:test:sec1 (")
        assert row["name"].endswith(", secrets)")

    def test_a_renewal_hides_the_lapsed_credential_of_the_same_role(self, client) -> None:
        # Every mint is a new instance and so a new actor: matching on actor
        # alone never sees a renewal, and the lapsed one crowds the list.
        with client.app.state.db.session() as session:
            _agent(
                session,
                actor="agent:test:old1",
                purpose="delivery",
                expires=NOW - timedelta(hours=1),
            )
            _agent(
                session,
                actor="agent:test:new1",
                purpose="delivery",
                expires=NOW + timedelta(days=7),
            )
            _agent(
                session,
                actor="agent:test:ux01",
                purpose="ux",
                expires=NOW - timedelta(hours=1),
            )
            found = credential_expiry.agent_credentials(session, NOW)
        names = [r["name"].split(" (")[0] for r in credential_expiry.expiring(found, NOW, 48)]
        assert names == ["agent:test:ux01"], "a lapse with no renewal of its role stays listed"

    def test_a_sub_agent_labelled_with_a_role_does_not_hide_its_lapse(self, client) -> None:
        # Any agent may mint a child with any purpose. Only a root credential
        # (minted by a person, empty lineage) renews a role, or a short-lived
        # child labelled "delivery" would hide the real delivery lapse.
        with client.app.state.db.session() as session:
            _agent(
                session,
                actor="agent:test:del0",
                purpose="delivery",
                expires=NOW - timedelta(hours=1),
            )
            _agent(
                session,
                actor="agent:test:kid1",
                purpose="delivery",
                lineage=["ux-root-instance"],
                expires=NOW + timedelta(hours=2),
            )
            found = credential_expiry.agent_credentials(session, NOW)
        names = [r["name"].split(" (")[0] for r in credential_expiry.expiring(found, NOW, 48)]
        assert "agent:test:del0" in names

    def test_a_role_matches_regardless_of_case_and_spacing(self, client) -> None:
        with client.app.state.db.session() as session:
            _agent(
                session,
                actor="agent:test:old2",
                purpose="CI  Triage",
                expires=NOW - timedelta(hours=1),
            )
            _agent(
                session,
                actor="agent:test:new2",
                purpose=" ci triage",
                expires=NOW + timedelta(days=7),
            )
            found = credential_expiry.agent_credentials(session, NOW)
        assert credential_expiry.expiring(found, NOW, 48) == []

    def test_control_characters_in_a_purpose_never_reach_the_name(self, client) -> None:
        # The name is printed in the `mykronos credentials` terminal table: an
        # escape or newline in a self-chosen purpose must not garble it.
        with client.app.state.db.session() as session:
            _agent(
                session,
                actor="agent:test:esc1",
                purpose="ux\x1b[31m\nfake row\r",
                expires=NOW + timedelta(hours=10),
            )
            found = credential_expiry.agent_credentials(session, NOW)
        [row] = credential_expiry.expiring(found, NOW, 48)
        assert row["name"].isprintable(), row["name"]
        assert row["name"].endswith(", ux[31m fake row)")

    # Guards: each of these must stay listed (the review checked them by hand).

    def test_a_live_credential_of_another_role_does_not_hide_a_lapse(self, client) -> None:
        with client.app.state.db.session() as session:
            _agent(session, actor="agent:test:g1a", purpose="ux", expires=NOW - timedelta(hours=1))
            _agent(session, actor="agent:test:g1b", purpose="docs", expires=NOW + timedelta(days=7))
            found = credential_expiry.agent_credentials(session, NOW)
        names = [r["name"].split(" (")[0] for r in credential_expiry.expiring(found, NOW, 48)]
        assert names == ["agent:test:g1a"]

    def test_a_live_credential_for_another_person_does_not_hide_a_lapse(self, client) -> None:
        with client.app.state.db.session() as session:
            _agent(session, actor="agent:test:g2a", purpose="ux", expires=NOW - timedelta(hours=1))
            _agent(
                session,
                actor="agent:test:g2b",
                purpose="ux",
                on_behalf_of="someone-else",
                expires=NOW + timedelta(days=7),
            )
            found = credential_expiry.agent_credentials(session, NOW)
        names = [r["name"].split(" (")[0] for r in credential_expiry.expiring(found, NOW, 48)]
        assert names == ["agent:test:g2a"]

    def test_a_revoked_renewal_does_not_hide_a_lapse(self, client) -> None:
        with client.app.state.db.session() as session:
            _agent(session, actor="agent:test:g3a", purpose="ux", expires=NOW - timedelta(hours=1))
            _agent(
                session,
                actor="agent:test:g3b",
                purpose="ux",
                revoked=True,
                expires=NOW + timedelta(days=7),
            )
            found = credential_expiry.agent_credentials(session, NOW)
        names = [r["name"].split(" (")[0] for r in credential_expiry.expiring(found, NOW, 48)]
        assert names == ["agent:test:g3a"]

    def test_one_expiring_exactly_now_is_lapsed_not_a_renewal(self, client) -> None:
        with client.app.state.db.session() as session:
            _agent(session, actor="agent:test:g4a", purpose="ux", expires=NOW - timedelta(hours=1))
            _agent(session, actor="agent:test:g4b", purpose="ux", expires=NOW)
            found = credential_expiry.agent_credentials(session, NOW)
        names = sorted(r["name"].split(" (")[0] for r in credential_expiry.expiring(found, NOW, 48))
        assert names == ["agent:test:g4a", "agent:test:g4b"]

    def test_empty_purposes_never_match_as_one_role(self, client) -> None:
        with client.app.state.db.session() as session:
            _agent(session, actor="agent:test:g5a", expires=NOW - timedelta(hours=1))
            _agent(session, actor="agent:test:g5b", expires=NOW + timedelta(days=7))
            found = credential_expiry.agent_credentials(session, NOW)
        names = [r["name"].split(" (")[0] for r in credential_expiry.expiring(found, NOW, 48)]
        assert names == ["agent:test:g5a"]

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

    def test_a_private_entry_replaces_the_public_one_of_the_same_name(self, tmp_path) -> None:
        public = tmp_path / "public.yaml"
        public.write_text(
            "credentials:\n"
            "  - name: ci-token\n    kind: ci-token\n    owner: op\n    renewal_step: generic\n"
            "  - name: app-key\n    kind: k\n    owner: op\n    renewal_step: r\n",
            encoding="utf-8",
        )
        private = tmp_path / "private.yaml"
        private.write_text(
            "credentials:\n"
            "  - name: ci-token\n    kind: ci-token\n    owner: op\n"
            "    expires_at: 2026-11-02\n    renewal_step: specific\n"
            "  - name: extra\n    kind: k\n    owner: op\n"
            "    expires_at: 2026-11-01T18:00:00Z\n    renewal_step: r\n",
            encoding="utf-8",
        )
        entries = credential_expiry.load_all(public, private)
        by_name = {e.name: e for e in entries}
        assert set(by_name) == {"ci-token", "app-key", "extra"}
        assert by_name["ci-token"].renewal_step == "specific"
        assert by_name["ci-token"].expires_at == datetime(2026, 11, 2)
        assert credential_expiry.undated(entries) == ["app-key"]
        assert [r["name"] for r in credential_expiry.expiring(entries, NOW, 48)] == [
            "extra",
            "ci-token",
        ]

    def test_an_empty_or_absent_private_file_leaves_the_public_list(self, tmp_path) -> None:
        public = REPO_ROOT / "credential-expiry-v1.yaml"
        empty = tmp_path / "empty.yaml"
        empty.write_text("", encoding="utf-8")
        names = {e.name for e in credential_expiry.load_declared(public)}
        assert {e.name for e in credential_expiry.load_all(public, empty)} == names
        assert {e.name for e in credential_expiry.load_all(public, None)} == names
        assert {e.name for e in credential_expiry.load_all(public, tmp_path / "no")} == names

    def test_the_private_file_is_refused_for_a_stray_field_like_the_public_one(
        self, tmp_path
    ) -> None:
        private = tmp_path / "private.yaml"
        private.write_text(
            "credentials:\n  - name: x\n    kind: k\n    owner: o\n"
            "    renewal_step: r\n    token: abc\n",
            encoding="utf-8",
        )
        with pytest.raises(credential_expiry.CredentialFileError):
            credential_expiry.load_all(REPO_ROOT / "credential-expiry-v1.yaml", private)

    def test_an_unreadable_path_is_refused_not_a_crash(self, tmp_path) -> None:
        # A directory where the file should be: what a short-syntax bind mount
        # of a missing host file produces. read_text raises OSError.
        with pytest.raises(credential_expiry.CredentialFileError):
            credential_expiry.load_declared(tmp_path)

    def test_a_file_that_is_not_utf8_is_refused(self, tmp_path) -> None:
        path = tmp_path / "latin1.yaml"
        path.write_bytes(b"credentials:\n  - name: caf\xe9\n")
        with pytest.raises(credential_expiry.CredentialFileError):
            credential_expiry.load_declared(path)

    @pytest.mark.parametrize(
        "body",
        ["- just\n- a list\n", "a plain string\n", "credentials: not-a-list\n"],
    )
    def test_a_document_of_the_wrong_shape_is_refused(self, tmp_path, body) -> None:
        with pytest.raises(credential_expiry.CredentialFileError):
            credential_expiry.load_declared(self._file(tmp_path, body))

    def test_an_empty_path_is_unset(self) -> None:
        assert credential_expiry.load_declared(Path("")) == []
        public = REPO_ROOT / "credential-expiry-v1.yaml"
        names = {e.name for e in credential_expiry.load_declared(public)}
        assert {e.name for e in credential_expiry.load_all(public, Path(""))} == names

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

    def test_a_broken_private_overlay_is_a_503_naming_the_file(
        self, client, admin_auth, tmp_path, monkeypatch
    ) -> None:
        self._fix_clock(client)
        broken = tmp_path / "private.yaml"
        broken.write_text("- not\n- a mapping\n", encoding="utf-8")
        monkeypatch.setattr(client.app.state.settings, "credential_expiry_private_path", broken)
        response = client.get("/api/credentials/expiring", headers=admin_auth)
        assert response.status_code == 503
        assert "private.yaml" in response.json()["detail"]


class TestTheComposeMount:
    """The overlay's mount: read-only, never created on the host, /dev/null when
    unset, and landing exactly where the backend is told to look."""

    COMPOSE = REPO_ROOT / "deploy" / "mykronos" / "docker-compose.yml"
    TARGET = "/secrets/credential-expiry-private.yaml"

    def _backend(self) -> dict:
        import yaml

        return yaml.safe_load(self.COMPOSE.read_text(encoding="utf-8"))["services"]["backend"]

    def _mount(self) -> dict:
        [mount] = [
            v
            for v in self._backend()["volumes"]
            if isinstance(v, dict) and v.get("target") == self.TARGET
        ]
        return mount

    def test_it_is_a_read_only_bind_that_never_creates_a_host_path(self) -> None:
        mount = self._mount()
        assert mount["type"] == "bind"
        assert mount["read_only"] is True
        # Short syntax would create a DIRECTORY at a missing host path, and the
        # loader would then read a directory. Long syntax refuses instead.
        assert mount["bind"]["create_host_path"] is False

    def test_unset_it_mounts_dev_null(self) -> None:
        expected = "${MYKRONOS_CREDENTIAL_EXPIRY_PRIVATE_HOST_PATH:-/dev/null}"
        assert self._mount()["source"] == expected

    def test_the_container_path_is_the_one_the_backend_reads(self) -> None:
        env = self._backend()["environment"]
        assert env["MYKRONOS_CREDENTIAL_EXPIRY_PRIVATE_PATH"] == self.TARGET


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

    def test_it_says_how_many_private_entries_loaded_and_nothing_else(
        self, settings: Settings, monkeypatch, capsys, tmp_path
    ) -> None:
        db = Database(settings.database_url)
        db.create_all()
        db.close()
        private = tmp_path / "private.yaml"
        private.write_text(
            "credentials:\n"
            "  - name: secret-sounding-name\n    kind: k\n    owner: o\n    renewal_step: r\n"
            "  - name: another\n    kind: k\n    owner: o\n    renewal_step: r\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(settings, "credential_expiry_private_path", private)
        monkeypatch.setattr(cli, "get_settings", lambda: settings)
        monkeypatch.setattr("mykronos.schemas.utcnow", lambda: NOW)

        assert cli.main(["credentials", "expiring", "--within-hours", "48"]) == 0
        out = capsys.readouterr().out
        assert "Private overlay: 2 entries" in out
        assert str(private) not in out, "the count only, never the host path"
