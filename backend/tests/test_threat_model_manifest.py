"""`.sdlc/threat-model.yaml` and the register's new fields (TheHub #60825, D4).

Three properties carry the design, and each has a test that reads as its
statement:

- **The file is the source of truth for its own rows, and only those.** A
  sync upserts what the manifest declares and removes what it stopped
  declaring; a row somebody declared through the API is never touched.
- **A broken or unreadable file changes nothing.** A typo must not delete a
  threat model, and "could not look" is never evidence of absence.
- **A manifest row is read-only through the API.** An edit there would be
  undone by the next sync, so it is refused with a 409 that says where to
  change it.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, get_args

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect, select, text

from mykronos import controls, surfaces
from mykronos import threat_model_manifest as tmm
from mykronos.dashboard import STRIDE_CATEGORIES
from mykronos.db.models import AuditLogEntry, PublicEndpoint, RepoControl, RepoSurface
from mykronos.db.session import Database
from mykronos.github import FakeGitHubClient
from mykronos.schemas import utcnow
from tests.conftest import REPO
from tests.test_onboarding import onboard

SPEC = Path(__file__).resolve().parents[2] / "specs" / "28-threat-model-resolution.md"

MANIFEST = """\
version: 1
assets:
  - id: findings-db
    name: Findings database
    exposure: internal
    sensitivity: source
    cr: H
    evidence_ref: backend/mykronos/db/models.py
    selectors:
      paths: ["backend/mykronos/db/**"]
      addresses: ["10.0.0.5:5433"]
entry_points:
  - id: public-app
    name: Public dashboard
    exposure: internet
    selectors:
      hostnames: ["mykronos-app.toddbenson.net"]
      images: ["toddgbenson/mykronos-frontend"]
trust_boundaries:
  - id: tunnel
    name: Cloudflare tunnel
    exposure: internet
controls:
  - id: gate
    kind: perimeter_gate
    description: Every request needs the gate token.
    evidence_ref: frontend/proxy.ts
    applies_to: public-app
    reviewed_at: 2026-10-01
  - id: headers
    kind: security_headers
    stride: tampering
    evidence_ref: frontend/next.config.ts
"""


def _repo_id(client: TestClient, admin_auth: dict[str, str]) -> str:
    return client.get("/api/dashboard/portfolio", headers=admin_auth).json()["repos"][0][
        "repo_id"
    ]


def _write_manifest(github: FakeGitHubClient, text: str | None) -> None:
    branch = github.repos[REPO].branches["main"]
    if text is None:
        branch.pop(tmm.MANIFEST_PATH, None)
    else:
        branch[tmm.MANIFEST_PATH] = text


def _sync(client: TestClient, admin_auth: dict[str, str]) -> dict[str, Any]:
    r = client.post(
        f"/api/dashboard/repos/{_repo_id(client, admin_auth)}/threat-model/sync",
        headers=admin_auth,
    )
    assert r.status_code == 200, r.text
    return r.json()


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------


class TestParsing:
    def test_the_example_parses(self) -> None:
        state = tmm.parse_manifest(MANIFEST)

        assert state.state == "valid", state.error
        assert state.manifest is not None
        assert state.manifest.assets[0].selectors.addresses == ["10.0.0.5:5433"]

    def test_the_spec_example_parses(self) -> None:
        """The documented example is the one a team copies; it must work."""
        section = SPEC.read_text(encoding="utf-8").split("## 8.", 1)[1]
        block = re.search(r"```yaml\n(.*?)```", section, re.DOTALL)
        assert block is not None

        state = tmm.parse_manifest(block.group(1))

        assert state.state == "valid", state.error

    def test_an_unknown_key_is_an_error_not_a_default(self) -> None:
        """`sensitivty:` silently meaning "unknown" is the failure this
        prevents."""
        state = tmm.parse_manifest(
            "version: 1\nassets:\n  - id: a\n    name: A\n    sensitivty: pii\n"
        )

        assert state.state == "invalid"
        assert "unknown key" in (state.error or "")

    def test_absent_is_its_own_state(self) -> None:
        assert tmm.parse_manifest(None).state == "absent"

    def test_bad_yaml_says_where(self) -> None:
        state = tmm.parse_manifest("version: 1\nassets: [\n")

        assert state.state == "invalid"
        assert "line" in (state.error or "")

    @pytest.mark.parametrize(
        ("snippet", "says"),
        [
            ("assets:\n  - {id: a, name: A}\n  - {id: a, name: B}\n", "used twice"),
            (
                "controls:\n  - {id: c, kind: waf, evidence_ref: x.yaml, applies_to: nope}\n",
                "applies_to",
            ),
            ("controls:\n  - {id: c, kind: vibes, evidence_ref: x}\n", "kind"),
            ("controls:\n  - {id: c, kind: waf}\n", "evidence_ref"),
            ("entry_points:\n  - {id: e, name: E, cr: H}\n", "unknown key"),
            ("assets:\n  - {id: a, name: A, selectors: {paths: ['../x']}}\n", "inside"),
            ("assets:\n  - {id: a, name: A, evidence_ref: 'javascript:alert(1)'}\n", "path"),
            ("assets:\n  - {id: A B, name: A}\n", "id"),
        ],
    )
    def test_what_a_manifest_cannot_say(self, snippet: str, says: str) -> None:
        state = tmm.parse_manifest("version: 1\n" + snippet)

        assert state.state == "invalid"
        assert says in (state.error or ""), state.error

    def test_the_vocabularies_are_the_registers(self) -> None:
        assert get_args(tmm.ControlKind) == controls.CONTROL_KINDS
        assert get_args(tmm.StrideCategory) == STRIDE_CATEGORIES


# --------------------------------------------------------------------------
# Sync, against the module
# --------------------------------------------------------------------------


class TestApply:
    def test_it_upserts_the_manifests_rows(self, client: TestClient) -> None:
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            report = tmm.apply(session, REPO, tmm.parse_manifest(MANIFEST))
            rows = {r.manifest_key: r for r in session.scalars(select(RepoSurface))}
            gate = session.scalars(
                select(RepoControl).where(RepoControl.manifest_key == "gate")
            ).one()

            assert (report.surfaces.added, report.controls.added) == (3, 2)
            assert rows["findings-db"].cr == "H"
            assert rows["findings-db"].declared_by == surfaces.MANIFEST_ACTOR
            assert rows["public-app"].selectors["hostnames"] == ["mykronos-app.toddbenson.net"]
            assert gate.applies_to_surface_id == rows["public-app"].id
            assert gate.stride == "spoofing"  # the kind's first typical category
            assert gate.verified_by_capability == "dast"
            assert gate.last_verified_at == datetime(2026, 10, 1)

    def test_a_second_sync_of_the_same_file_changes_nothing(self, client: TestClient) -> None:
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            tmm.apply(session, REPO, tmm.parse_manifest(MANIFEST))
            ids = sorted(r.id for r in session.scalars(select(RepoSurface)))
            report = tmm.apply(session, REPO, tmm.parse_manifest(MANIFEST))

            assert (report.surfaces.unchanged, report.controls.unchanged) == (3, 2)
            assert sorted(r.id for r in session.scalars(select(RepoSurface))) == ids

    def test_an_unchanged_control_is_not_reconfirmed_by_being_reread(
        self, client: TestClient
    ) -> None:
        """Or nothing would ever go stale: the job re-reads every six hours."""
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            start = utcnow() - timedelta(days=200)
            tmm.apply(session, REPO, tmm.parse_manifest(MANIFEST), now=start)
            tmm.apply(session, REPO, tmm.parse_manifest(MANIFEST))
            headers = session.scalars(
                select(RepoControl).where(RepoControl.manifest_key == "headers")
            ).one()

            assert headers.last_verified_at == start
            assert controls.as_dict(headers)["stale"] is True

    def test_what_the_file_stops_declaring_goes(self, client: TestClient) -> None:
        trimmed = MANIFEST.split("trust_boundaries:")[0]
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            tmm.apply(session, REPO, tmm.parse_manifest(MANIFEST))
            report = tmm.apply(session, REPO, tmm.parse_manifest(trimmed))

            assert (report.surfaces.removed, report.controls.removed) == (1, 2)

    def test_an_api_row_is_never_touched(self, client: TestClient) -> None:
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            mine = surfaces.declare(session, REPO, kind="asset", name="Mine", declared_by="admin")
            tmm.apply(session, REPO, tmm.parse_manifest(MANIFEST))
            tmm.apply(session, REPO, tmm.parse_manifest(None))

            assert session.get(RepoSurface, mine.id) is not None
            assert session.scalars(
                select(RepoSurface).where(RepoSurface.declared_by == "manifest")
            ).all() == []

    @pytest.mark.parametrize("broken", ["invalid", "unreadable"])
    def test_a_broken_or_unreadable_file_changes_nothing(
        self, client: TestClient, broken: str
    ) -> None:
        state = (
            tmm.parse_manifest("version: 2\n")
            if broken == "invalid"
            else tmm.ManifestState(state="unreadable", error="503")
        )
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            tmm.apply(session, REPO, tmm.parse_manifest(MANIFEST))
            report = tmm.apply(session, REPO, state)

            assert report.applied is False
            assert len(session.scalars(select(RepoSurface)).all()) == 3

    def test_another_repositorys_manifest_rows_are_not_this_ones(
        self, client: TestClient
    ) -> None:
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            tmm.apply(session, "acme/other", tmm.parse_manifest(MANIFEST))
            tmm.apply(session, REPO, tmm.parse_manifest(None))

            assert len(session.scalars(select(RepoSurface)).all()) == 3


# --------------------------------------------------------------------------
# Through the API
# --------------------------------------------------------------------------


class TestSyncEndpoint:
    def test_it_reads_the_default_branch_and_syncs(
        self, client: TestClient, admin_auth, github: FakeGitHubClient
    ) -> None:
        onboard(client, admin_auth)
        _write_manifest(github, MANIFEST)

        out = _sync(client, admin_auth)

        assert (out["state"], out["applied"]) == ("valid", True)
        assert out["surfaces"]["added"] == 3
        listed = client.get(
            f"/api/dashboard/repos/{_repo_id(client, admin_auth)}/surfaces", headers=admin_auth
        ).json()
        db = listed["assets"][0]
        assert (db["declared_via"], db["read_only"], db["cr"]) == ("manifest", True, "H")
        assert db["selectors"]["paths"] == ["backend/mykronos/db/**"]

    def test_an_invalid_file_is_reported_and_changes_nothing(
        self, client: TestClient, admin_auth, github: FakeGitHubClient
    ) -> None:
        onboard(client, admin_auth)
        _write_manifest(github, MANIFEST)
        _sync(client, admin_auth)
        _write_manifest(github, MANIFEST.replace("exposure: internal", "exposure: intranet"))

        out = _sync(client, admin_auth)

        assert (out["state"], out["applied"]) == ("invalid", False)
        assert "exposure" in out["error"]
        assert (
            client.get(
                f"/api/dashboard/repos/{_repo_id(client, admin_auth)}/surfaces",
                headers=admin_auth,
            ).json()["total"]
            == 3
        )

    def test_it_is_audited_with_the_person_who_asked(
        self, client: TestClient, admin_auth, github: FakeGitHubClient
    ) -> None:
        onboard(client, admin_auth)
        _write_manifest(github, MANIFEST)

        _sync(client, admin_auth)

        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            entry = session.scalars(
                select(AuditLogEntry).where(AuditLogEntry.action == "threat_model.sync")
            ).one()
            assert entry.actor != tmm.SYNC_ACTOR

    def test_a_viewer_cannot_sync(self, client: TestClient, admin_auth, viewer_auth) -> None:
        onboard(client, admin_auth)

        r = client.post(
            f"/api/dashboard/repos/{_repo_id(client, admin_auth)}/threat-model/sync",
            headers=viewer_auth,
        )

        assert r.status_code == 403


class TestManifestRowsAreReadOnly:
    def _ids(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient
    ) -> tuple[str, str, str]:
        onboard(client, admin_auth)
        _write_manifest(github, MANIFEST)
        _sync(client, admin_auth)
        repo_id = _repo_id(client, admin_auth)
        surface_id = client.get(
            f"/api/dashboard/repos/{repo_id}/surfaces", headers=admin_auth
        ).json()["assets"][0]["id"]
        control_id = client.get(
            f"/api/dashboard/repos/{repo_id}/controls", headers=admin_auth
        ).json()["controls"][0]["control_id"]
        return repo_id, surface_id, control_id

    def test_withdrawing_a_manifest_surface_is_a_409_naming_the_file(
        self, client: TestClient, admin_auth, github: FakeGitHubClient
    ) -> None:
        repo_id, surface_id, _ = self._ids(client, admin_auth, github)

        r = client.delete(
            f"/api/dashboard/repos/{repo_id}/surfaces/{surface_id}", headers=admin_auth
        )

        assert r.status_code == 409
        assert ".sdlc/threat-model.yaml" in r.json()["detail"]

    @pytest.mark.parametrize("action", ["confirm", "withdraw"])
    def test_a_manifest_control_cannot_be_confirmed_or_withdrawn_here(
        self, client: TestClient, admin_auth, github: FakeGitHubClient, action: str
    ) -> None:
        repo_id, _, control_id = self._ids(client, admin_auth, github)
        url = f"/api/dashboard/repos/{repo_id}/controls/{control_id}"

        r = (
            client.post(f"{url}/confirm", headers=admin_auth)
            if action == "confirm"
            else client.delete(url, headers=admin_auth)
        )

        assert r.status_code == 409

    def test_the_controls_list_says_which_are_read_only(
        self, client: TestClient, admin_auth, github: FakeGitHubClient
    ) -> None:
        repo_id, _, _ = self._ids(client, admin_auth, github)

        out = client.get(f"/api/dashboard/repos/{repo_id}/controls", headers=admin_auth).json()

        assert {c["read_only"] for c in out["controls"]} == {True}
        assert out["kinds"] == list(controls.CONTROL_KINDS)


# --------------------------------------------------------------------------
# The register's new fields, through the API
# --------------------------------------------------------------------------


class TestSurfaceFields:
    def _post(self, client: TestClient, admin_auth: dict[str, str], **body: Any) -> Any:
        return client.post(
            f"/api/dashboard/repos/{_repo_id(client, admin_auth)}/surfaces",
            json={"kind": "asset", "name": "Cardholder db", **body},
            headers=admin_auth,
        )

    def test_selectors_and_overrides_round_trip_normalised(
        self, client: TestClient, admin_auth
    ) -> None:
        onboard(client, admin_auth)

        r = self._post(
            client,
            admin_auth,
            selectors={"paths": ["./billing/**"], "images": ["postgres:15"]},
            cr="H",
            ar="L",
        )

        assert r.status_code == 200, r.text
        out = r.json()
        assert out["selectors"]["paths"] == ["billing/**"]
        assert out["selectors"]["images"] == ["library/postgres"]
        assert (out["cr"], out["ir"], out["ar"]) == ("H", None, "L")
        assert (out["declared_via"], out["read_only"]) == ("api", False)

    def test_an_override_on_an_entry_point_is_refused(self, client: TestClient, admin_auth) -> None:
        """A Security Requirement on a way in is a number nobody can act on,
        and the person sending one believes it means something."""
        onboard(client, admin_auth)

        r = self._post(client, admin_auth, kind="entry_point", cr="H")

        assert r.status_code == 422
        assert "asset" in r.json()["detail"]

    def test_a_meaningless_selector_is_refused(self, client: TestClient, admin_auth) -> None:
        onboard(client, admin_auth)

        r = self._post(client, admin_auth, selectors={"addresses": ["10.0.0.5"]})

        assert r.status_code == 422
        assert "host:port" in r.json()["detail"]

    def test_withdrawing_a_surface_returns_its_control_to_repository_scope(
        self, client: TestClient, admin_auth
    ) -> None:
        onboard(client, admin_auth)
        repo_id = _repo_id(client, admin_auth)
        surface_id = self._post(client, admin_auth, kind="entry_point", name="app").json()["id"]
        control = client.post(
            f"/api/dashboard/repos/{repo_id}/controls",
            json={"stride": "spoofing", "kind": "perimeter_gate", "evidence_ref": "proxy.ts",
                  "applies_to_surface_id": surface_id},
            headers=admin_auth,
        ).json()
        assert control["applies_to_surface_id"] == surface_id

        client.delete(f"/api/dashboard/repos/{repo_id}/surfaces/{surface_id}", headers=admin_auth)

        listed = client.get(f"/api/dashboard/repos/{repo_id}/controls", headers=admin_auth).json()
        assert listed["controls"][0]["applies_to_surface_id"] is None

    def test_a_control_cannot_name_another_repositorys_surface(
        self, client: TestClient, admin_auth
    ) -> None:
        onboard(client, admin_auth)
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            other = surfaces.declare(session, "acme/other", kind="entry_point", name="x").id

        r = client.post(
            f"/api/dashboard/repos/{_repo_id(client, admin_auth)}/controls",
            json={"stride": "spoofing", "kind": "perimeter_gate",
                  "applies_to_surface_id": other},
            headers=admin_auth,
        )

        assert r.status_code == 422


class TestPublicEndpointSurface:
    def test_an_endpoint_can_name_its_surface(self, client: TestClient, admin_auth) -> None:
        onboard(client, admin_auth)
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            surface_id = surfaces.declare(session, REPO, kind="entry_point", name="app").id

        r = client.post(
            "/api/exposure/endpoints",
            json={"url": "https://app.example.net", "repo_full_name": REPO,
                  "surface_id": surface_id},
            headers=admin_auth,
        )

        assert r.status_code == 201, r.text
        assert r.json()["surface_id"] == surface_id
        listed = client.get("/api/exposure", headers=admin_auth).json()["endpoints"]
        assert listed[0]["surface_id"] == surface_id

    def test_a_surface_on_another_repository_is_refused(
        self, client: TestClient, admin_auth
    ) -> None:
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            surface_id = surfaces.declare(session, "acme/other", kind="entry_point", name="x").id

        r = client.post(
            "/api/exposure/endpoints",
            json={"url": "https://app.example.net", "repo_full_name": REPO,
                  "surface_id": surface_id},
            headers=admin_auth,
        )

        assert r.status_code == 422

    def test_withdrawing_the_surface_nulls_the_link(self, client: TestClient) -> None:
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            surface = surfaces.declare(session, REPO, kind="entry_point", name="app")
            endpoint = PublicEndpoint(url="https://x.example.net", surface_id=surface.id)
            session.add(endpoint)
            session.flush()

            surfaces.remove(session, REPO, surface.id)
            session.flush()
            session.refresh(endpoint)

            assert endpoint.surface_id is None


# --------------------------------------------------------------------------
# Migration
# --------------------------------------------------------------------------


NEW_COLUMNS = {
    "repo_surfaces": ("selectors", "cr", "ir", "ar", "manifest_key"),
    "repo_controls": ("applies_to_surface_id", "manifest_key"),
    "public_endpoints": ("surface_id",),
}


def test_an_existing_database_gains_the_columns_and_keeps_its_rows(tmp_path: Path) -> None:
    """The deploy path: a database from before #60825, with rows in it, opened
    by the new code (a second `Database`, as a restarted process would)."""
    url = f"sqlite:///{tmp_path / 'ops.db'}"
    old = Database(url)
    try:
        old.create_all()
        with old.engine.begin() as connection:
            for table, columns in NEW_COLUMNS.items():
                for column in columns:
                    connection.execute(text(f"ALTER TABLE {table} DROP COLUMN {column}"))
            connection.execute(
                text(
                    "INSERT INTO repo_surfaces (id, repo_full_name, kind, name, description, "
                    "exposure, sensitivity, evidence_ref, declared_by, declared_at, updated_at) "
                    "VALUES ('s1', 'a/b', 'asset', 'db', '', 'internal', 'pii', '', 'admin', "
                    "'2026-01-01', '2026-01-01')"
                )
            )
    finally:
        old.close()

    new = Database(url)
    try:
        added = new.add_missing_columns()

        assert {f"{t}.{c}" for t, cs in NEW_COLUMNS.items() for c in cs} <= set(added)
        for table, columns in NEW_COLUMNS.items():
            present = {c["name"] for c in inspect(new.engine).get_columns(table)}
            assert set(columns) <= present
        with new.session() as session:
            row = session.get(RepoSurface, "s1")
            assert row is not None
            assert (row.name, row.selectors, row.cr) == ("db", {}, None)
            assert surfaces.declared_via(row) == "api"
    finally:
        new.close()
