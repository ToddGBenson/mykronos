"""Machine-collected evidence about controls (TheHub #60826, S4 of #60822).

A declaration (`RepoSurface`, `RepoControl`) is a person's claim. A
`ControlObservation` is what a collector saw, from a named vantage point, at a
named time. These pin the three properties the environmental scorer (S5) will
lean on:

* the vocabulary is closed - an assertion nobody defined cannot be stored;
* only `pass` / `fail` are evidence, and a collector that resolved nothing
  records `unknown`, never `pass`;
* attribution comes from the token, never the payload.
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from mykronos import control_observations as co
from mykronos.db.models import AuditLogEntry, ControlObservation, RepoControl, RepoSurface
from mykronos.schemas import utcnow
from tests.conftest import REPO, issue_token
from tests.test_onboarding import onboard

DATA = Path(__file__).parent / "data" / "control_observations"
URL = "/api/ingest/control-observations"


def _host_document() -> dict[str, Any]:
    return json.loads((DATA / "host_document.json").read_text(encoding="utf-8"))


def _obs(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "subject": "demo.example.net",
        "assertion": "anonymous_401",
        "state": "pass",
        "vantage": "internet",
        "tool": "curl",
        "tool_version": "8.9",
        "collected_at": (utcnow() - timedelta(hours=1)).isoformat(),
    }
    body.update(overrides)
    return body


def _post(client: TestClient, token: str, **body: Any):
    payload = {"collector": "pytest", "observations": [], **body}
    return client.post(URL, json=payload, headers={"Authorization": f"Bearer {token}"})


# ---------------------------------------------------------------------------
# The vocabulary
# ---------------------------------------------------------------------------


class TestSubjects:
    @pytest.mark.parametrize(
        ("subject", "host", "port"),
        [
            ("demo.example.net", "demo.example.net", None),
            ("Demo.Example.NET:443", "demo.example.net", 443),
            ("192.168.0.14:8002", "192.168.0.14", 8002),
            ("[::1]:5432", "::1", 5432),
            ("192.168.0.0/24", "192.168.0.0/24", None),
        ],
    )
    def test_host_forms(self, subject: str, host: str, port: int | None) -> None:
        parsed = co.parse_subject(subject)
        assert (parsed.host, parsed.port) == (host, port)
        assert parsed.surface_id is None and parsed.control_id is None

    def test_surface_and_control_forms(self) -> None:
        assert co.parse_subject("surface:abc").surface_id == "abc"
        assert co.parse_subject("control:def").control_id == "def"

    @pytest.mark.parametrize(
        "subject", ["", "a b", "host:99999", "host:0", "surface:", "x" * 300, "h:p"]
    )
    def test_malformed_subjects_are_refused(self, subject: str) -> None:
        with pytest.raises(co.ObservationError):
            co.parse_subject(subject)

    def test_only_pass_and_fail_are_evidence(self) -> None:
        assert co.EVIDENCE_STATES == ("pass", "fail")
        assert set(co.STATES) == {"pass", "fail", "unknown", "not_evidence", "not_measured"}


# ---------------------------------------------------------------------------
# POST /api/ingest/control-observations
# ---------------------------------------------------------------------------


class TestIngestAuth:
    def test_no_token_is_401(self, client: TestClient) -> None:
        assert client.post(URL, json={"collector": "x", "observations": []}).status_code == 401

    def test_the_network_grant_is_required(self, client: TestClient) -> None:
        """An observation can lower a score (S5); writing one is a grant, not a
        side effect of holding any token for the repository."""
        token = issue_token(client, REPO, "sast")
        assert _post(client, token, observations=[_obs()]).status_code == 403

    def test_a_granted_repo_may_post(self, client: TestClient) -> None:
        token = issue_token(client, REPO, "network")
        response = _post(client, token, observations=[_obs()])
        assert response.status_code == 200, response.text
        assert response.json()["accepted"] == 1


class TestIngest:
    def test_rows_are_stamped_from_the_token_and_audited(self, client: TestClient) -> None:
        token = issue_token(client, REPO, "network")
        body = _post(
            client,
            token,
            collector="Publish-ControlObservations.ps1@LAB",
            observations=[_obs(), _obs(assertion="header_csp", state="fail")],
        ).json()

        assert body["accepted"] == 2
        assert body["by_state"] == {"pass": 1, "fail": 1}
        with client.app.state.db.session() as session:
            rows = session.scalars(select(ControlObservation)).all()
            assert {r.repo_full_name for r in rows} == {REPO}
            assert {r.collector for r in rows} == {"Publish-ControlObservations.ps1@LAB"}
            entry = session.scalars(
                select(AuditLogEntry).where(
                    AuditLogEntry.action == "control_observation.ingested"
                )
            ).one()
            assert entry.actor == f"ingest:{REPO}"

    def test_a_payload_cannot_name_another_repository(self, client: TestClient) -> None:
        token = issue_token(client, REPO, "network")
        response = _post(client, token, observations=[_obs(repo_full_name="other/repo")])
        assert response.status_code == 422

    @pytest.mark.parametrize(
        "bad",
        [
            {"assertion": "port_open"},
            {"state": "ok"},
            {"vantage": "cloud"},
            {"subject": "two words"},
        ],
    )
    def test_the_vocabulary_is_closed(self, client: TestClient, bad: dict[str, Any]) -> None:
        token = issue_token(client, REPO, "network")
        assert _post(client, token, observations=[_obs(**bad)]).status_code == 422

    def test_a_future_observation_is_refused(self, client: TestClient) -> None:
        token = issue_token(client, REPO, "network")
        future = (utcnow() + timedelta(days=1)).isoformat()
        assert _post(client, token, observations=[_obs(collected_at=future)]).status_code == 422

    def test_an_empty_batch_is_refused(self, client: TestClient) -> None:
        """Nothing at all is not a run that found nothing - it is no run."""
        token = issue_token(client, REPO, "network")
        assert _post(client, token).status_code == 422

    def test_a_surface_subject_must_be_this_repositorys(self, client: TestClient) -> None:
        token = issue_token(client, REPO, "network")
        with client.app.state.db.session() as session:
            mine = RepoSurface(repo_full_name=REPO, kind="entry_point", name="api")
            theirs = RepoSurface(repo_full_name="other/repo", kind="entry_point", name="x")
            session.add_all([mine, theirs])
            session.commit()
            mine_id, theirs_id = mine.id, theirs.id

        ok = _post(client, token, observations=[_obs(subject=f"surface:{mine_id}")])
        assert ok.status_code == 200, ok.text
        refused = _post(client, token, observations=[_obs(subject=f"surface:{theirs_id}")])
        assert refused.status_code == 422
        with client.app.state.db.session() as session:
            (row,) = session.scalars(select(ControlObservation)).all()
            assert row.surface_id == mine_id


class TestHostDocument:
    """The host collector posts what it read; the judging happens here, under
    test, exactly as `host_controls` judges its document."""

    def test_the_fixture_translates_to_observations(self) -> None:
        observed = co.from_host_document(_host_document())
        by = {(o.subject, o.assertion): o for o in observed}

        published = by[("lab-host:8002", "port_published")]
        assert (published.state, published.vantage) == ("pass", "host")
        assert published.evidence["container"] == "thehub-demo-backend"
        assert by[("lab-host:8002", "bound_loopback")].state == "fail"
        assert by[("lab-host:5433", "bound_loopback")].state == "pass"
        # An exposed-but-unpublished container port is published to nothing.
        assert not any(s == "lab-host:5432" for s, _ in by)

        ingress = by[("demo.example.net", "ingress_published")]
        assert ingress.state == "pass"
        assert ingress.evidence["service_port"] == 8002
        assert by[("mykronos-app.example.net", "ingress_published")].evidence[
            "service_port"
        ] == 3100

        firewall = by[("lab-host:5000", "firewall_scope")]
        assert firewall.state == "pass"
        assert firewall.tool == "host_controls"

    def test_an_unreadable_cloudflared_config_is_unknown(self) -> None:
        document = _host_document()
        document.pop("cloudflared")
        document["errors"] = {"cloudflared": "Access to the path is denied."}

        observed = co.from_host_document(document)
        ingress = [o for o in observed if o.assertion == "ingress_published"]

        assert [o.state for o in ingress] == ["unknown"]
        assert "denied" in ingress[0].detail

    def test_a_config_that_is_not_yaml_is_unknown(self) -> None:
        document = _host_document()
        document["cloudflared"]["config_text"] = "ingress: [unclosed"
        ingress = [
            o for o in co.from_host_document(document) if o.assertion == "ingress_published"
        ]
        assert [o.state for o in ingress] == ["unknown"]

    def test_a_document_that_resolves_nothing_is_unknown_never_pass(self) -> None:
        observed = co.from_host_document(
            {"schema": "mykronos.host-observations/1", "host": "LAB", "errors": {}}
        )
        assert observed, "a run that resolved nothing still records that it ran"
        assert {o.state for o in observed} == {"unknown"}
        assert {o.assertion for o in observed} >= {
            "port_published",
            "ingress_published",
            "firewall_scope",
        }

    def test_docker_unreadable_is_unknown(self) -> None:
        document = _host_document()
        document.pop("docker")
        document["errors"] = {"docker": "docker ps exited 1"}
        docker = [
            o
            for o in co.from_host_document(document)
            if o.assertion in ("port_published", "bound_loopback")
        ]
        assert {o.state for o in docker} == {"unknown"}

    def test_the_endpoint_accepts_a_host_document(self, client: TestClient) -> None:
        token = issue_token(client, REPO, "network")
        response = _post(client, token, host_document=_host_document())
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["accepted"] == len(co.from_host_document(_host_document()))
        assert body["by_state"]["pass"] >= 4


# ---------------------------------------------------------------------------
# The read
# ---------------------------------------------------------------------------


class TestLatest:
    def test_latest_per_subject_and_assertion(self, client: TestClient, admin_auth) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]
        token = issue_token(client, REPO, "network")
        old = (utcnow() - timedelta(days=20)).isoformat()
        new = (utcnow() - timedelta(hours=2)).isoformat()
        _post(
            client,
            token,
            observations=[
                _obs(state="fail", collected_at=old),
                _obs(state="pass", collected_at=new),
                _obs(assertion="header_hsts", state="pass", collected_at=old),
            ],
        )

        response = client.get(
            f"/api/dashboard/repos/{repo_id}/control-observations", headers=admin_auth
        )
        assert response.status_code == 200, response.text
        rows = {(r["subject"], r["assertion"]): r for r in response.json()["observations"]}
        assert len(rows) == 2
        current = rows[("demo.example.net", "anonymous_401")]
        assert current["state"] == "pass" and current["fresh"] is True
        assert current["is_evidence"] is True
        assert rows[("demo.example.net", "header_hsts")]["fresh"] is False
        assert response.json()["fresh_days"] == co.FRESH_DAYS


# ---------------------------------------------------------------------------
# Contradiction (surfaces.CONTRADICTED_BY)
# ---------------------------------------------------------------------------


def _surface(
    exposure: str,
    name: str,
    description: str = "",
    sid: str = "s1",
    selectors: dict[str, list[str]] | None = None,
) -> RepoSurface:
    return RepoSurface(
        id=sid,
        repo_full_name=REPO,
        kind="entry_point",
        name=name,
        description=description,
        exposure=exposure,
        selectors=selectors or {},
    )


def _row(**overrides: Any) -> ControlObservation:
    values: dict[str, Any] = {
        "repo_full_name": REPO,
        "subject": "demo.example.net",
        "assertion": "ingress_published",
        "state": "pass",
        "vantage": "host",
        "tool": "t",
        "collected_at": utcnow() - timedelta(days=1),
        "evidence": {},
    }
    values.update(overrides)
    return ControlObservation(**values)


class TestContradiction:
    def test_a_tunnel_contradicts_an_internal_port(self) -> None:
        """#348: TheHub declares `Demo backend (tcp/8002)` internal while
        cloudflared publishes that exact port."""
        surface = _surface("internal", "Demo backend (tcp/8002)")
        row = _row(evidence={"service": "http://localhost:8002", "service_port": 8002})

        found = co.contradictions([surface], [row])

        (hit,) = found["s1"]
        assert hit.source == "published_ingress"
        assert hit.assertion == "ingress_published"

    def test_a_hostname_match(self) -> None:
        surface = _surface("internal", "Demo", "served at demo.example.net")
        found = co.contradictions([surface], [_row()])
        assert found["s1"]

    def test_a_stale_observation_contradicts_nothing(self) -> None:
        surface = _surface("internal", "Demo", "demo.example.net")
        row = _row(collected_at=utcnow() - timedelta(days=co.FRESH_DAYS + 1))
        assert co.contradictions([surface], [row]) == {}

    @pytest.mark.parametrize("state", ["fail", "unknown", "not_evidence", "not_measured"])
    def test_only_a_pass_contradicts(self, state: str) -> None:
        surface = _surface("internal", "Demo", "demo.example.net")
        assert co.contradictions([surface], [_row(state=state)]) == {}

    def test_internet_reachability_contradicts_internal(self) -> None:
        surface = _surface("internal", "Demo", "demo.example.net")
        row = _row(assertion="port_published", vantage="internet", subject="demo.example.net:443")
        (hit,) = co.contradictions([surface], [row])["s1"]
        assert hit.source == "network"

    def test_a_lan_port_contradicts_local_but_not_internal(self) -> None:
        """`internal` means reachable on the LAN: a LAN scan finding the port
        open is the claim holding, not failing."""
        row = _row(assertion="port_published", vantage="lan", subject="192.168.0.14:8002")
        local = _surface("local", "Admin (tcp/8002)", sid="local")
        internal = _surface("internal", "Admin (tcp/8002)", sid="internal")

        found = co.contradictions([local, internal], [row])

        assert set(found) == {"local"}

    def test_a_host_vantage_port_contradicts_nothing(self) -> None:
        surface = _surface("local", "Admin (tcp/8002)")
        row = _row(assertion="port_published", vantage="host", subject="lab:8002")
        assert co.contradictions([surface], [row]) == {}

    def test_internet_and_unknown_are_never_contradicted(self) -> None:
        rows = [_row(evidence={"service_port": 8002})]
        for exposure in ("internet", "unknown"):
            assert co.contradictions([_surface(exposure, "Demo (tcp/8002)")], rows) == {}

    def test_a_public_hostnames_443_does_not_match_every_surface_on_443(self) -> None:
        surface = _surface("internal", "Postgres (tcp/443)")
        row = _row(assertion="port_published", vantage="internet", subject="demo.example.net:443")
        assert co.contradictions([surface], [row]) == {}

    def test_a_direct_surface_link_matches(self) -> None:
        surface = _surface("internal", "Anything")
        row = _row(subject="surface:s1", surface_id="s1")
        assert co.contradictions([surface], [row])["s1"]

    def test_a_hostname_selector_matches(self) -> None:
        surface = _surface("internal", "Demo", selectors={"hostnames": ["*.example.net"]})
        assert co.contradictions([surface], [_row()])["s1"]

    def test_an_address_selector_matches_the_service_a_tunnel_routes_to(self) -> None:
        surface = _surface("internal", "Demo", selectors={"addresses": ["*:8002"]})
        row = _row(evidence={"service": "http://localhost:8002", "service_port": 8002})
        assert co.contradictions([surface], [row])["s1"]

    def test_selectors_decide_and_the_text_is_not_consulted(self) -> None:
        """A located surface is matched by where it is, not by what its name
        happens to mention."""
        surface = _surface(
            "internal",
            "Mentions demo.example.net and tcp/8002",
            selectors={"hostnames": ["other.example.net"]},
        )
        row = _row(evidence={"service": "http://localhost:8002", "service_port": 8002})
        assert co.contradictions([surface], [row]) == {}

    def test_paths_only_selectors_still_fall_back_to_the_text(self) -> None:
        surface = _surface(
            "internal", "Demo backend (tcp/8002)", selectors={"paths": ["backend/**"]}
        )
        row = _row(evidence={"service": "http://localhost:8002", "service_port": 8002})
        assert co.contradictions([surface], [row])["s1"]

    def test_the_surfaces_api_shows_it(self, client: TestClient, admin_auth) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]
        client.post(
            f"/api/dashboard/repos/{repo_id}/surfaces",
            json={"kind": "entry_point", "name": "Demo backend (tcp/8002)", "exposure": "internal"},
            headers=admin_auth,
        )
        token = issue_token(client, REPO, "network")
        _post(client, token, host_document=_host_document() | {
            "collected_at": utcnow().isoformat() + "Z"
        })

        body = client.get(f"/api/dashboard/repos/{repo_id}/surfaces", headers=admin_auth).json()

        (surface,) = body["entry_points"]
        (hit,) = surface["contradicted_by"]
        assert hit["assertion"] == "ingress_published"
        assert hit["subject"] == "demo.example.net"
        assert hit["source"] == "published_ingress"


def test_the_api_schema_and_the_module_agree_on_the_vocabulary() -> None:
    """Two lists, pinned together, so the OpenAPI types cannot drift."""
    from typing import get_args

    from mykronos import schemas

    assert get_args(schemas.ObservationAssertion) == co.ASSERTIONS
    assert get_args(schemas.ObservationState) == co.STATES
    assert get_args(schemas.ObservationVantage) == co.VANTAGES


class TestLinking:
    """`record` fills surface_id / control_id when the subject matches a
    surface's selectors (TheHub #60825's `surface_match`)."""

    def _seed(self, client: TestClient) -> tuple[str, str]:
        with client.app.state.db.session() as session:
            surface = RepoSurface(
                repo_full_name=REPO,
                kind="entry_point",
                name="App",
                exposure="internet",
                selectors={"hostnames": ["mykronos-app.example.net"], "addresses": ["*:3100"]},
            )
            session.add(surface)
            session.flush()
            gate = RepoControl(
                repo_full_name=REPO,
                stride="spoofing",
                kind="perimeter_gate",
                applies_to_surface_id=surface.id,
            )
            session.add(gate)
            session.commit()
            return surface.id, gate.id

    def test_a_hostname_subject_links_its_surface_and_control(self, client: TestClient) -> None:
        surface_id, gate_id = self._seed(client)
        token = issue_token(client, REPO, "network")
        _post(client, token, observations=[_obs(subject="mykronos-app.example.net")])
        with client.app.state.db.session() as session:
            (row,) = session.scalars(select(ControlObservation)).all()
        assert (row.surface_id, row.control_id) == (surface_id, gate_id)

    def test_a_header_observation_links_the_surface_but_no_gate(self, client: TestClient) -> None:
        surface_id, _ = self._seed(client)
        token = issue_token(client, REPO, "network")
        _post(
            client,
            token,
            observations=[_obs(subject="mykronos-app.example.net", assertion="header_csp")],
        )
        with client.app.state.db.session() as session:
            (row,) = session.scalars(select(ControlObservation)).all()
        assert (row.surface_id, row.control_id) == (surface_id, None)

    def test_a_tunnel_rule_links_by_the_service_it_routes_to(self, client: TestClient) -> None:
        surface_id, _ = self._seed(client)
        token = issue_token(client, REPO, "network")
        _post(client, token, host_document=_host_document())
        with client.app.state.db.session() as session:
            rows = session.scalars(
                select(ControlObservation).where(ControlObservation.surface_id == surface_id)
            ).all()
        assert {r.subject for r in rows} == {"mykronos-app.example.net"}

    def test_nothing_matching_links_nothing(self, client: TestClient) -> None:
        self._seed(client)
        token = issue_token(client, REPO, "network")
        _post(client, token, observations=[_obs(subject="elsewhere.example.org")])
        with client.app.state.db.session() as session:
            (row,) = session.scalars(select(ControlObservation)).all()
        assert row.surface_id is None and row.control_id is None
