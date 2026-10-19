"""Premise monitoring (spec 33 §4, TheHub #60831, S9 of #60822).

A risk acceptance's premises are typed, checkable assertions. These pin:

* each monitored premise type reads the right observations - the right
  assertion, the right vantage, the right subject - and only fresh `pass` /
  `fail` rows count;
* stale or missing evidence is `unverified`, never `holds`;
* a failed premise takes spec 33 §4.2's path: the acceptance moves to
  `premise_failed`, every finding it covers reopens with a note naming the
  premise, the risk owner and approver are notified, and all of it is audited
  with the observation ids as evidence;
* it runs as a scheduled job and on observation ingest, and the acceptance API
  shows every premise's status with its evidence.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select

from mykronos import main
from mykronos import premise_monitor as pm
from mykronos.db.models import (
    AuditLogEntry,
    ControlObservation,
    RepoSurface,
    RiskAcceptance,
    ThreatIntelMatch,
)
from mykronos.schemas import utcnow
from tests.conftest import REPO, issue_token
from tests.test_notify import RecordingNotifier
from tests.test_risk_acceptance import IMAGE, _agent, _approve, _propose, _statuses, lake

__all__ = ["lake"]  # the fixture, re-exported so pytest finds it here

NOW = datetime(2026, 10, 18, 12, 0, 0)


def _row(
    subject: str,
    assertion: str,
    state: str = "pass",
    vantage: str = "internet",
    *,
    age_days: float = 1,
    surface_id: str | None = None,
    evidence: dict[str, Any] | None = None,
    ident: str | None = None,
) -> ControlObservation:
    return ControlObservation(
        id=ident or f"obs-{subject}-{assertion}-{state}-{vantage}",
        repo_full_name=REPO,
        subject=subject,
        assertion=assertion,
        state=state,
        vantage=vantage,
        tool="pytest",
        collected_at=NOW - timedelta(days=age_days),
        received_at=NOW - timedelta(days=age_days),
        surface_id=surface_id,
        evidence=evidence or {},
        detail="",
    )


def _facts(
    rows: list[ControlObservation] | None = None,
    *,
    hostnames: dict[str, list[str]] | None = None,
    epss: dict[str, tuple[float | None, datetime]] | None = None,
    fresh_days: int = 14,
) -> pm.Facts:
    return pm.Facts(
        observations=rows or [],
        surface_hostnames=hostnames or {},
        epss=epss or {},
        now=NOW,
        fresh_days=fresh_days,
    )


def _check(
    premise: dict[str, Any], facts: pm.Facts, cves: list[str] | None = None
) -> pm.PremiseCheck:
    return pm.evaluate(premise, facts, cves_in_scope=cves or [])


# ---------------------------------------------------------------------------
# port_not_published
# ---------------------------------------------------------------------------


class TestPortNotPublished:
    PREMISE = {"type": "port_not_published", "port": 5432}

    def test_an_internet_port_published_pass_fails_it(self) -> None:
        row = _row("db.example.net:5432", "port_published", "pass", "internet")
        check = _check(self.PREMISE, _facts([row]))
        assert check.status == "failed"
        assert check.observation_ids == [row.id]

    def test_a_lan_port_published_pass_fails_it(self) -> None:
        row = _row("192.168.0.14:5432", "port_published", "pass", "lan")
        assert _check(self.PREMISE, _facts([row])).status == "failed"

    def test_an_ingress_routing_to_the_port_fails_it(self) -> None:
        row = _row(
            "db.example.net",
            "ingress_published",
            "pass",
            "host",
            evidence={"service": "tcp://localhost:5432", "service_port": 5432},
        )
        assert _check(self.PREMISE, _facts([row])).status == "failed"

    def test_a_host_binding_beyond_loopback_fails_it(self) -> None:
        row = _row("tgb-desktop:5432", "bound_loopback", "fail", "host")
        assert _check(self.PREMISE, _facts([row])).status == "failed"

    def test_another_port_says_nothing(self) -> None:
        row = _row("db.example.net:5433", "port_published", "pass", "internet")
        check = _check(self.PREMISE, _facts([row]))
        assert check.status == "unverified"
        assert check.observation_ids == []

    def test_a_stale_failing_observation_is_unverified_not_failed(self) -> None:
        row = _row("db.example.net:5432", "port_published", "pass", "internet", age_days=20)
        check = _check(self.PREMISE, _facts([row]))
        assert check.status == "unverified"
        assert "stale" in check.reason

    def test_the_freshness_window_is_configurable(self) -> None:
        row = _row("db.example.net:5432", "port_published", "pass", "internet", age_days=20)
        assert _check(self.PREMISE, _facts([row], fresh_days=30)).status == "failed"

    def test_unknown_is_not_evidence(self) -> None:
        row = _row("db.example.net:5432", "port_published", "unknown", "internet")
        assert _check(self.PREMISE, _facts([row])).status == "unverified"

    def test_no_evidence_at_all_is_unverified_never_holds(self) -> None:
        check = _check(self.PREMISE, _facts([]))
        assert check.status == "unverified"

    def test_a_fresh_closed_port_or_loopback_binding_holds(self) -> None:
        closed = _row("192.168.0.14:5432", "port_published", "fail", "lan")
        assert _check(self.PREMISE, _facts([closed])).status == "holds"
        loopback = _row("tgb-desktop:5432", "bound_loopback", "pass", "host")
        check = _check(self.PREMISE, _facts([loopback]))
        assert check.status == "holds"
        assert check.observation_ids == [loopback.id]

    def test_a_host_vantage_publish_alone_does_not_fail_it(self) -> None:
        """Every published port answers its own host; loopback-only is the premise."""
        row = _row("tgb-desktop:5432", "port_published", "pass", "host")
        assert _check(self.PREMISE, _facts([row])).status != "failed"

    def test_failing_evidence_wins_over_holding_evidence(self) -> None:
        closed = _row("192.168.0.14:5432", "port_published", "fail", "lan")
        open_ = _row("db.example.net:5432", "port_published", "pass", "internet")
        check = _check(self.PREMISE, _facts([closed, open_]))
        assert check.status == "failed"
        assert check.observation_ids == [open_.id]

    def test_matched_by_surface(self) -> None:
        row = _row("db.example.net:443", "port_published", "pass", "internet", surface_id="s-1")
        check = _check({"type": "port_not_published", "surface_id": "s-1"}, _facts([row]))
        assert check.status == "failed"

    def test_matched_by_container(self) -> None:
        row = _row(
            "tgb-desktop:15432",
            "bound_loopback",
            "fail",
            "host",
            evidence={"container": "mykronos-concourse-db"},
        )
        check = _check(
            {"type": "port_not_published", "container": "mykronos-concourse-db"}, _facts([row])
        )
        assert check.status == "failed"

    def test_a_host_filter_narrows_the_subject(self) -> None:
        row = _row("other.example.net:5432", "port_published", "pass", "internet")
        premise = {"type": "port_not_published", "port": 5432, "host": "db.example.net"}
        assert _check(premise, _facts([row])).status == "unverified"

    def test_a_premise_naming_nothing_is_unverified(self) -> None:
        row = _row("db.example.net:5432", "port_published", "pass", "internet")
        check = _check({"type": "port_not_published"}, _facts([row]))
        assert check.status == "unverified"
        assert "names no" in check.reason


# ---------------------------------------------------------------------------
# firewall_scope
# ---------------------------------------------------------------------------


class TestFirewallScope:
    PREMISE = {"type": "firewall_scope", "port": 5000}

    def test_a_failing_scope_fails_it(self) -> None:
        row = _row("tgb-desktop:5000", "firewall_scope", "fail", "host")
        check = _check(self.PREMISE, _facts([row]))
        assert check.status == "failed"
        assert check.observation_ids == [row.id]

    def test_a_passing_scope_holds(self) -> None:
        row = _row("tgb-desktop:5000", "firewall_scope", "pass", "host")
        assert _check(self.PREMISE, _facts([row])).status == "holds"

    def test_stale_is_unverified(self) -> None:
        row = _row("tgb-desktop:5000", "firewall_scope", "pass", "host", age_days=15)
        assert _check(self.PREMISE, _facts([row])).status == "unverified"

    def test_another_assertion_says_nothing(self) -> None:
        row = _row("tgb-desktop:5000", "port_published", "pass", "lan")
        assert _check(self.PREMISE, _facts([row])).status == "unverified"


# ---------------------------------------------------------------------------
# not_internet_facing
# ---------------------------------------------------------------------------


class TestNotInternetFacing:
    PREMISE = {"type": "not_internet_facing", "hostnames": ["app.example.net"]}

    @pytest.mark.parametrize(
        ("assertion", "state", "vantage"),
        [
            ("port_published", "pass", "internet"),
            ("anonymous_401", "pass", "internet"),
            ("anonymous_401", "fail", "internet"),
            ("ingress_published", "pass", "host"),
        ],
    )
    def test_internet_evidence_fails_it(self, assertion: str, state: str, vantage: str) -> None:
        row = _row("app.example.net", assertion, state, vantage)
        check = _check(self.PREMISE, _facts([row]))
        assert check.status == "failed"
        assert check.observation_ids == [row.id]

    def test_lan_evidence_does_not(self) -> None:
        row = _row("app.example.net:443", "port_published", "pass", "lan")
        assert _check(self.PREMISE, _facts([row])).status == "unverified"

    def test_hostnames_come_from_the_surface(self) -> None:
        row = _row("app.example.net:443", "port_published", "pass", "internet")
        facts = _facts([row], hostnames={"s-1": ["app.example.net"]})
        check = _check({"type": "not_internet_facing", "surface_id": "s-1"}, facts)
        assert check.status == "failed"

    def test_a_wildcard_surface_hostname_matches(self) -> None:
        row = _row("app.example.net", "anonymous_401", "pass", "internet")
        facts = _facts([row], hostnames={"s-1": ["*.example.net"]})
        assert _check({"type": "not_internet_facing", "surface_id": "s-1"}, facts).status == (
            "failed"
        )

    def test_an_unreachable_hostname_holds(self) -> None:
        row = _row("app.example.net:443", "port_published", "fail", "internet")
        assert _check(self.PREMISE, _facts([row])).status == "holds"

    def test_stale_internet_evidence_is_unverified(self) -> None:
        row = _row("app.example.net", "anonymous_401", "pass", "internet", age_days=30)
        assert _check(self.PREMISE, _facts([row])).status == "unverified"

    def test_no_hostnames_is_unverified(self) -> None:
        check = _check({"type": "not_internet_facing"}, _facts([]))
        assert check.status == "unverified"
        assert "names no" in check.reason


# ---------------------------------------------------------------------------
# epss_below
# ---------------------------------------------------------------------------


class TestEpssBelow:
    def test_a_score_above_the_threshold_fails_it(self) -> None:
        facts = _facts(epss={"CVE-2026-1": (0.4, NOW - timedelta(days=1))})
        check = _check({"type": "epss_below", "threshold": 0.1}, facts, ["CVE-2026-1"])
        assert check.status == "failed"
        assert check.evidence[0]["cve"] == "CVE-2026-1"
        assert check.evidence[0]["epss"] == 0.4

    def test_a_score_below_holds(self) -> None:
        facts = _facts(epss={"CVE-2026-1": (0.01, NOW - timedelta(days=1))})
        assert _check({"type": "epss_below", "threshold": 0.1}, facts, ["CVE-2026-1"]).status == (
            "holds"
        )

    def test_no_score_is_unverified(self) -> None:
        facts = _facts(epss={"CVE-2026-1": (None, NOW - timedelta(days=1))})
        assert _check({"type": "epss_below", "threshold": 0.1}, facts, ["CVE-2026-1"]).status == (
            "unverified"
        )

    def test_a_cve_the_feed_never_scored_is_unverified(self) -> None:
        assert _check(
            {"type": "epss_below", "threshold": 0.1}, _facts(), ["CVE-2026-9"]
        ).status == ("unverified")

    def test_a_stale_refresh_is_unverified(self) -> None:
        facts = _facts(epss={"CVE-2026-1": (0.01, NOW - timedelta(days=40))})
        assert _check({"type": "epss_below", "threshold": 0.1}, facts, ["CVE-2026-1"]).status == (
            "unverified"
        )

    def test_the_premise_may_name_its_cves(self) -> None:
        facts = _facts(epss={"CVE-2026-7": (0.9, NOW)})
        premise = {"type": "epss_below", "threshold": 0.5, "cves": ["CVE-2026-7"]}
        assert _check(premise, facts, ["CVE-2026-1"]).status == "failed"

    def test_no_threshold_is_unverified(self) -> None:
        facts = _facts(epss={"CVE-2026-1": (0.9, NOW)})
        check = _check({"type": "epss_below"}, facts, ["CVE-2026-1"])
        assert check.status == "unverified"
        assert "threshold" in check.reason

    def test_no_cves_is_unverified(self) -> None:
        assert _check({"type": "epss_below", "threshold": 0.1}, _facts()).status == "unverified"

    def test_one_failing_cve_fails_it_even_beside_an_unknown_one(self) -> None:
        facts = _facts(epss={"CVE-2026-1": (0.9, NOW)})
        premise = {"type": "epss_below", "threshold": 0.1}
        assert _check(premise, facts, ["CVE-2026-1", "CVE-2026-2"]).status == "failed"


class TestUnmonitoredTypes:
    @pytest.mark.parametrize("kind", ["image_role", "container_command", "path_unreachable"])
    def test_a_premise_with_no_monitor_is_unverified(self, kind: str) -> None:
        check = _check({"type": kind}, _facts())
        assert check.status == "unverified"
        assert "not evaluated" in check.reason


# ---------------------------------------------------------------------------
# The §4.2 path, end to end
# ---------------------------------------------------------------------------


def _accepted(client, admin_auth, premises: list[dict[str, Any]]) -> str:
    proposed = _propose(
        client,
        _agent(client, admin_auth),
        deviation_type="risk_adjustment",
        premises=premises,
    )
    assert proposed.status_code == 201, proposed.text
    body = proposed.json()
    assert _approve(client, admin_auth, body).json()["state"] == "approved"
    return str(body["risk_acceptance"]["id"])


def _observe(client, **overrides: Any) -> Any:
    token = issue_token(client, REPO, "network")
    observation = {
        "subject": "db.example.net:5432",
        "assertion": "port_published",
        "state": "pass",
        "vantage": "internet",
        "tool": "nmap",
        "collected_at": (utcnow() - timedelta(hours=1)).isoformat(),
    }
    observation.update(overrides)
    response = client.post(
        "/api/ingest/control-observations",
        json={"collector": "pytest", "observations": [observation]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200, response.text
    return response


def _record(client, record_id: str) -> RiskAcceptance:
    with client.app.state.db.session() as session:
        record = session.get(RiskAcceptance, record_id)
        assert record is not None
        session.expunge(record)
        return record


def _audits(client, action: str) -> list[AuditLogEntry]:
    with client.app.state.db.session() as session:
        rows = list(
            session.scalars(select(AuditLogEntry).where(AuditLogEntry.action == action)).all()
        )
        for row in rows:
            session.expunge(row)
        return rows


def _run(client, notifier: RecordingNotifier | None = None) -> pm.MonitorResult:
    return asyncio.run(
        pm.run_and_notify(
            client.app.state.db,
            client.app.state.catalog,
            notifier or RecordingNotifier(),
        )
    )


PORT_PREMISE = {"type": "port_not_published", "port": 5432, "container": "postgres"}


class TestOnFailure:
    def test_a_published_port_moves_the_acceptance_to_premise_failed(
        self, client, admin_auth, lake
    ) -> None:
        record_id = _accepted(client, admin_auth, [PORT_PREMISE])
        assert _statuses(client)[("CVE-2026-1", IMAGE)][0] == "accepted_risk"
        client.app.state.notifier = RecordingNotifier()

        _observe(client)  # the ingest itself runs the monitor

        record = _record(client, record_id)
        assert record.status == "premise_failed"
        assert "port_not_published" in (record.closed_reason or "")
        # Every covered finding reopens, and nothing outside the scope moves.
        statuses = _statuses(client)
        assert statuses[("CVE-2026-1", IMAGE)][0] == "open"
        assert statuses[("CVE-2026-2", IMAGE)][0] == "open"

    def test_it_is_audited_with_the_observation_ids(self, client, admin_auth, lake) -> None:
        record_id = _accepted(client, admin_auth, [PORT_PREMISE])
        _observe(client)
        with client.app.state.db.session() as session:
            obs_id = session.scalars(select(ControlObservation.id)).one()

        [failed] = _audits(client, "risk_acceptance.premise_failed")
        assert failed.entity_id == record_id
        assert failed.actor == pm.ACTOR
        detail = failed.detail or {}
        assert detail["before"] == "active" and detail["after"] == "premise_failed"
        assert detail["observation_ids"] == [obs_id]
        assert detail["failed"][0]["type"] == "port_not_published"
        assert detail["findings_reopened"] == 2

        # The note on each finding names the premise and the evidence.
        reopened = _audits(client, "finding.reopened_by_premise")
        assert len(reopened) == 2
        for entry in reopened:
            assert entry.entity_type == "finding"
            assert (entry.detail or {})["risk_acceptance_id"] == record_id
            assert (entry.detail or {})["premises"] == ["port_not_published"]
            assert (entry.detail or {})["observation_ids"] == [obs_id]

    def test_the_risk_owner_and_approver_are_notified(self, client, admin_auth, lake) -> None:
        record_id = _accepted(client, admin_auth, [PORT_PREMISE])
        notifier = RecordingNotifier()
        client.app.state.notifier = notifier
        _observe(client)

        [note] = [n for n in notifier.sent if "premise failed" in n.title.lower()]
        assert record_id[:8] in note.detail
        assert "tgb" in note.detail  # the risk owner
        assert client.app.state.settings.admin_identity in note.detail  # the approver
        assert "port_not_published" in note.detail
        assert note.repo_full_name == REPO

    def test_a_finding_another_live_record_covers_stays_accepted(
        self, client, admin_auth, lake
    ) -> None:
        failing = _accepted(client, admin_auth, [PORT_PREMISE])
        # A second, independent decision over the same findings, resting on a
        # premise the observation does not touch.
        with client.app.state.db.session() as session:
            first = session.get(RiskAcceptance, failing)
            assert first is not None
            other = RiskAcceptance(
                repo_full_name=REPO,
                scope=first.scope,
                covered_finding_ids=list(first.covered_finding_ids),
                deviation_type="vendor_dependency",
                premises=[{"type": "no_fixed_version"}],
                status="active",
                expires_at=first.expires_at,
                risk_owner="tgb",
            )
            session.add(other)
        _observe(client)
        assert _record(client, failing).status == "premise_failed"
        assert _statuses(client)[("CVE-2026-1", IMAGE)][0] == "accepted_risk"

    def test_unverified_premises_change_nothing(self, client, admin_auth, lake) -> None:
        record_id = _accepted(client, admin_auth, [PORT_PREMISE])
        result = _run(client)
        assert result.failed == []
        assert result.unverified >= 1
        assert _record(client, record_id).status == "active"
        assert _statuses(client)[("CVE-2026-1", IMAGE)][0] == "accepted_risk"

    def test_a_stale_observation_changes_nothing(self, client, admin_auth, lake) -> None:
        record_id = _accepted(client, admin_auth, [PORT_PREMISE])
        _observe(client, collected_at=(utcnow() - timedelta(days=20)).isoformat())
        assert _record(client, record_id).status == "active"

    def test_newly_unverified_premises_are_said_once(self, client, admin_auth, lake) -> None:
        _accepted(client, admin_auth, [PORT_PREMISE])
        notifier = RecordingNotifier()
        _run(client, notifier)
        _run(client, notifier)
        unverified = [n for n in notifier.sent if "could not be verified" in n.title.lower()]
        assert len(unverified) == 1
        # A monitor result is audited when it changes, not on every run.
        assert len(_audits(client, "risk_acceptance.premise_checked")) == 1

    def test_epss_rising_above_the_threshold_fails_it(self, client, admin_auth, lake) -> None:
        record_id = _accepted(client, admin_auth, [{"type": "epss_below", "threshold": 0.2}])
        with client.app.state.db.session() as session:
            session.add(ThreatIntelMatch(cve_id="CVE-2026-1", epss_score=0.05, fetched_at=utcnow()))
            session.add(ThreatIntelMatch(cve_id="CVE-2026-2", epss_score=0.01, fetched_at=utcnow()))
        _run(client)
        assert _record(client, record_id).status == "active"

        with client.app.state.db.session() as session:
            row = session.get(ThreatIntelMatch, "CVE-2026-1")
            assert row is not None
            row.epss_score = 0.6
        result = _run(client)
        assert [f.record_id for f in result.failed] == [record_id]
        assert _record(client, record_id).status == "premise_failed"

    def test_not_internet_facing_reads_the_surface_hostnames(
        self, client, admin_auth, lake
    ) -> None:
        with client.app.state.db.session() as session:
            surface = RepoSurface(
                repo_full_name=REPO,
                kind="entry_point",
                name="app",
                exposure="internal",
                selectors={
                    "paths": [],
                    "images": [],
                    "addresses": [],
                    "hostnames": ["app.example.net"],
                },
            )
            session.add(surface)
            session.flush()
            surface_id = surface.id
        record_id = _accepted(
            client, admin_auth, [{"type": "not_internet_facing", "surface_id": surface_id}]
        )
        _observe(client, subject="app.example.net", assertion="anonymous_401", state="pass")
        assert _record(client, record_id).status == "premise_failed"


class TestTheApiShowsThePremises:
    def test_the_detail_shows_each_premise_with_evidence(self, client, admin_auth, lake) -> None:
        record_id = _accepted(
            client,
            admin_auth,
            [PORT_PREMISE, {"type": "firewall_scope", "port": 5432}],
        )
        detail = client.get(f"/api/risk-acceptances/{record_id}", headers=admin_auth).json()
        checks = detail["premise_checks"]
        assert [c["type"] for c in checks] == ["port_not_published", "firewall_scope"]
        assert {c["status"] for c in checks} == {"unverified"}
        assert detail["premise_fresh_days"] == 14

    def test_the_detail_names_failing_evidence(self, client, admin_auth, lake) -> None:
        record_id = _accepted(client, admin_auth, [{"type": "firewall_scope", "port": 5432}])
        _observe(
            client,
            subject="tgb-desktop:5432",
            assertion="firewall_scope",
            state="pass",
            vantage="host",
        )
        detail = client.get(f"/api/risk-acceptances/{record_id}", headers=admin_auth).json()
        [check] = detail["premise_checks"]
        assert check["status"] == "holds"
        [evidence] = check["evidence"]
        assert evidence["assertion"] == "firewall_scope"
        assert evidence["observation_id"]
        assert evidence["subject"] == "tgb-desktop:5432"

    def test_the_proposal_carries_the_premise_checks(self, client, admin_auth, lake) -> None:
        proposed = _propose(
            client,
            _agent(client, admin_auth),
            deviation_type="risk_adjustment",
            premises=[PORT_PREMISE],
        ).json()
        [check] = proposed["premise_checks"]
        assert check["status"] == "unverified"

    def test_scores_say_when_they_are_not_available(self, client, admin_auth, lake) -> None:
        record_id = _accepted(client, admin_auth, [PORT_PREMISE])
        detail = client.get(f"/api/risk-acceptances/{record_id}", headers=admin_auth).json()
        scores = detail["scores"]
        assert set(scores) >= {"available", "items", "total"}
        if not scores["available"]:
            assert scores["items"] == [] and scores["reason"]


class TestScoresAreFeatureDetected:
    def test_without_the_model_there_are_no_scores(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mykronos.api import risk_acceptances as api
        from mykronos.db import models

        monkeypatch.delattr(models, "EnvironmentalScore", raising=False)
        out = api.environmental_scores(None, ["f-1"])
        assert out["available"] is False
        assert out["items"] == []

    def test_with_the_model_each_score_carries_its_facts(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from types import SimpleNamespace

        from mykronos.api import risk_acceptances as api
        from mykronos.db import models

        class FakeColumn:
            def in_(self, values: Any) -> Any:
                return ("in", tuple(values))

        class FakeModel:
            finding_id = FakeColumn()

        row = SimpleNamespace(
            finding_id="f-1",
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            base=9.8,
            environmental=6.5,
            base_band="critical",
            env_band="medium",
            effective_severity="medium",
            facts_json=[{"metric": "MAV", "value": "A", "applied": True}],
            computed_at=NOW,
        )

        class FakeSession:
            def scalars(self, _stmt: Any) -> Any:
                return SimpleNamespace(all=lambda: [row])

        monkeypatch.setattr(models, "EnvironmentalScore", FakeModel, raising=False)
        monkeypatch.setattr(api, "_select_scores", lambda model, ids: ("stmt", ids))
        out = api.environmental_scores(FakeSession(), ["f-1"])
        assert out["available"] is True
        [item] = out["items"]
        assert item["base"] == 9.8 and item["environmental"] == 6.5
        assert item["facts"] == [{"metric": "MAV", "value": "A", "applied": True}]


class TestItIsScheduled:
    def test_the_job_table_runs_it_daily(self, settings, monkeypatch: pytest.MonkeyPatch) -> None:
        from fastapi.testclient import TestClient

        captured: dict[str, Any] = {}

        async def record(name: str, interval: int, job: Any, db: Any = None) -> None:
            captured[name] = (interval, job)

        calls: list[dict[str, Any]] = []

        async def fake_run(db: Any, catalog: Any, notifier: Any, **kwargs: Any) -> Any:
            calls.append(kwargs)
            return pm.MonitorResult()

        monkeypatch.setattr(main, "_every", record)
        monkeypatch.setattr(pm, "run_and_notify", fake_run)
        settings = settings.model_copy(update={"run_jobs_in_background": True})
        with TestClient(main.create_app(settings)):
            pass
        interval, job = captured["premise-monitor"]
        assert interval == 86_400
        asyncio.run(job())
        assert calls == [{"fresh_days": 14}]

    def test_a_premise_that_cannot_be_reopened_fails_the_run_loudly(
        self, client, admin_auth, lake, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        record_id = _accepted(client, admin_auth, [PORT_PREMISE])
        with client.app.state.db.session() as session:
            session.add(
                ControlObservation(
                    repo_full_name=REPO,
                    subject="db.example.net:5432",
                    assertion="port_published",
                    state="pass",
                    vantage="internet",
                    collected_at=utcnow(),
                )
            )

        def boom(*_a: Any, **_k: Any) -> Any:
            raise RuntimeError("Catalog write-write conflict")

        monkeypatch.setattr(pm.ra, "release_findings", boom)
        with pytest.raises(RuntimeError, match="could not"):
            _run(client)
        # Not half-applied: the record stays live, so the next run retries it.
        assert _record(client, record_id).status == "active"
