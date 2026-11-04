"""`mykronos triage-packet --for-next-sprint` (TheHub #61346, ARRI D2.6).

The pre-sprint security triage packet: the candidates the operator selects
from, each with the scanner's band and a contextual band side by side, and
every factor marked observed, declared or unknown.

Sprints are not measured in days (TheHub #61357): one starts when the operator
starts it and finishes when its work ships. So the packet is built *for the
next sprint*, never for a date, and says nothing about weekdays.

All data is synthetic: example.test hosts, documentation-range addresses.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any

import pytest

from mykronos import briefing_sources, cli, sprint_signal, triage_packet
from mykronos.briefing import Briefing
from mykronos.db.models import PublicEndpoint, ThreatIntelMatch
from mykronos.delivery_sources import BoardRead
from mykronos.lake.mutate import locate_findings, update_findings
from mykronos.schemas import utcnow
from tests.conftest import REPO, finding_payload, issue_token, post_findings, post_scan
from tests.po_support import story
from tests.test_onboarding import onboard

#: Pinned: overdue and freshness are time windows.
NOW = datetime(2031, 3, 12, 12, 0, 0)

#: Every field D2.6 requires per candidate.
CANDIDATE_FIELDS = {
    "id",
    "title",
    "repo",
    "type",
    "existing_story",
    "scanner_band",
    "contextual_band",
    "environmental_band",
    "rationale",
    "factors",
    "evidence",
    "remediation_outline",
    "mitigation",
    "tests",
    "acceptance_criteria",
    "size",
    "unknowns",
    "downgrade_needs_confirmation",
    "classification",
    "mandatory_reasons",
    "priority",
}


def _report(**overrides: Any) -> Briefing:
    values: dict[str, Any] = {"generated_at": utcnow(), "total_open": 0}
    values.update(overrides)
    return Briefing(**values)


def _post(client: Any, capability: str, findings: list[dict[str, Any]], run: str) -> None:
    auth = {"Authorization": f"Bearer {issue_token(client, REPO, capability)}"}
    post_scan(client, auth, scan_run_id=run)
    post_findings(client, auth, findings, scan_run_id=run, capability=capability)


def _container(cve: str, *, fixed: str | None = "2.0.1", **overrides: Any) -> dict[str, Any]:
    raw: dict[str, Any] = {"image": "registry.example.test/team/api:3", "PkgName": "libz"}
    if fixed is not None:
        raw["fixed_version"] = fixed
    payload = finding_payload(
        rule_id=cve,
        title=f"{cve}: libz overflow",
        severity="high",
        file_path=None,
        line_start=None,
        line_end=None,
        symbol=cve,
        code_snippet=None,
        package_name="libz",
        package_version="2.0.0",
        raw_finding_json=raw,
    )
    payload.update(overrides)
    return payload


def _build(client: Any, catalog: Any, **kwargs: Any) -> triage_packet.Packet:
    kwargs.setdefault("report", _report())
    return triage_packet.build(catalog, client.app.state.db, now=NOW, **kwargs)


def _factor(candidate: dict[str, Any], name: str) -> dict[str, Any]:
    return next(f for f in candidate["factors"] if f["name"] == name)


# ---------------------------------------------------------------------------
# The candidate fields
# ---------------------------------------------------------------------------


class TestEveryField:
    def test_each_candidate_carries_every_d26_field(
        self, client: Any, admin_auth: dict[str, str], run_compaction: Any, catalog: Any
    ) -> None:
        onboard(client, admin_auth)
        _post(client, "containers", [_container("CVE-2031-2001")], "run-f1")
        _post(client, "sast", [finding_payload(severity="medium")], "run-f2")
        run_compaction()

        packet = _build(client, catalog).to_dict()

        assert packet["candidates"], "the open findings produce candidates"
        for candidate in packet["candidates"]:
            assert CANDIDATE_FIELDS <= set(candidate), CANDIDATE_FIELDS - set(candidate)
            assert candidate["id"].startswith("C-")
            assert candidate["acceptance_criteria"]
            assert any("Production check" in c for c in candidate["acceptance_criteria"])
            for factor in candidate["factors"]:
                assert factor["state"] in ("observed", "declared", "unknown")
                assert factor["evidence"]

    def test_scanner_and_contextual_bands_sit_side_by_side(
        self, client: Any, admin_auth: dict[str, str], run_compaction: Any, catalog: Any
    ) -> None:
        onboard(client, admin_auth)
        _post(client, "containers", [_container("CVE-2031-2002")], "run-f3")
        run_compaction()
        with client.app.state.db.session() as session:
            session.add(ThreatIntelMatch(cve_id="CVE-2031-2002", in_kev=True))

        candidate = _build(client, catalog).to_dict()["candidates"][0]

        assert candidate["scanner_band"] == "high"
        assert candidate["contextual_band"] == "critical"
        assert candidate["rationale"].startswith("Scanner High → Contextual Critical")


# ---------------------------------------------------------------------------
# Unknown is unknown
# ---------------------------------------------------------------------------


class TestExploitabilityUnknown:
    def test_a_cve_never_fetched_is_exploitability_unknown_never_not_kev(
        self, client: Any, admin_auth: dict[str, str], run_compaction: Any, catalog: Any
    ) -> None:
        onboard(client, admin_auth)
        _post(client, "containers", [_container("CVE-2031-2003")], "run-u1")
        run_compaction()

        candidate = _build(client, catalog).to_dict()["candidates"][0]

        exploit = _factor(candidate, "exploitability")
        assert exploit["state"] == "unknown"
        assert "exploitability unknown" in exploit["evidence"]
        text = json.dumps(candidate).lower()
        assert "not kev" not in text
        assert "not in kev" not in text
        assert "no known exploit" not in text
        assert "exploitability" in candidate["unknowns"]

    def test_a_kev_listed_cve_is_observed_and_mandatory(
        self, client: Any, admin_auth: dict[str, str], run_compaction: Any, catalog: Any
    ) -> None:
        onboard(client, admin_auth)
        _post(client, "containers", [_container("CVE-2031-2004")], "run-u2")
        run_compaction()
        with client.app.state.db.session() as session:
            session.add(ThreatIntelMatch(cve_id="CVE-2031-2004", in_kev=True))

        candidate = _build(client, catalog).to_dict()["candidates"][0]

        assert _factor(candidate, "exploitability")["state"] == "observed"
        assert candidate["classification"] == "mandatory"
        assert any("KEV" in r for r in candidate["mandatory_reasons"])


class TestValidationSpike:
    def test_a_high_with_two_unknown_key_factors_becomes_a_spike(
        self, client: Any, admin_auth: dict[str, str], run_compaction: Any, catalog: Any
    ) -> None:
        """No CVE (no exploit intelligence), no observed exposure, no import
        analysis: three unknowns at high, so confirm before fixing."""
        onboard(client, admin_auth)
        _post(client, "sast", [finding_payload(severity="high")], "run-v1")
        run_compaction()

        candidate = _build(client, catalog).to_dict()["candidates"][0]

        assert candidate["type"] == "validation"
        assert candidate["size"] == "S"
        assert len(candidate["unknowns"]) >= 2


# ---------------------------------------------------------------------------
# Mandatory rules
# ---------------------------------------------------------------------------


class TestMandatory:
    def test_an_overdue_high_is_mandatory(
        self, client: Any, admin_auth: dict[str, str], run_compaction: Any, catalog: Any
    ) -> None:
        onboard(client, admin_auth)
        _post(client, "containers", [_container("CVE-2031-2005")], "run-m1")
        run_compaction()
        ids = [str(r[0]) for r in catalog.query("SELECT finding_id FROM findings")]
        update_findings(
            catalog, locate_findings(catalog, ids), "due_at = ?", [NOW - timedelta(days=3)]
        )

        candidate = _build(client, catalog).to_dict()["candidates"][0]

        assert candidate["classification"] == "mandatory"
        assert any("overdue" in r for r in candidate["mandatory_reasons"])

    def test_a_secret_exposure_is_mandatory(
        self, client: Any, admin_auth: dict[str, str], run_compaction: Any, catalog: Any
    ) -> None:
        onboard(client, admin_auth)
        _post(
            client,
            "secrets",
            [finding_payload(rule_id="generic-api-key", title="Generic API key",
                             severity="high", file_path="config/app.env")],
            "run-m2",
        )
        run_compaction()

        candidates = _build(client, catalog).to_dict()["candidates"]

        secret = next(c for c in candidates if "secret" in " ".join(c["mandatory_reasons"]))
        assert secret["classification"] == "mandatory"


# ---------------------------------------------------------------------------
# No fix: an operator item, never a candidate
# ---------------------------------------------------------------------------


class TestNoFix:
    def test_a_no_fix_group_is_only_an_operator_item(
        self, client: Any, admin_auth: dict[str, str], run_compaction: Any, catalog: Any
    ) -> None:
        onboard(client, admin_auth)
        _post(client, "containers", [_container("CVE-2031-2006", fixed=None)], "run-n1")
        run_compaction()

        packet = _build(client, catalog).to_dict()

        assert not packet["candidates"]
        items = [i for i in packet["operator_items"] if i["kind"] == "no_fix"]
        assert len(items) == 1
        assert len(items[0]["options"]) == 3
        assert "no_vendor_fix" in items[0]["recommendation"]
        assert "make the change" not in json.dumps(packet).lower()


# ---------------------------------------------------------------------------
# Existing stories are linked, not duplicated
# ---------------------------------------------------------------------------


class TestExistingStories:
    def test_a_briefing_signal_story_for_the_same_fix_is_linked(
        self, client: Any, admin_auth: dict[str, str], run_compaction: Any, catalog: Any
    ) -> None:
        onboard(client, admin_auth)
        _post(client, "containers", [_container("CVE-2031-2007")], "run-s1")
        run_compaction()
        first = _build(client, catalog).to_dict()["candidates"][0]
        key = sprint_signal.signal_key(REPO, "fix", first["fix_id"])
        board = BoardRead(
            stories={"backlog": [story(id=4242, title="Upgrade libz", tags=[
                sprint_signal.SIGNAL_TAG, sprint_signal.key_tag(key), f"repo:{REPO}"])]},
            as_of=utcnow(),
        )

        packet = _build(client, catalog, board=board).to_dict()

        assert len(packet["candidates"]) == 1
        assert packet["candidates"][0]["existing_story"] == 4242

    def test_without_the_board_the_link_is_not_checked(
        self, client: Any, admin_auth: dict[str, str], run_compaction: Any, catalog: Any
    ) -> None:
        onboard(client, admin_auth)
        _post(client, "containers", [_container("CVE-2031-2008")], "run-s2")
        run_compaction()

        packet = _build(client, catalog).to_dict()

        assert packet["candidates"][0]["existing_story"] is None
        assert packet["board_read"] is False
        assert "not checked" in triage_packet.render(_build(client, catalog))


# ---------------------------------------------------------------------------
# Nothing private in the output
# ---------------------------------------------------------------------------


class TestNoHostnameIpOrToken:
    def test_hosts_addresses_and_urls_never_reach_the_output(
        self, client: Any, admin_auth: dict[str, str], run_compaction: Any, catalog: Any
    ) -> None:
        onboard(client, admin_auth)
        _post(
            client,
            "dast",
            [finding_payload(
                rule_id="ZAP-10038",
                title="CSP header not set at https://staging.internal.example.test/login",
                severity="medium",
                file_path="/login",
                raw_finding_json={"instance": {"uri": "https://staging.internal.example.test/login"}},
            )],
            "run-p1",
        )
        _post(
            client,
            "network",
            [finding_payload(
                rule_id="open-port-5432",
                title="Port 5432 open on 192.0.2.44",
                severity="high",
                file_path=None,
                address="192.0.2.44",
                port=5432,
                raw_finding_json={"hostname": "db.internal.example.test"},
            )],
            "run-p2",
        )
        run_compaction()
        with client.app.state.db.session() as session:
            session.add(PublicEndpoint(url="https://app.internal.example.test",
                                       repo_full_name=REPO, label="Public app",
                                       last_status="probed", last_probed_at=NOW))
        issued = issue_token(client, REPO, "sast")

        packet = _build(client, catalog)
        text = json.dumps(packet.to_dict()) + triage_packet.render(packet)

        for private in ("example.test", "192.0.2.44", "https://", "http://", issued):
            assert private not in text, private


# ---------------------------------------------------------------------------
# The sprint model: for the next sprint, never a date
# ---------------------------------------------------------------------------


class TestForTheNextSprint:
    def test_the_packet_names_the_next_sprint_and_no_weekday(
        self, client: Any, admin_auth: dict[str, str], run_compaction: Any, catalog: Any
    ) -> None:
        onboard(client, admin_auth)
        _post(client, "sast", [finding_payload(severity="medium")], "run-w1")
        run_compaction()

        packet = _build(client, catalog)
        data, text = packet.to_dict(), triage_packet.render(packet)

        assert data["for"] == "next_sprint"
        assert "sprint" not in {k for k in data if k.startswith("sprint_date")}
        assert "# Pre-sprint security triage: for the next sprint" in text
        assert "## PO changes" in text
        for day in ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday"):
            assert day not in text

    def test_the_budget_and_mandatory_overflow_are_stated(
        self, client: Any, admin_auth: dict[str, str], run_compaction: Any, catalog: Any
    ) -> None:
        onboard(client, admin_auth)
        _post(client, "sast", [finding_payload(severity="medium")], "run-w2")
        run_compaction()

        capacity = _build(client, catalog, budget=4).to_dict()["capacity"]

        assert capacity["security_budget"] == 4
        assert "over_budget_by" in capacity


class TestTheCommand:
    def test_for_next_sprint_is_the_flag_and_a_date_is_refused(self) -> None:
        parser = cli._build_parser()
        args = parser.parse_args(["triage-packet", "--for-next-sprint", "--json"])
        assert args.for_next_sprint is True and args.json is True
        with pytest.raises(SystemExit):
            parser.parse_args(["triage-packet", "--sprint", "2031-03-13"])

    def test_it_runs_like_the_briefing_and_prints_json(
        self,
        client: Any,
        admin_auth: dict[str, str],
        settings: Any,
        run_compaction: Any,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        onboard(client, admin_auth)
        _post(client, "sast", [finding_payload(severity="medium")], "run-c1")
        run_compaction()
        monkeypatch.setattr(briefing_sources, "gather", lambda *_a: briefing_sources.OperationalInputs())
        monkeypatch.setattr(cli, "get_settings", lambda: settings)
        capsys.readouterr()

        assert cli.main(["triage-packet", "--for-next-sprint", "--json"]) == 0

        out = json.loads(capsys.readouterr().out)
        assert out["for"] == "next_sprint"
        assert out["candidates"]
