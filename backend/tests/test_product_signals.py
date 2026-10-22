"""Product-specific signals in the per-product briefing (TheHub #60863).

The acceptance criterion: each product block has at least its listed signals
or a stated "not measurable yet". So every product has a test that every
listed signal is present, and each source has a measured test and a "could
not read" or "not measurable yet" one. TheHub is `FakeHub` behind
`httpx2.MockTransport`.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import httpx2
import pytest

from mykronos import briefing_sources, delivery_sources, product_signals
from mykronos.db.models import AuditLogEntry, ControlObservation, NetassessRun
from mykronos.lake.mutate import locate_findings, update_findings
from mykronos.schemas import utcnow
from tests.conftest import finding_payload, issue_token, post_findings, post_scan
from tests.po_support import FakeHub, attach_hub
from tests.po_support import onboard as onboard_repo
from tests.test_daily_briefing import _everything_read, _get, _section

THEHUB = "ToddGBenson/TheHub"
MYKRONOS = "ToddGBenson/mykronos"
PSOC = "ToddGBenson/personal-soc"
KEEL = "ToddGBenson/keel"
BINNACLE = "ToddGBenson/binnacle"


@pytest.fixture(autouse=True)
def _fresh_cache() -> Any:
    delivery_sources.clear_cache()
    product_signals.clear_cache()
    yield
    delivery_sources.clear_cache()
    product_signals.clear_cache()


@pytest.fixture
def gathered(monkeypatch: pytest.MonkeyPatch) -> None:
    inputs = _everything_read()
    monkeypatch.setattr(briefing_sources, "gather", lambda *_args: inputs)


def _signals(client: Any, admin_auth: dict[str, str], repo: str) -> dict[str, Any]:
    repo_id = onboard_repo(client, repo)
    return _section(_get(client, admin_auth, repo_id=repo_id), "product_signals")


def _by_key(section: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {s["key"]: s for s in section["data"]["signals"]}


def _ingest(client: Any, repo: str, run_id: str, *, findings: list[dict[str, Any]] | None = None,
            **overrides: Any) -> None:
    headers = {"Authorization": f"Bearer {issue_token(client, repo, 'sast')}"}
    response = post_scan(client, headers, scan_run_id=run_id, repo_full_name=repo, **overrides)
    assert response.status_code in (200, 201, 202), response.text
    if findings:
        post_findings(client, headers, findings, scan_run_id=run_id)


class SignalHub(FakeHub):
    """`FakeHub`, answering the read routes the TheHub signals use."""

    def __init__(self) -> None:
        super().__init__([])
        self.dashboard["last_7d_outcomes"] = {"success": 8, "failed": 2}
        self.routes: dict[str, Any] = {
            product_signals.USAGE: {"daily_trend": {"series": [
                {"date": f"2026-10-{d:02d}", "total_cost_usd": 1.5, "total_requests": 10}
                for d in range(8, 22)
            ]}},
            product_signals.SCHEDULER: [
                {"job_name": "freshness_sweep", "last_status": "success",
                 "failure_count_7d": 0, "total_runs_7d": 7},
                {"job_name": "garmin_sync", "last_status": "failed",
                 "failure_count_7d": 3, "total_runs_7d": 7},
            ],
            product_signals.BACKUPS: {"healthy": False, "total_backups": 4,
                                      "latest_backup": {"age_hours": 50.0},
                                      "verification": {"status": "fail"}},
            product_signals.CONTRACTS: [
                {"id": 1, "domain": "health", "field_name": "steps"},
                {"id": 2, "domain": "finance", "field_name": "balance"},
            ],
            f"{product_signals.CONTRACTS}/1/runs": [{"status": "ok", "age_minutes": 5}],
            f"{product_signals.CONTRACTS}/2/runs": [{"status": "breach", "age_minutes": 9000}],
        }

    def handler(self, request: httpx2.Request) -> httpx2.Response:
        if request.method == "GET" and request.url.path in self.routes:
            self.calls.append(("GET", request.url.path, None))
            if request.url.path in self.failing:
                return httpx2.Response(500, json={"detail": "boom"})
            return httpx2.Response(200, json=self.routes[request.url.path])
        return super().handler(request)


# ---------------------------------------------------------------------------
# Every product carries every listed signal
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("repo", [THEHUB, MYKRONOS, PSOC, KEEL, BINNACLE])
def test_every_listed_signal_is_on_the_page(client, admin_auth, gathered, repo: str) -> None:
    section = _signals(client, admin_auth, repo)

    product = product_signals.product_of(repo)
    assert product is not None
    expected = [key for key, _ in product_signals.EXPECTED[product]]
    assert [s["key"] for s in section["data"]["signals"]] == expected
    for signal in section["data"]["signals"]:
        assert signal["status"] in ("measured", "not_measurable", "unavailable")
        assert signal["source"], signal["key"]
        if signal["status"] == "measured":
            assert signal["value"], signal["key"]
        else:
            assert signal["reason"], signal["key"]
            assert signal["label"] in section["reason"], signal["key"]
        if signal["status"] == "not_measurable":
            assert signal["reason"].startswith("not measurable yet: ")
    if section["status"] != "ok":
        assert section["reason"]


def test_a_product_without_signals_says_so(client, admin_auth, gathered) -> None:
    section = _signals(client, admin_auth, "example-org/payments-api")
    assert section["status"] == "not_available"
    assert "No product-specific signals" in section["reason"]
    assert section["data"]["signals"] == []


def test_product_names_match_case_insensitively() -> None:
    assert product_signals.product_of("ToddGBenson/TheHub") == "thehub"
    assert product_signals.product_of("someone/Binnacle") == "binnacle"
    assert product_signals.product_of("o/keel-template") is None


# ---------------------------------------------------------------------------
# TheHub
# ---------------------------------------------------------------------------


class TestTheHub:
    def test_measured_from_thehubs_read_routes(self, client, admin_auth, gathered) -> None:
        hub = SignalHub()
        attach_hub(client, hub)

        section = _signals(client, admin_auth, THEHUB)
        signals = _by_key(section)

        assert section["status"] == "partial"
        assert signals["feature_use"]["status"] == "not_measurable"
        assert "Not measurable yet: Feature use" in section["reason"]
        agents = signals["agent_run_success"]
        assert agents["status"] == "measured"
        assert agents["detail"]["succeeded"] == 8 and agents["detail"]["total"] == 10
        spend = signals["ai_gateway_spend"]
        assert spend["detail"]["usd_7d"] == 10.5
        assert spend["detail"]["usd_today"] == 1.5
        scheduler = signals["scheduler_failures"]
        assert [j["job_name"] for j in scheduler["detail"]["failing"]] == ["garmin_sync"]
        freshness = signals["data_freshness"]
        assert freshness["detail"]["outside_limit"][0]["contract"] == "finance.balance"
        assert signals["backups"]["detail"]["healthy"] is False

        whats = [line["what"] for line in section["lines"]]
        assert any("garmin_sync" in w for w in whats)
        assert any("backups are not healthy" in w for w in whats)
        assert any("finance.balance" in w for w in whats)
        assert all(line["work"] in ("story", "decision") for line in section["lines"])

    def test_not_connected_is_unavailable_never_all_clear(
        self, client, admin_auth, gathered
    ) -> None:
        section = _signals(client, admin_auth, THEHUB)
        signals = _by_key(section)
        for key in ("agent_run_success", "ai_gateway_spend", "scheduler_failures",
                    "data_freshness", "backups"):
            assert signals[key]["status"] == "unavailable"
            assert "TheHub is not connected" in signals[key]["reason"]
        assert "Could not read:" in section["reason"]

    def test_a_route_thehub_does_not_serve_is_not_measurable(
        self, client, admin_auth, gathered
    ) -> None:
        hub = SignalHub()
        del hub.routes[product_signals.BACKUPS]
        attach_hub(client, hub)

        backups = _by_key(_signals(client, admin_auth, THEHUB))["backups"]

        assert backups["status"] == "not_measurable"
        assert "404" in backups["reason"]

    def test_one_failed_read_loses_one_signal(self, client, admin_auth, gathered) -> None:
        hub = SignalHub()
        hub.failing.add(product_signals.SCHEDULER)
        attach_hub(client, hub)

        signals = _by_key(_signals(client, admin_auth, THEHUB))

        assert signals["scheduler_failures"]["status"] == "unavailable"
        assert "HTTP 500" in signals["scheduler_failures"]["reason"]
        assert signals["backups"]["status"] == "measured"

    def test_cached_between_loads(self, client, admin_auth, gathered) -> None:
        hub = SignalHub()
        attach_hub(client, hub)
        repo_id = onboard_repo(client, THEHUB)
        _get(client, admin_auth, repo_id=repo_id)
        asked = len(hub.calls)
        _get(client, admin_auth, repo_id=repo_id)
        assert len([c for c in hub.calls[asked:] if c[1] == product_signals.BACKUPS]) == 0


# ---------------------------------------------------------------------------
# MyKronos
# ---------------------------------------------------------------------------


class TestMyKronos:
    def test_estate_signals_from_the_lake_and_audit_log(
        self, client, admin_auth, gathered, run_compaction, catalog
    ) -> None:
        onboard_repo(client, KEEL)
        _ingest(client, MYKRONOS, "run-m1", findings=[
            finding_payload(),
            finding_payload(rule_id="CWE-79", file_path="b.py", line_start=2),
            finding_payload(rule_id="CWE-22", file_path="c.py", line_start=3),
        ])
        _ingest(client, MYKRONOS, "run-m2", scan_status="failure")
        run_compaction()
        ids = sorted(str(r[0]) for r in catalog.query("SELECT finding_id FROM findings"))
        now = utcnow()
        update_findings(catalog, locate_findings(catalog, ids[:1]),
                        "status = ?, resolved_at = ?, first_seen_at = ?",
                        ["fixed", now - timedelta(hours=1), now - timedelta(days=3)])
        update_findings(catalog, locate_findings(catalog, ids[1:2]),
                        "status = ?, resolved_at = ?",
                        ["false_positive", now - timedelta(hours=1)])
        with client.app.state.db.session() as session:
            session.add(AuditLogEntry(actor="job:premise-monitor",
                                      action="risk_acceptance.premise_failed",
                                      entity_type="risk_acceptance", entity_id="ra-1"))
            session.commit()

        section = _signals(client, admin_auth, MYKRONOS)
        signals = _by_key(section)

        assert signals["ingestion_success"]["detail"]["by_status"]["success"] >= 1
        freshness = signals["scan_freshness"]
        assert freshness["status"] == "measured"
        assert {s["repo_full_name"] for s in freshness["detail"]["stale"]} == {KEEL}
        assert any(KEEL in line["what"] for line in section["lines"])
        assert signals["premise_transitions"]["detail"]["premise_failed_7d"] == 1
        fp = signals["false_positive_rate"]
        assert fp["detail"]["closed_30d"] == 2 and fp["detail"]["false_positive_30d"] == 1
        assert signals["time_to_close"]["detail"]["median_days"] == 3.0
        shadow = signals["oracle_shadow_agreement"]
        assert shadow["status"] == "not_measurable"
        assert "environmental shadow verdict" in shadow["reason"]

    def test_no_fix_means_time_to_close_is_not_measurable(
        self, client, admin_auth, gathered
    ) -> None:
        signals = _by_key(_signals(client, admin_auth, MYKRONOS))
        assert signals["time_to_close"]["status"] == "not_measurable"
        assert signals["ingestion_success"]["value"] == "No scan runs ingested in 7 days."

    def test_an_unreadable_lake_is_unavailable_per_signal(self, db_like) -> None:
        class _Broken:
            def query(self, *_args: Any) -> Any:
                raise RuntimeError("io")

        signals, _ = product_signals.mykronos_signals(_Broken(), db_like, now=utcnow())  # type: ignore[arg-type]
        by_key = {s.key: s for s in signals}
        for key in ("ingestion_success", "scan_freshness", "oracle_shadow_agreement",
                    "false_positive_rate", "time_to_close"):
            assert by_key[key].status == "unavailable"
            assert "RuntimeError" in by_key[key].reason
        assert by_key["premise_transitions"].status == "measured"


@pytest.fixture
def db_like(client: Any) -> Any:
    return client.app.state.db


# ---------------------------------------------------------------------------
# personal-soc
# ---------------------------------------------------------------------------


class TestPersonalSoc:
    def test_hosts_ports_and_scan_age(self, client, admin_auth, gathered) -> None:
        now = utcnow()
        with client.app.state.db.session() as session:
            session.add(NetassessRun(repo_full_name=PSOC, run_key="netassess-2026.9.1.zip",
                                     run_date=now - timedelta(days=20), believable=True))
            for subject, days_ago in (("192.168.0.10:22", 30), ("192.168.0.77:80", 2)):
                session.add(ControlObservation(
                    repo_full_name=PSOC, subject=subject, assertion="port_published",
                    state="pass", vantage="lan", collected_at=now - timedelta(days=days_ago)))
            session.add(ControlObservation(
                repo_full_name=PSOC, subject="home.example:8443", assertion="port_published",
                state="pass", vantage="internet", collected_at=now - timedelta(hours=3)))
            session.add(ControlObservation(
                repo_full_name=PSOC, subject="home.example:443", assertion="port_published",
                state="pass", vantage="internet", surface_id="s-1",
                collected_at=now - timedelta(hours=3)))
            session.commit()

        section = _signals(client, admin_auth, PSOC)
        signals = _by_key(section)

        assert signals["new_lan_hosts"]["detail"]["new_7d"] == ["192.168.0.77"]
        assert signals["wan_ports"]["detail"]["not_on_allowlist"] == ["home.example:8443"]
        assert signals["scan_age"]["detail"]["age_days"] == 20
        assert signals["nas_posture"]["status"] == "not_measurable"
        assert signals["nas_posture"]["detail"] == {"last_run_believable": True}
        works = {line["what"]: line["work"] for line in section["lines"]}
        assert any("new host" in w and k == "decision" for w, k in works.items())
        assert any("home.example:8443" in w and k == "decision" for w, k in works.items())
        assert any("20 day(s) old" in w and k == "story" for w, k in works.items())

    def test_nothing_recorded_is_not_measurable(self, client, admin_auth, gathered) -> None:
        signals = _by_key(_signals(client, admin_auth, PSOC))
        for key in ("new_lan_hosts", "wan_ports", "nas_posture", "scan_age"):
            assert signals[key]["status"] == "not_measurable", key


# ---------------------------------------------------------------------------
# keel and binnacle
# ---------------------------------------------------------------------------


class TestKeel:
    def test_scanner_versions_against_the_estate(
        self, client, admin_auth, gathered, run_compaction
    ) -> None:
        _ingest(client, KEEL, "run-k1", tool_name="semgrep", tool_version="1.80.0")
        _ingest(client, MYKRONOS, "run-m1", tool_name="semgrep", tool_version="1.95.0")
        run_compaction()

        section = _signals(client, admin_auth, KEEL)
        signals = _by_key(section)

        tools = signals["scanner_versions"]["detail"]["tools"]
        assert tools == [{"capability": "sast", "tool": "semgrep", "version": "1.80.0",
                          "estate_newest": "1.95.0"}]
        assert any("semgrep 1.80.0" in line["what"] for line in section["lines"])
        assert signals["template_drift"]["status"] == "not_measurable"


class TestBinnacle:
    def test_volume_and_gaps(self, client, admin_auth, gathered, run_compaction) -> None:
        old = (utcnow() - timedelta(days=5)).isoformat()
        _ingest(client, BINNACLE, "run-b1", started_at=old, finding_count=4)
        run_compaction()

        signals = _by_key(_signals(client, admin_auth, BINNACLE))

        volume = signals["ingestion_volume"]
        assert volume["detail"]["runs"] == 1
        gaps = signals["ingestion_gaps"]["detail"]["gaps"]
        assert gaps and gaps[-1]["days"] >= product_signals.GAP_DAYS

    def test_never_ingested(self, client, admin_auth, gathered) -> None:
        signals = _by_key(_signals(client, admin_auth, BINNACLE))
        assert signals["ingestion_volume"]["detail"]["runs"] == 0
        assert signals["ingestion_gaps"]["detail"]["hours_since_last"] is None
