"""personal-soc's network lanes reach the lake, each finding naming its host
(TheHub #60813, option A decided by Todd 2026-10-21).

`external-exposure`, `netassess-ingest` and `netassess-freshness` judged the
WAN edge, the LAN and the scan's cadence, went red on what they found, and
uploaded nothing: the findings model keys on a repository and a network finding
has none. Under option A a network finding is filed against the repository that
scanned, ToddGBenson/personal-soc, and says which host in `address` and `port`.

Pinned here: what each adapter makes of what its lane writes (a check that did
not run is `unknown`, never clean); that the host survives ingestion to the
finding detail, the triage queue and an acceptance; and that an upload refused
for want of a grant is recorded as lane health, so "refused" is not read as
"never sent".
"""

from __future__ import annotations

import json
import uuid
from datetime import date, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from mykronos.adapters import ScanContext, get_adapter, network_exposure, network_netassess
from mykronos.db.models import IngestRefusal, RepoOnboarding
from mykronos.schemas import ScanStatus, Severity, asset_label
from tests.conftest import REPO, issue_token, post_findings, post_scan, scan_run_payload
from tests.test_onboarding import onboard

CONTEXT = ScanContext(
    repo_full_name="ToddGBenson/personal-soc",
    capability="network",
    tool_name="netassess",
    tool_version="",
    commit_sha="0" * 40,
    branch="main",
)

INVENTORY = (
    '"IP","MAC","Vendor","State","SSDP"\n'
    '"192.168.0.1","AA-BB-CC-00-00-01","router","Reachable",""\n'
    '"192.168.0.5","AA-BB-CC-00-00-05","Synology","Reachable",""\n'
)

NAS_PROBE = (
    "===== attempt 1 of 3\n"
    "Starting Nmap 7.95 ( https://nmap.org )\n"
    "Nmap scan report for 192.168.0.5\n"
    "PORT    STATE SERVICE\n111/tcp open  rpcbind\n"
)


def status_md(
    nfs: str = "no NFS service (port 111 closed)",
    smb: str = "SMB2/3 only",
    shares: str = "0",
    wifi: str = "no open AP",
) -> str:
    return (
        "## Network status — 2026-10-18 (local scheduled scan)\n\n"
        "- **Hosts:** 2 live (+0 / -0 vs 2026-10-11)\n"
        f"- **NAS NFS exports:** {nfs}\n"
        f"- **NAS SMB:** {smb}\n"
        f"- **NAS anonymous shares listed:** {shares}\n"
        f"- **Open Wi-Fi AP:** {wifi}\n"
        "- **WAN (external) ports visible:** 7547 (NOT allowlisted: 7547)\n"
    )


def run(**fields: Any) -> bytes:
    document = {
        "run_key": "netassess-2026.10.18.zip",
        "network_status_md": status_md(),
        "inventory_csv": INVENTORY,
        "nas_probe": NAS_PROBE,
        **fields,
    }
    return json.dumps(document).encode()


def exposure(**fields: Any) -> bytes:
    return json.dumps(fields).encode()


# --------------------------------------------------------------------------
# The asset string
# --------------------------------------------------------------------------


class TestAssetLabel:
    @pytest.mark.parametrize(
        ("address", "port", "expected"),
        [
            ("192.168.0.5", 445, "192.168.0.5:445"),
            ("192.168.0.5", None, "192.168.0.5"),
            ("fe80::1", 22, "[fe80::1]:22"),
            ("wifi:Guest", None, "wifi:Guest"),
            (None, 445, None),
            ("  ", None, None),
        ],
    )
    def test_spells_the_host(self, address: Any, port: Any, expected: str | None) -> None:
        assert asset_label(address, port) == expected


# --------------------------------------------------------------------------
# external-exposure -> shodan-internetdb
# --------------------------------------------------------------------------


class TestTheWanEdge:
    def test_each_visible_port_is_a_finding_on_the_public_ip(self) -> None:
        result = network_exposure.normalize(
            exposure(
                ip="203.0.113.7",
                ports=[7547, 443],
                cves=["CVE-2014-9222"],
                unexpected_ports=[7547],
                allowlisted_ports=[443],
            ),
            CONTEXT,
        )

        assert result.scan_status is ScanStatus.SUCCESS
        by_rule = {f.rule_id: f for f in result.findings}
        assert by_rule["wan-port-7547"].severity is Severity.MEDIUM
        assert by_rule["wan-port-7547"].address == "203.0.113.7"
        assert by_rule["wan-port-7547"].port == 7547
        assert by_rule["wan-port-443"].severity is Severity.INFO
        assert by_rule["CVE-2014-9222"].severity is Severity.INFO
        assert by_rule["CVE-2014-9222"].address == "203.0.113.7"

    def test_the_public_ip_is_never_in_a_title(self) -> None:
        """Ingestion posts loud titles to Slack; the lane keeps the IP out."""
        result = network_exposure.normalize(
            exposure(ip="203.0.113.7", ports=[7547], unexpected_ports=[7547]), CONTEXT
        )

        assert all("203.0.113.7" not in f.title for f in result.findings)

    def test_a_one_element_array_written_as_a_bare_value_still_counts(self) -> None:
        """ConvertTo-Json writes `@(7547)` as `7547`."""
        result = network_exposure.normalize(
            exposure(ip="203.0.113.7", ports=7547, unexpected_ports=7547), CONTEXT
        )

        [finding] = result.findings
        assert finding.port == 7547 and finding.severity is Severity.MEDIUM

    def test_a_port_in_neither_list_is_not_treated_as_allowlisted(self) -> None:
        result = network_exposure.normalize(exposure(ip="203.0.113.7", ports=[8080]), CONTEXT)

        [finding] = result.findings
        assert finding.severity is Severity.MEDIUM

    def test_not_indexed_is_a_clean_observation(self) -> None:
        result = network_exposure.normalize(exposure(indexed=False), CONTEXT)

        assert result.scan_status is ScanStatus.SUCCESS
        assert result.findings == []

    def test_a_lookup_that_never_happened_is_unknown_not_clean(self) -> None:
        result = network_exposure.normalize(
            exposure(check="unknown", reason="no public IP resolved"), CONTEXT
        )

        assert result.scan_status is ScanStatus.FAILURE
        assert result.findings == []
        assert "no public IP resolved" in result.warnings[0]

    def test_ports_with_no_ip_have_no_host_and_are_not_filed(self) -> None:
        result = network_exposure.normalize(exposure(ports=[22]), CONTEXT)

        assert result.findings == []
        assert result.scan_status is ScanStatus.PARTIAL_FAILURE


# --------------------------------------------------------------------------
# netassess-ingest -> netassess
# --------------------------------------------------------------------------


class TestTheLanScan:
    def test_a_clean_run_files_nothing_and_succeeds(self) -> None:
        result = network_netassess.normalize(run(), CONTEXT)

        assert result.scan_status is ScanStatus.SUCCESS
        assert result.findings == []

    def test_every_exposure_lands_on_the_nas_address(self) -> None:
        result = network_netassess.normalize(
            run(
                network_status_md=status_md(
                    nfs="EXPORTS PRESENT (/volume1/media)",
                    smb="SMBv1 ENABLED",
                    shares="2 (media, public)",
                )
            ),
            CONTEXT,
        )

        found = {(f.rule_id, f.address, f.port, f.severity) for f in result.findings}
        assert found == {
            ("nas-nfs-exports", "192.168.0.5", 2049, Severity.HIGH),
            ("nas-smbv1", "192.168.0.5", 445, Severity.HIGH),
            ("nas-anonymous-shares", "192.168.0.5", 445, Severity.MEDIUM),
        }
        assert result.scan_status is ScanStatus.SUCCESS

    def test_wan_ports_in_the_summary_are_left_to_external_exposure(self) -> None:
        result = network_netassess.normalize(run(), CONTEXT)

        assert not any(f.rule_id.startswith("wan-") for f in result.findings)

    def test_an_open_access_point_is_filed_on_its_network_name(self) -> None:
        result = network_netassess.normalize(
            run(
                network_status_md=status_md(
                    wifi="SmartLife-6A82 (served by the gateway), Cam (80% signal) OPEN - "
                    "broadcasting; neighbouring, not ours: Xfinity 20%"
                )
            ),
            CONTEXT,
        )

        assert sorted(f.address for f in result.findings) == ["wifi:Cam", "wifi:SmartLife-6A82"]
        assert {f.rule_id for f in result.findings} == {"wifi-open-ap"}

    def test_a_check_that_reported_unknown_makes_the_run_partial(self) -> None:
        """The run must not be evidence: reconciliation closes nothing on it,
        so a NAS that was off this week is not 'fixed'."""
        result = network_netassess.normalize(
            run(network_status_md=status_md(smb="unknown")), CONTEXT
        )

        assert result.scan_status is ScanStatus.PARTIAL_FAILURE
        assert any("NAS SMB: unknown" in w for w in result.warnings)

    def test_a_check_missing_from_the_summary_is_unknown_too(self) -> None:
        md = "\n".join(line for line in status_md().splitlines() if "Open Wi-Fi AP" not in line)
        result = network_netassess.normalize(run(network_status_md=md), CONTEXT)

        assert result.scan_status is ScanStatus.PARTIAL_FAILURE
        assert any("Open Wi-Fi AP: not reported" in w for w in result.warnings)

    def test_findings_from_a_partial_run_are_still_kept(self) -> None:
        result = network_netassess.normalize(
            run(
                network_status_md=status_md(nfs="unknown (port 111 filtered)", smb="SMBv1 ENABLED")
            ),
            CONTEXT,
        )

        assert [f.rule_id for f in result.findings] == ["nas-smbv1"]
        assert result.scan_status is ScanStatus.PARTIAL_FAILURE

    def test_without_the_nas_address_it_is_named_not_guessed(self) -> None:
        result = network_netassess.normalize(
            run(nas_probe=None, network_status_md=status_md(smb="SMBv1 ENABLED")), CONTEXT
        )

        [finding] = result.findings
        assert finding.address == network_netassess.NAS_FALLBACK
        assert any("rather than a guessed IP" in w for w in result.warnings)

    def test_nmap_naming_the_host_reads_the_address_in_brackets(self) -> None:
        assert network_netassess.nas_address("Nmap scan report for nas.lan (192.168.0.5)") == (
            "192.168.0.5"
        )

    def test_no_summary_is_a_failed_run(self) -> None:
        result = network_netassess.normalize(run(network_status_md=None), CONTEXT)

        assert result.scan_status is ScanStatus.FAILURE

    def test_no_inventory_is_a_failed_run_that_keeps_its_verdicts(self) -> None:
        result = network_netassess.normalize(
            run(inventory_csv="", network_status_md=status_md(smb="SMBv1 ENABLED")), CONTEXT
        )

        assert result.scan_status is ScanStatus.FAILURE
        assert [f.rule_id for f in result.findings] == ["nas-smbv1"]


# --------------------------------------------------------------------------
# netassess-freshness -> netassess-freshness
# --------------------------------------------------------------------------


class TestFreshness:
    def _check(self, **document: Any):
        return network_netassess.normalize_freshness(json.dumps(document).encode(), CONTEXT)

    def test_a_recent_run_is_healthy_and_files_nothing(self) -> None:
        result = self._check(
            keys=["netassess-2026.10.11.zip", "netassess-2026.10.18.zip"],
            max_age_days=10,
            checked_on="2026-10-21",
        )

        assert result.scan_status is ScanStatus.SUCCESS
        assert result.findings == []

    def test_a_stale_run_is_a_failed_run(self) -> None:
        result = self._check(
            keys=["netassess-2026.9.6.zip"], max_age_days=10, checked_on="2026-10-21"
        )

        assert result.scan_status is ScanStatus.FAILURE
        assert "45 days" in result.warnings[0]

    def test_an_empty_bucket_is_a_failed_run(self) -> None:
        result = self._check(keys=[], max_age_days=10, checked_on="2026-10-21")

        assert result.scan_status is ScanStatus.FAILURE

    def test_a_bucket_nobody_could_read_is_unknown(self) -> None:
        result = self._check(check="unknown", reason="the bucket could not be listed")

        assert result.scan_status is ScanStatus.FAILURE
        assert "could not be listed" in result.warnings[0]


class TestRegistry:
    @pytest.mark.parametrize(
        ("tool", "pattern"),
        [
            ("shodan-internetdb", "external-exposure.json"),
            ("netassess", "netassess-run.json"),
            ("netassess-freshness", "netassess-freshness.json"),
        ],
    )
    def test_each_lane_has_its_own_tool(self, tool: str, pattern: str) -> None:
        """Reconciliation partitions on the tool: the freshness check's empty
        result must never read as the LAN scan finding nothing."""
        assert get_adapter("network", tool).pattern == pattern


# --------------------------------------------------------------------------
# Through the API: the host reaches every surface a person decides on
# --------------------------------------------------------------------------


def _activate(client: TestClient, admin_auth: dict[str, str]) -> dict[str, str]:
    onboard(client, admin_auth, REPO)
    with client.app.state.db.session() as session:  # type: ignore[attr-defined]
        record = (
            session.execute(
                select(RepoOnboarding).where(RepoOnboarding.github_repo_full_name == REPO)
            )
            .scalars()
            .one()
        )
        record.status = "active"
    return {"Authorization": f"Bearer {issue_token(client, REPO, 'network')}"}


def _ingest_lan_run(client: TestClient, auth: dict[str, str], run_compaction) -> None:
    result = network_netassess.normalize(
        run(network_status_md=status_md(smb="SMBv1 ENABLED")), CONTEXT
    )
    scan_run_id = str(uuid.uuid4())
    response = post_scan(
        client,
        auth,
        scan_run_id=scan_run_id,
        capability="network",
        tool_name="netassess",
        pr_number=None,
        triggered_by="schedule",
        finding_count=len(result.findings),
    )
    assert response.status_code in (200, 201), response.text
    response = post_findings(
        client,
        auth,
        [f.model_dump(mode="json") for f in result.findings],
        scan_run_id=scan_run_id,
        capability="network",
    )
    assert response.status_code in (200, 201), response.text
    run_compaction()


class TestTheHostReachesEverySurface:
    def test_a_netassess_result_is_in_the_lake_with_its_host(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        """The story's acceptance criterion."""
        _ingest_lan_run(client, _activate(client, admin_auth), run_compaction)

        rows = client.app.state.catalog.query(  # type: ignore[attr-defined]
            "SELECT repo_full_name, capability, rule_id, address, port FROM findings"
        )
        assert [tuple(r) for r in rows] == [(REPO, "network", "nas-smbv1", "192.168.0.5", 445)]

    def test_the_finding_detail_names_the_host(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        _ingest_lan_run(client, _activate(client, admin_auth), run_compaction)
        [(finding_id,)] = client.app.state.catalog.query(  # type: ignore[attr-defined]
            "SELECT finding_id FROM findings"
        )

        body = client.get(f"/api/dashboard/findings/{finding_id}", headers=admin_auth).json()

        assert body["address"] == "192.168.0.5"
        assert body["port"] == 445
        assert body["asset"] == "192.168.0.5:445"

    def test_the_triage_row_names_the_host(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        _ingest_lan_run(client, _activate(client, admin_auth), run_compaction)

        items = client.get("/api/dashboard/triage", headers=admin_auth).json()["items"]

        assert [item["asset"] for item in items] == ["192.168.0.5:445"]

    def test_the_repo_findings_tab_names_the_host(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        _ingest_lan_run(client, _activate(client, admin_auth), run_compaction)
        repo_id = client.get("/api/dashboard/portfolio", headers=admin_auth).json()["repos"][0][
            "repo_id"
        ]

        page = client.get(f"/api/dashboard/repos/{repo_id}/open-findings", headers=admin_auth)

        assert page.status_code == 200, page.text
        [group] = page.json()["groups"]
        assert [loc["asset"] for loc in group["locations"]] == ["192.168.0.5:445"]

    def test_an_acceptance_names_the_host(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        _ingest_lan_run(client, _activate(client, admin_auth), run_compaction)
        [(finding_id,)] = client.app.state.catalog.query(  # type: ignore[attr-defined]
            "SELECT finding_id FROM findings"
        )
        from mykronos.db.models import RiskAcceptance

        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            session.add(
                RiskAcceptance(
                    repo_full_name=REPO,
                    deviation_type="compensating_control",
                    justification="Segmented VLAN; only the backup host can reach it.",
                    status="approved",
                    requested_by="todd",
                    expires_at=date.today() + timedelta(days=30),
                    covered_finding_ids=[finding_id],
                )
            )
        repo_id = client.get("/api/dashboard/portfolio", headers=admin_auth).json()["repos"][0][
            "repo_id"
        ]

        page = client.get(f"/api/dashboard/repos/{repo_id}/risk-acceptances", headers=admin_auth)

        assert page.status_code == 200, page.text
        [record] = page.json()["acceptances"]
        assert [f["asset"] for f in record["findings"]] == ["192.168.0.5:445"]


# --------------------------------------------------------------------------
# Refused is not never-sent
# --------------------------------------------------------------------------


class TestRefusalsAreLaneHealth:
    def test_a_refused_upload_is_recorded_every_time(self, client: TestClient) -> None:
        token = issue_token(client, REPO, "sast")
        for _ in range(3):
            response = client.post(
                "/api/ingest/scan-run",
                json=scan_run_payload(capability="network"),
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 403

        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            row = session.get(IngestRefusal, (REPO, "network"))
            assert row is not None
            assert row.refusals == 3, "recorded every time, though notified once"
            assert row.last_refused_at >= row.first_refused_at
            assert "'network' is not enabled" in row.detail

    def test_the_portfolio_tells_refused_from_never_sent(
        self, client: TestClient, admin_auth
    ) -> None:
        onboard(client, admin_auth, REPO)
        token = issue_token(client, REPO, "sast")
        client.post(
            "/api/ingest/scan-run",
            json=scan_run_payload(capability="network"),
            headers={"Authorization": f"Bearer {token}"},
        )

        [row] = client.get("/api/dashboard/portfolio", headers=admin_auth).json()["repos"]
        states = {s["capability"]: s for s in row["capability_states"]}

        assert states["network"]["refused"] is True
        assert states["network"]["last_refused_at"] is not None
        assert states["network"]["has_scanned"] is False
        # Never sent: no scan run and no refusal.
        assert states["dast"]["refused"] is False
        assert states["dast"]["last_refused_at"] is None

    def test_a_scan_accepted_after_the_refusal_clears_it(
        self, client: TestClient, admin_auth
    ) -> None:
        onboard(client, admin_auth, REPO)
        refused = issue_token(client, REPO, "sast")
        client.post(
            "/api/ingest/scan-run",
            json=scan_run_payload(capability="network"),
            headers={"Authorization": f"Bearer {refused}"},
        )
        granted = {"Authorization": f"Bearer {issue_token(client, REPO, 'network')}"}
        response = post_scan(
            client,
            granted,
            scan_run_id=str(uuid.uuid4()),
            capability="network",
            tool_name="netassess",
            finding_count=0,
        )
        assert response.status_code in (200, 201), response.text

        from mykronos.lake.compaction import compact

        compact(client.app.state.catalog, client.app.state.buffer)  # type: ignore[attr-defined]
        [row] = client.get("/api/dashboard/portfolio", headers=admin_auth).json()["repos"]
        states = {s["capability"]: s for s in row["capability_states"]}

        assert states["network"]["has_scanned"] is True
        assert states["network"]["refused"] is False
        assert states["network"]["last_refused_at"] is not None, "the history is kept"

    def test_a_database_that_cannot_record_does_not_turn_a_403_into_a_500(
        self, client: TestClient, monkeypatch
    ) -> None:
        from mykronos.api import refusals

        def broken(*_a: Any, **_k: Any) -> Any:
            raise RuntimeError("database is gone")

        monkeypatch.setattr(refusals, "IngestRefusal", broken)
        token = issue_token(client, REPO, "sast")

        response = client.post(
            "/api/ingest/scan-run",
            json=scan_run_payload(capability="network"),
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 403
