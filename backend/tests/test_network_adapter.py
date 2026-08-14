"""nmap and nuclei output to findings (spec 14 §2, §5)."""

from __future__ import annotations

import json

from mykronos.adapters.base import ScanContext
from mykronos.adapters.network_nmap import normalize
from mykronos.fingerprint import FINGERPRINT_NETWORK, compute_finding_id
from mykronos.schemas import ScanStatus, Severity

NMAP = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
  <host>
    <address addr="192.168.0.14" addrtype="ipv4"/>
    <hostnames><hostname name="lab-host" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.2p1"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="closed"/>
        <service name="http-proxy"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def context() -> ScanContext:
    return ScanContext(
        repo_full_name="home-lab",
        capability="network",
        tool_name="nmap",
        tool_version="7.94",
        commit_sha="0" * 40,
        branch="",
    )


class TestNmap:
    def _findings(self):
        return normalize(NMAP.encode(), context()).findings

    def test_only_open_ports_become_findings(self) -> None:
        ports = sorted(f.port for f in self._findings())

        assert ports == [22, 443]

    def test_a_finding_carries_its_address_and_port(self) -> None:
        """Which is what gives it identity — it has no file (spec 14 §5)."""
        ssh = next(f for f in self._findings() if f.port == 22)

        assert ssh.address == "192.168.0.14"
        assert ssh.file_path is None

    def test_a_management_port_outranks_an_ordinary_one(self) -> None:
        by_port = {f.port: f for f in self._findings()}

        assert by_port[22].severity is Severity.MEDIUM
        assert by_port[443].severity is Severity.INFO

    def test_an_open_port_is_not_called_a_vulnerability(self) -> None:
        """Ordinary ports are inventory. Recording them as anything above
        `info` would inflate every risk score with the fact that a web server
        serves web."""
        https = next(f for f in self._findings() if f.port == 443)

        assert https.severity is Severity.INFO
        assert "not by itself a vulnerability" in https.description

    def test_the_banner_is_reported_but_not_part_of_identity(self) -> None:
        """Spec 14 §5: keying on the banner would churn identity on every
        patch — exactly the event that should instead resolve the finding."""
        ssh = next(f for f in self._findings() if f.port == 22)

        assert "OpenSSH" in ssh.title
        before, _ = compute_finding_id(
            repo_full_name="home-lab",
            capability="network",
            rule_id=ssh.rule_id,
            address=ssh.address,
            port=ssh.port,
        )
        after, version = compute_finding_id(
            repo_full_name="home-lab",
            capability="network",
            rule_id=ssh.rule_id,
            address=ssh.address,
            port=ssh.port,
        )
        assert before == after
        assert version == FINGERPRINT_NETWORK

    def test_two_ports_on_one_host_are_two_findings(self) -> None:
        """The repo-level fingerprint fallback would have collapsed them into
        one, which is why the network branch is checked first."""
        ids = {
            compute_finding_id(
                repo_full_name="home-lab",
                capability="network",
                rule_id=f.rule_id,
                address=f.address,
                port=f.port,
            )[0]
            for f in self._findings()
        }

        assert len(ids) == 2

    def test_malformed_xml_is_a_partial_failure_not_a_clean_scan(self) -> None:
        result = normalize(b"<nmaprun><host", context())

        assert result.scan_status is ScanStatus.PARTIAL_FAILURE
        assert result.findings == []

    def test_an_empty_report_is_not_success(self) -> None:
        result = normalize(b"", context())

        assert result.scan_status is ScanStatus.NO_APPLICABLE_TARGETS


class TestNuclei:
    def _record(self, **overrides):
        base = {
            "template-id": "ssh-weak-algo",
            "info": {
                "name": "SSH weak key exchange",
                "severity": "high",
                "description": "Server offers a deprecated algorithm.",
            },
            "host": "192.168.0.14:22",
            "ip": "192.168.0.14",
            "matched-at": "192.168.0.14:22",
        }
        base.update(overrides)
        return json.dumps(base)

    def test_severity_is_taken_from_the_tool(self) -> None:
        result = normalize(self._record().encode(), context())

        assert result.findings[0].severity is Severity.HIGH

    def test_the_address_and_port_are_extracted(self) -> None:
        finding = normalize(self._record().encode(), context()).findings[0]

        assert (finding.address, finding.port) == ("192.168.0.14", 22)

    def test_a_url_target_still_yields_an_address(self) -> None:
        record = self._record(host="https://192.168.0.14:8443/admin", ip="")
        finding = normalize(record.encode(), context()).findings[0]

        assert (finding.address, finding.port) == ("192.168.0.14", 8443)

    def test_a_finding_with_no_address_is_skipped_not_invented(self) -> None:
        """It would have no stable identity, and keying it on a URL would make
        every path a new finding."""
        record = self._record(host="", ip="", **{"matched-at": ""})

        result = normalize(record.encode(), context())

        assert result.findings == []
        assert result.skipped == 1

    def test_several_lines_are_several_findings(self) -> None:
        blob = "\n".join(
            [self._record(), self._record(**{"template-id": "tls-expired"})]
        )

        assert len(normalize(blob.encode(), context()).findings) == 2

    def test_an_unparseable_line_does_not_lose_the_others(self) -> None:
        blob = "\n".join(["{not json", self._record()])

        result = normalize(blob.encode(), context())

        assert len(result.findings) == 1
        assert result.skipped == 1
