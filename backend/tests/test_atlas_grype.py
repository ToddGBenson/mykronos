"""grype as a second Atlas tool (mykronos#414, keel#134).

keel's `mykronos-sca` lane scans with grype and uploads `atlas`. Before this
the upload failed with "No adapter for capability 'atlas' with tool 'grype'".

The fixture is real grype 0.87.0 output (`anchore/grype:v0.87.0 dir:/src -o
sarif`) over a directory holding only

    pyyaml==5.3
    requests==2.19.0
    urllib3>=1.24.1

grype matched the two pins and skipped the open-bounded `urllib3`.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mykronos.adapters import atlas_grype
from mykronos.adapters.base import ScanContext
from mykronos.adapters.registry import get_adapter, normalize_results, supported_tools
from mykronos.capabilities import validate_config
from mykronos.fingerprint import compute_finding_id
from mykronos.guidance import _containers
from mykronos.lake import reconcile_absences
from mykronos.supply_chain import _fixed_version
from mykronos.threat_intel import extract_cve
from tests.conftest import REPO, issue_token, post_findings, post_scan
from tests.test_upload import RecordingClient, make_args

FIXTURE = Path(__file__).parent / "data" / "grype-0.87.0-requirements.sarif"
REQUIREMENTS = "pyyaml==5.3\nrequests==2.19.0\nurllib3>=1.24.1\n"


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    (tmp_path / "requirements.txt").write_text(REQUIREMENTS, encoding="utf-8")
    return tmp_path


def _ctx(workspace: Path | None = None) -> ScanContext:
    return ScanContext(
        repo_full_name="ToddGBenson/keel",
        capability="atlas",
        tool_name="grype",
        tool_version="0.87.0",
        commit_sha="a" * 40,
        branch="main",
        workspace=workspace,
    )


class TestTheRealOutput:
    def test_every_match_becomes_a_finding_with_its_package(self, workspace: Path) -> None:
        result = atlas_grype.normalize(FIXTURE.read_bytes(), _ctx(workspace))

        assert result.warnings == []
        got = {
            f.rule_id: (f.package_name, f.package_version, f.raw_finding_json["fixed_version"])
            for f in result.findings
        }
        assert got == {
            "GHSA-6757-jp84-gxfx-pyyaml": ("pyyaml", "5.3", "5.3.1"),
            "GHSA-8q59-q68h-6hv4-pyyaml": ("pyyaml", "5.3", "5.4"),
            "GHSA-9hjg-9r4m-mvj7-requests": ("requests", "2.19.0", "2.32.4"),
            "GHSA-9wx4-h78v-vm56-requests": ("requests", "2.19.0", "2.32.0"),
            "GHSA-j8r2-6x86-q33q-requests": ("requests", "2.19.0", "2.31.0"),
            "GHSA-x84v-xcm2-53pg-requests": ("requests", "2.19.0", "2.20.0"),
        }

    def test_the_path_is_repo_relative_and_severity_comes_from_the_score(
        self, workspace: Path
    ) -> None:
        result = atlas_grype.normalize(FIXTURE.read_bytes(), _ctx(workspace))
        first = next(f for f in result.findings if f.rule_id == "GHSA-6757-jp84-gxfx-pyyaml")

        # grype writes `/requirements.txt`, rooted at the scanned directory.
        assert first.file_path == "requirements.txt"
        assert first.severity.value == "critical"
        assert first.cvss_score == 9.8

    def test_the_advisory_id_is_recorded_without_the_package_suffix(self, workspace: Path) -> None:
        result = atlas_grype.normalize(FIXTURE.read_bytes(), _ctx(workspace))
        ids = {f.raw_finding_json["vulnerability_id"] for f in result.findings}
        assert "GHSA-6757-jp84-gxfx" in ids
        assert not any(i.endswith(("-pyyaml", "-requests")) for i in ids)

    def test_a_pinned_requirement_is_a_declared_pin(self, workspace: Path) -> None:
        """Same `version_basis` reading as osv-scanner, from the same manifest."""
        result = atlas_grype.normalize(FIXTURE.read_bytes(), _ctx(workspace))
        assert {f.version_basis for f in result.findings} == {"declared_pin"}

    def test_identity_is_the_package_not_line_one(self, workspace: Path) -> None:
        """grype reports every match at line 1; keying on that would merge or
        churn findings for no reason."""
        result = atlas_grype.normalize(FIXTURE.read_bytes(), _ctx(workspace))
        assert all(f.package_name for f in result.findings)
        assert not any("positional identity" in w for w in result.warnings)

    def test_the_registry_reads_it_from_a_results_directory(
        self, tmp_path: Path, workspace: Path
    ) -> None:
        results = tmp_path / "grype-results"
        results.mkdir()
        (results / "grype.sarif").write_bytes(FIXTURE.read_bytes())

        outcome = normalize_results("atlas", "grype", results, _ctx(workspace))

        assert outcome.scan_status.value == "success"
        assert len(outcome.findings) == 6


def _grype_sarif(
    *,
    rule_id: str = "GHSA-aaaa-bbbb-cccc-js-yaml",
    message: str = (
        "A high vulnerability in npm package: js-yaml, version 3.14.0 was found at: "
        "/package-lock.json"
    ),
    help_text: str = (
        "Vulnerability GHSA-aaaa-bbbb-cccc\nSeverity: high\nPackage: js-yaml\n"
        "Version: 4.1.0\nFix Version: 3.15.1, 4.3.1\nType: npm\n"
        "Location: /package-lock.json"
    ),
    purls: list[str] | None = None,
) -> bytes:
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "grype",
                            "rules": [
                                {
                                    "id": rule_id,
                                    "shortDescription": {"text": "x"},
                                    "help": {"text": help_text},
                                    "properties": {
                                        "purls": purls or [],
                                        "security-severity": "7.5",
                                    },
                                }
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": rule_id,
                            "message": {"text": message},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "/package-lock.json"},
                                        "region": {"startLine": 1},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
    ).encode()


class TestShapes:
    def test_the_results_version_beats_the_rules(self) -> None:
        """One rule per vulnerability+package, so the rule's `Version:` is one
        of possibly several. The result message is about this match."""
        (finding,) = atlas_grype.normalize(_grype_sarif(), _ctx()).findings
        assert finding.package_version == "3.14.0"

    def test_the_fix_on_the_installed_release_line_wins(self) -> None:
        (finding,) = atlas_grype.normalize(_grype_sarif(), _ctx()).findings
        assert finding.raw_finding_json["fixed_version"] == "3.15.1"

    def test_no_fix_is_recorded_as_empty_not_absent(self) -> None:
        sarif = _grype_sarif(
            help_text="Vulnerability X\nPackage: js-yaml\nVersion: 3.14.0\nFix Version: \nType: npm"
        )
        (finding,) = atlas_grype.normalize(sarif, _ctx()).findings
        assert finding.raw_finding_json["fixed_version"] == ""

    def test_the_help_text_is_the_fallback_for_the_package(self) -> None:
        (finding,) = atlas_grype.normalize(_grype_sarif(message="unrecognised"), _ctx()).findings
        assert (finding.package_name, finding.package_version) == ("js-yaml", "4.1.0")

    def test_the_purl_is_the_last_fallback(self) -> None:
        sarif = _grype_sarif(
            message="unrecognised", help_text="", purls=["pkg:npm/%40scope/thing@1.2.3"]
        )
        (finding,) = atlas_grype.normalize(sarif, _ctx()).findings
        assert (finding.package_name, finding.package_version) == ("@scope/thing", "1.2.3")

    def test_nothing_parseable_says_so(self) -> None:
        result = atlas_grype.normalize(_grype_sarif(message="?", help_text=""), _ctx())
        assert result.findings[0].package_name is None
        assert any("No grype finding carried a parseable package" in w for w in result.warnings)

    def test_a_cve_keyed_match_is_found_by_the_cve_readers(self) -> None:
        sarif = _grype_sarif(rule_id="CVE-2021-23337-lodash")
        (finding,) = atlas_grype.normalize(sarif, _ctx()).findings
        assert extract_cve(finding.rule_id, finding.title) == "CVE-2021-23337"

    def test_the_fix_reaches_guidance_and_supply_chain(self) -> None:
        (finding,) = atlas_grype.normalize(_grype_sarif(), _ctx()).findings
        raw = finding.raw_finding_json
        assert _fixed_version(json.dumps(raw)) == "3.15.1"
        assert _containers(raw)[2] == "upgrade"


class TestRegistration:
    def test_the_registry_resolves_atlas_grype(self) -> None:
        spec = get_adapter("atlas", "grype")
        assert spec.normalize is atlas_grype.normalize
        assert spec.pattern == "*.sarif"

    def test_osv_scanner_is_still_there(self) -> None:
        assert supported_tools("atlas") == ["grype", "osv-scanner"]

    def test_grype_is_a_valid_atlas_tool_in_config(self) -> None:
        assert validate_config("atlas", {"enabled_tool": "grype"})["enabled_tool"] == "grype"


class TestUpload:
    def test_an_atlas_grype_upload_posts_normalised_findings(
        self, tmp_path: Path, workspace: Path
    ) -> None:
        """The step keel's lane runs, end to end against a recording client:
        the exact call that raised LookupError before."""
        results = tmp_path / "grype-results"
        results.mkdir()
        (results / "grype.sarif").write_bytes(FIXTURE.read_bytes())
        client = RecordingClient()

        from mykronos.upload import upload

        outcome = upload(
            make_args(
                results,
                workspace,
                capability="atlas",
                tool="grype",
                tool_version="0.87.0",
                repo="ToddGBenson/keel",
            ),
            client=client,
        )

        assert outcome.findings_accepted == 6
        (body,) = client.bodies_for("/api/ingest/findings")
        assert body["capability"] == "atlas"
        assert {(f["package_name"], f["package_version"]) for f in body["findings"]} == {
            ("pyyaml", "5.3"),
            ("requests", "2.19.0"),
        }
        assert all(f["raw_finding_json"]["fixed_version"] for f in body["findings"])
        assert client.bodies_for("/api/ingest/scan-run")[0]["tool_name"] == "grype"


def _atlas_scan(client, token: str, run_id: str, tool: str, findings: list) -> None:
    headers = {"Authorization": f"Bearer {token}"}
    post_scan(
        client,
        headers,
        scan_run_id=run_id,
        capability="atlas",
        tool_name=tool,
        branch="main",
        scan_status="success",
    )
    post_findings(client, headers, findings, scan_run_id=run_id, capability="atlas")


def _dependency(rule_id: str, title: str) -> dict:
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": "high",
        "file_path": "requirements.txt",
        "line_start": 1,
        "package_name": "pyyaml",
        "package_version": "5.3",
        "raw_finding_json": {"ruleId": rule_id},
    }


class TestToolsDoNotCloseEachOther:
    """Reconciliation partitions on (repo, capability, branch, tool_name), so
    two scans by one atlas tool say nothing about the other's findings."""

    def test_two_grype_runs_do_not_close_an_osv_scanner_finding(
        self, client, catalog, run_compaction
    ) -> None:
        token = issue_token(client, REPO, "atlas")
        _atlas_scan(
            client, token, "osv-1", "osv-scanner", [_dependency("GHSA-6757-jp84-gxfx", "osv")]
        )
        run_compaction()
        _atlas_scan(client, token, "grype-1", "grype", [])
        run_compaction()
        _atlas_scan(client, token, "grype-2", "grype", [])
        run_compaction()

        reconcile_absences(catalog)

        assert dict(catalog.query("SELECT title, status FROM findings")) == {"osv": "open"}

    def test_two_osv_scanner_runs_do_not_close_a_grype_finding(
        self, client, catalog, run_compaction
    ) -> None:
        token = issue_token(client, REPO, "atlas")
        _atlas_scan(
            client, token, "grype-1", "grype", [_dependency("GHSA-6757-jp84-gxfx-pyyaml", "grype")]
        )
        run_compaction()
        _atlas_scan(client, token, "osv-1", "osv-scanner", [])
        run_compaction()
        _atlas_scan(client, token, "osv-2", "osv-scanner", [])
        run_compaction()

        reconcile_absences(catalog)

        assert dict(catalog.query("SELECT title, status FROM findings")) == {"grype": "open"}

    def test_grype_can_still_close_its_own(self, client, catalog, run_compaction) -> None:
        token = issue_token(client, REPO, "atlas")
        _atlas_scan(
            client, token, "grype-1", "grype", [_dependency("GHSA-6757-jp84-gxfx-pyyaml", "grype")]
        )
        run_compaction()
        _atlas_scan(client, token, "grype-2", "grype", [])
        run_compaction()
        _atlas_scan(client, token, "grype-3", "grype", [])
        run_compaction()

        reconcile_absences(catalog)

        assert dict(catalog.query("SELECT title, status FROM findings")) == {"grype": "fixed"}

    def test_the_same_advisory_from_both_tools_is_two_findings(self) -> None:
        """grype's rule id carries the package suffix, so its finding id never
        collides with osv-scanner's for the same advisory and package."""
        common = {"repo_full_name": REPO, "capability": "atlas", "package_name": "pyyaml"}
        osv, _ = compute_finding_id(rule_id="GHSA-6757-jp84-gxfx", **common)
        grype, _ = compute_finding_id(rule_id="GHSA-6757-jp84-gxfx-pyyaml", **common)
        assert osv != grype
