"""Findings in tool images are listed, not scored (#666, Oracle policy 1.12).

On 2026-10-01 the ZAP scanner image - declared `x-mykronos-role: tool` in the
demo compose, run against synthetic data - carried 30 of the mykronos
repository's 39 open highs and held its score at no_go, so every deploy needed
an override. The role was declared and derived, and stopped at the build log.
These tests follow it the rest of the way: compose -> report -> finding ->
score, and pin that nothing is guessed and nothing is hidden.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from mykronos.adapters.base import ScanContext
from mykronos.adapters.containers_trivy import normalize
from mykronos.config import get_settings
from mykronos.estate_images import annotate_reports, derive
from mykronos.oracle import OracleEngine, load_policy
from mykronos.schemas import TriggeredBy
from tests.conftest import REPO, finding_payload, post_findings, post_scan

ZAP = "ghcr.io/zaproxy/zaproxy:weekly"
PG = "postgres:15"


def _compose(root: Path) -> None:
    (root / "demo").mkdir()
    (root / "demo" / "docker-compose.yml").write_text(
        "x-mykronos-role: tool\nservices:\n  zap:\n    image: " + ZAP + "\n",
        encoding="utf-8",
    )
    (root / "docker-compose.yml").write_text(
        "services:\n  db:\n    image: " + PG + "\n", encoding="utf-8"
    )


def _report(image: str, extra: dict | None = None) -> dict:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Trivy", "version": "0.58.1", "rules": [
                    {"id": "CVE-1", "shortDescription": {"text": "CVE-1 summary"}}
                ]}},
                "results": [
                    {
                        "ruleId": "CVE-1",
                        "level": "error",
                        "message": {"text": "Package: libx\nInstalled Version: 1.0\n"
                                    "Vulnerability CVE-1\nSeverity: HIGH\nFixed Version: \n"},
                        "locations": [{"physicalLocation": {
                            "artifactLocation": {"uri": image, "uriBaseId": "ROOTPATH"},
                            "region": {"startLine": 1}}}],
                    }
                ],
                "properties": {"imageName": image, **(extra or {})},
            }
        ],
    }


def _context() -> ScanContext:
    return ScanContext(
        repo_full_name=REPO, capability="containers", tool_name="trivy",
        tool_version="0.58.1", commit_sha="a91f2c7", branch="main",
        workflow_run_id="", triggered_by=TriggeredBy.PUSH, workspace=None,
    )


class TestTheRoleReachesTheReport:
    def test_only_the_declared_tool_is_marked(self, tmp_path: Path) -> None:
        _compose(tmp_path)
        results = tmp_path / "results"
        results.mkdir()
        (results / "trivy-estate-zap.sarif").write_text(json.dumps(_report(ZAP)))
        (results / "trivy-estate-pg.sarif").write_text(json.dumps(_report(PG)))

        counts = annotate_reports(derive(tmp_path, {}), results)

        assert counts == {"reports": 2, "tool_reports": 1}
        zap = json.loads((results / "trivy-estate-zap.sarif").read_text())
        pg = json.loads((results / "trivy-estate-pg.sarif").read_text())
        assert zap["runs"][0]["properties"]["mykronosRole"] == "tool"
        assert "mykronosRole" not in pg["runs"][0]["properties"]

    def test_an_image_any_compose_runs_as_a_service_is_not_a_tool(
        self, tmp_path: Path
    ) -> None:
        """The stricter answer wins: losing a finding to a disagreement is the
        error worth avoiding."""
        _compose(tmp_path)
        (tmp_path / "other.yml").write_text(
            "services:\n  live-zap:\n    image: " + ZAP + "\n", encoding="utf-8"
        )
        (tmp_path / "docker-compose.override.yml").write_text(
            "services:\n  live-zap:\n    image: " + ZAP + "\n", encoding="utf-8"
        )
        results = tmp_path / "results"
        results.mkdir()
        (results / "trivy-estate-zap.sarif").write_text(json.dumps(_report(ZAP)))

        counts = annotate_reports(derive(tmp_path, {}), results)

        assert counts["tool_reports"] == 0


class TestTheRoleReachesTheFinding:
    def test_a_marked_report_stamps_its_findings(self) -> None:
        outcome = normalize(json.dumps(_report(ZAP, {"mykronosRole": "tool"})).encode(), _context())

        assert outcome.findings
        assert all(f.raw_finding_json.get("image_role") == "tool" for f in outcome.findings)

    def test_an_unmarked_report_stamps_nothing(self) -> None:
        outcome = normalize(json.dumps(_report(PG)).encode(), _context())

        assert all("image_role" not in f.raw_finding_json for f in outcome.findings)


@pytest.fixture
def policy():
    return load_policy(get_settings().oracle_policy_path)


def _seed(client, auth, run_compaction) -> None:
    post_scan(client, auth, scan_run_id="run-1")
    post_findings(
        client,
        auth,
        [
            finding_payload(rule_id="TOOL-1", severity="critical", symbol="t1",
                            code_snippet="t1()", raw_finding_json={"image_role": "tool"}),
            finding_payload(rule_id="TOOL-2", severity="critical", symbol="t2",
                            code_snippet="t2()", raw_finding_json={"image_role": "tool"}),
            finding_payload(rule_id="SVC-1", severity="critical", symbol="s1",
                            code_snippet="s1()", raw_finding_json={}),
        ],
        scan_run_id="run-1",
    )
    run_compaction()


class TestTheScore:
    def test_tool_findings_do_not_count_and_are_reported(
        self, client, auth, catalog, run_compaction, policy
    ) -> None:
        assert policy.exclude_tool_images is True, "the shipped policy (1.12) turns it on"
        _seed(client, auth, run_compaction)

        decision = OracleEngine(catalog, policy).evaluate(REPO)
        snapshot = decision.inputs_snapshot

        assert snapshot["findings"]["counts_by_severity"].get("critical") == 1
        tools = snapshot["decision_scope"]["tool_images"]
        assert tools["excluded"] is True
        assert tools["open_by_severity"] == {"critical": 2}
        assert "2 open finding(s) in tool images" in decision.reasoning

    def test_off_counts_everything_as_before(
        self, client, auth, catalog, run_compaction, policy
    ) -> None:
        _seed(client, auth, run_compaction)
        off = dataclasses.replace(policy, exclude_tool_images=False)

        decision = OracleEngine(catalog, off).evaluate(REPO)

        assert decision.inputs_snapshot["findings"]["counts_by_severity"].get("critical") == 3
        assert decision.inputs_snapshot["decision_scope"]["tool_images"] == {"excluded": False}
        assert "tool images" not in decision.reasoning

    def test_excluding_lowers_the_score(self, client, auth, catalog, run_compaction, policy):
        _seed(client, auth, run_compaction)

        on = OracleEngine(catalog, policy).evaluate(REPO).overall_risk_score
        off = OracleEngine(
            catalog, dataclasses.replace(policy, exclude_tool_images=False)
        ).evaluate(REPO).overall_risk_score

        assert on < off
