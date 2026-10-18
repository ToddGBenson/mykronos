"""[#712] Container findings on an end-of-life base OS.

A finding on Debian 10 has no fixed version, and was filed with the rest of
the "no published fix" findings, whose advice is a `no_vendor_fix` acceptance
that re-opens when a vendor ships. For an end-of-life release no vendor ever
will: the fix is the base image.

The fixtures under `tests/data/trivy/` are real Trivy 0.73.0 output for
`debian:buster-slim` (JSON trimmed to the fields read; SARIF unchanged). They
pin the field name -- `Metadata.OS.EOSL` -- and the fact that Trivy's SARIF
carries no OS block, which is why the JSON's is stamped onto it.
"""

from __future__ import annotations

import dataclasses
import json
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import pytest

from mykronos import briefing, guidance
from mykronos import risk_acceptance as ra
from mykronos.adapters import containers_trivy
from mykronos.adapters.base import ScanContext
from mykronos.db.models import AuditLogEntry
from tests.conftest import REPO, issue_token
from tests.test_onboarding import onboard

DATA = Path(__file__).parent / "data" / "trivy"
IMAGE = "debian:buster-slim"


def _json() -> dict[str, Any]:
    return json.loads((DATA / "debian10-eosl.json").read_text(encoding="utf-8"))


def _sarif() -> dict[str, Any]:
    return json.loads((DATA / "debian10.sarif").read_text(encoding="utf-8"))


def _ctx() -> ScanContext:
    return ScanContext(
        repo_full_name=REPO,
        capability="containers",
        tool_name="trivy",
        tool_version="0.73.0",
        commit_sha="a" * 40,
        branch="main",
    )


def _stamped() -> dict[str, Any]:
    sarif = _sarif()
    assert containers_trivy.annotate_base_os(sarif, _json())
    return sarif


def _normalize(sarif: dict[str, Any]):
    return containers_trivy.normalize(json.dumps(sarif).encode(), _ctx())


# ---------------------------------------------------------------------------
# The field, verified against real output
# ---------------------------------------------------------------------------


class TestTrivyOutput:
    def test_the_json_names_the_end_of_life_as_metadata_os_eosl(self) -> None:
        assert _json()["Metadata"]["OS"] == {"Family": "debian", "Name": "10.13", "EOSL": True}

    def test_the_sarif_carries_no_os_block(self) -> None:
        # Why the stamp exists at all.
        properties = _sarif()["runs"][0]["properties"]
        assert properties["imageName"] == IMAGE
        assert not any("os" in key.lower() for key in properties)


# ---------------------------------------------------------------------------
# Stamping
# ---------------------------------------------------------------------------


class TestAnnotate:
    def test_copies_metadata_os_onto_the_matching_run(self) -> None:
        sarif = _stamped()
        assert sarif["runs"][0]["properties"]["trivyOs"]["EOSL"] is True

    def test_another_images_report_does_not_stamp(self) -> None:
        report = _json()
        report["ArtifactName"] = "postgres:15"
        assert not containers_trivy.annotate_base_os(_sarif(), report)

    def test_a_report_with_no_os_writes_nothing(self) -> None:
        report = _json()
        del report["Metadata"]["OS"]
        sarif = _sarif()
        assert not containers_trivy.annotate_base_os(sarif, report)
        assert "trivyOs" not in sarif["runs"][0]["properties"]

    def test_the_cli_stamps_in_place_and_never_fails(self, tmp_path: Path) -> None:
        sarif = tmp_path / "trivy.sarif"
        report = tmp_path / "trivy.json"
        sarif.write_text(json.dumps(_sarif()), encoding="utf-8")
        report.write_text(json.dumps(_json()), encoding="utf-8")
        assert containers_trivy.main(["--sarif", str(sarif), "--trivy-json", str(report)]) == 0
        written = json.loads(sarif.read_text(encoding="utf-8"))
        assert written["runs"][0]["properties"]["trivyOs"]["Name"] == "10.13"
        missing = str(tmp_path / "missing.json")
        assert containers_trivy.main(["--sarif", str(sarif), "--trivy-json", missing]) == 0


# ---------------------------------------------------------------------------
# The adapter
# ---------------------------------------------------------------------------


class TestAdapter:
    def test_os_findings_without_a_fix_are_tagged(self) -> None:
        result = _normalize(_stamped())
        assert len(result.findings) == 2
        for finding in result.findings:
            assert finding.raw_finding_json["base_os_eol"] is True
            assert finding.raw_finding_json["base_os"] == "debian 10.13"
        [note] = [w for w in result.warnings if "#712" in w]
        assert IMAGE in note and "debian 10.13" in note and "2 finding(s)" in note

    def test_unstamped_report_is_not_guessed_at(self) -> None:
        # The package versions say `+deb10u2` plainly. No table, no inference:
        # without Trivy's own statement nothing is tagged.
        result = _normalize(_sarif())
        assert result.findings
        assert not any("base_os_eol" in f.raw_finding_json for f in result.findings)

    @pytest.mark.parametrize("eosl", [False, None, "true"])
    def test_only_an_explicit_true_counts(self, eosl: object) -> None:
        sarif = _stamped()
        sarif["runs"][0]["properties"]["trivyOs"]["EOSL"] = eosl
        assert not any("base_os_eol" in f.raw_finding_json for f in _normalize(sarif).findings)

    def test_a_finding_with_a_fixed_version_is_not_tagged(self) -> None:
        sarif = _stamped()
        result = sarif["runs"][0]["results"][0]
        result["message"]["text"] = result["message"]["text"].replace(
            "Fixed Version: ", "Fixed Version: 5.3.28+dfsg1-0.5+deb10u1"
        )
        tagged = [
            f.package_name
            for f in _normalize(sarif).findings
            if f.raw_finding_json.get("base_os_eol")
        ]
        assert tagged == ["zlib1g"]

    def test_a_language_package_in_the_image_is_not_tagged(self) -> None:
        sarif = _stamped()
        for result in sarif["runs"][0]["results"]:
            location = result["locations"][0]["physicalLocation"]["artifactLocation"]
            location["uri"] = "usr/local/lib/python3.12/site-packages/x/METADATA"
        assert not any("base_os_eol" in f.raw_finding_json for f in _normalize(sarif).findings)


# ---------------------------------------------------------------------------
# Remediation text
# ---------------------------------------------------------------------------


def _eol_raw() -> dict[str, Any]:
    return {
        "message": {
            "text": "Package: zlib1g\nInstalled Version: 1:1.2.11.dfsg-1+deb10u2\nFixed Version: "
        },
        "image": IMAGE,
        "base_os_eol": True,
        "base_os": "debian 10.13",
    }


class TestRemediation:
    def test_names_the_base_image_not_the_package_fix(self) -> None:
        fix, source, effort = guidance._containers(_eol_raw())
        assert "debian 10.13 is end-of-life" in fix and IMAGE in fix
        assert "base image" in fix
        assert "accept with" not in fix  # not the no_vendor_fix advice
        assert effort == "upgrade"  # actionable: it has a fix, just not a package one

    def test_without_the_tag_the_advice_is_unchanged(self) -> None:
        raw = _eol_raw()
        del raw["base_os_eol"]
        fix, _, effort = guidance._containers(raw)
        assert effort == "no_fix" and "no_vendor_fix" in fix

    def test_every_eol_finding_in_an_image_is_one_fix(self) -> None:
        rule = guidance.RuleGuidance("containers", "CVE-1", "t", 1, "f", "scanner", "upgrade")
        fix_id, action = guidance._fix_key("containers", rule, _eol_raw())
        assert fix_id == "base_image:library/debian"
        assert IMAGE in action and "debian 10.13" in action
        assert guidance._STEPS["base_image"][-1].startswith("Re-run the containers lane")


# ---------------------------------------------------------------------------
# Lake-backed: risk acceptance and briefing
# ---------------------------------------------------------------------------


_MESSAGE = "Package: zlib1g\nInstalled Version: 1:1.2.11.dfsg-1+deb10u2\nFixed Version: "


def _finding(rule: str, severity: str, *, eol: bool, image: str = IMAGE) -> dict[str, Any]:
    raw: dict[str, Any] = {"image": image}
    if eol:
        raw.update({"base_os_eol": True, "base_os": "debian 10.13"})
    return {
        "rule_id": rule,
        "title": f"{rule} in zlib1g",
        "description": _MESSAGE,
        "severity": severity,
        "file_path": "library/debian",
        "package_name": "zlib1g",
        "package_version": "1:1.2.11.dfsg-1+deb10u2",
        "raw_finding_json": raw,
    }


@pytest.fixture
def eol_lake(client, admin_auth, run_compaction):
    onboard(client, admin_auth)
    auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'containers')}"}
    findings = [
        _finding("CVE-2023-50387", "high", eol=True),
        _finding("CVE-2023-45288", "medium", eol=True),
        _finding("CVE-2026-9", "medium", eol=False, image="postgres:15"),
    ]
    client.post(
        "/api/ingest/scan-run",
        json={
            "scan_run_id": "scan-eol",
            "repo_full_name": REPO,
            "capability": "containers",
            "tool_name": "trivy",
            "commit_sha": "a91f2c7",
            "branch": "main",
            "triggered_by": "push",
            "started_at": "2026-09-27T09:00:00",
            "scan_status": "success",
            "finding_count": len(findings),
        },
        headers=auth,
    )
    response = client.post(
        "/api/ingest/findings",
        json={"scan_run_id": "scan-eol", "capability": "containers", "findings": findings},
        headers=auth,
    )
    assert response.status_code == 200, response.text
    run_compaction()


def _proposal(image: str, deviation: str = "vendor_dependency") -> dict[str, Any]:
    body: dict[str, Any] = {
        "repo": REPO,
        "scope": {"capability": "containers", "image": image, "fixed_version": "absent"},
        "deviation_type": deviation,
        "justification": "Debian has not published a fix for these packages.",
        "residual_likelihood": "low",
        "residual_impact": "low",
        "risk_owner": "tgb",
        "requested_until": (date.today() + timedelta(days=60)).isoformat(),
        "milestones": [{"title": "Move the base", "due": "2026-11-25", "ends_weakness": True}],
    }
    if deviation == "risk_adjustment":
        body["premises"] = [{"type": "not_internet_facing"}]
    return body


class TestRiskAcceptance:
    def test_a_vendor_dependency_on_an_eol_base_is_flagged_with_its_reason(
        self, client, admin_auth, eol_lake
    ) -> None:
        response = client.post("/api/risk-acceptances", json=_proposal(IMAGE), headers=admin_auth)
        assert response.status_code == 201, response.text
        [flag] = response.json()["flags"]
        assert flag["code"] == "base_os_eol" and flag["findings"] == 2
        assert flag["bases"] == ["debian 10.13"] and flag["images"] == ["library/debian"]
        assert "will never re-open" in flag["reason"]
        # The approver signs the flag: it is in the evidence, under the digest.
        record_id = response.json()["risk_acceptance"]["id"]
        with client.app.state.db.session() as session:
            [entry] = (
                session.query(AuditLogEntry)
                .filter_by(action="risk_acceptance.requested", entity_id=record_id)
                .all()
            )
            assert entry.detail["premise_flags"] == ["base_os_eol"]

    def test_an_image_on_a_supported_base_is_not_flagged(
        self, client, admin_auth, eol_lake
    ) -> None:
        response = client.post(
            "/api/risk-acceptances", json=_proposal("postgres:15"), headers=admin_auth
        )
        assert response.status_code == 201, response.text
        assert response.json()["flags"] == []

    def test_only_the_vendor_dependency_premise_is_doubted(self) -> None:
        matched = [
            ra.MatchedFinding("f1", "CVE-1", "zlib1g", "high", "library/debian", IMAGE, "", "open",
                              base_os_eol="debian 10.13"),
        ]  # fmt: skip
        assert ra.premise_flags("vendor_dependency", matched)
        assert ra.premise_flags("risk_adjustment", matched) == []
        assert ra.premise_flags("operational_requirement", matched) == []
        plain = [dataclasses.replace(matched[0], base_os_eol="")]
        assert ra.premise_flags("vendor_dependency", plain) == []


class TestBriefing:
    def test_a_line_per_eol_image(self, client, eol_lake) -> None:
        report = briefing.build(client.app.state.catalog)
        [containers] = [c for c in report.classes if c.capability == "containers"]
        assert containers.eol_images == [(IMAGE, "debian 10.13", 2)]
        rendered = briefing.render(report)
        assert f"{IMAGE}: 2 finding(s) will never get a package fix — debian 10.13 is" in " ".join(
            rendered.split()
        )
        # They are no longer counted as "no published fix -- nothing to upgrade to".
        assert containers.no_fix_available == 1
