"""Denylist findings reach the findings table — spec 22 §3.

The findings themselves are covered in `test_atlas_licenses.py`. This is
about the road they travel: SARIF into the same results directory
osv-scanner writes to, collected by the upload step that already exists,
rather than a private ingestion path where the finding-id derivation could
drift from everything else.
"""

from __future__ import annotations

import json

import yaml

from mykronos import atlas_sbom
from mykronos.config import get_settings
from mykronos.installer import TemplateLibrary


def sbom(*components):
    return {"components": list(components)}


def component(name, licenses=None, *, version="1.0.0"):
    entry = {"name": name, "version": version, "purl": f"pkg:npm/{name}@{version}"}
    if licenses:
        entry["licenses"] = [{"license": {"id": lic}} for lic in licenses]
    return entry


class TestSarif:
    def test_a_finding_becomes_a_result(self) -> None:
        findings = atlas_sbom.denylist_findings(
            sbom(component("left-pad")), banned_packages=["left-pad"], blocked_licenses=[]
        )

        document = atlas_sbom.to_sarif(findings)
        results = document["runs"][0]["results"]

        assert len(results) == 1
        assert results[0]["ruleId"] == "atlas-banned-package"
        assert results[0]["level"] == "error"

    def test_the_rule_is_declared(self) -> None:
        """A SARIF result whose ruleId names no rule in the driver is legal
        and useless — the normaliser has nothing to title the finding with."""
        findings = atlas_sbom.denylist_findings(
            sbom(component("x", ["GPL-3.0"])), banned_packages=[], blocked_licenses=["gpl-3.0"]
        )

        driver = atlas_sbom.to_sarif(findings)["runs"][0]["tool"]["driver"]

        assert [rule["id"] for rule in driver["rules"]] == ["atlas-blocked-license"]

    def test_no_findings_still_produces_a_valid_document(self) -> None:
        """"Scanned and found nothing" and "produced no output" read
        differently to the uploader, and only the first one is true when the
        denylists are empty."""
        document = atlas_sbom.to_sarif([])

        assert document["runs"][0]["results"] == []
        assert document["runs"][0]["invocations"][0]["executionSuccessful"] is True
        # Round-trips: a malformed document would be discovered at upload
        # time, in somebody's workflow, rather than here.
        assert json.loads(json.dumps(document))

    def test_the_location_names_the_package(self) -> None:
        """There is no source line to point at — the finding is about a
        resolved dependency, not a file. The ecosystem-qualified name is what
        a person needs to act on it."""
        findings = atlas_sbom.denylist_findings(
            sbom(component("left-pad")), banned_packages=["left-pad"], blocked_licenses=[]
        )

        location = atlas_sbom.to_sarif(findings)["runs"][0]["results"][0]["locations"][0]

        assert location["physicalLocation"]["artifactLocation"]["uri"] == (
            "npm:left-pad@1.0.0"
        )


class TestTheWorkflowTemplate:
    def render(self, **config):
        library = TemplateLibrary(get_settings().workflow_templates_dir)
        return library.render(
            "atlas",
            repo_full_name="acme/widgets",
            default_branch="main",
            ingestion_api_url="https://mykronos.example",
            token_secret_name="MYKRONOS_TOKEN",
            upload_action_ref="ToddGBenson/mykronos@v1",
            mykronos_package_spec="mykronos @ git+https://example.invalid@v1",
            config=config,
        ).content

    def test_it_is_still_valid_yaml(self) -> None:
        assert yaml.safe_load(self.render(banned_packages=["left-pad"]))

    def test_a_banned_package_is_passed_to_the_runner(self) -> None:
        assert "--banned-package 'left-pad'" in self.render(banned_packages=["left-pad"])

    def test_a_blocked_license_is_passed_to_the_runner(self) -> None:
        assert "--blocked-license 'gpl-3.0'" in self.render(blocked_licenses=["gpl-3.0"])

    def test_the_license_pass_runs_regardless_of_the_denylists(self) -> None:
        """Scoring licenses and banning them are separate features. A repo
        that has banned nothing still gets its license terms."""
        assert "--sbom sbom.json" in self.render()

    def test_freshness_is_off_unless_asked_for(self) -> None:
        """spec 07 §7: the platform does not make outbound calls to third
        parties because a scan happened to run."""
        assert "--check-freshness" not in self.render()

    def test_freshness_can_be_opted_into(self) -> None:
        rendered = self.render(check_freshness=True, staleness_threshold_days=365)

        assert "--check-freshness" in rendered
        assert "--staleness-threshold-days 365" in rendered
