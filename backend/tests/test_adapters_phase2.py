"""Bespoke adapters for the non-SARIF tools — spec 04 §3, §4.

The Gitleaks class is the important one: that adapter handles the only data in
the system that is itself the secret.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from mykronos.adapters import ScanContext, supported_tools
from mykronos.adapters.cloud_generic import normalize as cloud_normalize
from mykronos.adapters.dast_zap import MAX_INSTANCES_PER_ALERT
from mykronos.adapters.dast_zap import normalize as zap_normalize
from mykronos.adapters.registry import get_adapter, normalize_results
from mykronos.adapters.secrets_gitleaks import REDACTED
from mykronos.adapters.secrets_gitleaks import normalize as gitleaks_normalize
from mykronos.fingerprint import FINGERPRINT_V2_SNIPPET, compute_finding_id
from mykronos.schemas import ScanStatus, Severity

REPO = "ToddGBenson/payments-api"

#: Stands in for a secret Gitleaks failed to redact. Deliberately *not*
#: credential-shaped: the scrubbing is keyed on field name, not on the value,
#: so a realistic key would prove nothing extra and would itself be a finding
#: in this repository. (It was. Our own Gitleaks job caught the previous
#: version of this line — see .gitleaksignore.)
UNREDACTED_SENTINEL = "sentinel-value-standing-in-for-a-leaked-credential"


def context(capability: str, workspace: Path | None = None) -> ScanContext:
    return ScanContext(
        repo_full_name=REPO,
        capability=capability,
        tool_name="t",
        tool_version="1",
        commit_sha="abc123",
        branch="main",
        workspace=workspace,
    )


# ---------------------------------------------------------------------------
# Gitleaks
# ---------------------------------------------------------------------------


def gitleaks_record(**overrides: Any) -> dict[str, Any]:
    record = {
        "RuleID": "aws-access-token",
        "Description": "AWS Access Token",
        "File": "config/settings.py",
        "StartLine": 42,
        "EndLine": 42,
        "Secret": "REDACTED",
        "Match": "REDACTED",
        "Entropy": 3.9,
        "Commit": "abc123",
    }
    record.update(overrides)
    return record


class TestGitleaks:
    def test_a_finding_is_produced(self) -> None:
        result = gitleaks_normalize(
            json.dumps([gitleaks_record()]).encode(), context("secrets")
        )
        assert len(result.findings) == 1
        assert result.findings[0].file_path == "config/settings.py"

    def test_severity_is_always_critical(self) -> None:
        """Gitleaks does not rank findings. A committed live credential is
        critical whichever pattern caught it."""
        result = gitleaks_normalize(
            json.dumps([gitleaks_record()]).encode(), context("secrets")
        )
        assert result.findings[0].severity is Severity.CRITICAL

    def test_no_snippet_is_ever_captured(self) -> None:
        """Every other adapter captures surrounding source for fingerprint
        stability. Doing that here would copy the secret into the lake."""
        result = gitleaks_normalize(
            json.dumps([gitleaks_record()]).encode(), context("secrets")
        )
        assert result.findings[0].code_snippet == REDACTED

    def test_an_unredacted_secret_is_scrubbed_from_the_raw_record(self) -> None:
        """`--redact` is in the template, but the archive is kept for a year
        (spec 05 §7). One workflow missing the flag must not turn that into a
        year-long secret store."""
        leaky = gitleaks_record(Secret=UNREDACTED_SENTINEL, Match=f"key = {UNREDACTED_SENTINEL}")

        result = gitleaks_normalize(json.dumps([leaky]).encode(), context("secrets"))
        finding = result.findings[0]

        serialised = json.dumps(finding.model_dump(mode="json"))
        assert UNREDACTED_SENTINEL not in serialised
        assert finding.raw_finding_json["Secret"] == REDACTED
        assert finding.raw_finding_json["Match"] == REDACTED

    def test_identity_is_stable_when_the_secret_moves_down_the_file(self) -> None:
        """The D-001 property, achieved without storing the secret: identity
        is (repo, capability, rule, file)."""
        first = gitleaks_normalize(
            json.dumps([gitleaks_record(StartLine=42)]).encode(), context("secrets")
        ).findings[0]
        second = gitleaks_normalize(
            json.dumps([gitleaks_record(StartLine=118)]).encode(), context("secrets")
        ).findings[0]

        def identity(finding):
            return compute_finding_id(
                repo_full_name=REPO,
                capability="secrets",
                rule_id=finding.rule_id,
                file_path=finding.file_path,
                symbol=finding.symbol,
                code_snippet=finding.code_snippet,
                line_start=finding.line_start,
            )

        assert identity(first) == identity(second)
        assert identity(first)[1] == FINGERPRINT_V2_SNIPPET

    def test_a_null_report_is_a_clean_scan(self) -> None:
        """Gitleaks writes literal `null` when it finds nothing. That is a
        clean result, not a broken one."""
        result = gitleaks_normalize(b"null", context("secrets"))
        assert result.findings == []
        assert result.scan_status is ScanStatus.SUCCESS

    def test_an_empty_report_is_a_clean_scan(self) -> None:
        result = gitleaks_normalize(b"", context("secrets"))
        assert result.findings == []
        assert result.scan_status is ScanStatus.SUCCESS

    def test_malformed_output_does_not_raise(self) -> None:
        result = gitleaks_normalize(b"{not json", context("secrets"))
        assert result.scan_status is ScanStatus.PARTIAL_FAILURE

    def test_records_missing_a_rule_or_file_are_skipped(self) -> None:
        payload = [gitleaks_record(), {"RuleID": "x"}, gitleaks_record(File="")]
        result = gitleaks_normalize(json.dumps(payload).encode(), context("secrets"))
        assert len(result.findings) == 1
        assert result.skipped == 2

    def test_the_description_says_to_rotate(self) -> None:
        """Deleting the line does not un-leak it — the value is in git history."""
        result = gitleaks_normalize(
            json.dumps([gitleaks_record()]).encode(), context("secrets")
        )
        assert "rotate" in result.findings[0].description.lower()
        assert "history" in result.findings[0].description.lower()


# ---------------------------------------------------------------------------
# ZAP
# ---------------------------------------------------------------------------


def zap_report(instances: list[dict[str, str]] | None = None, **alert: Any) -> bytes:
    base = {
        "pluginid": "10038",
        "alert": "Content Security Policy Header Not Set",
        "riskcode": "2",
        "desc": "No CSP header.",
        "solution": "Set one.",
        "cweid": "693",
        "instances": instances
        if instances is not None
        else [{"uri": "https://staging.example.com/admin", "method": "GET"}],
    }
    base.update(alert)
    site = {"@name": "https://staging.example.com", "alerts": [base]}
    return json.dumps({"site": [site]}).encode()


class TestZap:
    def test_riskcode_maps_to_severity(self) -> None:
        assert zap_normalize(zap_report(riskcode="3"), context("dast")).findings[
            0
        ].severity is Severity.HIGH
        assert zap_normalize(zap_report(riskcode="0"), context("dast")).findings[
            0
        ].severity is Severity.INFO

    def test_the_url_path_is_the_location(self) -> None:
        finding = zap_normalize(zap_report(), context("dast")).findings[0]
        assert finding.file_path == "/admin"
        assert "GET /admin" in (finding.code_snippet or "")

    def test_each_instance_is_its_own_finding(self) -> None:
        """One alert on five URLs is five findings: they are fixed and tracked
        separately, and collapsing them makes "how many are left" unanswerable."""
        result = zap_normalize(
            zap_report(
                instances=[
                    {"uri": "https://x.test/a", "method": "GET"},
                    {"uri": "https://x.test/b", "method": "POST"},
                ]
            ),
            context("dast"),
        )
        assert len(result.findings) == 2
        assert {f.file_path for f in result.findings} == {"/a", "/b"}

    def test_identity_is_stable_across_scans(self) -> None:
        def identity(finding):
            return compute_finding_id(
                repo_full_name=REPO,
                capability="dast",
                rule_id=finding.rule_id,
                file_path=finding.file_path,
                symbol=finding.symbol,
                code_snippet=finding.code_snippet,
                line_start=finding.line_start,
            )[0]

        first = zap_normalize(zap_report(), context("dast")).findings[0]
        second = zap_normalize(zap_report(), context("dast")).findings[0]
        assert identity(first) == identity(second)

    def test_an_alert_with_no_instances_is_kept(self) -> None:
        """A site-wide alert is still a finding."""
        result = zap_normalize(zap_report(instances=[]), context("dast"))
        assert len(result.findings) == 1

    def test_runaway_instance_counts_are_capped_and_reported(self) -> None:
        """Silent truncation would read as "that is all of them"."""
        instances = [
            {"uri": f"https://x.test/page/{i}", "method": "GET"} for i in range(60)
        ]
        result = zap_normalize(zap_report(instances=instances), context("dast"))

        assert len(result.findings) == MAX_INSTANCES_PER_ALERT
        assert any("not ingested" in w for w in result.warnings)

    def test_empty_report_is_clean(self) -> None:
        result = zap_normalize(json.dumps({"site": []}).encode(), context("dast"))
        assert result.findings == []
        assert result.scan_status is ScanStatus.SUCCESS


# ---------------------------------------------------------------------------
# Cloud
# ---------------------------------------------------------------------------


def ocsf(**overrides: Any) -> dict[str, Any]:
    record = {
        "status_code": "FAIL",
        "severity": "High",
        "check_id": "iam_root_mfa_enabled",
        "finding_info": {"title": "Root account lacks MFA", "uid": "iam_root_mfa_enabled"},
        "resources": [{"uid": "arn:aws:iam::123456789012:root"}],
        "cloud": {"account": {"uid": "123456789012"}},
        "status_detail": "MFA is not enabled on the root account.",
    }
    record.update(overrides)
    return record


class TestCloud:
    def test_a_failing_check_becomes_a_finding(self) -> None:
        result = cloud_normalize(json.dumps([ocsf()]).encode(), context("cloud"))
        assert len(result.findings) == 1
        assert result.findings[0].severity is Severity.HIGH
        assert result.findings[0].file_path == "arn:aws:iam::123456789012:root"

    def test_passing_checks_are_not_stored(self) -> None:
        """Storing every passing control for every resource on every daily
        scan grows without bound and answers no question anyone asks."""
        payload = [ocsf(), ocsf(status_code="PASS"), ocsf(status_code="PASS")]
        result = cloud_normalize(json.dumps(payload).encode(), context("cloud"))
        assert len(result.findings) == 1

    def test_newline_delimited_json_is_accepted(self) -> None:
        """Prowler has shipped both shapes. A scan that silently produced
        nothing because the writer changed format would look like a clean
        account."""
        raw = "\n".join(json.dumps(ocsf(check_id=f"c{i}")) for i in range(3)).encode()
        result = cloud_normalize(raw, context("cloud"))
        assert len(result.findings) == 3

    def test_a_wrapped_findings_array_is_accepted(self) -> None:
        raw = json.dumps({"findings": [ocsf()]}).encode()
        assert len(cloud_normalize(raw, context("cloud")).findings) == 1

    def test_identity_includes_the_resource(self) -> None:
        """Two accounts failing the same check are two findings."""
        a = cloud_normalize(json.dumps([ocsf()]).encode(), context("cloud")).findings[0]
        b = cloud_normalize(
            json.dumps(
                [
                    ocsf(
                        resources=[{"uid": "arn:aws:iam::999:root"}],
                        cloud={"account": {"uid": "999"}},
                    )
                ]
            ).encode(),
            context("cloud"),
        ).findings[0]
        assert a.file_path != b.file_path

    def test_unparseable_output_is_reported(self) -> None:
        result = cloud_normalize(b"<html>error</html>", context("cloud"))
        assert result.scan_status is ScanStatus.PARTIAL_FAILURE


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class TestRegistry:
    @pytest.mark.parametrize(
        ("capability", "tool"),
        [
            ("sast", "codeql"),
            ("sast", "semgrep"),
            ("secrets", "gitleaks"),
            ("containers", "trivy"),
            ("iac", "checkov"),
            ("dast", "zap"),
            ("cloud", "prowler"),
            ("atlas", "osv-scanner"),
        ],
    )
    def test_every_shipped_pairing_resolves(self, capability: str, tool: str) -> None:
        assert get_adapter(capability, tool) is not None

    def test_every_uploading_template_has_an_adapter(self) -> None:
        """The list above is hand-maintained, and that is how Atlas shipped
        without one: the template ran osv-scanner, the counts module parsed
        its JSON, the trust score was tested — and the upload failed with
        "'atlas' has no adapters registered" the first time a real repo tried
        it. Nothing in the suite connected the two halves.

        This asks the templates instead of a list. Any workflow that calls the
        shared upload action is claiming its output can be normalized, so the
        pairing it passes must resolve. A new capability with a scanner
        template now fails here rather than in somebody's Actions log.
        """
        from mykronos.config import get_settings
        from mykronos.installer import TemplateLibrary

        library = TemplateLibrary(get_settings().workflow_templates_dir)

        checked = []
        for capability in sorted(library.available):
            rendered = library.render(
                capability,
                repo_full_name="example-org/repo",
                default_branch="main",
                ingestion_api_url="https://example.invalid",
                token_secret_name="MYKRONOS_INGESTION_TOKEN",
                upload_action_ref="example-org/repo/actions/upload-results@v1",
                mykronos_package_spec="mykronos @ git+https://example.invalid@v1",
            ).content

            if "actions/upload-results@" not in rendered:
                continue  # Not a scanner — the Oracle gate and Patchwork.

            match = re.search(r"^\s*tool:\s*(\S+)\s*$", rendered, re.MULTILINE)
            assert match, f"{capability}: uploads results but declares no tool"
            tool = match.group(1)

            get_adapter(capability, tool)  # raises LookupError if missing
            checked.append((capability, tool))

        assert checked, "no scanner templates found — the discovery is broken"

    def test_the_upload_action_pins_no_version_of_its_own(self) -> None:
        """The composite action installs the `mykronos` package, and which
        version it installs must follow the ref the action was resolved at.

        It did not. The action shipped pinned to `v1` while its `mykronos-ref`
        input defaulted to a hardcoded `v0.1.0` that was never tagged, so every
        upload step in every onboarded repository failed with `pathspec
        'v0.1.0' did not match any file(s) known to git` — after the scan had
        succeeded, which made it read as an ingestion problem.

        Two version knobs that must agree will not stay agreed. This asserts
        there is only one.
        """
        import yaml

        from mykronos.config import get_settings

        action = get_settings().workflow_templates_dir.parent / (
            "actions/upload-results/action.yml"
        )
        spec = yaml.safe_load(action.read_text(encoding="utf-8"))

        default = spec["inputs"]["mykronos-ref"]["default"]
        assert default == "", (
            "mykronos-ref must default to empty so the install falls back to "
            f"github.action_ref; found a hardcoded {default!r}"
        )

        install = next(
            step
            for step in spec["runs"]["steps"]
            if "pip install" in str(step.get("run", ""))
        )
        assert "github.action_ref" in str(install.get("env", {})), (
            "the install step must resolve its ref from github.action_ref"
        )

    def test_atlas_installs_a_real_osv_scanner(self) -> None:
        """`pip install osv-scanner` installs nothing.

        That name on PyPI is a reserved placeholder — version 0.0.1, summary
        "Reserved name placeholder. No functionality." — so pip succeeded, no
        CLI landed on PATH, and `osv-scanner scan source` died with `command
        not found`. The blanket `|| true` on the scan step swallowed it, the
        SARIF file was never written, and every Atlas run in every onboarded
        repo uploaded zero findings before failing at the upload step, where
        the error read as an ingestion problem rather than a missing scanner.

        The supply-chain lane reported a clean supply chain because it never
        ran. OSV-Scanner is a Go binary released on GitHub; this asserts we
        fetch it pinned and checksum-verified.
        """
        import yaml

        from mykronos.config import get_settings
        from mykronos.installer import TemplateLibrary

        library = TemplateLibrary(get_settings().workflow_templates_dir)
        rendered = library.render(
            "atlas",
            repo_full_name="example-org/repo",
            default_branch="main",
            ingestion_api_url="https://example.invalid",
            token_secret_name="MYKRONOS_INGESTION_TOKEN",
            upload_action_ref="example-org/repo/actions/upload-results@v1",
            mykronos_package_spec="mykronos @ git+https://example.invalid@v1",
        ).content

        # Against the parsed `run` bodies, not the raw file: the step's own
        # comment explains what not to do and names the bad command, which a
        # text search cannot tell apart from doing it.
        spec = yaml.safe_load(rendered)
        scripts = [
            str(step.get("run", ""))
            for job in spec["jobs"].values()
            for step in job.get("steps", [])
        ]
        installs_placeholder = [
            s for s in scripts if re.search(r"pip install[^\n]*\bosv-scanner\b", s)
        ]
        assert not installs_placeholder, (
            "osv-scanner on PyPI is an empty placeholder — install the released binary instead"
        )
        assert "releases/download/v${OSV_VERSION}/osv-scanner_linux_amd64" in rendered, (
            "Atlas must fetch a pinned OSV-Scanner release binary"
        )
        assert "sha256sum -c -" in rendered, (
            "the one lane whose job is catching swapped artifacts must verify "
            "the checksum of the artifact it downloads"
        )

    def test_no_scanner_template_swallows_its_scanner_exit_code(self) -> None:
        """`|| true` on a scanner invocation is indistinguishable from a pass.

        Atlas used it to tolerate OSV-Scanner's exit 1 (vulnerabilities found,
        which is a result and not an error) and in doing so also tolerated
        exit 127 — the missing binary above — for the entire life of the lane.
        Tolerate the specific findings code, never the whole range.
        """
        import yaml

        from mykronos.config import get_settings
        from mykronos.installer import TemplateLibrary

        library = TemplateLibrary(get_settings().workflow_templates_dir)

        offenders = []
        for capability in sorted(library.available):
            rendered = library.render(
                capability,
                repo_full_name="example-org/repo",
                default_branch="main",
                ingestion_api_url="https://example.invalid",
                token_secret_name="MYKRONOS_INGESTION_TOKEN",
                upload_action_ref="example-org/repo/actions/upload-results@v1",
                mykronos_package_spec="mykronos @ git+https://example.invalid@v1",
            ).content
            if "actions/upload-results@" not in rendered:
                continue  # Not a scanner — the Oracle gate and Patchwork.

            spec = yaml.safe_load(rendered)
            for job in spec["jobs"].values():
                for step in job.get("steps", []):
                    if "|| true" in str(step.get("run", "")):
                        offenders.append(f"{capability}: {step.get('name')}")

        assert not offenders, (
            f"scanner steps must not blanket-ignore exit codes: {', '.join(offenders)}"
        )

    def test_an_unknown_tool_names_the_alternatives(self) -> None:
        with pytest.raises(LookupError) as excinfo:
            get_adapter("secrets", "trufflehog")
        assert "gitleaks" in str(excinfo.value)

    def test_supported_tools_drives_config_validation(self) -> None:
        """spec 04 §7: a bad tool name should fail the save, not a workflow
        run three hours later."""
        assert supported_tools("iac") == ["checkov"]
        assert supported_tools("aegis") == []

    def test_a_missing_results_directory_is_a_failure(self, tmp_path: Path) -> None:
        """spec 04 §6: a permanently broken scanner must not look like a
        permanently clean repo."""
        outcome = normalize_results(
            "secrets", "gitleaks", tmp_path / "nope", context("secrets")
        )
        assert outcome.scan_status is ScanStatus.FAILURE

    def test_the_tool_pattern_selects_the_right_files(self, tmp_path: Path) -> None:
        """Gitleaks writes JSON; globbing for SARIF would find nothing."""
        results = tmp_path / "out"
        results.mkdir()
        (results / "gitleaks.json").write_bytes(json.dumps([gitleaks_record()]).encode())
        (results / "unrelated.sarif").write_bytes(b"{}")

        outcome = normalize_results("secrets", "gitleaks", results, context("secrets"))

        assert len(outcome.findings) == 1
