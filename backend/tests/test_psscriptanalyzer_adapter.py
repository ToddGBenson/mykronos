"""Something that reads PowerShell (B-051).

`personal-soc` is 100% PowerShell and carries one capability, `secrets` -- so
gitleaks greps it for credential patterns and nothing has ever examined its
608 lines for a defect. CodeQL implements no PowerShell either, so enabling
`sast` there without this would have added a second green lane over unread
code rather than coverage.

The 2026-09-03 hand pass found no `Invoke-Expression`, no `DownloadString`, no
`-ExecutionPolicy Bypass` and no credential literals. A clean result is what
this lane should reproduce, on every push rather than once an afternoon.
"""

from __future__ import annotations

import json
import pathlib

import pytest
import yaml

from mykronos.adapters.base import ScanContext
from mykronos.adapters.registry import get_adapter, supported_tools
from mykronos.adapters.sast_psscriptanalyzer import normalize
from mykronos.analysers import readability
from mykronos.ci import CAPABILITY_BY_JOB
from mykronos.installer import TemplateLibrary
from mykronos.schemas import ScanStatus, Severity

TEMPLATES = pathlib.Path(__file__).resolve().parents[2] / "workflow-templates"
WORKSPACE = pathlib.PurePosixPath("/home/runner/work/personal-soc/personal-soc")


def context(workspace: pathlib.Path | None = None) -> ScanContext:
    return ScanContext(
        repo_full_name="ToddGBenson/personal-soc",
        capability="sast",
        tool_name="psscriptanalyzer",
        tool_version="1.25.0",
        commit_sha="abc1234",
        branch="main",
        workspace=workspace,
    )


def record(**overrides) -> dict:
    base = {
        "RuleName": "PSAvoidUsingInvokeExpression",
        "Severity": 1,
        "ScriptName": "Invoke-BreachCheck.ps1",
        "ScriptPath": f"{WORKSPACE}/Invoke-BreachCheck.ps1",
        "Line": 28,
        "Column": 5,
        "Message": "Invoke-Expression is used. Please remove it.",
    }
    base.update(overrides)
    return base


class TestReadingPSScriptAnalyzer:
    def test_a_finding_carries_its_rule_and_location(self) -> None:
        result = normalize(json.dumps([record()]).encode(), context())

        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.rule_id == "PSAvoidUsingInvokeExpression"
        assert finding.line_start == 28

    @pytest.mark.parametrize(
        ("severity", "expected"),
        [
            (0, Severity.INFO),
            (1, Severity.LOW),
            (2, Severity.MEDIUM),
            (3, Severity.MEDIUM),
        ],
    )
    def test_the_integer_enum_is_read(self, severity: int, expected: Severity) -> None:
        """`ConvertTo-Json` serialises the .NET enum as its ordinal. A reader
        expecting "Warning" gets `1`, and a naive mapping would file every
        finding at the default while looking like it worked."""
        result = normalize(json.dumps([record(Severity=severity)]).encode(), context())

        assert result.findings[0].severity is expected

    @pytest.mark.parametrize(
        ("severity", "expected"),
        [
            ("Information", Severity.INFO),
            ("Warning", Severity.LOW),
            ("Error", Severity.MEDIUM),
            ("ParseError", Severity.MEDIUM),
        ],
    )
    def test_the_string_form_is_read_too(self, severity: str, expected: Severity) -> None:
        """`-EnumsAsStrings` exists and a repository may well pass it."""
        result = normalize(json.dumps([record(Severity=severity)]).encode(), context())

        assert result.findings[0].severity is expected

    def test_nothing_maps_above_medium(self) -> None:
        """These are correctness levels from a linter. One that can reach
        `high` competes with the dependency scanner for the top of a queue it
        has no business being at the top of."""
        every = [record(Severity=level) for level in (0, 1, 2, 3)]
        result = normalize(json.dumps(every).encode(), context())

        assert all(f.severity is not Severity.HIGH for f in result.findings)
        assert all(f.severity is not Severity.CRITICAL for f in result.findings)

    def test_the_runner_path_is_made_repo_relative(self, tmp_path: pathlib.Path) -> None:
        """`ScriptPath` is absolute on the runner. A path that is not relative
        to the repository is not clickable, and a finding's identity derives
        from it (spec 05 §5) — so a changed checkout layout would reopen
        everything as new work."""
        result = normalize(json.dumps([record()]).encode(), context(pathlib.Path(WORKSPACE)))

        assert result.findings[0].file_path == "Invoke-BreachCheck.ps1"

    def test_a_single_finding_is_not_dropped(self) -> None:
        """`ConvertTo-Json` unwraps a one-element array into a bare object, so
        reading only lists would report a clean scan for a repository with
        exactly one problem."""
        result = normalize(json.dumps(record()).encode(), context())

        assert len(result.findings) == 1

    def test_a_clean_scan_is_not_a_failure(self) -> None:
        """What `personal-soc` should produce: the hand pass found nothing."""
        result = normalize(b"[]", context())

        assert result.findings == []
        assert result.scan_status is ScanStatus.SUCCESS

    def test_a_byte_order_mark_does_not_break_it(self) -> None:
        """PowerShell's `Set-Content -Encoding utf8` writes one on Windows."""
        result = normalize("﻿[]".encode(), context())

        assert result.scan_status is ScanStatus.SUCCESS

    def test_unparseable_output_is_a_partial_failure(self) -> None:
        result = normalize(b"Install-Module: no such module", context())

        assert result.scan_status is ScanStatus.PARTIAL_FAILURE

    def test_a_record_with_no_rule_is_skipped(self) -> None:
        result = normalize(json.dumps([record(RuleName="")]).encode(), context())

        assert result.skipped == 1
        assert any("no stable identity" in w for w in result.warnings)


class TestItIsRegistered:
    def test_psscriptanalyzer_is_a_sast_tool(self) -> None:
        assert "psscriptanalyzer" in supported_tools("sast")

    def test_the_adapter_is_reachable(self) -> None:
        assert get_adapter("sast", "psscriptanalyzer").pattern == "*.json"

    def test_the_lane_maps_to_sast(self) -> None:
        assert CAPABILITY_BY_JOB["sast-powershell"] == "sast"
        assert "mykronos-sast-powershell" not in CAPABILITY_BY_JOB


class TestTheLane:
    def _render(self, key: str):
        return TemplateLibrary(TEMPLATES).render(
            key,
            repo_full_name="ToddGBenson/personal-soc",
            default_branch="main",
            ingestion_api_url="https://mykronos.example",
            token_secret_name="MYKRONOS_INGESTION_TOKEN",
            upload_action_ref="main",
            mykronos_package_spec="mykronos@main",
        )

    def test_it_reports_sast_with_psscriptanalyzer(self) -> None:
        document = yaml.safe_load(self._render("sast-powershell").content)
        upload = [
            step
            for step in list(document["jobs"].values())[0]["steps"]
            if "Upload" in str(step.get("name"))
        ][0]["with"]

        assert upload["capability"] == "sast"
        assert upload["tool"] == "psscriptanalyzer"

    def test_the_three_sast_lanes_do_not_collide(self) -> None:
        """One capability, three workflows: names, job ids and file targets
        must stay distinct or one silently replaces another."""
        rendered = [self._render(k) for k in ("sast", "sast-shell", "sast-powershell")]
        documents = [yaml.safe_load(r.content) for r in rendered]

        assert len({d["name"] for d in documents}) == 3
        assert len({tuple(d["jobs"]) for d in documents}) == 3
        assert len({r.path for r in rendered}) == 3

    def test_the_module_version_is_pinned(self) -> None:
        """An analyser that silently changes its rule set changes what clean
        means without anybody deciding to."""
        assert "-RequiredVersion" in self._render("sast-powershell").content


class TestWhatItCloses:
    def test_personal_soc_becomes_fully_readable(self) -> None:
        personal_soc = {"PowerShell": 30000}

        assert readability("personal-soc", personal_soc, "codeql").share_unread == 1.0
        assert readability(
            "personal-soc", personal_soc, ["codeql", "psscriptanalyzer"]
        ).blind is False

    def test_it_does_not_help_a_shell_repository(self) -> None:
        """It reads PowerShell and nothing else, which is why the estate needs
        both this and ShellCheck rather than one of them."""
        keel = {"Shell": 219000, "Python": 66000, "JavaScript": 28000}

        assert readability("keel", keel, ["codeql", "psscriptanalyzer"]).blind is True
