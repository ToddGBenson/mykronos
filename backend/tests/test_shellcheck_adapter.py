"""Something that can read the 219 KB CodeQL cannot (B-051).

`keel` recorded 47 successful SAST runs and zero findings while 69% of it went
unexamined, because CodeQL implements no shell language at all. This is the
adapter and the lane that read the rest.

Two lanes on one capability is how "alongside" is expressed: both upload
`sast`, and `CAPABILITY_BY_JOB` maps both job names to it.
"""

from __future__ import annotations

import json
import pathlib

import pytest
import yaml

from mykronos.adapters.base import ScanContext
from mykronos.adapters.registry import get_adapter, supported_tools
from mykronos.adapters.sast_shellcheck import normalize
from mykronos.analysers import readability
from mykronos.ci import CAPABILITY_BY_JOB
from mykronos.installer import TemplateLibrary
from mykronos.schemas import ScanStatus, Severity

TEMPLATES = pathlib.Path(__file__).resolve().parents[2] / "workflow-templates"


def context() -> ScanContext:
    return ScanContext(
        repo_full_name="ToddGBenson/keel",
        capability="sast",
        tool_name="shellcheck",
        tool_version="0.10.0",
        commit_sha="abc1234",
        branch="main",
    )


def report(*comments: dict) -> bytes:
    return json.dumps({"comments": list(comments)}).encode()


def comment(**overrides) -> dict:
    base = {
        "file": "bin/deploy.sh",
        "line": 12,
        "endLine": 12,
        "column": 8,
        "endColumn": 12,
        "level": "warning",
        "code": 2115,
        "message": 'Use "${var:?}" to ensure this never expands to /* .',
        "fix": None,
    }
    base.update(overrides)
    return base


class TestReadingShellCheck:
    def test_a_finding_carries_its_code_and_location(self) -> None:
        result = normalize(report(comment()), context())

        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.rule_id == "SC2115"
        assert finding.file_path == "bin/deploy.sh"
        assert finding.line_start == 12

    def test_the_wiki_page_is_linked_rather_than_summarised(self) -> None:
        """ShellCheck's own explanation of a code is better writing than
        anything this platform would generate for it."""
        result = normalize(report(comment()), context())

        assert "shellcheck.net/wiki/SC2115" in (result.findings[0].description or "")

    @pytest.mark.parametrize(
        ("level", "severity"),
        [
            ("error", Severity.MEDIUM),
            ("warning", Severity.LOW),
            ("info", Severity.INFO),
            ("style", Severity.INFO),
        ],
    )
    def test_nothing_maps_above_medium(self, level: str, severity: Severity) -> None:
        """ShellCheck's levels are about correctness, not exploitability. A
        linter that can reach `high` competes with the dependency scanner for
        the top of a queue it has no business being at the top of."""
        result = normalize(report(comment(level=level)), context())

        assert result.findings[0].severity is severity

    def test_an_unknown_level_is_info_rather_than_a_guess(self) -> None:
        result = normalize(report(comment(level="verbose")), context())

        assert result.findings[0].severity is Severity.INFO

    def test_a_clean_scan_is_not_a_failure(self) -> None:
        result = normalize(report(), context())

        assert result.findings == []
        assert result.scan_status is ScanStatus.SUCCESS

    def test_the_older_bare_array_format_is_accepted(self) -> None:
        """A repository that pinned `--format=json` should still get its
        findings; every field read here is in both shapes."""
        result = normalize(json.dumps([comment()]).encode(), context())

        assert len(result.findings) == 1

    def test_unparseable_output_is_a_partial_failure(self) -> None:
        """Not a clean scan. An empty result from a broken scanner is the
        exact confusion this platform exists to prevent."""
        result = normalize(b"ShellCheck: command not found", context())

        assert result.scan_status is ScanStatus.PARTIAL_FAILURE
        assert result.findings == []

    def test_a_comment_with_no_file_is_skipped_and_said(self) -> None:
        """Without a file there is no location, so the finding has no stable
        identity and would be new on every run."""
        result = normalize(report(comment(file="")), context())

        assert result.findings == []
        assert result.skipped == 1
        assert any("no stable identity" in w for w in result.warnings)

    def test_a_comment_with_no_code_is_skipped(self) -> None:
        result = normalize(report(comment(code=None)), context())

        assert result.skipped == 1


class TestItIsRegistered:
    def test_shellcheck_is_a_sast_tool(self) -> None:
        assert "shellcheck" in supported_tools("sast")

    def test_the_adapter_is_reachable_by_capability_and_tool(self) -> None:
        spec = get_adapter("sast", "shellcheck")

        assert spec.pattern == "*.json"

    def test_it_does_not_displace_codeql(self) -> None:
        """It runs beside CodeQL. A repository choosing one over the other
        would trade 70% unread for 30% unread."""
        assert "codeql" in supported_tools("sast")


class TestTheLane:
    def test_the_workflow_reports_sast_with_shellcheck(self) -> None:
        """Two lanes, one capability. A repository does not gain a new thing
        to enable by adding an analyser."""
        rendered = TemplateLibrary(TEMPLATES).render(
            "sast-shell",
            repo_full_name="ToddGBenson/keel",
            default_branch="main",
            ingestion_api_url="https://mykronos.example",
            token_secret_name="MYKRONOS_INGESTION_TOKEN",
            upload_action_ref="main",
            mykronos_package_spec="mykronos@main",
        )
        document = yaml.safe_load(rendered.content)
        upload = [
            step
            for step in list(document["jobs"].values())[0]["steps"]
            if "Upload" in str(step.get("name"))
        ][0]["with"]

        assert upload["capability"] == "sast"
        assert upload["tool"] == "shellcheck"

    def test_both_lanes_map_to_sast(self) -> None:
        """Otherwise the coverage cross-check cannot see the second lane, and
        a capability produced by a real job reads as `no_job` forever.

        The registry key, not the workflow filename stem: an Actions lane is
        resolved through the template registry first, so it arrives here
        already named `sast-shell`. Adding the stem as well would put it in
        `jobs_for_capability("sast")`, where the "scan now" button would try
        to trigger a Concourse job that does not exist."""
        assert CAPABILITY_BY_JOB["sast"] == "sast"
        assert CAPABILITY_BY_JOB["sast-shell"] == "sast"
        assert "mykronos-sast-shell" not in CAPABILITY_BY_JOB

    def test_the_two_workflows_do_not_collide(self) -> None:
        """One capability, two workflows: the names, job ids and concurrency
        groups have to stay distinct or the second silently replaces the
        first."""
        library = TemplateLibrary(TEMPLATES)
        rendered = [
            library.render(
                key,
                repo_full_name="ToddGBenson/keel",
                default_branch="main",
                ingestion_api_url="https://mykronos.example",
                token_secret_name="T",
                upload_action_ref="main",
                mykronos_package_spec="mykronos@main",
            )
            for key in ("sast", "sast-shell")
        ]
        documents = [yaml.safe_load(r.content) for r in rendered]

        assert documents[0]["name"] != documents[1]["name"]
        assert set(documents[0]["jobs"]) != set(documents[1]["jobs"])
        assert {r.path for r in rendered} == {
            ".github/workflows/mykronos-sast.yml",
            ".github/workflows/mykronos-sast-shell.yml",
        }


class TestWhatItCloses:
    def test_the_two_analysers_together_read_all_of_keel(self) -> None:
        """The answer B-051 asked for, and the reason this is `alongside`
        rather than `instead of`."""
        keel = {"Shell": 219000, "Python": 66000, "JavaScript": 28000}

        assert readability("keel", keel, "codeql").share_unread == pytest.approx(0.70, abs=0.01)
        assert readability("keel", keel, "shellcheck").share_unread == pytest.approx(
            0.30, abs=0.01
        )
        assert readability("keel", keel, ["codeql", "shellcheck"]).blind is False

    def test_shellcheck_alone_is_not_the_answer(self) -> None:
        """Swapping the tool would trade one blind spot for another."""
        keel = {"Shell": 219000, "Python": 66000, "JavaScript": 28000}

        assert readability("keel", keel, "shellcheck").blind is True
