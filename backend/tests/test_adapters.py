"""SARIF normalization and snippet capture — spec 04 §4, §8; spec 05 §5.

The last class in this file is the point of the whole exercise: adapter output
fed through the real fingerprint must survive a line shift. Everything else
guards the path to it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from mykronos.adapters import ScanContext, sarif_to_findings
from mykronos.adapters.sarif import severity_from_security_score
from mykronos.adapters.sast_codeql import normalize_directory, tool_version_from_sarif
from mykronos.adapters.snippet import infer_symbol, read_source_lines, slice_snippet
from mykronos.fingerprint import (
    FINGERPRINT_V1_LINE,
    FINGERPRINT_V2_SNIPPET,
    compute_finding_id,
)
from mykronos.schemas import ScanStatus, Severity

REPO = "example-org/payments-api"

VULNERABLE_SOURCE = """\
import os
import sqlite3

CONNECTION = sqlite3.connect("orders.db")


def get_order(order_id):
    cursor = CONNECTION.cursor()
    cursor.execute("SELECT * FROM orders WHERE id = " + order_id)
    return cursor.fetchone()


def list_orders():
    return CONNECTION.cursor().execute("SELECT * FROM orders").fetchall()
"""


def context(workspace: Path | None = None) -> ScanContext:
    return ScanContext(
        repo_full_name=REPO,
        capability="sast",
        tool_name="codeql",
        tool_version="2.19.0",
        commit_sha="a91f2c7",
        branch="main",
        workspace=workspace,
    )


def sarif(
    *,
    rule_id: str = "py/sql-injection",
    security_severity: str | None = "9.8",
    level: str = "error",
    start_line: int = 9,
    end_line: int | None = None,
    uri: str = "orders/query.py",
    region_snippet: str | None = None,
    context_snippet: str | None = None,
    logical: str | None = None,
    extra_result: dict[str, Any] | None = None,
) -> bytes:
    rule: dict[str, Any] = {
        "id": rule_id,
        "name": "SqlInjection",
        "shortDescription": {"text": "SQL query built from user-controlled sources"},
        "fullDescription": {"text": "Building a SQL query from user input allows injection."},
        "defaultConfiguration": {"level": level},
    }
    if security_severity is not None:
        rule["properties"] = {"security-severity": security_severity}

    region: dict[str, Any] = {
        "startLine": start_line,
        "endLine": end_line if end_line is not None else start_line,
    }
    if region_snippet is not None:
        region["snippet"] = {"text": region_snippet}

    physical: dict[str, Any] = {
        "artifactLocation": {"uri": uri},
        "region": region,
    }
    if context_snippet is not None:
        physical["contextRegion"] = {"snippet": {"text": context_snippet}}

    result: dict[str, Any] = {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": "This query depends on a user-provided value."},
        "locations": [{"physicalLocation": physical}],
    }
    if logical:
        result["logicalLocations"] = [{"fullyQualifiedName": logical}]
    if extra_result:
        result.update(extra_result)

    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "CodeQL",
                            "semanticVersion": "2.19.0",
                            "rules": [rule],
                        }
                    },
                    "results": [result],
                }
            ],
        }
    ).encode()


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    (tmp_path / "orders").mkdir()
    (tmp_path / "orders" / "query.py").write_text(VULNERABLE_SOURCE, encoding="utf-8")
    return tmp_path


class TestSuppressions:
    """A pragma in the scanned repo is the author answering the finding.

    Before this, `# checkov:skip=` / `# nosemgrep` results were ingested as
    ordinary open findings. That is not merely a miscount: adding the pragma
    shifts the lines below it, and a finding without a snippet is identified
    positionally, so documenting a skip created a SECOND open finding for the
    same thing. The observed case was TheHub's Dockerfiles going from 2 open
    findings to 4 as a direct result of answering them.
    """

    def test_suppressed_result_is_not_a_finding(self) -> None:
        result = sarif_to_findings(
            sarif(extra_result={"suppressions": [{"kind": "inSource"}]}), context()
        )
        assert result.findings == []

    def test_suppression_is_reported_not_silent(self) -> None:
        """Dropping it quietly would make an answered check indistinguishable
        from one that never ran."""
        result = sarif_to_findings(
            sarif(rule_id="CKV_DOCKER_3", extra_result={"suppressions": [{"kind": "inSource"}]}),
            context(),
        )
        assert any("CKV_DOCKER_3" in w for w in result.warnings)
        assert any("suppressed" in w for w in result.warnings)

    def test_rejected_suppression_still_counts(self) -> None:
        """SARIF §3.35.2: `rejected` means the silencing was refused, so the
        result stands. Treating every `suppressions` entry as a silence would
        let a rejected one mute the finding."""
        result = sarif_to_findings(
            sarif(extra_result={"suppressions": [{"kind": "inSource", "status": "rejected"}]}),
            context(),
        )
        assert len(result.findings) == 1

    def test_absent_status_means_accepted(self) -> None:
        """The status field is optional and defaults to accepted."""
        result = sarif_to_findings(
            sarif(extra_result={"suppressions": [{"kind": "external"}]}), context()
        )
        assert result.findings == []

    def test_under_review_suppresses(self) -> None:
        result = sarif_to_findings(
            sarif(extra_result={"suppressions": [{"status": "underReview"}]}), context()
        )
        assert result.findings == []

    def test_empty_suppressions_list_is_not_a_suppression(self) -> None:
        """Some tools emit the key unconditionally."""
        result = sarif_to_findings(sarif(extra_result={"suppressions": []}), context())
        assert len(result.findings) == 1

    def test_suppression_is_not_a_scan_failure(self) -> None:
        """It is a normal, successful scan. Only parse failures degrade status."""
        result = sarif_to_findings(
            sarif(extra_result={"suppressions": [{"kind": "inSource"}]}), context()
        )
        assert result.scan_status == ScanStatus.SUCCESS


class TestSeverity:
    @pytest.mark.parametrize(
        ("score", "expected"),
        [
            (9.8, Severity.CRITICAL),
            (9.0, Severity.CRITICAL),
            (8.9, Severity.HIGH),
            (7.0, Severity.HIGH),
            (6.9, Severity.MEDIUM),
            (4.0, Severity.MEDIUM),
            (3.9, Severity.LOW),
            (0.1, Severity.LOW),
            (0.0, Severity.INFO),
        ],
    )
    def test_bands_match_github_code_scanning(
        self, score: float, expected: Severity
    ) -> None:
        """Same thresholds GitHub uses, so a rule's severity here agrees with
        what the same rule shows on github.com."""
        assert severity_from_security_score(score) == expected

    def test_security_severity_wins_over_level(self) -> None:
        """SARIF `level` has only four values and none of them mean critical."""
        result = sarif_to_findings(sarif(security_severity="9.8", level="warning"), context())
        assert result.findings[0].severity == Severity.CRITICAL

    def test_falls_back_to_level_when_no_score(self) -> None:
        result = sarif_to_findings(sarif(security_severity=None, level="note"), context())
        assert result.findings[0].severity == Severity.LOW

    def test_score_is_kept_as_cvss(self) -> None:
        result = sarif_to_findings(sarif(security_severity="7.5"), context())
        assert result.findings[0].cvss_score == 7.5

    def test_unparseable_score_falls_through_rather_than_crashing(self) -> None:
        result = sarif_to_findings(sarif(security_severity="not-a-number"), context())
        assert result.findings[0].severity == Severity.HIGH  # from level=error


class TestSnippetCapture:
    def test_context_region_is_preferred(self, workspace: Path) -> None:
        """The tool's own snippet with surrounding lines beats anything we
        reconstruct."""
        result = sarif_to_findings(
            sarif(context_snippet="CONTEXT SNIPPET", region_snippet="REGION"),
            context(workspace),
        )
        assert result.findings[0].code_snippet == "CONTEXT SNIPPET"

    def test_region_snippet_is_second_choice(self, workspace: Path) -> None:
        result = sarif_to_findings(sarif(region_snippet="REGION ONLY"), context(workspace))
        assert result.findings[0].code_snippet == "REGION ONLY"

    def test_falls_back_to_reading_the_working_tree(self, workspace: Path) -> None:
        """Without this tier, a tool that omits snippets silently produces
        churn-prone findings."""
        result = sarif_to_findings(sarif(), context(workspace))
        snippet = result.findings[0].code_snippet
        assert snippet is not None
        assert "cursor.execute" in snippet

    def test_no_workspace_and_no_snippet_is_flagged_loudly(self) -> None:
        """The degradation D-001 exists to prevent, made visible."""
        result = sarif_to_findings(sarif(), context(workspace=None))

        assert result.findings[0].code_snippet is None
        assert any("v1-line" in w for w in result.warnings)
        assert any("churn" in w for w in result.warnings)

    def test_symbol_is_inferred_from_the_source(self, workspace: Path) -> None:
        result = sarif_to_findings(sarif(start_line=9), context(workspace))
        assert result.findings[0].symbol == "get_order"

    def test_a_tool_supplied_logical_location_wins(self, workspace: Path) -> None:
        result = sarif_to_findings(
            sarif(logical="orders.query.get_order"), context(workspace)
        )
        assert result.findings[0].symbol == "orders.query.get_order"

    def test_paths_outside_the_workspace_are_refused(self, workspace: Path) -> None:
        """A malformed or hostile SARIF must not pull host files into stored
        finding records."""
        result = sarif_to_findings(
            sarif(uri="../../../../etc/passwd", start_line=1), context(workspace)
        )
        assert result.findings[0].code_snippet is None


class TestMalformedInput:
    def test_truncated_json_yields_no_findings_but_does_not_raise(self) -> None:
        """spec 04 §8: catch parse errors, preserve what exists, still fail."""
        result = sarif_to_findings(b'{"runs": [{"results": [', context())
        assert result.findings == []
        assert result.scan_status is ScanStatus.PARTIAL_FAILURE

    def test_non_utf8_is_survivable(self) -> None:
        result = sarif_to_findings(b"\xff\xfe not json at all", context())
        assert result.scan_status is ScanStatus.PARTIAL_FAILURE

    def test_one_bad_result_does_not_sink_the_batch(self) -> None:
        document = json.loads(sarif().decode())
        document["runs"][0]["results"].insert(0, {"no": "ruleId"})
        document["runs"][0]["results"].append("not even an object")

        result = sarif_to_findings(json.dumps(document).encode(), context())

        assert len(result.findings) == 1, "the good result survives"
        assert result.skipped == 2
        assert result.scan_status is ScanStatus.PARTIAL_FAILURE

    def test_empty_sarif_is_a_clean_success(self) -> None:
        """Scanned and found nothing is a real, successful outcome."""
        empty = json.dumps({"version": "2.1.0", "runs": []}).encode()
        result = sarif_to_findings(empty, context())
        assert result.findings == []
        assert result.scan_status is ScanStatus.SUCCESS

    def test_result_with_no_location_is_still_kept(self) -> None:
        """A repo-level finding has no file. Dropping it would lose real data."""
        document = json.loads(sarif().decode())
        del document["runs"][0]["results"][0]["locations"]

        result = sarif_to_findings(json.dumps(document).encode(), context())

        assert len(result.findings) == 1
        assert result.findings[0].file_path is None


class TestUriHandling:
    @pytest.mark.parametrize(
        "uri",
        ["orders/query.py", "./orders/query.py", "file:///orders/query.py"],
    )
    def test_uris_normalise_to_repo_relative_paths(self, uri: str) -> None:
        result = sarif_to_findings(sarif(uri=uri), context())
        assert result.findings[0].file_path == "orders/query.py"


class TestCodeQLDirectory:
    def test_merges_one_sarif_per_language(self, tmp_path: Path) -> None:
        results = tmp_path / "codeql-results"
        results.mkdir()
        (results / "python.sarif").write_bytes(sarif(rule_id="py/sql-injection"))
        (results / "javascript.sarif").write_bytes(sarif(rule_id="js/xss"))

        outcome = normalize_directory(results, context())

        assert {f.rule_id for f in outcome.findings} == {"py/sql-injection", "js/xss"}

    def test_missing_output_directory_is_a_failure_not_an_empty_scan(
        self, tmp_path: Path
    ) -> None:
        """spec 04 §6: 'found nothing' and 'never produced output' must not
        look the same in the lake."""
        outcome = normalize_directory(tmp_path / "nope", context())
        assert outcome.scan_status is ScanStatus.FAILURE
        assert outcome.findings == []

    def test_empty_output_directory_is_also_a_failure(self, tmp_path: Path) -> None:
        results = tmp_path / "codeql-results"
        results.mkdir()
        assert normalize_directory(results, context()).scan_status is ScanStatus.FAILURE

    def test_tool_version_is_read_from_the_driver(self) -> None:
        assert tool_version_from_sarif(sarif()) == "2.19.0"

    def test_tool_version_degrades_rather_than_raising(self) -> None:
        assert tool_version_from_sarif(b"garbage") == "unknown"


class TestSnippetHelpers:
    def test_slice_includes_context_lines(self) -> None:
        lines = [f"line{i}" for i in range(1, 21)]
        assert slice_snippet(lines, 10, 10) == "line8\nline9\nline10\nline11\nline12"

    def test_slice_clamps_at_file_boundaries(self) -> None:
        assert slice_snippet(["only"], 1, 1) == "only"

    def test_slice_of_nothing_is_none(self) -> None:
        assert slice_snippet([], 5, 5) is None
        assert slice_snippet(["a"], None, None) is None

    def test_slice_tolerates_end_before_start(self) -> None:
        """Malformed SARIF, but it should still yield a usable snippet rather
        than degrade the finding to positional identity."""
        lines = [f"line{i}" for i in range(1, 21)]
        assert slice_snippet(lines, 10, 4) == slice_snippet(lines, 10, 10)

    @pytest.mark.parametrize(
        ("source", "line", "expected"),
        [
            (["def handler(req):", "    x = 1"], 2, "handler"),
            (["class Orders:", "    def get(self):", "        pass"], 3, "get"),
            (["function doThing() {", "  bad();"], 2, "doThing"),
            (["func Handle(w, r) {", "  bad()"], 2, "Handle"),
            (["const run = async () => {", "  bad()"], 2, "run"),
            (["x = 1", "y = 2"], 2, None),
        ],
    )
    def test_symbol_inference(
        self, source: list[str], line: int, expected: str | None
    ) -> None:
        assert infer_symbol(source, line) == expected

    def test_symbol_inference_is_deterministic(self) -> None:
        """A consistently-wrong symbol still yields a stable fingerprint; an
        inconsistent one would not."""
        lines = VULNERABLE_SOURCE.splitlines()
        assert infer_symbol(lines, 9) == infer_symbol(lines, 9) == "get_order"

    def test_unreadable_file_returns_none(self, tmp_path: Path) -> None:
        assert read_source_lines(tmp_path, "does/not/exist.py") is None
        assert read_source_lines(None, "anything.py") is None


class TestFingerprintEndToEnd:
    """The point of the whole adapter: identity that survives refactoring."""

    def _finding_id(self, workspace: Path, source: str, start_line: int) -> tuple[str, str]:
        (workspace / "orders" / "query.py").write_text(source, encoding="utf-8")
        result = sarif_to_findings(sarif(start_line=start_line), context(workspace))
        finding = result.findings[0]
        return compute_finding_id(
            repo_full_name=REPO,
            capability="sast",
            rule_id=finding.rule_id,
            file_path=finding.file_path,
            symbol=finding.symbol,
            code_snippet=finding.code_snippet,
            line_start=finding.line_start,
        )

    def test_adapter_output_survives_a_line_shift(self, workspace: Path) -> None:
        """Someone adds imports at the top of the file. The finding moves down
        the file but is the same finding — and everything derived from
        first_seen_at depends on us agreeing."""
        before, version = self._finding_id(workspace, VULNERABLE_SOURCE, 9)

        shifted = "import json\nimport logging\nimport sys\n" + VULNERABLE_SOURCE
        after, version_after = self._finding_id(workspace, shifted, 12)

        assert before == after
        assert version == version_after == FINGERPRINT_V2_SNIPPET

    def test_adapter_output_changes_when_the_code_is_fixed(self, workspace: Path) -> None:
        """The counterweight — identity must not be so sticky that a real fix
        goes unnoticed."""
        vulnerable, _ = self._finding_id(workspace, VULNERABLE_SOURCE, 9)
        fixed_source = VULNERABLE_SOURCE.replace(
            'cursor.execute("SELECT * FROM orders WHERE id = " + order_id)',
            'cursor.execute("SELECT * FROM orders WHERE id = ?", [order_id])',
        )
        fixed, _ = self._finding_id(workspace, fixed_source, 9)

        assert vulnerable != fixed

    def test_without_a_workspace_identity_degrades_to_positional(self) -> None:
        """Proves the fallback is real, and that it is labelled — this is the
        mode that quietly destroys trend data if it goes unnoticed."""
        result = sarif_to_findings(sarif(start_line=9), context(workspace=None))
        finding = result.findings[0]

        _, version = compute_finding_id(
            repo_full_name=REPO,
            capability="sast",
            rule_id=finding.rule_id,
            file_path=finding.file_path,
            symbol=finding.symbol,
            code_snippet=finding.code_snippet,
            line_start=finding.line_start,
        )
        assert version == FINGERPRINT_V1_LINE
