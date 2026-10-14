"""Findings exports: CSV, SARIF 2.1.0 and a printable report (TheHub #60762)."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from jsonschema import Draft4Validator

from mykronos.findings_export import CSV_COLUMNS
from tests.conftest import (
    CAPABILITY,
    REPO,
    dependency_finding,
    finding_payload,
    issue_token,
    post_findings,
    post_scan,
)
from tests.test_onboarding import onboard

SCHEMA = Path(__file__).parent / "data" / "sarif-schema-2.1.0.json"
FORMULA = "=HYPERLINK(\"http://evil.test\",\"x\")"
SCRIPT = "<script>alert(1)</script>"


@pytest.fixture
def exported(client: TestClient, admin_auth: dict[str, str], run_compaction):
    """A repo with a critical, a high, a low marked false positive, and a
    dependency finding; the low one's title is a formula and a script tag."""
    repo_id = onboard(client, admin_auth).json()["id"]
    auth = {"Authorization": f"Bearer {issue_token(client, REPO, CAPABILITY)}"}
    post_scan(client, auth, scan_run_id="run-1")
    post_findings(
        client,
        auth,
        [
            finding_payload(rule_id="CWE-89", severity="critical", symbol="a"),
            finding_payload(rule_id="CWE-79", severity="high", symbol="b"),
            finding_payload(
                rule_id="CWE-22", severity="low", symbol="c", title=FORMULA + SCRIPT
            ),
            dependency_finding(),
        ],
        scan_run_id="run-1",
    )
    run_compaction()
    low = next(
        f
        for f in client.get(
            f"/api/dashboard/repos/{repo_id}/findings", headers=admin_auth
        ).json()["findings"]
        if f["rule_id"] == "CWE-22"
    )
    response = client.patch(
        f"/api/dashboard/findings/{low['finding_id']}/status",
        json={"status": "false_positive", "reason": "Path is a constant, not user input."},
        headers=admin_auth,
    )
    assert response.status_code == 200, response.text
    run_compaction()
    return repo_id


def _export(client, auth, repo_id, fmt, **params):
    return client.get(
        f"/api/dashboard/repos/{repo_id}/findings/export",
        params={"format": fmt, **params},
        headers=auth,
    )


class TestCsv:
    def test_columns_are_the_documented_set_in_order(
        self, client, admin_auth, exported
    ) -> None:
        response = _export(client, admin_auth, exported, "csv")

        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/csv")
        assert "attachment" in response.headers["content-disposition"]
        rows = list(csv.reader(io.StringIO(response.text)))
        assert tuple(rows[0]) == CSV_COLUMNS
        assert len(rows) == 5
        # Worst first, as the list orders it.
        assert rows[1][CSV_COLUMNS.index("severity")] == "critical"

    def test_the_filters_are_the_lists(self, client, admin_auth, exported) -> None:
        response = _export(client, admin_auth, exported, "csv", severity="critical")

        rows = list(csv.reader(io.StringIO(response.text)))
        assert [r[CSV_COLUMNS.index("rule_id")] for r in rows[1:]] == ["CWE-89"]

    def test_a_formula_is_exported_as_text(self, client, admin_auth, exported) -> None:
        """CSV injection: a scanner writes the title."""
        rows = list(csv.reader(io.StringIO(_export(client, admin_auth, exported, "csv").text)))
        [title] = [r[CSV_COLUMNS.index("title")] for r in rows[1:] if r[4] == "CWE-22"]
        assert title.startswith("'=")

    def test_a_disposition_carries_its_reason_and_who(
        self, client, admin_auth, exported
    ) -> None:
        reader = csv.DictReader(io.StringIO(_export(client, admin_auth, exported, "csv").text))
        [row] = [r for r in reader if r["rule_id"] == "CWE-22"]
        assert row["status"] == "false_positive"
        assert row["disposition_reason"] == "Path is a constant, not user input."
        assert row["disposition_by"]
        assert row["tool"] == "codeql"


class TestSarif:
    def test_validates_against_the_published_schema(
        self, client, admin_auth, exported
    ) -> None:
        response = _export(client, admin_auth, exported, "sarif")

        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/sarif+json")
        document = response.json()
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        errors = sorted(Draft4Validator(schema).iter_errors(document), key=str)
        assert not errors, [e.message for e in errors[:5]]
        assert document["version"] == "2.1.0"

    def test_one_run_per_tool_with_rules_and_levels(
        self, client, admin_auth, exported
    ) -> None:
        [run] = _export(client, admin_auth, exported, "sarif").json()["runs"]

        assert run["tool"]["driver"]["name"] == "codeql"
        assert {r["id"] for r in run["tool"]["driver"]["rules"]} >= {"CWE-89", "CWE-22"}
        levels = {r["ruleId"]: r["level"] for r in run["results"]}
        assert levels["CWE-89"] == "error"
        assert levels["CWE-22"] == "note"
        assert run["versionControlProvenance"][0]["revisionId"] == "a91f2c7"

    def test_a_disposition_is_a_suppression_with_its_justification(
        self, client, admin_auth, exported
    ) -> None:
        [run] = _export(client, admin_auth, exported, "sarif").json()["runs"]
        by_rule = {r["ruleId"]: r for r in run["results"]}

        [suppression] = by_rule["CWE-22"]["suppressions"]
        assert suppression["justification"] == "Path is a constant, not user input."
        assert suppression["status"] == "accepted"
        assert "suppressions" not in by_rule["CWE-89"]

    def test_a_dependency_finding_names_its_package(
        self, client, admin_auth, exported
    ) -> None:
        [run] = _export(client, admin_auth, exported, "sarif").json()["runs"]
        [result] = [r for r in run["results"] if r["ruleId"] == "CVE-2024-4812"]
        [location] = result["locations"]
        assert location["logicalLocations"][0]["name"] == "urllib3@2.0.4"


class TestHtml:
    def test_the_header_says_when_what_and_how_filtered(
        self, client, admin_auth, exported
    ) -> None:
        response = _export(client, admin_auth, exported, "html", severity="low")

        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/html")
        assert "attachment" not in response.headers.get("content-disposition", "")
        page = response.text
        assert "Generated " in page
        assert "a91f2c7" in page
        assert "severity=low" in page
        # The summary is the whole repository's open findings, unfiltered.
        assert "Open findings by severity" in page

    def test_scanner_text_is_escaped_and_scripts_are_forbidden(
        self, client, admin_auth, exported
    ) -> None:
        response = _export(client, admin_auth, exported, "html")

        assert SCRIPT not in response.text
        assert "&lt;script&gt;" in response.text
        assert "default-src 'none'" in response.headers["content-security-policy"]


@pytest.mark.parametrize("fmt", ["csv", "sarif", "html"])
@pytest.mark.parametrize("who", ["admin_auth", "viewer_auth"])
def test_no_raw_tool_output_in_any_export(
    client, admin_auth, viewer_auth, exported, fmt, who
) -> None:
    """spec 12 §5. An export leaves the platform, so no role gets the snippet
    or the tool's raw record in one, not even the admin."""
    auth = {"admin_auth": admin_auth, "viewer_auth": viewer_auth}[who]

    response = _export(client, auth, exported, fmt)

    assert response.status_code == 200
    assert "cursor.execute" not in response.text
    assert "raw_finding_json" not in response.text
    assert "code_snippet" not in response.text
