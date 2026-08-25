"""Coverage beside pass rate (spec 31 §4).

A green sparkline says the tests that exist passed. A repository with one
trivial test and a 100% pass rate renders identically to one with a real
suite, which is how a number stops carrying information.

Two things this must get right, and they are the two tests to read first. A
coverage report is **not** a broken JUnit file — before this it was handed to
the JUnit parser, found no `testsuite`, and downgraded a green run to
`no_applicable_targets`, so the file carrying the most useful context about a
suite was actively making the record worse. And a lane with no coverage report
is not a lane measured at zero; rendering both as 0% would make the honest one
look like the broken one.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from mykronos.adapters.base import ScanContext
from mykronos.adapters.registry import normalize_results
from mykronos.adapters.tests_junit import normalize
from mykronos.lake.catalog import Catalog
from mykronos.schemas import ScanStatus
from tests.conftest import REPO, issue_token, post_scan
from tests.test_onboarding import onboard

COBERTURA = (
    '<?xml version="1.0" ?>'
    '<coverage line-rate="0.8734" branch-rate="0.6" version="7.4.0">'
    "<packages/></coverage>"
)

JACOCO = (
    '<?xml version="1.0" ?><report name="app">'
    '<counter type="INSTRUCTION" missed="10" covered="90"/>'
    '<counter type="BRANCH" missed="4" covered="6"/>'
    '<counter type="LINE" missed="25" covered="75"/>'
    "</report>"
)

JUNIT = (
    '<?xml version="1.0" ?>'
    '<testsuite name="s" tests="4" failures="0" errors="0" skipped="0"/>'
)


def context() -> ScanContext:
    return ScanContext(
        repo_full_name=REPO,
        capability="unit",
        tool_name="junit",
        tool_version="",
        commit_sha="a" * 40,
        branch="main",
    )


class TestACoverageReportIsNotABrokenJUnitFile:
    def test_cobertura_yields_rates_not_a_warning(self) -> None:
        """Before this, `coverage.xml` beside `unit.xml` downgraded a green
        run to `no_applicable_targets` — so the most useful file in the
        directory made the record worse."""
        result = normalize(COBERTURA.encode(), context())

        assert result.scan_status is ScanStatus.SUCCESS
        assert result.warnings == []
        assert result.line_coverage == pytest.approx(0.8734)
        assert result.branch_coverage == pytest.approx(0.6)

    def test_jacoco_counters_become_a_ratio(self) -> None:
        """JaCoCo reports covered/missed pairs rather than a rate."""
        result = normalize(JACOCO.encode(), context())

        assert result.line_coverage == pytest.approx(0.75)
        assert result.branch_coverage == pytest.approx(0.6)

    def test_only_the_report_level_counters_count(self) -> None:
        """Summing every nested counter would count the same lines once per
        level of the tree."""
        nested = (
            '<report name="app">'
            '<counter type="LINE" missed="50" covered="50"/>'
            '<package name="a"><counter type="LINE" missed="0" covered="100"/></package>'
            "</report>"
        )

        assert normalize(nested.encode(), context()).line_coverage == pytest.approx(0.5)

    def test_a_junit_file_still_parses_as_one(self) -> None:
        result = normalize(JUNIT.encode(), context())

        assert result.scan_status is ScanStatus.SUCCESS
        assert result.line_coverage is None

    def test_the_right_shape_with_nothing_in_it_says_so(self) -> None:
        """Rather than being treated as a report that measured zero."""
        result = normalize(b'<coverage version="7.4.0"/>', context())

        assert result.line_coverage is None
        assert "no usable rates" in result.warnings[0]

    def test_a_rate_outside_zero_to_one_is_clamped(self) -> None:
        result = normalize(b'<coverage line-rate="1.4" branch-rate="-0.2"/>', context())

        assert result.line_coverage == 1.0
        assert result.branch_coverage == 0.0

    def test_an_unparseable_rate_is_not_a_crash(self) -> None:
        result = normalize(b'<coverage line-rate="n/a"/>', context())

        assert result.line_coverage is None


class TestMergingAcrossFiles:
    def test_a_suite_and_its_coverage_report_merge(self, tmp_path: Any) -> None:
        """The common shape: `unit.xml` and `coverage.xml` written side by
        side into the same results directory."""
        (tmp_path / "unit.xml").write_text(JUNIT, encoding="utf-8")
        (tmp_path / "coverage.xml").write_text(COBERTURA, encoding="utf-8")

        result = normalize_results("unit", "junit", tmp_path, context())

        assert result.scan_status is ScanStatus.SUCCESS
        assert result.line_coverage == pytest.approx(0.8734)

    def test_sharded_reports_take_the_highest(self, tmp_path: Any) -> None:
        """Each shard measures only the code its own shard touched. Summing
        would exceed 1.0 and averaging would understate a repository whose
        shards are deliberately narrow; the largest is at least a number
        somebody actually observed."""
        (tmp_path / "a.xml").write_text(
            '<coverage line-rate="0.4"/>', encoding="utf-8"
        )
        (tmp_path / "b.xml").write_text(
            '<coverage line-rate="0.9"/>', encoding="utf-8"
        )

        assert normalize_results(
            "unit", "junit", tmp_path, context()
        ).line_coverage == pytest.approx(0.9)


class TestTheRecordAndTheTab:
    def _unit_auth(self, client: TestClient) -> dict[str, str]:
        return {"Authorization": f"Bearer {issue_token(client, REPO, 'unit')}"}

    def _health(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> dict[str, dict[str, Any]]:
        repo_id = client.get("/api/dashboard/portfolio", headers=admin_auth).json()[
            "repos"
        ][0]["repo_id"]
        body = client.get(
            f"/api/dashboard/repos/{repo_id}/scan-health", headers=admin_auth
        ).json()
        return {row["capability"]: row for row in body["capabilities"]}

    def test_it_reaches_the_lake(
        self, client: TestClient, catalog: Catalog, run_compaction
    ) -> None:
        post_scan(
            client,
            self._unit_auth(client),
            capability="unit",
            tool_name="junit",
            line_coverage=0.873,
            branch_coverage=0.6,
        )
        run_compaction()

        stored = catalog.query("SELECT line_coverage, branch_coverage FROM scan_runs")[0]

        assert stored[0] == pytest.approx(0.873)
        assert stored[1] == pytest.approx(0.6)

    def test_a_rate_above_one_is_refused_at_the_door(self, client: TestClient) -> None:
        """A coverage of 140% is a units bug somewhere upstream, and storing
        it would put it on the tab as fact."""
        response = post_scan(
            client,
            self._unit_auth(client),
            capability="unit",
            tool_name="junit",
            line_coverage=1.4,
        )

        assert response.status_code == 422

    def test_the_tab_serves_it(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        onboard(client, admin_auth)
        post_scan(
            client,
            self._unit_auth(client),
            capability="unit",
            tool_name="junit",
            line_coverage=0.873,
        )
        run_compaction()

        assert self._health(client, admin_auth)["unit"]["line_coverage"] == pytest.approx(
            0.873
        )

    def test_a_lane_with_no_report_is_null_not_zero(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        """A lane with no coverage report and a lane measured at zero are
        different facts, and rendering both as 0% would make the honest one
        look like the broken one."""
        onboard(client, admin_auth)
        post_scan(client, auth)
        run_compaction()

        assert self._health(client, admin_auth)["sast"]["line_coverage"] is None

    def test_the_last_run_that_reported_it_wins_not_the_last_run(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        """A pipeline that writes a coverage report on scheduled runs and not
        on every push would otherwise show a number one day and a blank the
        next, which reads as coverage having been lost."""
        onboard(client, admin_auth)
        unit_auth = self._unit_auth(client)
        post_scan(
            client, unit_auth, scan_run_id="with", capability="unit",
            tool_name="junit", line_coverage=0.9,
        )
        post_scan(
            client, unit_auth, scan_run_id="without", capability="unit",
            tool_name="junit",
        )
        run_compaction()

        row = self._health(client, admin_auth)["unit"]

        assert row["line_coverage"] == pytest.approx(0.9)
        assert row["coverage_at"] is not None
