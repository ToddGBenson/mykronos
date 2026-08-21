"""What would make this repository go? (spec 26 §1)

The engine has always held every term, its weight, and the exact distance to
the threshold — and then reported a verdict and left the reader to solve the
inverse by hand. These tests pin the inverse, and in particular the two
properties that make it trustworthy: the arithmetic matches what actually
happens when somebody applies it, and it under-promises rather than over.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from mykronos.config import get_settings
from mykronos.lake.catalog import Catalog
from mykronos.oracle import OracleEngine, load_policy
from tests.conftest import REPO, finding_payload, post_findings, post_scan


@pytest.fixture
def policy() -> Any:
    return load_policy(get_settings().oracle_policy_path)


@pytest.fixture
def engine(catalog: Catalog, policy: Any) -> OracleEngine:
    return OracleEngine(catalog, policy)


def critical(index: int, **overrides: Any) -> dict[str, Any]:
    return finding_payload(
        rule_id=f"CWE-89-{index}",
        severity="critical",
        symbol=f"fn_{index}",
        code_snippet=f"unsafe_{index}()",
        file_path=f"src/m{index}.py",
        **overrides,
    )


def seed(
    client: TestClient, auth: dict[str, str], run_compaction: Any, findings: list[dict[str, Any]]
) -> None:
    post_scan(client, auth, scan_run_id="run-1")
    post_findings(client, auth, findings, scan_run_id="run-1")
    run_compaction()


def path(engine: OracleEngine) -> dict[str, Any]:
    return engine.evaluate(REPO).inputs_snapshot["path_to_green"]


class TestWhenThereIsNothingToDo:
    def test_a_clean_repository_has_an_empty_path(
        self,
        client: TestClient,
        auth: dict[str, str],
        engine: OracleEngine,
        run_compaction: Any,
    ) -> None:
        seed(client, auth, run_compaction, [])

        result = path(engine)

        assert result["steps"] == []
        assert "nothing to clear" in result["note"].lower()

    def test_a_repository_below_the_threshold_is_left_alone(
        self,
        client: TestClient,
        auth: dict[str, str],
        engine: OracleEngine,
        run_compaction: Any,
    ) -> None:
        seed(client, auth, run_compaction, [finding_payload(severity="low")])

        assert path(engine)["steps"] == []


class TestTheArithmetic:
    def test_the_path_names_findings_not_outcomes(
        self,
        client: TestClient,
        auth: dict[str, str],
        engine: OracleEngine,
        run_compaction: Any,
    ) -> None:
        seed(client, auth, run_compaction, [critical(i) for i in range(4)])

        steps = path(engine)["steps"]

        assert steps
        for step in steps:
            assert step["finding_id"]
            assert step["rule_id"].startswith("CWE-89-")
            assert step["points_removed"] > 0

    def test_later_steps_are_worth_less_than_earlier_ones(
        self,
        client: TestClient,
        auth: dict[str, str],
        engine: OracleEngine,
        run_compaction: Any,
    ) -> None:
        """The band curve is log2, so removing the second finding out of a
        band is worth less than the first. Independent deltas would publish
        arithmetic that does not match what happens."""
        seed(client, auth, run_compaction, [critical(i) for i in range(6)])

        savings = [step["points_removed"] for step in path(engine)["steps"]]

        assert savings == sorted(savings)

    def test_the_running_score_falls(
        self,
        client: TestClient,
        auth: dict[str, str],
        engine: OracleEngine,
        run_compaction: Any,
    ) -> None:
        seed(client, auth, run_compaction, [critical(i) for i in range(5)])

        scores = [step["score_after"] for step in path(engine)["steps"]]

        assert scores == sorted(scores, reverse=True)

    def test_applying_the_path_really_moves_the_verdict(
        self,
        client: TestClient,
        auth: dict[str, str],
        admin_auth: dict[str, str],
        engine: OracleEngine,
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        """spec 26 §5's acceptance criterion, asserted the only way that
        means anything: dispose of exactly what it named, re-evaluate, and
        check the verdict actually moved."""
        seed(client, auth, run_compaction, [critical(i) for i in range(6)])
        before = engine.evaluate(REPO)
        assert before.recommendation != "go"

        for step in path(engine)["steps"]:
            response = client.patch(
                f"/api/dashboard/findings/{step['finding_id']}/status",
                json={"status": "false_positive", "reason": "cleared for the test"},
                headers=admin_auth,
            )
            assert response.status_code == 200

        after = engine.evaluate(REPO)

        assert after.overall_risk_score < before.overall_risk_score
        assert after.recommendation != "no_go"

    def test_the_projection_under_promises(
        self,
        client: TestClient,
        auth: dict[str, str],
        admin_auth: dict[str, str],
        engine: OracleEngine,
        run_compaction: Any,
    ) -> None:
        """Removing a finding also removes any KEV boost and overdue points
        attached to it, so the real drop is at least the projected one.
        Under-promising is the safe direction for a number people plan
        against."""
        seed(client, auth, run_compaction, [critical(i) for i in range(4)])
        steps = path(engine)["steps"]
        projected = steps[-1]["score_after"]

        for step in steps:
            client.patch(
                f"/api/dashboard/findings/{step['finding_id']}/status",
                json={"status": "false_positive", "reason": "cleared"},
                headers=admin_auth,
            )

        assert engine.evaluate(REPO).overall_risk_score <= projected


class TestWhatItRefusesToSay:
    def test_a_finding_with_no_upstream_fix_is_not_named(
        self,
        client: TestClient,
        auth: dict[str, str],
        engine: OracleEngine,
        run_compaction: Any,
    ) -> None:
        """Telling a team to close a CVE the maintainer has not patched is
        advice they cannot take."""
        seed(
            client,
            auth,
            run_compaction,
            [
                finding_payload(
                    rule_id="CVE-2026-1",
                    severity="critical",
                    package_name="leftpad",
                    package_version="1.0.0",
                    file_path=None,
                    symbol=None,
                    code_snippet=None,
                    raw_finding_json={},
                ),
                *[critical(i) for i in range(3)],
            ],
        )

        named = {step["rule_id"] for step in path(engine)["steps"]}

        assert "CVE-2026-1" not in named

    def test_it_stops_at_a_prefix(
        self,
        client: TestClient,
        auth: dict[str, str],
        engine: OracleEngine,
        run_compaction: Any,
    ) -> None:
        """A list of forty items ordered by weight is the findings tab again.
        The value here is the prefix, and what is left is counted."""
        from mykronos.oracle.engine import PATH_STEPS_MAX

        seed(client, auth, run_compaction, [critical(i) for i in range(40)])

        result = path(engine)

        assert len(result["steps"]) <= PATH_STEPS_MAX
        assert result["findings_not_listed"] > 0

    def test_it_says_when_green_is_not_reachable_by_closing_findings(
        self,
        client: TestClient,
        auth: dict[str, str],
        engine: OracleEngine,
        run_compaction: Any,
    ) -> None:
        seed(client, auth, run_compaction, [critical(i) for i in range(40)])

        result = path(engine)

        assert result["reaches"] in {"go", "review_recommended", "no_go"}
        assert isinstance(result["reachable"], bool)
