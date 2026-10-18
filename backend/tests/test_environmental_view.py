"""Environmental severity on the Findings list, the summary and the Threat
Model tab (TheHub #60828)."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from mykronos import environment, environment_view
from mykronos.db.models import EnvironmentalScore, ThreatIntelMatch
from mykronos.environment_view import StoredScore
from tests.conftest import REPO
from tests.test_dashboard import outstanding  # noqa: F401  (fixture)

HEARTBLEED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"  # 7.5


@pytest.fixture(autouse=True)
def _clean_flags():
    environment.clear()
    yield
    environment.clear()


def _page(client: TestClient, auth: dict[str, str], repo_id: str, **params: Any) -> Any:
    response = client.get(
        f"/api/dashboard/repos/{repo_id}/open-findings", params=params, headers=auth
    )
    assert response.status_code == 200, response.text
    return response.json()


def _ids(page: Any) -> dict[tuple[str, str], str]:
    """(rule_id, capability) -> finding_id, for single-occurrence pairs."""
    return {
        (g["rule_id"], loc["capability"]): loc["finding_id"]
        for g in page["groups"]
        for loc in g["locations"]
    }


def _store(client: TestClient, finding_id: str, scanner: str, effective: str) -> None:
    with client.app.state.db.session() as session:  # type: ignore[attr-defined]
        session.add(
            EnvironmentalScore(
                finding_id=finding_id,
                repo_full_name=REPO,
                vector=HEARTBLEED,
                vector_version="3.1",
                vector_source="nvd",
                base=7.5,
                environmental=7.5,
                base_band="high",
                env_band="high",
                scanner_severity=scanner,
                effective_severity=effective,
                facts_json=[],
                context_id="c",
            )
        )


@pytest.fixture
def rescored(client: TestClient, admin_auth: dict[str, str], outstanding):  # noqa: F811
    """`outstanding` (seven open findings) with three stored scores: the atlas
    CVE rescored down, CWE-306 up, the container CVE unchanged."""
    ids = _ids(_page(client, admin_auth, outstanding))
    _store(client, ids[("CVE-2024-4812", "atlas")], "high", "medium")
    _store(client, ids[("CWE-306", "sast")], "medium", "high")
    _store(client, ids[("CVE-2024-4812", "containers")], "critical", "critical")
    return outstanding, ids


class TestDirection:
    def test_the_word_decides_not_the_number(self) -> None:
        assert environment_view.direction("high", "medium") == "down"
        assert environment_view.direction("medium", "critical") == "up"
        assert environment_view.direction("high", "high") == "unchanged"

    def test_an_unknown_word_is_never_a_rescore(self) -> None:
        assert environment_view.direction("", "low") == "unchanged"

    def test_counts_sum_to_the_findings_counted(self) -> None:
        stored = {"a": StoredScore("low", "high", 7.5, 3.1)}
        counts = environment_view.count_states(["a", "b", "c"], stored)
        assert counts == {"down": 1, "up": 0, "unchanged": 0, "not_rescorable": 2}
        assert environment_view.count_effective(["a", "b"], stored)["low"] == 1


class TestOpenFindingsRescoring:
    def test_summary_counts_come_from_the_stored_scores_and_sum_to_total(
        self, client: TestClient, admin_auth: dict[str, str], rescored
    ) -> None:
        repo_id, _ = rescored
        page = _page(client, admin_auth, repo_id)

        assert page["by_rescoring"] == {
            "down": 1,
            "up": 1,
            "unchanged": 1,
            "not_rescorable": 4,
        }
        assert sum(page["by_rescoring"].values()) == page["total"]
        assert page["by_effective_severity"]["critical"] == 1
        assert page["by_effective_severity"]["medium"] == 1

    def test_each_count_is_exactly_what_its_filter_lists(
        self, client: TestClient, admin_auth: dict[str, str], rescored
    ) -> None:
        repo_id, _ = rescored
        counts = _page(client, admin_auth, repo_id)["by_rescoring"]
        for state, count in counts.items():
            filtered = _page(client, admin_auth, repo_id, rescored=state)
            assert filtered["matching"] == count, state
            # The summary is before filters: it must not move under them.
            assert filtered["by_rescoring"] == counts

    def test_rescored_down_lists_only_the_occurrence_that_moved(
        self, client: TestClient, admin_auth: dict[str, str], rescored
    ) -> None:
        """The atlas and container reports of one CVE are one group; only the
        atlas occurrence was rescored down, so only it is listed."""
        repo_id, ids = rescored
        page = _page(client, admin_auth, repo_id, rescored="down")

        [group] = page["groups"]
        assert [loc["finding_id"] for loc in group["locations"]] == [
            ids[("CVE-2024-4812", "atlas")]
        ]
        assert group["effective_severity"] == "medium"

    def test_the_effective_column_is_the_worst_stored_and_null_without_one(
        self, client: TestClient, admin_auth: dict[str, str], rescored
    ) -> None:
        repo_id, _ = rescored
        groups = {g["rule_id"]: g for g in _page(client, admin_auth, repo_id)["groups"]}

        assert groups["CVE-2024-4812"]["effective_severity"] == "critical"
        assert {
            loc["capability"]: loc["effective_severity"]
            for loc in groups["CVE-2024-4812"]["locations"]
        } == {"atlas": "medium", "containers": "critical"}
        assert groups["CWE-306"]["effective_severity"] == "high"
        # Not rescorable: no effective severity, never the scanner's word.
        assert groups["CWE-79"]["effective_severity"] is None

    def test_the_effective_filter_keeps_that_effective_severity(
        self, client: TestClient, admin_auth: dict[str, str], rescored
    ) -> None:
        repo_id, _ = rescored
        page = _page(client, admin_auth, repo_id, effective="high")

        assert [g["rule_id"] for g in page["groups"]] == ["CWE-306"]
        assert page["matching"] == 1

    def test_a_bad_filter_value_is_refused(
        self, client: TestClient, admin_auth: dict[str, str], outstanding  # noqa: F811
    ) -> None:
        response = client.get(
            f"/api/dashboard/repos/{outstanding}/open-findings",
            params={"rescored": "sideways"},
            headers=admin_auth,
        )
        assert response.status_code == 422

    def test_after_a_real_rescore_the_list_agrees_with_the_store(
        self, client: TestClient, admin_auth: dict[str, str], outstanding  # noqa: F811
    ) -> None:
        """End to end: `environment.rescore` writes the rows, the list reads
        them. Both reports of the CVE get a score; nothing else has a vector."""
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            session.add(ThreatIntelMatch(cve_id="CVE-2024-4812", cvss_vector=HEARTBLEED))
        state = client.app.state  # type: ignore[attr-defined]
        result = environment.rescore(state.db, state.catalog, REPO)
        assert result.scored == 2

        page = _page(client, admin_auth, outstanding)
        assert page["by_rescoring"]["not_rescorable"] == 5
        assert sum(page["by_rescoring"].values()) == page["total"] == 7


class TestComponentCoverage:
    def _declare_web(self, client: TestClient, auth: dict[str, str], repo_id: str) -> None:
        response = client.post(
            f"/api/dashboard/repos/{repo_id}/surfaces",
            json={
                "kind": "entry_point",
                "name": "Web handlers",
                "exposure": "internet",
                "selectors": {"paths": ["web/**"]},
            },
            headers=auth,
        )
        assert response.status_code == 200, response.text

    def _coverage(self, client: TestClient, auth: dict[str, str], repo_id: str) -> Any:
        response = client.get(f"/api/dashboard/repos/{repo_id}/threat-model", headers=auth)
        assert response.status_code == 200, response.text
        return response.json()["component_coverage"]

    def test_with_no_surface_every_open_finding_maps_to_none(
        self, client: TestClient, admin_auth: dict[str, str], outstanding  # noqa: F811
    ) -> None:
        coverage = self._coverage(client, admin_auth, outstanding)
        assert coverage == {
            "open_findings": 7,
            "unplaced": 7,
            "surfaces": 0,
            "located_surfaces": 0,
        }

    def test_the_count_and_the_linked_list_agree(
        self, client: TestClient, admin_auth: dict[str, str], outstanding  # noqa: F811
    ) -> None:
        """Three CWE-79 findings under web/ are placed; the other four are not,
        and `component=none` lists exactly those four."""
        self._declare_web(client, admin_auth, outstanding)

        coverage = self._coverage(client, admin_auth, outstanding)
        assert coverage["unplaced"] == 4
        assert coverage["located_surfaces"] == 1

        page = _page(client, admin_auth, outstanding, component="none")
        assert page["matching"] == coverage["unplaced"]
        assert "CWE-79" not in {g["rule_id"] for g in page["groups"]}


class TestSeverityHereProvenance:
    def test_names_the_vector_source_and_each_facts_scope(
        self, client: TestClient, admin_auth: dict[str, str], outstanding  # noqa: F811
    ) -> None:
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            session.add(ThreatIntelMatch(cve_id="CVE-2024-4812", cvss_vector=HEARTBLEED))
        client.put(
            f"/api/repos/{outstanding}/risk-profile",
            json={"data_classification": "regulated"},
            headers=admin_auth,
        )
        finding_id = _ids(_page(client, admin_auth, outstanding))[("CVE-2024-4812", "atlas")]

        here = client.get(
            f"/api/dashboard/findings/{finding_id}/record", headers=admin_auth
        ).json()["severity_here"]

        assert here["vector_source"] == "nvd"
        assert here["vector_version"] == "3.1"
        cr = next(f for f in here["facts"] if f["metric"] == "CR")
        assert cr["source_kind"] == "risk_profile"
        assert cr["scope"] is None
        assert "evidence_id" in cr
