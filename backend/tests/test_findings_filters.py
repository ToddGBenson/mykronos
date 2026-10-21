"""The Findings tab's filter bar: multi-value filters and the new ones.

Every category filter on `open-findings` takes several values, either
comma-separated (`severity=critical,high`) or repeated
(`severity=critical&severity=high`), and one value means exactly what it
always did — old links keep working. `exposure`, `path` and the two age
bounds are new.

Uses `outstanding` (seven open findings): CWE-79 high in web/a.py, web/b.py,
web/c.py; CWE-89 critical and CWE-306 medium in orders/query.py; one urllib3
CVE reported by atlas (high) and containers (critical).
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from mykronos.api.dashboard import _split_commas
from mykronos.dashboard import _like_pattern, _many
from tests.test_dashboard import outstanding  # noqa: F401  (fixture)

URL = "/api/dashboard/repos/{}/open-findings"


def _get(client: TestClient, auth: dict[str, str], repo_id: str, params: Any) -> Any:
    response = client.get(URL.format(repo_id), params=params, headers=auth)
    assert response.status_code == 200, response.text
    return response.json()


def _rules(page: Any) -> set[str]:
    return {g["rule_id"] for g in page["groups"]}


def _declare_web(client: TestClient, auth: dict[str, str], repo_id: str) -> str:
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
    return str(response.json()["id"])


class TestParsing:
    def test_commas_and_repeats_flatten_and_dedupe(self) -> None:
        assert _split_commas("critical,high") == ["critical", "high"]
        assert _split_commas(["critical", "high,critical", " low "]) == [
            "critical",
            "high",
            "low",
        ]

    def test_one_value_is_a_list_of_one_and_blank_is_no_filter(self) -> None:
        assert _split_commas("high") == ["high"]
        assert _split_commas(",") is None
        assert _split_commas(None) is None

    def test_many_accepts_the_old_single_string(self) -> None:
        assert _many("open") == ("open",)
        assert _many(["a", "a", "b"]) == ("a", "b")
        assert _many(None) == ()

    def test_path_is_a_substring_unless_it_is_a_glob(self) -> None:
        assert _like_pattern("web/") == "%web/%"
        assert _like_pattern("web/*.py") == "web/%.py"
        assert _like_pattern("a?c") == "a_c"
        # A literal underscore or percent is not a wildcard.
        assert _like_pattern("my_pkg") == "%my\\_pkg%"
        assert _like_pattern("100%") == "%100\\%%"


class TestMultiValue:
    def test_comma_separated_severities_are_or(
        self, client: TestClient, admin_auth: dict[str, str], outstanding  # noqa: F811
    ) -> None:
        page = _get(client, admin_auth, outstanding, {"severity": "critical,high"})
        counts = page["by_severity"]
        assert page["matching"] == counts["critical"] + counts["high"] == 6
        assert "CWE-306" not in _rules(page)

    def test_repeated_params_mean_the_same_as_commas(
        self, client: TestClient, admin_auth: dict[str, str], outstanding  # noqa: F811
    ) -> None:
        commas = _get(client, admin_auth, outstanding, {"severity": "critical,high"})
        repeated = _get(
            client, admin_auth, outstanding, [("severity", "critical"), ("severity", "high")]
        )
        assert repeated["matching"] == commas["matching"]
        assert _rules(repeated) == _rules(commas)

    def test_a_single_value_link_still_means_what_it_did(
        self, client: TestClient, admin_auth: dict[str, str], outstanding  # noqa: F811
    ) -> None:
        page = _get(client, admin_auth, outstanding, {"severity": "medium"})
        assert _rules(page) == {"CWE-306"}
        assert page["matching"] == 1

    def test_one_bad_value_in_a_list_is_refused(
        self, client: TestClient, admin_auth: dict[str, str], outstanding  # noqa: F811
    ) -> None:
        response = client.get(
            URL.format(outstanding), params={"severity": "critical,nope"}, headers=admin_auth
        )
        assert response.status_code == 422

    def test_capabilities(
        self, client: TestClient, admin_auth: dict[str, str], outstanding  # noqa: F811
    ) -> None:
        page = _get(client, admin_auth, outstanding, {"capability": "atlas,containers"})
        assert _rules(page) == {"CVE-2024-4812"}
        assert page["matching"] == 2

    def test_triage_values(
        self, client: TestClient, admin_auth: dict[str, str], outstanding  # noqa: F811
    ) -> None:
        page = _get(
            client, admin_auth, outstanding, {"triage": "true_positive,toxic_combination"}
        )
        assert _rules(page) == {"CWE-79", "CVE-2024-4812", "CWE-89", "CWE-306"}

    def test_every_due_state_together_is_everything(
        self, client: TestClient, admin_auth: dict[str, str], outstanding  # noqa: F811
    ) -> None:
        page = _get(
            client,
            admin_auth,
            outstanding,
            {"due": "overdue,due_soon,on_track,no_target"},
        )
        assert page["matching"] == page["total"] == 7

    def test_statuses_and_their_counts(
        self, client: TestClient, admin_auth: dict[str, str], outstanding  # noqa: F811
    ) -> None:
        page = _get(client, admin_auth, outstanding, {"finding_status": "open,fixed"})
        assert page["finding_status"] == "open,fixed"
        assert page["total"] == 7
        assert page["by_status"] == {"open": 7}
        # The old single value, and the default, are unchanged.
        assert _get(client, admin_auth, outstanding, {})["finding_status"] == "open"
        fixed = _get(client, admin_auth, outstanding, {"finding_status": "fixed"})
        assert fixed["total"] == 0

    def test_owner_counts_sum_to_total(
        self, client: TestClient, admin_auth: dict[str, str], outstanding  # noqa: F811
    ) -> None:
        page = _get(client, admin_auth, outstanding, {})
        assert sum(page["by_owner"].values()) == page["total"]
        owners = ",".join(page["by_owner"])
        assert _get(client, admin_auth, outstanding, {"owner": owners})["matching"] == 7


class TestPath:
    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("web/", 3),
            ("WEB/", 3),
            ("web/*.py", 3),
            ("*.py", 5),
            ("orders", 2),
            ("urllib", 2),  # the package, for a dependency finding
            ("nowhere", 0),
        ],
    )
    def test_matches_file_or_package(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        outstanding,  # noqa: F811
        path: str,
        expected: int,
    ) -> None:
        page = _get(client, admin_auth, outstanding, {"path": path})
        assert page["matching"] == expected, path


class TestAge:
    def test_first_seen_bounds(
        self, client: TestClient, admin_auth: dict[str, str], outstanding  # noqa: F811
    ) -> None:
        """Everything here was first seen moments ago."""
        assert _get(client, admin_auth, outstanding, {"newer_than_days": 7})["matching"] == 7
        assert _get(client, admin_auth, outstanding, {"older_than_days": 7})["matching"] == 0
        assert _get(client, admin_auth, outstanding, {"older_than_days": 0})["matching"] == 7

    def test_a_negative_age_is_refused(
        self, client: TestClient, admin_auth: dict[str, str], outstanding  # noqa: F811
    ) -> None:
        response = client.get(
            URL.format(outstanding), params={"older_than_days": -1}, headers=admin_auth
        )
        assert response.status_code == 422


class TestExposureAndComponent:
    def test_with_no_surface_everything_is_unplaced(
        self, client: TestClient, admin_auth: dict[str, str], outstanding  # noqa: F811
    ) -> None:
        page = _get(client, admin_auth, outstanding, {})
        assert page["by_exposure"]["unplaced"] == 7
        assert sum(page["by_exposure"].values()) == page["total"]
        assert page["by_component"] == [
            {"value": "none", "label": "in no component", "exposure": "unplaced", "count": 7}
        ]
        internet = _get(client, admin_auth, outstanding, {"exposure": "internet"})
        assert internet["matching"] == 0
        assert internet["groups"] == []

    def test_exposure_is_the_placing_surface_s(
        self, client: TestClient, admin_auth: dict[str, str], outstanding  # noqa: F811
    ) -> None:
        _declare_web(client, admin_auth, outstanding)
        page = _get(client, admin_auth, outstanding, {})
        assert page["by_exposure"]["internet"] == 3
        assert page["by_exposure"]["unplaced"] == 4

        for value, count in page["by_exposure"].items():
            filtered = _get(client, admin_auth, outstanding, {"exposure": value})
            assert filtered["matching"] == count, value
            # Before filters: the counts do not move under the filter.
            assert filtered["by_exposure"] == page["by_exposure"]

        internet = _get(client, admin_auth, outstanding, {"exposure": "internet"})
        assert _rules(internet) == {"CWE-79"}
        both = _get(client, admin_auth, outstanding, {"exposure": "internet,unplaced"})
        assert both["matching"] == 7

    def test_exposure_composes_with_severity(
        self, client: TestClient, admin_auth: dict[str, str], outstanding  # noqa: F811
    ) -> None:
        _declare_web(client, admin_auth, outstanding)
        page = _get(
            client,
            admin_auth,
            outstanding,
            {"exposure": "unplaced", "severity": "critical,high"},
        )
        assert _rules(page) == {"CWE-89", "CVE-2024-4812"}

    def test_a_bad_exposure_is_refused(
        self, client: TestClient, admin_auth: dict[str, str], outstanding  # noqa: F811
    ) -> None:
        response = client.get(
            URL.format(outstanding), params={"exposure": "orbital"}, headers=admin_auth
        )
        assert response.status_code == 422

    def test_component_by_surface_id(
        self, client: TestClient, admin_auth: dict[str, str], outstanding  # noqa: F811
    ) -> None:
        surface_id = _declare_web(client, admin_auth, outstanding)
        page = _get(client, admin_auth, outstanding, {})
        web = next(c for c in page["by_component"] if c["value"] == surface_id)
        assert web == {
            "value": surface_id,
            "label": "Web handlers",
            "exposure": "internet",
            "count": 3,
        }
        only_web = _get(client, admin_auth, outstanding, {"component": surface_id})
        assert _rules(only_web) == {"CWE-79"}
        assert only_web["matching"] == 3
        # The old `component=none` link still lists the unplaced four.
        assert _get(client, admin_auth, outstanding, {"component": "none"})["matching"] == 4
        both = _get(client, admin_auth, outstanding, {"component": f"none,{surface_id}"})
        assert both["matching"] == 7
