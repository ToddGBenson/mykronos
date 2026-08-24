"""CWE out of SARIF, and STRIDE out of CWE (spec 28 §1, §2).

Spec 18 §6 explained the Threat Model tab's capability-level mapping by saying
no `Finding` carries a structured CWE. That was true of the schema and never
true of the SARIF at the door: `adapters/sarif.py` read one property —
`security-severity` — and dropped the rest, including the tags where CodeQL
and Semgrep write CWE identifiers.

The test that matters most is the one spec 18 §6 names in its own prose: a
SQL-injection finding and a hardcoded-credential finding from the same tool
used to land in the same two categories.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from mykronos.adapters.sarif import _cwe_ids
from mykronos.dashboard import STRIDE_BY_CAPABILITY, stride_by_cwe
from mykronos.lake.catalog import Catalog
from tests.conftest import post_findings, post_scan
from tests.test_onboarding import onboard


class TestExtraction:
    @pytest.mark.parametrize(
        ("tag", "expected"),
        [
            ("external/cwe/cwe-089", "CWE-89"),   # CodeQL
            ("CWE-79", "CWE-79"),                 # plain
            ("cwe-306", "CWE-306"),               # lowercase
            ("external/cwe/cwe-0089", "CWE-89"),  # leading zeros are cosmetic
        ],
    )
    def test_every_spelling_normalises(self, tag: str, expected: str) -> None:
        """Three spellings of one identifier, and a map keyed on one shape
        must not silently miss another."""
        assert _cwe_ids({"properties": {"tags": [tag]}}, {}) == [expected]

    def test_several_cwes_are_all_kept(self) -> None:
        """A rule legitimately maps to more than one; picking one would be
        the adapter inventing precision."""
        found = _cwe_ids({"properties": {"tags": ["CWE-79", "CWE-89", "security"]}}, {})
        assert found == ["CWE-79", "CWE-89"]

    def test_a_non_cwe_tag_yields_nothing(self) -> None:
        assert _cwe_ids({"properties": {"tags": ["maintainability", "style"]}}, {}) == []

    def test_the_result_is_checked_as_well_as_the_rule(self) -> None:
        """SARIF allows either, and a tool that annotates results would
        otherwise report nothing."""
        assert _cwe_ids(None, {"properties": {"cwe": "cwe-306"}}) == ["CWE-306"]

    def test_nothing_is_inferred_from_a_rule_name(self) -> None:
        """A regex over `rule_id` would be this platform manufacturing a
        taxonomy claim, which spec 18 §6 declined to do."""
        assert _cwe_ids({"id": "sql-injection", "properties": {}}, {}) == []

    def test_duplicates_collapse(self) -> None:
        found = _cwe_ids(
            {"properties": {"tags": ["CWE-89", "external/cwe/cwe-089"]}}, {}
        )
        assert found == ["CWE-89"]


class TestTheMap:
    def test_the_shipped_map_loads(self) -> None:
        assert stride_by_cwe()["CWE-89"] == ("tampering", "information_disclosure")

    def test_a_weakness_can_be_two_things(self) -> None:
        """A SQL injection genuinely both tampers with a query and discloses
        data; one category per weakness would be tidier and wrong."""
        assert len(stride_by_cwe()["CWE-89"]) == 2

    def test_authentication_and_authorisation_are_distinguished(self) -> None:
        assert "spoofing" in stride_by_cwe()["CWE-287"]
        assert "elevation_of_privilege" in stride_by_cwe()["CWE-862"]

    def test_an_absent_file_degrades_to_capability(self, tmp_path: Path) -> None:
        """A deployment without the taxonomy file keeps the behaviour it had.
        Refusing to start would make it a hard dependency of a tab that
        worked without one."""
        stride_by_cwe.cache_clear()
        try:
            assert stride_by_cwe(tmp_path / "nope.yaml") == {}
        finally:
            stride_by_cwe.cache_clear()

    def test_every_category_named_is_a_real_stride_category(self) -> None:
        known = {c for cats in STRIDE_BY_CAPABILITY.values() for c in cats}
        known |= {"repudiation", "denial_of_service", "elevation_of_privilege"}
        for categories in stride_by_cwe().values():
            assert set(categories) <= known


def sarif_finding(rule_id: str, cwes: list[str], **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "rule_id": rule_id,
        "title": f"{rule_id} finding",
        "description": "",
        "severity": "high",
        "file_path": f"src/{rule_id}.py",
        "symbol": rule_id,
        "code_snippet": f"unsafe_{rule_id}()",
        "cwe_ids": cwes,
        "raw_finding_json": {},
    }
    payload.update(overrides)
    return payload


class TestTheThreatModel:
    def _model(self, client: TestClient, admin_auth: dict[str, str]) -> dict[str, Any]:
        repo_id = client.get(
            "/api/dashboard/portfolio", headers=admin_auth
        ).json()["repos"][0]["repo_id"]
        return client.get(
            f"/api/dashboard/repos/{repo_id}/threat-model", headers=admin_auth
        ).json()

    def _seed(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        auth: dict[str, str],
        run_compaction: Any,
        findings: list[dict[str, Any]],
    ) -> None:
        onboard(client, admin_auth)
        post_scan(client, auth)
        post_findings(client, auth, findings)
        run_compaction()

    def test_two_sast_findings_no_longer_share_categories(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        """The failure spec 18 §6 names in its own prose."""
        self._seed(
            client,
            admin_auth,
            auth,
            run_compaction,
            [
                sarif_finding("sqli", ["CWE-89"]),
                sarif_finding("hardcoded", ["CWE-798"]),
            ],
        )

        model = self._model(client, admin_auth)
        by_stride = {
            c["stride"]: {f["rule_id"] for f in c["findings"]} for c in model["categories"]
        }

        # SQL injection: tampering + information disclosure.
        # Hardcoded credential: spoofing + information disclosure.
        assert "sqli" in by_stride["tampering"]
        assert "hardcoded" not in by_stride["tampering"]
        assert "hardcoded" in by_stride["spoofing"]

    def test_a_row_says_how_it_was_placed(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        self._seed(
            client, admin_auth, auth, run_compaction, [sarif_finding("sqli", ["CWE-89"])]
        )

        model = self._model(client, admin_auth)
        placed = [f for c in model["categories"] for f in c["findings"]]

        assert placed
        assert all(f["mapping_resolution"] == "cwe" for f in placed)

    def test_a_finding_with_no_cwe_keeps_the_old_behaviour(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        self._seed(
            client, admin_auth, auth, run_compaction, [sarif_finding("plain", [])]
        )

        model = self._model(client, admin_auth)
        placed = [f for c in model["categories"] for f in c["findings"]]

        assert all(f["mapping_resolution"] == "capability" for f in placed)

    def test_a_mixed_repository_says_mixed(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        """A page-level label would be wrong for half of it."""
        self._seed(
            client,
            admin_auth,
            auth,
            run_compaction,
            [sarif_finding("sqli", ["CWE-89"]), sarif_finding("plain", [])],
        )

        assert self._model(client, admin_auth)["mapping_resolution"] == "mixed"

    def test_an_unmapped_cwe_falls_back_and_is_counted(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        """Visible so the gap gets closed by somebody adding a row, rather
        than resolving to whatever looked closest."""
        self._seed(
            client,
            admin_auth,
            auth,
            run_compaction,
            [sarif_finding("exotic", ["CWE-9999"])],
        )

        model = self._model(client, admin_auth)

        assert model["unmapped_cwes"] == ["CWE-9999"]
        placed = [f for c in model["categories"] for f in c["findings"]]
        assert all(f["mapping_resolution"] == "capability" for f in placed)

    def test_the_cwes_ride_on_the_row(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        self._seed(
            client, admin_auth, auth, run_compaction, [sarif_finding("sqli", ["CWE-89"])]
        )

        placed = [
            f for c in self._model(client, admin_auth)["categories"] for f in c["findings"]
        ]

        assert placed[0]["cwe_ids"] == ["CWE-89"]


class TestPersistence:
    def test_the_lake_keeps_what_the_tool_said(
        self, client: TestClient, auth, catalog: Catalog, run_compaction
    ) -> None:
        post_scan(client, auth)
        post_findings(client, auth, [sarif_finding("sqli", ["CWE-89", "CWE-20"])])
        run_compaction()

        stored = catalog.query("SELECT cwe_ids_json FROM findings")[0][0]

        assert json.loads(stored) == ["CWE-89", "CWE-20"]

    def test_no_cwe_stores_null_not_an_empty_list(
        self, client: TestClient, auth, catalog: Catalog, run_compaction
    ) -> None:
        """Absent is not 'no CWE applies', and the mapping depends on the
        distinction."""
        post_scan(client, auth)
        post_findings(client, auth, [sarif_finding("plain", [])])
        run_compaction()

        assert catalog.query("SELECT cwe_ids_json FROM findings")[0][0] is None
