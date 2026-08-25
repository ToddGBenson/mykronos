"""Which fixed vulnerabilities would we notice coming back? (spec 31)

Findings and the Harness have been adjacent tabs with no relationship. These
tests pin the link between them, and in particular the three things that keep
the number honest: an empty denominator is not a failing grade, a link whose
lane stopped running does not count, and `asserted` is never quietly promoted
to `demonstrated`.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from mykronos import regression
from mykronos.lake.catalog import Catalog
from mykronos.lake.mutate import locate_findings, update_findings
from mykronos.schemas import utcnow
from tests.conftest import REPO, finding_payload, post_findings, post_scan
from tests.test_onboarding import onboard


def seed_fixed(
    client: TestClient, auth: dict[str, str], run_compaction: Any, count: int = 1
) -> list[str]:
    post_scan(client, auth)
    post_findings(
        client,
        auth,
        [finding_payload(rule_id=f"CWE-{i}", symbol=f"fn_{i}") for i in range(count)],
    )
    run_compaction()
    catalog = client.app.state.catalog  # type: ignore[attr-defined]
    ids = [str(r[0]) for r in catalog.query("SELECT finding_id FROM findings ORDER BY rule_id")]
    update_findings(
        catalog,
        locate_findings(catalog, ids),
        "status = 'fixed', resolved_at = ?",
        [utcnow()],
    )
    return ids


def green_lane(client: TestClient, auth: dict[str, str], run_compaction: Any) -> None:
    """A unit lane that completed successfully, so links are not stale.

    Its own token: the default fixture grants `sast` only, and a scan-run
    posted for a capability the token does not hold is a 403 -- which reads
    here as "the lane never ran" and quietly makes every link stale.
    """
    from tests.conftest import issue_token

    unit_auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'unit')}"}
    post_scan(
        client,
        unit_auth,
        scan_run_id="unit-1",
        capability="unit",
        tool_name="junit",
        scan_status="success",
        finding_count=0,
    )
    run_compaction()


class TestTheDenominator:
    def test_nothing_fixed_is_unavailable_not_zero(
        self, client: TestClient, auth, catalog: Catalog, run_compaction
    ) -> None:
        """0% would read as a failing grade rather than an empty
        denominator."""
        post_scan(client, auth)
        post_findings(client, auth, [finding_payload()])
        run_compaction()

        result = regression.coverage(catalog, REPO)

        assert result.available is False
        assert result.ratio is None

    def test_only_fixed_findings_count(
        self, client: TestClient, auth, catalog: Catalog, run_compaction
    ) -> None:
        """A vulnerability never fixed does not need a regression test; it
        needs a fix."""
        seed_fixed(client, auth, run_compaction, count=2)
        post_findings(client, auth, [finding_payload(rule_id="OPEN", symbol="open")],
                      scan_run_id="run-2")
        run_compaction()

        assert regression.coverage(catalog, REPO).fixed_findings == 2


class TestLinking:
    def test_a_link_counts_towards_coverage(
        self, client: TestClient, auth, catalog: Catalog, run_compaction
    ) -> None:
        [finding_id] = seed_fixed(client, auth, run_compaction)
        green_lane(client, auth, run_compaction)
        regression.record(
            client.app.state.buffer,  # type: ignore[attr-defined]
            repo_full_name=REPO,
            finding_id=finding_id,
            test_identifier="tests.test_orders.test_no_sqli",
            capability="unit",
            linked_by="@sam",
        )
        run_compaction()

        result = regression.coverage(catalog, REPO)

        assert (result.covered, result.asserted, result.demonstrated) == (1, 1, 0)
        assert result.ratio == 1.0

    def test_relinking_the_same_test_is_one_row(
        self, client: TestClient, auth, catalog: Catalog, run_compaction
    ) -> None:
        """A webhook delivered twice must not inflate the count."""
        [finding_id] = seed_fixed(client, auth, run_compaction)
        green_lane(client, auth, run_compaction)
        for _ in range(3):
            regression.record(
                client.app.state.buffer,  # type: ignore[attr-defined]
                repo_full_name=REPO,
                finding_id=finding_id,
                test_identifier="tests.test_orders.test_no_sqli",
                capability="unit",
            )
        run_compaction()

        assert catalog.count("finding_tests") == 1

    def test_demonstrated_outranks_asserted(
        self, client: TestClient, auth, catalog: Catalog, run_compaction
    ) -> None:
        """A team that proves its tests work should not be counted the same
        as one that says so — and a later assertion must not demote it."""
        [finding_id] = seed_fixed(client, auth, run_compaction)
        green_lane(client, auth, run_compaction)
        buffer = client.app.state.buffer  # type: ignore[attr-defined]
        regression.record(
            buffer,
            repo_full_name=REPO,
            finding_id=finding_id,
            test_identifier="t.test_x",
            capability="unit",
            evidence=regression.DEMONSTRATED,
        )
        run_compaction()
        regression.record(
            buffer,
            repo_full_name=REPO,
            finding_id=finding_id,
            test_identifier="t.test_x",
            capability="unit",
            evidence=regression.ASSERTED,
        )
        run_compaction()

        result = regression.coverage(catalog, REPO)

        assert result.demonstrated == 1
        assert result.asserted == 0

    def test_an_unknown_lane_is_refused(self, client: TestClient) -> None:
        with pytest.raises(regression.RegressionError, match="not a test lane"):
            regression.record(
                client.app.state.buffer,  # type: ignore[attr-defined]
                repo_full_name=REPO,
                finding_id="x",
                test_identifier="t.test_x",
                capability="sast",
            )

    def test_an_empty_identifier_is_refused(self, client: TestClient) -> None:
        with pytest.raises(regression.RegressionError, match="test identifier"):
            regression.record(
                client.app.state.buffer,  # type: ignore[attr-defined]
                repo_full_name=REPO,
                finding_id="x",
                test_identifier="   ",
                capability="unit",
            )


class TestStaleness:
    def test_a_lane_that_stopped_running_makes_its_links_stale(
        self, client: TestClient, auth, catalog: Catalog, run_compaction
    ) -> None:
        """A protection nobody runs is a protection that quietly expired, and
        counting it would make this a number that only ever goes up."""
        [finding_id] = seed_fixed(client, auth, run_compaction)
        regression.record(
            client.app.state.buffer,  # type: ignore[attr-defined]
            repo_full_name=REPO,
            finding_id=finding_id,
            test_identifier="t.test_x",
            capability="unit",
        )
        run_compaction()

        result = regression.coverage(catalog, REPO)

        assert (result.covered, result.stale) == (0, 1)

    def test_stale_is_reported_beside_the_headline_not_folded_in(
        self, client: TestClient, auth, catalog: Catalog, run_compaction
    ) -> None:
        [finding_id] = seed_fixed(client, auth, run_compaction)
        regression.record(
            client.app.state.buffer,  # type: ignore[attr-defined]
            repo_full_name=REPO,
            finding_id=finding_id,
            test_identifier="t.test_x",
            capability="unit",
        )
        run_compaction()

        body = regression.as_dict(regression.coverage(catalog, REPO))

        assert body["stale"] == 1
        assert body["ratio"] == 0.0

    def test_the_note_states_what_staleness_cannot_catch(self) -> None:
        """The JUnit adapter records suite totals, not case names, so a
        deleted test inside a running lane still counts. Said rather than
        papered over."""
        note = regression.as_dict(regression.Coverage(fixed_findings=1))["note"]

        assert "cannot catch" in note
        assert "D-046" in note


class TestTheApi:
    def _repo_id(self, client: TestClient, admin_auth: dict[str, str]) -> str:
        return client.get("/api/dashboard/portfolio", headers=admin_auth).json()["repos"][0][
            "repo_id"
        ]

    def test_a_person_can_pin_a_test(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        onboard(client, admin_auth)
        [finding_id] = seed_fixed(client, auth, run_compaction)

        r = client.post(
            f"/api/dashboard/findings/{finding_id}/regression-test",
            json={"test_identifier": "tests.test_orders.test_no_sqli"},
            headers=admin_auth,
        )

        assert r.status_code == 200
        assert r.json()["evidence"] == "asserted"

    def test_the_route_cannot_claim_demonstrated(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        """One of the two grades is somebody's word and the other is
        evidence; this route only ever produces the first."""
        onboard(client, admin_auth)
        [finding_id] = seed_fixed(client, auth, run_compaction)

        r = client.post(
            f"/api/dashboard/findings/{finding_id}/regression-test",
            json={"test_identifier": "t.test_x", "evidence": "demonstrated"},
            headers=admin_auth,
        )

        assert r.status_code == 422  # extra="forbid"

    def test_a_viewer_cannot_pin(
        self, client: TestClient, admin_auth, auth, viewer_auth, run_compaction
    ) -> None:
        onboard(client, admin_auth)
        [finding_id] = seed_fixed(client, auth, run_compaction)

        r = client.post(
            f"/api/dashboard/findings/{finding_id}/regression-test",
            json={"test_identifier": "t.test_x"},
            headers=viewer_auth,
        )

        assert r.status_code == 403

    def test_the_coverage_endpoint_serves_it(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        onboard(client, admin_auth)
        [finding_id] = seed_fixed(client, auth, run_compaction)
        green_lane(client, auth, run_compaction)
        client.post(
            f"/api/dashboard/findings/{finding_id}/regression-test",
            json={"test_identifier": "t.test_x"},
            headers=admin_auth,
        )
        run_compaction()

        body = client.get(
            f"/api/dashboard/repos/{self._repo_id(client, admin_auth)}/regression-coverage",
            headers=admin_auth,
        ).json()

        assert body["available"] is True
        assert body["covered"] == 1
        assert body["ratio"] == 1.0

    def test_an_unknown_finding_is_404(
        self, client: TestClient, admin_auth
    ) -> None:
        r = client.post(
            "/api/dashboard/findings/nope/regression-test",
            json={"test_identifier": "t.test_x"},
            headers=admin_auth,
        )

        assert r.status_code == 404
