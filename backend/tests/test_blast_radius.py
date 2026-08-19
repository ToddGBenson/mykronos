"""Portfolio-wide package concentration — spec 19 §2.4.

The one Oracle input derived from other repositories. Every other category is
a fact about the repo being scored; this one asks whether the package it is
vulnerable to is a package much of the portfolio is also carrying.

Deliberately approximate, and the tests say where. Package name, not version.
Findings, not the full dependency tree. Both limits under-report and neither
over-reports, which is the correct direction for a signal that adds points.
"""

from __future__ import annotations

import pytest

from mykronos import blast_radius
from mykronos.oracle.engine import OracleEngine
from mykronos.oracle.policy import load_policy
from tests.conftest import (
    REPO,
    dependency_finding,
    finding_payload,
    issue_token,
    post_findings,
    post_scan,
)
from tests.test_onboarding import onboard


@pytest.fixture
def engine(client, catalog):
    return OracleEngine(catalog, client.app.state.oracle_policy)


def atlas(package, *, rule_id="CVE-2024-0001"):
    return dependency_finding(package_name=package, rule_id=rule_id)


def seed(client, admin_auth, run_compaction, findings, *, run_id="run-blast"):
    """Findings need a scan run to belong to, and the capability has to be
    enabled before a token for it can ingest anything."""
    repo_id = onboard(client, admin_auth).json()["id"]
    client.patch(
        f"/api/repos/{repo_id}/capabilities",
        json={"capabilities": ["atlas"], "install_workflows": False},
        headers=admin_auth,
    )
    auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'atlas')}"}
    post_scan(client, auth, scan_run_id=run_id, capability="atlas")
    response = post_findings(client, auth, findings, scan_run_id=run_id, capability="atlas")
    assert response.status_code < 300, response.text
    run_compaction()
    return repo_id


class TestTheMap:
    def test_it_counts_distinct_repositories(
        self, client, admin_auth, catalog, run_compaction
    ) -> None:
        seed(
            client,
            admin_auth,
            run_compaction,
            [atlas("urllib3", rule_id="CVE-2024-0001"), atlas("urllib3", rule_id="CVE-2024-0002")],
        )

        # Two findings, one repository. The map counts exposure, not volume.
        assert blast_radius.build(catalog).get("urllib3") == 1

    def test_names_are_case_folded(
        self, client, admin_auth, catalog, run_compaction
    ) -> None:
        """Ecosystems disagree about case and scanners pass it through. Two
        keys for one package would halve every count."""
        seed(
            client,
            admin_auth,
            run_compaction,
            [atlas("Urllib3", rule_id="CVE-2024-0001"), atlas("urllib3", rule_id="CVE-2024-0002")],
        )

        assert list(blast_radius.build(catalog)) == ["urllib3"]

    def test_findings_without_a_package_are_ignored(
        self, client, admin_auth, auth, catalog, run_compaction
    ) -> None:
        """A SAST finding has no package. Bucketing those under an empty name
        would create one enormous phantom dependency."""
        onboard(client, admin_auth)
        post_scan(client, auth)
        post_findings(client, auth, [finding_payload(rule_id="CWE-89")])
        run_compaction()

        assert blast_radius.build(catalog) == {}

    def test_a_resolved_finding_leaves_the_map(
        self, client, admin_auth, catalog, run_compaction
    ) -> None:
        """A package everybody already fixed is not a concentration risk, and
        counting it would make the signal insensitive to exactly the work it
        exists to encourage."""
        seed(client, admin_auth, run_compaction, [atlas("urllib3")])

        finding_id = catalog.query(
            "SELECT finding_id FROM findings WHERE package_name = 'urllib3'"
        )[0][0]
        client.patch(
            f"/api/dashboard/findings/{finding_id}/status",
            json={"status": "false_positive", "reason": "vendored"},
            headers=admin_auth,
        )
        run_compaction()

        assert blast_radius.build(catalog) == {}


class TestTheSnapshot:
    def test_no_map_is_unavailable(self) -> None:
        """The established pattern for every Oracle input: absent, not zero.
        Concentration is a fact about the whole portfolio and cannot be
        derived from one repository's evidence."""
        snapshot, points = blast_radius.snapshot(["urllib3"], None)

        assert snapshot["available"] is False
        assert points == 0.0

    def test_an_empty_map_is_available_and_worth_nothing(self) -> None:
        """A different statement from "not computed", and it reads
        differently in the reasoning: nobody else carries this package."""
        snapshot, points = blast_radius.snapshot(["urllib3"], {})

        assert snapshot["available"] is True
        assert points == 0.0

    def test_a_concentrated_package_scores(self) -> None:
        snapshot, points = blast_radius.snapshot(
            ["urllib3"], {"urllib3": 7}, min_dependents=5, points_per_package=4
        )

        assert points == 4
        assert snapshot["concentrated_packages"] == [
            {"package_name": "urllib3", "dependent_repos": 7}
        ]

    def test_below_the_threshold_is_use_not_concentration(self) -> None:
        """SSCS trust already penalises a repository for its own vulnerable
        dependencies. A threshold of one or two would make this a second
        dependency-count penalty wearing a new name."""
        snapshot, points = blast_radius.snapshot(
            ["urllib3"], {"urllib3": 2}, min_dependents=5, points_per_package=4
        )

        assert points == 0
        assert snapshot["concentrated_packages"] == []

    def test_the_threshold_is_configurable(self) -> None:
        """Where "several teams use it" becomes "concentrated" is a judgement
        about this portfolio's size, not a universal constant."""
        _, lenient = blast_radius.snapshot(
            ["urllib3"], {"urllib3": 3}, min_dependents=3, points_per_package=4
        )

        assert lenient == 4

    def test_a_package_counted_twice_scores_once(self) -> None:
        """The repo can have several findings on one package, and often
        does — one advisory per CVE."""
        _, points = blast_radius.snapshot(
            ["urllib3", "urllib3", "URLLIB3"],
            {"urllib3": 9},
            min_dependents=5,
            points_per_package=4,
        )

        assert points == 4


class TestTheOracleCategory:
    def test_it_is_in_every_snapshot(self, client, admin_auth, engine) -> None:
        """spec 09 §9: every category appears whether or not it has anything
        to say. A key that is sometimes absent makes every consumer
        special-case "not there yet" against "says unknown"."""
        onboard(client, admin_auth)

        assert "blast_radius" in engine.evaluate(REPO).inputs_snapshot

    def test_no_shared_packages_contributes_nothing(
        self, client, admin_auth, engine, run_compaction
    ) -> None:
        seed(client, admin_auth, run_compaction, [atlas("lonely-package")])

        snapshot = engine.evaluate(REPO).inputs_snapshot["blast_radius"]

        assert snapshot["available"] is True
        assert snapshot["contribution"] == 0.0


class TestThePolicy:
    def test_the_shipped_policy_carries_weights(self) -> None:
        from mykronos.config import get_settings

        policy = load_policy(get_settings().oracle_policy_path)

        assert policy.blast_radius.min_dependents >= 2
        assert policy.blast_radius.points_per_package > 0
        assert policy.blast_radius.cap > 0

    def test_the_cap_cannot_swing_a_verdict_alone(self) -> None:
        """The map behind this is package-name matching, not version
        resolution. A deliberately approximate signal must not be able to
        reach `no_go` on its own."""
        from mykronos.config import get_settings

        policy = load_policy(get_settings().oracle_policy_path)

        assert policy.blast_radius.cap < policy.no_go

    def test_a_policy_without_the_block_still_loads(self, tmp_path) -> None:
        """A deployment running the file from before spec 19 §2.4 keeps
        working, with the category available and worth zero. Requiring the
        block would have made the policy change mandatory before the code
        could load at all."""
        import yaml

        from mykronos.config import get_settings

        document = yaml.safe_load(
            get_settings().oracle_policy_path.read_text(encoding="utf-8")
        )
        del document["modifiers"]["blast_radius"]
        path = tmp_path / "old-policy.yaml"
        path.write_text(yaml.safe_dump(document), encoding="utf-8")

        policy = load_policy(path)

        assert policy.blast_radius.points_per_package == 0
