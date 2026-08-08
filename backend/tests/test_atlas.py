"""Atlas — supply-chain trust scoring and evidence (spec 07)."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from mykronos.atlas import evidence_id, score
from mykronos.db.models import CapabilityConfig
from mykronos.schemas import EcosystemEvidence
from tests.conftest import REPO, issue_token
from tests.test_onboarding import onboard


@pytest.fixture
def atlas_auth(client: TestClient) -> dict[str, str]:
    return {"Authorization": f"Bearer {issue_token(client, REPO, 'atlas')}"}


def eco(**overrides) -> EcosystemEvidence:
    payload = {"ecosystem": "npm", "dependency_count": 100}
    payload.update(overrides)
    return EcosystemEvidence(**payload)


def submission(**overrides) -> dict:
    payload = {
        "commit_sha": "a91f2c7",
        "ecosystems": [{"ecosystem": "npm", "dependency_count": 100}],
        "provenance": {"builder": "github-actions", "run_id": "9900123"},
    }
    payload.update(overrides)
    return payload


def post(client, auth, **overrides):
    return client.post("/api/ingest/atlas", json=submission(**overrides), headers=auth)


class TestTrustScore:
    def test_a_clean_tree_scores_100(self) -> None:
        assert score([eco()]).trust_score == 100

    def test_vulnerabilities_are_curved_not_summed(self) -> None:
        """20 × log2(1 + n). Five criticals used to floor the score at 0 — and
        so did five hundred (spec 07 §5)."""
        five = score([eco(critical_vulns=5)])
        fifty = score([eco(critical_vulns=50)])

        assert five.trust_score > 0, "five criticals should not floor the score"
        assert fifty.trust_score < five.trust_score, "ranking must be preserved"

    def test_the_raw_score_survives_the_floor(self) -> None:
        """Two repos both displaying 0 still need an order."""
        bad = score([eco(critical_vulns=500, high_vulns=500)])
        worse = score([eco(critical_vulns=5000, high_vulns=5000)])

        assert bad.trust_score == worse.trust_score == 0
        assert worse.raw_trust_score < bad.raw_trust_score
        assert worse.floored is True

    def test_severity_is_weighted(self) -> None:
        assert (
            score([eco(critical_vulns=4)]).trust_score
            < score([eco(high_vulns=4)]).trust_score
            < score([eco(medium_vulns=4)]).trust_score
        )

    def test_floating_versions_are_penalised_proportionally(self) -> None:
        half = score([eco(dependency_count=100, floating_versions=50)])
        all_of_them = score([eco(dependency_count=100, floating_versions=100)])

        assert half.trust_score == 95
        assert all_of_them.trust_score == 90

    def test_ratio_terms_cannot_saturate(self) -> None:
        """A ratio is already bounded at 1, which is why it stays linear."""
        worst = score(
            [eco(dependency_count=100, floating_versions=100, stale_dependencies=100)]
        )

        assert worst.trust_score == 80

    def test_packages_with_no_maintenance_data_leave_the_denominator(self) -> None:
        """spec 07 §8: excluding them beats counting them as fresh or as stale,
        because either default is a claim the data does not support."""
        known = score(
            [
                eco(
                    dependency_count=100,
                    stale_dependencies=10,
                    maintenance_data_available_for=20,
                )
            ]
        )
        assumed = score([eco(dependency_count=100, stale_dependencies=10)])

        # 10/20 stale is a much worse signal than 10/100.
        assert known.trust_score < assumed.trust_score

    def test_a_monorepo_sums_across_ecosystems(self) -> None:
        """spec 07 §8 — one row per commit, counts summed."""
        combined = score(
            [
                eco(ecosystem="npm", dependency_count=100, critical_vulns=1),
                eco(ecosystem="pypi", dependency_count=50, high_vulns=2),
            ]
        )

        assert combined.dependency_count == 150
        assert combined.vulnerable_dependency_count == 3

    def test_the_arithmetic_is_recorded(self) -> None:
        result = score([eco(critical_vulns=3)])
        term = next(t for t in result.terms if t["key"] == "critical_vulnerabilities")

        assert "log2(1 + 3)" in term["detail"]

    def test_it_is_reproducible(self) -> None:
        """spec 07 §7 makes this an acceptance criterion."""
        counts = [eco(critical_vulns=2, high_vulns=7, dependency_count=213)]

        assert score(counts) == score(counts)

    def test_the_id_is_derived_from_repo_and_commit(self) -> None:
        assert evidence_id(REPO, "abc") == evidence_id(REPO, "abc")
        assert evidence_id(REPO, "abc") != evidence_id(REPO, "def")


class TestIngestion:
    def test_evidence_is_written(
        self, client, admin_auth, atlas_auth, run_compaction, catalog
    ) -> None:
        onboard(client, admin_auth)
        response = post(
            client,
            atlas_auth,
            ecosystems=[
                {"ecosystem": "npm", "dependency_count": 100, "critical_vulns": 1}
            ],
        )
        run_compaction()

        assert response.status_code == 200, response.text
        rows = catalog.query(
            "SELECT dependency_count, vulnerable_dependency_count, trust_score "
            "FROM sscs_evidence"
        )
        assert rows == [(100, 1, 80)]

    def test_the_score_is_computed_server_side(
        self, client, admin_auth, atlas_auth
    ) -> None:
        """Not accepted from the runner: spec 07 §7 requires reproducibility,
        and a score the workflow calculates drifts between action versions."""
        onboard(client, admin_auth)
        payload = submission()
        payload["trust_score"] = 100

        response = client.post("/api/ingest/atlas", json=payload, headers=atlas_auth)

        assert response.status_code == 422

    def test_rescanning_a_commit_upserts(
        self, client, admin_auth, atlas_auth, run_compaction, catalog
    ) -> None:
        onboard(client, admin_auth)
        post(client, atlas_auth)
        run_compaction()
        post(client, atlas_auth)
        run_compaction()

        assert catalog.count("sscs_evidence") == 1

    def test_a_release_adds_its_sbom_to_the_commits_existing_row(
        self, client, admin_auth, atlas_auth, run_compaction, catalog
    ) -> None:
        """spec 07 §7: exactly one evidence row per tagged release, and the
        push scan of the same commit came first."""
        onboard(client, admin_auth)
        post(client, atlas_auth)
        run_compaction()
        post(client, atlas_auth, tag_or_release="v2.1.0", sbom_ref="raw/sbom.json")
        run_compaction()

        assert catalog.count("sscs_evidence") == 1
        assert catalog.query("SELECT tag_or_release, sbom_ref FROM sscs_evidence") == [
            ("v2.1.0", "raw/sbom.json")
        ]

    def test_a_later_push_scan_does_not_blank_the_release_evidence(
        self, client, admin_auth, atlas_auth, run_compaction, catalog
    ) -> None:
        """The SBOM belongs to the commit, and a rescan of that commit does not
        un-release it."""
        onboard(client, admin_auth)
        post(client, atlas_auth, tag_or_release="v2.1.0", sbom_ref="raw/sbom.json")
        run_compaction()
        post(client, atlas_auth)
        run_compaction()

        assert catalog.query("SELECT tag_or_release, sbom_ref FROM sscs_evidence") == [
            ("v2.1.0", "raw/sbom.json")
        ]

    def test_both_land_in_one_compaction_window_without_loss(
        self, client, admin_auth, atlas_auth, run_compaction, catalog
    ) -> None:
        """The D-020 failure mode, on this table: the push row carries no SBOM
        and would win the batch collapse if the patch columns were not
        declared."""
        onboard(client, admin_auth)
        post(client, atlas_auth, tag_or_release="v2.1.0", sbom_ref="raw/sbom.json")
        post(client, atlas_auth)
        run_compaction()

        assert catalog.query("SELECT sbom_ref FROM sscs_evidence") == [
            ("raw/sbom.json",)
        ]

    def test_provenance_and_ecosystem_detail_are_kept(
        self, client, admin_auth, atlas_auth, run_compaction, catalog
    ) -> None:
        onboard(client, admin_auth)
        post(
            client,
            atlas_auth,
            ecosystems=[
                {"ecosystem": "npm", "dependency_count": 100, "critical_vulns": 1},
                {"ecosystem": "pypi", "dependency_count": 40, "high_vulns": 2},
            ],
        )
        run_compaction()

        provenance, ecosystems = catalog.query(
            "SELECT provenance_json, ecosystems_json FROM sscs_evidence"
        )[0]
        assert json.loads(provenance)["run_id"] == "9900123"
        detail = json.loads(ecosystems)
        assert [e["ecosystem"] for e in detail["ecosystems"]] == ["npm", "pypi"]
        assert detail["score_terms"], "the arithmetic travels with the row"

    def test_below_minimum_is_reported_even_when_not_blocking(
        self, client, admin_auth, atlas_auth
    ) -> None:
        """So the workflow log says what would have happened."""
        repo_id = onboard(client, admin_auth).json()["id"]
        with client.app.state.db.session() as session:
            session.add(
                CapabilityConfig(
                    repo_onboarding_id=repo_id,
                    capability="atlas",
                    config_json={"min_trust_score": 95},
                )
            )

        body = post(
            client,
            atlas_auth,
            ecosystems=[
                {"ecosystem": "npm", "dependency_count": 10, "critical_vulns": 2}
            ],
        ).json()

        assert body["below_minimum"] is True
        assert body["blocking"] is False

    def test_the_atlas_grant_is_required(self, client, admin_auth) -> None:
        onboard(client, admin_auth)
        other = {
            "Authorization": f"Bearer {issue_token(client, 'example-org/other', 'sast')}"
        }

        assert post(client, other).status_code == 403

    def test_the_repo_comes_from_the_token(self, client, admin_auth, atlas_auth) -> None:
        onboard(client, admin_auth)
        payload = submission()
        payload["repo_full_name"] = "someone/else"

        response = client.post("/api/ingest/atlas", json=payload, headers=atlas_auth)

        assert response.status_code == 422
