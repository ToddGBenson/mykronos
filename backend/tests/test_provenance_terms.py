"""Provenance in the trust score (spec 29 §3).

Every trust-score term before these was a fact about *dependencies*. Nothing
scored the integrity of the repository's own outputs — whether its commits are
signed, whether its artefacts carry an attestation, whether what it deploys is
pinned by digest rather than by a tag somebody can move underneath it.

Two tests carry the weight. `test_a_repository_reporting_nothing_scores_exactly
_as_before` is spec 29 §4's acceptance criterion and the thing that makes this
safe to ship at all. `test_absent_is_not_the_same_as_no` is the one that keeps
a permissions problem from becoming a supply-chain verdict.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from mykronos.atlas import SIGNED_COMMITS_MIN_SAMPLE, score
from mykronos.schemas import EcosystemEvidence, ProvenanceSignals
from tests.conftest import REPO, issue_token


def npm(**overrides: Any) -> list[EcosystemEvidence]:
    payload: dict[str, Any] = {"ecosystem": "npm", "dependency_count": 100}
    payload.update(overrides)
    return [EcosystemEvidence(**payload)]


def term(assessment: Any, key: str) -> dict[str, Any]:
    return [t for t in assessment.terms if t["key"] == key][0]


ALL_GOOD = ProvenanceSignals(
    signed_commits_ratio=1.0,
    signed_commits_sampled=50,
    attestation_present=True,
    digest_pinned_deployment=True,
)


class TestItChangesNothingItShouldNot:
    def test_a_repository_reporting_nothing_scores_exactly_as_before(self) -> None:
        """spec 29 §4's acceptance criterion, and the reason this is safe to
        ship: every field defaults to absent, so a repository that has never
        heard of provenance scores identically."""
        assert score(npm(critical_vulns=3)).trust_score == score(
            npm(critical_vulns=3), ProvenanceSignals()
        ).trust_score

    def test_a_clean_repository_cannot_exceed_the_ceiling(self) -> None:
        """The score's ceiling means "nothing wrong found". A credit that
        pushed past it would make 100 stop meaning that."""
        assert score(npm(), ALL_GOOD).trust_score == 100

    def test_credits_only_recover_ground_already_lost(self) -> None:
        """The only shape a hygiene bonus can honestly take inside a
        subtractive score."""
        penalised = score(npm(critical_vulns=3)).trust_score
        recovered = score(npm(critical_vulns=3), ALL_GOOD).trust_score

        assert penalised is not None and recovered is not None
        assert penalised < recovered <= 100

    def test_a_repository_cannot_attest_its_way_past_a_critical(self) -> None:
        """Small and capped: these are degrees of hygiene, not
        vulnerabilities."""
        with_everything = score(npm(critical_vulns=20), ALL_GOOD).trust_score
        clean = score(npm()).trust_score

        assert with_everything is not None and clean is not None
        assert with_everything < clean


class TestAbsentIsNotNo:
    def test_absent_is_not_the_same_as_no(self) -> None:
        """A repository whose default branch could not be read has not failed
        the signing check. Scoring the two the same way turns a permissions
        problem into a supply-chain verdict."""
        unread = score(npm(critical_vulns=3), ProvenanceSignals())
        unsigned = score(
            npm(critical_vulns=3),
            ProvenanceSignals(signed_commits_ratio=0.0, signed_commits_sampled=50),
        )

        assert term(unread, "signed_commits")["available"] is False
        assert term(unsigned, "signed_commits")["available"] is True

    def test_an_unavailable_term_says_why(self) -> None:
        """A term that silently contributes zero is how a team concludes the
        model is rigged."""
        assessment = score(npm(critical_vulns=3), ProvenanceSignals())

        for key in ("signed_commits", "attestation_present", "digest_pinned_deployment"):
            entry = term(assessment, key)
            assert entry["available"] is False
            assert entry["detail"]

    def test_absent_and_no_both_score_zero_and_that_is_fine(self) -> None:
        """They contribute the same *points* and make different *claims*, and
        it is the claim the tab renders."""
        unread = score(npm(critical_vulns=3), ProvenanceSignals()).trust_score
        absent = score(
            npm(critical_vulns=3),
            ProvenanceSignals(attestation_present=False, digest_pinned_deployment=False),
        ).trust_score

        assert unread == absent

    def test_a_reported_absence_says_there_is_no_penalty(self) -> None:
        """No credit is not the same as a deduction, and a team reading the
        breakdown should not have to work that out."""
        assessment = score(
            npm(critical_vulns=3), ProvenanceSignals(attestation_present=False)
        )

        assert "no penalty either" in term(assessment, "attestation_present")["detail"]


class TestTheSignedCommitsSample:
    def test_a_tiny_sample_is_not_a_practice(self) -> None:
        """One person signing one merge is not a signing policy."""
        assessment = score(
            npm(critical_vulns=3),
            ProvenanceSignals(signed_commits_ratio=1.0, signed_commits_sampled=2),
        )

        assert term(assessment, "signed_commits")["available"] is False
        assert "coincidence" in term(assessment, "signed_commits")["detail"]

    def test_the_minimum_sample_qualifies(self) -> None:
        assessment = score(
            npm(critical_vulns=3),
            ProvenanceSignals(
                signed_commits_ratio=1.0,
                signed_commits_sampled=SIGNED_COMMITS_MIN_SAMPLE,
            ),
        )

        assert term(assessment, "signed_commits")["available"] is True

    def test_the_credit_scales_with_the_ratio(self) -> None:
        half = score(
            npm(critical_vulns=3),
            ProvenanceSignals(signed_commits_ratio=0.5, signed_commits_sampled=50),
        ).trust_score
        full = score(
            npm(critical_vulns=3),
            ProvenanceSignals(signed_commits_ratio=1.0, signed_commits_sampled=50),
        ).trust_score

        assert half is not None and full is not None
        assert half < full

    def test_the_sample_is_reported(self) -> None:
        """A ratio of 1.0 across two hundred commits is not the same claim as
        1.0 across ten, and a reader has to be able to tell."""
        assessment = score(
            npm(critical_vulns=3),
            ProvenanceSignals(signed_commits_ratio=1.0, signed_commits_sampled=200),
        )

        assert term(assessment, "signed_commits")["count"] == 200


class TestThroughIngestion:
    @pytest.fixture
    def atlas_auth(self, client: TestClient) -> dict[str, str]:
        return {"Authorization": f"Bearer {issue_token(client, REPO, 'atlas')}"}

    def test_the_signals_reach_the_score(
        self, client: TestClient, atlas_auth: dict[str, str]
    ) -> None:
        without = client.post(
            "/api/ingest/atlas",
            json={
                "commit_sha": "a" * 40,
                "ecosystems": [
                    {"ecosystem": "npm", "dependency_count": 100, "critical_vulns": 3}
                ],
            },
            headers=atlas_auth,
        ).json()["trust_score"]

        with_signals = client.post(
            "/api/ingest/atlas",
            json={
                "commit_sha": "b" * 40,
                "ecosystems": [
                    {"ecosystem": "npm", "dependency_count": 100, "critical_vulns": 3}
                ],
                "provenance_signals": {
                    "signed_commits_ratio": 1.0,
                    "signed_commits_sampled": 50,
                    "attestation_present": True,
                    "digest_pinned_deployment": True,
                },
            },
            headers=atlas_auth,
        ).json()["trust_score"]

        assert with_signals > without

    def test_a_ratio_above_one_is_refused(
        self, client: TestClient, atlas_auth: dict[str, str]
    ) -> None:
        """More signed commits than commits is a counting bug upstream, and
        storing it would put it in a score as fact."""
        response = client.post(
            "/api/ingest/atlas",
            json={
                "commit_sha": "a" * 40,
                "ecosystems": [{"ecosystem": "npm", "dependency_count": 1}],
                "provenance_signals": {"signed_commits_ratio": 1.4},
            },
            headers=atlas_auth,
        )

        assert response.status_code == 422

    def test_an_unknown_signal_is_refused(
        self, client: TestClient, atlas_auth: dict[str, str]
    ) -> None:
        """`extra="forbid"`, so a runner reporting a signal the platform does
        not score fails loudly rather than having it silently dropped."""
        response = client.post(
            "/api/ingest/atlas",
            json={
                "commit_sha": "a" * 40,
                "ecosystems": [{"ecosystem": "npm", "dependency_count": 1}],
                "provenance_signals": {"vibes_good": True},
            },
            headers=atlas_auth,
        )

        assert response.status_code == 422
