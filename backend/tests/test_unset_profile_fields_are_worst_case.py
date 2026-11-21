"""An unset data_classification or business_criticality is the worst case (TheHub #61556).

D-176 (policy 1.19) made an unset `internet_facing` on a recorded risk profile
score at the worst answer, as its own term, instead of scoring like `false`.
It left the other two asset facts behind: a profile that leaves
`data_classification` or `business_criticality` unset still added nothing,
which is exactly what `public` data and `low` criticality add. Nobody said
either.

Operator decision 2026-11-21: score each unset field at the worst value its
policy map holds, and say "unset" in the explanation. A recorded value scores
as it did, and no profile at all still adds nothing. All data is synthetic.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient

from mykronos.config import get_settings
from mykronos.oracle import OracleEngine, load_policy
from mykronos.oracle.environmental import DOUBLE_COUNTED
from tests.conftest import REPO
from tests.test_onboarding import onboard
from tests.test_oracle_risk_profile import put_profile, seed

CLASSIFICATION_UNSET = "risk_profile.data_classification_unknown"
CRITICALITY_UNSET = "risk_profile.business_criticality_unknown"


@pytest.fixture
def policy() -> Any:
    return load_policy(get_settings().oracle_policy_path)


def _decide(
    catalog: Any,
    policy: Any,
    client: TestClient,
    admin_auth: dict[str, str],
    run_compaction: Any,
    **profile: Any,
) -> Any:
    # internet_facing recorded, so only the two fields under test can move.
    profile.setdefault("internet_facing", False)
    repo_id = onboard(client, admin_auth).json()["id"]
    put_profile(client, admin_auth, repo_id, **profile)
    seed(client, run_compaction)
    return OracleEngine(catalog, policy, db=client.app.state.db).evaluate(REPO)


def _terms(decision: Any) -> dict[str, dict[str, Any]]:
    return {t["key"]: t for t in decision.inputs_snapshot["terms"]}


def _worst(points: dict[str, float]) -> float:
    return max(points.values())


class TestDataClassificationUnset:
    def test_unset_scores_the_worst_classification(
        self, catalog, policy, client, admin_auth, run_compaction
    ) -> None:
        decision = _decide(
            catalog,
            policy,
            client,
            admin_auth,
            run_compaction,
            business_criticality="low",
        )

        terms = _terms(decision)
        assert "risk_profile.data_classification" not in terms
        unset = terms[CLASSIFICATION_UNSET]
        assert unset["contribution"] == pytest.approx(
            _worst(policy.risk_profile.data_classification_points)
        )
        assert "unset" in unset["label"]
        assert "unset" in unset["detail"]
        snapshot = decision.inputs_snapshot["risk_profile"]
        assert snapshot["data_classification_state"] == "unset"
        assert snapshot["business_criticality_state"] == "recorded"
        assert CRITICALITY_UNSET not in terms

    def test_the_explanation_says_unset(
        self, catalog, policy, client, admin_auth, run_compaction
    ) -> None:
        decision = _decide(
            catalog,
            policy,
            client,
            admin_auth,
            run_compaction,
            business_criticality="low",
        )
        assert "Data classification unset" in decision.reasoning

    def test_unset_scores_above_the_mildest_recorded_value(
        self, catalog, policy, client, admin_auth, run_compaction
    ) -> None:
        """The story in one assertion: unset used to equal `public`."""
        unset = _decide(
            catalog, policy, client, admin_auth, run_compaction, business_criticality="low"
        )
        repo_id = client.get("/api/repos", headers=admin_auth).json()[0]["id"]
        put_profile(
            client,
            admin_auth,
            repo_id,
            internet_facing=False,
            business_criticality="low",
            data_classification="public",
        )
        public = OracleEngine(catalog, policy, db=client.app.state.db).evaluate(REPO)

        assert unset.overall_risk_score > public.overall_risk_score


class TestBusinessCriticalityUnset:
    def test_unset_scores_the_worst_criticality(
        self, catalog, policy, client, admin_auth, run_compaction
    ) -> None:
        decision = _decide(
            catalog,
            policy,
            client,
            admin_auth,
            run_compaction,
            data_classification="public",
        )

        terms = _terms(decision)
        assert "risk_profile.business_criticality" not in terms
        unset = terms[CRITICALITY_UNSET]
        assert unset["contribution"] == pytest.approx(
            _worst(policy.risk_profile.business_criticality_points)
        )
        assert "unset" in unset["label"]
        assert "unset" in unset["detail"]
        snapshot = decision.inputs_snapshot["risk_profile"]
        assert snapshot["business_criticality_state"] == "unset"
        assert snapshot["data_classification_state"] == "recorded"
        assert CLASSIFICATION_UNSET not in terms

    def test_the_explanation_says_unset(
        self, catalog, policy, client, admin_auth, run_compaction
    ) -> None:
        decision = _decide(
            catalog,
            policy,
            client,
            admin_auth,
            run_compaction,
            data_classification="public",
        )
        assert "Business criticality unset" in decision.reasoning


class TestBothUnset:
    def test_both_unset_score_both_worst_cases(
        self, catalog, policy, client, admin_auth, run_compaction
    ) -> None:
        decision = _decide(catalog, policy, client, admin_auth, run_compaction)

        terms = _terms(decision)
        assert CLASSIFICATION_UNSET in terms
        assert CRITICALITY_UNSET in terms
        expected = _worst(policy.risk_profile.data_classification_points) + _worst(
            policy.risk_profile.business_criticality_points
        )
        assert decision.inputs_snapshot["risk_profile"]["contribution"] == pytest.approx(
            expected
        )
        assert "Data classification unset" in decision.reasoning
        assert "Business criticality unset" in decision.reasoning

    def test_an_empty_profile_is_worst_case_on_all_three(
        self, catalog, policy, client, admin_auth, run_compaction
    ) -> None:
        """Nothing recorded at all: every unanswered question at its worst."""
        decision = _decide(
            catalog, policy, client, admin_auth, run_compaction, internet_facing=None
        )

        rp = policy.risk_profile
        expected = (
            rp.internet_facing_unknown_points
            + _worst(rp.data_classification_points)
            + _worst(rp.business_criticality_points)
        )
        assert decision.inputs_snapshot["risk_profile"]["contribution"] == pytest.approx(
            expected
        )


class TestRecordedValuesAreUnchanged:
    @pytest.mark.parametrize("value", ["public", "internal", "confidential", "regulated"])
    def test_a_recorded_classification_scores_its_own_points(
        self, value, catalog, policy, client, admin_auth, run_compaction
    ) -> None:
        decision = _decide(
            catalog,
            policy,
            client,
            admin_auth,
            run_compaction,
            data_classification=value,
            business_criticality="low",
        )

        terms = _terms(decision)
        assert CLASSIFICATION_UNSET not in terms
        assert CRITICALITY_UNSET not in terms
        expected = policy.risk_profile.data_classification_points[value]
        assert decision.inputs_snapshot["risk_profile"]["contribution"] == pytest.approx(
            expected
        )
        assert decision.inputs_snapshot["risk_profile"]["data_classification_state"] == (
            "recorded"
        )

    @pytest.mark.parametrize("value", ["low", "medium", "high", "critical"])
    def test_a_recorded_criticality_scores_its_own_points(
        self, value, catalog, policy, client, admin_auth, run_compaction
    ) -> None:
        decision = _decide(
            catalog,
            policy,
            client,
            admin_auth,
            run_compaction,
            data_classification="public",
            business_criticality=value,
        )

        terms = _terms(decision)
        assert CLASSIFICATION_UNSET not in terms
        assert CRITICALITY_UNSET not in terms
        expected = policy.risk_profile.business_criticality_points[value]
        assert decision.inputs_snapshot["risk_profile"]["contribution"] == pytest.approx(
            expected
        )

    def test_no_profile_still_adds_nothing(
        self, catalog, policy, client, admin_auth, run_compaction
    ) -> None:
        onboard(client, admin_auth)
        seed(client, run_compaction)

        decision = OracleEngine(catalog, policy, db=client.app.state.db).evaluate(REPO)

        snapshot = decision.inputs_snapshot["risk_profile"]
        assert snapshot["available"] is False
        assert snapshot["contribution"] == 0.0
        keys = set(_terms(decision))
        assert CLASSIFICATION_UNSET not in keys
        assert CRITICALITY_UNSET not in keys


class TestThePolicy:
    def test_the_shipped_unset_points_are_the_worst_recorded_value(self, policy) -> None:
        """Stated in the file, like internet_facing_unknown_points, and pinned
        here so raising a recorded weight cannot leave unset scoring below it."""
        rp = policy.risk_profile
        assert rp.data_classification_unknown_points == _worst(rp.data_classification_points)
        assert rp.business_criticality_unknown_points == _worst(
            rp.business_criticality_points
        )

    def test_the_policy_version_moved(self, policy) -> None:
        assert policy.version == "1.20"

    def test_the_file_states_both_keys(self) -> None:
        raw = yaml.safe_load(Path(get_settings().oracle_policy_path).read_text("utf-8"))
        profile = raw["modifiers"]["risk_profile"]
        assert "data_classification_unknown_points" in profile
        assert "business_criticality_unknown_points" in profile


class TestEnvironmental:
    def test_unset_classification_is_not_trimmed_as_double_counted(self) -> None:
        """A recorded classification sets the CVSS confidentiality requirement,
        so its term is trimmed when environmental scoring is live. An unset one
        leaves CR undefined, which is neutral, not High: nothing else counts
        the worst case, so the term stays."""
        assert "risk_profile.data_classification" in DOUBLE_COUNTED
        assert CLASSIFICATION_UNSET not in DOUBLE_COUNTED
        assert CRITICALITY_UNSET not in DOUBLE_COUNTED
