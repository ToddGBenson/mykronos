"""Maturity tiers and trend series — spec 10 §2.3, §6.

The tests that matter most here are the ones about *incentives*. A maturity
model is a statement about what a team should aim at, and the failure mode is
not a wrong number — it is a number that is right and pushes people the wrong
way.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from mykronos.maturity import (
    MaturityModelError,
    assess,
    load_model,
    mean_time_to_fix,
    parse_model,
    trend_series,
)
from mykronos.schemas import utcnow
from tests.conftest import REPO, finding_payload, issue_token, post_findings, post_scan
from tests.test_onboarding import onboard

MODEL_PATH = Path(__file__).resolve().parents[2] / "maturity-model-v1.yaml"


@pytest.fixture
def model():
    return load_model(MODEL_PATH)


@pytest.fixture
def auth(client) -> dict[str, str]:
    return {"Authorization": f"Bearer {issue_token(client, REPO, 'sast', 'secrets')}"}


class TestTheModelItself:
    def test_the_shipped_model_loads(self, model) -> None:
        assert model.version == "1.0"
        assert [t.id for t in model.tiers][0] == "unmanaged"

    def test_no_criterion_can_reward_a_switch_position(self, model) -> None:
        """The design rule, asserted rather than trusted to the comments.

        Spec 09 §6 makes Oracle blocking opt-in and conditional on shadow-mode
        evidence. A tier that rewarded flipping it would push teams to turn on
        a gate nobody agreed to, which is how the platform gets switched off.
        """
        forbidden = ("blocking", "enabled", "capability_count", "config")

        for criterion in model.criteria.values():
            metric = criterion.metric.lower()
            assert not any(word in metric for word in forbidden), (
                f"{criterion.key} measures {criterion.metric}, which looks "
                "like configuration rather than evidence."
            )

    def test_every_criterion_can_fail(self) -> None:
        """A criterion with no threshold always passes and inflates every tier
        silently."""
        with pytest.raises(MaturityModelError, match="can never fail"):
            parse_model(
                {
                    "version": "x",
                    "criteria": {"c": {"metric": "aged_criticals"}},
                    "tiers": [{"id": "t", "requires": ["c"]}],
                }
            )

    def test_a_tier_cannot_require_an_unknown_criterion(self) -> None:
        with pytest.raises(MaturityModelError, match="unknown criteria"):
            parse_model(
                {"version": "x", "criteria": {}, "tiers": [{"id": "t", "requires": ["nope"]}]}
            )

    def test_a_missing_model_is_refused_not_defaulted(self) -> None:
        """A silently-empty model would put every repo at the top tier."""
        with pytest.raises(MaturityModelError, match="No maturity model"):
            load_model(Path("does-not-exist.yaml"))


class TestAssessment:
    def test_a_bare_repo_is_unmanaged(self, client, admin_auth, catalog, model) -> None:
        onboard(client, admin_auth)

        result = assess(catalog, REPO, model)

        assert result.tier_id == "unmanaged"
        assert result.next_tier_name == "Observed"

    def test_it_names_what_is_blocking_the_next_tier(
        self, client, admin_auth, catalog, model
    ) -> None:
        """A tier with no route out of it is a scold, not a roadmap."""
        onboard(client, admin_auth)

        result = assess(catalog, REPO, model)

        assert result.blocking
        assert all(not c.passed for c in result.blocking)

    def test_only_the_next_tier_blocks(self, client, admin_auth, catalog, model) -> None:
        """Listing every unmet criterion in the model would bury the one thing
        to do next."""
        onboard(client, admin_auth)

        result = assess(catalog, REPO, model)

        assert len(result.blocking) < len(result.criteria)

    def test_scanning_two_capabilities_reaches_observed(
        self, client, admin_auth, auth, catalog, run_compaction, model
    ) -> None:
        onboard(client, admin_auth)
        post_scan(client, auth, scan_run_id="s1", capability="sast")
        post_scan(client, auth, scan_run_id="s2", capability="secrets")
        post_findings(client, auth, [finding_payload()], scan_run_id="s1")
        run_compaction()

        assert assess(catalog, REPO, model).tier_id == "observed"

    def test_a_stale_scan_drops_the_tier(
        self, client, admin_auth, auth, catalog, run_compaction, model
    ) -> None:
        """A stale scan is worse than none: it reports a clean repository
        nobody has looked at recently."""
        onboard(client, admin_auth)
        post_scan(client, auth, scan_run_id="s1", capability="sast")
        post_scan(client, auth, scan_run_id="s2", capability="secrets")
        run_compaction()

        fresh = assess(catalog, REPO, model)
        stale = assess(catalog, REPO, model, as_of=utcnow() + timedelta(days=40))

        assert fresh.tier_id == "observed"
        assert stale.tier_id == "unmanaged"

    def test_tiers_cannot_be_skipped(
        self, client, admin_auth, auth, catalog, run_compaction, model
    ) -> None:
        """A repo with a sophisticated learning loop and no scanners running
        has not leapfrogged anything — it has a gap worth looking at."""
        onboard(client, admin_auth)
        # Supply-chain evidence and a decision, but nothing has scanned.
        client.app.state.buffer.append(
            "sscs_evidence",
            [
                {
                    "evidence_id": "e1",
                    "repo_full_name": REPO,
                    "commit_sha": "abc",
                    "tag_or_release": None,
                    "sbom_ref": None,
                    "dependency_count": 5,
                    "vulnerable_dependency_count": 0,
                    "trust_score": 100,
                    "raw_trust_score": 100.0,
                    "provenance_json": "{}",
                    "ecosystems_json": "{}",
                    "evaluated_at": utcnow(),
                }
            ],
        )
        run_compaction()

        result = assess(catalog, REPO, model)

        assert result.tier_id == "unmanaged"
        # The evidence still shows as passing — the tier is gated on the gap,
        # not on pretending the evidence is absent.
        assert any(c.key == "supply_chain_evidence" and c.passed for c in result.criteria)

    def test_no_data_fails_rather_than_passes(
        self, client, admin_auth, catalog, model
    ) -> None:
        """A model that awarded tiers for absent data would reward having
        none."""
        onboard(client, admin_auth)

        result = assess(catalog, REPO, model)

        unmeasured = [c for c in result.criteria if c.value is None]
        assert unmeasured
        assert all(not c.passed for c in unmeasured)

    def test_every_criterion_carries_its_working(
        self, client, admin_auth, catalog, model
    ) -> None:
        """spec 10 §6: no dashboard-only number that cannot be traced back."""
        onboard(client, admin_auth)

        for criterion in assess(catalog, REPO, model).criteria:
            assert criterion.label
            assert criterion.threshold
            assert criterion.measured
            assert criterion.why, f"{criterion.key} does not say why it matters"


class TestTrends:
    def test_a_finding_is_open_only_within_its_lifespan(
        self, client, admin_auth, auth, catalog, run_compaction
    ) -> None:
        """The whole series is reconstructed from first_seen_at and
        resolved_at, so this is the property everything else rests on."""
        onboard(client, admin_auth)
        post_findings(client, auth, [finding_payload()])
        run_compaction()

        before = trend_series(catalog, REPO, days=30, points=3, as_of=utcnow())
        assert before[-1].open_total == 1

        # Reconstructed as of a week before it existed.
        earlier = trend_series(
            catalog, REPO, days=30, points=3, as_of=utcnow() - timedelta(days=7)
        )
        assert earlier[-1].open_total == 0

    def test_a_resolved_finding_leaves_the_series(
        self, client, admin_auth, auth, catalog, run_compaction, admin_auth2=None
    ) -> None:
        onboard(client, admin_auth)
        post_findings(client, auth, [finding_payload()])
        run_compaction()

        finding_id = catalog.query("SELECT finding_id FROM findings")[0][0]
        client.patch(
            f"/api/dashboard/findings/{finding_id}/status",
            json={"status": "false_positive", "reason": "vendored"},
            headers=admin_auth,
        )

        assert trend_series(catalog, REPO, days=30, points=2)[-1].open_total == 0

    def test_the_portfolio_series_spans_repos(
        self, client, admin_auth, auth, catalog, run_compaction
    ) -> None:
        onboard(client, admin_auth)
        post_findings(client, auth, [finding_payload()])
        run_compaction()

        assert trend_series(catalog, None, days=30, points=2)[-1].open_total == 1

    def test_it_asks_for_the_score_as_of_that_instant(
        self, client, admin_auth, catalog, run_compaction
    ) -> None:
        """Using the latest decision for every point would draw a flat line at
        today's value and call it a trend."""
        onboard(client, admin_auth)
        client.app.state.buffer.append(
            "risk_decisions",
            [
                {
                    "decision_id": "d1",
                    "repo_full_name": REPO,
                    "decision_type": "portfolio",
                    "pr_number": None,
                    "release_tag": None,
                    "commit_sha": "",
                    "overall_risk_score": 70,
                    "recommendation": "no_go",
                    "inputs_snapshot": "{}",
                    "reasoning": "",
                    "policy_version": "1.0",
                    "evaluated_at": utcnow() - timedelta(days=1),
                    "human_override": None,
                    "github_check_run_id": None,
                    "gate_outcome": None,
                }
            ],
        )
        run_compaction()

        series = trend_series(catalog, REPO, days=30, points=4)

        assert series[0].risk_score is None, "before the decision existed"
        assert series[-1].risk_score == 70

    def test_an_empty_lake_produces_a_flat_series_not_an_error(
        self, client, admin_auth, catalog
    ) -> None:
        series = trend_series(catalog, REPO, days=30, points=4)

        assert len(series) == 4
        assert all(point.open_total == 0 for point in series)


class TestMeanTimeToFix:
    def test_dismissals_do_not_count_as_fixes(
        self, client, admin_auth, auth, catalog, run_compaction
    ) -> None:
        """Otherwise the fastest way to improve this number is a click."""
        onboard(client, admin_auth)
        post_findings(client, auth, [finding_payload()])
        run_compaction()
        finding_id = catalog.query("SELECT finding_id FROM findings")[0][0]
        client.patch(
            f"/api/dashboard/findings/{finding_id}/status",
            json={"status": "false_positive", "reason": "vendored"},
            headers=admin_auth,
        )

        assert mean_time_to_fix(catalog, REPO) is None

    def test_nothing_fixed_yet_is_none_not_zero(
        self, client, admin_auth, catalog
    ) -> None:
        assert mean_time_to_fix(catalog, REPO) is None


class TestApi:
    def test_trends_are_served(self, client, admin_auth) -> None:
        body = client.get("/api/dashboard/trends", headers=admin_auth).json()

        assert body["scope"] == "portfolio"
        assert len(body["points"]) == 12
        # The claim, not the wording: every point is computed from the findings
        # rather than read from a stored snapshot, so the series cannot drift
        # away from the data it describes.
        assert "not a stored snapshot" in body["note"]
        # And it says so without citing a specification section at the reader,
        # who has no way to open one.
        assert "spec " not in body["note"]

    def test_maturity_is_served(self, client, admin_auth) -> None:
        onboard(client, admin_auth)

        body = client.get("/api/dashboard/maturity", headers=admin_auth).json()

        assert body["model_version"] == "1.0"
        assert body["repos"] == [] or body["repos"][0]["tier_id"] == "unmanaged"

    def test_maturity_shows_its_working(self, client, admin_auth, catalog) -> None:
        from tests.test_portfolio_job import register

        register(client, REPO, capabilities=["sast"])

        repo = client.get("/api/dashboard/maturity", headers=admin_auth).json()["repos"][0]

        assert repo["criteria"]
        assert all("threshold" in c and "measured" in c for c in repo["criteria"])
        assert repo["blocking"]

    def test_a_viewer_may_read_both(self, client, viewer_auth) -> None:
        assert client.get("/api/dashboard/trends", headers=viewer_auth).status_code == 200
        assert client.get("/api/dashboard/maturity", headers=viewer_auth).status_code == 200

    def test_they_need_authentication(self, client) -> None:
        assert client.get("/api/dashboard/trends").status_code == 401
        assert client.get("/api/dashboard/maturity").status_code == 401
