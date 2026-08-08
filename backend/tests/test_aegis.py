"""Aegis — insider-risk scoring and ingestion (spec 06).

The governance rules in spec 06 §9 are normative, so they are tested like
behaviour rather than trusted as prose: the author is recorded, the rationale
is mandatory, "not evaluated" never collapses into "evaluated, human", and no
pair of signals can reach a block on its own.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from mykronos.aegis import SIGNAL_CAP, assess, signal_id
from mykronos.db.models import CapabilityConfig
from mykronos.schemas import InsiderRiskSubmission, SubSignal
from tests.conftest import REPO, issue_token
from tests.test_onboarding import onboard


@pytest.fixture
def aegis_auth(client: TestClient) -> dict[str, str]:
    return {"Authorization": f"Bearer {issue_token(client, REPO, 'aegis')}"}


def submission(**overrides) -> dict:
    payload = {
        "pr_number": 2841,
        "commit_sha": "a91f2c7",
        "author_login": "octocat",
        "signals": [],
    }
    payload.update(overrides)
    return payload


def signal(key: str, score: float, rationale: str = "because") -> dict:
    return {"key": key, "score": score, "rationale": rationale}


def post(client, auth, **overrides):
    return client.post("/api/ingest/aegis", json=submission(**overrides), headers=auth)


def configure(client, repo_id: str, **config) -> None:
    with client.app.state.db.session() as session:
        session.add(
            CapabilityConfig(
                repo_onboarding_id=repo_id, capability="aegis", config_json=config
            )
        )


class TestScoring:
    def test_signals_sum_into_a_recommendation(self) -> None:
        result = assess(
            InsiderRiskSubmission(
                pr_number=1,
                commit_sha="abc",
                author_login="octocat",
                signals=[
                    SubSignal(key="sensitive_path", score=30, rationale="touches auth/"),
                    SubSignal(key="access_anomaly", score=25, rationale="first commit"),
                ],
            ),
            REPO,
        )

        assert result.insider_risk_score == 55
        assert result.recommendation == "review_recommended"

    def test_no_two_signals_can_reach_the_default_block_threshold(self) -> None:
        """A heuristic that fires wrongly should cost a review, never a block.
        Blocking always needs at least three independent signals agreeing."""
        caps = sorted(SIGNAL_CAP.values(), reverse=True)

        assert caps[0] + caps[1] < 80

    def test_a_signal_is_capped_at_its_ceiling(self) -> None:
        result = assess(
            InsiderRiskSubmission(
                pr_number=1,
                commit_sha="abc",
                author_login="octocat",
                signals=[SubSignal(key="sensitive_path", score=100, rationale="x")],
            ),
            REPO,
        )

        assert result.insider_risk_score == 30
        assert result.breakdown["signals"][0]["capped_at"] == 30.0

    def test_an_unknown_signal_is_rejected_not_scored(self) -> None:
        """A repo running a forked scorer cannot invent a contribution nobody
        can interpret."""
        result = assess(
            InsiderRiskSubmission(
                pr_number=1,
                commit_sha="abc",
                author_login="octocat",
                signals=[SubSignal(key="vibes", score=90, rationale="hunch")],
            ),
            REPO,
        )

        assert result.insider_risk_score == 0
        assert result.breakdown["signals_rejected"] == ["vibes"]

    def test_signals_that_did_not_run_are_named(self) -> None:
        """"Scored zero" and "never ran" are different facts, exactly as in
        Oracle's inputs_snapshot."""
        result = assess(
            InsiderRiskSubmission(
                pr_number=1,
                commit_sha="abc",
                author_login="octocat",
                signals=[SubSignal(key="sensitive_path", score=5, rationale="x")],
            ),
            REPO,
        )

        assert "access_anomaly" in result.breakdown["signals_not_reported"]
        assert "sensitive_path" not in result.breakdown["signals_not_reported"]

    def test_the_id_is_derived_so_a_re_run_upserts(self) -> None:
        assert signal_id(REPO, 1, "abc") == signal_id(REPO, 1, "abc")
        assert signal_id(REPO, 1, "abc") != signal_id(REPO, 1, "def")
        assert signal_id(REPO, 1, "abc") != signal_id(REPO, 2, "abc")

    def test_a_clean_pr_passes(self) -> None:
        result = assess(
            InsiderRiskSubmission(
                pr_number=1, commit_sha="abc", author_login="octocat", signals=[]
            ),
            REPO,
        )

        assert result.recommendation == "pass"
        assert result.insider_risk_score == 0


class TestAiAuthorshipHasThreeStates:
    """spec 06 §3, §7. Collapsing null into false would report "we checked, it
    is human" when nothing checked."""

    def _assess(self, flag, configured: bool):
        return assess(
            InsiderRiskSubmission(
                pr_number=1,
                commit_sha="abc",
                author_login="octocat",
                ai_authorship_flag=flag,
            ),
            REPO,
            ai_classifier_configured=configured,
        )

    def test_unevaluated_because_nothing_is_configured(self) -> None:
        result = self._assess(None, configured=False)

        assert result.ai_authorship_flag is None
        assert result.breakdown["ai_authorship"]["evaluated"] is False
        assert "No AI-authorship classifier is configured" in (
            result.breakdown["ai_authorship"]["reason"]
        )

    def test_unevaluated_because_the_classifier_failed(self) -> None:
        """A different fact from the above, and the breakdown says which."""
        result = self._assess(None, configured=True)

        assert result.ai_authorship_flag is None
        assert "did not return a result" in result.breakdown["ai_authorship"]["reason"]

    def test_evaluated_and_human(self) -> None:
        result = self._assess(False, configured=True)

        assert result.ai_authorship_flag is False
        assert result.breakdown["ai_authorship"]["evaluated"] is True
        assert result.breakdown["ai_authorship"]["likely_ai_and_undisclosed"] is False

    def test_evaluated_and_undisclosed_ai(self) -> None:
        result = self._assess(True, configured=True)

        assert result.breakdown["ai_authorship"]["likely_ai_and_undisclosed"] is True


class TestIngestion:
    def test_a_signal_row_is_written(
        self, client, admin_auth, aegis_auth, run_compaction, catalog
    ) -> None:
        onboard(client, admin_auth)
        response = post(
            client, aegis_auth, signals=[signal("sensitive_path", 30, "touches auth/")]
        )
        run_compaction()

        assert response.status_code == 200, response.text
        rows = catalog.query(
            "SELECT author_login, insider_risk_score, recommendation, pr_number "
            "FROM insider_risk_signals"
        )
        assert rows == [("octocat", 30, "pass", 2841)]

    def test_the_author_is_required(self, client, admin_auth, aegis_auth) -> None:
        """A score you cannot attribute is one nobody can challenge and nobody
        can delete on request (spec 06 §9)."""
        onboard(client, admin_auth)
        payload = submission()
        del payload["author_login"]

        response = client.post("/api/ingest/aegis", json=payload, headers=aegis_auth)

        assert response.status_code == 422

    def test_a_rationale_is_required_for_every_signal(
        self, client, admin_auth, aegis_auth
    ) -> None:
        onboard(client, admin_auth)
        response = client.post(
            "/api/ingest/aegis",
            json=submission(signals=[{"key": "sensitive_path", "score": 30}]),
            headers=aegis_auth,
        )

        assert response.status_code == 422

    def test_re_evaluating_the_same_commit_upserts(
        self, client, admin_auth, aegis_auth, run_compaction, catalog
    ) -> None:
        """The workflow triggers on `synchronize`, so a re-run is ordinary. A
        second row would build the per-author history spec 06 §9 forbids."""
        onboard(client, admin_auth)
        post(client, aegis_auth, signals=[signal("sensitive_path", 10)])
        run_compaction()
        post(client, aegis_auth, signals=[signal("sensitive_path", 30)])
        run_compaction()

        assert catalog.count("insider_risk_signals") == 1
        assert catalog.query("SELECT insider_risk_score FROM insider_risk_signals") == [
            (30,)
        ]

    def test_a_new_head_commit_is_a_new_row(
        self, client, admin_auth, aegis_auth, run_compaction, catalog
    ) -> None:
        """Each score is about the code as it then stood."""
        onboard(client, admin_auth)
        post(client, aegis_auth, commit_sha="aaa")
        post(client, aegis_auth, commit_sha="bbb")
        run_compaction()

        assert catalog.count("insider_risk_signals") == 2

    def test_the_repo_comes_from_the_token(self, client, admin_auth, aegis_auth) -> None:
        onboard(client, admin_auth)
        payload = submission()
        payload["repo_full_name"] = "someone/else"

        response = client.post("/api/ingest/aegis", json=payload, headers=aegis_auth)

        assert response.status_code == 422

    def test_the_aegis_grant_is_required(self, client, admin_auth) -> None:
        onboard(client, admin_auth)
        sast_only = {
            "Authorization": f"Bearer {issue_token(client, 'example-org/other', 'sast')}"
        }

        assert post(client, sast_only).status_code == 403

    def test_the_breakdown_is_persisted_with_rationales(
        self, client, admin_auth, aegis_auth, run_compaction, catalog
    ) -> None:
        onboard(client, admin_auth)
        post(
            client,
            aegis_auth,
            signals=[signal("sensitive_path", 30, "modifies .github/workflows/ci.yml")],
        )
        run_compaction()

        (raw,) = catalog.query("SELECT signal_breakdown FROM insider_risk_signals")[0]
        breakdown = json.loads(raw)
        assert breakdown["signals"][0]["rationale"] == (
            "modifies .github/workflows/ci.yml"
        )


class TestCheckRun:
    def test_a_check_run_is_posted(
        self, client, admin_auth, aegis_auth, github
    ) -> None:
        onboard(client, admin_auth)
        body = post(client, aegis_auth, signals=[signal("sensitive_path", 30)]).json()

        assert body["check_run_id"]
        run = github.repos[REPO].check_runs[-1]
        assert run["head_sha"] == "a91f2c7"
        assert "30/100" in run["title"]

    def test_advisory_by_default_means_neutral_not_failure(
        self, client, admin_auth, aegis_auth, github
    ) -> None:
        onboard(client, admin_auth)
        body = post(
            client,
            aegis_auth,
            signals=[
                signal("sensitive_path", 30),
                signal("access_anomaly", 25),
                signal("author_baseline", 25),
            ],
        ).json()

        assert body["recommendation"] == "block_recommended"
        assert body["blocking"] is False
        assert github.repos[REPO].check_runs[-1]["conclusion"] == "neutral"

    def test_blocking_turns_a_block_recommendation_into_a_failure(
        self, client, admin_auth, aegis_auth, github
    ) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]
        configure(client, repo_id, blocking=True)

        post(
            client,
            aegis_auth,
            signals=[
                signal("sensitive_path", 30),
                signal("access_anomaly", 25),
                signal("author_baseline", 25),
            ],
        )

        assert github.repos[REPO].check_runs[-1]["conclusion"] == "failure"

    def test_a_clean_pr_gets_a_passing_check(
        self, client, admin_auth, aegis_auth, github
    ) -> None:
        onboard(client, admin_auth)
        post(client, aegis_auth)

        assert github.repos[REPO].check_runs[-1]["conclusion"] == "success"

    def test_a_failed_check_run_does_not_lose_the_row(
        self, client, admin_auth, aegis_auth, github, run_compaction, catalog
    ) -> None:
        onboard(client, admin_auth)
        github.permissions.pop("checks")

        body = post(client, aegis_auth).json()
        run_compaction()

        assert body["check_run_id"] is None
        assert body["check_run_error"]
        assert catalog.count("insider_risk_signals") == 1

    def test_the_summary_is_about_the_change_not_the_person(
        self, client, admin_auth, aegis_auth, github
    ) -> None:
        """Same facts either way; the framing is the difference between a
        review prompt and an accusation (spec 06 §9)."""
        onboard(client, admin_auth)
        post(
            client,
            aegis_auth,
            signals=[signal("sensitive_path", 30, "modifies auth/session.py")],
        )

        summary = github.repos[REPO].check_runs[-1]["summary"]
        assert "not a judgement about the person" in summary
        assert "cannot block, merge or close" in summary
        assert "modifies auth/session.py" in summary
        # The author's login is deliberately absent from the public Check Run:
        # everyone can already see who opened the PR, and repeating it next to
        # a risk score is what turns a review prompt into a label.
        assert "octocat" not in summary

    def test_the_threshold_config_is_respected(
        self, client, admin_auth, aegis_auth
    ) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]
        configure(client, repo_id, block_threshold=25)

        body = post(client, aegis_auth, signals=[signal("sensitive_path", 30)]).json()

        assert body["recommendation"] == "block_recommended"
