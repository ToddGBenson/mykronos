"""Change-governance posture (spec 30).

Aegis has nine signals and every one describes a pull request after the fact.
`self_approval` firing is a symptom; *"self-approval is permitted on the
default branch"* is the cause, and it was invisible from anywhere in this
platform. The GitHub App has been installed the whole time and the client had
no operation that read a single control.

Two tests carry the weight, and both are about refusing to say more than the
platform knows. `test_a_refusal_is_never_reported_as_absent_protection` keeps a
permissions gap from rendering as a security failure, and
`test_an_unreadable_repository_has_no_score_rather_than_a_bad_one` keeps it
from being scored as one.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from fastapi.testclient import TestClient

from mykronos import governance
from mykronos.github.client import (
    FakeGitHubClient,
    FakeRepo,
    GitHubError,
)
from mykronos.oracle.policy import GovernancePolicy
from mykronos.schemas import utcnow
from tests.conftest import REPO
from tests.test_onboarding import onboard

BRANCH = "main"


def protection(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "required_pull_request_reviews": {
            "required_approving_review_count": 2,
            "dismiss_stale_reviews": True,
            "require_code_owner_reviews": True,
        },
        "enforce_admins": {"enabled": True},
        "required_signatures": {"enabled": True},
        "required_status_checks": {"contexts": ["oracle", "sast"]},
        "allow_force_pushes": {"enabled": False},
    }
    payload.update(overrides)
    return payload


def fake(protected: dict[str, Any] | None = None, **repo_kwargs: Any) -> FakeGitHubClient:
    repo = FakeRepo(full_name=REPO, default_branch=BRANCH, **repo_kwargs)
    if protected is not None:
        repo.branch_protection[BRANCH] = protected
    return FakeGitHubClient({REPO: repo})


def control(result: governance.Governance, key: str) -> governance.Control:
    return [c for c in result.controls if c.key == key][0]


class TestReadingTheControls:
    async def test_a_well_governed_repository_reads_as_such(self) -> None:
        result = await governance.read(fake(protection()), REPO, BRANCH)

        assert result.readable
        assert control(result, "pull_request_required").state == "on"
        assert control(result, "enforced_for_admins").state == "on"

    async def test_an_unprotected_branch_is_an_answer(self) -> None:
        """GitHub returns 404 for "this branch is not protected", which is a
        finding rather than a failure."""
        result = await governance.read(fake(None), REPO, BRANCH)

        assert result.readable
        assert control(result, "pull_request_required").state == "off"

    async def test_a_refusal_is_never_reported_as_absent_protection(self) -> None:
        """The distinction the whole module is built around. "We were not
        allowed to look" and "there is nothing there" are opposite claims, and
        rendering the first as the second turns a permissions gap into a
        security failure."""
        client = fake(protection())
        client.permissions.pop("administration", None)

        result = await governance.read(client, REPO, BRANCH)

        assert result.readable is False
        assert "administration: read" in result.unreadable
        assert result.controls == []

    async def test_a_transport_failure_is_also_unreadable_not_unprotected(self) -> None:
        class Broken(FakeGitHubClient):
            async def get_branch_protection(self, repo_full_name: str, branch: str) -> Any:
                raise GitHubError("upstream had a bad day", status=502)

        result = await governance.read(Broken({REPO: FakeRepo(REPO)}), REPO, BRANCH)

        assert result.readable is False
        assert "refused" in result.unreadable

    async def test_one_required_approval_is_partial_not_on(self) -> None:
        """It is the configuration `self_approval` and `sole_approver` both
        fire under. Calling it "on" would put a repository one rubber stamp
        from a bad merge level with one that requires two people."""
        result = await governance.read(
            fake(
                protection(
                    required_pull_request_reviews={"required_approving_review_count": 1}
                )
            ),
            REPO,
            BRANCH,
        )

        assert control(result, "approving_reviews_required").state == "partial"
        assert "sole_approver" in control(result, "approving_reviews_required").detail

    async def test_every_control_names_what_it_would_have_prevented(self) -> None:
        """The link is the whole point of the panel: it turns a log of
        oddities into a diagnosis with a remedy the team can action."""
        result = await governance.read(fake(protection()), REPO, BRANCH)
        body = governance.as_dict(result)

        by_key = {c["key"]: c for c in body["controls"]}

        assert "self_approval" in by_key["approving_reviews_required"]["prevents"]
        assert "fast_approval" in by_key["dismiss_stale_reviews"]["prevents"]


class TestRulesets:
    async def test_a_repository_governed_only_by_rulesets_is_not_unprotected(
        self,
    ) -> None:
        """The newer model increasingly supersedes branch protection, and
        reading only the older one would report a modern, well-governed
        repository as wide open."""
        client = fake(
            None,
            rulesets=[
                {
                    "enforcement": "active",
                    "rules": [
                        {
                            "type": "pull_request",
                            "parameters": {
                                "required_approving_review_count": 2,
                                "require_code_owner_review": True,
                            },
                        }
                    ],
                }
            ],
        )

        result = await governance.read(client, REPO, BRANCH)

        assert control(result, "pull_request_required").state == "on"
        assert control(result, "approving_reviews_required").state == "on"
        assert result.source == "ruleset"

    async def test_the_strongest_rule_wins_across_both_models(self) -> None:
        """A repository with both is protected by the union of them, and
        taking either alone would under-report one governed twice over."""
        client = fake(
            protection(
                required_pull_request_reviews={"required_approving_review_count": 1}
            ),
            rulesets=[
                {
                    "enforcement": "active",
                    "rules": [
                        {
                            "type": "pull_request",
                            "parameters": {"required_approving_review_count": 3},
                        }
                    ],
                }
            ],
        )

        result = await governance.read(client, REPO, BRANCH)

        assert control(result, "approving_reviews_required").state == "on"
        assert result.source == "both"

    async def test_an_evaluate_mode_ruleset_earns_nothing(self) -> None:
        """A dry run reports what it would have done and blocks nothing.
        Counting it would credit a repository for a control that is off."""
        client = fake(
            None,
            rulesets=[
                {
                    "enforcement": "evaluate",
                    "rules": [
                        {
                            "type": "pull_request",
                            "parameters": {"required_approving_review_count": 2},
                        }
                    ],
                }
            ],
        )

        result = await governance.read(client, REPO, BRANCH)

        assert control(result, "pull_request_required").state == "off"
        assert result.source == "none"

    async def test_unreadable_rulesets_do_not_discard_what_was_read(self) -> None:
        """A repository with branch protection and an unreadable ruleset list
        is still mostly describable."""

        class Partial(FakeGitHubClient):
            async def get_rulesets(self, repo_full_name: str) -> Any:
                raise GitHubError("no ruleset access")

        repo = FakeRepo(full_name=REPO, default_branch=BRANCH)
        repo.branch_protection[BRANCH] = protection()

        result = await governance.read(Partial({REPO: repo}), REPO, BRANCH)

        assert result.readable
        assert control(result, "enforced_for_admins").state == "on"


class TestCodeownersCoverage:
    def test_it_measures_routed_paths(self) -> None:
        content = "*.py @team-a\n"
        paths = ["src/a.py", "src/b.py", "docs/x.md", "docs/y.md"]

        assert governance.codeowners_coverage(content, paths) == 0.5

    def test_no_file_is_unknown_not_zero(self) -> None:
        """Without one, a code-owner review requirement routes to nobody —
        which is a different fact from a file that covers nothing."""
        assert governance.codeowners_coverage(None, ["src/a.py"]) is None

    def test_nothing_to_measure_against_is_unknown(self) -> None:
        """An empty repository has not failed a coverage check."""
        assert governance.codeowners_coverage("* @team", []) is None

    def test_a_file_covering_nothing_is_zero(self) -> None:
        assert governance.codeowners_coverage("# just a comment\n", ["src/a.py"]) == 0.0

    def test_partial_coverage_reads_as_partial(self) -> None:
        result = governance._controls({}, 0.62)
        row = [c for c in result if c.key == "codeowners_coverage"][0]

        assert row.state == "partial"
        assert "62%" in row.detail


class TestTheScore:
    def test_a_fully_governed_repository_scores_a_hundred(self) -> None:
        facts = {
            "pull_request_required": True,
            "required_approvals": 2,
            "dismiss_stale_reviews": True,
            "codeowner_review_required": True,
            "enforced_for_admins": True,
            "signed_commits_required": True,
            "required_status_checks": 3,
            "force_push_blocked": True,
        }
        result = governance.Governance(
            repo_full_name=REPO, controls=governance._controls(facts, 1.0)
        )

        assert governance.score(result) == 100

    def test_an_ungoverned_repository_scores_zero(self) -> None:
        result = governance.Governance(
            repo_full_name=REPO, controls=governance._controls({}, 0.0)
        )

        assert governance.score(result) == 0

    def test_an_unreadable_repository_has_no_score_rather_than_a_bad_one(self) -> None:
        """A permissions gap is not a posture, and the same `available: False`
        rule spec 09 §9 applies to every Oracle input applies here."""
        result = governance.Governance(repo_full_name=REPO, unreadable="no permission")

        assert governance.score(result) is None

    def test_it_is_scored_over_what_was_read(self) -> None:
        """Not over what exists. An unknown control is excluded from both
        halves of the fraction rather than counted as a failure."""
        controls = [
            governance.Control(key="pull_request_required", state="on"),
            governance.Control(key="enforced_for_admins", state=governance.UNKNOWN),
        ]
        result = governance.Governance(repo_full_name=REPO, controls=controls)

        assert governance.score(result) == 100

    def test_partial_earns_half(self) -> None:
        """A single required approval is genuinely better than none and
        genuinely is not two, and a binary would have to call it one."""
        controls = [governance.Control(key="approving_reviews_required", state="partial")]
        result = governance.Governance(repo_full_name=REPO, controls=controls)

        assert governance.score(result) == 50

    def test_the_weights_come_from_the_reviewed_file(self) -> None:
        """A file, not a dict in a module: this decides what a team is told to
        aim at."""
        table = governance.weights()

        assert set(table) == set(governance.CONTROL_ORDER)
        assert table["enforced_for_admins"] > table["force_push_blocked"]


class TestPersistenceAndStaleness:
    def test_a_reading_is_stored_for_oracle(self, client: TestClient) -> None:
        """Oracle cannot make an HTTP call, so the panel's live read is copied
        past on its way."""
        result = governance.Governance(
            repo_full_name=REPO,
            controls=governance._controls({"pull_request_required": True}, 1.0),
            read_at=utcnow(),
            source="branch_protection",
        )
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            governance.remember(session, result)

            assert governance.stored(session, REPO) is not None

    def test_a_stale_reading_is_none_rather_than_old(self, client: TestClient) -> None:
        """An out-of-date reading is not a weaker version of a current one —
        it is a claim about a repository that may have been reconfigured
        twice since."""
        result = governance.Governance(
            repo_full_name=REPO,
            controls=governance._controls({"pull_request_required": True}, 1.0),
            read_at=utcnow() - timedelta(days=60),
        )
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            governance.remember(session, result)

            assert governance.stored(session, REPO) is None

    def test_nothing_read_is_none(self, client: TestClient) -> None:
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            assert governance.stored(session, "acme/never-read") is None


class TestIntoOracle:
    def _snapshot(self, reading: dict[str, Any] | None, **policy: Any) -> dict[str, Any]:
        from mykronos.config import get_settings
        from mykronos.oracle import load_policy

        loaded = load_policy(get_settings().oracle_policy_path)
        merged = GovernancePolicy(**{"points_at_zero": 8.0, **policy})
        from dataclasses import replace

        from mykronos.oracle.engine import _governance_snapshot

        snapshot, _ = _governance_snapshot(reading, replace(loaded, governance=merged))
        return snapshot

    def test_no_reading_is_unavailable_with_a_reason(self) -> None:
        snapshot = self._snapshot(None)

        assert snapshot["available"] is False
        assert "neither is a statement" in snapshot["reason"]

    def test_too_few_controls_read_is_not_a_posture(self) -> None:
        snapshot = self._snapshot(
            {"governance_score": 20, "controls_read": 2, "source": "none"}
        )

        assert snapshot["available"] is False

    def test_weak_governance_adds_points(self) -> None:
        snapshot = self._snapshot(
            {"governance_score": 0, "controls_read": 9, "source": "branch_protection"}
        )

        assert snapshot["contribution"] > 0

    def test_strong_governance_adds_nothing_and_takes_nothing(self) -> None:
        """Only ever a penalty. Branch protection is a switch, and spec 26
        §2.3 refuses credit for switch-flipping because the fastest route to a
        good score must never be a setting."""
        snapshot = self._snapshot(
            {"governance_score": 100, "controls_read": 9, "source": "branch_protection"}
        )

        assert snapshot["contribution"] == 0.0

    def test_good_enough_is_short_of_perfect(self) -> None:
        """A term that could only be silenced by a flawless configuration is
        one teams learn to ignore."""
        snapshot = self._snapshot(
            {"governance_score": 80, "controls_read": 9, "source": "branch_protection"}
        )

        assert snapshot["contribution"] == 0.0

    def test_it_ships_dark(self) -> None:
        """`points_at_zero: 0` in the shipped policy, so no repository's score
        moves until an operator has reviewed the weights and set one."""
        from mykronos.config import get_settings
        from mykronos.oracle import load_policy

        assert load_policy(get_settings().oracle_policy_path).governance.points_at_zero == 0

    def test_the_category_appears_even_when_unwired(self, client: TestClient) -> None:
        """spec 09 §9: a reader can tell "not weighed" from "weighed and found
        nothing"."""
        from mykronos.config import get_settings
        from mykronos.oracle import OracleEngine, load_policy

        engine = OracleEngine(
            client.app.state.catalog,  # type: ignore[attr-defined]
            load_policy(get_settings().oracle_policy_path),
        )

        assert "governance" in engine.evaluate(REPO).inputs_snapshot


class TestMergeCounts:
    def test_nothing_assessed_is_unavailable(self, client: TestClient) -> None:
        result = governance.merge_counts(
            client.app.state.catalog,  # type: ignore[attr-defined]
            REPO,
        )

        assert result["available"] is False

    def test_the_note_says_it_is_never_by_person(self, client: TestClient) -> None:
        """spec 06 §9 already decided that question and this agrees with it."""
        result = governance.merge_counts(
            client.app.state.catalog,  # type: ignore[attr-defined]
            REPO,
        )

        assert "reason" in result


class TestTheEndpoint:
    def _repo_id(self, client: TestClient, admin_auth: dict[str, str]) -> str:
        return client.get("/api/dashboard/portfolio", headers=admin_auth).json()["repos"][
            0
        ]["repo_id"]

    def test_it_serves_the_panel(self, client: TestClient, admin_auth) -> None:
        onboard(client, admin_auth)

        body = client.get(
            f"/api/dashboard/repos/{self._repo_id(client, admin_auth)}/governance",
            headers=admin_auth,
        ).json()

        assert len(body["controls"]) == len(governance.CONTROL_ORDER)
        assert body["note"]

    def test_a_viewer_may_read_it(
        self, client: TestClient, admin_auth, viewer_auth
    ) -> None:
        onboard(client, admin_auth)

        r = client.get(
            f"/api/dashboard/repos/{self._repo_id(client, admin_auth)}/governance",
            headers=viewer_auth,
        )

        assert r.status_code == 200

    def test_reading_it_stores_it(self, client: TestClient, admin_auth) -> None:
        onboard(client, admin_auth)
        client.get(
            f"/api/dashboard/repos/{self._repo_id(client, admin_auth)}/governance",
            headers=admin_auth,
        )

        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            assert governance.stored(session, REPO) is not None
