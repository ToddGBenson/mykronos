"""Promotion, retro and trend reports — spec 11 §2, §7, §10."""

from __future__ import annotations

from datetime import timedelta

import pytest

from mykronos.knowledge.promotion import (
    find_cross_project_candidates,
    render_policy_proposal,
)
from mykronos.knowledge.reports import (
    MIN_TREND_PERIODS,
    NotEnoughHistoryError,
    build_retro,
    build_trend,
    render_retro_markdown,
)
from mykronos.knowledge.store import KnowledgeStore
from mykronos.schemas import utcnow
from tests.test_onboarding import onboard

NOW = utcnow()


@pytest.fixture
def store(tmp_path) -> KnowledgeStore:
    return KnowledgeStore(tmp_path / "knowledge", tier="personal")


def dismissal(store, *, repo, rule="CKV_AWS_123", reason="generated", when=None, times=1):
    for index in range(times):
        result = store.add_entry(
            source_type="finding_dismissal",
            subject=rule,
            source_ref=f"f-{index}",
            text=f"{rule} in {repo} was dismissed as a false positive — {reason}",
            repo_full_name=repo,
            reason=reason,
            now=when,
        )
    return result


class TestPromotionCandidates:
    def test_a_pattern_in_two_repos_is_a_candidate(self, store) -> None:
        dismissal(store, repo="org/a", times=3)
        dismissal(store, repo="org/b", times=3)

        candidates = find_cross_project_candidates(store)

        assert [c.subject for c in candidates] == ["CKV_AWS_123"]
        assert candidates[0].repos == ["org/a", "org/b"]
        assert candidates[0].to_tier == "team"

    def test_repetition_in_one_repo_is_not(self, store) -> None:
        """Ten dismissals in one repository is one team's opinion held firmly;
        three across three repositories is a rule that is probably noisy
        everywhere. Only the second generalises."""
        dismissal(store, repo="org/a", times=10)

        assert find_cross_project_candidates(store) == []

    def test_a_restricted_entry_contributes_the_fact_but_not_the_prose(
        self, store
    ) -> None:
        """"Rule X was dismissed in A and B" is an observation about a rule.
        "Because our vendor ships this pattern" is somebody's free text about
        their own codebase. Only the second is what `restricted` protects, and
        excluding the whole entry made promotion inert."""
        for repo in ("org/a", "org/b"):
            for i in range(3):
                store.add_entry(
                    source_type="finding_dismissal",
                    subject="R1",
                    source_ref=f"f-{i}",
                    text="noise",
                    repo_full_name=repo,
                    reason="our vendor ships this in every module",
                    sensitivity="restricted",
                )

        candidate = find_cross_project_candidates(store)[0]

        assert candidate.project_count == 2
        assert candidate.reasons == []
        assert candidate.reasons_withheld == 2

    def test_the_proposal_says_evidence_is_being_withheld(self, store) -> None:
        """A reviewer weighing thin evidence should know some of it is not
        shown."""
        for repo in ("org/a", "org/b"):
            # Three each: a single dismissal starts at 0.5 confidence, below
            # the 0.7 promotion bar. Reaching the bar is itself part of what
            # makes something a candidate.
            for i in range(3):
                store.add_entry(
                    source_type="finding_dismissal",
                    subject="R1",
                    source_ref=f"f-{i}",
                    text="noise",
                    repo_full_name=repo,
                    reason="internal detail",
                    sensitivity="restricted",
                )

        body = render_policy_proposal(find_cross_project_candidates(store))

        assert body is not None
        assert "internal detail" not in body
        assert "withheld" in body
        assert "No reason may be shown" in body

    def test_unreasoned_entries_are_never_promoted(self, store) -> None:
        for repo in ("org/a", "org/b"):
            dismissal(store, repo=repo, reason="", times=3)

        assert find_cross_project_candidates(store) == []

    def test_low_confidence_entries_are_excluded(self, store) -> None:
        dismissal(store, repo="org/a", times=3)
        dismissal(store, repo="org/b", times=3)
        stale = NOW + timedelta(days=3_650)

        assert find_cross_project_candidates(store, as_of=stale) == []

    def test_the_org_tier_has_nowhere_to_promote_to(self, tmp_path) -> None:
        org = KnowledgeStore(tmp_path / "k", tier="org")
        org.add_entry(
            source_type="retro_note",
            subject="R1",
            source_ref="r",
            text="x",
            repo_full_name="org/a",
            reason="y",
            sensitivity="public",
        )

        assert find_cross_project_candidates(org) == []


class TestPolicyProposal:
    def _candidates(self, store):
        for repo in ("org/a", "org/b"):
            for i in range(3):
                store.add_entry(
                    source_type="finding_dismissal",
                    subject="CKV_AWS_123",
                    source_ref=f"f-{i}",
                    text="noise",
                    repo_full_name=repo,
                    reason=f"vendored module in {repo}",
                    sensitivity="public",
                )
        return find_cross_project_candidates(store)

    def test_it_renders_the_evidence(self, store) -> None:
        body = render_policy_proposal(self._candidates(store))

        assert body is not None
        assert "CKV_AWS_123" in body
        assert "vendored module in org/a" in body

    def test_it_says_nothing_has_been_applied(self, store) -> None:
        body = render_policy_proposal(self._candidates(store))

        assert body is not None
        assert "Nothing has been applied" in body
        assert "Never auto-applied" in body

    def test_it_reminds_the_reviewer_to_bump_the_version(self, store) -> None:
        """A past decision has to stay reproducible under the policy it was
        scored with (spec 09 §10)."""
        body = render_policy_proposal(self._candidates(store))

        assert body is not None
        assert "bump `version`" in body
        assert "golden" in body

    def test_it_warns_about_repo_shaped_reasons(self, store) -> None:
        """"Our generated directory trips this" is an argument for a path
        exclusion, not for quietening the rule everywhere."""
        body = render_policy_proposal(self._candidates(store))

        assert body is not None
        assert "path exclusion" in body

    def test_nothing_to_propose_opens_nothing(self, store) -> None:
        """A weekly empty pull request is how people learn to ignore the ones
        that matter."""
        assert render_policy_proposal([]) is None


class TestRetroReport:
    def test_new_entries_are_listed(self, store) -> None:
        dismissal(store, repo="org/a")

        report = build_retro(store)

        assert len(report.new_entries) == 1
        assert report.is_quiet is False

    def test_reconfirmations_are_separate_from_new(self, store) -> None:
        old = NOW - timedelta(days=60)
        dismissal(store, repo="org/a", when=old)
        dismissal(store, repo="org/a")

        report = build_retro(store)

        assert report.new_entries == []
        assert len(report.reconfirmed) == 1

    def test_fading_entries_are_surfaced(self, store) -> None:
        """Either the problem went away or people gave up on the tool. Those
        look identical in the data and completely different in a retro."""
        dismissal(store, repo="org/a", when=NOW - timedelta(days=900))

        report = build_retro(store)

        assert len(report.decaying) == 1

    def test_unreasoned_entries_are_counted(self, store) -> None:
        dismissal(store, repo="org/a", reason="")

        assert build_retro(store).unreasoned == 1

    def test_a_quiet_period_says_so_thoughtfully(self, store) -> None:
        markdown = render_retro_markdown(build_retro(store))

        assert "Nothing was learned this period" in markdown
        assert "nobody had time to argue with them" in markdown

    def test_the_markdown_reports_what_happened(self, store) -> None:
        dismissal(store, repo="org/a", reason="vendored terraform module")

        markdown = render_retro_markdown(build_retro(store))

        assert "New learnings (1)" in markdown
        assert "vendored terraform module" in markdown
        assert "reproducible" in markdown

    def test_it_is_reproducible(self, store) -> None:
        dismissal(store, repo="org/a")
        stamp = NOW + timedelta(days=3)

        first = render_retro_markdown(build_retro(store, as_of=stamp))
        second = render_retro_markdown(build_retro(store, as_of=stamp))

        assert first == second


class TestTrendReport:
    def _long_history(self, store):
        for week in range(12, 0, -1):
            dismissal(
                store,
                repo="org/a",
                rule=f"R{week}",
                when=NOW - timedelta(days=week * 14),
            )

    def test_too_few_periods_is_refused(self, store) -> None:
        """spec 11 §10: a clear error rather than a misleading report."""
        self._long_history(store)

        with pytest.raises(NotEnoughHistoryError, match="at least"):
            build_trend(store, periods=2)

    def test_too_little_history_is_refused(self, store) -> None:
        dismissal(store, repo="org/a")

        with pytest.raises(NotEnoughHistoryError, match="days of history"):
            build_trend(store)

    def test_an_empty_store_is_refused(self, store) -> None:
        with pytest.raises(NotEnoughHistoryError, match="empty"):
            build_trend(store)

    def test_the_error_explains_rather_than_just_refusing(self, store) -> None:
        with pytest.raises(NotEnoughHistoryError) as excinfo:
            build_trend(store, periods=2)

        assert "noise with a line drawn through it" in str(excinfo.value)

    def test_a_long_enough_history_produces_points(self, store) -> None:
        self._long_history(store)

        report = build_trend(store, periods=MIN_TREND_PERIODS)

        assert len(report.points) == MIN_TREND_PERIODS
        assert report.points[0]["period_start"] < report.points[-1]["period_start"]

    def test_the_direction_is_a_word_not_a_slope(self, store) -> None:
        """A slope on four points invites more precision than four points can
        carry."""
        self._long_history(store)

        assert build_trend(store).direction in {"rising", "falling", "flat"}


class TestApi:
    @pytest.fixture
    def seeded(self, client, admin_auth):
        onboard(client, admin_auth)
        for repo in ("org/a", "org/b"):
            for i in range(3):
                client.app.state.knowledge.add_entry(
                    source_type="finding_dismissal",
                    subject="CKV_AWS_123",
                    source_ref=f"f-{i}",
                    text=f"CKV_AWS_123 in {repo} is noise",
                    repo_full_name=repo,
                    reason="vendored module",
                    sensitivity="public",
                )

    def test_entries_are_listed_with_current_confidence(
        self, client, admin_auth, seeded
    ) -> None:
        body = client.get("/api/knowledge/entries", headers=admin_auth).json()

        assert body["total"] == 2
        assert body["active"] == 2
        assert all("confidence" in e for e in body["entries"])

    def test_a_viewer_may_read(self, client, viewer_auth, seeded) -> None:
        assert client.get("/api/knowledge/entries", headers=viewer_auth).status_code == 200

    def test_a_viewer_may_not_write_a_note(self, client, viewer_auth) -> None:
        """This corpus eventually influences how every repository is scored."""
        response = client.post(
            "/api/knowledge/notes",
            json={"subject": "x", "text": "y"},
            headers=viewer_auth,
        )

        assert response.status_code == 403

    def test_an_admin_can_write_a_note(self, client, admin_auth) -> None:
        response = client.post(
            "/api/knowledge/notes",
            json={
                "subject": "checkov-terraform",
                "text": "Checkov's terraform module rules assume a flat layout.",
            },
            headers=admin_auth,
        )

        assert response.status_code == 201
        assert response.json()["source_type"] == "retro_note"
        assert response.json()["has_reason"] is True

    def test_a_note_is_audit_logged(self, client, admin_auth) -> None:
        from mykronos.db.models import AuditLogEntry

        client.post(
            "/api/knowledge/notes",
            json={"subject": "s", "text": "t"},
            headers=admin_auth,
        )

        with client.app.state.db.session() as session:
            actions = [row.action for row in session.query(AuditLogEntry).all()]
        assert "knowledge.note" in actions

    def test_the_retro_report_renders(self, client, admin_auth, seeded) -> None:
        body = client.get("/api/knowledge/retro", headers=admin_auth).json()

        assert body["quiet"] is False
        assert len(body["new_entries"]) == 2
        assert body["promotion_candidates"]

    def test_the_retro_report_renders_as_markdown(
        self, client, admin_auth, seeded
    ) -> None:
        response = client.get(
            "/api/knowledge/retro?fmt=markdown", headers=admin_auth
        )

        assert response.status_code == 200
        assert "# Security retro" in response.text

    def test_the_trend_report_refuses_thin_data(self, client, admin_auth, seeded) -> None:
        response = client.get("/api/knowledge/trend", headers=admin_auth)

        assert response.status_code == 422
        assert "days of history" in response.json()["detail"]

    def test_promotion_candidates_carry_the_proposal(
        self, client, admin_auth, seeded
    ) -> None:
        body = client.get(
            "/api/knowledge/promotion-candidates", headers=admin_auth
        ).json()

        assert body["candidates"][0]["project_count"] == 2
        assert "CKV_AWS_123" in body["policy_proposal"]
        assert "Nothing here has been applied" in body["note"]

    def test_min_projects_cannot_be_lowered_to_one(self, client, admin_auth) -> None:
        """Allowing 1 would turn this into a list of every entry."""
        response = client.get(
            "/api/knowledge/promotion-candidates?min_projects=1", headers=admin_auth
        )

        assert response.status_code == 422

    def test_it_needs_authentication(self, client) -> None:
        assert client.get("/api/knowledge/entries").status_code == 401


class TestPurgeJob:
    def test_learnings_for_offboarded_repos_are_dropped(
        self, client, admin_auth
    ) -> None:
        from mykronos.jobs import purge_orphaned_learnings
        from tests.conftest import REPO

        onboard(client, admin_auth)
        store = client.app.state.knowledge
        store.add_entry(
            source_type="finding_dismissal",
            subject="R1",
            source_ref="f",
            text="noise",
            repo_full_name=REPO,
            reason="x",
        )
        store.add_entry(
            source_type="finding_dismissal",
            subject="R1",
            source_ref="f",
            text="noise",
            repo_full_name="org/long-gone",
            reason="x",
        )

        result = purge_orphaned_learnings(client.app.state.db, store)

        assert result.count == 1
        assert [e.repo_full_name for e in store.list_entries()] == [REPO]

    def test_a_suspended_repo_keeps_its_learnings(self, client, admin_auth) -> None:
        """It is expected back, and forgetting what its team concluded while
        it was paused would be a real loss."""
        from mykronos.db.models import RepoOnboarding
        from mykronos.jobs import purge_orphaned_learnings
        from tests.conftest import REPO

        repo_id = onboard(client, admin_auth).json()["id"]
        with client.app.state.db.session() as session:
            session.get(RepoOnboarding, repo_id).status = "suspended"

        store = client.app.state.knowledge
        store.add_entry(
            source_type="finding_dismissal",
            subject="R1",
            source_ref="f",
            text="noise",
            repo_full_name=REPO,
            reason="x",
        )

        assert purge_orphaned_learnings(client.app.state.db, store).count == 0
