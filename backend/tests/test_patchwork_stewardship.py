"""Looking after draft fixes after they open — spec 08 §3, §8.

Two behaviours that decide whether a team keeps this capability switched on,
and neither is about generating a good fix.
"""

from __future__ import annotations

import pytest

from mykronos.patchwork.stewardship import (
    BRANCH_PREFIX,
    close_superseded_drafts,
    commit_is_ours,
    is_patchwork_branch,
)
from tests.conftest import REPO, issue_token
from tests.test_onboarding import deliver, onboard
from tests.test_patchwork import REQUIREMENTS, dependency_finding, put_file, seed

BOT = "mykronos-platform[bot]"


@pytest.fixture
def auth(client) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {issue_token(client, REPO, 'sast', 'patchwork')}"
    }


@pytest.fixture
def with_draft(client, admin_auth, auth, run_compaction, github):
    """A repository with one Patchwork draft open."""
    onboard(client, admin_auth)
    put_file(github, REQUIREMENTS, "urllib3==2.0.4\n")
    seed(client, auth, run_compaction, [dependency_finding()])
    client.post("/api/patchwork/run", json={}, headers=auth)
    run_compaction()
    return github.repos[REPO].pull_requests[-1]


def push(client, branch: str, *, author: str, repo: str = REPO):
    return deliver(
        client,
        "push",
        {
            "ref": f"refs/heads/{branch}",
            "repository": {"full_name": repo},
            "commits": [
                {
                    "id": "abc123",
                    "author": {"username": author, "name": author},
                    "committer": {"username": author, "name": author},
                }
            ],
        },
    )


class TestIdentity:
    def test_it_recognises_a_patchwork_branch(self) -> None:
        assert is_patchwork_branch(f"refs/heads/{BRANCH_PREFIX}abc")
        assert is_patchwork_branch(f"{BRANCH_PREFIX}abc")
        assert not is_patchwork_branch("refs/heads/feature/anything")

    def test_a_bot_commit_is_ours(self) -> None:
        commit = {"author": {"username": BOT}, "committer": {"username": BOT}}

        assert commit_is_ours(commit, {BOT})

    def test_a_human_commit_is_not(self) -> None:
        commit = {"author": {"username": "octocat"}, "committer": {"username": BOT}}

        assert not commit_is_ours(commit, {BOT})

    def test_with_no_configured_identity_nothing_is_ours(self) -> None:
        """Fails closed on purpose. A stale draft costs one unrefreshed fix;
        the opposite mistake overwrites somebody's commit."""
        commit = {"author": {"username": BOT}, "committer": {"username": BOT}}

        assert not commit_is_ours(commit, set())


class TestHumanEdits:
    def test_a_human_push_marks_the_branch(
        self, client, with_draft, run_compaction, catalog, gated_settings=None
    ) -> None:
        client.app.state.settings.github_bot_logins = [BOT]

        push(client, with_draft.head_branch, author="octocat")
        run_compaction()

        assert catalog.query("SELECT pr_status FROM remediation_events") == [
            ("human_edited",)
        ]

    def test_patchworks_own_push_does_not(
        self, client, with_draft, run_compaction, catalog
    ) -> None:
        client.app.state.settings.github_bot_logins = [BOT]

        response = push(client, with_draft.head_branch, author=BOT)
        run_compaction()

        assert response.json()["marked_human_edited"] is False
        assert catalog.query("SELECT pr_status FROM remediation_events") == [
            ("draft_open",)
        ]

    def test_a_push_to_an_unrelated_branch_is_ignored(
        self, client, with_draft, run_compaction, catalog
    ) -> None:
        """The webhook fires for every push in the repository."""
        client.app.state.settings.github_bot_logins = [BOT]

        response = push(client, "feature/someone-elses-work", author="octocat")

        assert response.json()["ignored"] == "not a Patchwork branch"

    def test_the_pipeline_stops_touching_an_edited_branch(
        self, client, with_draft, auth, run_compaction, catalog, github
    ) -> None:
        """spec 08 §3's whole point. A bot that reverted a colleague's commit
        would end this capability's welcome the same afternoon."""
        client.app.state.settings.github_bot_logins = [BOT]
        push(client, with_draft.head_branch, author="octocat")
        run_compaction()

        commits_before = len(
            [c for c in github.calls if c[0] == "commit_files"]
        )
        client.post("/api/patchwork/run", json={}, headers=auth)
        run_compaction()

        assert (
            len([c for c in github.calls if c[0] == "commit_files"])
            == commits_before
        )
        assert catalog.query("SELECT pr_status FROM remediation_events") == [
            ("human_edited",)
        ]

    def test_the_transition_is_permanent(
        self, client, with_draft, auth, run_compaction, catalog
    ) -> None:
        """No path back, deliberately (spec 08 §3)."""
        client.app.state.settings.github_bot_logins = [BOT]
        push(client, with_draft.head_branch, author="octocat")
        run_compaction()

        # Patchwork pushes again — or would, if it were allowed to.
        push(client, with_draft.head_branch, author=BOT)
        run_compaction()

        assert catalog.query("SELECT pr_status FROM remediation_events") == [
            ("human_edited",)
        ]

    def test_it_is_audit_logged(self, client, with_draft, run_compaction) -> None:
        from mykronos.db.models import AuditLogEntry

        client.app.state.settings.github_bot_logins = [BOT]
        push(client, with_draft.head_branch, author="octocat")

        with client.app.state.db.session() as session:
            actions = [row.action for row in session.query(AuditLogEntry).all()]
        assert "patchwork.human_edited" in actions

    def test_a_broken_lake_does_not_fail_the_webhook(
        self, client, with_draft, monkeypatch
    ) -> None:
        """GitHub disables a webhook that fails often enough."""
        client.app.state.settings.github_bot_logins = [BOT]
        monkeypatch.setattr(
            client.app.state.catalog,
            "query",
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("lake is on fire")),
        )

        assert push(client, with_draft.head_branch, author="octocat").status_code == 200


class TestSupersededDrafts:
    @pytest.mark.anyio
    async def test_a_fix_for_a_resolved_finding_closes_itself(
        self, client, with_draft, admin_auth, run_compaction, catalog, github
    ) -> None:
        finding_id = catalog.query("SELECT finding_id FROM findings")[0][0]
        client.patch(
            f"/api/dashboard/findings/{finding_id}/status",
            json={"status": "false_positive", "reason": "vendored"},
            headers=admin_auth,
        )

        outcome = await close_superseded_drafts(
            client.app.state.catalog, client.app.state.buffer, REPO, github
        )
        run_compaction()

        assert len(outcome.closed) == 1
        assert catalog.query(
            "SELECT pipeline_stage_reached, pr_status FROM remediation_events"
        ) == [("superseded", "closed_unmerged")]

    @pytest.mark.anyio
    async def test_a_still_open_finding_keeps_its_draft(
        self, client, with_draft, run_compaction, catalog, github
    ) -> None:
        outcome = await close_superseded_drafts(
            client.app.state.catalog, client.app.state.buffer, REPO, github
        )

        assert outcome.closed == []
        assert outcome.checked == 1

    @pytest.mark.anyio
    async def test_it_explains_itself_rather_than_vanishing(
        self, client, with_draft, admin_auth, run_compaction, github
    ) -> None:
        finding_id = client.app.state.catalog.query(
            "SELECT finding_id FROM findings"
        )[0][0]
        client.patch(
            f"/api/dashboard/findings/{finding_id}/status",
            json={"status": "false_positive", "reason": "vendored"},
            headers=admin_auth,
        )

        await close_superseded_drafts(
            client.app.state.catalog, client.app.state.buffer, REPO, github
        )

        assert ("close_pull_request", f"{REPO}#{with_draft.number}") in github.calls

    @pytest.mark.anyio
    async def test_a_human_edited_draft_is_left_alone(
        self, client, with_draft, admin_auth, run_compaction, catalog, github
    ) -> None:
        """Somebody is working on that one. They may have dismissed the
        finding precisely because they are mid-fix."""
        client.app.state.settings.github_bot_logins = [BOT]
        push(client, with_draft.head_branch, author="octocat")
        run_compaction()

        finding_id = catalog.query("SELECT finding_id FROM findings")[0][0]
        client.patch(
            f"/api/dashboard/findings/{finding_id}/status",
            json={"status": "false_positive", "reason": "handling it myself"},
            headers=admin_auth,
        )

        outcome = await close_superseded_drafts(
            client.app.state.catalog, client.app.state.buffer, REPO, github
        )

        assert outcome.closed == []
        assert outcome.checked == 0

    @pytest.mark.anyio
    async def test_a_failure_to_close_is_reported_not_swallowed(
        self, client, with_draft, admin_auth, run_compaction, catalog, github
    ) -> None:
        finding_id = catalog.query("SELECT finding_id FROM findings")[0][0]
        client.patch(
            f"/api/dashboard/findings/{finding_id}/status",
            json={"status": "false_positive", "reason": "vendored"},
            headers=admin_auth,
        )
        github.permissions["pull_requests"] = "read"

        outcome = await close_superseded_drafts(
            client.app.state.catalog, client.app.state.buffer, REPO, github
        )

        assert outcome.closed == []
        assert len(outcome.failed) == 1

    @pytest.mark.anyio
    async def test_the_sweep_survives_one_bad_repo(
        self, client, admin_auth, run_compaction
    ) -> None:
        from mykronos.github.factory import FakeGitHubClientFactory
        from mykronos.jobs import close_superseded_fixes
        from tests.test_portfolio_job import register

        register(client, "example-org/vanished", capabilities=["patchwork"])

        totals = await close_superseded_fixes(
            client.app.state.db,
            client.app.state.catalog,
            client.app.state.buffer,
            FakeGitHubClientFactory(client.app.state.github_factory.client),
        )

        assert totals["closed"] == 0
