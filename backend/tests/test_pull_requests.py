"""The unified pull-request view (spec 10 §2).

The interesting behaviour is not the listing. It is what the page does when
the platform's record and GitHub disagree, which is the normal case rather
than the exceptional one: the record is only as fresh as the last webhook
that was actually delivered.
"""

from __future__ import annotations

import pytest

from mykronos.github.client import GitHubError, PullRequest
from mykronos.pull_requests import open_pull_requests
from tests.conftest import REPO, issue_token
from tests.test_onboarding import onboard
from tests.test_patchwork import REQUIREMENTS, dependency_finding, put_file, seed


@pytest.fixture
def auth(client) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {issue_token(client, REPO, 'sast', 'patchwork')}"
    }


def install_pr(client, admin_auth, *capabilities: str) -> str:
    """Onboard and request a capability, which is what opens an install PR.

    `onboard()` alone registers the repo and touches nothing on GitHub, so a
    test that used it and expected a pull request would be asserting against
    a repo where the platform had deliberately done nothing.
    """
    repo_id = onboard(client, admin_auth).json()["id"]
    response = client.patch(
        f"/api/repos/{repo_id}/capabilities",
        json={"capabilities": list(capabilities or ("secrets",))},
        headers=admin_auth,
    )
    assert response.status_code == 200, response.text
    assert response.json()["pull_request_number"], "expected an install PR"
    return repo_id


async def listing(client):
    with client.app.state.db.session() as session:
        return await open_pull_requests(
            session, client.app.state.catalog, client.app.state.github_factory
        )


class TestInstallPullRequests:
    @pytest.mark.anyio
    async def test_an_open_install_pr_is_listed(self, client, admin_auth) -> None:
        install_pr(client, admin_auth)

        result = await listing(client)

        assert [(r.repo_full_name, r.kind) for r in result.pull_requests] == [
            (REPO, "install")
        ]
        assert result.pull_requests[0].capabilities

    @pytest.mark.anyio
    async def test_a_repo_with_nothing_pending_contributes_nothing(
        self, client, admin_auth
    ) -> None:
        result = await listing(client)

        assert result.pull_requests == []

    @pytest.mark.anyio
    async def test_a_pr_merged_behind_our_back_drops_off(
        self, client, admin_auth, github
    ) -> None:
        """The case that makes live confirmation worth its API calls.

        `pending_pr_number` still points at it and no webhook ever arrived, so
        the record says outstanding. Listing it would mean the page shows work
        that does not exist, which is how people stop reading a work list.
        """
        install_pr(client, admin_auth)
        pull_request = github.repos[REPO].pull_requests[-1]
        pull_request.state = "closed"
        pull_request.merged = True

        result = await listing(client)

        assert result.pull_requests == []

    @pytest.mark.anyio
    async def test_a_pr_deleted_on_github_drops_off(
        self, client, admin_auth, github
    ) -> None:
        install_pr(client, admin_auth)
        github.repos[REPO].pull_requests.clear()

        result = await listing(client)

        assert result.pull_requests == []


class TestFixPullRequests:
    @pytest.mark.anyio
    async def test_a_patchwork_draft_is_listed_as_a_fix(
        self, client, admin_auth, auth, run_compaction, github
    ) -> None:
        onboard(client, admin_auth)
        put_file(github, REQUIREMENTS, "urllib3==2.0.4\n")
        seed(client, auth, run_compaction, [dependency_finding()])
        client.post("/api/patchwork/run", json={}, headers=auth)
        run_compaction()

        result = await listing(client)

        kinds = {row.kind for row in result.pull_requests}
        assert "fix" in kinds
        fix = next(row for row in result.pull_requests if row.kind == "fix")
        assert fix.finding_id
        assert fix.draft is True
        assert fix.detail  # Patchwork's rationale, not an empty cell.

    @pytest.mark.anyio
    async def test_fixes_sort_before_installs(
        self, client, admin_auth, auth, run_compaction, github
    ) -> None:
        """A fix is a proposal about your code; an install is configuration."""
        onboard(client, admin_auth)
        put_file(github, REQUIREMENTS, "urllib3==2.0.4\n")
        seed(client, auth, run_compaction, [dependency_finding()])
        client.post("/api/patchwork/run", json={}, headers=auth)
        run_compaction()

        result = await listing(client)

        assert [row.kind for row in result.pull_requests][0] == "fix"

    @pytest.mark.anyio
    async def test_a_fix_for_an_offboarded_repo_is_not_listed(
        self, client, admin_auth, auth, run_compaction, github
    ) -> None:
        """The lake outlives the onboarding. A fix for a repo the platform no
        longer manages is not work anybody here can action."""
        onboard(client, admin_auth)
        put_file(github, REQUIREMENTS, "urllib3==2.0.4\n")
        seed(client, auth, run_compaction, [dependency_finding()])
        client.post("/api/patchwork/run", json={}, headers=auth)
        run_compaction()

        with client.app.state.db.session() as session:
            from mykronos.db.models import RepoOnboarding

            for row in session.query(RepoOnboarding).all():
                session.delete(row)
            session.commit()

        result = await listing(client)

        assert result.pull_requests == []


class TestEverybodyElsesPullRequests:
    """The defect this view had: it could only ever show its own work."""

    @pytest.mark.anyio
    async def test_a_pull_request_mykronos_did_not_open_is_listed(
        self, client, admin_auth, github
    ) -> None:
        """The whole point. A repository with a human's pull request open used
        to render as empty on a page called Pull requests."""
        install_pr(client, admin_auth)
        await github.create_pull_request(
            REPO,
            title="Rewrite the payments reconciler",
            body="Nothing to do with Mykronos.",
            head="feature/reconciler",
            base="main",
        )

        result = await listing(client)

        titles = {row.title for row in result.pull_requests}
        assert "Rewrite the payments reconciler" in titles

    @pytest.mark.anyio
    async def test_ours_and_theirs_stay_distinguishable(
        self, client, admin_auth, github
    ) -> None:
        """Listing everything must not blur what this platform is answerable
        for. An install turns scanning on; somebody else's branch does not."""
        install_pr(client, admin_auth)
        await github.create_pull_request(
            REPO, title="Unrelated", body="", head="feature/x", base="main"
        )

        rows = {row.title: row for row in (await listing(client)).pull_requests}

        assert rows["Unrelated"].kind == "other"
        assert rows["Unrelated"].summary == "", "no rationale to claim for it"
        ours = [row for row in rows.values() if row.kind == "install"]
        assert ours and ours[0].capabilities == ["secrets"]

    @pytest.mark.anyio
    async def test_our_work_sorts_above_work_we_only_report_on(
        self, client, admin_auth, github
    ) -> None:
        install_pr(client, admin_auth)
        await github.create_pull_request(
            REPO, title="Unrelated", body="", head="feature/x", base="main"
        )

        kinds = [row.kind for row in (await listing(client)).pull_requests]

        assert kinds.index("install") < kinds.index("other")


class TestDegrading:
    @pytest.mark.anyio
    async def test_an_unreachable_repo_is_reported_not_dropped(
        self, client, admin_auth, github, monkeypatch
    ) -> None:
        """A shorter list of outstanding work looks exactly like progress.

        Patched at `list_open_pull_requests` rather than `get_pull_request`:
        the view now asks GitHub for every open pull request per repository
        instead of asking about each one it remembers opening, so that is where
        an unreachable repository now fails.
        """
        install_pr(client, admin_auth)

        async def boom(*args: object, **kwargs: object) -> list[PullRequest]:
            raise GitHubError("upstream is having a day", status=502)

        monkeypatch.setattr(github, "list_open_pull_requests", boom)

        result = await listing(client)

        assert result.pull_requests == []
        assert [name for name, _ in result.unreachable] == [REPO]

    @pytest.mark.anyio
    async def test_a_failed_check_summary_leaves_the_row(
        self, client, admin_auth, github, monkeypatch
    ) -> None:
        """A missing check summary is a missing column, not a missing row."""
        install_pr(client, admin_auth)

        async def boom(*args: object, **kwargs: object) -> object:
            raise GitHubError("no checks for you", status=403)

        monkeypatch.setattr(github, "get_checks_summary", boom)

        result = await listing(client)

        assert len(result.pull_requests) == 1
        assert result.pull_requests[0].checks is None


class TestTheApi:
    def test_the_endpoint_requires_a_principal(self, client) -> None:
        assert client.get("/api/dashboard/pull-requests").status_code == 401

    def test_it_returns_the_page(self, client, admin_auth) -> None:
        install_pr(client, admin_auth)

        response = client.get("/api/dashboard/pull-requests", headers=admin_auth)

        assert response.status_code == 200
        body = response.json()
        assert body["pull_requests"][0]["kind"] == "install"
        assert body["unreachable"] == []

    def test_there_is_still_no_way_to_merge(self, client, admin_auth) -> None:
        """spec 08 §3, restated at the API boundary. The view exists precisely
        so that merging stays somewhere else."""
        schema = client.get("/openapi.json", headers=admin_auth).json()
        merge_routes = [
            path for path in schema["paths"] if "merge" in path.lower()
        ]

        assert merge_routes == []
