"""Bulk template resync — spec 03 §6.

The property spec 03 §6 insists on, and the one worth testing hardest, is that
drift is detected by comparing *content* rather than the version header. A
repository where somebody hand-edited the workflow advertises a version it no
longer matches; trusting the header would skip exactly the repository most in
need of the sweep.
"""

from __future__ import annotations

import pytest

from mykronos.config import get_settings
from mykronos.github.factory import FakeGitHubClientFactory
from mykronos.installer import DEFAULT_SECRET_NAME, TemplateLibrary
from mykronos.installer.installer import BRANCH_PREFIX
from mykronos.installer.resync import RESYNC_BRANCH_PREFIX, resync_templates
from tests.conftest import REPO
from tests.test_portfolio_job import register

SAST_PATH = ".github/workflows/mykronos-sast.yml"


@pytest.fixture
def templates() -> TemplateLibrary:
    return TemplateLibrary(get_settings().workflow_templates_dir)


async def sweep(client, github, templates, **kwargs):
    return await resync_templates(
        client.app.state.db,
        templates,
        FakeGitHubClientFactory(github),
        ingestion_api_url="https://mykronos.test",
        upload_action_ref="ToddGBenson/mykronos/actions/upload-results@v1",
        package_spec="mykronos @ git+https://github.com/x/y@v1#subdirectory=backend",
        secret_name=DEFAULT_SECRET_NAME,
        **kwargs,
    )


def put(github, path: str, content: str, branch: str = "main") -> None:
    repo = github.repos[REPO]
    repo.files[path] = content
    repo.branches.setdefault(branch, {})[path] = content


def rendered(templates, capability="sast") -> str:
    from tests.conftest import render_context

    return templates.render(
        capability, **render_context(
            ingestion_api_url="https://mykronos.test",
            gate_depends_on=[],
        )
    ).content


class TestDriftDetection:
    @pytest.mark.anyio
    async def test_an_up_to_date_repo_is_left_alone(
        self, client, admin_auth, github, templates
    ) -> None:
        register(client, REPO, capabilities=["sast"])
        put(github, SAST_PATH, rendered(templates))

        result = await sweep(client, github, templates)

        assert result.up_to_date == 1
        assert result.opened == []

    @pytest.mark.anyio
    async def test_a_drifted_file_gets_a_pull_request(
        self, client, admin_auth, github, templates
    ) -> None:
        register(client, REPO, capabilities=["sast"])
        put(github, SAST_PATH, "name: something else entirely\n")

        result = await sweep(client, github, templates)

        assert len(result.opened) == 1
        assert result.opened[0].drifted == [SAST_PATH]

    @pytest.mark.anyio
    async def test_a_hand_edit_is_caught_despite_a_matching_header(
        self, client, admin_auth, github, templates
    ) -> None:
        """The case spec 03 §6 exists for. The header still claims the current
        version; the body does not match it. Trusting the string would skip
        the one repository that most needs looking at."""
        tampered = rendered(templates).replace(
            "runs-on: ubuntu-latest", "runs-on: self-hosted-mystery-box"
        )
        register(client, REPO, capabilities=["sast"])
        put(github, SAST_PATH, tampered)

        result = await sweep(client, github, templates)

        assert len(result.opened) == 1

    @pytest.mark.anyio
    async def test_line_endings_alone_are_not_drift(
        self, client, admin_auth, github, templates
    ) -> None:
        """A pull request whose entire diff is CRLF trains people to ignore
        these."""
        register(client, REPO, capabilities=["sast"])
        put(github, SAST_PATH, rendered(templates).replace("\n", "\r\n"))

        result = await sweep(client, github, templates)

        assert result.up_to_date == 1

    @pytest.mark.anyio
    async def test_a_missing_file_is_drift(
        self, client, admin_auth, github, templates
    ) -> None:
        """Somebody deleted the workflow. The capability is still enabled, so
        Mykronos believes it is scanning and it is not."""
        register(client, REPO, capabilities=["sast"])

        result = await sweep(client, github, templates)

        assert len(result.opened) == 1


class TestScope:
    @pytest.mark.anyio
    async def test_only_active_repos_are_swept(
        self, client, admin_auth, github, templates
    ) -> None:
        register(client, REPO, capabilities=["sast"], status="removed")

        assert (await sweep(client, github, templates)).checked == 0

    @pytest.mark.anyio
    async def test_a_capability_filter_narrows_the_sweep(
        self, client, admin_auth, github, templates
    ) -> None:
        register(client, REPO, capabilities=["sast"])

        result = await sweep(client, github, templates, capabilities={"secrets"})

        assert result.opened == []
        assert result.up_to_date == 1


class TestBoundedness:
    @pytest.mark.anyio
    async def test_the_limit_defers_rather_than_drops(
        self, client, admin_auth, github, templates
    ) -> None:
        """A sweep that opened a pull request against every repository at once
        would be indistinguishable from an incident."""
        register(client, REPO, capabilities=["sast"])
        register(client, "example-org/ledger-core", capabilities=["sast"])
        github.add_repo("example-org/ledger-core", files={"README.md": "#"})
        github.repos["example-org/ledger-core"].branches["main"] = {"README.md": "#"}

        result = await sweep(client, github, templates, max_pull_requests=1)

        assert len(result.opened) == 1
        assert len(result.deferred) == 1

    @pytest.mark.anyio
    async def test_what_was_deferred_is_named(
        self, client, admin_auth, github, templates
    ) -> None:
        """An unreported cap reads as "everything is up to date"."""
        register(client, REPO, capabilities=["sast"])
        register(client, "example-org/ledger-core", capabilities=["sast"])
        github.add_repo("example-org/ledger-core", files={"README.md": "#"})
        github.repos["example-org/ledger-core"].branches["main"] = {"README.md": "#"}

        result = await sweep(client, github, templates, max_pull_requests=1)

        assert result.deferred
        deferred = next(r for r in result.repos if r.repo_full_name in result.deferred)
        assert "next run will pick it up" in (deferred.skipped_reason or "")

    @pytest.mark.anyio
    async def test_a_dry_run_touches_nothing(
        self, client, admin_auth, github, templates
    ) -> None:
        register(client, REPO, capabilities=["sast"])

        result = await sweep(client, github, templates, dry_run=True)

        assert result.opened == []
        assert result.repos[0].drifted == [SAST_PATH]
        assert github.repos[REPO].pull_requests == []


class TestItDoesNotCollide:
    @pytest.mark.anyio
    async def test_an_open_install_pr_defers_the_resync(
        self, client, admin_auth, github, templates
    ) -> None:
        """Two pull requests touching the same files means whichever merges
        second conflicts."""
        register(client, REPO, capabilities=["sast"])
        github.repos[REPO].branches[f"{BRANCH_PREFIX}x"] = {}
        await github.create_pull_request(
            REPO, head=f"{BRANCH_PREFIX}x", base="main", title="install", body=""
        )

        result = await sweep(client, github, templates)

        assert result.opened == []
        assert "install pull request" in (result.repos[0].skipped_reason or "")

    @pytest.mark.anyio
    async def test_a_second_run_pushes_to_the_open_resync_pr(
        self, client, admin_auth, github, templates
    ) -> None:
        """An operator with two resync pull requests cannot tell which is
        current."""
        register(client, REPO, capabilities=["sast"])

        first = await sweep(client, github, templates)
        second = await sweep(client, github, templates)

        assert len(github.repos[REPO].pull_requests) == 1
        assert (
            first.opened[0].pull_request_number
            == second.opened[0].pull_request_number
        )

    @pytest.mark.anyio
    async def test_it_never_commits_to_the_default_branch(
        self, client, admin_auth, github, templates
    ) -> None:
        register(client, REPO, capabilities=["sast"])
        before = dict(github.repos[REPO].branches.get("main", {}))

        await sweep(client, github, templates)

        assert github.repos[REPO].branches["main"] == before
        assert github.repos[REPO].pull_requests[-1].head_branch.startswith(
            RESYNC_BRANCH_PREFIX
        )


class TestFailures:
    @pytest.mark.anyio
    async def test_one_unreachable_repo_does_not_stop_the_sweep(
        self, client, admin_auth, github, templates
    ) -> None:
        register(client, REPO, capabilities=["sast"])
        register(client, "example-org/vanished", capabilities=["sast"])
        # Deliberately not added to the fake, so reading it raises a 404.

        result = await sweep(client, github, templates)

        assert result.checked == 2
        assert len(result.opened) == 1
        assert any(r.error for r in result.repos)

    @pytest.mark.anyio
    async def test_a_failure_is_not_counted_as_up_to_date(
        self, client, admin_auth, github, templates
    ) -> None:
        """The reading that matters: "we could not check" must not look like
        "nothing to do"."""
        register(client, "example-org/vanished", capabilities=["sast"])

        result = await sweep(client, github, templates)

        assert result.up_to_date == 0
        assert result.repos[0].error


class TestThePullRequestBody:
    @pytest.mark.anyio
    async def test_it_explains_a_hand_edit(
        self, client, admin_auth, github, templates
    ) -> None:
        register(client, REPO, capabilities=["sast"])

        await sweep(client, github, templates)
        number = github.repos[REPO].pull_requests[-1].number
        body = github.pull_request_bodies[number]

        assert "edited by hand" in body
        assert "compares **content**" in body
        assert "never merges them" in body
