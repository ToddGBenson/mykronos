"""What exists, against what is watched (B-051).

The platform knew what it had been told about and never what existed, so "four
of eleven repositories are watched" came from a person reading the account
rather than from here. Nothing could notice a repository nobody onboarded:
`binnacle` sat unscanned with 30 shell scripts in it until somebody looked.

The count is only ever as wide as the App's grant, and the response says so.
An installation scoped to five repositories reports five of five and is
telling the truth about itself while saying nothing about the account.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from mykronos.github import FakeGitHubClient
from mykronos.github.client import FakeRepo, GitHubError
from tests.conftest import REPO
from tests.test_onboarding import onboard


def estate(client: TestClient, admin_auth: dict[str, str]) -> dict:
    response = client.get("/api/dashboard/portfolio", headers=admin_auth)
    assert response.status_code == 200
    return response.json()["estate"]


class TestCountingTheEstate:
    def test_a_repository_nobody_onboarded_is_named(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient
    ) -> None:
        """A number says there is a gap. The name says which repository to go
        and look at, which is the whole difference between this and the
        sentence it replaces."""
        onboard(client, admin_auth)
        github.repos["example-org/forgotten"] = FakeRepo(full_name="example-org/forgotten")

        body = estate(client, admin_auth)

        assert body["visible"] == 2
        assert body["onboarded"] == 1
        assert body["unwatched"] == ["example-org/forgotten"]

    def test_a_fully_watched_estate_names_nothing(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        onboard(client, admin_auth)

        body = estate(client, admin_auth)

        assert body["visible"] == 1
        assert body["onboarded"] == 1
        assert body["unwatched"] == []

    def test_the_note_says_the_count_is_as_wide_as_the_grant(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        """Five of five is true about the installation and says nothing about
        the account. Reporting it without that sentence is how a narrow grant
        reads as a clean estate."""
        onboard(client, admin_auth)

        assert "as the App is granted it" in estate(client, admin_auth)["note"]


class TestWhenItCannotBeRead:
    def test_an_unreadable_listing_claims_nothing(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient
    ) -> None:
        """"The App could not tell us" and "the account has no other
        repositories" are different facts, and only one of them is good news.
        `visible` stays null rather than falling back to zero, which would
        report an estate of nothing."""
        onboard(client, admin_auth)

        async def refuse() -> list[str] | None:
            raise GitHubError("no", status=403)

        github.installation_repositories = refuse  # type: ignore[method-assign]

        body = estate(client, admin_auth)

        assert body["visible"] is None
        assert body["unwatched"] == []
        assert "could not be read" in body["note"]

    def test_onboarded_is_still_counted(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient
    ) -> None:
        """What the platform was told about is knowable without GitHub, and
        losing the listing must not lose that too."""
        onboard(client, admin_auth)

        async def refuse() -> list[str] | None:
            raise GitHubError("no", status=403)

        github.installation_repositories = refuse  # type: ignore[method-assign]

        assert estate(client, admin_auth)["onboarded"] == 1


class TestTheClient:
    async def test_the_fake_lists_what_it_holds(self, github: FakeGitHubClient) -> None:
        github.repos[REPO] = FakeRepo(full_name=REPO)
        github.repos["example-org/other"] = FakeRepo(full_name="example-org/other")

        assert await github.installation_repositories() == sorted(
            ["example-org/other", REPO]
        )
