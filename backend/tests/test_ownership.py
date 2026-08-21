"""Finding ownership, resolved at ingest (spec 24 §1).

The property under test throughout: an owner is *copied* from the repository's
own CODEOWNERS file or from its risk profile, and is never invented. Every
path that cannot answer resolves to `unresolved` rather than to something that
looks like a routing decision somebody made.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from mykronos.db.models import Organization, RepoOnboarding, RiskProfile
from mykronos.github.client import FakeGitHubClient
from mykronos.lake.catalog import Catalog
from tests.conftest import (
    INSTALLATION,
    REPO,
    dependency_finding,
    finding_payload,
    post_findings,
    post_scan,
)


def onboard(client: TestClient, repo: str = REPO) -> str:
    """Minimum onboarding: ingest needs an installation to read a file with."""
    owner = repo.split("/")[0]
    with client.app.state.db.session() as session:  # type: ignore[attr-defined]
        org = (
            session.query(Organization).filter(Organization.github_org_login == owner).one_or_none()
        )
        if org is None:
            org = Organization(github_org_login=owner)
            session.add(org)
            session.flush()
        row = RepoOnboarding(
            org_id=org.id,
            github_repo_full_name=repo,
            github_installation_id=INSTALLATION,
            status="active",
            enabled_capabilities=["sast"],
            default_branch="main",
        )
        session.add(row)
        session.flush()
        return str(row.id)


def set_profile_owner(client: TestClient, onboarding_id: str, owner: str) -> None:
    with client.app.state.db.session() as session:  # type: ignore[attr-defined]
        session.add(RiskProfile(repo_onboarding_id=onboarding_id, owner=owner))


def owners(catalog: Catalog) -> list[tuple[Any, Any]]:
    return [
        (row[0], row[1])
        for row in catalog.query("SELECT owner, owner_source FROM findings ORDER BY rule_id")
    ]


class TestResolutionAtIngest:
    def test_a_matching_pattern_owns_the_finding(
        self,
        client: TestClient,
        auth: dict[str, str],
        github: FakeGitHubClient,
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        onboard(client)
        github.add_repo(
            REPO, files={".github/CODEOWNERS": "* @org/platform\norders/ @org/payments\n"}
        )

        post_scan(client, auth)
        post_findings(client, auth, [finding_payload()])  # orders/query.py
        run_compaction()

        assert owners(catalog) == [("@org/payments", "codeowners")]

    def test_a_path_no_pattern_matches_is_unresolved(
        self,
        client: TestClient,
        auth: dict[str, str],
        github: FakeGitHubClient,
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        onboard(client)
        github.add_repo(REPO, files={".github/CODEOWNERS": "docs/ @org/docs\n"})

        post_scan(client, auth)
        post_findings(client, auth, [finding_payload()])
        run_compaction()

        assert owners(catalog) == [(None, "unresolved")]

    def test_no_codeowners_file_is_unresolved(
        self,
        client: TestClient,
        auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        """The common case in this portfolio, and it must not guess."""
        onboard(client)

        post_scan(client, auth)
        post_findings(client, auth, [finding_payload()])
        run_compaction()

        assert owners(catalog) == [(None, "unresolved")]

    def test_an_unonboarded_repo_ingests_without_an_owner(
        self,
        client: TestClient,
        auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        """No installation to read a file with is one more way of not knowing.
        It is emphatically not an ingest failure."""
        post_scan(client, auth)
        assert post_findings(client, auth, [finding_payload()]).status_code == 200
        run_compaction()

        assert owners(catalog) == [(None, "unresolved")]

    def test_github_failing_does_not_fail_the_ingest(
        self,
        client: TestClient,
        auth: dict[str, str],
        github: FakeGitHubClient,
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        onboard(client)

        async def explode(*_args: Any, **_kwargs: Any) -> str:
            raise RuntimeError("api.github.com is having a day")

        github.get_file = explode  # type: ignore[method-assign]

        post_scan(client, auth)
        assert post_findings(client, auth, [finding_payload()]).status_code == 200
        run_compaction()

        assert owners(catalog) == [(None, "unresolved")]


class TestFindingsWithNoPath:
    def test_a_dependency_finding_uses_the_profile_owner(
        self,
        client: TestClient,
        auth: dict[str, str],
        github: FakeGitHubClient,
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        onboarding_id = onboard(client)
        set_profile_owner(client, onboarding_id, "@org/platform")
        github.add_repo(REPO, files={".github/CODEOWNERS": "* @org/everything\n"})

        post_scan(client, auth)
        post_findings(client, auth, [dependency_finding()])
        run_compaction()

        # Not `@org/everything`: a dependency finding names a package, not the
        # file that declares it, so the catch-all pattern is not evidence
        # about who owns this dependency.
        assert owners(catalog) == [("@org/platform", "profile")]

    def test_a_dependency_finding_with_no_profile_is_unresolved(
        self,
        client: TestClient,
        auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        onboard(client)

        post_scan(client, auth)
        post_findings(client, auth, [dependency_finding()])
        run_compaction()

        assert owners(catalog) == [(None, "unresolved")]


class TestCaching:
    def test_one_codeowners_read_serves_a_whole_batch(
        self,
        client: TestClient,
        auth: dict[str, str],
        github: FakeGitHubClient,
    ) -> None:
        """A four-hundred-finding upload is one GitHub request, not four
        hundred."""
        onboard(client)
        github.add_repo(REPO, files={".github/CODEOWNERS": "* @org/platform\n"})

        post_scan(client, auth)
        post_findings(
            client,
            auth,
            [finding_payload(rule_id=f"RULE-{n}", symbol=f"fn_{n}") for n in range(25)],
        )

        reads = [call for call in github.calls if call[0] == "get_file"]
        assert len(reads) == 1

    def test_a_second_batch_reuses_the_cached_read(
        self,
        client: TestClient,
        auth: dict[str, str],
        github: FakeGitHubClient,
    ) -> None:
        onboard(client)
        github.add_repo(REPO, files={".github/CODEOWNERS": "* @org/platform\n"})

        post_scan(client, auth)
        post_findings(client, auth, [finding_payload()])
        post_findings(client, auth, [finding_payload(rule_id="OTHER")])

        assert len([call for call in github.calls if call[0] == "get_file"]) == 1

    def test_a_repo_with_no_file_is_not_asked_again(
        self,
        client: TestClient,
        auth: dict[str, str],
        github: FakeGitHubClient,
    ) -> None:
        """The negative result is cached too — otherwise the common case
        spends a rate-limit budget on a 404 per batch."""
        onboard(client)

        post_scan(client, auth)
        post_findings(client, auth, [finding_payload()])
        first = len([call for call in github.calls if call[0] == "get_file"])
        post_findings(client, auth, [finding_payload(rule_id="OTHER")])

        assert len([call for call in github.calls if call[0] == "get_file"]) == first


class TestPrecedence:
    @pytest.mark.parametrize("path", [".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"])
    def test_every_location_github_looks_in(
        self,
        client: TestClient,
        auth: dict[str, str],
        github: FakeGitHubClient,
        catalog: Catalog,
        run_compaction: Any,
        path: str,
    ) -> None:
        onboard(client)
        github.add_repo(REPO, files={path: "* @org/platform\n"})

        post_scan(client, auth)
        post_findings(client, auth, [finding_payload()])
        run_compaction()

        assert owners(catalog) == [("@org/platform", "codeowners")]


class TestManualAssignment:
    def test_an_admin_can_reassign_a_finding(
        self,
        client: TestClient,
        auth: dict[str, str],
        admin_auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        onboard(client)
        post_scan(client, auth)
        post_findings(client, auth, [finding_payload()])
        run_compaction()
        (finding_id,) = catalog.query("SELECT finding_id FROM findings")[0]

        response = client.patch(
            f"/api/dashboard/findings/{finding_id}/owner",
            json={"owner": "@org/payments"},
            headers=admin_auth,
        )

        assert response.status_code == 200
        assert response.json()["owner_source"] == "manual"
        assert owners(catalog) == [("@org/payments", "manual")]

    def test_a_viewer_cannot_reassign(
        self,
        client: TestClient,
        auth: dict[str, str],
        viewer_auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        onboard(client)
        post_scan(client, auth)
        post_findings(client, auth, [finding_payload()])
        run_compaction()
        (finding_id,) = catalog.query("SELECT finding_id FROM findings")[0]

        response = client.patch(
            f"/api/dashboard/findings/{finding_id}/owner",
            json={"owner": "@someone"},
            headers=viewer_auth,
        )

        assert response.status_code == 403

    def test_a_manual_owner_survives_a_rescan(
        self,
        client: TestClient,
        auth: dict[str, str],
        admin_auth: dict[str, str],
        github: FakeGitHubClient,
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        """spec 24 §1.2: a re-scan is not new information about who should fix
        it. CODEOWNERS says @org/platform; a person said otherwise."""
        onboard(client)
        github.add_repo(REPO, files={".github/CODEOWNERS": "* @org/platform\n"})
        post_scan(client, auth)
        post_findings(client, auth, [finding_payload()])
        run_compaction()
        (finding_id,) = catalog.query("SELECT finding_id FROM findings")[0]
        client.patch(
            f"/api/dashboard/findings/{finding_id}/owner",
            json={"owner": "@org/payments"},
            headers=admin_auth,
        )

        post_findings(client, auth, [finding_payload()], scan_run_id="run-2")
        run_compaction()

        assert owners(catalog) == [("@org/payments", "manual")]

    def test_clearing_an_owner_hands_it_back_to_codeowners(
        self,
        client: TestClient,
        auth: dict[str, str],
        admin_auth: dict[str, str],
        github: FakeGitHubClient,
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        """Not a permanent unassignment: the next scan re-resolves it."""
        onboard(client)
        github.add_repo(REPO, files={".github/CODEOWNERS": "* @org/platform\n"})
        post_scan(client, auth)
        post_findings(client, auth, [finding_payload()])
        run_compaction()
        (finding_id,) = catalog.query("SELECT finding_id FROM findings")[0]

        client.patch(
            f"/api/dashboard/findings/{finding_id}/owner",
            json={"owner": "@org/payments"},
            headers=admin_auth,
        )
        client.patch(
            f"/api/dashboard/findings/{finding_id}/owner",
            json={"owner": None},
            headers=admin_auth,
        )
        post_findings(client, auth, [finding_payload()], scan_run_id="run-2")
        run_compaction()

        assert owners(catalog) == [("@org/platform", "codeowners")]

    def test_the_reassignment_is_audited(
        self,
        client: TestClient,
        auth: dict[str, str],
        admin_auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        onboard(client)
        post_scan(client, auth)
        post_findings(client, auth, [finding_payload()])
        run_compaction()
        (finding_id,) = catalog.query("SELECT finding_id FROM findings")[0]

        client.patch(
            f"/api/dashboard/findings/{finding_id}/owner",
            json={"owner": "@org/payments"},
            headers=admin_auth,
        )

        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            actions = [row[0] for row in session.execute(text("SELECT action FROM audit_log"))]
        assert "finding.owner" in actions
