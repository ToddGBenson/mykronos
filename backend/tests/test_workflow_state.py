"""Enabling and disabling installed workflows — spec 32 §6.

The distinction every test here is about: **install is a pull request, enable
and disable are API calls.** Adding or removing code that runs in somebody's
repository stays a reviewed change (spec 03 §3); switching existing code off
does not, because the state an operator needs mid-incident is the `fly pause`
equivalent that takes effect now rather than after a review round-trip.

The second distinction, which is the one that would silently corrupt data if
it were got wrong: a disabled workflow is an *enabled capability whose lane is
paused*. `enabled_capabilities` and the capability grants must not move when a
workflow is switched off, or the grant registry starts disagreeing with what
may write to the lake — and the grants are what the coverage cross-check
trusts for any repository whose installer ledger never moves (spec 03 §3a).
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.conftest import REPO
from tests.test_onboarding import deliver, onboard


def _install(client: TestClient, admin_auth: dict[str, str], *capabilities: str) -> str:
    """Onboard, request capabilities, and merge the install pull request.

    The merge matters twice over. It is what moves the capability out of
    `pending_capabilities`, which is a different state from installed-and-
    disabled and is asserted on separately below. And it is what puts the
    workflow file on the default branch, which is the only place GitHub
    looks when asked what workflows a repository has.

    `FakeGitHubClient` deliberately does not merge on its own — it commits to
    the branch the installer created and leaves it there, because merging is
    a human action it has no business simulating. So the merge is performed
    here, explicitly, by copying the head branch's tree onto the default
    branch. Doing it in the helper rather than in the fake keeps "a pull
    request was opened" and "a pull request was merged" as two separate facts
    a test has to ask for.
    """
    repo_id = onboard(client, admin_auth).json()["id"]
    patch = client.patch(
        f"/api/repos/{repo_id}/capabilities",
        json={"capabilities": list(capabilities)},
        headers=admin_auth,
    ).json()

    fake = client.app.state.github_factory.client
    repo = fake.repos[REPO]
    number = patch["pull_request_number"]
    head = next(pr.head_branch for pr in repo.pull_requests if pr.number == number)
    repo.files.update(repo.branches[head])
    repo.branches[repo.default_branch] = dict(repo.files)

    deliver(
        client,
        "pull_request",
        {
            "action": "closed",
            "pull_request": {
                "number": number,
                "merged": True,
                "head": {"ref": head},
            },
            "repository": {"full_name": REPO},
        },
    )
    return str(repo_id)


class TestListing:
    def test_an_installed_workflow_reads_active(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        repo_id = _install(client, admin_auth, "sast")

        body = client.get(f"/api/repos/{repo_id}/workflows", headers=admin_auth).json()

        assert body["unavailable"] is None
        assert body["workflows"] == [
            {
                "capability": "sast",
                "workflow_file": "mykronos-sast.yml",
                "installed": True,
                "enabled": True,
                "state": "active",
                "url": f"https://github.com/{REPO}/actions/workflows/mykronos-sast.yml",
            }
        ]

    def test_state_comes_from_github_not_from_a_column(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        """spec 32 §6: derived, never stored.

        Somebody clicking Disable in the GitHub UI is the case a stored
        column gets wrong and never corrects. Mykronos is not told, so the
        only way to be right is to ask on every read.
        """
        repo_id = _install(client, admin_auth, "sast")
        fake = client.app.state.github_factory.client
        fake.repos[REPO].workflow_states["mykronos-sast.yml"] = "disabled_manually"

        body = client.get(f"/api/repos/{repo_id}/workflows", headers=admin_auth).json()

        assert body["workflows"][0]["state"] == "disabled_manually"
        assert body["workflows"][0]["enabled"] is False

    def test_disabled_by_inactivity_is_not_disabled_by_a_person(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        """The two are both "not running" and only one was somebody's choice.

        GitHub switches a scheduled workflow off after sixty days without a
        push. Collapsing that into the same answer as a deliberate pause
        hides a real coverage gap behind an intentional one.
        """
        repo_id = _install(client, admin_auth, "sast")
        fake = client.app.state.github_factory.client
        fake.repos[REPO].workflow_states["mykronos-sast.yml"] = "disabled_inactivity"

        body = client.get(f"/api/repos/{repo_id}/workflows", headers=admin_auth).json()

        assert body["workflows"][0]["state"] == "disabled_inactivity"

    def test_a_pending_install_reads_not_installed(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        """Requested, pull request open, nothing merged.

        `not_installed` rather than `disabled`: the fix is merging a pull
        request, not clicking enable, and the two must not look alike.
        """
        repo_id = onboard(client, admin_auth).json()["id"]
        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast"]},
            headers=admin_auth,
        )

        body = client.get(f"/api/repos/{repo_id}/workflows", headers=admin_auth).json()

        # Pending, so not in `enabled_capabilities` yet and correctly absent.
        assert body["workflows"] == []

    def test_a_concourse_repo_says_so_rather_than_erroring(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        """Spec 03 §3a. No workflows is a fact about the repository, not a
        failure, and a panel that 500s here teaches people to ignore it."""
        repo_id = onboard(client, admin_auth, scanned_by="concourse").json()["id"]

        response = client.get(f"/api/repos/{repo_id}/workflows", headers=admin_auth)

        assert response.status_code == 200
        body = response.json()
        assert body["workflows"] == []
        assert "concourse" in body["unavailable"]

    def test_github_being_unreachable_is_not_an_error(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        """§7's fail-soft rule, applied here: a repository page is about
        findings, and GitHub being down must not take it with it."""
        repo_id = _install(client, admin_auth, "sast")
        fake = client.app.state.github_factory.client
        del fake.repos[REPO]

        response = client.get(f"/api/repos/{repo_id}/workflows", headers=admin_auth)

        assert response.status_code == 200
        assert response.json()["unavailable"].startswith("GitHub did not answer")


class TestSwitching:
    def test_disable_takes_effect_without_a_pull_request(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        repo_id = _install(client, admin_auth, "sast")
        fake = client.app.state.github_factory.client
        before = len(fake.repos[REPO].pull_requests)

        response = client.put(
            f"/api/repos/{repo_id}/workflows/sast/disable", headers=admin_auth
        )

        assert response.status_code == 200
        assert response.json()["enabled"] is False
        assert fake.repos[REPO].workflow_states["mykronos-sast.yml"] == "disabled_manually"
        assert len(fake.repos[REPO].pull_requests) == before

    def test_the_file_survives_a_disable(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        """Disable is not uninstall. The file stays, so it still says what
        the lane does when somebody switches it back on."""
        repo_id = _install(client, admin_auth, "sast")
        client.put(f"/api/repos/{repo_id}/workflows/sast/disable", headers=admin_auth)

        fake = client.app.state.github_factory.client
        assert ".github/workflows/mykronos-sast.yml" in fake.repos[REPO].files

    def test_enable_puts_it_back(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        repo_id = _install(client, admin_auth, "sast")
        client.put(f"/api/repos/{repo_id}/workflows/sast/disable", headers=admin_auth)

        response = client.put(
            f"/api/repos/{repo_id}/workflows/sast/enable", headers=admin_auth
        )

        assert response.status_code == 200
        fake = client.app.state.github_factory.client
        assert fake.repos[REPO].workflow_states["mykronos-sast.yml"] == "active"

    def test_disabling_does_not_revoke_the_capability(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        """The invariant this endpoint exists next to and must not break.

        A paused lane is not a withdrawn permission. If disabling narrowed
        the grants, re-enabling would silently leave a capability that runs
        and cannot write — findings would upload 403 and the lane would look
        green for a reason nobody could see.
        """
        repo_id = _install(client, admin_auth, "sast")
        detail = client.get(f"/api/repos/{repo_id}", headers=admin_auth).json()
        assert detail["enabled_capabilities"] == ["sast"]

        client.put(f"/api/repos/{repo_id}/workflows/sast/disable", headers=admin_auth)

        after = client.get(f"/api/repos/{repo_id}", headers=admin_auth).json()
        assert after["enabled_capabilities"] == ["sast"]

    def test_switching_an_uninstalled_workflow_is_a_404(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        """And the message says the fix is an install pull request, because
        "not found" alone sends somebody to look for a broken toggle."""
        repo_id = _install(client, admin_auth, "sast")

        response = client.put(
            f"/api/repos/{repo_id}/workflows/secrets/disable", headers=admin_auth
        )

        assert response.status_code == 404
        assert "pull request" in response.json()["detail"]

    def test_a_concourse_repo_refuses_with_a_reason(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        """Unlike the read, this is a write with no honest way to succeed —
        so it refuses, and names the thing to pause instead."""
        repo_id = onboard(client, admin_auth, scanned_by="concourse").json()["id"]

        response = client.put(
            f"/api/repos/{repo_id}/workflows/sast/disable", headers=admin_auth
        )

        assert response.status_code == 409
        assert "Concourse" in response.json()["detail"]

    def test_a_capability_with_no_template_is_a_404(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        """`network` is configurable and has no workflow template, so there
        is nothing installed to switch."""
        repo_id = _install(client, admin_auth, "sast")

        response = client.put(
            f"/api/repos/{repo_id}/workflows/network/disable", headers=admin_auth
        )

        assert response.status_code == 404

    def test_the_change_is_audited(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        """Spec 12 §7. An off switch with no audit trail answers "why did
        this stop scanning" with a shrug."""
        repo_id = _install(client, admin_auth, "sast")
        client.put(f"/api/repos/{repo_id}/workflows/sast/disable", headers=admin_auth)

        from mykronos.db.models import AuditLogEntry

        db = client.app.state.db
        with db.session() as session:
            actions = [row.action for row in session.query(AuditLogEntry).all()]
        assert "workflow.disabled" in actions
