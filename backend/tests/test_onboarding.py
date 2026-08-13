"""Onboarding API and webhook receiver — spec 02 §5, §7; spec 12 §3, §7.

The webhook tests carry most of the weight. That endpoint cannot present a
bearer token, so its HMAC signature is the only thing between the open
internet and an API that creates onboardings and flips repos to active.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

from fastapi.testclient import TestClient

from mykronos.auth import TokenRegistry
from mykronos.config import Settings
from mykronos.db.models import AuditLogEntry, RepoOnboarding
from mykronos.github import FakeGitHubClient
from mykronos.installer import BRANCH_PREFIX, DEFAULT_SECRET_NAME
from mykronos.main import create_app
from tests.conftest import INSTALLATION, REPO, WEBHOOK_SECRET, scan_run_payload


def sign(body: bytes, secret: str = WEBHOOK_SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def deliver(
    client: TestClient, event: str, payload: dict[str, Any], secret: str = WEBHOOK_SECRET
):
    body = json.dumps(payload).encode()
    return client.post(
        "/webhooks/github",
        content=body,
        headers={
            "X-GitHub-Event": event,
            "X-GitHub-Delivery": "delivery-1",
            "X-Hub-Signature-256": sign(body, secret),
            "Content-Type": "application/json",
        },
    )


def installation_payload(action: str = "created", repos: list[str] | None = None):
    return {
        "action": action,
        "installation": {
            "id": INSTALLATION,
            "account": {"login": "example-org"},
        },
        "repositories": [{"full_name": name} for name in (repos or [REPO])],
    }


def onboard(client: TestClient, admin_auth: dict[str, str], repo: str = REPO):
    return client.post(
        "/api/repos",
        json={
            "github_repo_full_name": repo,
            "github_installation_id": INSTALLATION,
            "default_branch": "main",
        },
        headers=admin_auth,
    )


# ---------------------------------------------------------------------------


class TestWebhookSecurity:
    def test_a_forged_signature_is_rejected(self, client: TestClient) -> None:
        """The whole security model of this endpoint."""
        response = deliver(client, "installation", installation_payload(), secret="wrong")
        assert response.status_code == 401

    def test_a_missing_signature_is_rejected(self, client: TestClient) -> None:
        response = client.post(
            "/webhooks/github",
            content=b"{}",
            headers={"X-GitHub-Event": "installation"},
        )
        assert response.status_code == 401

    def test_a_tampered_body_is_rejected(self, client: TestClient) -> None:
        """Signature is over the exact bytes, so altering the payload after
        signing must not slip through."""
        original = json.dumps(installation_payload()).encode()
        tampered = json.dumps(installation_payload(repos=["attacker/evil"])).encode()

        response = client.post(
            "/webhooks/github",
            content=tampered,
            headers={
                "X-GitHub-Event": "installation",
                "X-Hub-Signature-256": sign(original),
            },
        )
        assert response.status_code == 401

    def test_no_configured_secret_rejects_everything(self, settings: Settings) -> None:
        """Fail closed. An unconfigured deployment must not accept unsigned
        instructions to onboard repos."""
        settings.github_webhook_secret = ""
        with TestClient(create_app(settings)) as unconfigured:
            response = deliver(unconfigured, "installation", installation_payload())
        assert response.status_code == 503
        assert "webhook secret" in response.json()["detail"].lower()

    def test_an_unhandled_event_returns_200(self, client: TestClient) -> None:
        """A non-2xx is a delivery failure to GitHub, and enough of them
        disable the webhook. "Not interested" must not look like "broken"."""
        response = deliver(client, "check_run", {"action": "created"})
        assert response.status_code == 200
        assert response.json()["ignored"] == "check_run"


class TestInstallationEvents:
    def test_installation_creates_a_pending_onboarding(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        assert deliver(client, "installation", installation_payload()).status_code == 200

        repos = client.get("/api/repos", headers=admin_auth).json()
        assert [r["github_repo_full_name"] for r in repos] == [REPO]
        assert repos[0]["status"] == "pending_install"
        assert repos[0]["enabled_capabilities"] == []

    def test_redelivery_does_not_duplicate(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        """GitHub redelivers. Handlers have to be idempotent."""
        deliver(client, "installation", installation_payload())
        deliver(client, "installation", installation_payload())

        assert len(client.get("/api/repos", headers=admin_auth).json()) == 1

    def test_uninstall_marks_repos_removed(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        deliver(client, "installation", installation_payload())
        deliver(client, "installation", installation_payload(action="deleted"))

        assert client.get("/api/repos", headers=admin_auth).json() == []
        including = client.get(
            "/api/repos", params={"include_removed": True}, headers=admin_auth
        ).json()
        assert including[0]["status"] == "removed"

    def test_suspend_is_distinct_from_removed(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        """spec 02 §9: so the dashboard can say "paused" rather than "gone"."""
        deliver(client, "installation", installation_payload())
        deliver(client, "installation", installation_payload(action="suspend"))

        repos = client.get("/api/repos", headers=admin_auth).json()
        assert repos[0]["status"] == "suspended"

    def test_reinstall_revives_a_removed_repo(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        """Otherwise the row is stranded as `removed` with a stale
        installation id and the repo can never be onboarded again."""
        deliver(client, "installation", installation_payload())
        deliver(client, "installation", installation_payload(action="deleted"))
        deliver(client, "installation", installation_payload())

        repos = client.get("/api/repos", headers=admin_auth).json()
        assert len(repos) == 1
        assert repos[0]["status"] == "pending_install"

    def test_repositories_added_and_removed(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        deliver(
            client,
            "installation_repositories",
            {
                "action": "added",
                "installation": {"id": INSTALLATION, "account": {"login": "example-org"}},
                "repositories_added": [{"full_name": REPO}, {"full_name": "example-org/other"}],
                "repositories_removed": [],
            },
        )
        assert len(client.get("/api/repos", headers=admin_auth).json()) == 2

        deliver(
            client,
            "installation_repositories",
            {
                "action": "removed",
                "installation": {"id": INSTALLATION, "account": {"login": "example-org"}},
                "repositories_added": [],
                "repositories_removed": [{"full_name": "example-org/other"}],
            },
        )
        assert len(client.get("/api/repos", headers=admin_auth).json()) == 1


class TestAdminAuth:
    def test_unauthenticated_is_refused(self, client: TestClient) -> None:
        assert client.get("/api/repos").status_code == 401

    def test_a_wrong_token_is_refused(self, client: TestClient) -> None:
        assert client.get(
            "/api/repos", headers={"Authorization": "Bearer nope"}
        ).status_code == 401

    def test_no_configured_token_disables_the_api(self, settings: Settings) -> None:
        """Fail closed: an unconfigured deployment is unusable, not open."""
        settings.admin_token = ""
        with TestClient(create_app(settings)) as unconfigured:
            response = unconfigured.get("/api/repos")
        assert response.status_code == 503
        assert "no token configured" in response.json()["detail"].lower()


class TestOnboardingApi:
    def test_onboard_is_idempotent(self, client: TestClient, admin_auth: dict[str, str]) -> None:
        first = onboard(client, admin_auth)
        second = onboard(client, admin_auth)

        assert first.status_code == 201
        assert first.json()["id"] == second.json()["id"]
        assert len(client.get("/api/repos", headers=admin_auth).json()) == 1

    def test_enabling_a_capability_opens_a_pull_request(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient
    ) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]

        response = client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast"]},
            headers=admin_auth,
        )

        assert response.status_code == 200
        body = response.json()
        assert body["added"] == ["sast"]
        assert body["pull_request_number"] is not None
        assert body["secret_provisioned"] is True
        assert DEFAULT_SECRET_NAME in github.repos[REPO].secrets

    def test_capabilities_are_pending_until_the_pr_merges(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]
        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast"]},
            headers=admin_auth,
        )

        detail = client.get(f"/api/repos/{repo_id}", headers=admin_auth).json()
        assert detail["enabled_capabilities"] == []
        assert detail["pending_capabilities"] == ["sast"]
        # Grants are live immediately, though (spec 03 §5).
        assert detail["granted_capabilities"] == ["sast"]

    def test_merging_the_install_pr_activates_the_repo(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        """The full loop: onboard, enable, merge, active."""
        repo_id = onboard(client, admin_auth).json()["id"]
        patch = client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast"]},
            headers=admin_auth,
        ).json()

        deliver(
            client,
            "pull_request",
            {
                "action": "closed",
                "pull_request": {
                    "number": patch["pull_request_number"],
                    "merged": True,
                    "head": {"ref": f"{BRANCH_PREFIX}20260808T000000"},
                },
                "repository": {"full_name": REPO},
            },
        )

        detail = client.get(f"/api/repos/{repo_id}", headers=admin_auth).json()
        assert detail["status"] == "active"
        assert detail["enabled_capabilities"] == ["sast"]
        assert detail["pending_capabilities"] is None

    def test_an_unrelated_merged_pr_changes_nothing(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]
        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast"]},
            headers=admin_auth,
        )

        response = deliver(
            client,
            "pull_request",
            {
                "action": "closed",
                "pull_request": {
                    "number": 99,
                    "merged": True,
                    "head": {"ref": "feature/someone-elses-work"},
                },
                "repository": {"full_name": REPO},
            },
        )

        # The event is still handled — a closing PR is now also where a gate
        # outcome gets recorded — but nothing is promoted off the back of a
        # branch we did not create.
        assert response.json()["promoted"] == []
        assert client.get(f"/api/repos/{repo_id}", headers=admin_auth).json()["status"] != "active"

    def test_a_repeated_save_opens_no_second_pr(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient
    ) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]
        body = {"capabilities": ["sast"]}
        client.patch(f"/api/repos/{repo_id}/capabilities", json=body, headers=admin_auth)
        second = client.patch(f"/api/repos/{repo_id}/capabilities", json=body, headers=admin_auth)

        assert second.json()["added"] == []
        assert len(github.repos[REPO].pull_requests) == 1
        assert "already requested" in second.json()["detail"]
        # The open PR is still named, so the admin knows what to go and merge.
        assert second.json()["pull_request_number"] is not None

    def test_withdrawing_before_merge_closes_the_pr_and_revokes_the_grant(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient
    ) -> None:
        """Enable sast, change your mind before the PR merges.

        Until this was fixed the withdrawal was a complete no-op: the grant
        stayed live and the PR stayed open, so merging it later would enable
        exactly what the admin had cancelled.
        """
        repo_id = onboard(client, admin_auth).json()["id"]
        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast"]},
            headers=admin_auth,
        )

        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": []},
            headers=admin_auth,
        )

        assert github.repos[REPO].pull_requests[0].state == "closed"
        detail = client.get(f"/api/repos/{repo_id}", headers=admin_auth).json()
        assert detail["granted_capabilities"] == []
        assert detail["pending_capabilities"] is None

    def test_a_path_collision_is_a_409_naming_the_file(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient
    ) -> None:
        """spec 03 §8 surfaced to the admin, not buried in a log."""
        github.repos[REPO].branches["main"][
            ".github/workflows/mykronos-sast.yml"
        ] = "name: hand-written"
        repo_id = onboard(client, admin_auth).json()["id"]

        response = client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast"]},
            headers=admin_auth,
        )

        assert response.status_code == 409
        assert "mykronos-sast.yml" in response.json()["detail"]

    def test_config_for_a_disabled_capability_is_rejected(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]
        response = client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast"], "config": {"iac": {"blocking": True}}},
            headers=admin_auth,
        )
        assert response.status_code == 422

    def test_offboarding_revokes_tokens_but_keeps_history(
        self, client: TestClient, admin_auth: dict[str, str], settings: Settings
    ) -> None:
        """spec 02 §6: stop the activity, keep the audit trail."""
        repo_id = onboard(client, admin_auth).json()["id"]
        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast"]},
            headers=admin_auth,
        )

        assert client.delete(f"/api/repos/{repo_id}", headers=admin_auth).status_code == 200

        with client.app.state.db.session() as session:
            registry = TokenRegistry(session)
            assert registry.granted_capabilities(REPO) == set()
            row = session.get(RepoOnboarding, repo_id)
            assert row is not None and row.status == "removed"

    def test_capabilities_cannot_change_on_an_offboarded_repo(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]
        client.delete(f"/api/repos/{repo_id}", headers=admin_auth)

        response = client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast"]},
            headers=admin_auth,
        )
        assert response.status_code == 409

    def test_unknown_repo_is_404(self, client: TestClient, admin_auth: dict[str, str]) -> None:
        assert client.get("/api/repos/nope", headers=admin_auth).status_code == 404


class TestAuditTrail:
    def test_every_mutation_is_logged_with_its_actor(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        """spec 12 §7 — and §8 requires an entry for every capability change."""
        repo_id = onboard(client, admin_auth).json()["id"]
        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast"]},
            headers=admin_auth,
        )
        client.delete(f"/api/repos/{repo_id}", headers=admin_auth)

        with client.app.state.db.session() as session:
            entries = session.query(AuditLogEntry).order_by(AuditLogEntry.created_at).all()
            actions = [e.action for e in entries]

        assert "repo.onboard" in actions
        assert "repo.capabilities" in actions
        assert "repo.offboard" in actions
        assert all(e.actor for e in entries)

    def test_webhook_driven_changes_are_attributed_to_the_webhook(
        self, client: TestClient
    ) -> None:
        """An audit trail that says 'admin' for something no admin did would
        be worse than no attribution."""
        deliver(client, "installation", installation_payload())

        with client.app.state.db.session() as session:
            entries = session.query(AuditLogEntry).all()

        assert entries
        assert all(e.actor == "github-webhook" for e in entries)


class TestEnablingWithoutInstallingWorkflows:
    """spec 16 §15. A repository scanned by a pipeline Mykronos does not
    install still has to be able to say which capabilities are enabled.

    Before this existed, `enabled_capabilities` moved only when an install PR
    merged — so TheHub, scanned entirely by Concourse, reported findings for
    capabilities its coverage column would never show. The only way to correct
    it was to open a pull request adding the GitHub Actions workflows spec 16
    exists to remove.
    """

    def test_the_enabled_set_moves_without_a_pull_request(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient
    ) -> None:
        before = len(github.pull_request_bodies)

        repo_id = onboard(client, admin_auth).json()["id"]

        response = client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={
                "capabilities": ["sast", "dast", "cloud"],
                "install_workflows": False,
            },
            headers=admin_auth,
        )

        assert response.status_code == 200
        body = response.json()
        assert body["repo"]["enabled_capabilities"] == ["cloud", "dast", "sast"]
        assert body["repo"]["pending_capabilities"] is None
        assert body["pull_request_number"] is None
        assert len(github.pull_request_bodies) == before, "no PR should have been opened"

    def test_grants_are_synced_the_same_way(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient
    ) -> None:
        """The flag changes where workflows come from, not what a capability
        is allowed to write. A repo enabled this way must be able to ingest,
        and must lose the grant when the capability is turned off."""
        repo_id = onboard(client, admin_auth).json()["id"]
        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast", "dast"], "install_workflows": False},
            headers=admin_auth,
        )
        with client.app.state.db.session() as session:
            registry = TokenRegistry(session)
            plaintext = registry.issue(REPO)
        assert client.post(
            "/api/ingest/scan-run",
            json=scan_run_payload(capability="dast"),
            headers={"Authorization": f"Bearer {plaintext}"},
        ).status_code == 200

        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast"], "install_workflows": False},
            headers=admin_auth,
        )
        assert client.post(
            "/api/ingest/scan-run",
            json=scan_run_payload(capability="dast"),
            headers={"Authorization": f"Bearer {plaintext}"},
        ).status_code == 403

    def test_the_default_still_opens_a_pull_request(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient
    ) -> None:
        """The flag is opt-in. Onboarding a repository the normal way must not
        quietly stop installing its workflows."""
        before = len(github.pull_request_bodies)
        repo_id = onboard(client, admin_auth).json()["id"]

        response = client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast", "secrets"]},
            headers=admin_auth,
        )
        assert response.status_code == 200
        assert len(github.pull_request_bodies) > before
        # Still pending: the enabled set moves when the PR merges (spec 03 §3.6).
        assert response.json()["repo"]["pending_capabilities"] == ["sast", "secrets"]
