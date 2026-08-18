"""On-demand scan dispatch — spec 17 §2.5."""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.conftest import REPO
from tests.test_onboarding import deliver, onboard


class TestGitHubActionsDispatch:
    def test_a_pending_capability_is_blocked(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        """Nothing has merged yet — there is no workflow file to dispatch."""
        repo_id = onboard(client, admin_auth).json()["id"]
        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast"]},
            headers=admin_auth,
        )

        response = client.post(f"/api/repos/{repo_id}/scan", headers=admin_auth)

        assert response.status_code == 409
        assert "sast" in response.json()["detail"]

    def test_an_enabled_capability_dispatches(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
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
                    "head": {"ref": "mykronos/enable-workflows-20260808T000000"},
                },
                "repository": {"full_name": REPO},
            },
        )

        response = client.post(f"/api/repos/{repo_id}/scan", headers=admin_auth)

        assert response.status_code == 200
        body = response.json()
        assert body["dispatched"] == ["sast"]
        assert body["failed"] == []

        fake = client.app.state.github_factory.client
        assert fake.repos[REPO].dispatched_workflows == [
            {"workflow_file": "mykronos-sast.yml", "ref": "main", "inputs": {}}
        ]

    def test_no_capability_enabled_is_not_an_error(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]

        response = client.post(f"/api/repos/{repo_id}/scan", headers=admin_auth)

        assert response.status_code == 200
        body = response.json()
        assert body["dispatched"] == []
        assert body["failed"] == []
        assert "No scanning capability" in body["detail"]

    def test_an_offboarded_repo_is_409(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]
        client.delete(f"/api/repos/{repo_id}", headers=admin_auth)

        response = client.post(f"/api/repos/{repo_id}/scan", headers=admin_auth)
        assert response.status_code == 409

    def test_an_unknown_repo_is_404(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        assert client.post("/api/repos/nope/scan", headers=admin_auth).status_code == 404

    def test_a_viewer_cannot_trigger_a_scan(
        self, client: TestClient, admin_auth: dict[str, str], viewer_auth: dict[str, str]
    ) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]
        assert client.post(f"/api/repos/{repo_id}/scan", headers=viewer_auth).status_code == 403


class TestConcourseDispatch:
    def test_no_token_configured_is_503(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        repo_id = onboard(client, admin_auth, scanned_by="concourse").json()["id"]
        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast"], "install_workflows": False},
            headers=admin_auth,
        )
        # No `concourse_url`/`concourse_api_token` on the test `settings`
        # fixture by default (spec 15 §4a's own "no Concourse configured").

        response = client.post(f"/api/repos/{repo_id}/scan", headers=admin_auth)
        assert response.status_code == 503

    def test_a_granted_capability_dispatches(
        self, client: TestClient, admin_auth: dict[str, str], monkeypatch
    ) -> None:
        posted: list[str] = []

        class FakeResponse:
            def raise_for_status(self) -> None:
                return None

        def fake_post(url: str, headers=None, timeout: float = 0):
            posted.append(url)
            return FakeResponse()

        monkeypatch.setattr("mykronos.ci.httpx2.post", fake_post)
        client.app.state.settings.concourse_url = "http://concourse:8080"
        client.app.state.settings.concourse_api_token = "test-token"

        repo_id = onboard(client, admin_auth, scanned_by="concourse").json()["id"]
        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast"], "install_workflows": False},
            headers=admin_auth,
        )

        response = client.post(f"/api/repos/{repo_id}/scan", headers=admin_auth)

        assert response.status_code == 200
        body = response.json()
        assert body["dispatched"] == ["sast"]
        assert any(u.endswith("/pipelines/payments-api/jobs/sast/builds") for u in posted)

    def test_a_job_concourse_rejects_is_reported_as_failed(
        self, client: TestClient, admin_auth: dict[str, str], monkeypatch
    ) -> None:
        class FakeResponse:
            def raise_for_status(self) -> None:
                raise RuntimeError("HTTP 404")

        monkeypatch.setattr(
            "mykronos.ci.httpx2.post", lambda url, headers=None, timeout=0: FakeResponse()
        )
        client.app.state.settings.concourse_url = "http://concourse:8080"
        client.app.state.settings.concourse_api_token = "test-token"

        repo_id = onboard(client, admin_auth, scanned_by="concourse").json()["id"]
        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast"], "install_workflows": False},
            headers=admin_auth,
        )

        body = client.post(f"/api/repos/{repo_id}/scan", headers=admin_auth).json()
        assert body["dispatched"] == []
        assert body["failed"] == ["sast"]
