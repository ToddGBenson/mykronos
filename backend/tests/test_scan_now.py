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

    def test_enabling_a_test_capability_is_refused_with_no_workflow_template(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        """No unit.yml.j2 exists (spec 18, Test Harness tab), and an
        Actions-scanned repo's install PR is generated from one — so `unit`
        cannot even be *enabled* here today, refused at the same 422 any
        other template-less capability already gets. Dispatch (scan_now)
        never sees this repo's `unit`, because it can never reach
        `enabled_capabilities` in the first place; the Concourse-side
        `test_a_test_capability_dispatches_via_the_job_name_mapping` below is
        the reachable path for these three capabilities today."""
        repo_id = onboard(client, admin_auth).json()["id"]

        response = client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["unit"]},
            headers=admin_auth,
        )

        assert response.status_code == 422
        assert "unit" in response.json()["detail"]


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

    def test_a_test_capability_dispatches_via_the_job_name_mapping(
        self, client: TestClient, admin_auth: dict[str, str], monkeypatch
    ) -> None:
        """`unit` resolves through `_JOBS_BY_CAPABILITY` — the reverse of
        `ci.py`'s `CAPABILITY_BY_JOB`, reused rather than a second mapping
        built just for the Test Harness tab."""
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
            json={"capabilities": ["unit"], "install_workflows": False},
            headers=admin_auth,
        )

        response = client.post(f"/api/repos/{repo_id}/scan", headers=admin_auth)

        assert response.status_code == 200
        body = response.json()
        assert body["dispatched"] == ["unit"]
        assert any(u.endswith("/jobs/unit/builds") for u in posted)

    def test_capabilities_param_scopes_the_dispatch(
        self, client: TestClient, admin_auth: dict[str, str], monkeypatch
    ) -> None:
        """The Test Harness tab's 'run tests' button dispatches unit only,
        not sast alongside it, even though both are enabled."""
        posted: list[str] = []

        class FakeResponse:
            def raise_for_status(self) -> None:
                return None

        monkeypatch.setattr(
            "mykronos.ci.httpx2.post",
            lambda url, headers=None, timeout=0: (posted.append(url), FakeResponse())[1],
        )
        client.app.state.settings.concourse_url = "http://concourse:8080"
        client.app.state.settings.concourse_api_token = "test-token"

        repo_id = onboard(client, admin_auth, scanned_by="concourse").json()["id"]
        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast", "unit"], "install_workflows": False},
            headers=admin_auth,
        )

        response = client.post(
            f"/api/repos/{repo_id}/scan", params={"capabilities": "unit"}, headers=admin_auth
        )

        assert response.status_code == 200
        assert response.json()["dispatched"] == ["unit"]
        assert not any("sast" in u for u in posted)
