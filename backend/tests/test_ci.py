"""Reading Concourse back (spec 15 §4a).

The failure this guards against is not a wrong link. It is a panel that says
nothing when Concourse is down and says the same nothing when a repository has
no pipeline — because then nobody can tell "we do not scan this here" from "the
CI server is restarting", and a panel that cannot distinguish those gets
ignored.
"""

from __future__ import annotations

import json

import pytest

from mykronos.ci import ConcourseClient, pipeline_name_for


class FakeResponse:
    def __init__(self, payload: object, status: int = 200) -> None:
        self._payload = payload
        self.status = status

    def raise_for_status(self) -> None:
        if self.status >= 400:
            raise RuntimeError(f"HTTP {self.status}")

    def json(self) -> object:
        return json.loads(json.dumps(self._payload))


@pytest.fixture
def concourse(monkeypatch):
    """A ConcourseClient wired to a scripted API, keyed by path suffix."""

    routes: dict[str, object] = {}

    def fake_get(url: str, timeout: float = 0) -> FakeResponse:
        for suffix, payload in routes.items():
            if url.endswith(suffix):
                if isinstance(payload, Exception):
                    raise payload
                return FakeResponse(payload)
        return FakeResponse(None, status=404)

    monkeypatch.setattr("mykronos.ci.httpx2.get", fake_get)
    client = ConcourseClient(
        "http://concourse:8080", team="main", external_url="http://localhost:8080"
    )
    return client, routes


JOBS = [
    {
        "name": "unit",
        "finished_build": {
            "name": "8",
            "status": "succeeded",
            "end_time": 1786602220,
        },
    },
    {
        "name": "sast",
        "finished_build": {"name": "5", "status": "failed", "end_time": 1786602300},
    },
    {"name": "deploy"},
]


class TestPipelineNaming:
    def test_the_pipeline_is_the_repo_name_lowercased(self) -> None:
        assert pipeline_name_for("ToddGBenson/TheHub") == "thehub"
        assert pipeline_name_for("ToddGBenson/mykronos") == "mykronos"
        assert pipeline_name_for("ToddGBenson/personal-soc") == "personal-soc"


class TestStatus:
    def test_jobs_carry_a_link_to_their_last_build(self, concourse) -> None:
        client, routes = concourse
        routes["/api/v1/pipelines"] = [{"name": "mykronos"}]
        routes["/pipelines/mykronos/jobs"] = JOBS

        status = client.status_for("ToddGBenson/mykronos")

        assert status.pipeline == "mykronos"
        assert status.url == "http://localhost:8080/teams/main/pipelines/mykronos"
        unit = status.jobs[0]
        assert unit.status == "succeeded"
        assert unit.build_url == (
            "http://localhost:8080/teams/main/pipelines/mykronos/jobs/unit/builds/8"
        )

    def test_the_link_uses_the_browser_url_not_the_internal_one(
        self, concourse
    ) -> None:
        """These genuinely differ: this process reaches Concourse by container
        name on a shared network, and a person reaches it on localhost. A link
        to http://concourse:8080 resolves nowhere from a laptop."""
        client, routes = concourse
        routes["/api/v1/pipelines"] = [{"name": "mykronos"}]
        routes["/pipelines/mykronos/jobs"] = JOBS

        status = client.status_for("ToddGBenson/mykronos")

        assert "concourse:8080" not in (status.url or "")

    def test_failing_jobs_are_named(self, concourse) -> None:
        client, routes = concourse
        routes["/api/v1/pipelines"] = [{"name": "mykronos"}]
        routes["/pipelines/mykronos/jobs"] = JOBS

        assert client.status_for("ToddGBenson/mykronos").failing == ["sast"]

    def test_a_job_that_never_ran_is_neither_pass_nor_fail(self, concourse) -> None:
        client, routes = concourse
        routes["/api/v1/pipelines"] = [{"name": "mykronos"}]
        routes["/pipelines/mykronos/jobs"] = JOBS

        deploy = client.status_for("ToddGBenson/mykronos").jobs[2]

        assert deploy.status is None
        assert deploy.build_url is None

    def test_a_repo_with_no_pipeline_says_which_ci_does_scan_it(
        self, concourse
    ) -> None:
        """keel is in exactly this state: onboarded, scanned by Actions, and
        absent from Concourse. An empty panel would read as a coverage gap."""
        client, routes = concourse
        routes["/api/v1/pipelines"] = [{"name": "mykronos"}]

        status = client.status_for("ToddGBenson/keel")

        assert status.pipeline is None
        assert "No Concourse pipeline named 'keel'" in (status.unavailable or "")
        assert "GitHub Actions" in (status.unavailable or "")

    def test_an_unreachable_concourse_is_a_different_answer(self, concourse) -> None:
        """The distinction this whole module exists to preserve."""
        client, routes = concourse
        routes["/api/v1/pipelines"] = RuntimeError("connection refused")

        status = client.status_for("ToddGBenson/keel")

        assert "did not answer" in (status.unavailable or "")
        assert "No Concourse pipeline" not in (status.unavailable or "")

    def test_an_unreachable_concourse_never_raises(self, concourse) -> None:
        """A page about findings must not fail because a CI server restarted."""
        client, routes = concourse
        routes["/api/v1/pipelines"] = [{"name": "mykronos"}]
        routes["/pipelines/mykronos/jobs"] = TimeoutError("timed out")

        status = client.status_for("ToddGBenson/mykronos")

        assert status.pipeline == "mykronos"
        assert status.jobs == []
        assert status.unavailable is not None

    def test_no_concourse_configured_is_not_an_error(self) -> None:
        status = ConcourseClient("").status_for("ToddGBenson/mykronos")

        assert status.unavailable == "No Concourse is configured for this deployment."


class TestTheEndpoint:
    def test_it_always_links_to_github(self, client, admin_auth) -> None:
        """Even with no Concourse at all: the repository still exists and the
        page is still the place somebody looks for it."""
        from tests.test_onboarding import onboard

        onboard(client, admin_auth)
        repo = client.get("/api/dashboard/portfolio", headers=admin_auth).json()["repos"][0]

        page = client.get(
            f"/api/dashboard/repos/{repo['repo_id']}/ci", headers=admin_auth
        ).json()

        assert page["github_url"] == f"https://github.com/{page['repo_full_name']}"
        assert page["github_actions_url"].endswith("/actions")
        assert page["pipeline"] is None
        assert page["unavailable"]
