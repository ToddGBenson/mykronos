"""The flows a person actually performs (PIP-2).

These are chosen for two jobs at once. They assert the application works, and
they are the request corpus ZAP spiders from (PIP-3) — so a flow that is
skipped here is a surface that never gets attacked. Coverage of *paths* is
therefore part of the point, not incidental.
"""

from __future__ import annotations

import pytest

TABS = ["findings", "scan-health", "decisions", "sscs", "insider", "remediation"]


class TestTheGate:
    """The gate is backend middleware, so it is asserted against the API.

    The first draft of this pointed at the frontend and failed: the dashboard
    answers anonymously because it is a rendering layer, and what protects it
    is the tunnel in front and the gated API behind. Asserting the gate where
    it does not live would have been a test that passes once somebody removes
    the gate that does exist.
    """

    def test_the_api_refuses_an_anonymous_caller(self, anonymous_api) -> None:
        response = anonymous_api.get("/api/dashboard/portfolio")

        assert response.status_code == 401

    def test_the_api_refuses_a_wrong_token(self, anonymous_api) -> None:
        response = anonymous_api.get(
            "/api/dashboard/portfolio", headers={"X-Hub-Token": "not-the-token"}
        )

        assert response.status_code == 401

    def test_healthz_stays_open(self, anonymous_api) -> None:
        """Exempt on purpose: a health check that needs a credential cannot be
        used by the thing that restarts the container."""
        assert anonymous_api.get("/healthz").status_code == 200


class TestPortfolio:
    def test_the_landing_page_lists_repositories(self, browser, seeded_repos) -> None:
        response = browser.get("/")

        assert response.status_code == 200
        for repo in seeded_repos:
            assert repo["repo_full_name"] in response.text

    def test_severity_counts_are_rendered(self, browser, seeded_repos) -> None:
        """An empty dashboard would pass every navigation test while showing
        nothing, which is exactly what a DAST scan of an unseeded environment
        reports as secure."""
        response = browser.get("/")

        assert any(word in response.text.lower() for word in ("critical", "high"))


class TestRepositoryDrilldown:
    @pytest.mark.parametrize("tab", TABS)
    def test_every_tab_renders(self, browser, seeded_repos, tab) -> None:
        repo_id = seeded_repos[0]["repo_id"]

        response = browser.get(f"/repos/{repo_id}", params={"tab": tab})

        assert response.status_code == 200

    def test_filtering_findings_by_severity(self, browser, seeded_repos) -> None:
        """A query-parameter path. Worth walking deliberately: parameters are
        where an active scan does most of its work, and a spider that never
        saw one never tests it."""
        repo_id = seeded_repos[0]["repo_id"]

        response = browser.get(
            f"/repos/{repo_id}", params={"tab": "findings", "severity": "critical"}
        )

        assert response.status_code == 200

    def test_every_seeded_repository_opens(self, browser, seeded_repos) -> None:
        for repo in seeded_repos:
            response = browser.get(f"/repos/{repo['repo_id']}")
            assert response.status_code == 200, repo["repo_full_name"]


class TestCrossPortfolioViews:
    @pytest.mark.parametrize("path", ["/triage", "/trends", "/decisions", "/retro"])
    def test_it_renders(self, browser, path) -> None:
        assert browser.get(path).status_code == 200


class TestTheApi:
    """Exercised through the same proxy, so ZAP sees the JSON surface too — it
    is the half an attacker reaches directly rather than through a page."""

    def test_portfolio(self, api) -> None:
        assert api.get("/api/dashboard/portfolio").status_code == 200

    def test_trends(self, api) -> None:
        assert api.get("/api/dashboard/trends").status_code == 200

    def test_maturity(self, api) -> None:
        assert api.get("/api/dashboard/maturity").status_code == 200

    @pytest.mark.parametrize(
        "suffix", ["findings", "scan-health", "insider-risk", "sscs", "ci"]
    )
    def test_per_repo_endpoints(self, api, seeded_repos, suffix) -> None:
        repo_id = seeded_repos[0]["repo_id"]

        assert api.get(f"/api/dashboard/repos/{repo_id}/{suffix}").status_code == 200

    def test_an_unknown_repository_is_a_404_not_a_500(self, api) -> None:
        """The shape of the error matters: a 500 here would be an unhandled
        exception on a caller-supplied identifier, which is the first thing an
        active scan probes for."""
        response = api.get("/api/dashboard/repos/does-not-exist/findings")

        assert response.status_code == 404
