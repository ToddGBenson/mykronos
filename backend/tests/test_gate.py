"""The perimeter gate.

The exemptions are what these tests are really for. Getting the gate wrong in
the closed direction breaks GitHub silently — a runner gets a 401 it cannot
fix, a webhook delivery fails and GitHub eventually disables the hook — and
none of that surfaces as an error in Mykronos. Getting it wrong in the open
direction puts the dashboard on the internet.
"""

from __future__ import annotations

import hashlib
import hmac
import json

import pytest
from fastapi.testclient import TestClient

from mykronos.config import Settings
from mykronos.gate import TOKEN_COOKIE, TOKEN_HEADER, TOKEN_QUERY
from mykronos.main import create_app
from tests.conftest import (
    ADMIN_TOKEN,
    REPO,
    VIEWER_TOKEN,
    WEBHOOK_SECRET,
    issue_token,
    scan_run_payload,
)

GATE = "hub-token-value"


@pytest.fixture
def gated_settings(tmp_path) -> Settings:
    return Settings(
        datalake_dir=tmp_path / "datalake",
        database_url=f"sqlite:///{(tmp_path / 'g.db').as_posix()}",
        run_compaction_in_background=False,
        run_jobs_in_background=False,
        admin_token=ADMIN_TOKEN,
        viewer_token=VIEWER_TOKEN,
        github_webhook_secret=WEBHOOK_SECRET,
        gate_token=GATE,
    )


@pytest.fixture
def gated(gated_settings):
    with TestClient(create_app(gated_settings)) as client:
        yield client


def gate_header() -> dict[str, str]:
    return {TOKEN_HEADER: GATE}


class TestItBlocks:
    def test_the_dashboard_is_closed_without_the_token(self, gated) -> None:
        response = gated.get(
            "/api/dashboard/portfolio",
            headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        )

        assert response.status_code == 401
        assert response.json()["detail"] == "Not authorised for this host."

    def test_a_wrong_token_is_refused(self, gated) -> None:
        response = gated.get(
            "/api/dashboard/portfolio",
            headers={TOKEN_HEADER: "not-it", "Authorization": f"Bearer {ADMIN_TOKEN}"},
        )

        assert response.status_code == 401

    def test_the_refusal_says_nothing_useful(self, gated) -> None:
        """Identical whether the path exists, the token was absent, or it was
        wrong. A gate that explains itself to an unauthenticated caller is a
        gate that helps them."""
        real = gated.get("/api/dashboard/portfolio")
        fictional = gated.get("/api/does-not-exist")

        assert real.status_code == fictional.status_code == 401
        assert real.json() == fictional.json()

    def test_the_docs_are_closed_too(self, gated) -> None:
        """The OpenAPI schema is a map of every endpoint and its shape."""
        assert gated.get("/openapi.json").status_code == 401


class TestItOpens:
    def test_the_header_works(self, gated) -> None:
        response = gated.get(
            "/api/dashboard/portfolio",
            headers={**gate_header(), "Authorization": f"Bearer {ADMIN_TOKEN}"},
        )

        assert response.status_code == 200

    def test_the_cookie_works(self, gated) -> None:
        gated.cookies.set(TOKEN_COOKIE, GATE)

        response = gated.get(
            "/api/dashboard/portfolio",
            headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        )

        assert response.status_code == 200

    def test_the_query_parameter_sets_a_cookie_and_redirects(self, gated) -> None:
        """So the token stops appearing in the address bar, in history, and in
        any Referer the page goes on to send."""
        response = gated.get(
            f"/api/dashboard/portfolio?{TOKEN_QUERY}={GATE}", follow_redirects=False
        )

        assert response.status_code == 302
        assert TOKEN_QUERY not in response.headers["location"]
        assert TOKEN_COOKIE in response.cookies

    def test_the_cookie_is_httponly(self, gated) -> None:
        """Nothing in this dashboard reads it — every backend call is made
        server-side — so an XSS here cannot walk off with the credential that
        also opens the Hub."""
        response = gated.get(
            f"/api/dashboard/portfolio?{TOKEN_QUERY}={GATE}", follow_redirects=False
        )

        assert "httponly" in response.headers["set-cookie"].lower()


class TestTheExemptions:
    """Paths that carry their own proof. Each of these breaks GitHub silently
    if the gate closes over it."""

    def test_ingestion_is_reachable_with_only_a_repo_token(self, gated) -> None:
        """A runner has one credential and it is not this one. Requiring the
        gate as well would mean a second secret in every repository."""
        auth = {"Authorization": f"Bearer {issue_token(gated, REPO, 'sast')}"}

        response = gated.post(
            "/api/ingest/scan-run", json=scan_run_payload(), headers=auth
        )

        assert response.status_code == 200

    def test_the_ingest_health_probe_is_reachable(self, gated) -> None:
        auth = {"Authorization": f"Bearer {issue_token(gated, REPO, 'sast')}"}

        assert gated.get("/api/ingest/health", headers=auth).status_code == 200

    def test_the_oracle_gate_endpoint_is_reachable(self, gated) -> None:
        auth = {"Authorization": f"Bearer {issue_token(gated, REPO, 'oracle')}"}

        response = gated.post(
            "/api/oracle/evaluate",
            json={"decision_type": "pr_gate", "commit_sha": "abc", "pr_number": 1},
            headers=auth,
        )

        assert response.status_code != 401

    def test_the_patchwork_endpoint_is_reachable(self, gated) -> None:
        auth = {"Authorization": f"Bearer {issue_token(gated, REPO, 'patchwork')}"}

        assert (
            gated.post("/api/patchwork/run", json={}, headers=auth).status_code != 401
        )

    def test_the_webhook_is_reachable(self, gated) -> None:
        """GitHub cannot be given a custom header at all. This endpoint is
        authenticated by HMAC over the body, which is stronger anyway."""
        body = json.dumps({"action": "ignored"}).encode()
        signature = (
            "sha256="
            + hmac.new(WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
        )

        response = gated.post(
            "/webhooks/github",
            content=body,
            headers={
                "X-GitHub-Event": "ping",
                "X-Hub-Signature-256": signature,
                "Content-Type": "application/json",
            },
        )

        assert response.status_code == 200

    def test_liveness_is_reachable(self, gated) -> None:
        assert gated.get("/healthz").status_code == 200

    def test_an_exemption_does_not_leak_to_a_neighbour(self) -> None:
        """`/api/ingest` must not also exempt `/api/ingestion-admin` if
        somebody adds one — which is why the pattern is anchored rather than a
        prefix list."""
        from mykronos.gate import is_exempt

        assert is_exempt("/api/ingest/findings")
        assert not is_exempt("/api/ingestion-admin")
        assert not is_exempt("/api/ingest/../dashboard/portfolio")
        assert not is_exempt("/api/oracle/decisions/abc")
        assert not is_exempt("/webhooks/github/extra")


class TestItIsAPerimeterNotAnAuthorisationModel:
    def test_the_gate_does_not_make_you_an_admin(self, gated) -> None:
        """Collapsing the two layers would make everyone who can reach the
        host an admin."""
        response = gated.get("/api/dashboard/portfolio", headers=gate_header())

        assert response.status_code == 401
        assert "admin token" in response.json()["detail"].lower()

    def test_a_viewer_is_still_a_viewer_behind_the_gate(
        self, gated, run_compaction
    ) -> None:
        response = gated.patch(
            "/api/dashboard/findings/whatever/status",
            json={"status": "false_positive", "reason": "x"},
            headers={**gate_header(), "Authorization": f"Bearer {VIEWER_TOKEN}"},
        )

        assert response.status_code == 403


class TestItIsOffByDefault:
    def test_no_token_means_no_gate(self, client) -> None:
        """Correct on a laptop. Safe because the admin API underneath already
        refuses to serve without its own token."""
        assert (
            client.get(
                "/api/dashboard/portfolio",
                headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
            ).status_code
            == 200
        )
