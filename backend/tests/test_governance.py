"""The spec 06 §9 access rule, tested as a requirement.

Insider-risk detail is admin-only. Not "hidden from the viewer UI" — withheld
at the query layer, on the same principle as raw tool output: "not rendered" is
not "not sent", and a dashboard bug should not be able to leak a colleague's
risk breakdown.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tests.conftest import REPO, issue_token
from tests.test_onboarding import onboard


@pytest.fixture
def aegis_auth(client: TestClient) -> dict[str, str]:
    return {"Authorization": f"Bearer {issue_token(client, REPO, 'aegis')}"}


@pytest.fixture
def scored(client, admin_auth, aegis_auth, run_compaction) -> str:
    repo_id = onboard(client, admin_auth).json()["id"]
    client.post(
        "/api/ingest/aegis",
        json={
            "pr_number": 2841,
            "commit_sha": "a91f2c7",
            "author_login": "octocat",
            "signals": [
                {
                    "key": "sensitive_path",
                    "score": 30,
                    "rationale": "modifies auth/session.py",
                }
            ],
        },
        headers=aegis_auth,
    )
    run_compaction()
    return repo_id


class TestInsiderRiskAccess:
    def test_an_admin_sees_the_detail(self, client, admin_auth, scored) -> None:
        body = client.get(
            f"/api/dashboard/repos/{scored}/insider-risk", headers=admin_auth
        ).json()

        assert body["detail_included"] is True
        signal = body["signals"][0]
        assert signal["author_login"] == "octocat"
        assert signal["signal_breakdown"]["signals"][0]["rationale"]

    def test_a_viewer_does_not(self, client, viewer_auth, scored) -> None:
        body = client.get(
            f"/api/dashboard/repos/{scored}/insider-risk", headers=viewer_auth
        ).json()

        assert body["detail_included"] is False
        signal = body["signals"][0]
        assert signal["author_login"] is None
        assert signal["signal_breakdown"] is None

    def test_a_viewer_still_sees_the_verdict(self, client, viewer_auth, scored) -> None:
        """Withholding this too would be theatre: anyone who can see the
        repository can already read the Check Run."""
        body = client.get(
            f"/api/dashboard/repos/{scored}/insider-risk", headers=viewer_auth
        ).json()

        signal = body["signals"][0]
        assert signal["insider_risk_score"] == 30
        assert signal["recommendation"] == "pass"
        assert signal["pr_number"] == 2841

    def test_the_withheld_fields_are_null_not_absent(
        self, client, viewer_auth, scored
    ) -> None:
        """A stable key shape, so a caller never has to guess whether a field
        is missing because it was withheld or because nothing recorded it."""
        signal = client.get(
            f"/api/dashboard/repos/{scored}/insider-risk", headers=viewer_auth
        ).json()["signals"][0]

        assert "author_login" in signal
        assert "signal_breakdown" in signal

    def test_it_needs_authentication(self, client, scored) -> None:
        assert (
            client.get(f"/api/dashboard/repos/{scored}/insider-risk").status_code == 401
        )

    def test_the_governance_note_travels_with_the_data(
        self, client, admin_auth, scored
    ) -> None:
        """A consumer should not have to read spec 06 §9 to learn these rows are
        not a per-person rating."""
        body = client.get(
            f"/api/dashboard/repos/{scored}/insider-risk", headers=admin_auth
        ).json()

        assert "not a per-person" in body["governance"] or "not a rating" in (
            body["governance"]
        )

    def test_there_is_no_per_author_endpoint(self, client, admin_auth, scored) -> None:
        """spec 06 §9 forbids aggregating or ranking individuals, and the way to
        keep that true is for the query not to exist. If someone adds one, this
        test is where the conversation should happen."""
        paths = [
            route.path
            for route in client.app.routes
            if hasattr(route, "path")
        ]

        assert not [p for p in paths if "author" in p.lower()]
        assert not [p for p in paths if "contributor" in p.lower()]


class TestSscsEvidence:
    @pytest.fixture
    def evidenced(self, client, admin_auth, run_compaction) -> str:
        repo_id = onboard(client, admin_auth).json()["id"]
        auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'atlas')}"}
        client.post(
            "/api/ingest/atlas",
            json={
                "commit_sha": "a91f2c7",
                "tag_or_release": "v2.1.0",
                "sbom_ref": "raw/example-org/payments-api/9900/sbom.json",
                "ecosystems": [
                    {
                        "ecosystem": "npm",
                        "dependency_count": 214,
                        "critical_vulns": 2,
                        "high_vulns": 5,
                    }
                ],
                "provenance": {"builder_id": "github-actions", "build_run_id": "9900"},
            },
            headers=auth,
        )
        run_compaction()
        return repo_id

    def test_evidence_is_served(self, client, admin_auth, evidenced) -> None:
        body = client.get(
            f"/api/dashboard/repos/{evidenced}/sscs", headers=admin_auth
        ).json()

        assert body["latest"]["tag_or_release"] == "v2.1.0"
        assert body["latest"]["dependency_count"] == 214
        assert body["latest"]["trust_score"] < 100

    def test_the_sbom_reference_is_exposed(self, client, admin_auth, evidenced) -> None:
        """spec 10 §9 wants a download link, which needs the ref."""
        body = client.get(
            f"/api/dashboard/repos/{evidenced}/sscs", headers=admin_auth
        ).json()

        assert body["latest"]["sbom_ref"].endswith("sbom.json")

    def test_the_arithmetic_travels_with_the_evidence(
        self, client, admin_auth, evidenced
    ) -> None:
        body = client.get(
            f"/api/dashboard/repos/{evidenced}/sscs", headers=admin_auth
        ).json()

        assert body["latest"]["ecosystems_json"]["score_terms"]
        assert body["latest"]["provenance_json"]["builder_id"] == "github-actions"

    def test_a_viewer_may_read_it(self, client, viewer_auth, evidenced) -> None:
        """Supply-chain evidence is about packages, not people. There is no
        reason to restrict it and restricting it would just make the trend
        invisible to the people who need it."""
        response = client.get(
            f"/api/dashboard/repos/{evidenced}/sscs", headers=viewer_auth
        )

        assert response.status_code == 200
        assert response.json()["latest"]["trust_score"] < 100

    def test_a_repo_with_no_evidence_is_not_an_error(
        self, client, admin_auth
    ) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]

        body = client.get(
            f"/api/dashboard/repos/{repo_id}/sscs", headers=admin_auth
        ).json()

        assert body["evidence"] == []
        assert body["latest"] is None

    def test_an_unknown_repo_is_404(self, client, admin_auth) -> None:
        assert (
            client.get(
                "/api/dashboard/repos/nope/sscs", headers=admin_auth
            ).status_code
            == 404
        )
