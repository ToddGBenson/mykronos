"""i2i grooming API — spec 17 §7.2."""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.conftest import REPO, finding_payload, issue_token, post_findings, post_scan
from tests.test_onboarding import onboard


def _seed_finding(client, admin_auth, run_compaction, **overrides):
    repo_id = onboard(client, admin_auth).json()["id"]
    client.patch(
        f"/api/repos/{repo_id}/capabilities",
        json={"capabilities": ["sast"]},
        headers=admin_auth,
    )
    token = issue_token(client, REPO, "sast")
    auth = {"Authorization": f"Bearer {token}"}
    post_scan(client, auth, scan_run_id="run-groom")
    post_findings(client, auth, [finding_payload(**overrides)], scan_run_id="run-groom")
    run_compaction()

    findings = client.get(f"/api/dashboard/repos/{repo_id}/findings", headers=admin_auth).json()
    return repo_id, findings["findings"][0]["finding_id"]


class TestGroomFinding:
    def test_opens_an_issue(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction
    ) -> None:
        _repo_id, finding_id = _seed_finding(client, admin_auth, run_compaction)

        response = client.post(f"/api/triage/{finding_id}/groom", headers=admin_auth)

        assert response.status_code == 200
        body = response.json()
        assert body["created"] is True
        assert body["dev_ready"] is True
        assert body["missing_fields"] == []
        assert body["github_issue_number"] == 1
        assert body["github_issue_url"].endswith(f"/{REPO}/issues/1")

        fake = client.app.state.github_factory.client
        issue = fake.repos[REPO].issues[0]
        # Plus a severity-derived priority label (spec 19 §4.3) — asserted
        # by membership so adding one does not break every groom test.
        assert "mykronos:dev-ready" in issue["labels"]
        assert "SQL injection" in issue["title"] or "CWE-89" in issue["title"]
        assert "## Acceptance criteria" in issue["body"]

    def test_re_grooming_updates_rather_than_duplicates(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction
    ) -> None:
        _repo_id, finding_id = _seed_finding(client, admin_auth, run_compaction)

        first = client.post(f"/api/triage/{finding_id}/groom", headers=admin_auth).json()
        second = client.post(f"/api/triage/{finding_id}/groom", headers=admin_auth).json()

        assert first["created"] is True
        assert second["created"] is False
        assert first["github_issue_number"] == second["github_issue_number"]

        fake = client.app.state.github_factory.client
        assert len(fake.repos[REPO].issues) == 1

    def test_the_story_id_is_stable_across_grooms(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction
    ) -> None:
        _repo_id, finding_id = _seed_finding(client, admin_auth, run_compaction)
        first = client.post(f"/api/triage/{finding_id}/groom", headers=admin_auth).json()
        second = client.post(f"/api/triage/{finding_id}/groom", headers=admin_auth).json()
        assert first["story_id"] == second["story_id"]

    def test_an_unknown_finding_is_404(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        assert client.post("/api/triage/nope/groom", headers=admin_auth).status_code == 404

    def test_a_viewer_cannot_groom(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        viewer_auth: dict[str, str],
        run_compaction,
    ) -> None:
        _repo_id, finding_id = _seed_finding(client, admin_auth, run_compaction)
        response = client.post(f"/api/triage/{finding_id}/groom", headers=viewer_auth)
        assert response.status_code == 403

    def test_a_repo_with_no_github_app_installation_is_409(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction
    ) -> None:
        """Findings live in the lake independently of the operational
        database. Renaming the onboarding row's repo name (rather than
        deleting it, which cascades into a foreign-key-constrained
        CapabilityConfig row) makes `_github_for`'s lookup find nothing for
        the finding's actual repo — reproducing "there is no installation
        to open an issue with" without touching the lake."""
        from sqlalchemy import select

        from mykronos.db.models import RepoOnboarding

        _repo_id, finding_id = _seed_finding(client, admin_auth, run_compaction)
        with client.app.state.db.session() as session:
            row = session.execute(
                select(RepoOnboarding).where(RepoOnboarding.github_repo_full_name == REPO)
            ).scalar_one()
            row.github_repo_full_name = "example-org/renamed-elsewhere"

        response = client.post(f"/api/triage/{finding_id}/groom", headers=admin_auth)
        assert response.status_code == 409

    def test_the_audit_log_records_the_groom(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction
    ) -> None:
        from sqlalchemy import select

        from mykronos.db.models import AuditLogEntry

        _repo_id, finding_id = _seed_finding(client, admin_auth, run_compaction)
        client.post(f"/api/triage/{finding_id}/groom", headers=admin_auth)

        with client.app.state.db.session() as session:
            entries = session.execute(
                select(AuditLogEntry).where(AuditLogEntry.action == "triage.groom")
            ).scalars().all()
        assert len(entries) == 1
        assert entries[0].detail["created"] is True


class TestGroomCombination:
    def _seed_combination(self, client, admin_auth, run_compaction):
        repo_id = onboard(client, admin_auth).json()["id"]
        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast"]},
            headers=admin_auth,
        )
        token = issue_token(client, REPO, "sast")
        auth = {"Authorization": f"Bearer {token}"}
        post_scan(client, auth, scan_run_id="run-combo")
        post_findings(
            client,
            auth,
            [
                finding_payload(
                    rule_id="CWE-89",
                    title="SQL injection via string concatenation",
                    severity="high",
                    symbol="a",
                    file_path="a.py",
                ),
                finding_payload(
                    rule_id="CWE-306",
                    title="Missing authentication check",
                    severity="medium",
                    symbol="b",
                    file_path="a.py",
                ),
            ],
            scan_run_id="run-combo",
        )
        run_compaction()
        return repo_id

    def _combination_id(self, client, admin_auth, repo_id):
        page = client.get(
            f"/api/dashboard/repos/{repo_id}/open-findings", headers=admin_auth
        ).json()
        return page["toxic_combinations"][0]["combination_id"]

    def test_opens_an_issue_naming_every_member(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction
    ) -> None:
        repo_id = self._seed_combination(client, admin_auth, run_compaction)
        combination_id = self._combination_id(client, admin_auth, repo_id)

        response = client.post(
            f"/api/triage/repos/{repo_id}/combinations/{combination_id}/groom",
            headers=admin_auth,
        )

        assert response.status_code == 200
        body = response.json()
        assert body["created"] is True

        fake = client.app.state.github_factory.client
        issue = fake.repos[REPO].issues[0]
        assert "Unauthenticated injectable endpoint" in issue["title"]
        assert body["dev_ready"] is True  # two members, two acceptance criteria

    def test_an_unknown_combination_is_404(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction
    ) -> None:
        repo_id = self._seed_combination(client, admin_auth, run_compaction)
        response = client.post(
            f"/api/triage/repos/{repo_id}/combinations/does-not-exist/groom",
            headers=admin_auth,
        )
        assert response.status_code == 404

    def test_an_unknown_repo_is_404(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        response = client.post(
            "/api/triage/repos/nope/combinations/whatever/groom", headers=admin_auth
        )
        assert response.status_code == 404
