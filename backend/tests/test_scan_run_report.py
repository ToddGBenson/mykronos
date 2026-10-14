"""One scan run's report and its raw output (TheHub #60761)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.conftest import (
    CAPABILITY,
    REPO,
    finding_payload,
    issue_token,
    later,
    post_findings,
    post_scan,
)
from tests.test_onboarding import onboard

A = finding_payload(rule_id="CWE-89", severity="critical", symbol="a")
B = finding_payload(rule_id="CWE-79", severity="high", symbol="b")
C = finding_payload(rule_id="CWE-22", severity="low", symbol="c")


def _auth(client: TestClient) -> dict[str, str]:
    return {"Authorization": f"Bearer {issue_token(client, REPO, CAPABILITY)}"}


def _run(client, auth, run_compaction, run_id, findings, minutes=0, **scan) -> None:
    post_scan(client, auth, scan_run_id=run_id, started_at=later(minutes), **scan)
    if findings:
        post_findings(client, auth, findings, scan_run_id=run_id)
    run_compaction()


def _detail(client, admin_auth, run_id):
    return client.get(f"/api/dashboard/scan-runs/{run_id}", headers=admin_auth)


class TestChanges:
    def _two_runs(self, client, admin_auth, run_compaction):
        onboard(client, admin_auth)
        auth = _auth(client)
        _run(client, auth, run_compaction, "run-1", [A, B])
        _run(client, auth, run_compaction, "run-2", [B, C], minutes=1)

    def test_the_newest_run_against_the_one_before_it(
        self, client, admin_auth, run_compaction
    ) -> None:
        self._two_runs(client, admin_auth, run_compaction)

        body = _detail(client, admin_auth, "run-2").json()

        assert body["previous_scan_run_id"] == "run-1"
        assert body["next_scan_run_id"] is None
        assert body["exact"] is True
        assert body["observed"] is True
        changes = body["changes"]
        assert changes["new"]["total"] == 1
        assert changes["new"]["by_severity"]["low"] == 1
        assert changes["still_reported"]["total"] == 1
        assert changes["still_reported"]["by_severity"]["high"] == 1
        assert changes["not_reported"]["total"] == 1
        assert changes["not_reported"]["by_severity"]["critical"] == 1
        # One missed scan does not close a finding (spec 05 §5).
        assert changes["not_reported"]["closed"] == 0

    def test_an_older_run_says_its_counts_are_not_exact(
        self, client, admin_auth, run_compaction
    ) -> None:
        self._two_runs(client, admin_auth, run_compaction)

        body = _detail(client, admin_auth, "run-1").json()

        assert body["previous_scan_run_id"] is None
        assert body["next_scan_run_id"] == "run-2"
        assert body["exact"] is False
        assert body["changes"]["new"]["total"] == 2
        assert body["changes"]["not_reported"] is None

    def test_metadata_is_the_runs_own(self, client, admin_auth, run_compaction) -> None:
        self._two_runs(client, admin_auth, run_compaction)

        body = _detail(client, admin_auth, "run-2").json()

        assert body["tool_name"] == "codeql"
        assert body["tool_version"] == "2.19.0"
        assert body["commit_sha"] == "a91f2c7"
        assert body["lane"] == {
            "repo_full_name": REPO,
            "capability": CAPABILITY,
            "branch": "main",
            "tool_name": "codeql",
        }

    def test_another_branch_is_another_lane(
        self, client, admin_auth, run_compaction
    ) -> None:
        """B-056: a `develop` scan is never compared with a `main` scan."""
        onboard(client, admin_auth)
        auth = _auth(client)
        _run(client, auth, run_compaction, "run-main", [A])
        _run(client, auth, run_compaction, "run-dev", [B], minutes=1, branch="develop")

        body = _detail(client, admin_auth, "run-dev").json()

        assert body["previous_scan_run_id"] is None
        assert body["changes"]["not_reported"] is None

    def test_a_failed_run_is_not_evidence_of_absence(
        self, client, admin_auth, run_compaction
    ) -> None:
        onboard(client, admin_auth)
        auth = _auth(client)
        _run(client, auth, run_compaction, "run-1", [A])
        _run(client, auth, run_compaction, "run-2", [], minutes=1, scan_status="failure")

        body = _detail(client, admin_auth, "run-2").json()

        assert body["observed"] is False
        assert body["previous_scan_run_id"] == "run-1"
        assert body["changes"]["not_reported"] is None

    def test_an_unknown_run_is_404(self, client, admin_auth) -> None:
        assert _detail(client, admin_auth, "no-such-run").status_code == 404


class TestRawOutput:
    def _archive(self, client, admin_auth, run_compaction, filename="results.sarif"):
        onboard(client, admin_auth)
        auth = _auth(client)
        _run(client, auth, run_compaction, "run-1", [A])
        response = client.post(
            "/api/ingest/raw",
            params={"scan_run_id": "run-1", "capability": CAPABILITY, "filename": filename},
            content=b'{"version": "2.1.0"}',
            headers=auth,
        )
        assert response.status_code == 200

    def test_the_run_lists_what_ingest_archived(
        self, client, admin_auth, run_compaction
    ) -> None:
        self._archive(client, admin_auth, run_compaction)

        files = _detail(client, admin_auth, "run-1").json()["raw_files"]

        assert files == [{"filename": "results.sarif", "bytes": 20}]

    def test_an_admin_downloads_the_bytes(
        self, client, admin_auth, run_compaction
    ) -> None:
        self._archive(client, admin_auth, run_compaction)

        response = client.get(
            "/api/dashboard/scan-runs/run-1/raw/results.sarif", headers=admin_auth
        )

        assert response.status_code == 200
        assert response.content == b'{"version": "2.1.0"}'
        assert "results.sarif" in response.headers["content-disposition"]

    def test_a_viewer_is_refused(
        self, client, admin_auth, viewer_auth, run_compaction
    ) -> None:
        """spec 12 §5: raw output is withheld from viewers, as the SBOM is."""
        self._archive(client, admin_auth, run_compaction)

        response = client.get(
            "/api/dashboard/scan-runs/run-1/raw/results.sarif", headers=viewer_auth
        )

        assert response.status_code == 403

    def test_an_agent_downloads_it_too(self, client, admin_auth, run_compaction) -> None:
        """`may_see_raw_output` is admin or agent; only viewers are refused."""
        self._archive(client, admin_auth, run_compaction)
        minted = client.post(
            "/api/agents/credentials", json={"family": "claude-opus-5.5"}, headers=admin_auth
        ).json()

        response = client.get(
            "/api/dashboard/scan-runs/run-1/raw/results.sarif",
            headers={"Authorization": f"Bearer {minted['token']}"},
        )

        assert response.status_code == 200, response.text

    def test_a_file_the_run_does_not_list_is_404(
        self, client, admin_auth, run_compaction
    ) -> None:
        self._archive(client, admin_auth, run_compaction)

        for name in ("other.json", "..%2F..%2F_manifest.duckdb", "%2E%2E"):
            response = client.get(
                f"/api/dashboard/scan-runs/run-1/raw/{name}", headers=admin_auth
            )
            assert response.status_code == 404, name

    def test_a_raw_output_ref_outside_the_lake_is_not_listed(
        self, client, admin_auth, run_compaction
    ) -> None:
        onboard(client, admin_auth)
        auth = _auth(client)
        _run(client, auth, run_compaction, "run-1", [], raw_output_ref="../../etc/passwd")

        assert _detail(client, admin_auth, "run-1").json()["raw_files"] == []


class TestDiscovery:
    def test_a_repositorys_runs_newest_first(
        self, client, admin_auth, run_compaction
    ) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]
        auth = _auth(client)
        _run(client, auth, run_compaction, "run-1", [A])
        _run(client, auth, run_compaction, "run-2", [A], minutes=1)

        body = client.get(
            f"/api/dashboard/repos/{repo_id}/scan-runs", headers=admin_auth
        ).json()

        assert [r["scan_run_id"] for r in body["runs"]] == ["run-2", "run-1"]

    def test_scan_health_names_the_latest_run(
        self, client, admin_auth, run_compaction
    ) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]
        auth = _auth(client)
        _run(client, auth, run_compaction, "run-1", [A])
        _run(client, auth, run_compaction, "run-2", [A], minutes=1)

        body = client.get(
            f"/api/dashboard/repos/{repo_id}/scan-health", headers=admin_auth
        ).json()

        [row] = [c for c in body["capabilities"] if c["capability"] == CAPABILITY]
        assert row["last_scan_run_id"] == "run-2"
