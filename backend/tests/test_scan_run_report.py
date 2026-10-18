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


def _history(client, auth, repo_id, **params):
    return client.get(
        f"/api/dashboard/repos/{repo_id}/scan-runs", params=params, headers=auth
    )


class TestCheckHistory:
    """A check's run history, the list a dashboard tile opens (TheHub #60819)."""

    def test_one_capability_newest_first_with_what_tells_runs_apart(
        self, client, admin_auth, run_compaction
    ) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]
        auth = _auth(client)
        _run(client, auth, run_compaction, "run-1", [A], job="sast-main")
        _run(client, auth, run_compaction, "run-2", [A], minutes=1, job="sast-main")

        body = _history(client, admin_auth, repo_id, capability=CAPABILITY).json()

        assert [r["scan_run_id"] for r in body["runs"]] == ["run-2", "run-1"]
        newest = body["runs"][0]
        assert newest["job"] == "sast-main"
        assert newest["branch"] == "main"
        assert newest["commit_sha"] == "a91f2c7"
        assert newest["commit_url"] == f"https://github.com/{REPO}/commit/a91f2c7"
        assert newest["finding_count"] == 1
        assert newest["started_at"]
        assert "completed_at" in newest
        assert body["has_more"] is False

    def test_an_empty_history_is_an_empty_list_not_an_error(
        self, client, admin_auth
    ) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]

        response = _history(client, admin_auth, repo_id, capability="dast")

        assert response.status_code == 200
        body = response.json()
        assert body["runs"] == []
        assert body["lanes"] == []
        assert body["has_more"] is False

    def test_pages_by_limit_and_offset(self, client, admin_auth, run_compaction) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]
        auth = _auth(client)
        for i in range(3):
            _run(client, auth, run_compaction, f"run-{i}", [], minutes=i)

        first = _history(client, admin_auth, repo_id, capability=CAPABILITY, limit=2).json()
        second = _history(
            client, admin_auth, repo_id, capability=CAPABILITY, limit=2, offset=2
        ).json()

        assert [r["scan_run_id"] for r in first["runs"]] == ["run-2", "run-1"]
        assert first["has_more"] is True
        assert [r["scan_run_id"] for r in second["runs"]] == ["run-0"]
        assert second["has_more"] is False

    def test_a_capability_with_several_jobs_lists_them_and_narrows_by_one(
        self, client, admin_auth, run_compaction
    ) -> None:
        """#449: two jobs of one capability, otherwise identical in the lake."""
        repo_id = onboard(client, admin_auth).json()["id"]
        auth = _auth(client)
        _run(client, auth, run_compaction, "run-demo", [], job="sast-demo")
        _run(client, auth, run_compaction, "run-staging", [], minutes=1, job="sast-staging")

        body = _history(client, admin_auth, repo_id, capability=CAPABILITY).json()
        narrowed = _history(
            client, admin_auth, repo_id, capability=CAPABILITY, job="sast-demo"
        ).json()

        assert [(lane["job"], lane["runs"]) for lane in body["lanes"]] == [
            ("sast-staging", 1),
            ("sast-demo", 1),
        ]
        assert [r["scan_run_id"] for r in narrowed["runs"]] == ["run-demo"]

    def test_a_run_reposted_at_completion_is_listed_once(
        self, client, admin_auth, run_compaction
    ) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]
        auth = _auth(client)
        _run(client, auth, run_compaction, "run-1", [])
        post_scan(
            client, auth, scan_run_id="run-1", started_at=later(0), completed_at=later(1)
        )

        body = _history(client, admin_auth, repo_id, capability=CAPABILITY).json()

        assert [r["scan_run_id"] for r in body["runs"]] == ["run-1"]

    def test_a_commit_that_is_not_a_sha_gets_no_link(
        self, client, admin_auth, run_compaction
    ) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]
        auth = _auth(client)
        _run(client, auth, run_compaction, "run-1", [], commit_sha="HEAD")

        [row] = _history(client, admin_auth, repo_id, capability=CAPABILITY).json()["runs"]

        assert row["commit_url"] is None


JUNIT = b"""<?xml version="1.0"?>
<testsuites>
  <testsuite name="lint-and-types" tests="3" failures="1" errors="0" skipped="1">
    <testcase classname="lint" name="ruff"/>
    <testcase classname="lint" name="mypy">
      <failure message="2 errors">mykronos/x.py:1: error: secret-ish output</failure>
    </testcase>
    <testcase classname="lint" name="openapi"><skipped/></testcase>
  </testsuite>
</testsuites>
"""


class TestTheFullReport:
    def test_the_findings_a_run_reported_by_name_worst_first(
        self, client, admin_auth, run_compaction
    ) -> None:
        onboard(client, admin_auth)
        auth = _auth(client)
        _run(client, auth, run_compaction, "run-1", [A, B])
        _run(client, auth, run_compaction, "run-2", [B, C], minutes=1)

        body = _detail(client, admin_auth, "run-2").json()

        findings = body["findings"]
        assert findings["total"] == 2
        assert findings["truncated"] is False
        assert [(f["rule_id"], f["severity"], f["new"]) for f in findings["items"]] == [
            ("CWE-79", "high", False),
            ("CWE-22", "low", True),
        ]
        assert body["commit_url"] == f"https://github.com/{REPO}/commit/a91f2c7"
        assert body["tests"] is None

    def test_job_and_coverage_are_on_the_report(
        self, client, admin_auth, run_compaction
    ) -> None:
        onboard(client, admin_auth)
        auth = _auth(client)
        _run(
            client,
            auth,
            run_compaction,
            "run-1",
            [],
            job="unit",
            line_coverage=0.81,
            branch_coverage=0.5,
        )

        body = _detail(client, admin_auth, "run-1").json()

        assert body["job"] == "unit"
        assert body["line_coverage"] == 0.81
        assert body["branch_coverage"] == 0.5

    def _junit_run(self, client, admin_auth, run_compaction) -> None:
        onboard(client, admin_auth)
        auth = _auth(client)
        _run(client, auth, run_compaction, "run-1", [])
        response = client.post(
            "/api/ingest/raw",
            params={"scan_run_id": "run-1", "capability": CAPABILITY, "filename": "lint.xml"},
            content=JUNIT,
            headers=auth,
        )
        assert response.status_code == 200

    def test_junit_results_are_read_case_by_case(
        self, client, admin_auth, run_compaction
    ) -> None:
        self._junit_run(client, admin_auth, run_compaction)

        tests = _detail(client, admin_auth, "run-1").json()["tests"]

        assert tests["tests"] == 3
        assert tests["passed"] == 1
        assert tests["failures"] == 1
        assert tests["skipped"] == 1
        assert tests["suites"][0]["name"] == "lint-and-types"
        [failing] = tests["failing"]
        assert failing["name"] == "mypy"
        assert failing["message"] == "2 errors"
        assert "secret-ish output" in failing["output"]
        assert tests["output_withheld"] is False

    def test_a_viewer_gets_the_cases_but_not_the_tool_output(
        self, client, admin_auth, viewer_auth, run_compaction
    ) -> None:
        """spec 12 §5: a failure body is raw tool output."""
        self._junit_run(client, admin_auth, run_compaction)

        tests = _detail(client, viewer_auth, "run-1").json()["tests"]

        [failing] = tests["failing"]
        assert failing["name"] == "mypy"
        assert "output" not in failing
        assert tests["output_withheld"] is True

    def test_an_unparseable_xml_file_is_named_not_fatal(
        self, client, admin_auth, run_compaction
    ) -> None:
        onboard(client, admin_auth)
        auth = _auth(client)
        _run(client, auth, run_compaction, "run-1", [])
        client.post(
            "/api/ingest/raw",
            params={"scan_run_id": "run-1", "capability": CAPABILITY, "filename": "bad.xml"},
            content=b"<testsuite",
            headers=auth,
        )

        response = _detail(client, admin_auth, "run-1")

        assert response.status_code == 200
        assert response.json()["tests"]["unreadable"] == ["bad.xml"]
