"""Dropping an analyser strands the findings only it could see.

B-047 one level down. Removing a *capability* strands its open findings,
because closure needs two consecutive successful scans that no longer observe
the finding and a capability that cannot upload will never produce one.

Removing a *tool* from a capability that still runs is the same dead end.
ShellCheck's findings need ShellCheck's silence, and CodeQL's silence about a
shell script has never been evidence of anything — which is the whole reason
absence reconciliation learned to read `tool_name`.

Before it did, those findings closed on the other tool's silence: tidily, and
wrongly. Now they stay open with no exit, which is honest and useless on its
own. This is the half that makes the removal say what it did.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.conftest import REPO, finding_payload, issue_token, post_findings, post_scan
from tests.test_onboarding import onboard


def scan_with(client: TestClient, token: str, run_id: str, tool: str, findings: list) -> None:
    headers = {"Authorization": f"Bearer {token}"}
    post_scan(
        client,
        headers,
        scan_run_id=run_id,
        capability="sast",
        tool_name=tool,
        branch="main",
        scan_status="success",
    )
    post_findings(client, headers, findings, scan_run_id=run_id, capability="sast")


def statuses(catalog) -> dict[str, str]:
    return {
        str(row[0]): str(row[1])
        for row in catalog.query("SELECT title, status FROM findings")
    }


def set_analysers(client: TestClient, admin_auth, repo_id: int, analysers: list[str]):
    return client.patch(
        f"/api/repos/{repo_id}/capabilities",
        json={
            "capabilities": ["sast"],
            "config": {"sast": {"extra_analysers": analysers}},
        },
        headers=admin_auth,
    )


def seed(client: TestClient, admin_auth, catalog, run_compaction) -> int:
    """A repository with both analysers on, and one finding from each."""
    repo_id = onboard(client, admin_auth).json()["id"]
    assert set_analysers(client, admin_auth, repo_id, ["shellcheck"]).status_code == 200

    token = issue_token(client, REPO, "sast")
    scan_with(
        client,
        token,
        "run-shell-1",
        "shellcheck",
        [finding_payload(title="Shell", rule_id="SC2086", file_path="scripts/deploy.sh")],
    )
    run_compaction()
    scan_with(
        client,
        token,
        "run-codeql-1",
        "codeql",
        [finding_payload(title="Java", rule_id="CWE-89", file_path="orders/query.py")],
    )
    run_compaction()
    return repo_id


class TestDroppingAnAnalyser:
    def test_its_findings_are_stranded(
        self, client, admin_auth, catalog, run_compaction
    ) -> None:
        repo_id = seed(client, admin_auth, catalog, run_compaction)

        set_analysers(client, admin_auth, repo_id, [])

        assert statuses(catalog)["Shell"] == "stranded"

    def test_the_other_tool_keeps_its_own(
        self, client, admin_auth, catalog, run_compaction
    ) -> None:
        """CodeQL is still running. Nothing about its findings changed, and
        stranding them would be a statement about the pipeline that is not
        true of that half of it."""
        repo_id = seed(client, admin_auth, catalog, run_compaction)

        set_analysers(client, admin_auth, repo_id, [])

        assert statuses(catalog)["Java"] == "open"

    def test_the_response_says_what_happened_to_them(
        self, client, admin_auth, catalog, run_compaction
    ) -> None:
        """A number in a log is not the operator finding out. The same
        sentence a capability removal produces, because the reader is being
        told the same thing: this many findings can no longer be closed."""
        repo_id = seed(client, admin_auth, catalog, run_compaction)

        response = set_analysers(client, admin_auth, repo_id, [])

        assert "stranded" in response.json()["detail"]

    def test_the_capability_itself_is_untouched(
        self, client, admin_auth, catalog, run_compaction
    ) -> None:
        """Dropping an analyser is not disabling `sast`. The grant must not
        move, or a configuration change silently stops ingestion."""
        repo_id = seed(client, admin_auth, catalog, run_compaction)

        response = set_analysers(client, admin_auth, repo_id, [])

        assert response.json()["removed"] == []


class TestAddingItBack:
    def test_the_findings_are_open_again(
        self, client, admin_auth, catalog, run_compaction
    ) -> None:
        """Nothing about the finding changed; only whether anything was still
        looking. A repository that toggles an analyser off and on would
        otherwise accumulate a permanent shadow of findings nothing will ever
        examine, and the platform would be quieter for it while being no
        safer."""
        repo_id = seed(client, admin_auth, catalog, run_compaction)
        set_analysers(client, admin_auth, repo_id, [])
        assert statuses(catalog)["Shell"] == "stranded"

        set_analysers(client, admin_auth, repo_id, ["shellcheck"])

        assert statuses(catalog)["Shell"] == "open"


class TestWhatMustNotChange:
    def test_an_unrelated_config_change_strands_nothing(
        self, client, admin_auth, catalog, run_compaction
    ) -> None:
        """An alert about findings nobody can close is worth reading exactly
        because it is rare. Re-saving the same analyser set must produce
        neither a strand nor a sentence."""
        repo_id = seed(client, admin_auth, catalog, run_compaction)

        response = set_analysers(client, admin_auth, repo_id, ["shellcheck"])

        assert statuses(catalog)["Shell"] == "open"
        assert "stranded" not in response.json()["detail"]

    def test_a_repository_that_never_had_analysers_is_unaffected(
        self, client, admin_auth, catalog, run_compaction
    ) -> None:
        """Every repository in this estate today."""
        repo_id = onboard(client, admin_auth).json()["id"]
        token = issue_token(client, REPO, "sast")
        scan_with(client, token, "run-1", "codeql", [finding_payload(title="Injection")])
        run_compaction()

        set_analysers(client, admin_auth, repo_id, [])

        assert statuses(catalog)["Injection"] == "open"
