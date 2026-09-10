"""A finding closes on evidence from a tool that could have seen it.

This is B-056's defect one dimension over. Absence reconciliation learned to
read `branch` because two `main` scans were closing findings that only ever
existed on `develop`. It still could not read `tool_name`, and that did not
matter while every capability had exactly one tool.

It stopped being true on 2026-09-09. `extra_analysers` puts ShellCheck or
PSScriptAnalyzer on the same `sast` capability as CodeQL, deliberately —
CodeQL implements no shell language, so running the two *alongside* each other
is the entire point (B-051). Two lanes, one capability.

Reconciliation partitions on `(repo, capability, branch)`. So two CodeQL runs
are two qualifying `sast` scans, and every ShellCheck finding is absent from
both — because CodeQL cannot see shell and never could. They are closed as
fixed.

That is the reassuring direction, which is the worse one. A shell injection
found by ShellCheck disappears from the queue because a Java scanner ran
twice, `resolved_at` is written, mean-time-to-fix improves, and nothing
anywhere says a tool was never asked.

**Latent rather than live.** Neither analyser is enabled on any repository
yet, so no lane in this estate has two tools today. It fires on the day
somebody does what B-051 asks and enables ShellCheck on `keel` — which is why
it is worth finding now rather than from the first closed finding nobody
fixed.
"""

from __future__ import annotations

from mykronos.lake import reconcile_absences
from tests.conftest import REPO, finding_payload, issue_token, post_findings, post_scan


def scan(
    client,
    token: str,
    run_id: str,
    tool: str,
    findings: list | None = None,
    *,
    branch: str = "main",
    capability: str = "sast",
) -> None:
    headers = {"Authorization": f"Bearer {token}"}
    post_scan(
        client,
        headers,
        scan_run_id=run_id,
        capability=capability,
        tool_name=tool,
        branch=branch,
        scan_status="success",
    )
    post_findings(
        client, headers, findings or [], scan_run_id=run_id, capability=capability
    )


def statuses(catalog) -> dict[str, str]:
    return {
        str(row[0]): str(row[1])
        for row in catalog.query("SELECT title, status FROM findings")
    }


class TestOneToolDoesNotCloseAnother:
    def test_two_codeql_runs_do_not_close_a_shellcheck_finding(
        self, client, catalog, run_compaction
    ) -> None:
        """The whole bug, in the shape it will arrive in.

        CodeQL implements no shell language. Its silence about a shell finding
        is not evidence, and treating it as evidence closes a real problem
        because an unrelated scanner ran.
        """
        token = issue_token(client, REPO, "sast")
        scan(
            client,
            token,
            "run-shell-1",
            "shellcheck",
            [finding_payload(title="Unquoted variable in deploy.sh")],
        )
        run_compaction()

        scan(client, token, "run-codeql-1", "codeql", [])
        run_compaction()
        scan(client, token, "run-codeql-2", "codeql", [])
        run_compaction()

        reconcile_absences(catalog)

        assert statuses(catalog)["Unquoted variable in deploy.sh"] == "open"

    def test_the_tool_that_found_it_can_still_close_it(
        self, client, catalog, run_compaction
    ) -> None:
        """The other half, and the one that must keep working. Scoping by tool
        is worthless if it means nothing ever closes."""
        token = issue_token(client, REPO, "sast")
        scan(
            client,
            token,
            "run-shell-1",
            "shellcheck",
            [finding_payload(title="Unquoted variable in deploy.sh")],
        )
        run_compaction()

        scan(client, token, "run-shell-2", "shellcheck", [])
        run_compaction()
        scan(client, token, "run-shell-3", "shellcheck", [])
        run_compaction()

        reconcile_absences(catalog)

        assert statuses(catalog)["Unquoted variable in deploy.sh"] == "fixed"

    def test_one_run_of_the_right_tool_is_still_not_enough(
        self, client, catalog, run_compaction
    ) -> None:
        """The two-scan rule survives the change.

        Interleaved lanes were the quieter half of this bug: with both tools
        reporting on every push, the two most recent `sast` runs are one of
        each, so a finding one push old was absent from "two consecutive
        scans" after a single push. The guarantee degraded from two to one
        without anything appearing to change.
        """
        token = issue_token(client, REPO, "sast")
        scan(
            client,
            token,
            "run-shell-1",
            "shellcheck",
            [finding_payload(title="Unquoted variable in deploy.sh")],
        )
        run_compaction()

        scan(client, token, "run-codeql-1", "codeql", [])
        run_compaction()
        scan(client, token, "run-shell-2", "shellcheck", [])
        run_compaction()

        reconcile_absences(catalog)

        assert statuses(catalog)["Unquoted variable in deploy.sh"] == "open"

    def test_each_tool_closes_only_its_own(
        self, client, catalog, run_compaction
    ) -> None:
        """Both lanes working at once, which is the state B-051 is asking for.
        Each finding answers to the tool that found it and to no other."""
        token = issue_token(client, REPO, "sast")
        # Distinct `rule_id` and `file_path`, because the finding id is a
        # fingerprint of those rather than of the title — two findings that
        # differ only by title are one finding, which would make this test
        # pass for the wrong reason.
        shell = finding_payload(
            title="Shell", rule_id="SC2086", file_path="scripts/deploy.sh"
        )
        java = finding_payload(
            title="Java", rule_id="CWE-89", file_path="orders/query.py"
        )
        scan(client, token, "run-shell-1", "shellcheck", [shell])
        run_compaction()
        scan(client, token, "run-codeql-1", "codeql", [java])
        run_compaction()

        # Two more ShellCheck runs, silent. CodeQL has run once and says
        # nothing more.
        scan(client, token, "run-shell-2", "shellcheck", [])
        run_compaction()
        scan(client, token, "run-shell-3", "shellcheck", [])
        run_compaction()

        reconcile_absences(catalog)

        current = statuses(catalog)
        assert current["Shell"] == "fixed"
        assert current["Java"] == "open"


class TestTheSingleToolCaseIsUnchanged:
    def test_two_runs_of_the_only_tool_still_close_a_finding(
        self, client, catalog, run_compaction
    ) -> None:
        """Every repository in this estate today. Nothing about reading one
        more column may change what a single-tool lane does."""
        token = issue_token(client, REPO, "sast")
        scan(client, token, "run-1", "codeql", [finding_payload(title="Injection")])
        run_compaction()
        scan(client, token, "run-2", "codeql", [])
        run_compaction()
        scan(client, token, "run-3", "codeql", [])
        run_compaction()

        reconcile_absences(catalog)

        assert statuses(catalog)["Injection"] == "fixed"
