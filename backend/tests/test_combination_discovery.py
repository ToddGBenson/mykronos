"""Candidate toxic combinations — spec 19 §2.2.

The nine rules in `correlate.py` are hand-written and always will be. What was
missing is a way to *notice* a pattern worth writing one for, which today
depends on somebody happening to see the same pairing twice.

The load-bearing property is what this does not do: it writes nothing to
`correlate.py`, proposes no rule text, and stops at a section of the retro
report. The machine surfaces, the human decides — the same division spec 11's
promotion candidates already draw.
"""

from __future__ import annotations

import pytest

from mykronos.knowledge.reports import build_retro, render_retro_markdown
from mykronos.patchwork import correlate, discovery
from tests.conftest import REPO, finding_payload, issue_token, post_findings, post_scan
from tests.test_onboarding import onboard


def finding(capability, rule_id, path, *, severity="high"):
    return finding_payload(
        rule_id=rule_id, severity=severity, file_path=path, title=rule_id
    )


@pytest.fixture
def seed(client, admin_auth, run_compaction):
    """Ingest findings under a named capability, enabling it first."""
    enabled: set[str] = set()

    def write(capability, findings, *, run_id=None):
        repo_id = onboard(client, admin_auth).json()["id"]
        enabled.add(capability)
        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": sorted(enabled), "install_workflows": False},
            headers=admin_auth,
        )
        auth = {"Authorization": f"Bearer {issue_token(client, REPO, capability)}"}
        run = run_id or f"run-{capability}"
        post_scan(client, auth, scan_run_id=run, capability=capability)
        response = post_findings(
            client, auth, findings, scan_run_id=run, capability=capability
        )
        assert response.status_code < 300, response.text
        run_compaction()

    return write


class TestWhatCounts:
    def test_an_uncovered_pair_in_enough_files_is_a_candidate(
        self, catalog, seed
    ) -> None:
        """`sast` + `iac` — a real gap. No `CombinationRule` pairs them, and
        "insecure code in a file that also provisions infrastructure" is
        exactly the shape somebody might want a rule for."""
        paths = [f"src/module_{i}.py" for i in range(3)]
        seed("sast", [finding("sast", "CWE-89", p) for p in paths])
        seed("iac", [finding("iac", "CKV_AWS_1", p) for p in paths])

        candidates = discovery.find_candidates(catalog, min_repos=1, min_files=3)

        assert [c.capabilities for c in candidates] == [("iac", "sast")]
        assert candidates[0].files == 3

    def test_one_shared_file_is_a_coincidence(self, catalog, seed) -> None:
        """Two capabilities finding something in the same file once is the
        normal texture of a codebase, not a pattern worth a rule."""
        seed("sast", [finding("sast", "CWE-89", "src/app.py")])
        seed("iac", [finding("iac", "CKV_AWS_1", "src/app.py")])

        assert discovery.find_candidates(catalog, min_repos=1, min_files=3) == []

    def test_a_pair_an_existing_rule_covers_is_not_suggested(
        self, catalog, seed
    ) -> None:
        """Read from `BUILT_IN_RULES` rather than hardcoded, so a rule
        somebody writes tomorrow stops this proposing the pairing it covers.
        A report that keeps suggesting what already exists is one people stop
        reading."""
        paths = [f"src/module_{i}.py" for i in range(3)]
        seed("sast", [finding("sast", "CWE-89", p) for p in paths])
        seed("secrets", [finding("secrets", "generic-api-key", p) for p in paths])

        # `secret-in-code-with-injection` already pairs these two.
        assert frozenset({"sast", "secrets"}) in discovery._covered_pairs()
        assert discovery.find_candidates(catalog, min_repos=1, min_files=3) == []

    def test_resolved_findings_do_not_count(
        self, client, admin_auth, catalog, seed, run_compaction
    ) -> None:
        """A pairing somebody already fixed is not a pattern to write a rule
        about."""
        paths = [f"src/module_{i}.py" for i in range(3)]
        seed("sast", [finding("sast", "CWE-89", p) for p in paths])
        seed("iac", [finding("iac", "CKV_AWS_1", p) for p in paths])

        for row in catalog.query(
            "SELECT finding_id FROM findings WHERE capability = 'iac'"
        ):
            client.patch(
                f"/api/dashboard/findings/{row[0]}/status",
                json={"status": "false_positive", "reason": "test fixture"},
                headers=admin_auth,
            )
        run_compaction()

        assert discovery.find_candidates(catalog, min_repos=1, min_files=3) == []

    def test_findings_with_no_file_are_ignored(self, catalog, seed) -> None:
        """Dependency findings carry an empty path. Bucketing them together
        would collapse every one into a single enormous phantom
        co-occurrence."""
        seed("sast", [finding("sast", "CWE-89", "")])
        seed("iac", [finding("iac", "CKV_AWS_1", "")])

        assert discovery.find_candidates(catalog, min_repos=1, min_files=1) == []

    def test_one_example_per_capability_per_file(self, catalog, seed) -> None:
        """A file with forty SAST findings would otherwise fill every example
        list with the same rule."""
        seed(
            "sast",
            [finding("sast", f"CWE-{i}", "src/app.py") for i in (89, 79, 22)],
        )
        seed("iac", [finding("iac", "CKV_AWS_1", "src/app.py")])

        candidates = discovery.find_candidates(catalog, min_repos=1, min_files=1)

        assert len(candidates[0].examples[0]["findings"]) == 2


class TestItStopsAtSuggesting:
    def test_the_built_in_rules_are_untouched(self, catalog, seed) -> None:
        """The property spec 08 §5 rests on. Nothing here may add a rule."""
        before = len(correlate.BUILT_IN_RULES)
        seed("sast", [finding("sast", "CWE-89", f"src/m{i}.py") for i in range(3)])
        seed("iac", [finding("iac", "CKV_AWS_1", f"src/m{i}.py") for i in range(3)])

        discovery.find_candidates(catalog, min_repos=1, min_files=3)

        assert len(correlate.BUILT_IN_RULES) == before


class TestTheRetroSection:
    def test_candidates_appear_in_the_report(self, client, catalog, seed) -> None:
        paths = [f"src/module_{i}.py" for i in range(3)]
        seed("sast", [finding("sast", "CWE-89", p) for p in paths])
        seed("iac", [finding("iac", "CKV_AWS_1", p) for p in paths])

        report = build_retro(client.app.state.knowledge, catalog=catalog)

        # The pairing is there — but in one repository, and the default
        # `min_repos` is 2. A pattern inside a single codebase is that team's
        # habit, not a portfolio-wide rule worth writing, so the section is
        # correctly empty and the threshold is what makes it so.
        assert discovery.find_candidates(catalog, min_repos=1, min_files=3)
        assert report.candidate_combinations == []

    def test_the_markdown_says_nothing_was_written(self, client, catalog) -> None:
        """The one sentence a reader needs: this is a suggestion, and no rule
        exists because of it."""
        report = build_retro(client.app.state.knowledge, catalog=catalog)
        report.candidate_combinations = [
            discovery.CandidateCombination(
                capabilities=("sast", "secrets"),
                files=4,
                repos=2,
                examples=[
                    {
                        "repo_full_name": REPO,
                        "file_path": "src/app.py",
                        "findings": [
                            {"capability": "sast", "rule_id": "CWE-89", "title": "x"},
                            {"capability": "secrets", "rule_id": "key", "title": "y"},
                        ],
                    }
                ],
            )
        ]

        markdown = render_retro_markdown(report)

        assert "Candidate combinations (1)" in markdown
        assert "sast + secrets" in markdown
        assert "Nothing has been written to `correlate.py`" in markdown

    def test_a_retro_without_a_catalog_still_works(self, client) -> None:
        """Optional on purpose: the Knowledge Store stays the only hard
        dependency of a retro."""
        report = build_retro(client.app.state.knowledge)

        assert report.candidate_combinations == []
