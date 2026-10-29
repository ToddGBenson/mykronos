"""A commit is charged only for dependency findings its own tree introduces
(TheHub #61063).

Observed 2026-10-27: TheHub's gate refused develop 09a6ca31 with "Introduced
by 09a6ca31: 0 critical, 3 high". The three were pypdf 6.21.1 advisories
published that day, read out of the committed SBOM of the *running*
production backend - and 09a6ca31 was the commit that pinned pypdf 6.21.2,
which fixes all three. "First seen in a scan of this commit" counted findings
no code change introduced, against a version the commit was removing.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from mykronos import atlas_baseline
from mykronos.adapters.base import ScanContext
from mykronos.api.oracle import disclosure_sentence
from mykronos.dashboard import DashboardQueries
from mykronos.schemas import FindingSubmission
from tests.conftest import REPO, finding_payload, issue_token, post_findings, post_scan

SBOM = "docs/sbom/latest-python.cdx.json"
CVES = ("CVE-2026-115572", "CVE-2026-115580", "CVE-2026-115585")

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


def _sbom(version: str) -> str:
    return json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {"name": "pypdf", "version": version, "purl": f"pkg:pypi/pypdf@{version}"},
                {"name": "redis", "version": "6.4.0", "purl": "pkg:pypi/redis@6.4.0"},
            ],
        }
    )


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def _commit(repo: Path, files: dict[str, str], message: str) -> str:
    for name, text in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qm", message)
    return _git(repo, "rev-parse", "HEAD")


@pytest.fixture
def checkout(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    return repo


def _findings(fixed: str = "6.21.2") -> list[FindingSubmission]:
    return [
        FindingSubmission(
            rule_id=cve,
            title=f"pypdf {cve}",
            severity="high",
            file_path=SBOM,
            line_start=1,
            line_end=1,
            package_name="pypdf",
            package_version="6.21.1",
            raw_finding_json={"ruleId": cve, "fixed_version": fixed},
        )
        for cve in CVES
    ]


def _context(workspace: Path, sha: str) -> ScanContext:
    return ScanContext(
        repo_full_name=REPO,
        capability="atlas",
        tool_name="osv-scanner",
        tool_version="2.5.0",
        commit_sha=sha,
        branch="develop",
        workspace=workspace,
    )


# -- The runner: what the checkout knows -------------------------------------


@needs_git
class TestTheRunnerReadsTheTree:
    def test_a_component_the_parent_already_carried_names_the_parent(
        self, checkout: Path
    ) -> None:
        parent = _commit(
            checkout, {SBOM: _sbom("6.21.1"), "requirements.txt": "pypdf>=6.0\n"}, "one"
        )
        head = _commit(checkout, {"README.md": "docs\n"}, "two")
        findings = _findings()

        atlas_baseline.annotate(findings, _context(checkout, head))

        assert findings[0].raw_finding_json["baseline_commits"] == [parent]
        assert "remediated_by" not in findings[0].raw_finding_json

    def test_a_component_this_commit_added_has_no_baseline(self, checkout: Path) -> None:
        _commit(checkout, {SBOM: _sbom("6.20.0")}, "one")
        head = _commit(checkout, {SBOM: _sbom("6.21.1")}, "two")
        findings = _findings()

        atlas_baseline.annotate(findings, _context(checkout, head))

        assert findings[0].raw_finding_json["baseline_commits"] == []

    def test_a_pin_to_the_fixed_version_is_a_remediation(self, checkout: Path) -> None:
        """09a6ca31: the SBOM of what runs still says 6.21.1; the commit pins
        6.21.2."""
        _commit(
            checkout, {SBOM: _sbom("6.21.1"), "requirements.txt": "pypdf==6.21.1\n"}, "one"
        )
        head = _commit(checkout, {"requirements.txt": "pypdf==6.21.2\n"}, "two")
        findings = _findings()

        atlas_baseline.annotate(findings, _context(checkout, head))

        assert findings[0].raw_finding_json["remediated_by"] == {
            "file": "requirements.txt",
            "spec": "==6.21.2",
        }

    def test_a_pin_short_of_the_fix_is_not(self, checkout: Path) -> None:
        _commit(checkout, {SBOM: _sbom("6.21.1")}, "one")
        head = _commit(checkout, {"requirements.txt": "pypdf==6.21.0\n"}, "two")
        findings = _findings()

        atlas_baseline.annotate(findings, _context(checkout, head))

        assert "remediated_by" not in findings[0].raw_finding_json

    def test_no_git_history_records_nothing(self, tmp_path: Path) -> None:
        """Absent is "could not tell", which the platform reads as introduced."""
        (tmp_path / "docs" / "sbom").mkdir(parents=True)
        (tmp_path / SBOM).write_text(_sbom("6.21.1"), encoding="utf-8")
        findings = _findings()

        atlas_baseline.annotate(findings, _context(tmp_path / "nowhere", "c" * 40))

        assert "baseline_commits" not in findings[0].raw_finding_json


# -- The platform: what the gate counts --------------------------------------


def _atlas_scan(
    client: TestClient, run_compaction, scan_run_id: str, commit: str, started_at: str,
    findings: list[dict],
) -> None:
    auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'atlas')}"}
    post_scan(
        client, auth, scan_run_id=scan_run_id, commit_sha=commit, capability="atlas",
        tool_name="osv-scanner", tool_version="2.5.0", started_at=started_at,
        finding_count=len(findings),
    )
    response = post_findings(client, auth, findings, scan_run_id=scan_run_id, capability="atlas")
    assert response.status_code < 300, response.text
    run_compaction()


def _payloads(findings: list[FindingSubmission]) -> list[dict]:
    return [
        finding_payload(
            rule_id=f.rule_id, title=f.title, severity="high", file_path=f.file_path,
            line_start=1, line_end=1, symbol=None, code_snippet=None,
            package_name=f.package_name, package_version=f.package_version,
            raw_finding_json=f.raw_finding_json,
        )
        for f in findings
    ]


def _raw(**extra) -> list[dict]:
    findings = _findings()
    for f in findings:
        f.raw_finding_json.update(extra)
    return _payloads(findings)


OLD = "a" * 40
NEW = "b" * 40
OTHER = "c" * 40
BEFORE = "2026-10-27T08:00:00"
AFTER = "2026-10-27T15:00:00"
UNRELATED = [
    finding_payload(
        rule_id="CVE-2025-0001", severity="low", file_path="requirements.txt",
        line_start=1, line_end=1, symbol=None, code_snippet=None,
        package_name="redis", package_version="6.4.0",
    )
]


class TestTheGateCountsWhatTheCommitIntroduced:
    def test_the_09a6ca31_case_introduces_nothing(
        self, client, run_compaction, catalog
    ) -> None:
        """The regression (AC2): production's SBOM has pypdf 6.21.1 with three
        highs, the commit pins 6.21.2 - introduced.high is 0."""
        _atlas_scan(client, run_compaction, "atlas-old", OLD, BEFORE, UNRELATED)
        _atlas_scan(
            client, run_compaction, "atlas-new", NEW, AFTER,
            _raw(baseline_commits=[OLD],
                 remediated_by={"file": "requirements.txt", "spec": "==6.21.2"}),
        )

        queries = DashboardQueries(catalog)
        assert queries.introduced_by(REPO, NEW).get("high", 0) == 0
        assert queries.introduced_rows(REPO, NEW) == []
        assert queries.disclosed_by(REPO, NEW) == {"high": 3}
        assert queries.remediated_by(REPO, NEW) == {"high": 3}
        assert queries.introduced_by_commits([(REPO, NEW)]) == {(REPO, NEW): {}}

    def test_a_fix_in_the_tree_clears_it_even_without_history(
        self, client, run_compaction, catalog
    ) -> None:
        """A commit that upgrades to the fixing version is never charged for
        it, whatever the walk back found."""
        _atlas_scan(client, run_compaction, "atlas-old", OLD, BEFORE, UNRELATED)
        _atlas_scan(
            client, run_compaction, "atlas-new", NEW, AFTER,
            _raw(remediated_by={"file": "requirements.txt", "spec": "==6.21.2"}),
        )

        assert DashboardQueries(catalog).introduced_by(REPO, NEW) == {}

    def test_a_component_the_baseline_carried_is_disclosed(
        self, client, run_compaction, catalog
    ) -> None:
        """AC1: new only because an advisory was published against the
        baseline's version."""
        _atlas_scan(client, run_compaction, "atlas-old", OLD, BEFORE, UNRELATED)
        _atlas_scan(
            client, run_compaction, "atlas-new", NEW, AFTER, _raw(baseline_commits=[OLD]),
        )

        queries = DashboardQueries(catalog)
        assert queries.introduced_by(REPO, NEW) == {}
        assert queries.disclosed_by(REPO, NEW) == {"high": 3}
        assert queries.remediated_by(REPO, NEW) == {}

    def test_a_component_absent_from_the_baseline_is_introduced(
        self, client, run_compaction, catalog
    ) -> None:
        """The baseline scan's commit is not among the ancestors that had it:
        this change (or one since the baseline) added it."""
        _atlas_scan(client, run_compaction, "atlas-old", OLD, BEFORE, UNRELATED)
        _atlas_scan(
            client, run_compaction, "atlas-new", NEW, AFTER, _raw(baseline_commits=[OTHER]),
        )

        assert DashboardQueries(catalog).introduced_by(REPO, NEW) == {"high": 3}

    def test_no_evidence_is_introduced(self, client, run_compaction, catalog) -> None:
        """An older uploader writes neither field. Missing evidence never
        opens the gate."""
        _atlas_scan(client, run_compaction, "atlas-old", OLD, BEFORE, UNRELATED)
        _atlas_scan(client, run_compaction, "atlas-new", NEW, AFTER, _raw())

        assert DashboardQueries(catalog).introduced_by(REPO, NEW) == {"high": 3}

    def test_no_earlier_scan_is_introduced(self, client, run_compaction, catalog) -> None:
        _atlas_scan(
            client, run_compaction, "atlas-new", NEW, AFTER, _raw(baseline_commits=[OLD]),
        )

        assert DashboardQueries(catalog).introduced_by(REPO, NEW) == {"high": 3}

    def test_the_gate_names_them_and_does_not_block(
        self, client, run_compaction
    ) -> None:
        """AC3: kept out of `introduced`, never out of sight."""
        _atlas_scan(client, run_compaction, "atlas-old", OLD, BEFORE, UNRELATED)
        _atlas_scan(
            client, run_compaction, "atlas-new", NEW, AFTER,
            _raw(baseline_commits=[OLD],
                 remediated_by={"file": "requirements.txt", "spec": "==6.21.2"}),
        )
        oracle = {"Authorization": f"Bearer {issue_token(client, REPO, 'atlas', 'oracle')}"}

        body = client.post(
            "/api/oracle/evaluate",
            json={"commit_sha": NEW, "decision_type": "commit_gate"},
            headers=oracle,
        ).json()

        assert body["introduced_blocking"] is False
        assert body["introduced"].get("high", 0) == 0
        assert body["disclosed"] == {"high": 3}
        assert body["remediates"] == {"high": 3}
        assert "Newly disclosed, not introduced by this commit: 3 high" in body["reasoning"]
        assert "This commit remediates 3." in body["reasoning"]


@needs_git
class TestEndToEnd:
    def test_the_runner_and_the_gate_agree_on_09a6ca31(
        self, checkout: Path, client, run_compaction, catalog
    ) -> None:
        """The runner annotates from a real history; the gate reads it."""
        parent = _commit(
            checkout, {SBOM: _sbom("6.21.1"), "requirements.txt": "pypdf>=6.0\n"}, "one"
        )
        head = _commit(checkout, {"requirements.txt": "pypdf==6.21.2\n"}, "pin pypdf")
        findings = _findings()
        atlas_baseline.annotate(findings, _context(checkout, head))

        _atlas_scan(client, run_compaction, "atlas-old", parent, BEFORE, UNRELATED)
        _atlas_scan(client, run_compaction, "atlas-new", head, AFTER, _payloads(findings))

        queries = DashboardQueries(catalog)
        assert queries.introduced_by(REPO, head).get("high", 0) == 0
        assert queries.disclosed_by(REPO, head) == {"high": 3}
        assert queries.remediated_by(REPO, head) == {"high": 3}


class TestTheSentence:
    def test_nothing_disclosed_says_nothing(self) -> None:
        assert disclosure_sentence({}, {}) == ""

    def test_it_counts_and_names_the_remediation(self) -> None:
        sentence = disclosure_sentence({"high": 3, "critical": 1}, {"high": 2})

        assert sentence.startswith(
            "Newly disclosed, not introduced by this commit: 1 critical, 3 high"
        )
        assert sentence.endswith("This commit remediates 2.")
