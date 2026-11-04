"""apply-semgrep-fix: a named rule's own Semgrep fix, applied as written
(TheHub #60746).

The fixtures under `fixtures/semgrep_fix/` are real Semgrep output, not
hand-written approximations of it:

- `src/` is the tree Semgrep scanned, one file per named rule;
- `semgrep.sarif` is `semgrep scan --config semgrep_fix_rules.yml --sarif
  --autofix --dryrun` over it (Semgrep 1.97.0, the version the SAST lane
  pins; without `--autofix --dryrun` Semgrep writes no `fixes` into SARIF);
- `semgrep.json` is the same scan with `--json`, whose `extra.fix` is the
  replacement for the match span alone;
- `fixed/` is the same tree after `semgrep scan --autofix` with the same
  rules, which is the diff Semgrep itself would write.

Regenerate all three with the `semgrep/semgrep:1.97.0` image from inside the
fixture directory, if the rules change.

So "the pull request's diff is exactly the Semgrep fix output" is asserted
as: the file on the pull request's branch equals the file in `fixed/`, byte
for byte, and no other file changed.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from mykronos.adapters import ScanContext, sarif_to_findings
from mykronos.patchwork import fixers, semgrep_fix
from tests.conftest import REPO, post_findings, post_scan
from tests.test_onboarding import onboard
from tests.test_patchwork import patchwork_auth  # noqa: F401 - fixture

FIXTURES = Path(__file__).with_name("fixtures") / "semgrep_fix"

#: Named rule -> the fixture file Semgrep matched it in.
FIXTURE_FILES = {
    "mykronos-pyyaml-load-to-safe-load": "src/pyyaml_load.py",
    "mykronos-jinja2-autoescape-disabled": "src/jinja2_autoescape.py",
    "mykronos-flask-debug-enabled": "src/flask_debug.py",
}


def _read(relative: str) -> str:
    return (FIXTURES / relative).read_bytes().decode("utf-8")


def _sarif() -> dict[str, Any]:
    return json.loads(_read("semgrep.sarif"))


def _context() -> ScanContext:
    return ScanContext(
        repo_full_name=REPO,
        capability="sast",
        tool_name="semgrep",
        tool_version="1.97.0",
        commit_sha="a91f2c7",
        branch="main",
        workspace=FIXTURES,
    )


def _findings() -> dict[str, dict[str, Any]]:
    """Every fixture result, through the real SARIF adapter, by named rule."""
    result = sarif_to_findings(json.dumps(_sarif()), _context())
    by_rule: dict[str, dict[str, Any]] = {}
    for submission in result.findings:
        name = semgrep_fix.rule_name(submission.rule_id)
        assert name is not None, f"{submission.rule_id} is not a named rule"
        record = submission.model_dump(mode="json")
        record["capability"] = "sast"
        by_rule[name] = record
    return by_rule


class TestTheNamedList:
    def test_the_list_is_exactly_the_rules_file(self) -> None:
        document = yaml.safe_load(semgrep_fix.RULES_FILE.read_text(encoding="utf-8"))
        ids = [rule["id"] for rule in document["rules"]]

        assert tuple(ids) == semgrep_fix.SEMGREP_FIX_RULES

    def test_every_named_rule_carries_a_fix(self) -> None:
        document = yaml.safe_load(semgrep_fix.RULES_FILE.read_text(encoding="utf-8"))

        for rule in document["rules"]:
            assert "fix" in rule or "fix-regex" in rule, rule["id"]
            assert rule["metadata"]["mykronos-fix"] == "mechanical", rule["id"]

    def test_every_named_rule_has_review_notes(self) -> None:
        assert set(semgrep_fix._RULE_NOTES) == set(semgrep_fix.SEMGREP_FIX_RULES)

    def test_every_named_rule_has_a_fixture_finding(self) -> None:
        assert set(_findings()) == set(semgrep_fix.SEMGREP_FIX_RULES)

    def test_a_local_rule_id_is_matched_with_its_config_prefix(self) -> None:
        assert (
            semgrep_fix.rule_name("rules.mykronos-flask-debug-enabled")
            == "mykronos-flask-debug-enabled"
        )
        assert semgrep_fix.rule_name("mykronos-flask-debug-enabled-ish") is None
        assert semgrep_fix.rule_name("python.flask.debug-enabled") is None


@pytest.mark.parametrize("rule", semgrep_fix.SEMGREP_FIX_RULES)
class TestEachRule:
    def test_the_fix_is_exactly_semgreps_autofix(self, rule: str) -> None:
        finding = _findings()[rule]
        path = FIXTURE_FILES[rule]
        assert finding["file_path"] == path

        generated = fixers.generate(finding, _read(path))

        assert generated is not None
        name, fix = generated
        assert name == "apply-semgrep-fix"
        assert fix.files == {path: _read(path.replace("src/", "fixed/", 1))}

    def test_the_span_text_is_semgreps_own_json_fix(self, rule: str) -> None:
        """Semgrep's SARIF `insertedContent` is whole fixed lines; its JSON
        `extra.fix` is the span alone. Reading the first as the second's
        lines is what makes the result equal `--autofix`."""
        results = json.loads(_read("semgrep.json"))["results"]
        (match,) = [r for r in results if semgrep_fix.rule_name(r["check_id"]) == rule]
        before = _read(FIXTURE_FILES[rule])
        fix = semgrep_fix.apply_semgrep_fix(_findings()[rule], before)

        assert fix is not None
        expected = (
            before[: match["start"]["offset"]]
            + match["extra"]["fix"]
            + before[match["end"]["offset"] :]
        )
        assert fix.files[FIXTURE_FILES[rule]] == expected

    def test_a_fix_that_does_not_line_up_is_refused(self, rule: str) -> None:
        finding = _findings()[rule]
        (fix,) = finding["raw_finding_json"]["fixes"]
        (replacement,) = fix["artifactChanges"][0]["replacements"]
        replacement["insertedContent"]["text"] = "x = 1"
        content = _read(FIXTURE_FILES[rule])

        assert "does not line up" in str(semgrep_fix.explain(finding, content))

    def test_it_is_deterministic(self, rule: str) -> None:
        finding = _findings()[rule]
        content = _read(FIXTURE_FILES[rule])

        first = semgrep_fix.apply_semgrep_fix(finding, content)
        second = semgrep_fix.apply_semgrep_fix(copy.deepcopy(finding), content)

        assert first is not None and second is not None
        assert first.files == second.files

    def test_a_changed_file_is_refused(self, rule: str) -> None:
        """Fix positions name the scanned commit. If the matched lines moved,
        the same columns are different code."""
        finding = _findings()[rule]
        content = "# a line added above everything\n" + _read(FIXTURE_FILES[rule])

        assert semgrep_fix.apply_semgrep_fix(finding, content) is None
        assert "has changed" in str(semgrep_fix.explain(finding, content))


class TestWhatItRefuses:
    def test_a_rule_outside_the_list_is_not_applied_even_with_a_fix(self) -> None:
        finding = _findings()["mykronos-flask-debug-enabled"]
        finding["rule_id"] = "python.flask.security.audit.debug-enabled"
        content = _read(FIXTURE_FILES["mykronos-flask-debug-enabled"])

        assert finding["raw_finding_json"].get("fixes")
        assert semgrep_fix.apply_semgrep_fix(finding, content) is None

    def test_a_result_with_no_fix_is_not_applied(self) -> None:
        finding = _findings()["mykronos-flask-debug-enabled"]
        finding["raw_finding_json"].pop("fixes")
        content = _read(FIXTURE_FILES["mykronos-flask-debug-enabled"])

        assert semgrep_fix.explain(finding, content) == "Semgrep reported no fix for this result."

    def test_only_sast_findings(self) -> None:
        finding = _findings()["mykronos-flask-debug-enabled"]
        finding["capability"] = "iac"
        content = _read(FIXTURE_FILES["mykronos-flask-debug-enabled"])

        assert semgrep_fix.apply_semgrep_fix(finding, content) is None


class TestThroughThePipeline:
    """A fixture finding, ingested, produces a draft whose diff is the fix."""

    @pytest.mark.parametrize("rule", semgrep_fix.SEMGREP_FIX_RULES)
    def test_the_pull_request_diff_is_exactly_the_semgrep_fix(
        self,
        rule: str,
        client,
        admin_auth,
        patchwork_auth,  # noqa: F811 - the fixture
        run_compaction,
        github,
    ) -> None:
        onboard(client, admin_auth)
        path = FIXTURE_FILES[rule]
        before = _read(path)
        repo = github.repos[REPO]
        repo.files[path] = before
        repo.branches.setdefault("main", {})[path] = before
        main_before = dict(repo.branches["main"])

        finding = _findings()[rule]
        finding["severity"] = "high"
        finding.pop("capability")
        post_scan(client, patchwork_auth, scan_run_id="scan-sg", tool_name="semgrep")
        response = post_findings(client, patchwork_auth, [finding], scan_run_id="scan-sg")
        assert response.status_code in (200, 201, 202), response.text
        run_compaction()

        body = client.post("/api/patchwork/run", json={}, headers=patchwork_auth).json()

        assert body["draft_prs_opened"] == 1, body
        (pr,) = repo.pull_requests
        assert pr.draft is True
        branch = repo.branches[pr.head_branch]
        changed = {p for p in set(branch) | set(main_before) if branch.get(p) != main_before.get(p)}
        assert changed == {path}
        assert branch[path] == _read(path.replace("src/", "fixed/", 1))
        assert "apply-semgrep-fix" in github.pull_request_bodies[pr.number]


class TestTheLaneRunsTheRules:
    """The fixer only ever sees a fix the lane asked Semgrep to write."""

    PIPELINE = Path(__file__).resolve().parents[2] / "deploy/concourse/pipelines/mykronos.yml"

    def _semgrep_command(self) -> str:
        text = self.PIPELINE.read_text(encoding="utf-8")
        start = text.index("semgrep scan \\")
        return text[start : text.index("|| rc=$?", start)]

    def test_the_sast_lane_scans_with_the_fix_rules(self) -> None:
        command = self._semgrep_command()
        relative = semgrep_fix.RULES_FILE.relative_to(Path(__file__).resolve().parents[2])

        assert f"--config {relative.as_posix()}" in command

    def test_it_asks_semgrep_to_write_fixes_without_touching_the_tree(self) -> None:
        command = self._semgrep_command()

        assert "--autofix --dryrun" in command, "without both, SARIF carries no fixes"

    def test_this_fixers_own_fixtures_are_not_scanned(self) -> None:
        assert "--exclude backend/tests/fixtures/semgrep_fix" in self._semgrep_command()
