"""Semgrep taint mode as Python reachability, with the import floor kept as
the fallback (TheHub #60745, a child of #60736).

The four acceptance criteria, one class each:

* a finding of a taint-covered rule carries reachable, unreachable or
  unknown, citing the taint trace when reachable;
* a rule with no taint spec gets exactly the import floor's verdict;
* on the seeded corpus, taint precision is at least the floor's, with both
  figures computed here from a recorded Semgrep run;
* a Semgrep failure or timeout is unknown, never unreachable.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from mykronos import reachability, taint_reachability
from mykronos.schemas import ReachabilitySubmission
from mykronos.taint_reachability import (
    TAINT_SPECS,
    TaintRun,
    floor_verdict,
    parse_semgrep_output,
    run_semgrep,
    verdict_for,
)

ROOT = Path(__file__).resolve().parents[2]
BENCH = ROOT / "bench" / "reachability"
RECORDED = BENCH / "semgrep-taint-recorded.json"

sys.path.insert(0, str(ROOT / "scripts"))

import bench_reachability  # noqa: E402

SHELL = "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true"
EVAL = "python.lang.security.audit.eval-detected.eval-detected"
UNCOVERED = "python.lang.security.audit.insecure-hash-algorithm-md5.insecure-hash-algorithm-md5"


def recorded_run() -> TaintRun:
    return parse_semgrep_output(RECORDED.read_text(encoding="utf-8"))


class TestTheNamedList:
    def test_the_list_is_named_and_every_entry_has_a_rule(self) -> None:
        assert SHELL in TAINT_SPECS
        assert EVAL in TAINT_SPECS
        config = taint_reachability.semgrep_config()
        ids = {rule["id"] for rule in config["rules"]}
        assert set(TAINT_SPECS.values()) <= ids
        assert all(rule["mode"] == "taint" for rule in config["rules"])

    def test_an_uncovered_rule_is_not_in_it(self) -> None:
        assert UNCOVERED not in TAINT_SPECS


class TestACoveredFindingCarriesAVerdict:
    def test_a_traced_flow_is_reachable_and_cites_the_trace(self) -> None:
        verdict = verdict_for(
            SHELL, "handlers.py", 20, orphaned=set(), taint=recorded_run()
        )

        assert verdict.verdict == "reachable"
        assert verdict.basis == "taint"
        assert verdict.trace is not None
        assert verdict.trace["source"]["path"] == "handlers.py"
        assert verdict.trace["source"]["line"] == 19
        assert verdict.trace["source"]["content"] == "request.args"
        assert verdict.trace["sink"]["line"] == 20
        assert verdict.trace["taint_rule"] == TAINT_SPECS[SHELL]

    def test_no_trace_is_unknown_never_unreachable(self) -> None:
        """Semgrep OSS taint is intraprocedural: the helper case in the corpus
        is reachable and has no trace. "No trace" cannot mean "no flow"."""
        verdict = verdict_for(
            SHELL, "helpers.py", 13, orphaned=set(), taint=recorded_run()
        )

        assert verdict.verdict == "unknown"
        assert verdict.trace is None
        assert "intraprocedural" in verdict.reason

    def test_a_trace_in_another_rule_does_not_count(self) -> None:
        """handlers.py:53 is an eval trace; a shell finding on that line is
        not reached by it."""
        verdict = verdict_for(
            SHELL, "handlers.py", 53, orphaned=set(), taint=recorded_run()
        )

        assert verdict.verdict == "unknown"

    def test_an_orphaned_file_is_unreachable_even_with_a_trace(self) -> None:
        """legacy.py has a traced flow, but nothing imports or registers it.
        The import floor's unreachable stands, and the trace is not cited as
        evidence of reachability."""
        verdict = verdict_for(
            EVAL, "legacy.py", 18, orphaned={"legacy.py"}, taint=recorded_run()
        )

        assert verdict.verdict == "unreachable"
        assert verdict.basis == "import_floor"

    def test_a_multi_line_finding_matches_an_overlapping_trace(self) -> None:
        verdict = verdict_for(
            EVAL, "handlers.py", 52, 53, orphaned=set(), taint=recorded_run()
        )

        assert verdict.verdict == "reachable"

    def test_paths_are_compared_normalised(self) -> None:
        verdict = verdict_for(
            SHELL, "./handlers.py", 20, orphaned=set(), taint=recorded_run()
        )

        assert verdict.verdict == "reachable"


class TestAnUncoveredRuleKeepsTheFloor:
    SOURCES = {
        "app.py": "import used\n",
        "used.py": "import hashlib\n",
        "dead.py": "import hashlib\n",
        "notes.md": "",
    }

    @pytest.mark.parametrize("path", ["used.py", "dead.py", "app.py", "notes.md", "x.js"])
    def test_it_is_exactly_the_floor_verdict(self, path: str) -> None:
        py = {k: v for k, v in self.SOURCES.items() if k.endswith(".py")}
        orphaned = set(reachability.orphaned(py))
        assert orphaned == {"dead.py"}

        for taint in (recorded_run(), TaintRun.failed("boom"), None):
            got = verdict_for(UNCOVERED, path, 1, orphaned=orphaned, taint=taint)
            assert got == floor_verdict(path, orphaned)

    def test_the_floor_is_today_s_rule(self) -> None:
        """Orphaned is unreachable; anything else is unknown, because an
        imported file is not proven reachable (spec 19 §2.1)."""
        assert floor_verdict("dead.py", {"dead.py"}).verdict == "unreachable"
        assert floor_verdict("used.py", {"dead.py"}).verdict == "unknown"
        assert floor_verdict("dead.js", {"dead.js"}).verdict == "unknown"
        assert floor_verdict("dead.py", {"dead.py"}).basis == "import_floor"


class TestAFailureIsUnknown:
    @staticmethod
    def runner(result: Any):
        def run(*args: Any, **kwargs: Any) -> Any:
            if isinstance(result, BaseException):
                raise result
            return result

        return run

    def assert_unknown_everywhere(self, run: TaintRun) -> None:
        assert run.status == "failed"
        for path in ("handlers.py", "legacy.py"):
            verdict = verdict_for(SHELL, path, 20, orphaned={"legacy.py"}, taint=run)
            assert verdict.verdict == "unknown", (path, verdict)

    def test_a_timeout(self, tmp_path: Path) -> None:
        run = run_semgrep(
            tmp_path,
            timeout=1,
            runner=self.runner(subprocess.TimeoutExpired(["semgrep"], 1)),
        )
        self.assert_unknown_everywhere(run)
        assert "timed out" in run.reason

    def test_semgrep_missing(self, tmp_path: Path) -> None:
        run = run_semgrep(tmp_path, runner=self.runner(FileNotFoundError("semgrep")))
        self.assert_unknown_everywhere(run)

    def test_a_fatal_exit_code(self, tmp_path: Path) -> None:
        done = subprocess.CompletedProcess(["semgrep"], 2, stdout="", stderr="bad config")
        run = run_semgrep(tmp_path, runner=self.runner(done))
        self.assert_unknown_everywhere(run)
        assert "exited 2" in run.reason

    def test_output_that_is_not_json(self, tmp_path: Path) -> None:
        done = subprocess.CompletedProcess(["semgrep"], 0, stdout="{nope", stderr="")
        run = run_semgrep(tmp_path, runner=self.runner(done))
        self.assert_unknown_everywhere(run)

    def test_a_per_file_timeout_is_unknown_for_that_file(self) -> None:
        body = json.loads(RECORDED.read_text(encoding="utf-8"))
        body["errors"] = [
            {"type": "Timeout", "level": "warn", "path": "legacy.py", "message": "t"}
        ]
        run = parse_semgrep_output(json.dumps(body))

        assert run.status == "ok"
        assert verdict_for(EVAL, "legacy.py", 18, orphaned={"legacy.py"}, taint=run).verdict == "unknown"
        assert verdict_for(SHELL, "handlers.py", 20, orphaned=set(), taint=run).verdict == "reachable"

    def test_not_run_is_unknown(self) -> None:
        assert verdict_for(SHELL, "legacy.py", 20, orphaned={"legacy.py"}, taint=None).verdict == "unknown"

    def test_the_semgrep_command_uses_taint_rules_only(self, tmp_path: Path) -> None:
        """No registry pack, no metrics: the source and the rules stay here."""
        seen: dict[str, Any] = {}

        def run(cmd: list[str], **kwargs: Any) -> Any:
            seen["cmd"] = cmd
            seen["kwargs"] = kwargs
            config = Path(cmd[cmd.index("--config") + 1])
            seen["config"] = json.loads(config.read_text(encoding="utf-8"))
            return subprocess.CompletedProcess(cmd, 0, stdout=RECORDED.read_text(encoding="utf-8"), stderr="")

        result = run_semgrep(tmp_path, timeout=30, runner=run)

        assert result.status == "ok"
        assert "--dataflow-traces" in seen["cmd"]
        assert seen["cmd"][seen["cmd"].index("--metrics") + 1] == "off"
        assert seen["kwargs"]["timeout"] == 30
        assert {r["id"] for r in seen["config"]["rules"]} == set(TAINT_SPECS.values())


class TestTheSubmission:
    def test_the_cli_adds_the_taint_block(self, tmp_path: Path, monkeypatch, capsys) -> None:
        (tmp_path / "app.py").write_text("import os\n", encoding="utf-8")
        monkeypatch.setattr(
            taint_reachability, "run_semgrep", lambda root, **kw: recorded_run()
        )

        assert reachability.main([str(tmp_path), "--commit-sha", "abc", "--taint"]) == 0
        body = json.loads(capsys.readouterr().out)

        assert body["taint"]["status"] == "ok"
        assert body["taint"]["rules"] == sorted(TAINT_SPECS)
        assert len(body["taint"]["matches"]) == 4
        ReachabilitySubmission.model_validate(body)

    def test_without_the_flag_nothing_changes(self, tmp_path: Path, capsys) -> None:
        (tmp_path / "app.py").write_text("import os\n", encoding="utf-8")

        reachability.main([str(tmp_path), "--commit-sha", "abc"])
        body = json.loads(capsys.readouterr().out)

        assert "taint" not in body

    def test_a_round_trip_keeps_the_verdicts(self) -> None:
        run = recorded_run()
        again = TaintRun.from_submission(json.loads(json.dumps(run.as_submission())))

        for line, path in ((20, "handlers.py"), (13, "helpers.py")):
            assert verdict_for(SHELL, path, line, orphaned=set(), taint=again) == verdict_for(
                SHELL, path, line, orphaned=set(), taint=run
            )


class TestStoredAndRead:
    def post(self, client, body):
        from tests.conftest import REPO, issue_token

        auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'sast')}"}
        return client.post("/api/ingest/reachability", json=body, headers=auth)

    def test_ingest_stores_it_and_the_repo_view_reports_it(self, client, admin_auth) -> None:
        from tests.test_onboarding import onboard

        repo_id = onboard(client, admin_auth).json()["id"]
        body = {
            "orphaned_paths": ["legacy.py"],
            "files_analysed": 4,
            "taint": recorded_run().as_submission(),
        }

        assert self.post(client, body).status_code == 200
        out = client.get(f"/api/repos/{repo_id}/reachability", headers=admin_auth).json()

        assert out["taint_status"] == "ok"
        assert out["taint_matches"] == 4
        assert SHELL in out["taint_rules"]

    def test_an_old_runner_without_taint_reads_as_not_run(self, client, admin_auth) -> None:
        from tests.test_onboarding import onboard

        repo_id = onboard(client, admin_auth).json()["id"]
        self.post(client, {"orphaned_paths": [], "files_analysed": 1})
        out = client.get(f"/api/repos/{repo_id}/reachability", headers=admin_auth).json()

        assert out["taint_status"] == "not_run"

    def test_the_finding_record_carries_the_verdict(
        self, client, admin_auth, run_compaction
    ) -> None:
        from tests.conftest import REPO, finding_payload, issue_token, post_findings, post_scan
        from tests.test_onboarding import onboard

        repo_id = onboard(client, admin_auth).json()["id"]
        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast"]},
            headers=admin_auth,
        )
        auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'sast')}"}
        post_scan(client, auth, scan_run_id="run-1")
        post_findings(
            client,
            auth,
            [
                finding_payload(
                    rule_id=SHELL, file_path="handlers.py", line_start=20, line_end=20, symbol="a"
                ),
                finding_payload(
                    rule_id=SHELL, file_path="helpers.py", line_start=13, line_end=13, symbol="b"
                ),
                finding_payload(
                    rule_id=UNCOVERED, file_path="legacy.py", line_start=3, line_end=3, symbol="c"
                ),
            ],
            scan_run_id="run-1",
        )
        run_compaction()
        self.post(
            client,
            {
                "orphaned_paths": ["legacy.py"],
                "files_analysed": 4,
                "taint": recorded_run().as_submission(),
            },
        )

        listed = client.get(
            f"/api/dashboard/repos/{repo_id}/findings", headers=admin_auth
        ).json()["findings"]
        verdicts = {}
        for row in listed:
            record = client.get(
                f"/api/dashboard/findings/{row['finding_id']}/record", headers=admin_auth
            ).json()
            verdicts[row["file_path"]] = record["reachability"]

        assert verdicts["handlers.py"]["verdict"] == "reachable"
        assert verdicts["handlers.py"]["trace"]["source"]["content"] == "request.args"
        assert verdicts["helpers.py"]["verdict"] == "unknown"
        assert verdicts["legacy.py"] == {
            **floor_verdict("legacy.py", {"legacy.py"}).as_dict()
        }

    def test_a_record_with_no_report_is_unknown(self, client, admin_auth, run_compaction) -> None:
        from tests.conftest import REPO, finding_payload, issue_token, post_findings, post_scan
        from tests.test_onboarding import onboard

        repo_id = onboard(client, admin_auth).json()["id"]
        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast"]},
            headers=admin_auth,
        )
        auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'sast')}"}
        post_scan(client, auth, scan_run_id="run-1")
        post_findings(client, auth, [finding_payload(rule_id=SHELL)], scan_run_id="run-1")
        run_compaction()
        row = client.get(
            f"/api/dashboard/repos/{repo_id}/findings", headers=admin_auth
        ).json()["findings"][0]

        record = client.get(
            f"/api/dashboard/findings/{row['finding_id']}/record", headers=admin_auth
        ).json()

        assert record["reachability"]["verdict"] == "unknown"


class TestTheCorpusGrade:
    def test_taint_precision_is_at_least_the_floor_s(self) -> None:
        grade = bench_reachability.grade(
            BENCH / "manifest.yaml", BENCH / "corpus", taint=recorded_run()
        )

        floor = grade["import_floor"]
        taint = grade["taint"]
        assert floor["decisive"] >= 1 and taint["decisive"] >= 1
        assert taint["precision"] >= floor["precision"]
        # Recorded so a change to either number is a visible diff here, not
        # a silent drift: the figures #60745 reports.
        assert (floor["decisive"], floor["correct"]) == (1, 1)
        assert (taint["decisive"], taint["correct"]) == (4, 4)

    def test_uncovered_findings_keep_the_floor_on_the_corpus(self) -> None:
        grade = bench_reachability.grade(
            BENCH / "manifest.yaml", BENCH / "corpus", taint=recorded_run()
        )

        for row in grade["findings"]:
            if row["rule_id"] not in TAINT_SPECS:
                assert row["taint_verdict"] == row["floor_verdict"]

    def test_a_failed_run_grades_as_not_measured(self) -> None:
        grade = bench_reachability.grade(
            BENCH / "manifest.yaml", BENCH / "corpus", taint=TaintRun.failed("boom")
        )

        assert grade["taint"]["status"] == "failed"
        assert all(
            row["taint_verdict"] == "unknown"
            for row in grade["findings"]
            if row["rule_id"] in TAINT_SPECS
        )

    def test_the_corpus_is_inert_in_this_repository(self) -> None:
        """No `.py` under the corpus: a scanner or the import graph walking
        this repository must not see seeded vulnerabilities as ours."""
        files = list((BENCH / "corpus").iterdir())
        assert files and all(f.name.endswith(".py.txt") for f in files)

    @pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep is not installed")
    def test_a_live_run_matches_the_recording(self) -> None:
        live = bench_reachability.grade(BENCH / "manifest.yaml", BENCH / "corpus")
        recorded = bench_reachability.grade(
            BENCH / "manifest.yaml", BENCH / "corpus", taint=recorded_run()
        )

        assert live["taint"]["decisive"] == recorded["taint"]["decisive"]
        assert live["taint"]["correct"] == recorded["taint"]["correct"]
