"""The demo seed is the same estate every time, and a finding is one finding (TheHub #61207).

`deploy/demo/seed.py` promises a reproducible estate: the same seed, the same
data, so a demo can be described in advance and a DAST result compared run to
run. Two things broke that promise.

- Every submission drew `line_start` from the RNG and sent no `code_snippet`,
  so identity fell back to the positional `v1-line` key and every one of the
  21-, 7- and 0-day runs minted new findings. "A finding was fixed" on the
  seeded demo was churn: nothing was ever the same finding twice.
- The commit sha came from `hash()` of a tuple, which `PYTHONHASHSEED` salts
  per process, so every rebuild had different commits.

And the rebuild returned with every page empty (the findings sat in the
write-ahead buffer until the scheduled compaction) and the closures waiting
on the hourly absence sweep. The seed now settles the estate itself.

The seed runs in a fresh interpreter per run here, with a different
`PYTHONHASHSEED` each time, because a per-process salt is invisible to two
calls in one process.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]
SEED = BACKEND.parent / "deploy" / "demo" / "seed.py"

#: Runs the real `main()` against a recording client and a stubbed CLI, then
#: derives each submission's identity with the platform's own fingerprint.
DRIVER = r"""
import importlib.util, json, subprocess, sys

spec = importlib.util.spec_from_file_location("demo_seed_under_test", sys.argv[1])
seed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(seed)

from mykronos.fingerprint import compute_finding_id

events = []

class Recorder(seed.Client):
    def __init__(self, *args, **kwargs):
        pass

    def call(self, method, path, body=None, token=""):
        events.append({"kind": "http", "method": method, "path": path, "body": body})
        return {"id": sum(1 for e in events if e["kind"] == "http")}

def fake_run(argv, **kwargs):
    events.append({"kind": "cli", "argv": list(argv)})
    return subprocess.CompletedProcess(argv, 0, stdout="Token     : demo-token\n", stderr="")

seed.subprocess.run = fake_run
seed.Client = Recorder
# `main`, not `seed()`: settling is part of what the rebuild runs.
assert seed.main([]) == 0

runs = {}
for event in events:
    if event["kind"] != "http":
        continue
    body = event["body"] or {}
    if event["path"] == "/api/ingest/scan-run" and "completed_at" not in body:
        runs[body["scan_run_id"]] = {
            "repo": body["repo_full_name"],
            "capability": body["capability"],
            "commit": body["commit_sha"],
            "findings": [],
        }
    if event["path"] == "/api/ingest/findings":
        run = runs[body["scan_run_id"]]
        for f in body["findings"]:
            finding_id, version = compute_finding_id(
                repo_full_name=run["repo"],
                capability=run["capability"],
                rule_id=f["rule_id"],
                file_path=f.get("file_path"),
                symbol=f.get("symbol"),
                code_snippet=f.get("code_snippet"),
                line_start=f.get("line_start"),
                package_name=f.get("package_name"),
                title=f.get("title"),
            )
            run["findings"].append({"rule_id": f["rule_id"], "finding_id": finding_id})

print(json.dumps({"runs": runs, "events": [
    {"kind": e["kind"], "path": e.get("path"), "argv": e.get("argv")} for e in events
]}))
"""


def _seed_in_a_fresh_process(hash_seed: str) -> dict:
    env = {**os.environ, "PYTHONHASHSEED": hash_seed, "PYTHONPATH": str(BACKEND)}
    completed = subprocess.run(
        [sys.executable, "-c", DRIVER, str(SEED)],
        capture_output=True,
        text=True,
        env=env,
        cwd=BACKEND,
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr[-2000:]
    return json.loads(completed.stdout.strip().splitlines()[-1])


@pytest.fixture(scope="module")
def two_seedings() -> tuple[dict, dict]:
    return _seed_in_a_fresh_process("1"), _seed_in_a_fresh_process("2")


def _age(scan_run_id: str) -> int:
    return int(scan_run_id.rsplit(":", 1)[1])


class TestTwoProcessesSeedTheSameEstate:
    def test_commit_shas_are_identical(self, two_seedings) -> None:
        first, second = two_seedings
        shas_first = {rid: run["commit"] for rid, run in first["runs"].items()}
        shas_second = {rid: run["commit"] for rid, run in second["runs"].items()}
        assert shas_first == shas_second, (
            "The commit sha differs between two processes: it is derived from a "
            "per-process salted hash(), not a stable digest."
        )

    def test_commit_shas_look_like_shas(self, two_seedings) -> None:
        first, _ = two_seedings
        for run in first["runs"].values():
            assert len(run["commit"]) == 40
            int(run["commit"], 16)

    def test_finding_ids_are_identical(self, two_seedings) -> None:
        first, second = two_seedings
        ids_first = {rid: run["findings"] for rid, run in first["runs"].items()}
        ids_second = {rid: run["findings"] for rid, run in second["runs"].items()}
        assert ids_first == ids_second


class TestAFindingKeepsItsIdentityAcrossTheThreeRuns:
    def test_the_same_rule_in_the_same_repo_is_one_finding(self, two_seedings) -> None:
        first, _ = two_seedings
        identities: dict[tuple[str, str, str], set[str]] = defaultdict(set)
        for run in first["runs"].values():
            for f in run["findings"]:
                identities[(run["repo"], run["capability"], f["rule_id"])].add(f["finding_id"])
        churned = {key: ids for key, ids in identities.items() if len(ids) != 1}
        assert not churned, (
            f"{len(churned)} rule(s) got a new finding_id in a later run, so a "
            f"finding dropped from a later run never closes as the same finding: "
            f"{sorted(churned)[:5]}"
        )

    def test_later_runs_report_a_subset_of_the_oldest_findings(self, two_seedings) -> None:
        """A finding absent from the 7- and 0-day runs is one the 21-day run had."""
        first, _ = two_seedings
        by_lane: dict[tuple[str, str], dict[int, set[str]]] = defaultdict(dict)
        for rid, run in first["runs"].items():
            by_lane[(run["repo"], run["capability"])][_age(rid)] = {
                f["finding_id"] for f in run["findings"]
            }
        dropped = 0
        for lane, ages in by_lane.items():
            assert set(ages) == {21, 7, 0}, lane
            assert ages[7] <= ages[21], lane
            assert ages[0] <= ages[7], lane
            dropped += len(ages[21] - ages[0])
        assert dropped > 0, "No finding is ever dropped, so nothing in the demo is fixed."

    def test_no_two_findings_in_one_run_share_an_identity(self, two_seedings) -> None:
        first, _ = two_seedings
        for rid, run in first["runs"].items():
            ids = [f["finding_id"] for f in run["findings"]]
            assert len(ids) == len(set(ids)), rid


class TestTheSeedLeavesTheDemoSettled:
    """The rebuild returns compacted and reconciled, not waiting on a sweep."""

    def _cli_after_last_ingest(self, seeding: dict) -> list[list[str]]:
        events = seeding["events"]
        last_ingest = max(
            i for i, e in enumerate(events)
            if e["kind"] == "http" and str(e["path"]).startswith("/api/ingest/")
        )
        return [e["argv"] for e in events[last_ingest + 1 :] if e["kind"] == "cli"]

    def test_it_compacts_then_reconciles_absences_after_the_last_ingest(
        self, two_seedings
    ) -> None:
        first, _ = two_seedings
        commands = [
            argv[argv.index("mykronos.cli") + 1]
            for argv in self._cli_after_last_ingest(first)
            if "mykronos.cli" in argv
        ]
        assert "compact" in commands, (
            "Nothing compacts after seeding, so every page is empty until the "
            "scheduled compaction folds the write-ahead buffer."
        )
        assert "reconcile-absences" in commands, (
            "Nothing reconciles absences after seeding, so the dropped findings "
            "wait for the hourly sweep to close."
        )
        assert commands.index("compact") < commands.index("reconcile-absences"), (
            "Absence reconciliation reads the lake, so the buffer must be "
            "compacted first or it sees no scan runs."
        )

    def test_the_rebuild_script_runs_the_seed_without_skipping_the_settle(self) -> None:
        rebuild = (SEED.parent / "Invoke-DemoRebuild.ps1").read_text(encoding="utf-8")
        seed_lines = [ln for ln in rebuild.splitlines() if "/tmp/seed.py --url" in ln]
        assert seed_lines, "Invoke-DemoRebuild.ps1 no longer runs the seed."
        for line in seed_lines:
            assert "--no-settle" not in line
