"""TheHub's gate blocks on what a commit introduced — D-083.

It used to block on the composite score. D-048 had already written down why
that does not work, for the mykronos pipeline: the score describes the whole
estate, so a repository carrying a large accepted backlog refuses every commit
regardless of content, "and a gate that refuses everything gets switched off
or routed around".

That is precisely what happened. TheHub's gate refused everything, and on
2026-08-18 it was switched off by an operator. The lesson had been learned
once, for one pipeline, and left unapplied to the other.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml

PIPELINES = Path(__file__).resolve().parents[2] / "deploy" / "concourse" / "pipelines"


def gate_script(pipeline: str) -> str:
    document = yaml.safe_load((PIPELINES / pipeline).read_text(encoding="utf-8"))
    for job in document["jobs"]:
        if job["name"] != "oracle-gate":
            continue
        for step in job.get("plan", []):
            run = (step.get("config") or {}).get("run") or {}
            if run.get("path") == "bash" and "INTRODUCED_BLOCKING" in str(run.get("args")):
                return run["args"][-1]
    raise AssertionError(f"no oracle-gate task in {pipeline} blocks on introduced findings")


@pytest.mark.parametrize("pipeline", ["thehub.yml", "mykronos.yml"])
class TestBothGatesUseTheSameRule:
    """The point of porting it: one rule, not two pipelines drifting apart."""

    def test_it_blocks_on_introduced_findings(self, pipeline: str) -> None:
        assert "INTRODUCED_BLOCKING" in gate_script(pipeline)

    def test_the_score_does_not_decide(self, pipeline: str) -> None:
        """The score is still evaluated, recorded and reported. What it must
        not do is gate the deploy — that is the whole of D-048."""
        script = gate_script(pipeline)

        # The only `exit 1` in the gate is the introduced-findings one.
        blocking_exits = [
            line for line in script.splitlines() if line.strip() == "exit 1"
        ]
        assert len(blocking_exits) == 1, script

    def test_it_still_reports_the_score(self, pipeline: str) -> None:
        """Dropping the score entirely would be the opposite mistake: the
        backlog is real and a gate that never mentions it hides it."""
        script = gate_script(pipeline)

        assert "no_go" in script
        assert "SCORE" in script

    def test_the_script_is_valid_shell(self, pipeline: str) -> None:
        """These are long heredoc-free bash bodies assembled by hand, and a
        syntax error only shows up when the lane runs."""
        result = subprocess.run(
            ["bash", "-n"], input=gate_script(pipeline), text=True, capture_output=True
        )

        assert result.returncode == 0, result.stderr


class TestOnlyTrueOrFalseIsAVerdict:
    """thehub/oracle-gate failed only on `introduced_blocking == "true"`, so a
    decision with the field missing or null (`jq -r` prints "null") passed --
    a verdict nobody rendered, read as "nothing new blocks"."""

    @staticmethod
    def _verdict(value: str, blocking: str = "true") -> subprocess.CompletedProcess[str]:
        """Run the gate's verdict block alone: from `REFUSE=1` to its `fi`."""
        lines = gate_script("thehub.yml").splitlines()
        start = next(i for i, line in enumerate(lines) if line.strip() == "REFUSE=1")
        end = next(
            i
            for i in range(start, len(lines))
            if lines[i].strip() == 'if [ "$REFUSE" -ne 0 ]; then'
        )
        block = "\n".join(lines[start : end + 3]).replace("../notify/message.txt", "/dev/null")
        prelude = (
            f'SHORT=abc1234\nNEW_CRITICAL=0\nNEW_HIGH=1\nORACLE_BLOCKING="{blocking}"\n'
            f'INTRODUCED_BLOCKING="{value}"\n'
        )
        script = prelude + block + "\necho decided\n"
        return subprocess.run(["bash", "-c", script], text=True, capture_output=True)

    @pytest.mark.parametrize("value", ["null", "", "True", "1", "yes"])
    def test_what_is_not_a_verdict_fails_the_gate(self, value: str) -> None:
        result = self._verdict(value)
        assert result.returncode == 1, result.stdout + result.stderr
        assert "not true or false" in result.stdout

    def test_the_off_switch_does_not_waive_a_missing_verdict(self) -> None:
        result = self._verdict("null", blocking="false")
        assert result.returncode == 1, result.stdout + result.stderr

    def test_false_passes_and_true_blocks(self) -> None:
        passed = self._verdict("false")
        assert passed.returncode == 0 and "decided" in passed.stdout, passed.stderr
        assert self._verdict("true").returncode == 1


class TestTheOverrideSurvivesButIsOn:
    """The escape hatch stays — a control switched off invisibly is worse than
    one switched off loudly (D-081) — but its reason for being off is gone."""

    @staticmethod
    def _setter() -> str:
        return (
            PIPELINES.parent / "set-thehub-pipeline.ps1"
        ).read_text(encoding="utf-8")

    def test_blocking_defaults_to_true_again(self) -> None:
        assert '$OracleBlocking = "true"' in self._setter()

    def test_the_override_still_exists(self) -> None:
        """Removing it would repeat the mistake it was created to fix: the
        2026-08-18 override lived only in a working tree, so the repository
        said the gate blocked while the applied pipeline let everything
        through."""
        assert "thehub-oracle-blocking" in self._setter()

    def test_taking_the_override_is_announced(self) -> None:
        script = gate_script("thehub.yml")

        assert "NON-BLOCKING" in script
        assert "NOT a passing risk decision" in script
