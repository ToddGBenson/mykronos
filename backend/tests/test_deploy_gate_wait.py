"""deploy.ps1's wait for the risk gate survives one unanswered poll.

On 2026-10-15 `deploy.ps1 -Tag 9a2eec4` waited for the gate, as #735 has it
do. Forty minutes in, one poll took longer than its 10 s timeout. The wait
loop only continued while the verdict was "unjudged", so that one miss ended
it, and the commit shipped as COULD NOT ASK while its gate was minutes away
from deciding. The fallback for an unreachable platform is deliberate (D-126:
fail open); a single slow answer in the middle of a wait is not that.

The whole of `deploy.ps1` runs here, as in test_deploy_follows_d048.py: copied
into a scratch tree with `-NoStart`, and `Invoke-RestMethod`, `docker` and
`Start-Sleep` shadowed. `Invoke-RestMethod` plays back a script of answers,
where "THROW" is a timeout, and repeats the last one when the script runs out.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "deploy" / "mykronos" / "deploy.ps1"
TAG = "abc1234"

UNSCORED: dict[str, Any] = {
    "commit_sha": TAG,
    "found": False,
    "recommendation": None,
    "effective_recommendation": None,
    "overridden": False,
    "decision_id": None,
    "introduced": {},
    "disclosed": {},
    "introduced_blocking": False,
}
CLEAN: dict[str, Any] = UNSCORED | {
    "found": True,
    "recommendation": "go",
    "effective_recommendation": "go",
    "decision_id": "dec-1",
    "decision_type": "commit_gate",
    "repo_full_name": "ToddGBenson/mykronos",
    "overall_risk_score": 10,
    "reasoning": "clean",
    "policy_version": "v1",
    "evaluated_at": "2026-10-15T03:50:00",
}

needs_pwsh = pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh is not on PATH")


def deploy(tmp_path: Path, answers: list[Any], wait_minutes: int = 45) -> tuple[str, list[dict]]:
    tree = tmp_path / "tree"
    (tree / "deploy" / "mykronos").mkdir(parents=True)
    (tree / "backend").mkdir()
    shutil.copy(SCRIPT, tree / "deploy" / "mykronos" / "deploy.ps1")
    (tree / "backend" / ".env").write_text("MYKRONOS_VIEWER_TOKEN=t\n", encoding="utf-8")
    fixture = tmp_path / "answers.json"
    fixture.write_text(json.dumps(answers), encoding="utf-8")
    program = f"""
$global:Answers = Get-Content -Raw '{fixture}' | ConvertFrom-Json
$global:Asked = 0
function Invoke-RestMethod {{
  $i = [Math]::Min($global:Asked, $global:Answers.Count - 1)
  $global:Asked++
  $a = $global:Answers[$i]
  if ($a -is [string] -and $a -eq 'THROW') {{
    throw 'The request was canceled: HttpClient.Timeout of 10 seconds elapsed.'
  }}
  return $a
}}
function docker {{ $global:LASTEXITCODE = 0 }}
function Start-Sleep {{ }}
try {{
  & '{tree / "deploy" / "mykronos" / "deploy.ps1"}' -Tag {TAG} -NoStart `
    -GateWaitMinutes {wait_minutes} *>&1 | ForEach-Object {{ "$_" }}
  "ASKED: $global:Asked"
  exit 0
}} catch {{
  "THROWN: $($_.Exception.Message)"
  exit 3
}}
"""
    out = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", program],
        capture_output=True, text=True, encoding="utf-8", timeout=120,
    )
    ledger_path = tree / "deploy" / "mykronos" / "deploy-risk-log.jsonl"
    ledger = (
        [json.loads(line) for line in ledger_path.read_text(encoding="utf-8").splitlines()]
        if ledger_path.exists() else []
    )
    return out.stdout + out.stderr, ledger


@needs_pwsh
class TestTheWaitSurvivesAMiss:
    def test_one_timeout_mid_wait_keeps_waiting_for_the_decision(self, tmp_path: Path) -> None:
        output, ledger = deploy(tmp_path, [UNSCORED, UNSCORED, "THROW", UNSCORED, CLEAN])
        assert "a poll went unanswered (1 so far)" in output
        assert "COULD NOT ASK" not in output
        assert ledger[-1]["state"] == "clean", ledger

    def test_several_timeouts_still_reach_the_decision(self, tmp_path: Path) -> None:
        output, ledger = deploy(tmp_path, [UNSCORED, "THROW", "THROW", "THROW", CLEAN])
        assert "COULD NOT ASK" not in output
        assert ledger[-1]["state"] == "clean", ledger


@needs_pwsh
class TestWhatStillFailsOpen:
    def test_an_unreachable_platform_at_the_first_ask_is_still_could_not_ask(
        self, tmp_path: Path
    ) -> None:
        """D-126: no answer at all is a banner and a deploy, never a wait."""
        output, ledger = deploy(tmp_path, ["THROW"])
        assert "COULD NOT ASK" in output
        assert ledger[-1]["state"] == "unasked", ledger
