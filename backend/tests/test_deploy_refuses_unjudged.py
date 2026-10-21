"""deploy.ps1 refuses a sha nothing has scored, and fails open only when it cannot ask.

Concourse scores only a commit that passed every lane. A sha whose `unit` lane
is red therefore never gets a risk decision, and `deploy.ps1` used to print
NOT JUDGED and ship it: the commit went out unassessed precisely because it
was broken. D-126's fail-open posture was decided for "could not ask" (the
platform unreachable, Vault sealed), not for "asked, and nothing scored this".

So "unjudged" now refuses unless `-Force -ForceReason` is given, recorded in
the ledger before anything is pulled; "unasked" still warns and proceeds.

The whole of `deploy.ps1` runs here, as in test_deploy_follows_d048.py: copied
into a scratch tree with `-NoStart`, with `Invoke-RestMethod`, `docker` and
`Start-Sleep` shadowed, so it reaches a real verdict and a real ledger line and
pulls nothing.
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

pytestmark = pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh is not on PATH")


def deploy(
    tmp_path: Path, answers: list[Any], *extra: str, wait_minutes: int = 0
) -> tuple[int, str, list[dict]]:
    """Run deploy.ps1 -NoStart; `answers` plays back in order ("THROW" = timeout)."""
    tree = tmp_path / "tree"
    (tree / "deploy" / "mykronos").mkdir(parents=True)
    (tree / "backend").mkdir()
    shutil.copy(SCRIPT, tree / "deploy" / "mykronos" / "deploy.ps1")
    (tree / "backend" / ".env").write_text("MYKRONOS_VIEWER_TOKEN=t\n", encoding="utf-8")
    fixture = tmp_path / "answers.json"
    fixture.write_text(json.dumps(answers), encoding="utf-8")
    args = " ".join(f"'{a}'" if " " in a else a for a in extra)
    program = f"""
$global:Answers = @(Get-Content -Raw '{fixture}' | ConvertFrom-Json)
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
    -GateWaitMinutes {wait_minutes} {args} *>&1 | ForEach-Object {{ "$_" }}
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
    return out.returncode, out.stdout + out.stderr, ledger


class TestUnjudgedRefuses:
    def test_a_sha_nothing_scored_is_refused_and_nothing_is_pulled(
        self, tmp_path: Path
    ) -> None:
        code, output, ledger = deploy(tmp_path, [UNSCORED])

        assert code == 3, output
        assert "Pulling images" not in output, "an unjudged sha must not be pulled"
        assert [(e["event"], e["state"]) for e in ledger] == [("refused", "unjudged")]

    def test_the_refusal_says_wait_or_deploy_the_last_green_sha(
        self, tmp_path: Path
    ) -> None:
        _, output, _ = deploy(tmp_path, [UNSCORED])

        assert "about 30 minutes after Delivery" in output
        assert "last green sha" in output
        assert "-Force -ForceReason" in output

    def test_force_with_a_reason_ships_it_and_records_the_override(
        self, tmp_path: Path
    ) -> None:
        code, output, ledger = deploy(
            tmp_path, [UNSCORED], "-Force", "-ForceReason", "unit lane red on a flaky test only"
        )

        assert code == 0, output
        assert "OVERRIDDEN - SHIPPING A SHA NOTHING HAS SCORED" in output
        assert "Pulling images" in output
        assert "there was nothing to override" not in output
        assert [(e["event"], e["state"], e["reason"]) for e in ledger] == [
            ("override", "unjudged", "unit lane red on a flaky test only")
        ]

    def test_force_without_a_reason_is_still_rejected(self, tmp_path: Path) -> None:
        code, output, ledger = deploy(tmp_path, [UNSCORED], "-Force")

        assert code == 3, output
        assert "-Force needs -ForceReason" in output
        assert ledger == []


class TestUnaskedStillFailsOpen:
    def test_an_unreachable_platform_warns_and_proceeds(self, tmp_path: Path) -> None:
        """D-126: could not ask is a banner and a deploy, never a refusal."""
        code, output, ledger = deploy(tmp_path, ["THROW"])

        assert code == 0, output
        assert "COULD NOT ASK" in output
        assert "Pulling images" in output
        assert [(e["event"], e["state"]) for e in ledger] == [("checked", "unasked")]
