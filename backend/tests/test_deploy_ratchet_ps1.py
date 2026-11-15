"""deploy.ps1 asks the ratchet and fails closed (D-182).

Supersedes the fail-open posture (D-126) and "only the floor refuses"
(D-159): the deploy asks `GET /api/oracle/deploy-gate` with the running
image's build stamp as the baseline, and anything but an explicit allow stops
before anything is pulled - a refusal, a sha nothing has scored, and a
platform that could not be asked. `-Force` still ships, only with a
`-ForceReason`, recorded in the ledger before the pull.

The whole of `deploy.ps1` runs here, as the earlier deploy tests did: copied
into a scratch tree with `-NoStart`, with `Invoke-RestMethod`, `docker` and
`Start-Sleep` shadowed, so it reaches a real verdict and a real ledger line
and pulls nothing. The `Invoke-RestMethod` stand-in serves the ratchet's
answers in order and records every URL it was asked.
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
RUNNING = "0e9a8886" + "0" * 32

pytestmark = pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh is not on PATH")


def ratchet(allow: bool, *codes: str, **extra: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "repo_full_name": "ToddGBenson/mykronos",
        "commit_sha": TAG,
        "deployed_sha": RUNNING,
        "baseline_source": "this process (MYKRONOS_BUILD_SHA)",
        "verdict": "allow" if allow else "refuse",
        "allow": allow,
        "reasons": [{"code": c, "message": f"because {c}"} for c in codes],
        "candidate_score": 41.0,
        "baseline_score": 40.0,
        "score_delta": 1.0,
        "tolerance": 0.5,
        "no_go_threshold": 70.0,
        "policy_version": "1.19",
        "direction": "forward",
        "range_commits": [TAG],
        "introduced": {},
        "fixed": {},
        "introduced_blocking_ids": [],
        "candidate_decision": {"decision_id": "dec-1"},
        "latch": {"latched": False},
    }
    body.update(extra)
    return body


ALLOW = ratchet(True, "not_raised")
RAISED = ratchet(False, "score_raised")
NO_DECISION = ratchet(False, "no_decision", candidate_decision=None)


def deploy(
    tmp_path: Path, answers: list[Any], *extra: str, wait_minutes: int = 0,
    running: str | None = RUNNING, env: str = "MYKRONOS_VIEWER_TOKEN=t\n",
) -> tuple[int, str, list[dict], list[str]]:
    """Run deploy.ps1 -NoStart; ratchet `answers` play back in order
    ("THROW" = timeout). Returns (exit, output, ledger, ratchet URLs asked)."""
    tree = tmp_path / "tree"
    (tree / "deploy" / "mykronos").mkdir(parents=True)
    (tree / "backend").mkdir()
    shutil.copy(SCRIPT, tree / "deploy" / "mykronos" / "deploy.ps1")
    shutil.copy(SCRIPT.parent / "DeployLock.ps1", tree / "deploy" / "mykronos" / "DeployLock.ps1")
    (tree / "backend" / ".env").write_text(env, encoding="utf-8")
    fixture = tmp_path / "answers.json"
    fixture.write_text(json.dumps(answers), encoding="utf-8")
    asked = tmp_path / "asked.txt"
    args = " ".join(f"'{a}'" if " " in a else a for a in extra)
    stamp = f"MYKRONOS_BUILD_SHA={running}" if running else ""
    program = f"""
$env:MYKRONOS_DEPLOY_LOCK_DIR = '{tmp_path / "deploy.lock"}'
$global:Answers = @(Get-Content -Raw '{fixture}' | ConvertFrom-Json)
$global:Asked = 0
function Invoke-RestMethod {{
  param([string]$Uri, [string]$Method, $Headers, $Body, $ContentType, $TimeoutSec)
  if ($Uri -notlike '*deploy-gate*') {{
    # by-commit, for the nearest-scored hint: nothing scored anything.
    return [pscustomobject]@{{ found = $false }}
  }}
  Add-Content -Path '{asked}' -Value $Uri
  $i = [Math]::Min($global:Asked, $global:Answers.Count - 1)
  $global:Asked++
  $a = $global:Answers[$i]
  if ($a -is [string] -and $a -eq 'THROW') {{
    throw 'The request was canceled: HttpClient.Timeout of 60 seconds elapsed.'
  }}
  return $a
}}
function docker {{
  $global:LASTEXITCODE = 0
  if ($args -contains 'inspect') {{ '{stamp}' }}
}}
function git {{ $global:LASTEXITCODE = 1 }}
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
        capture_output=True, text=True, encoding="utf-8", timeout=180,
    )
    ledger_path = tree / "deploy" / "mykronos" / "deploy-risk-log.jsonl"
    ledger = (
        [json.loads(line) for line in ledger_path.read_text(encoding="utf-8").splitlines()]
        if ledger_path.exists() else []
    )
    urls = asked.read_text(encoding="utf-8").splitlines() if asked.exists() else []
    return out.returncode, out.stdout + out.stderr, ledger, urls


class TestTheRatchetDecides:
    def test_an_allow_is_one_quiet_line_and_ships(self, tmp_path: Path) -> None:
        code, output, ledger, urls = deploy(tmp_path, [ALLOW])

        assert code == 0, output
        assert "Risk gate: allow for abc1234 over 0e9a88860000" in output
        assert "Pulling images" in output
        assert "BANNER" not in output and "REFUSED" not in output
        assert [(e["event"], e["state"]) for e in ledger] == [("checked", "allow")]

    def test_it_asks_with_the_running_build_stamp_as_the_baseline(
        self, tmp_path: Path
    ) -> None:
        _, _, _, urls = deploy(tmp_path, [ALLOW])

        assert len(urls) == 1
        assert "/api/oracle/deploy-gate?" in urls[0]
        assert "repo=ToddGBenson%2Fmykronos" in urls[0]
        assert f"commit={TAG}" in urls[0]
        assert f"deployed={RUNNING}" in urls[0]

    def test_with_nothing_running_it_asks_without_a_baseline(self, tmp_path: Path) -> None:
        """The platform answers baseline_unknown, or uses its own stamp."""
        _, _, _, urls = deploy(tmp_path, [ALLOW], running=None)

        assert "deployed=" not in urls[0]

    @pytest.mark.parametrize(
        "codes",
        [("score_raised",), ("introduced_blocking",), ("latched_no_go",),
         ("baseline_unknown",), ("baseline_disagrees",), ("evaluation_failed",),
         ("no_decision", "baseline_unknown")],
    )
    def test_a_refusal_stops_before_anything_is_pulled(
        self, tmp_path: Path, codes: tuple[str, ...]
    ) -> None:
        code, output, ledger, _ = deploy(tmp_path, [ratchet(False, *codes)])

        assert code == 3, output
        assert "Pulling images" not in output
        assert "DEPLOY-PRE-MOVE-REFUSAL kind=risk_refused" in output
        for c in codes:
            assert f"[{c}] because {c}" in output
        assert [(e["event"], e["kind"]) for e in ledger] == [("refused", "risk_refused")]
        assert ledger[0]["codes"] == list(codes)

    @pytest.mark.parametrize(
        "answer",
        [
            {**ALLOW, "allow": "true"},
            {**ALLOW, "verdict": "refuse"},
            {**ALLOW, "allow": None},
        ],
        ids=["string-true", "verdict-not-allow", "null"],
    )
    def test_anything_but_an_explicit_allow_refuses(
        self, tmp_path: Path, answer: dict[str, Any]
    ) -> None:
        code, output, _, _ = deploy(tmp_path, [answer])

        assert code == 3, output
        assert "Pulling images" not in output


class TestItFailsClosed:
    def test_an_unreachable_platform_is_a_refusal(self, tmp_path: Path) -> None:
        """D-126 shipped this with a banner. D-182: it stops."""
        code, output, ledger, _ = deploy(tmp_path, ["THROW"])

        assert code == 3, output
        assert "COULD NOT ASK" in output
        assert "Pulling images" not in output
        assert "DEPLOY-PRE-MOVE-REFUSAL kind=risk_unasked" in output
        assert [(e["event"], e["state"]) for e in ledger] == [("refused", "unasked")]

    def test_an_answer_that_is_not_a_verdict_is_a_refusal(self, tmp_path: Path) -> None:
        code, output, _, _ = deploy(tmp_path, [{"detail": "Not Found"}])

        assert code == 3, output
        assert "not with a ratchet verdict" in output
        assert "kind=risk_unasked" in output

    def test_no_token_is_a_refusal(self, tmp_path: Path) -> None:
        code, output, _, urls = deploy(tmp_path, [ALLOW], env="OTHER=1\n")

        assert code == 3, output
        assert "no credential to ask with" in output
        assert urls == []

    def test_a_sha_nothing_scored_is_not_judged_and_refused(self, tmp_path: Path) -> None:
        code, output, ledger, _ = deploy(tmp_path, [NO_DECISION])

        assert code == 3, output
        assert "NOT JUDGED" in output
        assert "kind=risk_not_judged" in output
        assert "last green sha" in output
        assert [(e["event"], e["state"]) for e in ledger] == [("refused", "unjudged")]


class TestItWaitsForTheGate:
    def test_it_waits_for_a_decision_and_then_follows_it(self, tmp_path: Path) -> None:
        code, output, ledger, urls = deploy(
            tmp_path, [NO_DECISION, NO_DECISION, ALLOW], wait_minutes=45
        )

        assert code == 0, output
        assert "Waiting up to 45 minutes" in output
        assert len(urls) == 3
        assert ledger[-1]["state"] == "allow"

    def test_one_timeout_mid_wait_keeps_waiting(self, tmp_path: Path) -> None:
        code, output, ledger, _ = deploy(
            tmp_path, [NO_DECISION, "THROW", NO_DECISION, RAISED], wait_minutes=45
        )

        assert code == 3, output
        assert "a poll went unanswered (1 so far)" in output
        assert "COULD NOT ASK" not in output
        assert ledger[-1]["codes"] == ["score_raised"]

    def test_an_unreachable_platform_at_the_first_ask_does_not_wait(
        self, tmp_path: Path
    ) -> None:
        _, output, _, urls = deploy(tmp_path, ["THROW", ALLOW], wait_minutes=45)

        assert "Waiting up to" not in output
        assert len(urls) == 1


class TestForceIsTheOperatorsOverride:
    def test_force_with_a_reason_ships_a_refusal_and_records_it_first(
        self, tmp_path: Path
    ) -> None:
        code, output, ledger, _ = deploy(
            tmp_path, [RAISED], "-Force", "-ForceReason", "hotfix for the sealed vault"
        )

        assert code == 0, output
        assert "OVERRIDDEN" in output
        assert output.index("Override recorded") < output.index("Pulling images")
        assert [(e["event"], e["reason"], e["codes"]) for e in ledger] == [
            ("override", "hotfix for the sealed vault", ["score_raised"])
        ]

    def test_force_ships_through_an_unreachable_platform_with_a_reason(
        self, tmp_path: Path
    ) -> None:
        code, output, ledger, _ = deploy(
            tmp_path, ["THROW"], "-Force", "-ForceReason", "backend down, this is its fix"
        )

        assert code == 0, output
        assert [(e["event"], e["state"]) for e in ledger] == [("override", "unasked")]

    def test_force_without_a_reason_is_rejected_before_asking(self, tmp_path: Path) -> None:
        code, output, ledger, urls = deploy(tmp_path, [RAISED], "-Force")

        assert code == 3, output
        assert "-Force needs -ForceReason" in output
        assert ledger == [] and urls == []

    def test_force_on_an_allow_has_nothing_to_override(self, tmp_path: Path) -> None:
        code, output, ledger, _ = deploy(
            tmp_path, [ALLOW], "-Force", "-ForceReason", "not needed any more at all"
        )

        assert code == 0
        assert "there was nothing to override" in output
        assert [e["event"] for e in ledger] == ["checked"]


def test_the_fail_open_path_is_gone() -> None:
    """No branch of the gate proceeds on "could not ask" without -Force."""
    text = SCRIPT.read_text(encoding="utf-8")
    assert "Proceeding: the decided posture is fail open" not in text
    assert 'State = "backlog"' not in text.split("function Get-RatchetVerdict")[1]
