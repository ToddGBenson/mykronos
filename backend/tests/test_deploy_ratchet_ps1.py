"""deploy.ps1 asks the ratchet and fails closed (D-183).

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

import hashlib
import hmac
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
    ledger_unwritable: bool = False, tag: str = TAG, down: bool = False,
    with_deploying: bool = False, start: bool = False, stamps: list[str] | None = None,
) -> tuple[int, str, list[dict], list[str]]:
    """Run deploy.ps1 -NoStart; ratchet `answers` play back in order
    ("THROW" = timeout). Returns (exit, output, ledger, ratchet URLs asked).
    `ledger_unwritable` puts a directory where the ledger file goes. `down`
    makes every request fail, as a stopped backend does. The tree (and so
    the ledger) is kept between calls with the same `tmp_path`. The
    `deploying` lines every deploy writes before its pull are left out of
    the returned ledger unless `with_deploying`. `start` runs past the pull
    (no -NoStart): compose and the health wait are faked healthy, and
    `stamps` are the running build stamps `docker inspect` reports, in order
    (before the deploy, then after it)."""
    tree = tmp_path / "tree"
    (tree / "deploy" / "mykronos").mkdir(parents=True, exist_ok=True)
    if ledger_unwritable:
        (tree / "deploy" / "mykronos" / "deploy-risk-log.jsonl").mkdir()
    (tree / "backend").mkdir(exist_ok=True)
    shutil.copy(SCRIPT, tree / "deploy" / "mykronos" / "deploy.ps1")
    shutil.copy(SCRIPT.parent / "DeployLock.ps1", tree / "deploy" / "mykronos" / "DeployLock.ps1")
    (tree / "backend" / ".env").write_text(env, encoding="utf-8")
    fixture = tmp_path / "answers.json"
    fixture.write_text(json.dumps(answers), encoding="utf-8")
    asked = tmp_path / "asked.txt"
    asked.unlink(missing_ok=True)
    args = " ".join(f"'{a}'" if " " in a else a for a in extra)
    stamp = f"MYKRONOS_BUILD_SHA={running}" if running else ""
    down_ps = "true" if down else "false"
    stamp_list = json.dumps([f"MYKRONOS_BUILD_SHA={s}" for s in (stamps or [])])
    no_start = "" if start else "-NoStart"
    program = f"""
$env:MYKRONOS_DEPLOY_LOCK_DIR = '{tmp_path / "deploy.lock"}'
$global:Answers = @(Get-Content -Raw '{fixture}' | ConvertFrom-Json)
$global:Asked = 0
function Invoke-RestMethod {{
  param([string]$Uri, [string]$Method, $Headers, $Body, $ContentType, $TimeoutSec)
  if (${down_ps}) {{
    Add-Content -Path '{asked}' -Value $Uri
    throw 'No connection could be made because the target machine actively refused it.'
  }}
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
$global:Stamps = @('{stamp_list}' | ConvertFrom-Json)
$global:StampAt = 0
function docker {{
  $global:LASTEXITCODE = 0
  $joined = $args -join ' '
  if ($joined -like '*Health.Status*') {{ return 'healthy' }}
  if ($joined -like '*State.Status*') {{ return 'running' }}
  if ($args -contains 'inspect') {{
    if ($global:Stamps.Count -gt 0) {{
      $s = $global:Stamps[[Math]::Min($global:StampAt, $global:Stamps.Count - 1)]
      $global:StampAt++
      return $s
    }}
    '{stamp}'
  }}
}}
function git {{ $global:LASTEXITCODE = 1 }}
function Start-Sleep {{ }}
try {{
  & '{tree / "deploy" / "mykronos" / "deploy.ps1"}' -Tag {tag} {no_start} `
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
        [_parse(line) for line in ledger_path.read_text(encoding="utf-8").splitlines()]
        if ledger_path.is_file() else []
    )
    if not with_deploying:
        ledger = [e for e in ledger if e.get("event") != "deploying"]
    urls = asked.read_text(encoding="utf-8").splitlines() if asked.exists() else []
    return out.returncode, out.stdout + out.stderr, ledger, urls


def _parse(line: str) -> dict[str, Any]:
    try:
        value = json.loads(line)
    except ValueError:
        return {"event": "<not json>"}
    return value if isinstance(value, dict) else {"event": "<not json>"}


class TestTheRatchetDecides:
    def test_an_allow_is_one_quiet_line_and_ships(self, tmp_path: Path) -> None:
        code, output, ledger, urls = deploy(tmp_path, [ALLOW])

        assert code == 0, output
        assert "Risk gate: allow for abc1234 over 0e9a88860000" in output
        assert "Pulling images" in output
        assert "BANNER" not in output and "REFUSED" not in output
        assert [(e["event"], e["state"]) for e in ledger] == [("checked", "allow")]
        assert ledger[0]["asked"] == "http://127.0.0.1:8100"
        assert "Fix credit pending" not in output

    def test_an_allow_says_when_fix_credit_is_pending(self, tmp_path: Path) -> None:
        code, output, _, _ = deploy(tmp_path, [{**ALLOW, "fix_credit_pending": 3}])

        assert code == 0, output
        assert "Fix credit pending: 3 finding(s)" in output

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
        """D-126 shipped this with a banner. D-183: it stops."""
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


class TestItAsksOnlyTheProductionBackend:
    """B5: since the gate fails closed, the address it asks is the gate."""

    def test_another_platform_url_is_rejected_before_asking(self, tmp_path: Path) -> None:
        code, output, ledger, urls = deploy(
            tmp_path, [ALLOW], "-PlatformUrl", "http://127.0.0.1:9999"
        )

        assert code == 3, output
        assert "-PlatformUrl must be http://127.0.0.1:8100" in output
        assert "Pulling images" not in output
        assert urls == [] and ledger == []

    def test_there_is_no_repo_parameter(self, tmp_path: Path) -> None:
        code, output, _, urls = deploy(tmp_path, [ALLOW], "-Repo", "someone/else")

        assert code == 3, output
        assert "Pulling images" not in output
        assert urls == []


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

    def test_several_timeouts_still_reach_the_decision(self, tmp_path: Path) -> None:
        """Ten misses in a row: reported at the first and the tenth, and the
        wait still ends on the gate's answer."""
        code, output, ledger, urls = deploy(
            tmp_path, [NO_DECISION, *(["THROW"] * 10), NO_DECISION, ALLOW], wait_minutes=45
        )

        assert code == 0, output
        assert "a poll went unanswered (1 so far)" in output
        assert "a poll went unanswered (10 so far)" in output
        assert "(2 so far)" not in output
        assert "COULD NOT ASK" not in output
        assert len(urls) == 13
        assert ledger[-1]["state"] == "allow"

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

    def test_force_ships_an_unjudged_sha_with_a_reason(self, tmp_path: Path) -> None:
        code, output, ledger, _ = deploy(
            tmp_path, [NO_DECISION], "-Force", "-ForceReason", "the gate is down for hours"
        )

        assert code == 0, output
        assert "OVERRIDDEN" in output and "NOT JUDGED" in output
        assert output.index("Override recorded") < output.index("Pulling images")
        assert [(e["event"], e["state"], e["kind"]) for e in ledger] == [
            ("override", "unjudged", "risk_not_judged")
        ]

    def test_an_override_that_cannot_be_recorded_does_not_ship(self, tmp_path: Path) -> None:
        code, output, _, _ = deploy(
            tmp_path, [RAISED], "-Force", "-ForceReason", "hotfix for the sealed vault",
            ledger_unwritable=True,
        )

        assert code == 3, output
        assert "DEPLOY-PRE-MOVE-REFUSAL kind=override_unrecorded" in output
        assert "Pulling images" not in output

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


# -- D-183 restore (operator decision 2026-11-15: "Allow restore of the prior sha")

FAILED = "abc1234" + "0" * 33  # the stamp of the deploy that failed health
OTHER = "5" * 40


def _ledger_path(tmp_path: Path) -> Path:
    return tmp_path / "tree" / "deploy" / "mykronos" / "deploy-risk-log.jsonl"


class TestARollbackRestoresThePriorSha:
    """The watcher's rollback runs when the new stack is unhealthy, which is
    when the backend that answers the ratchet may be down. It may ship the
    sha the failed deploy replaced, read from deploy.ps1's own signed ledger
    line, without asking; anything else still fails closed."""

    def _failed_deploy(self, tmp_path: Path) -> None:
        code, output, _, _ = deploy(tmp_path, [ALLOW])
        assert code == 0, output

    def test_the_deploy_records_what_it_replaces_before_the_pull(self, tmp_path: Path) -> None:
        code, output, ledger, _ = deploy(tmp_path, [ALLOW], with_deploying=True)

        assert code == 0, output
        assert [e["event"] for e in ledger] == ["checked", "deploying"]
        assert ledger[1]["previous"] == RUNNING and ledger[1]["tag"] == TAG
        assert len(ledger[1]["mac"]) == 64

    def test_with_the_backend_down_the_restore_ships(self, tmp_path: Path) -> None:
        self._failed_deploy(tmp_path)

        code, output, ledger, urls = deploy(
            tmp_path, [], "-Restore", tag=RUNNING, running=FAILED, down=True,
            with_deploying=True,
        )

        assert code == 0, output
        assert "Pulling images" in output
        assert "RESTORE of 0e9a88860000" in output
        assert urls == []  # nothing was asked: the backend is down
        assert [e["event"] for e in ledger] == ["checked", "deploying", "restore"]
        assert ledger[-1]["restores"] == RUNNING
        assert ledger[-1]["failed_deploy"] == TAG

    def test_a_restore_by_prefix_of_the_recorded_sha_ships(self, tmp_path: Path) -> None:
        """The running images may carry the shorter tag a hand deploy used."""
        self._failed_deploy(tmp_path)

        code, output, _, _ = deploy(
            tmp_path, [], "-Restore", tag=RUNNING[:12], running=FAILED, down=True
        )

        assert code == 0, output

    def test_any_other_sha_is_refused(self, tmp_path: Path) -> None:
        self._failed_deploy(tmp_path)

        code, output, ledger, urls = deploy(
            tmp_path, [], "-Restore", tag=OTHER, running=FAILED, down=True
        )

        assert code == 3, output
        assert "DEPLOY-PRE-MOVE-REFUSAL kind=restore_refused" in output
        assert "Pulling images" not in output
        assert urls == []
        assert (ledger[-1]["event"], ledger[-1]["kind"]) == ("refused", "restore_refused")

    def test_with_no_ledger_it_is_refused(self, tmp_path: Path) -> None:
        code, output, _, _ = deploy(
            tmp_path, [], "-Restore", tag=RUNNING, running=FAILED, down=True
        )

        assert code == 3, output
        assert "DEPLOY-PRE-MOVE-REFUSAL kind=restore_refused" in output
        assert "no deploy ledger" in output
        assert "Pulling images" not in output

    def test_an_edited_ledger_line_is_refused(self, tmp_path: Path) -> None:
        """Rewriting the recorded sha to make another one restorable."""
        self._failed_deploy(tmp_path)
        path = _ledger_path(tmp_path)
        lines = path.read_text(encoding="utf-8").splitlines()
        edited = []
        for line in lines:
            entry = json.loads(line)
            if entry["event"] == "deploying":
                entry["previous"] = OTHER
            edited.append(json.dumps(entry))
        path.write_text("\n".join(edited) + "\n", encoding="utf-8")

        code, output, _, _ = deploy(
            tmp_path, [], "-Restore", tag=OTHER, running=FAILED, down=True
        )

        assert code == 3, output
        assert "DEPLOY-PRE-MOVE-REFUSAL kind=restore_refused" in output
        assert "does not verify" in output

    def test_a_forged_deploying_line_is_refused(self, tmp_path: Path) -> None:
        """Appending a newer line without the host's token to sign it."""
        self._failed_deploy(tmp_path)
        with _ledger_path(tmp_path).open("a", encoding="utf-8") as f:
            f.write(json.dumps({"event": "deploying", "tag": "f" * 40, "previous": OTHER,
                                "nonce": "0" * 32, "mac": "0" * 64}) + "\n")

        code, output, _, _ = deploy(
            tmp_path, [], "-Restore", tag=OTHER, running=FAILED, down=True
        )

        assert code == 3, output
        assert "DEPLOY-PRE-MOVE-REFUSAL kind=restore_refused" in output

    def test_an_unreadable_ledger_is_refused(self, tmp_path: Path) -> None:
        self._failed_deploy(tmp_path)
        with _ledger_path(tmp_path).open("a", encoding="utf-8") as f:
            f.write("{not json\n")

        code, output, _, _ = deploy(
            tmp_path, [], "-Restore", tag=RUNNING, running=FAILED, down=True
        )

        assert code == 3, output
        assert "DEPLOY-PRE-MOVE-REFUSAL kind=restore_refused" in output
        assert "not JSON" in output

    def test_a_restore_never_makes_the_failed_sha_restorable(self, tmp_path: Path) -> None:
        self._failed_deploy(tmp_path)
        code, output, _, _ = deploy(
            tmp_path, [], "-Restore", tag=RUNNING, running=FAILED, down=True
        )
        assert code == 0, output

        code, output, _, _ = deploy(
            tmp_path, [], "-Restore", tag=FAILED, running=RUNNING, down=True
        )

        assert code == 3, output
        assert "DEPLOY-PRE-MOVE-REFUSAL kind=restore_refused" in output

    def test_a_restore_does_not_combine_with_force(self, tmp_path: Path) -> None:
        self._failed_deploy(tmp_path)

        code, output, _, _ = deploy(
            tmp_path, [], "-Restore", "-Force", "-ForceReason", "because it must ship now",
            tag=RUNNING, running=FAILED, down=True,
        )

        assert code == 3, output
        assert "DEPLOY-PRE-MOVE-REFUSAL kind=usage" in output

    def test_a_deploy_that_cannot_record_what_it_replaces_does_not_happen(
        self, tmp_path: Path
    ) -> None:
        code, output, _, _ = deploy(tmp_path, [ALLOW], ledger_unwritable=True)

        assert code == 3, output
        assert "DEPLOY-PRE-MOVE-REFUSAL kind=deploy_unrecorded" in output
        assert "Pulling images" not in output


class TestTheRestoreIsBoundToWhatRuns:
    """Re-review of ab9a17d7, non-blocking 1 and 4."""

    def test_a_replayed_older_deploy_line_cannot_re_target_it(self, tmp_path: Path) -> None:
        """Deploy 1 replaced RUNNING; deploy 2 (def5678) replaced deploy 1's
        sha. Deploy 1's line appended again, even re-signed with a fresh
        nonce by someone holding the token (so the nonce check cannot see
        it), must not make RUNNING restorable while deploy 2's build runs."""
        code, output, _, _ = deploy(tmp_path, [ALLOW])
        assert code == 0, output
        path = _ledger_path(tmp_path)
        first = next(line for line in path.read_text(encoding="utf-8").splitlines()
                     if json.loads(line)["event"] == "deploying")
        second_tag = "def5678"
        code, output, _, _ = deploy(tmp_path, [ALLOW], tag=second_tag, running=FAILED)
        assert code == 0, output
        replay = json.loads(first)
        replay["nonce"] = "1" * 32
        replay["mac"] = hmac.new(
            b"t", f"deploying|{replay['tag']}|{replay['previous']}|{replay['nonce']}".encode(),
            hashlib.sha256,
        ).hexdigest()
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(replay) + "\n")

        code, output, _, _ = deploy(
            tmp_path, [], "-Restore", tag=RUNNING, running=second_tag + "0" * 33, down=True
        )

        assert code == 3, output
        assert "DEPLOY-PRE-MOVE-REFUSAL kind=restore_refused" in output
        assert "the most recent recorded deploy" in output

    def test_with_the_running_stamp_unreadable_the_restore_ships(self, tmp_path: Path) -> None:
        code, output, _, _ = deploy(tmp_path, [ALLOW])
        assert code == 0, output

        code, output, _, _ = deploy(
            tmp_path, [], "-Restore", tag=RUNNING, running=None, down=True
        )

        assert code == 0, output

    def test_a_deploy_with_no_token_says_it_cannot_be_restored(self, tmp_path: Path) -> None:
        code, output, ledger, _ = deploy(
            tmp_path, ["THROW"], "-Force", "-ForceReason", "the platform is down and this fixes it",
            env="", with_deploying=True,
        )

        assert code == 0, output
        assert "cannot be restored with -Restore" in output
        deploying = [e for e in ledger if e["event"] == "deploying"]
        assert deploying and deploying[0]["mac"] is None


class TestTheRestoreIsConfirmedInFull:
    """Re-review of d7f34eff: the post-deploy check that a restore runs the
    full recorded sha, and the nonce replay check."""

    def _failed_deploy(self, tmp_path: Path) -> None:
        code, output, _, _ = deploy(tmp_path, [ALLOW])
        assert code == 0, output

    def test_a_restore_running_the_full_recorded_sha_is_confirmed(self, tmp_path: Path) -> None:
        self._failed_deploy(tmp_path)

        code, output, _, _ = deploy(
            tmp_path, [], "-Restore", tag=RUNNING[:12], down=True, start=True,
            stamps=[FAILED, RUNNING],
        )

        assert code == 0, output
        assert "Confirmed: the backend is running" in output
        assert "RESTORE MISMATCH" not in output

    def test_a_restore_running_another_sha_with_the_same_prefix_fails(
        self, tmp_path: Path
    ) -> None:
        self._failed_deploy(tmp_path)
        collision = RUNNING[:7] + "f" * 33

        code, output, _, _ = deploy(
            tmp_path, [], "-Restore", tag=RUNNING[:7], down=True, start=True,
            stamps=[FAILED, collision],
        )

        assert code == 3, output
        assert "RESTORE MISMATCH" in output
        assert "Confirmed: the backend is running" not in output

    def test_a_replayed_copy_of_the_latest_line_is_refused(self, tmp_path: Path) -> None:
        """A byte copy repeats the nonce; the stamp check alone passes it."""
        self._failed_deploy(tmp_path)
        path = _ledger_path(tmp_path)
        line = next(x for x in path.read_text(encoding="utf-8").splitlines()
                    if json.loads(x)["event"] == "deploying")
        with path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")

        code, output, _, _ = deploy(
            tmp_path, [], "-Restore", tag=RUNNING, running=FAILED, down=True
        )

        assert code == 3, output
        assert "DEPLOY-PRE-MOVE-REFUSAL kind=restore_refused" in output
        assert "replayed copy" in output


class TestTheLedgerIsReadInOnePass:
    """TheHub #61730 (2): `Get-RestoreTarget` appended every ledger entry to a
    PowerShell array (`+=` copies the whole array each time) and then walked
    the entries again for the nonce check, so a restore's cost grew with the
    square of a ledger that only ever grows."""

    @staticmethod
    def _body() -> str:
        text = SCRIPT.read_text(encoding="utf-8")
        start = text.index("function Get-RestoreTarget")
        return text[start:text.index("\nfunction ", start)]

    def test_no_entry_is_appended_to_an_array(self) -> None:
        body = self._body()
        assert "+=" not in body, "an array append inside the scan copies the array"
        assert "$entries" not in body, "the entries are not collected for a second walk"

    def test_a_long_ledger_still_restores_and_still_catches_a_replay(
        self, tmp_path: Path
    ) -> None:
        self._failed_deploy_with_history(tmp_path, 2000)
        code, output, _, _ = deploy(
            tmp_path, [], "-Restore", tag=RUNNING, running=FAILED, down=True
        )
        assert code == 0, output
        assert "RESTORE of 0e9a88860000" in output

    def test_a_replay_behind_a_long_history_is_refused(self, tmp_path: Path) -> None:
        self._failed_deploy_with_history(tmp_path, 2000)
        path = _ledger_path(tmp_path)
        line = next(x for x in path.read_text(encoding="utf-8").splitlines()
                    if json.loads(x)["event"] == "deploying")
        with path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")

        code, output, _, _ = deploy(
            tmp_path, [], "-Restore", tag=RUNNING, running=FAILED, down=True
        )

        assert code == 3, output
        assert "replayed copy" in output

    @staticmethod
    def _failed_deploy_with_history(tmp_path: Path, lines: int) -> None:
        """`lines` older entries, each with its own nonce, then a deploy."""
        path = _ledger_path(tmp_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            for i in range(lines):
                f.write(json.dumps({"event": "checked", "tag": TAG, "nonce": f"old{i}"}) + "\n")
        code, output, _, _ = deploy(tmp_path, [ALLOW])
        assert code == 0, output
