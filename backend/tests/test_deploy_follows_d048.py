"""deploy.ps1 refuses only what the gate refuses (D-159, TheHub #60732).

The gate job (`oracle-gate` in `deploy/concourse/pipelines/mykronos.yml`)
fails only when the commit INTRODUCED an open critical or high (D-048). A
`no_go` recommendation describes the standing backlog, and the job warns on it
and passes. `deploy.ps1` used to refuse that `no_go` too, so the two disagreed
about the same decision, and getting past the deploy script took `-Force`.

Both sides run here against the same decisions:

* the whole of `deploy.ps1`, copied into a scratch tree with `-NoStart`, with
  `Invoke-RestMethod`, `docker` and `Start-Sleep` shadowed by functions, so
  it reaches a real verdict, a real banner and a real ledger line and pulls
  nothing;
* the gate job's own verdict script, cut from the pipeline file and run under
  bash, with `curl` serving the decision and a small `jq` stand-in that
  answers only the filters the script uses. An unknown filter fails the test.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "deploy" / "mykronos" / "deploy.ps1"
PIPELINE = ROOT / "deploy" / "concourse" / "pipelines" / "mykronos.yml"
TAG = "abc1234"


def decision(*, recommendation: str, blocking: bool, high: int = 0,
             overridden: bool = False) -> dict[str, Any]:
    return {
        "commit_sha": TAG,
        "found": True,
        "recommendation": recommendation,
        "effective_recommendation": "go" if overridden else recommendation,
        "overridden": overridden,
        "decision_id": "dec-1",
        "decision_type": "commit_gate",
        "repo_full_name": "ToddGBenson/mykronos",
        "overall_risk_score": 82,
        "reasoning": "standing backlog",
        "policy_version": "v1",
        "evaluated_at": "2026-10-12T18:00:00",
        "introduced": {"high": high} if high else {},
        "disclosed": {},
        "introduced_blocking": blocking,
    }


BACKLOG_NO_GO = decision(recommendation="no_go", blocking=False)
INTRODUCED_HIGH = decision(recommendation="review_recommended", blocking=True, high=1)
NO_GO_AND_HIGH = decision(recommendation="no_go", blocking=True, high=2)
CLEAN = decision(recommendation="go", blocking=False)


# -- deploy.ps1, end to end ----------------------------------------------------


def deploy(tmp_path: Path, answer: dict[str, Any], *extra: str) -> tuple[int, str, list[dict]]:
    """Run deploy.ps1 -NoStart against `answer`. Returns (exit, output, ledger)."""
    tree = tmp_path / "tree"
    (tree / "deploy" / "mykronos").mkdir(parents=True)
    (tree / "backend").mkdir()
    shutil.copy(SCRIPT, tree / "deploy" / "mykronos" / "deploy.ps1")
    (tree / "backend" / ".env").write_text("MYKRONOS_VIEWER_TOKEN=t\n", encoding="utf-8")
    fixture = tmp_path / "answer.json"
    fixture.write_text(json.dumps(answer), encoding="utf-8")
    args = " ".join(f"'{a}'" if " " in a else a for a in extra)
    program = f"""
function Invoke-RestMethod {{ Get-Content -Raw '{fixture}' | ConvertFrom-Json }}
function docker {{ $global:LASTEXITCODE = 0 }}
function Start-Sleep {{ }}
try {{
  & '{tree / "deploy" / "mykronos" / "deploy.ps1"}' -Tag {TAG} -NoStart `
    -GateWaitMinutes 0 {args} *>&1 |
    ForEach-Object {{ "$_" }}
  exit 0
}} catch {{
  "THROWN: $($_.Exception.Message)"
  exit 3
}}
"""
    out = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", program],
        capture_output=True, text=True, encoding="utf-8",
    )
    ledger_path = tree / "deploy" / "mykronos" / "deploy-risk-log.jsonl"
    ledger = (
        [json.loads(line) for line in ledger_path.read_text(encoding="utf-8").splitlines()]
        if ledger_path.exists() else []
    )
    return out.returncode, out.stdout + out.stderr, ledger


needs_pwsh = pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh is not on PATH")


@needs_pwsh
class TestDeployPs1:
    def test_a_backlog_no_go_passes_with_a_warning(self, tmp_path: Path) -> None:
        code, output, ledger = deploy(tmp_path, BACKLOG_NO_GO)

        assert code == 0, output
        assert "BACKLOG NO_GO" in output
        assert "Recommendation no_go, effective no_go, score 82" in output
        assert "Pulling images" in output, "the deploy went on"
        assert [entry["state"] for entry in ledger] == ["backlog_no_go"]
        assert ledger[0]["introduced_blocking"] is False
        assert ledger[0]["score"] == 82

    def test_introduced_blocking_refuses(self, tmp_path: Path) -> None:
        code, output, ledger = deploy(tmp_path, INTRODUCED_HIGH)

        assert code == 3, output
        assert "it introduced 0 critical and 1 high open finding(s)" in output
        assert "Pulling images" not in output
        assert [(e["event"], e["state"], e["floor"]) for e in ledger] == [
            ("refused", "refused", True)
        ]

    def test_no_go_and_introduced_blocking_refuses_as_the_floor(self, tmp_path: Path) -> None:
        code, _, ledger = deploy(tmp_path, NO_GO_AND_HIGH)

        assert code == 3
        assert ledger[0]["floor"] is True

    def test_force_with_a_reason_still_ships_a_refusal_and_records_it(
        self, tmp_path: Path
    ) -> None:
        code, output, ledger = deploy(
            tmp_path, INTRODUCED_HIGH, "-Force", "-ForceReason", "hotfix for the sealed vault"
        )

        assert code == 0, output
        assert "OVERRIDDEN" in output
        assert [(e["event"], e["reason"]) for e in ledger] == [
            ("override", "hotfix for the sealed vault")
        ]

    def test_a_recorded_override_clears_the_floor(self, tmp_path: Path) -> None:
        answer = decision(recommendation="no_go", blocking=True, high=1, overridden=True)

        code, _, ledger = deploy(tmp_path, answer)

        assert code == 0
        assert ledger[0]["state"] == "clean"

    def test_force_on_a_backlog_no_go_has_nothing_to_override(self, tmp_path: Path) -> None:
        code, output, ledger = deploy(
            tmp_path, BACKLOG_NO_GO, "-Force", "-ForceReason", "not needed any more at all"
        )

        assert code == 0
        assert "there was nothing to override" in output
        assert [e["event"] for e in ledger] == ["checked"]

    def test_clean_is_one_quiet_line(self, tmp_path: Path) -> None:
        code, output, ledger = deploy(tmp_path, CLEAN)

        assert code == 0
        assert "BACKLOG" not in output
        assert ledger[0]["state"] == "clean"


# -- the gate job's own rule ---------------------------------------------------

#: The only jq filters the verdict script uses, in Python. A filter not here
#: fails the run, so the stand-in cannot quietly answer something it was never
#: taught.
JQ_STANDIN = r'''
import json, sys
args = [a for a in sys.argv[1:] if a != "-r"]
expr, path = args[0], args[1]
d = json.load(open(path, encoding="utf-8"))
def out(v):
    if v is None: return ""
    if isinstance(v, bool): return "true" if v else "false"
    return str(v)
filters = {
    ".recommendation": lambda: d.get("recommendation"),
    ".overall_risk_score": lambda: d.get("overall_risk_score"),
    ".reasoning // empty": lambda: d.get("reasoning") or None,
    ".introduced_blocking": lambda: d.get("introduced_blocking"),
    ".introduced.critical // 0": lambda: (d.get("introduced") or {}).get("critical") or 0,
    ".introduced.high // 0": lambda: (d.get("introduced") or {}).get("high") or 0,
}
if expr.startswith(".disclosed"):
    v = ", ".join(f"{n} {k}" for k, n in (d.get("disclosed") or {}).items())
elif expr in filters:
    v = filters[expr]()
else:
    sys.exit(f"jq stand-in does not know {expr!r}")
print(out(v))
'''


def gate_verdict_script() -> str:
    """The gate job's evaluate task, from where it reads the decision onward."""
    config = yaml.safe_load(PIPELINE.read_text(encoding="utf-8"))
    job = next(j for j in config["jobs"] if j["name"] == "oracle-gate")
    task = next(step for step in job["plan"] if step.get("task") == "evaluate")
    script = task["config"]["run"]["args"][-1]
    start = script.index("RECOMMENDATION=$(jq")
    return script[start:]


def run_gate(tmp_path: Path, answer: dict[str, Any]) -> tuple[int, str]:
    (tmp_path / "decision.json").write_text(json.dumps(answer), encoding="utf-8")
    standin = tmp_path / "jq_standin.py"
    standin.write_text(JQ_STANDIN, encoding="utf-8")
    python = Path(sys.executable).as_posix()
    program = (
        "set -euo pipefail\n"
        f"jq() {{ '{python}' '{standin.as_posix()}' \"$@\"; }}\n"
        + gate_verdict_script()
    )
    out = subprocess.run(
        ["bash", "-c", program], cwd=tmp_path, capture_output=True, text=True, encoding="utf-8"
    )
    return out.returncode, out.stdout + out.stderr


needs_bash = pytest.mark.skipif(shutil.which("bash") is None, reason="bash is not on PATH")


@needs_bash
class TestTheGateJobAgrees:
    def test_the_gate_passes_a_backlog_no_go_with_a_warning(self, tmp_path: Path) -> None:
        code, output = run_gate(tmp_path, BACKLOG_NO_GO)

        assert code == 0, output
        assert "::warning::Oracle scores this repository no_go" in output

    def test_the_gate_refuses_introduced_blocking(self, tmp_path: Path) -> None:
        code, output = run_gate(tmp_path, INTRODUCED_HIGH)

        assert code == 1, output
        assert "introduced 0 critical and 1 high" in output

    @needs_pwsh
    @pytest.mark.parametrize(
        "answer", [BACKLOG_NO_GO, INTRODUCED_HIGH, NO_GO_AND_HIGH, CLEAN],
        ids=["backlog-no-go", "introduced-high", "no-go-and-high", "clean"],
    )
    def test_deploy_ps1_refuses_exactly_what_the_gate_refuses(
        self, tmp_path: Path, answer: dict[str, Any]
    ) -> None:
        (tmp_path / "gate").mkdir()
        gate_code, _ = run_gate(tmp_path / "gate", answer)
        deploy_code, _, _ = deploy(tmp_path / "deploy", answer)

        assert (gate_code != 0) == (deploy_code != 0)
