"""The gate job refuses only what a commit introduced (D-159, TheHub #60732).

Since D-183 deploy.ps1 no longer mirrors this job: it asks the deploy ratchet
(`GET /api/oracle/deploy-gate`), which refuses a superset (a raised score, a
latched No-Go, and anything it could not judge), and is tested in
test_deploy_ratchet_ps1.py. What stays here is the gate job's own rule.

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

    def test_the_gate_passes_an_explicit_false(self, tmp_path: Path) -> None:
        code, output = run_gate(tmp_path, CLEAN)

        assert code == 0, output

    @pytest.mark.parametrize(
        "value", [None, "yes", 1, "True"], ids=["null", "yes", "one", "capital-true"]
    )
    def test_the_gate_refuses_anything_but_true_or_false(
        self, tmp_path: Path, value: object
    ) -> None:
        """It blocked only on `true`, so a missing or malformed field passed.
        An answer the gate cannot read is not "nothing was introduced"."""
        answer = {**CLEAN, "introduced_blocking": value}

        code, output = run_gate(tmp_path, answer)

        assert code == 1, output
        assert "not true or false" in output

    def test_the_gate_refuses_a_decision_without_the_field(self, tmp_path: Path) -> None:
        answer = {k: v for k, v in CLEAN.items() if k != "introduced_blocking"}

        code, output = run_gate(tmp_path, answer)

        assert code == 1, output
        assert "not true or false" in output
