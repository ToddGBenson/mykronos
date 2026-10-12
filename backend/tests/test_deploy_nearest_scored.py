"""An unjudged sha names the nearest scored commit and its verdict (TheHub #60731).

Concourse scores only the newest commit that passed every lane, so a sha it
skipped is unjudged even when main is green. `deploy.ps1` used to stop at
"nothing scored this". It now walks the sha's ancestors and names the first one
the gate did score.

These run the script's own `Find-NearestScored` and `Format-NearestScored`,
extracted from its AST, against a real git history. `Get-RiskVerdict` is
replaced by a fake that answers from a table, so nothing here calls a backend.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "deploy" / "mykronos" / "deploy.ps1"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or shutil.which("git") is None,
    reason="needs pwsh and git on PATH",
)


def git(cwd: Path, *args: str) -> str:
    out = subprocess.run(
        ["git", "-C", str(cwd), "-c", "user.name=t", "-c", "user.email=t@t", *args],
        capture_output=True, text=True, encoding="utf-8", check=True,
    )
    return out.stdout.strip()


@pytest.fixture
def history(tmp_path: Path) -> tuple[Path, list[str]]:
    """Four commits; returns the repo and their shas, oldest first."""
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    shas = []
    for n in range(4):
        (repo / "f.txt").write_text(f"{n}\n", encoding="utf-8")
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", f"c{n}")
        shas.append(git(repo, "rev-parse", "HEAD"))
    return repo, shas


def nearest(repo: Path, sha: str, answers: dict[str, dict[str, object]]) -> tuple[dict, str]:
    """Run the script's functions; `answers` maps sha -> fake Get-RiskVerdict result."""
    table = json.dumps(answers).replace("'", "''")
    program = f"""
$ErrorActionPreference = 'Stop'
$ast = [System.Management.Automation.Language.Parser]::ParseFile('{SCRIPT}', [ref]$null, [ref]$null)
$wanted = 'Find-NearestScored', 'Format-NearestScored'
$isFn = {{ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }}
foreach ($fn in $ast.FindAll($isFn, $true) | Where-Object Name -in $wanted) {{
  . ([scriptblock]::Create($fn.Extent.Text))
}}
$table = '{table}' | ConvertFrom-Json -AsHashtable
function Get-RiskVerdict {{
  param([string]$Sha, [string]$BaseUrl, [string]$Token)
  if ($table.ContainsKey($Sha)) {{
    $a = $table[$Sha]
    return @{{ State = $a.State; Floor = $a.Floor; Reason = $a.Reason;
      Decision = [pscustomobject]$a.Decision }}
  }}
  return @{{ State = 'unjudged' }}
}}
$n = Find-NearestScored -Sha '{sha}' -BaseUrl 'http://x' -Token 't' -RepoPath '{repo}'
$n | ConvertTo-Json -Compress
Format-NearestScored -Nearest $n -Sha '{sha[:7]}'
"""
    out = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", program],
        capture_output=True, text=True, encoding="utf-8", check=True,
    )
    lines = out.stdout.strip().splitlines()
    return json.loads(lines[-2]), lines[-1]


def test_it_names_the_nearest_scored_ancestor_and_its_verdict(
    history: tuple[Path, list[str]],
) -> None:
    repo, shas = history
    answers = {
        shas[1]: {"State": "clean",
                  "Decision": {"effective_recommendation": "go", "overall_risk_score": 12}},
        shas[0]: {"State": "clean",
                  "Decision": {"effective_recommendation": "review_recommended",
                               "overall_risk_score": 40}},
    }

    found, line = nearest(repo, shas[3], answers)

    assert found["Found"] is True
    assert found["Sha"] == shas[1], "the NEAREST scored ancestor, not any"
    assert found["Distance"] == 2
    assert line == (
        f"Nearest scored commit: {shas[1][:12]}, 2 commit(s) before {shas[3][:7]}: "
        "go (score 12). It does not cover the 2 commit(s) after it."
    )


def test_a_refused_ancestor_says_refused_not_its_recommendation(
    history: tuple[Path, list[str]],
) -> None:
    repo, shas = history
    answers = {shas[2]: {"State": "refused", "Floor": True,
                         "Decision": {"effective_recommendation": "go",
                                      "overall_risk_score": 70}}}

    _, line = nearest(repo, shas[3], answers)

    assert "refused (it introduced an open critical or high)" in line


def test_none_scored_says_none_was_found(history: tuple[Path, list[str]]) -> None:
    repo, shas = history

    found, line = nearest(repo, shas[3], {})

    assert found["Found"] is False
    assert line == (
        "Nearest scored commit: none found - none of the 3 commit(s) before "
        f"{shas[3]} has a risk decision."
    )


def test_a_sha_the_checkout_does_not_have_says_so(history: tuple[Path, list[str]]) -> None:
    repo, _ = history

    found, line = nearest(repo, "deadbeefdeadbeef", {})

    assert found["Found"] is False
    assert "is not in the checkout" in line


def test_it_stops_at_the_first_could_not_ask(history: tuple[Path, list[str]]) -> None:
    repo, shas = history
    answers = {
        shas[2]: {"State": "unasked", "Reason": "http://x did not answer"},
        shas[1]: {"State": "clean",
                  "Decision": {"effective_recommendation": "go", "overall_risk_score": 1}},
    }

    found, line = nearest(repo, shas[3], answers)

    assert found["Found"] is False
    assert "stopped asking at" in line and "did not answer" in line
