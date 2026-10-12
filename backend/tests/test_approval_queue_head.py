"""After the approval queue pushes a new head, it uses that head (D-149 follow-up).

The operator's run of 2026-10-11 16:40: the queue merged main into #781 and
pushed `3321e159 -> 635ad80c`, then polled thirty minutes for an approval
request on `3321e159` and gave up. `gh pr view` was still reporting the old
head, and every later step read it from there. The platform opens requests
for the head it sees, which was the new one, so the queue waited for a request
that would never come.

These run the queue's own PowerShell functions, extracted from the script,
against a real bare remote and a fake `gh` that reports the stale head.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "approval-queue.ps1"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or shutil.which("git") is None,
    reason="needs pwsh and git on PATH",
)


def git(cwd: Path, *args: str) -> str:
    out = subprocess.run(
        ["git", "-C", str(cwd), "-c", "user.name=t", "-c", "user.email=t@t", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return out.stdout.strip()


@pytest.fixture
def pushed(tmp_path: Path) -> tuple[Path, str, str]:
    """A clone whose `feat` was pushed at `old`, then pushed again at `new`."""
    origin = tmp_path / "origin.git"
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(origin)], check=True)
    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", "-q", str(origin), str(clone)], check=True, capture_output=True)
    (clone / "a.txt").write_text("one\n", encoding="utf-8")
    git(clone, "checkout", "-qb", "feat")
    git(clone, "add", "-A")
    git(clone, "commit", "-qm", "old")
    git(clone, "push", "-q", "origin", "feat")
    old = git(clone, "rev-parse", "HEAD")
    (clone / "a.txt").write_text("two\n", encoding="utf-8")
    git(clone, "commit", "-qam", "merge main in")
    git(clone, "push", "-q", "origin", "feat")
    new = git(clone, "rev-parse", "HEAD")
    return clone, old, new


def run_get_pr(clone: Path, reported_head: str, log: Path) -> dict:
    stale = json.dumps(
        {
            "number": 781,
            "state": "OPEN",
            "headRefName": "feat",
            "headRefOid": reported_head,
            "baseRefName": "main",
            "isCrossRepository": False,
            "isDraft": False,
        }
    )
    program = f"""
$ErrorActionPreference = 'Stop'
$ast = [System.Management.Automation.Language.Parser]::ParseFile('{SCRIPT}', [ref]$null, [ref]$null)
$wanted = 'Log', 'Get-RemoteHead', 'Get-Pr'
$isFn = {{ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }}
foreach ($fn in $ast.FindAll($isFn, $true) | Where-Object Name -in $wanted) {{
  . ([scriptblock]::Create($fn.Extent.Text))
}}
$RepoPath = '{clone}'
$Repo = 'acme/app'
$PrFields = 'number'
$script:LogFile = '{log}'
function gh {{ $global:LASTEXITCODE = 0; return '{stale}' }}
$p = Get-Pr 781
$p | ConvertTo-Json -Compress
"""
    out = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", program],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_after_a_push_the_queue_polls_the_pushed_head(
    pushed: tuple[Path, str, str], tmp_path: Path
) -> None:
    clone, old, new = pushed
    log = tmp_path / "queue.log"

    pr = run_get_pr(clone, reported_head=old, log=log)

    assert pr["headRefOid"] == new, "GitHub's stale head was used"
    assert "GitHub still reports head" in log.read_text(encoding="utf-8")


def test_when_github_agrees_nothing_is_rewritten(
    pushed: tuple[Path, str, str], tmp_path: Path
) -> None:
    clone, _, new = pushed
    log = tmp_path / "queue.log"

    pr = run_get_pr(clone, reported_head=new, log=log)

    assert pr["headRefOid"] == new
    assert not log.exists() or "GitHub still reports" not in log.read_text(encoding="utf-8")


def test_every_head_the_queue_acts_on_comes_through_get_pr() -> None:
    """The poll, the evidence match, the head-moved check and the merge read
    `headRefOid` from objects Get-Pr returned, and the object is refreshed
    after the push."""
    script = SCRIPT.read_text(encoding="utf-8")
    refresh = script.index("$err = Update-Branch $p")
    assert script.index("$prs[$n] = Get-Pr $n", refresh) - refresh < 200
    poll = script.index('$ref = "$Repo#$n@$($prs[$n].headRefOid)"')
    merge = script.index("--match-head-commit $sha")
    assert refresh < poll < merge
    assert script.count("= gh pr view ") == 1, "a second, unwrapped read of the head"
