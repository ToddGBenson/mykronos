"""The skills installer keeps its state outside the working tree (TheHub #60737).

`Install-PersonalSocSkills.ps1` wrote the installed skills SHA to
`deploy/personal-soc/.installed-skills`, which was tracked. Every install
therefore dirtied the checkout, and `PipelineSource.ps1` -- correctly --
refused every `set-pipeline` after it.

The state now lives under `%LOCALAPPDATA%\\mykronos\\personal-soc`, the old
in-repo file is read once as a migration source, and it is no longer tracked.

The executable tests run the script's own `Invoke-Cycle`, `Get-InstalledSkills`
and `Set-InstalledSkills`, extracted from its AST, inside a throwaway git
repository. `mc` is replaced by a scriptblock that serves a fake bucket from a
directory, so nothing touches MinIO, `~/.claude` or the real checkout.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "deploy" / "personal-soc" / "Install-PersonalSocSkills.ps1"
LEGACY = "deploy/personal-soc/.installed-skills"

OLD_SHA = "3b498fbb281b4162b819c7cfef5fbfedc5ff4af8"
NEW_SHA = "c4af97d0000000000000000000000000000000aa"

needs_pwsh = pytest.mark.skipif(
    shutil.which("pwsh") is None or shutil.which("git") is None,
    reason="needs pwsh and git on PATH",
)


def git(cwd: Path, *args: str) -> str:
    out = subprocess.run(
        [
            "git",
            "-C",
            str(cwd),
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "-c",
            "core.autocrlf=false",
            *args,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return out.stdout.strip()


def test_the_legacy_state_file_is_gitignored() -> None:
    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert LEGACY in [line.strip() for line in ignore]


@pytest.mark.skipif(
    shutil.which("git") is None or not (ROOT / ".git").exists(),
    reason="needs a git checkout",
)
def test_the_legacy_state_file_is_not_tracked() -> None:
    assert git(ROOT, "ls-files", "--", LEGACY) == "", (
        f"{LEGACY} is tracked again; every install would dirty the tree."
    )


def test_the_default_state_path_is_outside_the_checkout() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert (
        "[string]$StateFile = (Join-Path $env:LOCALAPPDATA "
        '"mykronos\\personal-soc\\installed-skills")'
    ) in text
    # The only path built from the legacy name is the read-only migration source.
    assert text.count('".installed-skills"') == 1
    assert "Set-InstalledSkills -Path $StateFile" in text


@pytest.fixture
def checkout(tmp_path: Path) -> Path:
    """A repo shaped like the operator's: the installer AND the legacy file tracked."""
    repo = tmp_path / "repo"
    psoc = repo / "deploy" / "personal-soc"
    psoc.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    shutil.copy(SCRIPT, psoc / SCRIPT.name)
    (psoc / ".installed-skills").write_text(OLD_SHA, encoding="ascii")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "init")
    return repo


def cycle(tmp_path: Path, repo: Path, requested: str) -> subprocess.CompletedProcess[str]:
    """Run one real Invoke-Cycle with a fake `mc`; the bucket is a directory."""
    program = f"""
$ErrorActionPreference = 'Stop'
$ast = [System.Management.Automation.Language.Parser]::ParseFile('{SCRIPT}', [ref]$null, [ref]$null)
$wanted = 'Get-Pointer', 'Invoke-Cycle', 'Get-InstalledSkills', 'Set-InstalledSkills'
$isFn = {{ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }}
foreach ($fn in $ast.FindAll($isFn, $true) | Where-Object Name -in $wanted) {{
  . ([scriptblock]::Create($fn.Extent.Text))
}}

$tmp = '{tmp_path}'
$bucketDir = Join-Path $tmp 'bucket'
New-Item -ItemType Directory -Force $bucketDir | Out-Null
Set-Content (Join-Path $bucketDir 'skills.requested') '{requested}' -NoNewline
$stage = Join-Path $tmp 'stage-{requested}'
New-Item -ItemType Directory -Force (Join-Path $stage 'skills\\demo') | Out-Null
Set-Content (Join-Path $stage 'skills\\demo\\SKILL.md') 'v{requested}'
Compress-Archive -Path (Join-Path $stage 'skills') -Force `
  -DestinationPath (Join-Path $bucketDir 'skills-{requested}.zip')

$Bucket = 'b'
$mc = {{
  $map = {{
    param($p)
    if ($p -like 'psoc/*') {{ Join-Path $bucketDir ($p -replace '^psoc/[^/]+/', '') }}
    else {{ $p }}
  }}
  $src = & $map $args[2]; $dst = & $map $args[3]
  $global:LASTEXITCODE = 1
  if (Test-Path $src) {{ Copy-Item $src $dst -Force; $global:LASTEXITCODE = 0 }}
}}
$here = '{repo}\\deploy\\personal-soc'
$legacyStateFile = Join-Path $here '.installed-skills'
$StateFile = Join-Path $tmp 'localappdata\\mykronos\\personal-soc\\installed-skills'
$SkillRoot = Join-Path $tmp 'skills-root'
$Confidential = @('profile.md', 'identifiers.md')
$script:failures = 0

Invoke-Cycle
"failures=$script:failures"
"""
    return subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", program],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )


def state_file(tmp_path: Path) -> Path:
    return tmp_path / "localappdata" / "mykronos" / "personal-soc" / "installed-skills"


@needs_pwsh
def test_the_migration_reads_the_old_in_repo_file(tmp_path: Path, checkout: Path) -> None:
    """New state absent, old file present: its SHA is carried across, no reinstall."""
    out = cycle(tmp_path, checkout, OLD_SHA)

    assert state_file(tmp_path).read_text(encoding="ascii") == OLD_SHA
    assert "skills state migrated from" in out.stdout
    assert "failures=0" in out.stdout
    # Already at the requested SHA once migrated, so nothing was installed.
    assert not (tmp_path / "skills-root").exists(), out.stdout


@needs_pwsh
def test_an_install_cycle_leaves_git_status_clean(tmp_path: Path, checkout: Path) -> None:
    """The story's acceptance test: a real install, then `git status` is empty."""
    out = cycle(tmp_path, checkout, NEW_SHA)

    assert "skills installed and acknowledged at " + NEW_SHA in out.stdout, out.stdout
    assert (tmp_path / "skills-root" / "demo" / "SKILL.md").is_file()
    assert state_file(tmp_path).read_text(encoding="ascii") == NEW_SHA
    assert (tmp_path / "bucket" / "skills.installed").read_text(encoding="ascii") == NEW_SHA

    assert git(checkout, "status", "--porcelain") == "", (
        "the install cycle wrote into the working tree"
    )
    legacy = checkout / "deploy" / "personal-soc" / ".installed-skills"
    assert legacy.read_text(encoding="ascii") == OLD_SHA, "the legacy file is read, never written"
