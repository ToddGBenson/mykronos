"""deploy.ps1 tells the backlog what it shipped (TheHub #61046).

Nothing a mykronos deploy did reached the Hub's story lifecycle, so a story
whose code was live waited at "tested" until someone moved it by hand: 53
stall reports were open on 2026-10-27, and 16 stories had been moved by hand
in the previous 30 days.

The recorder lives outside this repository and is named in backend/.env, so
this script carries no address or credential for it. deploy.ps1's part is to
hand it the facts only the deploy knows: the commit that was running before,
and the commit that is running now.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "deploy" / "mykronos" / "deploy.ps1"
CODE = "\n".join(
    line for line in SCRIPT.read_text(encoding="utf-8").splitlines()
    if not line.lstrip().startswith("#")
)


def test_the_previous_commit_is_read_before_anything_is_pulled():
    before = CODE.index("$previousSha = Get-RunningBuildSha")
    assert before < CODE.index('Write-Host "Pulling images from')


def test_the_running_commit_is_read_by_the_same_function():
    assert "$running = Get-RunningBuildSha" in CODE


def test_the_recorder_is_named_in_the_env_file_not_in_this_script():
    assert 'Read-EnvValue $backendEnv "MYKRONOS_DEPLOY_RECORDER"' in CODE


def test_the_recorder_gets_the_range_and_the_checkout():
    call = CODE[CODE.index("function Invoke-DeployRecorder"):]
    for arg in ("--repo", "mykronos", "--sha", "--since", "--checkout"):
        assert arg in call, arg


def test_only_a_confirmed_deploy_is_recorded():
    """A mismatch means the stories are NOT live; recording it would advance
    them on a deploy that did not take."""
    confirmed = CODE.index('Write-Host "Confirmed: the backend is running $Tag."')
    record = CODE.index("Invoke-DeployRecorder -Sha $running")
    mismatch = CODE.index('Write-Host "MISMATCH: asked for $Tag')
    assert confirmed < record < mismatch


def test_a_recorder_failure_never_fails_the_deploy():
    body = CODE[CODE.index("function Invoke-DeployRecorder"):]
    body = body[:body.index("\n}\n")]
    assert "throw" not in body
    assert "catch" in body


def test_the_script_stays_ascii():
    SCRIPT.read_bytes().decode("ascii")
