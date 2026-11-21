"""TheHub #62158: the unsealer died before its first line under Windows PowerShell 5.1.

Both things that run ``vault-unseal.ps1`` unattended start it with
``powershell.exe`` (Windows PowerShell 5.1): the "Mykronos Vault Unseal"
scheduled task that ``Install-VaultUnsealTask.ps1`` registers, and TheHub's
``start-production-after-boot.ps1``. In 5.1, a script that declares
``[CmdletBinding()]`` sees an EMPTY ``$PSScriptRoot`` while its param defaults
are evaluated, so ``[string] $InitFile = (Join-Path $PSScriptRoot ...)`` threw
"Cannot bind argument to parameter 'Path' because it is an empty string" and
the script exited 1 before it wrote a log line or looked at Vault.

Measured: after the 2026-11-15 and 2026-11-20 reboots the boot log reads
``FAIL vault-unseal.ps1 exit 1`` with no line from the unsealer at all, Vault
stayed sealed, and CI errored on "Vault is sealed" until a person unsealed it
by hand (Hub incident 37443). Under pwsh 7 the same command works, which is
why running it by hand never reproduced it.

The behavioural test runs the real script under ``powershell.exe`` with a fake
``docker`` that reports no Vault container, which is the script's quiet
``exit 0`` path. It needs Windows PowerShell, so it is skipped elsewhere; the
static test on the installer runs everywhere.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CONCOURSE = REPO_ROOT / "deploy" / "concourse"
UNSEALER = CONCOURSE / "vault-unseal.ps1"
INSTALLER = CONCOURSE / "Install-VaultUnsealTask.ps1"

WINDOWS_POWERSHELL = shutil.which("powershell.exe") if os.name == "nt" else None


@pytest.mark.skipif(WINDOWS_POWERSHELL is None, reason="Windows PowerShell 5.1 is not on this host")
def test_the_unsealer_runs_under_windows_powershell(tmp_path: Path) -> None:
    # A docker that answers every call with failure: `docker inspect` fails,
    # which the script reads as "no Vault container on this host" and exits 0
    # after logging it. Nothing reaches the real engine.
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "docker.cmd").write_text("@echo off\r\nexit /b 1\r\n", encoding="ascii")
    log = tmp_path / "unseal.log"

    env = dict(os.environ)
    system_root = env.get("SystemRoot", r"C:\Windows")
    env["PATH"] = os.pathsep.join([str(fake_bin), str(Path(system_root) / "System32")])

    result = subprocess.run(
        [
            str(WINDOWS_POWERSHELL),
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(UNSEALER),
            "-LogFile",
            str(log),
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
        check=False,
    )

    assert result.returncode == 0, (
        "vault-unseal.ps1 failed under Windows PowerShell 5.1, the host both the "
        "unseal task and TheHub's boot task use. stderr:\n" + result.stderr
    )
    assert log.exists() and "nothing to unseal" in log.read_text(encoding="ascii"), (
        "the unsealer exited without writing its log line, so a failure would "
        "have been as silent as the one in #62158"
    )


def test_the_unseal_task_is_not_registered_on_windows_powershell() -> None:
    """The installer registers the same host as the repo's other tasks.

    Register-MyKronosBackupTasks.ps1, Register-ControlObservationTasks.ps1 and
    Register-AutoDeploy.ps1 all register ``pwsh``; this one alone hard-coded
    ``powershell.exe``, and a hand repair that switched the live task to pwsh
    is undone by the next run of the installer.
    """
    text = INSTALLER.read_text(encoding="utf-8")
    match = re.search(r"New-ScheduledTaskAction\s+-Execute\s+(\S+)", text)
    assert match, "Install-VaultUnsealTask.ps1 no longer builds a task action"
    assert "powershell.exe" not in match.group(1).lower(), (
        "the unseal task is registered on powershell.exe (Windows PowerShell 5.1); "
        "register pwsh, as the other task installers do"
    )
