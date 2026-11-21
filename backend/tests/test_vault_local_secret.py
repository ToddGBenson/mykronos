"""TheHub #60836: Vault's unseal key and root token leave the plaintext init.json.

``deploy/concourse/vault/init.json`` held the 1-of-1 unseal key and the root
token in plaintext beside the compose file. The operator decision of
2026-11-21 keeps the automatic unseal but reads the key from a file only the
operator's Windows account can decrypt (DPAPI, ``VaultLocalSecret.ps1``), and
replaces the root token with an admin-policy token kept in the same file.

A DPAPI file that exists is the only source: one that cannot be used (zero
bytes, not XML, the wrong shape, or not decryptable by this logon) is refused,
never treated as absent, because falling back to init.json hides a failed move
behind the plaintext root token. init.json is read only when there is no
DPAPI file at all, and then with a warning naming it every time.

The behavioural tests run the real ``vault-unseal.ps1`` under each Windows
shell on the host (Windows PowerShell 5.1 starts it from TheHub's boot task,
pwsh from the unseal task) against a fake ``docker`` that plays a sealed Vault
and records the key it is given. They need Windows, so they are skipped
elsewhere; the static tests run everywhere.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
CONCOURSE = REPO_ROOT / "deploy" / "concourse"
UNSEALER = CONCOURSE / "vault-unseal.ps1"
HELPER = CONCOURSE / "VaultLocalSecret.ps1"
INSTALLER = CONCOURSE / "Install-VaultUnsealTask.ps1"
VAULT_INIT = CONCOURSE / "vault-init.ps1"

SHELLS = [
    pytest.param(name, id=name)
    for name in ("powershell.exe", "pwsh")
    if os.name == "nt" and shutil.which(name)
]
needs_shell = pytest.mark.skipif(
    not SHELLS, reason="needs Windows PowerShell or pwsh on Windows (DPAPI)"
)

FAKE_DOCKER = r'''
import json, os, sys
state = os.environ["FAKE_VAULT_STATE"]
args = sys.argv[1:]
if args[:1] == ["inspect"]:
    print("true")
    sys.exit(0)
joined = " ".join(args)
if "vault status" in joined:
    unsealed = os.path.exists(os.path.join(state, "unsealed"))
    print(json.dumps({"sealed": not unsealed}))
    sys.exit(0 if unsealed else 2)
if "operator" in args and "unseal" in args:
    key = args[-1]
    with open(os.path.join(state, "keys"), "a", encoding="ascii") as f:
        f.write(key + "\n")
    if key == os.environ["FAKE_VAULT_KEY"]:
        open(os.path.join(state, "unsealed"), "w").close()
        print("Sealed false")
        sys.exit(0)
    print("Error unsealing: invalid key", file=sys.stderr)
    sys.exit(2)
print("fake docker: unexpected call " + joined, file=sys.stderr)
sys.exit(1)
'''

INIT_JSON = '{"unseal_keys_b64": ["the-right-key"], "root_token": "the-root-token"}'


def _fake_docker(tmp_path: Path, key: str) -> tuple[dict[str, str], Path]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    state = tmp_path / "state"
    state.mkdir()
    (bin_dir / "fake_docker.py").write_text(FAKE_DOCKER, encoding="ascii")
    (bin_dir / "docker.cmd").write_text(
        f'@echo off\r\n"{sys.executable}" "%~dp0fake_docker.py" %*\r\nexit /b %ERRORLEVEL%\r\n',
        encoding="ascii",
    )
    env = dict(os.environ)
    # Inherited from a pwsh parent, PSModulePath names PowerShell 7's modules
    # first and Windows PowerShell 5.1 then cannot load its own Security and
    # Utility modules. Each shell rebuilds the default when it is unset, which
    # is what a scheduled task starts with. (A copy of os.environ has
    # upper-cased keys on Windows, so match the name without case.)
    for name in [k for k in env if k.upper() == "PSMODULEPATH"]:
        del env[name]
    system_root = env.get("SystemRoot", r"C:\Windows")
    shells = (shutil.which("pwsh"), shutil.which("powershell.exe"))
    shell_dirs = {str(Path(p).parent) for p in shells if p}
    system32 = str(Path(system_root) / "System32")
    env["PATH"] = os.pathsep.join([str(bin_dir), system32, *sorted(shell_dirs)])
    env["FAKE_VAULT_STATE"] = str(state)
    env["FAKE_VAULT_KEY"] = key
    env["MYKRONOS_VAULT_LOCAL_SECRET"] = str(tmp_path / "vault-local.clixml")
    return env, state


def _run(shell: str, args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            shutil.which(shell) or shell,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            *args,
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
        check=False,
    )


def _write_local_secret(shell: str, env: dict[str, str], keys: str) -> None:
    # The key reaches the child by environment, never argv, as the operator script does it.
    env = dict(env, FAKE_SECRET_KEYS=keys)
    command = (
        "$ErrorActionPreference='Stop';"
        "@{ UnsealKeys = (ConvertTo-SecureString $env:FAKE_SECRET_KEYS -AsPlainText -Force) } |"
        " Export-Clixml -LiteralPath $env:MYKRONOS_VAULT_LOCAL_SECRET"
    )
    made = _run(shell, ["-Command", command], env)
    assert made.returncode == 0, made.stderr


def _unseal(
    shell: str, env: dict[str, str], init: Path, log: Path
) -> subprocess.CompletedProcess[str]:
    return _run(
        shell, ["-File", str(UNSEALER), "-InitFile", str(init), "-LogFile", str(log)], env
    )


@needs_shell
@pytest.mark.parametrize("shell", SHELLS)
def test_the_unsealer_reads_the_dpapi_file_when_init_json_is_gone(
    shell: str, tmp_path: Path
) -> None:
    env, state = _fake_docker(tmp_path, key="the-right-key")
    _write_local_secret(shell, env, "the-right-key")
    log = tmp_path / "unseal.log"

    result = _unseal(shell, env, tmp_path / "gone" / "init.json", log)

    assert result.returncode == 0, result.stdout + result.stderr
    assert (state / "keys").read_text(encoding="ascii").split() == ["the-right-key"]
    text = log.read_text(encoding="ascii")
    assert "Vault unsealed." in text
    # The log names where the key came from, never the key.
    assert "the-right-key" not in text


@needs_shell
@pytest.mark.parametrize("shell", SHELLS)
def test_the_dpapi_file_wins_over_a_stale_init_json(shell: str, tmp_path: Path) -> None:
    env, state = _fake_docker(tmp_path, key="the-right-key")
    _write_local_secret(shell, env, "the-right-key")
    init = tmp_path / "init.json"
    init.write_text('{"unseal_keys_b64": ["a-stale-key"], "root_token": "x"}', encoding="ascii")

    result = _run(shell, ["-File", str(UNSEALER), "-InitFile", str(init)], env)

    assert result.returncode == 0, result.stdout + result.stderr
    assert (state / "keys").read_text(encoding="ascii").split() == ["the-right-key"]


@needs_shell
@pytest.mark.parametrize("shell", SHELLS)
def test_init_json_unseals_before_the_move_and_the_log_says_so_every_time(
    shell: str, tmp_path: Path
) -> None:
    """No DPAPI file at all: init.json is used, and every run logs a warning
    naming the plaintext file it fell back to and the DPAPI file it lacks."""
    env, state = _fake_docker(tmp_path, key="the-right-key")
    init = tmp_path / "init.json"
    init.write_text(INIT_JSON, encoding="ascii")
    log = tmp_path / "unseal.log"

    for _ in range(2):
        (state / "unsealed").unlink(missing_ok=True)
        result = _unseal(shell, env, init, log)
        assert result.returncode == 0, result.stdout + result.stderr

    assert (state / "keys").read_text(encoding="ascii").split() == ["the-right-key"] * 2
    warnings = [line for line in log.read_text(encoding="ascii").splitlines() if "WARNING" in line]
    assert len(warnings) == 2, warnings
    for line in warnings:
        assert str(init) in line
        assert env["MYKRONOS_VAULT_LOCAL_SECRET"] in line
        assert "plaintext" in line


UNDECRYPTABLE = (
    '<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">'
    '<Obj RefId="0"><TN RefId="0"><T>System.Collections.Hashtable</T><T>System.Object</T></TN>'
    '<DCT><En><S N="Key">UnsealKeys</S><SS N="Value">00ff00ff</SS></En></DCT></Obj></Objs>'
)

# What a broken file holds, and the words the refusal must use for it. A
# damaged file is never blamed on the logon: that sends the operator to the
# wrong repair.
BROKEN = {
    "zero-bytes": ("", "damaged"),
    "not-xml": ("this is not clixml\r\n", "damaged"),
}

# Wrong shapes, written by the shell under test with Export-Clixml, so the
# file is well-formed and decrypts: only its content is wrong.
WRONG_SHAPES = {
    "pscustomobject": (
        "[pscustomobject]@{ UnsealKeys = (ConvertTo-SecureString 'the-right-key'"
        " -AsPlainText -Force) }"
    ),
    "plain-string": "@{ UnsealKeys = 'the-right-key' }",
    "missing-name": (
        "@{ AdminToken = (ConvertTo-SecureString 'a-token' -AsPlainText -Force) }"
    ),
}


def _assert_refused(result: subprocess.CompletedProcess[str], state: Path, *words: str) -> str:
    out = result.stdout + result.stderr
    assert result.returncode == 1, out
    # Nothing was taken from init.json: no key reached Vault at all.
    assert not (state / "keys").exists(), out
    for word in words:
        assert word in out, out
    return out


@needs_shell
@pytest.mark.parametrize("init_present", [True, False], ids=["init-json", "no-init-json"])
@pytest.mark.parametrize("shell", SHELLS)
def test_an_undecryptable_file_refuses_and_names_the_logon(
    shell: str, init_present: bool, tmp_path: Path
) -> None:
    """What an S4U or SYSTEM task meets: the file is there and DPAPI cannot
    decrypt it. It refuses, init.json or not, and names the logon."""
    env, state = _fake_docker(tmp_path, key="the-right-key")
    Path(env["MYKRONOS_VAULT_LOCAL_SECRET"]).write_text(UNDECRYPTABLE, encoding="utf-8")
    init = tmp_path / "init.json"
    if init_present:
        init.write_text(INIT_JSON, encoding="ascii")

    result = _unseal(shell, env, init, tmp_path / "unseal.log")

    out = _assert_refused(result, state, "cannot decrypt", "S4U")
    assert "wrong shape" not in out


@needs_shell
@pytest.mark.parametrize("init_present", [True, False], ids=["init-json", "no-init-json"])
@pytest.mark.parametrize("case", list(BROKEN))
@pytest.mark.parametrize("shell", SHELLS)
def test_a_damaged_file_refuses_without_blaming_the_logon(
    shell: str, case: str, init_present: bool, tmp_path: Path
) -> None:
    env, state = _fake_docker(tmp_path, key="the-right-key")
    content, word = BROKEN[case]
    Path(env["MYKRONOS_VAULT_LOCAL_SECRET"]).write_bytes(content.encode("ascii"))
    init = tmp_path / "init.json"
    if init_present:
        init.write_text(INIT_JSON, encoding="ascii")

    result = _unseal(shell, env, init, tmp_path / "unseal.log")

    out = _assert_refused(result, state, word, env["MYKRONOS_VAULT_LOCAL_SECRET"])
    assert "S4U" not in out
    assert "cannot decrypt" not in out


@needs_shell
@pytest.mark.parametrize("init_present", [True, False], ids=["init-json", "no-init-json"])
@pytest.mark.parametrize("shape", list(WRONG_SHAPES))
@pytest.mark.parametrize("shell", SHELLS)
def test_a_wrong_shape_refuses_and_is_never_read_as_absent(
    shell: str, shape: str, init_present: bool, tmp_path: Path
) -> None:
    env, state = _fake_docker(tmp_path, key="the-right-key")
    made = _run(
        shell,
        [
            "-Command",
            f"$ErrorActionPreference='Stop'; {WRONG_SHAPES[shape]} |"
            " Export-Clixml -LiteralPath $env:MYKRONOS_VAULT_LOCAL_SECRET",
        ],
        env,
    )
    assert made.returncode == 0, made.stderr
    init = tmp_path / "init.json"
    if init_present:
        init.write_text(INIT_JSON, encoding="ascii")

    result = _unseal(shell, env, init, tmp_path / "unseal.log")

    out = _assert_refused(result, state, "wrong shape")
    assert "no DPAPI file" not in out
    assert "S4U" not in out


# The four token readers discard .Source, so the helper itself must refuse a
# broken file and warn on the fallback; these run it the way they do.
ADMIN_TOKEN_PROBE = (
    "$ErrorActionPreference='Stop'; . $env:HELPER;"
    " try { $t = Get-VaultAdminToken -InitFile $env:INIT }"
    " catch { Write-Output ('REFUSED: ' + $_.Exception.Message); exit 3 }"
    " if ($t) { Write-Output ('SOURCE: ' + $t.Source) } else { Write-Output 'NONE' }"
)


@needs_shell
@pytest.mark.parametrize("shell", SHELLS)
def test_the_admin_token_readers_refuse_a_broken_file_beside_init_json(
    shell: str, tmp_path: Path
) -> None:
    env, _ = _fake_docker(tmp_path, key="unused")
    init = tmp_path / "init.json"
    init.write_text(INIT_JSON, encoding="ascii")
    env = dict(env, HELPER=str(HELPER), INIT=str(init))
    Path(env["MYKRONOS_VAULT_LOCAL_SECRET"]).write_bytes(b"")

    result = _run(shell, ["-Command", ADMIN_TOKEN_PROBE], env)

    out = result.stdout + result.stderr
    assert result.returncode == 3, out
    assert "REFUSED:" in out and "damaged" in out
    assert "root token" not in out


@needs_shell
@pytest.mark.parametrize("shell", SHELLS)
def test_the_admin_token_readers_warn_when_they_fall_back_to_the_root_token(
    shell: str, tmp_path: Path
) -> None:
    env, _ = _fake_docker(tmp_path, key="unused")
    init = tmp_path / "init.json"
    init.write_text(INIT_JSON, encoding="ascii")
    env = dict(env, HELPER=str(HELPER), INIT=str(init))

    result = _run(shell, ["-Command", ADMIN_TOKEN_PROBE], env)

    out = result.stdout + result.stderr
    assert result.returncode == 0, out
    assert f"SOURCE: the root token in {init}" in out
    assert "WARNING" in out and "plaintext" in out and str(init) in out
    assert "the-root-token" not in out


ADMIN_READERS = [
    "vault-secret.ps1",
    "Import-EnvSecretsToVault.ps1",
    "repair-ingestion-token.ps1",
    "vault-init.ps1",
]


@pytest.mark.parametrize("name", ADMIN_READERS)
def test_every_root_token_reader_goes_through_the_helper(name: str) -> None:
    """Once init.json is deleted, a script that still reads `.root_token`
    from it stops working - so none may read it except through the helper."""
    text = (CONCOURSE / name).read_text(encoding="utf-8")
    assert "VaultLocalSecret.ps1" in text, f"{name} does not dot-source VaultLocalSecret.ps1"
    assert "Get-VaultAdminToken" in text, (
        f"{name} does not read its token through Get-VaultAdminToken"
    )
    assert not re.search(r"\)\.root_token", text), (
        f"{name} still reads root_token out of init.json itself"
    )


def test_the_unsealer_reads_keys_through_the_helper() -> None:
    text = UNSEALER.read_text(encoding="utf-8")
    assert "Get-VaultUnsealKey" in text
    assert not re.search(r"\)\.unseal_keys_b64|\$init\.unseal_keys_b64", text)


def test_the_helper_is_ascii() -> None:
    # Windows PowerShell 5.1 reads a BOM-less file as CP1252 (setup.ps1).
    HELPER.read_bytes().decode("ascii")


def test_the_unseal_task_cannot_be_registered_as_system() -> None:
    """SYSTEM holds no key for a CurrentUser DPAPI file, so a SYSTEM task
    would fail every interval once init.json is gone."""
    text = INSTALLER.read_text(encoding="utf-8")
    assert not re.search(r"\[switch\]\s*\$AsSystem", text, re.IGNORECASE)
    assert "NT AUTHORITY\\SYSTEM" not in text and "-UserId 'SYSTEM'" not in text
    assert "already sits in vault/init.json" not in text


def test_vault_init_resolves_its_paths_in_the_body() -> None:
    """Windows PowerShell 5.1 leaves $PSScriptRoot empty in a param default
    under [CmdletBinding()] (the defect #1204 fixes in the unsealer)."""
    text = VAULT_INIT.read_text(encoding="utf-8")
    params = text.split("param(", 1)[1].split(")\n", 1)[0]
    assert "$PSScriptRoot" not in params


def test_vault_init_refuses_a_new_vault_beside_an_old_dpapi_file() -> None:
    """A leftover DPAPI file from an earlier Vault would win over the fresh
    init.json and fail the unseal blaming the keys."""
    text = VAULT_INIT.read_text(encoding="utf-8")
    block = text.split("if (-not $status.initialized) {", 1)[1].split("operator', 'init'", 1)[0]
    assert "Get-VaultLocalSecretPath" in block


def test_concourse_redacts_secrets_in_build_logs() -> None:
    """TheHub #60802 (folded into 60839): a build log that echoes a resolved
    ((var)) shows it redacted."""
    document = yaml.safe_load((CONCOURSE / "docker-compose.yml").read_text(encoding="utf-8"))
    env = document["services"]["concourse"]["environment"]
    assert str(env.get("CONCOURSE_ENABLE_REDACT_SECRETS")).lower() == "true"
