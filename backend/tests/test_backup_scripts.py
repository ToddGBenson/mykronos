"""The backup chain's decisions, driven without Docker, Azure or a real key (TheHub #60842).

`deploy/backup/` backs up the operational database, the lake, MinIO and
Vault's storage. Everything that DECIDES something lives in
`MyKronosBackup.psm1` as a pure function, and this file runs those functions
in pwsh the way test_registry_scope_remove.py runs its script:

  * the HUBENC1 codec round-trips with Python's `cryptography` Fernet in both
    directions -- it is TheHub's format, so TheHub's decrypt must open
    Mykronos's archives and the reverse -- and refuses truncation and a wrong
    key without leaving output behind;
  * `Get-BackupVerdict` turns a manifest into ok / degraded / failed;
  * `Select-BackupsToPrune` never takes the last good copies;
  * `Get-DrillVerdict` keeps an inconclusive drill apart from a failed one;
  * the SAS signature never reaches a printable form;
  * `Backup-MyKronos.ps1 -DryRun` and `Test-MyKronosRestore.ps1 -DryRun`
    write nothing and execute nothing, with `docker` shadowed by a function
    that records its calls; and a real run with no key refuses before it
    creates a directory.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import struct
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
BACKUP_DIR = ROOT / "deploy" / "backup"
MODULE = BACKUP_DIR / "MyKronosBackup.psm1"
BACKUP_SCRIPT = BACKUP_DIR / "Backup-MyKronos.ps1"
DRILL_SCRIPT = BACKUP_DIR / "Test-MyKronosRestore.ps1"

needs_pwsh = pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh is not on PATH")

# A fixed, test-only Fernet key (url-safe base64 of 32 bytes). Never a real one.
KEY = base64.urlsafe_b64encode(bytes(range(32))).decode()
OTHER_KEY = base64.urlsafe_b64encode(bytes(range(1, 33))).decode()
MAGIC = b"HUBENC1\n"


def _env(**extra: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("MYKRONOS_BACKUP_")}
    env.update(extra)
    return env


def pwsh(program: str, *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", program],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=180,
        env=env or _env(),
    )


def call_json(body: str, **env: str) -> Any:
    """Import the module, run `body`, and parse what it printed as JSON."""
    out = pwsh(
        f"Import-Module '{MODULE}' -Force\n{body} | ConvertTo-Json -Depth 8 -Compress",
        env=_env(**env),
    )
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def ps_literal(value: Any) -> str:
    """A JSON document as a PowerShell single-quoted literal, parsed back."""
    text = json.dumps(value).replace("'", "''")
    return f"('{text}' | ConvertFrom-Json)"


# ---------------------------------------------------------------------------
# The codec
# ---------------------------------------------------------------------------


def python_decrypt(path: Path, key: str) -> bytes:
    """TheHub's reader, reduced to the format: magic, header frame, frames."""
    from cryptography.fernet import Fernet

    f = Fernet(key.encode())
    data = path.read_bytes()
    assert data[:8] == MAGIC
    pos = 8
    frames: list[bytes] = []
    while pos < len(data):
        (n,) = struct.unpack(">I", data[pos : pos + 4])
        frames.append(data[pos + 4 : pos + 4 + n])
        pos += 4 + n
    header = json.loads(f.decrypt(frames[0]))
    body = b"".join(f.decrypt(t) for t in frames[1:])
    assert header["v"] == 1
    assert header["size"] == len(body)
    assert header["sha256"] == hashlib.sha256(body).hexdigest()
    return body


def python_encrypt(src: bytes, dst: Path, key: str, chunk: int = 1000) -> None:
    from cryptography.fernet import Fernet

    f = Fernet(key.encode())
    header = json.dumps(
        {"v": 1, "sha256": hashlib.sha256(src).hexdigest(), "size": len(src), "chunk": chunk},
        sort_keys=True,
    ).encode()
    out = bytearray(MAGIC)
    for token in [f.encrypt(header)] + [
        f.encrypt(src[i : i + chunk]) for i in range(0, len(src), chunk)
    ]:
        out += struct.pack(">I", len(token)) + token
    dst.write_bytes(bytes(out))


@needs_pwsh
class TestCodec:
    def test_powershell_archive_opens_with_python_fernet(self, tmp_path: Path) -> None:
        pytest.importorskip("cryptography")
        plain = os.urandom(10_000) + b"tail"
        src, dst = tmp_path / "p.bin", tmp_path / "p.hubenc"
        src.write_bytes(plain)
        result = call_json(
            f"Protect-BackupFile -Path '{src}' -Destination '{dst}' -Key '{KEY}' -ChunkBytes 3000"
        )
        assert result["Frames"] == 4
        assert result["PlaintextSha256"] == hashlib.sha256(plain).hexdigest()
        assert python_decrypt(dst, KEY) == plain

    def test_python_archive_opens_in_powershell(self, tmp_path: Path) -> None:
        pytest.importorskip("cryptography")
        plain = os.urandom(5_500)
        src, out = tmp_path / "p.hubenc", tmp_path / "p.out"
        python_encrypt(plain, src, KEY)
        result = call_json(f"Unprotect-BackupFile -Path '{src}' -Destination '{out}' -Key '{KEY}'")
        assert out.read_bytes() == plain
        assert result["PlaintextBytes"] == len(plain)

    def test_empty_file_round_trips(self, tmp_path: Path) -> None:
        src, dst, out = tmp_path / "e", tmp_path / "e.hubenc", tmp_path / "e.out"
        src.write_bytes(b"")
        call_json(
            f"Protect-BackupFile -Path '{src}' -Destination '{dst}' -Key '{KEY}' | Out-Null; "
            f"Unprotect-BackupFile -Path '{dst}' -Destination '{out}' -Key '{KEY}'"
        )
        assert out.read_bytes() == b""

    def _encrypted(self, tmp_path: Path) -> Path:
        src, dst = tmp_path / "p.bin", tmp_path / "p.hubenc"
        src.write_bytes(os.urandom(9_000))
        call_json(
            f"Protect-BackupFile -Path '{src}' -Destination '{dst}' -Key '{KEY}' -ChunkBytes 3000"
        )
        return dst

    def _unprotect(self, src: Path, out: Path, key: str = KEY) -> subprocess.CompletedProcess[str]:
        return pwsh(
            f"Import-Module '{MODULE}' -Force\n"
            f"try {{ Unprotect-BackupFile -Path '{src}' -Destination '{out}' -Key '{key}' "
            "| Out-Null; 'RESTORED' }"
            " catch { 'REFUSED: ' + $_.Exception.Message }"
        )

    def test_a_dropped_trailing_frame_is_refused_and_leaves_nothing(self, tmp_path: Path) -> None:
        # Every remaining frame still authenticates; only the sealed size and
        # digest notice. This is the corruption an interrupted upload makes.
        dst = self._encrypted(tmp_path)
        data = dst.read_bytes()
        pos, frames = 8, []
        while pos < len(data):
            (n,) = struct.unpack(">I", data[pos : pos + 4])
            frames.append(pos)
            pos += 4 + n
        dst.write_bytes(data[: frames[-1]])
        out = tmp_path / "out"
        result = self._unprotect(dst, out)
        assert "REFUSED" in result.stdout and "truncated" in result.stdout
        assert not out.exists()

    def test_a_cut_mid_frame_is_refused(self, tmp_path: Path) -> None:
        dst = self._encrypted(tmp_path)
        dst.write_bytes(dst.read_bytes()[:-10])
        out = tmp_path / "out"
        assert "REFUSED" in self._unprotect(dst, out).stdout
        assert not out.exists()

    def test_the_wrong_key_is_refused(self, tmp_path: Path) -> None:
        dst = self._encrypted(tmp_path)
        out = tmp_path / "out"
        result = self._unprotect(dst, out, OTHER_KEY)
        assert "REFUSED" in result.stdout and "wrong key" in result.stdout
        assert not out.exists()

    def test_a_malformed_key_names_the_setting_and_never_the_value(self, tmp_path: Path) -> None:
        src = tmp_path / "p.bin"
        src.write_bytes(b"x")
        bad = "not-a-key-SECRETVALUE"
        out = pwsh(
            f"Import-Module '{MODULE}' -Force\n"
            f"try {{ Protect-BackupFile -Path '{src}' -Destination '{tmp_path / 'o'}' "
            f"-Key '{bad}' }}"
            " catch { 'REFUSED: ' + $_.Exception.Message }"
        )
        assert "MYKRONOS_BACKUP_ENCRYPTION_KEY is not a valid Fernet key" in out.stdout
        assert "SECRETVALUE" not in out.stdout + out.stderr


# ---------------------------------------------------------------------------
# Judging a manifest
# ---------------------------------------------------------------------------


def component(name: str, **over: Any) -> dict[str, Any]:
    c = {
        "name": name,
        "status": "ok",
        "file": f"{name}.tar.gz.hubenc",
        "bytes": 1234,
        "sha256": "a" * 64,
        "warnings": [],
        "error": None,
    }
    c.update(over)
    return c


def manifest(**over: Any) -> dict[str, Any]:
    m: dict[str, Any] = {
        "created_utc": "2026-10-18T03:00:00Z",
        "components": [
            component(n) for n in ("operational-db", "datalake", "minio", "vault-storage")
        ],
        "offsite": {"status": "ok", "failed": [], "sas_expires_utc": "2027-10-18T00:00:00Z"},
        "errors": [],
    }
    m.update(over)
    return m


def verdict(m: dict[str, Any]) -> dict[str, Any]:
    return call_json(
        f"$v = Get-BackupVerdict -Manifest {ps_literal(m)}; "
        "[pscustomobject]@{ Verdict = $v.Verdict; Errors = @($v.Errors); "
        "Warnings = @($v.Warnings); "
        "Exit = (Get-VerdictExitCode -Verdict $v.Verdict) }"
    )


@needs_pwsh
class TestVerdict:
    def test_a_complete_set_with_its_offsite_copy_is_ok(self) -> None:
        v = verdict(manifest())
        assert (v["Verdict"], v["Exit"], v["Errors"]) == ("ok", 0, [])

    def test_no_offsite_configured_is_degraded_not_ok(self) -> None:
        # One copy in the same room as its source: a real gap, a different
        # exit code from a broken backup.
        v = verdict(manifest(offsite={"status": "not-configured"}))
        assert (v["Verdict"], v["Exit"]) == ("degraded", 2)

    def test_an_offsite_upload_that_failed_is_a_failure(self) -> None:
        v = verdict(manifest(offsite={"status": "failed", "failed": ["datalake.tar.gz.hubenc"]}))
        assert (v["Verdict"], v["Exit"]) == ("failed", 1)
        assert "1 file(s) failed" in v["Errors"][0]

    def test_a_manifest_still_pending_upload_is_a_failure(self) -> None:
        # The interim manifest written before the upload must never read as
        # "predates offsite tracking" -- TheHub #59071.
        v = verdict(manifest(offsite={"status": "pending"}))
        assert v["Verdict"] == "failed"

    def test_a_failed_component_fails_the_set(self) -> None:
        comps = manifest()["components"]
        comps[1] = component("datalake", status="failed", error="tar exited 2")
        v = verdict(manifest(components=comps))
        assert v["Verdict"] == "failed"
        assert any("datalake" in e and "tar exited 2" in e for e in v["Errors"])

    def test_a_missing_component_fails_the_set(self) -> None:
        comps = [c for c in manifest()["components"] if c["name"] != "vault-storage"]
        v = verdict(manifest(components=comps))
        assert v["Verdict"] == "failed"
        assert any("vault-storage is missing" in e for e in v["Errors"])

    @pytest.mark.parametrize(
        "over, expected",
        [
            ({"bytes": 0}, "is empty"),
            ({"sha256": None}, "no SHA-256"),
            ({"file": "datalake.tar.gz"}, "no encrypted file"),
        ],
    )
    def test_an_ok_component_without_its_evidence_is_not_ok(
        self, over: dict[str, Any], expected: str
    ) -> None:
        comps = manifest()["components"]
        comps[1] = component("datalake", **over)
        v = verdict(manifest(components=comps))
        assert v["Verdict"] == "failed"
        assert any(expected in e for e in v["Errors"])

    def test_a_sas_close_to_expiry_warns_without_failing(self) -> None:
        v = verdict(
            manifest(
                offsite={"status": "ok", "failed": [], "sas_expires_utc": "2026-10-23T00:00:00Z"}
            )
        )
        assert v["Verdict"] == "ok"
        assert any("SAS expires" in w for w in v["Warnings"])

    def test_tar_warnings_are_carried_but_do_not_fail(self) -> None:
        comps = manifest()["components"]
        comps[1] = component("datalake", warnings=["tar: files changed while being read"])
        v = verdict(manifest(components=comps))
        assert v["Verdict"] == "ok"
        assert v["Warnings"] == ["datalake: tar: files changed while being read"]


# ---------------------------------------------------------------------------
# Local retention
# ---------------------------------------------------------------------------


def prune(sets: list[tuple[int, bool]], retain_days: int = 7, min_keep: int = 3) -> list[str]:
    """sets: (age in days, success). Names are mykronos_<n>."""
    now = datetime(2026, 10, 18, 3, 0, 0)
    rows = ", ".join(
        f"[pscustomobject]@{{ Name = 'set{i}'; "
        f"Created = [datetime]'{(now - timedelta(days=age)).isoformat()}'; "
        f"Success = ${str(ok).lower()} }}"
        for i, (age, ok) in enumerate(sets)
    )
    # -InputObject, not the pipeline: piped, one name serialises as a bare
    # string and none as nothing at all.
    out = pwsh(
        f"Import-Module '{MODULE}' -Force\n"
        f"ConvertTo-Json -Compress -InputObject @(Select-BackupsToPrune -Sets @({rows}) "
        f"-RetainDays {retain_days} -MinKeep {min_keep} -Now ([datetime]'{now.isoformat()}'))"
    )
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


@needs_pwsh
class TestRetention:
    def test_old_sets_past_the_floor_go(self) -> None:
        assert sorted(prune([(0, True), (1, True), (2, True), (10, True), (11, True)])) == [
            "set3",
            "set4",
        ]

    def test_the_floor_holds_when_every_set_is_old(self) -> None:
        # The producer stopped a month ago: retention must not reap the last
        # good copies (TheHub's 2026-07 outage).
        assert prune([(30, True), (31, True), (32, True), (33, True)]) == ["set3"]

    def test_failed_sets_do_not_count_toward_the_floor(self) -> None:
        pruned = prune([(1, False), (2, False), (3, False), (20, True), (21, True), (22, True)])
        assert pruned == []

    def test_old_failed_sets_are_pruned(self) -> None:
        assert prune([(0, True), (1, True), (2, True), (9, False)]) == ["set3"]

    def test_nothing_young_is_touched(self) -> None:
        assert prune([(0, False), (1, False), (6, True)], min_keep=0) == []


# ---------------------------------------------------------------------------
# Drill verdicts and SAS hygiene
# ---------------------------------------------------------------------------


def drill(statuses: list[str]) -> dict[str, Any]:
    rows = ", ".join(
        f"[pscustomobject]@{{ name = 'c{i}'; status = '{s}' }}" for i, s in enumerate(statuses)
    )
    return call_json(f"Get-DrillVerdict -Checks @({rows})")


@needs_pwsh
class TestDrillVerdict:
    def test_all_pass_with_a_skip_passes(self) -> None:
        assert drill(["pass", "pass", "skip"])["Verdict"] == "pass"

    def test_one_fail_fails(self) -> None:
        v = drill(["pass", "fail", "inconclusive"])
        assert (v["Verdict"], v["ExitCode"], v["Failed"]) == ("fail", 1, ["c1"])

    def test_inconclusive_is_its_own_answer(self) -> None:
        v = drill(["pass", "inconclusive"])
        assert (v["Verdict"], v["ExitCode"]) == ("inconclusive", 2)

    def test_no_checks_is_a_failure(self) -> None:
        assert call_json("Get-DrillVerdict -Checks @()")["Verdict"] == "fail"


SAS = "https://acct.blob.core.windows.net/mykronos-backups?sv=2022-11-02&se=2027-01-31T00%3A00%3A00Z&sr=c&sp=cw&sig=SECRETSIG"


@needs_pwsh
class TestSas:
    def test_the_printable_url_has_no_signature(self) -> None:
        safe = call_json(f"Get-SafeContainerUrl -SasUrl '{SAS}'")
        assert safe == "https://acct.blob.core.windows.net/mykronos-backups"

    def test_expiry_is_read_from_se(self) -> None:
        assert call_json(f"(Get-SasExpiry -SasUrl '{SAS}').ToString('yyyy-MM-dd')") == "2027-01-31"


# ---------------------------------------------------------------------------
# The scripts: dry runs execute nothing, and no key means no directory
# ---------------------------------------------------------------------------

DOCKER_MOCK = r"""
$global:DockerCalls = @()
function global:docker {
  $global:DockerCalls += ($args -join ' ')
  $global:LASTEXITCODE = 0
  switch ($args[0]) {
    'version' { '27.0.0' }
    'inspect' {
      if ($args -contains '{{.Config.Image}}') { 'mykronos-backend:test' } else { 'true' }
    }
    'volume'  { $args[-1] }
    default   { $global:LASTEXITCODE = 99; 'unexpected docker call' }
  }
}
"""


def run_script(
    script: Path, root: Path, *args: str, env: dict[str, str]
) -> tuple[int, str, list[str]]:
    calls = root.parent / f"{root.name}-calls.json"
    # A path that does not exist, so a developer's real DPAPI secrets file is
    # never read by a test.
    secrets = root.parent / "no-such-secrets.clixml"
    program = (
        DOCKER_MOCK
        + f"& '{script}' -BackupRoot '{root}' -SecretPath '{secrets}' {' '.join(args)} "
        + '*>&1 | ForEach-Object { "$_" }\n'
        + "$code = $LASTEXITCODE\n"
        + f",$global:DockerCalls | ConvertTo-Json | Set-Content -Path '{calls}'\n"
        + "exit $code\n"
    )
    out = pwsh(program, env=env)
    recorded = json.loads(calls.read_text(encoding="utf-8")) if calls.exists() else []
    return out.returncode, out.stdout + out.stderr, [c for c in (recorded or []) if c]


@needs_pwsh
class TestBackupScript:
    def test_dry_run_prints_the_plan_and_executes_nothing(self, tmp_path: Path) -> None:
        root = tmp_path / "backups"
        code, output, calls = run_script(
            BACKUP_SCRIPT,
            root,
            "-DryRun",
            "-MinFreeGB",
            "0",
            env=_env(MYKRONOS_BACKUP_ENCRYPTION_KEY=KEY),
        )
        assert code == 0, output
        assert "preflight passed" in output
        for volume in (
            "mykronos_mykronos-data",
            "mykronos-concourse_minio-data",
            "mykronos-concourse_vault-data",
        ):
            assert volume in output
        assert "excluded   : registry" in output
        assert "vault-unseal-key-and-root-token" in output
        assert "offsite    : NOT CONFIGURED" in output
        assert KEY not in output
        assert not root.exists()
        assert not any(c.split()[0] in ("run", "exec", "cp") for c in calls), calls

    def test_dry_run_never_prints_the_sas_signature(self, tmp_path: Path) -> None:
        code, output, _ = run_script(
            BACKUP_SCRIPT,
            tmp_path / "b",
            "-DryRun",
            "-MinFreeGB",
            "0",
            env=_env(MYKRONOS_BACKUP_ENCRYPTION_KEY=KEY, MYKRONOS_BACKUP_SAS_URL=SAS),
        )
        assert code == 0, output
        assert "https://acct.blob.core.windows.net/mykronos-backups/<set>/" in output
        assert "SECRETSIG" not in output

    def test_dry_run_without_a_key_says_it_would_refuse(self, tmp_path: Path) -> None:
        code, output, _ = run_script(
            BACKUP_SCRIPT, tmp_path / "b", "-DryRun", "-MinFreeGB", "0", env=_env()
        )
        assert code == 1
        assert "WOULD REFUSE: MYKRONOS_BACKUP_ENCRYPTION_KEY is not set" in output

    def test_a_real_run_without_a_key_creates_nothing(self, tmp_path: Path) -> None:
        root = tmp_path / "backups"
        code, output, calls = run_script(BACKUP_SCRIPT, root, "-MinFreeGB", "0", env=_env())
        assert code == 1
        assert "REFUSING TO RUN - MYKRONOS_BACKUP_ENCRYPTION_KEY is not set" in output
        assert not root.exists()
        assert not any(c.split()[0] in ("run", "exec", "cp") for c in calls), calls


@needs_pwsh
class TestDrillScript:
    def _set(self, root: Path, name: str, success: bool) -> None:
        d = root / name
        d.mkdir(parents=True)
        (d / "manifest.json").write_text(
            json.dumps({"success": success, "components": []}), encoding="ascii"
        )

    def test_dry_run_picks_the_newest_successful_set_and_creates_nothing(
        self, tmp_path: Path
    ) -> None:
        root = tmp_path / "backups"
        self._set(root, "mykronos_20261016_030000", True)
        self._set(root, "mykronos_20261017_030000", True)
        self._set(root, "mykronos_20261018_030000", False)
        before = sorted(p.name for p in root.iterdir())
        code, output, calls = run_script(
            DRILL_SCRIPT, root, "-DryRun", env=_env(MYKRONOS_BACKUP_ENCRYPTION_KEY=KEY)
        )
        assert code == 0, output
        assert "set        : mykronos_20261017_030000" in output
        assert "the newest set mykronos_20261018_030000 is not successful" in output
        assert sorted(p.name for p in root.iterdir()) == before
        assert not any(c.split()[0] in ("run", "exec", "cp", "volume") for c in calls), calls

    def test_dry_run_with_no_backup_says_the_drill_would_fail(self, tmp_path: Path) -> None:
        code, output, _ = run_script(
            DRILL_SCRIPT, tmp_path / "none", "-DryRun", env=_env(MYKRONOS_BACKUP_ENCRYPTION_KEY=KEY)
        )
        assert code == 0
        assert "NONE - the drill would fail" in output

    def test_a_real_drill_with_no_backup_fails(self, tmp_path: Path) -> None:
        code, output, _ = run_script(
            DRILL_SCRIPT, tmp_path / "none", env=_env(MYKRONOS_BACKUP_ENCRYPTION_KEY=KEY)
        )
        assert code == 1, output
        assert "no successful backup set found" in output
