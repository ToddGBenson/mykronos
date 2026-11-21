"""The weekly threat monitor runs the key-free breach watch (TheHub #61367).

`run-threat-monitor.ps1` used to say breach-check was a Concourse job; it was
retired 2026-09-23. The replacement, the skill's `Get-NewBreaches.ps1`, needs
no key but reads a git-ignored domains file, so it can only run on the owner's
machine, from this script. The executable tests run the script's own
`Invoke-BreachWatch` against a fake skill folder: exit 0 is clean, 1 names the
breaches, and 2, a crash, a missing script and a missing domains file are all
reported as not clean.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "deploy" / "personal-soc" / "run-threat-monitor.ps1"
PIPELINE = ROOT / "deploy" / "concourse" / "pipelines" / "personal-soc.yml"

needs_pwsh = pytest.mark.skipif(shutil.which("pwsh") is None, reason="needs pwsh on PATH")


def text() -> str:
    return SCRIPT.read_text(encoding="ascii")


class TestWording:
    def test_it_no_longer_calls_breach_check_a_concourse_job(self) -> None:
        assert "breach-check, a Concourse job" not in text()

    def test_it_names_the_key_free_script(self) -> None:
        assert "Get-NewBreaches.ps1" in text()

    def test_it_runs_the_watch_before_the_model(self) -> None:
        body = text()
        assert body.index("Invoke-BreachWatch -Script") < body.index("--print $prompt")

    def test_the_functional_job_lists_the_script_as_not_covered_live(self) -> None:
        assert "Get-NewBreaches.ps1" in PIPELINE.read_text(encoding="utf-8")


BOGUS = "C:/mykronos-test-nonexistent"
GUARD_ARGS = f"-Claude '{BOGUS}/claude.exe' -Repo '{BOGUS}/repo'"


def safe_pwsh(command: str) -> subprocess.CompletedProcess[str]:
    """The only way these tests start pwsh.

    run-threat-monitor.ps1 starts a real unattended Claude run when it is
    executed, so refuse any command that is not pointed at paths that do not
    exist, and always set the load-only variable.
    """
    assert f"-Claude '{BOGUS}" in command
    assert f"-Repo '{BOGUS}" in command
    assert not Path(BOGUS).exists()
    return subprocess.run(
        ["pwsh", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        timeout=120,
        env={**os.environ, "MYKRONOS_TEST_LOAD_ONLY": "1"},
    )


def run_watch(
    tmp_path: Path,
    exit_code: int | None,
    *,
    domains: bool,
    breaches: bool = False,
    crash: bool = False,
    stale: bool = False,
):
    skill = tmp_path / "skill"
    scripts = skill / "scripts"
    (skill / "references").mkdir(parents=True)
    scripts.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    if stale:
        (out / "new-breaches.json").write_text(
            '[{"name":"StaleService","domain":"stale.test"}]', encoding="ascii"
        )
    script = scripts / "Get-NewBreaches.ps1"
    if crash:
        script.write_text("param([string]$OutDir='.')\nthrow 'boom'\n", encoding="ascii")
    elif exit_code is not None:
        body = "param([string]$OutDir='.')\n"
        if breaches:
            body += (
                "'[{\"name\":\"ExampleService\",\"domain\":\"example.test\"}]'"
                " | Set-Content (Join-Path $OutDir 'new-breaches.json')\n"
            )
        body += f"exit {exit_code}\n"
        script.write_text(body, encoding="ascii")
    if domains:
        (skill / "references" / "account-domains.local.txt").write_text("example.test\n")
    driver = (
        f". '{SCRIPT}' {GUARD_ARGS}; "
        f"$r = Invoke-BreachWatch -Script '{script}' -OutDir '{out}'; "
        "$r | ConvertTo-Json -Compress"
    )
    proc = safe_pwsh(driver)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout.strip().splitlines()[-1])


@needs_pwsh
class TestGuard:
    def test_running_the_script_with_the_variable_set_throws(self) -> None:
        proc = safe_pwsh(f"& '{SCRIPT}' {GUARD_ARGS}; exit 0")
        assert proc.returncode != 0
        assert "not dot-sourced" in proc.stderr + proc.stdout

    def test_dot_sourcing_with_the_variable_set_loads_the_functions(self) -> None:
        proc = safe_pwsh(f". '{SCRIPT}' {GUARD_ARGS}; (Get-Command Invoke-BreachWatch).Name")
        assert proc.returncode == 0, proc.stderr
        assert "Invoke-BreachWatch" in proc.stdout


@needs_pwsh
class TestInvokeBreachWatch:
    def test_a_crash_is_unknown_not_a_new_breach(self, tmp_path: Path) -> None:
        r = run_watch(tmp_path, None, domains=True, crash=True)
        assert (r["Code"], r["State"]) == (2, "unknown")

    def test_a_crash_never_reports_a_stale_file(self, tmp_path: Path) -> None:
        r = run_watch(tmp_path, None, domains=True, crash=True, stale=True)
        assert (r["Code"], r["State"]) == (2, "unknown")
        assert "StaleService" not in r["Text"]

    def test_exit_one_without_a_fresh_file_is_unknown(self, tmp_path: Path) -> None:
        r = run_watch(tmp_path, 1, domains=True, stale=True)
        assert (r["Code"], r["State"]) == (2, "unknown")
        assert "StaleService" not in r["Text"]

    def test_exit_zero_is_clean(self, tmp_path: Path) -> None:
        r = run_watch(tmp_path, 0, domains=True)
        assert (r["Code"], r["State"]) == (0, "clean")

    def test_exit_one_names_the_breaches(self, tmp_path: Path) -> None:
        r = run_watch(tmp_path, 1, domains=True, breaches=True)
        assert (r["Code"], r["State"]) == (1, "new-breaches")
        assert "ExampleService (example.test)" in r["Text"]

    def test_exit_two_is_unknown_never_clean(self, tmp_path: Path) -> None:
        r = run_watch(tmp_path, 2, domains=True)
        assert (r["Code"], r["State"]) == (2, "unknown")
        assert "not a pass" in r["Text"]

    def test_an_unexpected_exit_code_is_unknown(self, tmp_path: Path) -> None:
        r = run_watch(tmp_path, 7, domains=True)
        assert r["State"] == "unknown"

    def test_a_missing_domains_file_is_not_configured(self, tmp_path: Path) -> None:
        r = run_watch(tmp_path, 0, domains=False)
        assert (r["Code"], r["State"]) == (2, "not-configured")
        assert "not configured" in r["Text"]

    def test_a_missing_script_is_unknown(self, tmp_path: Path) -> None:
        r = run_watch(tmp_path, None, domains=True)
        assert r["State"] == "unknown"
