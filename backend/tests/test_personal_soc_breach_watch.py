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


def run_watch(tmp_path: Path, exit_code: int | None, *, domains: bool, breaches: bool = False):
    skill = tmp_path / "skill"
    scripts = skill / "scripts"
    (skill / "references").mkdir(parents=True)
    scripts.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    script = scripts / "Get-NewBreaches.ps1"
    if exit_code is not None:
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
        "$env:MYKRONOS_TEST_LOAD_ONLY='1'; "
        f". '{SCRIPT}'; "
        f"$r = Invoke-BreachWatch -Script '{script}' -OutDir '{out}'; "
        "$r | ConvertTo-Json -Compress"
    )
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-Command", driver], capture_output=True, text=True, timeout=120
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout.strip().splitlines()[-1])


@needs_pwsh
class TestInvokeBreachWatch:
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
