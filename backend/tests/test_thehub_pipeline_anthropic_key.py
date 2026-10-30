"""`set-thehub-pipeline.ps1` finds TheHub's Claude key and never bakes it empty (TheHub #61085).

TheHub's .env names the key `CLAUDE_API_KEY`. The script read only
`ANTHROPIC_API_KEY`, found nothing, and wrote `anthropic-api-key: ''` into the
pipeline config unconditionally - which overrides Vault - so `ai-models` failed
on every commit after the pipeline was re-set on 2026-10-29.

Three properties, each checked by running the script's own code with pwsh:
the key is found under either name (CLAUDE_API_KEY first), a missing key stops
the script with an error that names both variables and never the value, and the
literal vars block no longer writes the key at all.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
APPLIER = ROOT / "deploy" / "concourse" / "set-thehub-pipeline.ps1"
SENTINEL = "sk-ant-sentinel-must-not-appear"
PWSH = shutil.which("pwsh")


def _source() -> str:
    return APPLIER.read_text(encoding="utf-8")


def _between(text: str, start: str, end: str) -> str:
    i = text.index(start)
    return text[i : text.index(end, i)]


def _run(script: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [PWSH, "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=60,
    )


def _selection(env_path: Path) -> str:
    """Read-EnvValue plus the key-selection block, as they stand in the script."""
    src = _source()
    read_env = _between(src, "function Read-EnvValue", "\n}\n") + "\n}\n"
    select = _between(src, '$hubAnthropicKey = ""', "if (-not $hubAnthropicKey) {")
    return f"$TheHubEnvPath = '{env_path}'\n{read_env}\n{select}\n"


needs_pwsh = pytest.mark.skipif(PWSH is None, reason="pwsh is not installed")


@needs_pwsh
@pytest.mark.parametrize(
    "lines",
    [
        [f"CLAUDE_API_KEY={SENTINEL}"],
        [f"ANTHROPIC_API_KEY={SENTINEL}"],
        [f"CLAUDE_API_KEY={SENTINEL}", "ANTHROPIC_API_KEY=other"],
    ],
    ids=["claude-name", "anthropic-name", "claude-wins"],
)
def test_the_key_is_found_under_either_name(tmp_path: Path, lines: list[str]) -> None:
    env = tmp_path / ".env"
    env.write_text("\n".join(["OTHER=x", *lines]) + "\n", encoding="utf-8")

    got = _run(_selection(env) + "if ($hubAnthropicKey -eq '%s') { 'MATCH' } else { 'NO' }" % SENTINEL)

    assert got.returncode == 0, got.stderr
    assert got.stdout.strip().splitlines()[-1] == "MATCH"


@needs_pwsh
def test_a_missing_key_stops_the_script_naming_both_variables(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text("OTHER=x\n", encoding="utf-8")
    fallback = re.search(
        r'Add-Secret -Name "anthropic-api-key"\s+-Fallback (\{.*?\n\})', _source(), re.S
    )
    assert fallback, "anthropic-api-key fallback not found"

    got = _run(_selection(env) + f"& {fallback.group(1)}")

    assert got.returncode != 0
    assert "CLAUDE_API_KEY" in got.stderr and "ANTHROPIC_API_KEY" in got.stderr


@needs_pwsh
def test_a_found_key_is_returned_by_the_fallback_and_not_printed(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text(f"CLAUDE_API_KEY={SENTINEL}\n", encoding="utf-8")
    fallback = re.search(
        r'Add-Secret -Name "anthropic-api-key"\s+-Fallback (\{.*?\n\})', _source(), re.S
    )
    assert fallback

    got = _run(_selection(env) + f"$v = & {fallback.group(1)}; $v.Length")

    assert got.returncode == 0, got.stderr
    assert got.stdout.strip().splitlines()[-1] == str(len(SENTINEL))
    assert SENTINEL not in got.stdout + got.stderr


def test_the_vars_block_no_longer_writes_the_key() -> None:
    """Written there unconditionally, it overrode Vault - and was '' when unread."""
    block = _between(_source(), '"minio-endpoint:', "$vars = $vars + $secretVars")
    live = [ln for ln in block.splitlines() if not ln.strip().startswith("#")]
    assert not any("anthropic-api-key" in ln for ln in live)
