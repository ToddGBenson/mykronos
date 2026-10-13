"""No script puts a Vault token, or a secret it writes, on a command line.

`vault-secret.ps1` has said since it was written that the token goes in as
`-e VAULT_TOKEN` with no value, forwarded from this process's environment, "so
the token never appears in any command line". Eight other call sites wrote
`-e "VAULT_TOKEN=$token"`, which is the token in docker.exe's argv: readable by
other processes on the host, and recorded verbatim by process-creation
auditing and any EDR. One of them was the Vault root token, under a comment
saying it was not on a command line; another put a freshly rotated ingestion
token into `sh -c "printf %s '<token>' | vault write ..."`, which is also in
the Vault container's process list for as long as the write runs.

Found by globbing, not listed, so the next script is covered the day it is
written.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = sorted(
    p
    for d in ("deploy", "scripts")
    for p in (ROOT / d).rglob("*")
    if p.suffix in {".ps1", ".sh"} and "node_modules" not in p.parts
)

# `VAULT_TOKEN=` followed by an interpolated value: `$x`, `$(...)`, `${x}`.
TOKEN_IN_ARGV = re.compile(r"VAULT_TOKEN=\$")
# A PowerShell variable interpolated inside `sh -c "printf ... '$x'"`.
SECRET_IN_SH_C = re.compile(r"printf\s+%s\s+'\$\w+'")


def _hits(pattern: re.Pattern[str]) -> list[str]:
    return [
        f"{p.relative_to(ROOT)}:{n}: {line.strip()}"
        for p in SCRIPTS
        for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
        if pattern.search(line) and not line.lstrip().startswith("#")
    ]


def test_the_glob_finds_the_scripts() -> None:
    names = {p.name for p in SCRIPTS}
    assert {"vault-secret.ps1", "set-pipeline.ps1", "deploy.ps1"} <= names


def test_no_vault_token_is_passed_by_value() -> None:
    assert _hits(TOKEN_IN_ARGV) == []


def test_no_secret_is_interpolated_into_sh_c() -> None:
    assert _hits(SECRET_IN_SH_C) == []
