"""No script puts a token, a password or a key on a command line.

`vault-secret.ps1` has said since it was written that the token goes in as
`-e VAULT_TOKEN` with no value, forwarded from this process's environment, "so
the token never appears in any command line". Eight other call sites wrote
`-e "VAULT_TOKEN=$token"`, which is the token in docker.exe's argv: readable by
other processes on the host, and recorded verbatim by process-creation
auditing and any EDR. One of them was the Vault root token, under a comment
saying it was not on a command line; another put a freshly rotated ingestion
token into `sh -c "printf %s '<token>' | vault write ..."`, which is also in
the Vault container's process list for as long as the write runs.

#817 fixed those and added this test. #821 then copied the old pattern back
into enable-agent-reviewer.ps1 from a stale checkout; this test went red on
that pull request and it merged anyway, because `backend-tests` is advisory.
#822 fixed it. The `secret-hygiene` job in backend-pr.yml now runs this file on
its own, in seconds and with nothing installed but pytest, so that check can be
made required without waiting for the full suite to be shown steady (D-162).

It covers every secret-named variable, not only VAULT_TOKEN: a GitHub token or
an API key passed by value is in the same process list.

Found by globbing, not listed, so the next script is covered the day it is
written. Standard library only: the `secret-hygiene` job does not install the
backend.
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

# A variable name that holds a secret.
_SECRET_NAME = r"[A-Za-z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY)[A-Za-z0-9_]*"
# `-e NAME=$x`, `-e "NAME=$(...)"`, `--env NAME=${x}`, `--env=NAME=$x` and
# `--build-arg NAME=$x`: a secret-named variable given a value on the command
# line. `-e NAME` with no value forwards it from the environment and is fine.
SECRET_IN_ARGV = re.compile(
    rf"(?:-e|--env|--build-arg)[ =]+[\"']?{_SECRET_NAME}=\$", re.IGNORECASE
)
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


def test_no_secret_is_passed_by_value() -> None:
    assert _hits(SECRET_IN_ARGV) == []


def test_no_secret_is_interpolated_into_sh_c() -> None:
    assert _hits(SECRET_IN_SH_C) == []


def test_the_pattern_catches_what_it_is_for() -> None:
    """The cases above pass on a clean tree, which proves nothing about the
    pattern. These are the shapes #817 and #821 removed, and their neighbours."""
    caught = [
        'docker exec -e "VAULT_TOKEN=$vaultToken" vault vault kv get x',
        "docker run -e VAULT_TOKEN=$(cat token) img",
        "docker run --env GITHUB_TOKEN=${token} img",
        "docker run --env=MYKRONOS_REVIEWER_API_KEY=$key img",
        "docker build --build-arg NPM_TOKEN=$t .",
        "docker run -e 'DB_PASSWORD=$pw' img",
        "docker run -e hub_api_token=$t img",
    ]
    allowed = [
        "docker exec -e VAULT_TOKEN vault vault kv get x",
        'docker run -e "MYKRONOS_ENV=$envName" img',
        "docker run -e LOG_LEVEL=debug img",
        "$env:VAULT_TOKEN = $token",
        "GITHUB_TOKEN=$(gh auth token)",
    ]
    assert [c for c in caught if not SECRET_IN_ARGV.search(c)] == []
    assert [a for a in allowed if SECRET_IN_ARGV.search(a)] == []
