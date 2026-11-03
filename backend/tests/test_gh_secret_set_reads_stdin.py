"""`gh secret set NAME --body -` stores a one-character secret: a hyphen.

TheHub #61209. `gh secret set` reads the value from standard input only when
`--body` is NOT given ("reads from standard input if not specified", in gh's
own help). `--body -` is not the stdin convention it looks like: gh takes the
`-` literally, ignores the token piped into it, and reports success.

`repair-ingestion-token.ps1` and `repair-personal-soc-token.ps1` both wrote
the Actions secret that way from 2026-09-01. Nothing noticed while every repo
they touched was scanned by Concourse, which reads Vault, and Vault was
written correctly. binnacle was the first Actions-scanned repo repaired with
it (2026-10-27): its MYKRONOS_INGESTION_TOKEN became `-`, every upload
workflow failed its preflight with a bare 401, and GitHub's log masking
starred out every hyphen in the job log, which is the visible fingerprint.

Text checks, because no test here runs PowerShell (see
test_concourse_bootstrap.py). The value still has to travel on stdin, not
argv (mykronos #817), so the fix is to drop `--body`, not to pass the token
to it.
"""

from __future__ import annotations

import re
import shutil
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CONCOURSE = ROOT / "deploy" / "concourse"
REPAIR_SCRIPTS = [
    CONCOURSE / "repair-ingestion-token.ps1",
    CONCOURSE / "repair-personal-soc-token.ps1",
]

# Everything an operator or a pipeline runs. Tests and docs are left out: they
# may quote the broken form to explain it.
SCANNED_SUFFIXES = {".ps1", ".psm1", ".sh", ".py", ".yml", ".yaml"}
SKIPPED_PARTS = {".git", "node_modules", ".venv", "tests", "docs", ".next"}

GH_SECRET_SET = re.compile(r"\bgh\s+secret\s+set\b[^\n]*")
BODY_DASH = re.compile(r"(?:--body|-b)(?:\s+|=)[\"']?-[\"']?(?=\s|$)")


def _secret_set_lines() -> list[tuple[Path, int, str]]:
    found = []
    for path in ROOT.rglob("*"):
        if path.suffix not in SCANNED_SUFFIXES or not path.is_file():
            continue
        if SKIPPED_PARTS.intersection(path.relative_to(ROOT).parts):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for number, line in enumerate(text.splitlines(), start=1):
            if line.lstrip().startswith("#"):
                continue
            match = GH_SECRET_SET.search(line)
            if match:
                found.append((path, number, match.group(0)))
    return found


def test_no_script_sets_a_secret_to_a_literal_hyphen() -> None:
    offenders = [
        f"{path.relative_to(ROOT)}:{number}: {call}"
        for path, number, call in _secret_set_lines()
        if BODY_DASH.search(call)
    ]
    assert not offenders, (
        "`gh secret set ... --body -` stores the secret as `-` and ignores "
        "stdin; drop --body so gh reads the piped value:\n" + "\n".join(offenders)
    )


def test_the_scan_sees_the_repair_scripts() -> None:
    """Guard on the guard: if the walk stopped finding these calls, the test
    above would pass on an empty list."""
    scanned = {path for path, _, _ in _secret_set_lines()}
    for script in REPAIR_SCRIPTS:
        assert script in scanned, f"{script.name} has no `gh secret set` the scan can see"


def test_an_untracked_stale_copy_does_not_fail_the_scan() -> None:
    """TheHub #61211. The scan judges what is tracked, not whatever sits
    under the checkout. A stale Claude worktree under .claude/worktrees/
    holding the pre-fix script made the test above fail locally while CI,
    on a clean checkout, passed. Plant such a copy and check the scan
    does not see it."""
    planted_dir = ROOT / ".claude" / "worktrees" / f"stale-{uuid.uuid4().hex}"
    planted = planted_dir / "deploy" / "concourse" / "repair-ingestion-token.ps1"
    created_parents = [
        parent for parent in (ROOT / ".claude", ROOT / ".claude" / "worktrees")
        if not parent.exists()
    ]
    planted.parent.mkdir(parents=True)
    try:
        planted.write_text(
            "$token | gh secret set MYKRONOS_INGESTION_TOKEN --body -\n",
            encoding="utf-8",
        )
        scanned = {path for path, _, _ in _secret_set_lines()}
        assert planted not in scanned, "an untracked file was scanned"
    finally:
        shutil.rmtree(planted_dir)
        for parent in reversed(created_parents):
            try:
                parent.rmdir()
            except OSError:
                pass


@pytest.mark.parametrize("script", REPAIR_SCRIPTS, ids=lambda p: p.name)
def test_repair_scripts_pipe_the_token_on_stdin(script: Path) -> None:
    """Still on stdin, never argv (#817): the token is piped in, and no
    `--body` follows to override it."""
    calls = [
        line.strip()
        for line in script.read_text(encoding="utf-8").splitlines()
        if GH_SECRET_SET.search(line) and not line.lstrip().startswith("#")
    ]
    assert calls, f"{script.name} no longer writes the Actions secret"
    for call in calls:
        assert re.match(r"^\$token\s*\|\s*gh\s+secret\s+set\b", call), call
        assert not re.search(r"(?:--body|-b)\b", call), call
