#!/usr/bin/env python3
"""Point this clone's git hooks at scripts/hooks/.

    python scripts/install_hooks.py

Sets core.hooksPath so the committed hooks in scripts/hooks/ run, rather than
copying files into .git/hooks where they cannot be reviewed or updated with
the tree. Idempotent; safe to re-run.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    hooks = ROOT / "scripts" / "hooks"
    if not hooks.is_dir():
        print(f"No hooks directory at {hooks}", file=sys.stderr)
        return 1

    subprocess.run(
        ["git", "config", "core.hooksPath", "scripts/hooks"],
        check=True,
        cwd=ROOT,
    )
    # Git needs the hook executable on Unix; on Windows the shebang + bash is
    # what runs it, and the bit is a no-op, so this is best-effort.
    try:
        (hooks / "pre-commit").chmod(0o755)
    except OSError:
        pass

    print("Hooks installed: core.hooksPath -> scripts/hooks")
    print("The pre-commit hook keeps frontend API types in sync with the schema.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
