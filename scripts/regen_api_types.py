#!/usr/bin/env python3
"""Regenerate frontend/lib/api-types.d.ts from the backend's OpenAPI schema.

The single source of truth for a two-command dance that, done by hand, was
forgotten four times in one day -- each time the frontend lane caught it in
CI, twenty minutes and a re-trigger later. This is what the pre-commit hook
(scripts/hooks/pre-commit) runs, and what the lane's own error message tells
you to run.

    python scripts/regen_api_types.py           # write the types
    python scripts/regen_api_types.py --check    # fail if they are stale

--check is what a hook or a lane wants: it regenerates to a temp file and
compares, touching nothing, exiting non-zero on drift.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = ROOT / "frontend" / "openapi.json"
TYPES = ROOT / "frontend" / "lib" / "api-types.d.ts"


def _dump_schema() -> None:
    subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "dump_openapi.py"), str(SCHEMA)],
        check=True,
        cwd=ROOT,
    )


def _generate(dest: Path) -> None:
    # npx so this needs no global install; the frontend lane pins the same
    # openapi-typescript, so local and CI agree by construction.
    subprocess.run(
        ["npx", "--yes", "openapi-typescript", str(SCHEMA), "-o", str(dest)],
        check=True,
        cwd=ROOT / "frontend",
        shell=(sys.platform == "win32"),  # npx is a .cmd on Windows
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if the committed types are stale; write nothing.",
    )
    args = parser.parse_args(argv)

    _dump_schema()

    if not args.check:
        _generate(TYPES)
        print(f"Wrote {TYPES.relative_to(ROOT)}")
        return 0

    with tempfile.TemporaryDirectory() as tmp:
        fresh = Path(tmp) / "api-types.d.ts"
        _generate(fresh)
        if not TYPES.exists() or TYPES.read_text(encoding="utf-8") != fresh.read_text(encoding="utf-8"):
            print(
                "::error::frontend/lib/api-types.d.ts is out of date.\n"
                "  The backend's OpenAPI schema changed without the types being "
                "regenerated.\n  Run: python scripts/regen_api_types.py",
                file=sys.stderr,
            )
            return 1

    print("API types are up to date.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
