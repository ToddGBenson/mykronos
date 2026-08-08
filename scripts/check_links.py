#!/usr/bin/env python3
"""Verify every relative Markdown link resolves.

The specs are the contract and the code cites them by section, so a dead
cross-reference means a spec was renamed without its citations moving.

This exists as a script rather than inline shell in the workflow so CI and a
developer run byte-identical code. The previous shell version conflated
"grep found no links in this file" with "found a broken link" — grep exits 1
on no-match, and under `set -e` that failed the build on perfectly good files.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

LINK = re.compile(r"\]\(\s*([^)\s]+?\.md)(#[^)]*)?\s*\)")
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".mypy_cache"}


def broken_links(root: Path) -> list[tuple[Path, str]]:
    broken: list[tuple[Path, str]] = []
    for path in sorted(root.rglob("*.md")):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            broken.append((path, f"unreadable: {exc}"))
            continue
        for target, _anchor in LINK.findall(text):
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            if not (path.parent / target).is_file():
                broken.append((path, target))
    return broken


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    broken = broken_links(root)

    for path, target in broken:
        relative = path.relative_to(root).as_posix()
        # GitHub Actions annotation, so the failure lands on the right file.
        if os.environ.get("GITHUB_ACTIONS"):
            print(f"::error file={relative}::broken link -> {target}")
        print(f"{relative}: broken link -> {target}", file=sys.stderr)

    if broken:
        print(f"\n{len(broken)} broken link(s).", file=sys.stderr)
        return 1

    print("All relative Markdown links resolve.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
