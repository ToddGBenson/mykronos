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


def junit(root: Path, broken: list[tuple[Path, str]], destination: Path) -> None:
    """Write the result as JUnit XML so Mykronos can record it (D-046).

    One test case per Markdown file rather than per broken link, because the
    counts have to mean something: "18 of 60 documents have a broken link" is
    a fact about the documentation, while "18 broken links" could be one file
    with eighteen of them.

    QA reports a ScanRun and no findings, like unit and functional. A broken
    link is a defect and it is not a vulnerability, and giving it a severity
    would put documentation drift into a security risk score.
    """
    from xml.etree.ElementTree import Element, ElementTree, SubElement

    failures: dict[str, list[str]] = {}
    for path, target in broken:
        failures.setdefault(path.relative_to(root).as_posix(), []).append(target)

    documents = sorted(
        p.relative_to(root).as_posix()
        for p in root.rglob("*.md")
        if not any(part in SKIP_DIRS for part in p.parts)
    )

    suite = Element(
        "testsuite",
        name="qa-spec-links",
        tests=str(len(documents)),
        failures=str(len(failures)),
        errors="0",
        skipped="0",
    )
    for document in documents:
        case = SubElement(suite, "testcase", classname="links", name=document)
        if document in failures:
            targets = ", ".join(sorted(failures[document]))
            SubElement(
                case, "failure", message=f"broken link -> {targets}"
            ).text = f"{document} links to {targets}, which does not exist."

    root_element = Element("testsuites")
    root_element.append(suite)
    destination.parent.mkdir(parents=True, exist_ok=True)
    ElementTree(root_element).write(destination, encoding="utf-8", xml_declaration=True)


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    root = Path(args[0] if args else ".").resolve()
    broken = broken_links(root)

    for flag in sys.argv[1:]:
        if flag.startswith("--junit-xml="):
            junit(root, broken, Path(flag.split("=", 1)[1]))

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
