#!/usr/bin/env python3
"""Check a repository's README and docs/ tree against the tree itself.

The sprint-end doc drift check (TheHub #61166). A sentence in a doc that names
a file is a claim: the file exists. This script checks every such claim a
machine can check, in every README and every Markdown file under `docs/`:

- a relative link (`[text](docs/GUIDE.md)`) must resolve, from the document's
  own folder, to a file or folder;
- a backticked repository path (`scripts/check.py`) must exist. A backtick
  counts as a path only when its first word contains a slash and its first
  segment is a top-level entry of the repository, so `GET /api/x`, globs and
  container paths are not claims about this tree.

Records describe the past: decisions, retros, lessons, ADRs, reports, audits
and any file dated in its name. A path in one of them names what existed then,
so records are counted as skipped rather than checked.

Run it against a fresh clone of the branch the docs describe (origin/main or
origin/develop), never a shared checkout that lags. It exits 1 when anything
drifted, so a scheduled run can tell. Claims about runtime behaviour (numbers,
labels, counts) are not mechanical; the Docs agent checks those against the
running image by hand and records both in the retro's Docs drift section.

    python scripts/doc_drift.py <repo checkout> [--json]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import unquote

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".mypy_cache", ".next"}
RECORD_DIRS = {
    "decisions",
    "retros",
    "lessons",
    "adr",
    "reports",
    "audit",
    "sweeps",
    "research",
    "spikes",
}
DATED = re.compile(r"\d{4}-\d{2}-\d{2}")
LINK = re.compile(r"\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
TICK = re.compile(r"`([^`\n]+)`")
SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")
NOT_A_PATH = set("*?{}<>[]$%|=")


@dataclass(frozen=True)
class Drift:
    document: str
    line: int
    kind: str  # "link" or "path"
    claim: str


@dataclass
class Report:
    documents_checked: int = 0
    records_skipped: int = 0
    claims_checked: int = 0
    drift: list[Drift] = field(default_factory=list)


def _skipped(path: Path, root: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.relative_to(root).parts)


def _is_record(rel: Path) -> bool:
    parts = rel.parts
    if parts[0] != "docs":
        return False
    if any(part.lower() in RECORD_DIRS for part in parts[1:-1]):
        return True
    return bool(DATED.search(rel.name))


def documents(root: Path) -> tuple[list[Path], list[Path]]:
    """Every README and every Markdown file under docs/: (living, records)."""
    found: set[Path] = set()
    for path in root.rglob("*.md"):
        if _skipped(path, root):
            continue
        rel = path.relative_to(root)
        if path.name.upper().startswith("README") or rel.parts[0] == "docs":
            found.add(path)
    ordered = sorted(found, key=lambda p: p.relative_to(root).as_posix())
    living = [p for p in ordered if not _is_record(p.relative_to(root))]
    records = [p for p in ordered if _is_record(p.relative_to(root))]
    return living, records


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _link_target(raw: str) -> str | None:
    if raw.startswith("#") or SCHEME.match(raw):
        return None
    target = unquote(raw.split("#", 1)[0].split("?", 1)[0])
    return target or None


def _path_claim(content: str, top_level: set[str]) -> str | None:
    word = content.strip().split()[0] if content.strip() else ""
    word = word.rstrip(".,;:)")
    word = re.sub(r":\d+(-\d+)?$", "", word)
    word = word.split("#", 1)[0]
    if word.startswith("./"):
        word = word[2:]
    if "/" not in word or word.startswith(("/", "~", ".", "-")) or "\\" in word:
        return None
    if any(ch in NOT_A_PATH for ch in word):
        return None
    if word.split("/", 1)[0] not in top_level:
        return None
    return word


def check(root: Path) -> Report:
    root = root.resolve()
    living, records = documents(root)
    top_level = {p.name for p in root.iterdir() if p.name not in SKIP_DIRS}
    report = Report(documents_checked=len(living), records_skipped=len(records))
    for doc in living:
        rel = doc.relative_to(root).as_posix()
        try:
            text = doc.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            report.drift.append(Drift(rel, 0, "unreadable", rel))
            continue
        for m in LINK.finditer(text):
            target = _link_target(m.group(1))
            if target is None:
                continue
            report.claims_checked += 1
            base = root if target.startswith("/") else doc.parent
            if not (base / target.lstrip("/")).exists():
                report.drift.append(Drift(rel, _line(text, m.start()), "link", target))
        for m in TICK.finditer(text):
            claim = _path_claim(m.group(1), top_level)
            if claim is None:
                continue
            report.claims_checked += 1
            if not (root / claim).exists():
                report.drift.append(Drift(rel, _line(text, m.start()), "path", claim))
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("root", type=Path, help="a checkout of the branch the docs describe")
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    args = parser.parse_args(argv)
    report = check(args.root)
    if args.json:
        out = {
            "documents_checked": report.documents_checked,
            "records_skipped": report.records_skipped,
            "claims_checked": report.claims_checked,
            "drifted": len(report.drift),
            "drift": [asdict(x) for x in report.drift],
        }
        print(json.dumps(out, indent=2))
    else:
        for x in report.drift:
            print(f"{x.document}:{x.line}: {x.kind} {x.claim}")
        print(
            f"{report.documents_checked} documents checked, {report.records_skipped} records skipped, "
            f"{report.claims_checked} claims checked, {len(report.drift)} drifted"
        )
    return 1 if report.drift else 0


if __name__ == "__main__":
    sys.exit(main())
