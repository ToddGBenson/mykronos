"""One-off: move D-137 onward out of docs/DECISIONS.md into docs/decisions/ (D-149).

Pull requests opened before D-149 appended their decisions to the log. This
moves every in-file entry numbered above D-136 into its own
`docs/decisions/D-nnn-<slug>.md` and regenerates the index. Run it once, in
its own pull request, after those PRs have merged. D-001 to D-136 are not
touched.

Each entry's text is kept as written, except relative links, which are
re-rooted: the file sits one directory deeper than the log. `../specs/x.md`
becomes `../../specs/x.md`, `approvals.md` becomes `../approvals.md`, and an
anchor into the log, `#d-082-...`, becomes `../DECISIONS.md#d-082-...`.

Dry run by default: it prints what it would move. `--apply` writes.
It refuses, and changes nothing, if a target file exists or a number would be
duplicated.

Usage: python scripts/move-decisions-to-files.py [--apply] [--root PATH]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import decisions_index

LAST_IN_LOG = 136

HEADING = re.compile(r"^## D-(\d+) — (.*)$", re.MULTILINE)
LINK = re.compile(r"\]\((?![a-z][a-z0-9+.-]*:|/)([^)\s]+)\)")
SEPARATOR = re.compile(r"(?:\s*\n---\s*)+\s*\Z")


def slug(title: str, limit: int = 60) -> str:
    words = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    if len(words) <= limit:
        return words or "decision"
    return words[:limit].rsplit("-", 1)[0] or words[:limit]


def reroot(text: str) -> str:
    def fix(match: re.Match[str]) -> str:
        target = match.group(1)
        if target.startswith("#"):
            return f"](../DECISIONS.md{target})"
        return f"](../{target})"

    return LINK.sub(fix, text)


def split(text: str) -> tuple[str, list[tuple[int, str, str]]]:
    """(the log with the moved entries cut out, [(number, title, entry text)])."""
    matches = list(HEADING.finditer(text))
    kept: list[str] = []
    moved: list[tuple[int, str, str]] = []
    cursor = 0
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        number = int(m.group(1))
        if number <= LAST_IN_LOG:
            continue
        kept.append(text[cursor : m.start()])
        entry = SEPARATOR.sub("", text[m.start() : end].rstrip()) + "\n"
        moved.append((number, m.group(2).strip(), entry))
        cursor = end
    kept.append(text[cursor:])
    rest = "".join(kept)
    rest = SEPARATOR.sub("", rest.rstrip()) + "\n"
    return rest, moved


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--apply", action="store_true", help="write the files")
    parser.add_argument("--root", type=Path, default=decisions_index.ROOT)
    args = parser.parse_args(argv)
    root: Path = args.root

    log = root / decisions_index.LOG
    directory = root / decisions_index.DIRECTORY
    raw = log.read_bytes().decode("utf-8").replace("\r\n", "\n")
    rest, moved = split(raw)
    if not moved:
        print("Nothing to move: no entry above D-136 is left in docs/DECISIONS.md.")
        return 0

    existing, problems = decisions_index.decision_files(root)
    taken = {d.number for d in existing}
    plan: list[tuple[Path, str]] = []
    for number, title, entry in moved:
        name = f"D-{number:03d}"
        target = directory / f"{name}-{slug(title)}.md"
        if name in taken:
            problems.append(f"{name} already has a file in {decisions_index.DIRECTORY}")
        if target.exists():
            problems.append(f"{target.relative_to(root)} already exists")
        taken.add(name)
        plan.append((target, reroot(entry)))
    if problems:
        for p in problems:
            print(f"refused: {p}", file=sys.stderr)
        return 1

    for target, _ in plan:
        print(
            f"{'moving' if args.apply else 'would move'} -> {target.relative_to(root).as_posix()}"
        )
    if not args.apply:
        print("Dry run. Re-run with --apply to write.")
        return 0
    directory.mkdir(parents=True, exist_ok=True)
    for target, entry in plan:
        target.write_text(entry, encoding="utf-8", newline="\n")
    log.write_text(rest, encoding="utf-8", newline="\n")
    decisions_index.write(root)
    print(
        f"Moved {len(plan)} entr{'y' if len(plan) == 1 else 'ies'} and regenerated the index."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
