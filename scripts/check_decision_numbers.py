"""Decision numbers are unique across main and every open pull request (D-158).

One file per decision (D-149) ended the merge conflicts in the log, but not
the collisions: two sessions writing at once each take "the next free number"
from the same main. On 2026-10-11 that happened four times across open PRs
(D-136 to D-139 once, D-153 three times), and the numbering test cannot see it,
because each branch is consistent on its own. Only a comparison across open
pull requests can.

What a change "adds" is measured from trees, not diffs: the numbers in its head
(the log's `## D-nnn` headings plus `docs/decisions/D-nnn-*.md` filenames)
minus the numbers at its merge-base with main. An entry *moved* from the log
into a file (scripts/move-decisions-to-files.py) is in both and adds nothing.

A collision is a number a change adds that main already has, or that another
open PR also adds. Between two PRs, the later one (higher number) is told to
renumber. Each message names both sides and suggests the next free number:
one above everything main and every open PR holds.

Usage (local, with `gh` and git):
  python scripts/check_decision_numbers.py               every open PR against main and each other
  python scripts/check_decision_numbers.py --pr 777      only what involves #777
  python scripts/check_decision_numbers.py --head HEAD   a branch not yet opened as a PR (pre-push)
  python scripts/check_decision_numbers.py --next        print the next free number
The approval queue calls `round` (see `round_refusals`).

Why not a CI lane: the Concourse `source` resource tracks main only, so no
lane sees a PR head. The check runs in the approval queue, before a PR is
decided, and as a pre-push hint (scripts/hooks/pre-push).
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOG = "docs/DECISIONS.md"
DIRECTORY = "docs/decisions"
REPO = "ToddGBenson/mykronos"
FETCH_NAMESPACE = "refs/decision-check/pr"

LOG_HEADING = re.compile(r"^## D-(\d+) — ", re.MULTILINE)
FILENAME = re.compile(r"^D-(\d{3,})-[^/]+\.md$")


# -- Pure logic ----------------------------------------------------------------------


def numbers_in(log_text: str, decision_filenames: list[str]) -> set[int]:
    """Every decision number a tree holds: log headings and file names."""
    found = {int(n) for n in LOG_HEADING.findall(log_text)}
    for name in decision_filenames:
        match = FILENAME.match(Path(name).name)
        if match:
            found.add(int(match.group(1)))
    return found


def label(n: int) -> str:
    return f"D-{n:03d}"


@dataclass
class Change:
    """One change that adds decision numbers: an open PR, or a local branch."""

    name: str  # "#777" or "HEAD (feat/x)"
    adds: set[int]
    rank: int = 0  # who renumbers between two changes: the higher rank


@dataclass
class Collision:
    change: str  # the one to renumber
    number: int
    other: str  # "main" or the other change
    suggest: int

    @property
    def message(self) -> str:
        where = (
            "main already has it"
            if self.other == "main"
            else f"{self.other} also adds it"
        )
        return (
            f"{self.change} adds {label(self.number)}, but {where}: renumber "
            f"{label(self.number)} -> {label(self.suggest)} in {self.change}."
        )


@dataclass
class _Suggester:
    taken: set[int]
    given: list[int] = field(default_factory=list)

    def next(self) -> int:
        n = max(self.taken | set(self.given) | {0}) + 1
        self.given.append(n)
        return n


def next_free(main: set[int], changes: list[Change]) -> int:
    taken = set(main)
    for c in changes:
        taken |= c.adds
    return max(taken | {0}) + 1


def collisions(
    main: set[int], changes: list[Change], focus: str | None = None
) -> list[Collision]:
    """Every collision, each with its own suggested number.

    With `focus`, only those the named change is a party to.
    """
    taken = set(main)
    for c in changes:
        taken |= c.adds
    suggest = _Suggester(taken)
    found: list[Collision] = []
    for c in changes:
        for n in sorted(c.adds & main):
            found.append(Collision(c.name, n, "main", 0))
    ordered = sorted(changes, key=lambda c: c.rank)
    for i, a in enumerate(ordered):
        for b in ordered[i + 1 :]:
            for n in sorted((a.adds & b.adds) - main):
                found.append(Collision(b.name, n, a.name, 0))
    if focus is not None:
        found = [f for f in found if focus in (f.change, f.other)]
    for f in found:
        f.suggest = suggest.next()
    return found


def round_refusals(main: set[int], ordered: list[Change]) -> list[Collision]:
    """The approval queue's guard, for one round in merge order.

    A PR is refused when a number it adds is on main or was added by a PR
    earlier in the same round that was not itself refused: that earlier PR
    merges first, and the later one would land a duplicate.
    """
    taken = set(main)
    everything = set(main)
    for c in ordered:
        everything |= c.adds
    suggest = _Suggester(everything)
    owner = {n: "main" for n in main}
    refused: list[Collision] = []
    for c in ordered:
        clash = sorted(c.adds & taken)
        if clash:
            refused += [Collision(c.name, n, owner[n], suggest.next()) for n in clash]
            continue
        taken |= c.adds
        owner.update({n: c.name for n in c.adds})
    return refused


# -- Reading trees with git ------------------------------------------------------------


def _git(
    repo: Path, *args: str, check: bool = True
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, check=check
    )


def tree_numbers(repo: Path, rev: str) -> set[int]:
    shown = _git(repo, "show", f"{rev}:{LOG}", check=False)
    log_text = shown.stdout.decode("utf-8") if shown.returncode == 0 else ""
    listed = _git(repo, "ls-tree", "--name-only", f"{rev}:{DIRECTORY}", check=False)
    names = listed.stdout.decode("utf-8").split() if listed.returncode == 0 else []
    return numbers_in(log_text, names)


def added_by(repo: Path, rev: str, main: str = "origin/main") -> set[int]:
    base = _git(repo, "merge-base", main, rev).stdout.decode().strip()
    return tree_numbers(repo, rev) - tree_numbers(repo, base)


def open_pull_requests(repo: Path, repo_name: str) -> list[dict]:
    out = subprocess.run(
        [
            "gh",
            "pr",
            "list",
            "--repo",
            repo_name,
            "--state",
            "open",
            "--limit",
            "100",
            "--json",
            "number,headRefName,headRefOid,title",
        ],
        capture_output=True,
        check=True,
        text=True,
        encoding="utf-8",
    )
    prs = json.loads(out.stdout)
    refspecs = [
        f"+refs/pull/{p['number']}/head:{FETCH_NAMESPACE}/{p['number']}" for p in prs
    ]
    _git(
        repo,
        "fetch",
        "--quiet",
        "origin",
        "+refs/heads/main:refs/remotes/origin/main",
        *refspecs,
    )
    return prs


def gather(repo: Path, repo_name: str) -> tuple[set[int], list[Change], list[dict]]:
    prs = open_pull_requests(repo, repo_name)
    main = tree_numbers(repo, "origin/main")
    changes = [
        Change(
            f"#{p['number']}",
            added_by(repo, f"{FETCH_NAMESPACE}/{p['number']}"),
            p["number"],
        )
        for p in prs
    ]
    return main, changes, prs


# -- CLI --------------------------------------------------------------------------------


def _round(argv: list[str]) -> int:
    """`round <repo> <input.json>`: [{"number", "ref"}...] in merge order -> JSON."""
    repo = Path(argv[0])
    items = json.loads(Path(argv[1]).read_text(encoding="utf-8-sig"))
    main = tree_numbers(repo, "origin/main")
    ordered = [
        Change(f"#{i['number']}", added_by(repo, i["ref"]), n)
        for n, i in enumerate(items)
    ]
    by_pr: dict[int, list[str]] = {}
    for r in round_refusals(main, ordered):
        by_pr.setdefault(int(r.change.lstrip("#")), []).append(r.message)
    out = {
        "refused": [{"number": n, "message": " ".join(m)} for n, m in by_pr.items()],
        "next_free": next_free(main, ordered),
    }
    sys.stdout.write(json.dumps(out))
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["round"]:
        return _round(argv[1:])
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--pr", type=int, help="report only what involves this PR")
    parser.add_argument("--head", help="check a local branch that is not a PR yet")
    parser.add_argument(
        "--next", action="store_true", help="print the next free number"
    )
    parser.add_argument("--repo", default=REPO)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)

    main_numbers, changes, prs = gather(args.root, args.repo)
    focus = f"#{args.pr}" if args.pr else None
    if args.head:
        sha = _git(args.root, "rev-parse", args.head).stdout.decode().strip()
        branch = (
            _git(args.root, "rev-parse", "--abbrev-ref", args.head)
            .stdout.decode()
            .strip()
        )
        mine = {
            f"#{p['number']}"
            for p in prs
            if p["headRefOid"] == sha or p["headRefName"] == branch
        }
        changes = [c for c in changes if c.name not in mine]
        focus = f"HEAD ({branch})"
        changes.append(Change(focus, added_by(args.root, args.head), 10**9))

    if args.next:
        print(label(next_free(main_numbers, changes)))
        return 0
    found = collisions(main_numbers, changes, focus)
    for f in found:
        print(f.message, file=sys.stderr)
    if not found:
        scope = focus or f"{len(changes)} open PR(s)"
        print(
            f"No decision-number collisions for {scope}; next free is "
            f"{label(next_free(main_numbers, changes))}."
        )
    return 1 if found else 0


if __name__ == "__main__":
    raise SystemExit(main())
