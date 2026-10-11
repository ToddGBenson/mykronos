"""The decision log's numbering holds (D-082), across the log and its files (D-149).

`D-046`, `D-047` and `D-048` were each taken twice on 2026-08-13 by two
sessions three hours apart, and nobody noticed for a week — the log is
append-only and nothing read it back. Both sets are cited from live code and
specs, so neither could be renumbered without thirty judgement calls; what is
fixable is that it never happens again.

The three known collisions are named in `KNOWN_COLLISIONS` rather than hidden
behind a count, so the allow-list is itself the record: a *new* collision fails
this test, an old one does not, and removing an entry from that set is how you
declare a collision resolved.

From D-137 on a decision is its own file in `docs/decisions/` (D-149). During
the transition, entries from D-137 may sit in either place: pull requests
opened earlier appended to the log, and `scripts/move-decisions-to-files.py`
moves them later. So numbers are counted across both, and the index in the log
must list exactly the files.
"""

from __future__ import annotations

import importlib.util
import re
import shutil
import sys
from collections import Counter
from pathlib import Path

import pytest

from mykronos.approvals.engine import rationale_problem

ROOT = Path(__file__).resolve().parents[2]
LOG = ROOT / "docs" / "DECISIONS.md"
DIRECTORY = ROOT / "docs" / "decisions"

sys.path.insert(0, str(ROOT / "scripts"))

import decisions_index  # noqa: E402

HEADING = re.compile(r"^## (D-\d+) — (.*)$", re.MULTILINE)

#: Numbers that were taken twice before anything checked. Documented in D-082.
#: Do not add to this to make a failure go away — a new duplicate is a mistake
#: to fix at the point it is written, while it is still one edit.
KNOWN_COLLISIONS = {"D-046", "D-047", "D-048"}


def decision_files() -> list[Path]:
    return sorted(p for p in DIRECTORY.glob("*.md") if p.name != "README.md")


def headings() -> list[tuple[str, str]]:
    """Every decision heading, in the log and in the files."""
    found = HEADING.findall(LOG.read_text(encoding="utf-8"))
    for path in decision_files():
        found += HEADING.findall(path.read_text(encoding="utf-8"))
    return found


def test_no_new_duplicate_decision_numbers() -> None:
    counts = Counter(number for number, _ in headings())
    duplicates = {number for number, count in counts.items() if count > 1}
    unexpected = duplicates - KNOWN_COLLISIONS

    assert not unexpected, (
        "These decision numbers are used more than once, across docs/DECISIONS.md "
        "and docs/decisions/: "
        + ", ".join(sorted(unexpected))
        + ". Give the new entry the next free number — a duplicate is one edit to fix "
        "now and thirty citations to disambiguate later (D-082)."
    )


def test_known_collisions_are_still_collisions() -> None:
    """The allow-list describes the file, rather than outliving it.

    If someone does resolve one of the three, this fails and tells them to drop
    it from the set — so the list cannot quietly grow stale the way the log's
    numbering did.
    """
    counts = Counter(number for number, _ in headings())
    resolved = {number for number in KNOWN_COLLISIONS if counts.get(number, 0) <= 1}

    assert not resolved, (
        "No longer duplicated: "
        + ", ".join(sorted(resolved))
        + ". Remove them from KNOWN_COLLISIONS and delete the shared-number note "
        "under the remaining heading."
    )


def test_every_collision_is_flagged_in_the_document() -> None:
    """Each colliding heading carries the line pointing a reader at D-082."""
    text = LOG.read_text(encoding="utf-8")
    blocks = re.split(r"^## ", text, flags=re.MULTILINE)

    missing = []
    for block in blocks:
        match = re.match(r"(D-\d+) — (.*)", block)
        if not match or match.group(1) not in KNOWN_COLLISIONS:
            continue
        # The note sits directly under the heading, before the Status line.
        head = block[: block.find("**Status:**")] if "**Status:**" in block else block[:400]
        if "Two entries share this number" not in head:
            missing.append(f"{match.group(1)} — {match.group(2)[:40]}")

    assert not missing, "These colliding entries have no shared-number note: " + "; ".join(missing)


# -- One file per decision (D-149) ---------------------------------------------------


def test_the_decision_files_read_cleanly() -> None:
    """Named D-nnn-<slug>.md, one heading each, the heading's number the
    filename's. A file named D-151 that says D-150 would be counted as one
    number and found as another."""
    _, problems = decisions_index.decision_files(ROOT)
    assert not problems, "\n".join(problems)


@pytest.mark.parametrize("path", decision_files(), ids=lambda p: p.name)
def test_a_decision_says_why(path: Path) -> None:
    """D-130's rule, applied to the entry: what is left after the heading and
    the status and spec lines is the reasoning, and it has to be some."""
    body = [
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if not line.startswith("## ") and "**Status:**" not in line and "**Spec:**" not in line
    ]
    problem = rationale_problem(" ".join(body))
    assert problem is None, f"{path.name}: {problem}"


def test_the_index_lists_exactly_the_files() -> None:
    problems = decisions_index.check(ROOT)
    assert not problems, "\n".join(problems)


def test_no_file_reuses_a_number_still_in_the_log() -> None:
    """The transition's one real hazard: a session writes D-150 as a file while
    an older PR has already appended D-150 to the log."""
    in_log = {n for n, _ in HEADING.findall(LOG.read_text(encoding="utf-8"))}
    in_files = {n for path in decision_files() for n, _ in HEADING.findall(path.read_text("utf-8"))}
    assert not in_log & in_files, f"in both places: {sorted(in_log & in_files)}"


# -- The generator and the one-off move, on a copy -------------------------------------


@pytest.fixture
def copy(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "docs").mkdir(parents=True)
    shutil.copy(LOG, root / "docs" / "DECISIONS.md")
    shutil.copytree(DIRECTORY, root / "docs" / "decisions")
    return root


def entry(number: int, title: str, body: str = "Because the measurement said so.") -> str:
    return f"## D-{number:03d} — {title}\n\n**Status:** Decided\n\n{body}\n"


def test_a_new_file_without_an_index_line_fails_the_check(copy: Path) -> None:
    (copy / "docs" / "decisions" / "D-900-new.md").write_text(entry(900, "New"), "utf-8")
    assert decisions_index.check(copy)
    decisions_index.write(copy)
    assert decisions_index.check(copy) == []
    assert "(decisions/D-900-new.md)" in (copy / "docs" / "DECISIONS.md").read_text("utf-8")


def test_a_file_whose_number_is_not_its_name_is_refused(copy: Path) -> None:
    (copy / "docs" / "decisions" / "D-900-new.md").write_text(entry(901, "New"), "utf-8")
    _, problems = decisions_index.decision_files(copy)
    assert any("the heading says D-901, the filename D-900" in p for p in problems)


def _move_script():
    spec = importlib.util.spec_from_file_location(
        "move_decisions", ROOT / "scripts" / "move-decisions-to-files.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_move_takes_d137_onward_and_leaves_the_history(copy: Path) -> None:
    log = copy / "docs" / "DECISIONS.md"
    before = log.read_text(encoding="utf-8")
    appended = (
        "\n---\n\n"
        + entry(137, "The notifier", "See [spec 05](../specs/05-datalake.md) and [D-082](#d-082).")
        + "\n---\n\n"
        + entry(138, "Migration DDL is schema")
    )
    log.write_text(before + appended, encoding="utf-8")
    old_numbers = [n for n, _ in HEADING.findall(before) if int(n[2:]) <= 136]

    assert _move_script().main(["--apply", "--root", str(copy)]) == 0

    after = log.read_text(encoding="utf-8")
    assert [n for n, _ in HEADING.findall(after)] == old_numbers
    moved = (copy / "docs" / "decisions" / "D-137-the-notifier.md").read_text("utf-8")
    assert "](../../specs/05-datalake.md)" in moved
    assert "](../DECISIONS.md#d-082)" in moved
    assert not moved.rstrip().endswith("---")
    assert (copy / "docs" / "decisions" / "D-138-migration-ddl-is-schema.md").exists()
    assert decisions_index.check(copy) == []


def test_the_move_refuses_a_number_that_already_has_a_file(copy: Path) -> None:
    log = copy / "docs" / "DECISIONS.md"
    log.write_text(log.read_text("utf-8") + "\n---\n\n" + entry(149, "Again"), "utf-8")
    before = log.read_text("utf-8")

    assert _move_script().main(["--apply", "--root", str(copy)]) == 1
    assert log.read_text("utf-8") == before
