"""The decision log's numbering holds (D-082).

`D-046`, `D-047` and `D-048` were each taken twice on 2026-08-13 by two
sessions three hours apart, and nobody noticed for a week — the log is
append-only and nothing read it back. Both sets are cited from live code and
specs, so neither could be renumbered without thirty judgement calls; what is
fixable is that it never happens again.

The three known collisions are named in `KNOWN_COLLISIONS` rather than hidden
behind a count, so the allow-list is itself the record: a *new* collision fails
this test, an old one does not, and removing an entry from that set is how you
declare a collision resolved.
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

LOG = Path(__file__).resolve().parents[2] / "docs" / "DECISIONS.md"

HEADING = re.compile(r"^## (D-\d+) — (.*)$", re.MULTILINE)

#: Numbers that were taken twice before anything checked. Documented in D-082.
#: Do not add to this to make a failure go away — a new duplicate is a mistake
#: to fix at the point it is written, while it is still one edit.
KNOWN_COLLISIONS = {"D-046", "D-047", "D-048"}


def headings() -> list[tuple[str, str]]:
    return HEADING.findall(LOG.read_text(encoding="utf-8"))


def test_no_new_duplicate_decision_numbers() -> None:
    counts = Counter(number for number, _ in headings())
    duplicates = {number for number, count in counts.items() if count > 1}
    unexpected = duplicates - KNOWN_COLLISIONS

    assert not unexpected, (
        "These decision numbers are used more than once: "
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

    assert not missing, (
        "These colliding entries have no shared-number note: " + "; ".join(missing)
    )
