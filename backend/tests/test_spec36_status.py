"""Spec 36 §8 says what became of each follow-up story (TheHub #60799).

The spec's phases were followed by a reconciliation round: seven TheHub
stories, each tagged `spec36-followup`. §8 is where a reader learns what each
one did, so a follow-up with no row, or a row with no outcome, is a spec that
no longer says what was built.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SPEC = REPO_ROOT / "specs" / "36-the-agent-contract.md"

#: The TheHub stories tagged `spec36-followup`.
FOLLOW_UPS = (60793, 60794, 60795, 60796, 60797, 60798, 60799)

_ROW = re.compile(r"^\| TheHub #(?P<story>\d+) \|(?P<rest>.*)\|\s*$", re.M)


def _section_8() -> str:
    text = SPEC.read_text(encoding="utf-8")
    return text.split("\n## 8. ", 1)[1].split("\n## ", 1)[0]


def test_section_8_has_one_row_per_follow_up_with_an_outcome() -> None:
    rows: dict[int, list[str]] = {}
    for m in _ROW.finditer(_section_8()):
        story = int(m.group("story"))
        assert story not in rows, f"TheHub #{story} has two rows"
        rows[story] = [cell.strip() for cell in m.group("rest").split("|")]
    assert sorted(rows) == sorted(FOLLOW_UPS)
    for story, cells in rows.items():
        # | story | what it asked | outcome |
        assert len(cells) == 2, (story, cells)
        assert all(cells), f"TheHub #{story} has an empty cell"
