"""D-175 records TheHub #60736's chosen option, its order and its guards.

#60736 was decided on 2026-10-12 (option A, deterministic first) and its eight
children were filed the next day, but nothing in this repository said so: the
order, which steps were built ahead of it, and the rule that a model only ever
proposes lived in TheHub alone. These checks keep the record complete, so a
later reader (or a later model-use story) finds the ladder, the prerequisites
and the KPI baseline in one place.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DIRECTORY = ROOT / "docs" / "decisions"

#: The children of #60736, in the order the decision sets.
CHILDREN = ["#60742", "#60743", "#60744", "#60745", "#60746", "#60747", "#60748", "#60749"]


def _decision() -> str:
    matches = sorted(DIRECTORY.glob("D-175-*.md"))
    assert matches, "D-175 (the #60736 deterministic-first ladder) is not recorded"
    return matches[0].read_text(encoding="utf-8")


def test_the_ladder_names_every_child_in_order() -> None:
    text = _decision()
    positions = [text.find(child) for child in CHILDREN]
    assert all(p >= 0 for p in positions), dict(zip(CHILDREN, positions))
    assert positions == sorted(positions), "children are not listed in the decided order"


def test_model_use_is_proposal_only_under_finding_disposition_in_shadow() -> None:
    text = _decision()
    assert "finding_disposition" in text
    assert "shadow" in text
    assert "never changes a finding" in text
    assert "Oracle" in text


def test_a_model_written_fix_waits_on_a_decision_amending_d096() -> None:
    assert "amending D-096" in _decision()


def test_prerequisites_and_already_built_items_are_named() -> None:
    text = _decision()
    for needle in ("mykronos-bench", "backend-tests", "EPSS", "KEV", "CWE"):
        assert needle in text, needle


def test_the_kpi_has_a_recall_guard_and_a_dated_baseline() -> None:
    text = _decision()
    assert "needs_human_judgment" in text
    assert "recall" in text
    assert re.search(r"Baseline[^\n]*\d+ of \d+[^\n]*2026-\d\d-\d\d", text), (
        "no baseline value and date"
    )
