"""A cancelled or unseeded run uploads no DAST scan as if it were complete.

2026-10-15, run 38676875040: a newer Delivery cancelled the run during `Seed`.
The scan steps were `if: always()`, which runs on cancellation too, so ZAP
scanned a half-seeded stack and `Upload the DAST result` recorded it as a
successful scan of 76 findings. A successful scan confirms absence, so every
finding the unseeded stack could not show would be closed after two such runs.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "demo-and-dast.yml"


def _steps() -> list[dict[str, Any]]:
    doc = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps: list[dict[str, Any]] = doc["jobs"]["demo-and-dast"]["steps"]
    return steps


def _step(name: str) -> dict[str, Any]:
    found = [s for s in _steps() if s.get("name") == name]
    assert found, name
    return found[0]


def _condition(name: str) -> str:
    return str(_step(name).get("if", ""))


def test_the_seed_step_can_be_referred_to() -> None:
    assert _step("Seed").get("id") == "seed"


def test_the_scans_need_a_seeded_stack_and_an_uncancelled_run() -> None:
    for name in ("Spider, and scan", "Scan the backend API from its OpenAPI document"):
        cond = _condition(name)
        assert "always()" not in cond, f"{name} runs on cancellation"
        assert "!cancelled()" in cond, name
        assert "steps.seed.outcome == 'success'" in cond, f"{name} scans an unseeded stack"


def test_the_uploads_do_not_run_on_a_cancelled_run() -> None:
    # A failed scan still uploads (as a failed or partial run, closing
    # nothing); a cancelled one uploads nothing.
    for name in ("Upload the functional result", "Upload the DAST result"):
        cond = _condition(name)
        assert "always()" not in cond, f"{name} uploads a cancelled run"
        assert "!cancelled()" in cond, name


def test_teardown_still_always_runs() -> None:
    assert "always()" in _condition("Tear down")
