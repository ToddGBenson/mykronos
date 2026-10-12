"""The Product Owner modules pass the same mypy the lint lane runs.

Two `mypy --strict` errors in `po_console.py` and `po_trace.py` (#773, #774)
turned `lint-and-types` red on every main commit from 2ca8b25 onward. Every
scan lane is `passed: [unit, lint-and-types, qa-spec-links, frontend]`, and
`oracle-gate` is `passed:` those lanes, so no commit after 49d9a1d reached the
risk gate. `deploy.ps1` waited 45 minutes per deploy and recorded NOT JUDGED.

Neither error was a runtime bug, and that is why no unit test caught them:
the unit lane stayed green while the lane that holds the gate went red. This
test runs the lane's own check on the two modules, so the failure shows up
in the tier a developer runs before pushing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

mypy_api = pytest.importorskip("mypy.api")

BACKEND = Path(__file__).resolve().parents[1]


def test_po_console_and_po_trace_typecheck_clean() -> None:
    stdout, stderr, status = mypy_api.run(
        [
            "--config-file",
            str(BACKEND / "pyproject.toml"),
            "--follow-imports=silent",
            str(BACKEND / "mykronos" / "po_console.py"),
            str(BACKEND / "mykronos" / "po_trace.py"),
        ]
    )
    assert status == 0, stdout + stderr
