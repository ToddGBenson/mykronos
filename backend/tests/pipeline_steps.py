"""Walk a Concourse plan through the steps that nest others.

Since the operator decision of 2026-11-16 the tasks that run on the remote
`linux` workers sit in a timed `do:` (a task's own `timeout:` starts only
once a worker is chosen, so the cap has to be on a wrapper). Tests that look
a task up by name read the plan through `flat`, so they find it at any depth.
Hooks are not walked: a hook is not a step of the plan.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any


def flat(plan: Any) -> list[dict[str, Any]]:
    """Every step of `plan`, depth first, wrappers included, in plan order."""
    return list(_walk(plan))


def _walk(steps: Any) -> Iterator[dict[str, Any]]:
    if isinstance(steps, dict):
        steps = steps.get("steps", [])
    for step in steps or []:
        if not isinstance(step, dict):
            continue
        yield step
        for key in ("do", "in_parallel", "aggregate"):
            if key in step:
                yield from _walk(step[key])
        if "try" in step:
            yield from _walk([step["try"]])


def holder(plan: list[dict[str, Any]], task: str) -> int:
    """The index of the top-level step of `plan` that is, or wraps, `task`."""
    for n, step in enumerate(plan):
        if any(s.get("task") == task for s in flat([step])):
            return n
    raise StopIteration(task)


def find(plan: list[dict[str, Any]], task: str) -> dict[str, Any]:
    """The task step named `task`, at any depth of `plan`."""
    return next(s for s in flat(plan) if s.get("task") == task)
