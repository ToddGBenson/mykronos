"""A coroutine handed to a caller that does not know it is one.

The weekly digest was never delivered. `SlackNotifier.send` is a coroutine and
`digest.send_all` was synchronous, took the notifier as `Any`, and called
`send` without awaiting it — so every call built a coroutine, dropped it, and
then logged `Weekly digest sent to N owner(s)`. It ran that way for as long as
the job had existed.

Three things had to line up for that to stay invisible, and only one of them
was the empty webhook:

1. The parameter was typed `Any`, so mypy was never asked.
2. The test double's `send` was synchronous, so it agreed with the caller.
3. The whole job went through `asyncio.to_thread`, which made dropping the
   coroutine look like the ordinary shape of the code.

Fixing that one call site fixes one bug. These two tests are about the shape,
because the shape is what will produce the next one.

**Why a test rather than a lint rule.** `Any` is legitimate in plenty of
places here — scan payloads, DuckDB rows, adapter output. What is not
legitimate is `Any` on a parameter this codebase has an actual protocol for,
because there the type is available and declining it is what turns a missing
`await` into a silent success. Only those names are checked.

Measured, not asserted: with `notifier: Any` an un-awaited `send` passes mypy
clean, and with `notifier: Notifier | None` the same line is
`[unused-coroutine] Are you missing an await?`.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parent.parent / "mykronos"
TESTS = Path(__file__).resolve().parent

#: Parameter names with a real protocol behind them. `Any` here is not
#: shorthand, it is the type being declined at the one place a missing `await`
#: stops being an error and starts being a quiet success.
PROTOCOLLED = {
    "github": "mykronos.github.GitHubClient",
    "notifier": "mykronos.notify.Notifier",
}


def _annotated_any(annotation: ast.expr | None) -> bool:
    """`Any`, `Any | None`, and `Optional[Any]` all count."""
    if annotation is None:
        return False
    return any(
        isinstance(node, ast.Name) and node.id == "Any" for node in ast.walk(annotation)
    )


def _parameters(function: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.arg]:
    args = function.args
    return [*args.posonlyargs, *args.args, *args.kwonlyargs]


def test_no_protocolled_parameter_is_typed_any() -> None:
    """The half that hid the digest bug from mypy."""
    offenders: list[str] = []
    for path in sorted(PACKAGE.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            for parameter in _parameters(node):
                if parameter.arg in PROTOCOLLED and _annotated_any(parameter.annotation):
                    protocol = PROTOCOLLED[parameter.arg]
                    offenders.append(
                        f"{path.relative_to(PACKAGE.parent)}:{parameter.lineno} "
                        f"{node.name}({parameter.arg}: Any) — use {protocol}"
                    )

    assert not offenders, (
        "A parameter with a protocol behind it is typed `Any`, so mypy cannot "
        "see a missing `await` on it:\n  " + "\n  ".join(offenders)
    )


def _async_method_names() -> set[str]:
    """Every public async method defined on a class in the package."""
    names: set[str] = set()
    for path in PACKAGE.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            for item in node.body:
                if isinstance(item, ast.AsyncFunctionDef) and not item.name.startswith("_"):
                    names.add(item.name)
    return names


#: Helper classes in the suite that are not doubles for anything, and whose
#: method names collide with a real async method by coincidence. Each one is
#: named rather than pattern-matched, so a genuine double cannot join them by
#: being called something convenient.
NOT_A_DOUBLE = {
    ("test_ai_classifier.py", "TestTheScorerReadsIt", "run"),
}


def test_no_test_double_answers_an_async_method_synchronously() -> None:
    """The half that hid it from the test suite.

    A double whose `send` is synchronous agrees with a caller that forgot to
    await, and the test passes for a job that delivers nothing. The double
    then tests the double.
    """
    real = _async_method_names()
    offenders: list[str] = []
    for path in sorted(TESTS.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            for item in node.body:
                if not isinstance(item, ast.FunctionDef) or item.name not in real:
                    continue
                if (path.name, node.name, item.name) in NOT_A_DOUBLE:
                    continue
                offenders.append(
                    f"{path.name}:{item.lineno} {node.name}.{item.name} is `def`, "
                    f"and the class it stands in for defines it `async def`"
                )

    assert not offenders, (
        "A test double answers synchronously where the real class is async, so "
        "it agrees with a caller that forgot to await:\n  " + "\n  ".join(offenders)
    )


@pytest.mark.parametrize("name", sorted(PROTOCOLLED))
def test_the_protocol_this_names_actually_exists(name: str) -> None:
    """`PROTOCOLLED` is only worth anything while its right-hand side
    resolves. A stale path here would turn the guard's advice into a wrong
    answer given confidently."""
    import importlib

    module_path, _, attribute = PROTOCOLLED[name].rpartition(".")
    protocol = getattr(importlib.import_module(module_path), attribute)

    assert inspect.isclass(protocol)
