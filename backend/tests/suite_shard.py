"""One shard of the backend suite, by test file (TheHub #62416).

`MYKRONOS_PYTEST_SHARD=K/N` makes pytest keep only the test files whose path
hashes to shard K of N; conftest.py applies it after collection, through
pytest's own deselection, so the run's summary counts what it left out.
backend-pr.yml runs N such shards side by side on hosted runners.

The split is by FILE, never by test: a module's fixtures and its order stay
whole. The hash is sha256 of the path relative to backend/, with `/`
separators, so it is the same on every runner and in every run; Python's
`hash()` is randomised per process and would not be. Every collected file
maps to exactly one K in 1..N, so N green shards are the whole suite. A new
test file needs no list: it lands in some shard the day it is added.

Measured on the 2026-11-27 junit of the Concourse `unit` lane (426 files,
3,560 s of test time): the heaviest of four shards carries 1.15 times the
mean.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

ENV = "MYKRONOS_PYTEST_SHARD"
_SPEC = re.compile(r"([1-9][0-9]*)/([1-9][0-9]*)")


def parse(value: str) -> tuple[int, int]:
    """`K/N` with 1 <= K <= N. Anything else stops the run: a shard that
    silently ran nothing, or everything, would read as green."""
    match = _SPEC.fullmatch(value.strip())
    if match is None or int(match[1]) > int(match[2]):
        raise pytest.UsageError(f"{ENV}={value!r}: expected K/N with 1 <= K <= N, for example 2/4")
    return int(match[1]), int(match[2])


def shard_of(path: str, count: int) -> int:
    """The 1-based shard of a test file, from its POSIX path relative to backend/."""
    digest = hashlib.sha256(path.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % count + 1


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def select(items: Sequence[Any], root: Path, value: str) -> tuple[list[Any], list[Any]]:
    """(kept, dropped) for shard `value`; each item goes by its file's path."""
    index, count = parse(value)
    kept: list[Any] = []
    dropped: list[Any] = []
    for item in items:
        target = kept if shard_of(_relative(Path(item.path), root), count) == index else dropped
        target.append(item)
    return kept, dropped
