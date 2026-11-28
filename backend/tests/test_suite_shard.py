"""One shard of the backend suite, by test file (TheHub #62416).

`backend-tests` took 778-1,208 s on a 4-vCPU hosted runner over the 20 pull
requests before this file. backend-pr.yml now runs the suite as four shards in
parallel, each one `MYKRONOS_PYTEST_SHARD=K/4`, and conftest.py keeps only the
test files whose path hashes to shard K. These tests hold the property that
makes that safe: every collected test lands in exactly one shard, so four green
shards are the whole suite.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tests import suite_shard
from tests.conftest import pytest_collection_modifyitems, pytest_report_header

BACKEND = Path(__file__).resolve().parents[1]
TESTS = BACKEND / "tests"


def _test_files() -> list[str]:
    found = {p for pattern in ("test_*.py", "*_test.py") for p in TESTS.rglob(pattern)}
    return sorted(p.relative_to(BACKEND).as_posix() for p in found)


def _item(path: Path, name: str) -> Any:
    return SimpleNamespace(path=path, nodeid=f"{path.name}::{name}")


def _config(root: Path) -> tuple[Any, list[Any]]:
    dropped: list[Any] = []
    hook = SimpleNamespace(pytest_deselected=lambda items: dropped.extend(items))
    return SimpleNamespace(rootpath=root, hook=hook), dropped


@pytest.mark.parametrize("count", [1, 2, 3, 4, 5, 8])
def test_every_test_file_lands_in_exactly_one_shard(count: int) -> None:
    files = _test_files()
    assert len(files) > 100, "the suite's test files were not found"
    shards = {f: suite_shard.shard_of(f, count) for f in files}
    assert set(shards.values()) <= set(range(1, count + 1))
    # A pure function of the path: asking again gives the same shard.
    assert all(suite_shard.shard_of(f, count) == k for f, k in shards.items())


def test_the_shard_is_a_stable_hash_of_the_posix_path() -> None:
    """Pinned so the split moves only when somebody means it to: a hash that
    changed between runners (a randomised str hash, a Windows path) would
    put one file in two shards, or in none."""
    # sha256 of the path relative to backend/, first 8 bytes big-endian, mod N, plus 1.
    assert suite_shard.shard_of("tests/test_dashboard.py", 4) == 2
    assert [suite_shard.shard_of(f"tests/test_{n}.py", 4) for n in ("a", "b", "c", "d")] == [
        1, 3, 3, 1,
    ]
    assert suite_shard.shard_of(Path("tests", "test_a.py").as_posix(), 4) == 1


def test_four_shards_each_carry_a_fair_part_of_the_suite() -> None:
    """A degenerate split (everything in one shard) would leave the other three
    green over nothing and the fourth as slow as the whole suite."""
    files = _test_files()
    sizes = [sum(1 for f in files if suite_shard.shard_of(f, 4) == k) for k in range(1, 5)]
    assert sum(sizes) == len(files)
    assert min(sizes) >= len(files) * 0.15, sizes


@pytest.mark.parametrize("value", ["0/4", "5/4", "1/0", "4", "a/b", "1/4/2", "-1/4", "1 / 4"])
def test_a_malformed_shard_stops_the_run(value: str) -> None:
    with pytest.raises(pytest.UsageError, match="MYKRONOS_PYTEST_SHARD"):
        suite_shard.parse(value)


def test_a_well_formed_shard_parses() -> None:
    assert suite_shard.parse("2/4") == (2, 4)
    assert suite_shard.parse(" 1/1 ") == (1, 1)


def test_without_the_variable_nothing_is_deselected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(suite_shard.ENV, raising=False)
    items = [_item(TESTS / "test_a.py", "t"), _item(TESTS / "test_b.py", "t")]
    config, dropped = _config(BACKEND)
    pytest_collection_modifyitems(config, items)  # type: ignore[arg-type]
    assert len(items) == 2 and dropped == []
    assert pytest_report_header(config) == []  # type: ignore[arg-type]


def test_the_shards_partition_the_collected_items(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every item kept by exactly one of the four shards; the rest go through
    pytest's own deselection hook, so the summary says how many were left out."""
    paths = [TESTS / f"test_{n}.py" for n in "abcdefghij"]
    everything = [_item(p, f"case{i}") for p in paths for i in range(3)]
    kept: list[str] = []
    for k in range(1, 5):
        monkeypatch.setenv(suite_shard.ENV, f"{k}/4")
        items = list(everything)
        config, dropped = _config(BACKEND)
        pytest_collection_modifyitems(config, items)  # type: ignore[arg-type]
        assert len(items) + len(dropped) == len(everything)
        assert {i.nodeid for i in items}.isdisjoint({i.nodeid for i in dropped})
        # A file is never split: its items all stay or all go.
        assert {i.path for i in items}.isdisjoint({i.path for i in dropped})
        kept += [i.nodeid for i in items]
        assert pytest_report_header(config) == [  # type: ignore[arg-type]
            f"{suite_shard.ENV}={k}/4: one shard of the suite, by test file"
        ]
    assert sorted(kept) == sorted(i.nodeid for i in everything)


def test_real_pytest_collects_the_same_tests_across_the_shards() -> None:
    """The hook as pytest runs it: the shards' collections, together, are the
    unsharded collection of the same files, test for test. Two shards, not
    four: each collection imports the app, and the fake-item test above
    already covers four."""
    files = [
        "tests/test_backend_pr_workflow.py",
        "tests/test_action_pins.py",
        "tests/test_suite_shard.py",
        "tests/test_dependency_lock.py",
        "tests/test_gitleaks_allowlist.py",
        "tests/test_no_secret_on_a_command_line.py",
    ]

    def collect(shard: str | None) -> list[str]:
        env = {k: v for k, v in os.environ.items() if k != suite_shard.ENV}
        if shard:
            env[suite_shard.ENV] = shard
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider",
             "-p", "no:xdist", *files],
            cwd=BACKEND, env=env, capture_output=True, text=True, check=False,
        )
        assert result.returncode in (0, 5), result.stdout[-2000:] + result.stderr[-2000:]
        return [line for line in result.stdout.splitlines() if "::" in line]

    whole = collect(None)
    assert len(whole) > 50
    parts = [collect(f"{k}/2") for k in (1, 2)]
    assert all(parts), "a shard collected nothing from six files"
    assert sorted(n for part in parts for n in part) == sorted(whole)
