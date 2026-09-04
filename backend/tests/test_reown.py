"""Backfilling ownership onto findings that predate it (B-034)."""

from __future__ import annotations

from typing import Any

from mykronos import reown
from mykronos.codeowners import parse


class _FakeCatalog:
    def __init__(self, rows: list[tuple[Any, ...]]) -> None:
        self._rows = rows

    def query(self, sql: str, params: list[Any] | None = None) -> list[tuple[Any, ...]]:
        if params:
            return [row for row in self._rows if row[1] == params[0]]
        return self._rows


def _catalog(*rows: tuple[Any, ...]) -> _FakeCatalog:
    return _FakeCatalog(list(rows))


class TestPlan:
    def test_a_null_owner_source_is_backfilled(self) -> None:
        """The shape found on the live estate: 1001 findings with no source at
        all — not `unresolved`, which at least says somebody asked."""
        catalog = _catalog(("f1", "acme/api", "src/app.py", None, None))

        changes, report = reown.plan(
            catalog, rules_by_repo={}, profile_owner_by_repo={}
        )

        assert report.scanned == 1
        assert report.changed == 1
        assert changes == [
            {"finding_id": "f1", "owner": "acme", "owner_source": "repo_owner"}
        ]

    def test_codeowners_wins_over_the_account(self) -> None:
        catalog = _catalog(("f1", "acme/api", "src/app.py", None, None))
        rules = parse("src/ @acme/platform\n")

        changes, _ = reown.plan(
            catalog,
            rules_by_repo={"acme/api": (rules, True)},
            profile_owner_by_repo={},
        )

        assert changes[0]["owner"] == "@acme/platform"
        assert changes[0]["owner_source"] == "codeowners"

    def test_a_manual_assignment_is_never_overwritten(self) -> None:
        """A person said so. That outranks anything this can infer, and a
        backfill that ignored it would undo the one kind of ownership somebody
        actually decided."""
        catalog = _catalog(("f1", "acme/api", "src/app.py", "@someone", "manual"))

        changes, report = reown.plan(
            catalog, rules_by_repo={}, profile_owner_by_repo={}
        )

        assert changes == []
        assert report.protected == 1

    def test_an_unreadable_codeowners_does_not_become_an_assignment(self) -> None:
        """The distinction the third rung made load-bearing.

        "We could not ask" must never be written into a column as "the account
        owns it". It *is* still worth recording as `unresolved`, which says
        somebody asked and could not tell — a strictly better record than the
        null it replaces, and one nobody will mistake for a decision.
        """
        catalog = _catalog(("f1", "acme/api", "src/app.py", None, None))

        changes, _ = reown.plan(
            catalog,
            rules_by_repo={"acme/api": ([], False)},
            profile_owner_by_repo={},
        )

        assert changes == [
            {"finding_id": "f1", "owner": None, "owner_source": "unresolved"}
        ]

    def test_it_is_idempotent(self) -> None:
        catalog = _catalog(("f1", "acme/api", "src/app.py", "acme", "repo_owner"))

        changes, report = reown.plan(
            catalog, rules_by_repo={}, profile_owner_by_repo={}
        )

        assert changes == []
        assert report.changed == 0

    def test_it_can_be_limited_to_one_repository(self) -> None:
        catalog = _catalog(
            ("f1", "acme/api", "src/a.py", None, None),
            ("f2", "other/thing", "src/b.py", None, None),
        )

        changes, report = reown.plan(
            catalog,
            rules_by_repo={},
            profile_owner_by_repo={},
            repo_full_name="acme/api",
        )

        assert report.scanned == 1
        assert [c["finding_id"] for c in changes] == ["f1"]
