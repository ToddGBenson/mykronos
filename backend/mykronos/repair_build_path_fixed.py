"""Undo `fixed` on findings that only moved, while their paths were build dirs (TheHub #60734).

Before #795, PSScriptAnalyzer findings were stored under Concourse's build
directory (`tmp/build/<handle>/source/...`). No snippet could be read from a
path that is not in the checkout, so every one of them was keyed on its line
(`v1-line`). An edit above a finding moved it to a new line and a new id, and
absence reconciliation closed the old id as `fixed`: 13 mykronos findings on
2026-10-13 00:47Z, every one of which still has an open finding with the same
rule and the same message in the same file. Nothing was remediated, and
`fixed` feeds mean-time-to-fix and the Oracle's posture credits.

**What it decides, per (repository, rule, file, message).**

- *before*: the prefixed rows reported by the scan that last saw the fixed
  row -- the rows whose first and last sightings span it.
- *after*: the open repo-relative rows today.
- *moved*: the open repo-relative rows whose old prefixed identity first
  appeared after the fixed row was last seen -- the ids the edit minted.

Only where `before == after` (nothing with that message was added or removed
overall) **and** `moved` equals the number of fixed rows is the group
repaired. Each fixed row is paired with a moved row in line order -- an edit
above code shifts it without reordering it -- and becomes `superseded` by it
(`superseded_source = 'rekey'`). The successor inherits the earlier first
sighting. Anything else is reported with its counts and left alone: a count
that changed means at least one of those findings may really have gone, and
which one is not a question this can answer.

`dry_run` computes and reports everything and writes nothing. Do that first.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from mykronos.lake.catalog import Catalog
from mykronos.lake.mutate import locate_findings, update_findings
from mykronos.schemas import FindingStatus, utcnow

#: The prefix `adapters/sarif._clean_uri` strips since #795.
_BUILD_DIR = re.compile(r"^tmp/build/[0-9a-f]+/source/(?P<rest>.+)$")


@dataclass(frozen=True)
class _Row:
    finding_id: str
    asset_id: str
    capability: str
    rule_id: str
    title: str
    file_path: str
    line_start: int | None
    status: str
    first_seen_at: datetime | None
    first_seen_scan_run_id: str | None
    last_seen_at: datetime | None
    superseded_by: str | None

    @property
    def relative(self) -> str | None:
        match = _BUILD_DIR.match(self.file_path)
        return match.group("rest") if match else None


@dataclass
class Group:
    asset_id: str
    rule_id: str
    file_path: str
    title: str
    fixed: list[str]
    before: int
    after: int
    moved: int
    #: (fixed id, successor id, fixed line, successor's old line) when repaired.
    pairs: list[tuple[str, str, int | None, int | None]] = field(default_factory=list)
    reason: str = ""

    @property
    def repaired(self) -> bool:
        return bool(self.pairs)


@dataclass
class RepairResult:
    groups: list[Group] = field(default_factory=list)
    partitions_written: int = 0

    def summary(self) -> str:
        fixed = sum(len(g.fixed) for g in self.groups)
        repaired = sum(len(g.pairs) for g in self.groups)
        return (
            f"{fixed} fixed row(s) under a build-dir path in {len(self.groups)} "
            f"group(s): {repaired} superseded by the finding they moved to, "
            f"{fixed - repaired} left fixed and reported"
        )


_COLUMNS = (
    "finding_id, asset_id, capability, rule_id, coalesce(title, ''), file_path, "
    "line_start, status, first_seen_at, first_seen_scan_run_id, last_seen_at, superseded_by"
)


def _rows(catalog: Catalog, where: str, params: list[Any]) -> list[_Row]:
    return [
        _Row(
            finding_id=str(r[0]),
            asset_id=str(r[1]),
            capability=str(r[2]),
            rule_id=str(r[3]),
            title=str(r[4]),
            file_path=str(r[5]),
            line_start=r[6],
            status=str(r[7]),
            first_seen_at=r[8],
            first_seen_scan_run_id=None if r[9] is None else str(r[9]),
            last_seen_at=r[10],
            superseded_by=None if r[11] is None else str(r[11]),
        )
        for r in catalog.query(f"SELECT {_COLUMNS} FROM findings WHERE {where}", params)
    ]


def repair_build_path_fixed(
    catalog: Catalog, *, repo_full_name: str | None = None, dry_run: bool = False
) -> RepairResult:
    result = RepairResult()
    if not catalog.all_files("findings"):
        return result

    scope = " AND asset_id = ?" if repo_full_name else ""
    scope_params: list[Any] = [repo_full_name] if repo_full_name else []
    fixed = [
        r
        for r in _rows(
            catalog,
            "status = 'fixed' AND fingerprint_version = 'v1-line' "
            "AND file_path LIKE 'tmp/build/%'" + scope,
            scope_params,
        )
        if r.relative
    ]
    if not fixed:
        return result

    grouped: dict[tuple[str, str, str, str, str], list[_Row]] = defaultdict(list)
    for row in fixed:
        grouped[(row.asset_id, row.capability, row.rule_id, row.relative or "", row.title)].append(
            row
        )

    writes: list[tuple[_Row, _Row]] = []
    for (asset, capability, rule, relative, title), dead in sorted(grouped.items()):
        same = "asset_id = ? AND capability = ? AND rule_id = ? AND coalesce(title, '') = ?"
        params = [asset, capability, rule, title]
        prefixed = [
            r
            for r in _rows(catalog, f"{same} AND file_path LIKE 'tmp/build/%'", params)
            if r.relative == relative
        ]
        current = _rows(
            catalog, f"{same} AND file_path = ? AND status = 'open'", [*params, relative]
        )

        # Fixed rows in one group were last seen by one scan in practice; take
        # the latest so a row seen later than another is never "before" it.
        seen = max((d.last_seen_at for d in dead if d.last_seen_at), default=None)
        before = sum(
            1
            for r in prefixed
            if seen
            and r.first_seen_at
            and r.last_seen_at
            and r.first_seen_at <= seen <= r.last_seen_at
        )
        old_of = {r.superseded_by: r for r in prefixed if r.superseded_by}
        moved = sorted(
            (
                (c, old_of[c.finding_id])
                for c in current
                if c.finding_id in old_of
                and seen
                and old_of[c.finding_id].first_seen_at
                and old_of[c.finding_id].first_seen_at > seen  # type: ignore[operator]
            ),
            key=lambda pair: (pair[1].line_start or 0, pair[0].finding_id),
        )
        group = Group(
            asset_id=asset,
            rule_id=rule,
            file_path=relative,
            title=title,
            fixed=sorted(d.finding_id for d in dead),
            before=before,
            after=len(current),
            moved=len(moved),
        )
        result.groups.append(group)

        if before != len(current):
            group.reason = (
                f"count not conserved: {before} before, {len(current)} now -- "
                "something with this message was added or removed"
            )
            continue
        if len(moved) != len(dead):
            group.reason = f"{len(dead)} fixed but {len(moved)} moved finding(s) to pair them with"
            continue

        ordered = sorted(dead, key=lambda d: (d.line_start or 0, d.finding_id))
        for old, (successor, minted) in zip(ordered, moved, strict=True):
            group.pairs.append(
                (old.finding_id, successor.finding_id, old.line_start, minted.line_start)
            )
            writes.append((old, successor))

    if dry_run or not writes:
        return result

    now = utcnow()
    for old, successor in writes:
        if old.first_seen_at and (
            successor.first_seen_at is None or old.first_seen_at < successor.first_seen_at
        ):
            outcome = update_findings(
                catalog,
                locate_findings(catalog, [successor.finding_id]),
                "first_seen_at = ?, first_seen_scan_run_id = ?",
                [old.first_seen_at, old.first_seen_scan_run_id],
                only_if_status=FindingStatus.OPEN.value,
            )
            result.partitions_written += outcome.partitions_written
        # `superseded`, not `fixed`: the defect is the successor, still open.
        outcome = update_findings(
            catalog,
            locate_findings(catalog, [old.finding_id]),
            "status = ?, superseded_by = ?, resolved_at = ?, superseded_source = 'rekey'",
            [FindingStatus.SUPERSEDED.value, successor.finding_id, now],
            only_if_status=FindingStatus.FIXED.value,
        )
        result.partitions_written += outcome.partitions_written
    return result
