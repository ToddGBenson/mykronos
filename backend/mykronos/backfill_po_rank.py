"""Copy MyKronos's `po_backlog_rank` rows into TheHub's `po_rank` (B-068, D-153).

One shot. The Product Owner's rank used to live here, keyed by (repository,
story); it now lives on the Hub story. This copies what was here across, once,
before the table is dropped (`RETIRED_TABLES` in `db/session.py`).

The table is read with plain SQL, not through a model, so the script still
runs -- and says there is nothing to copy -- once the model has gone.

What it does with each story id:

- **Ranked by one repository:** PATCHes `{"po_rank": rank}` and nothing else.
- **Ranked by two repositories:** reported, never resolved. The Hub has one
  rank per story and the two repositories disagree about it, or agree by
  accident; either way choosing one is the Product Owner's call, not this
  script's.
- **Gone from TheHub (404):** skipped and reported.
- **Already ranked in TheHub:** left alone and reported. The tab may have
  written it since; overwriting it with an older value would lose that.

`--dry-run` makes the same reads and writes nothing.

    python -m mykronos.backfill_po_rank --dry-run
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections import defaultdict
from dataclasses import dataclass, field

from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine

from mykronos import product_owner as po

TABLE = "po_backlog_rank"


@dataclass
class BackfillReport:
    rows: int = 0
    copied: list[tuple[int, int]] = field(default_factory=list)
    already_ranked: list[tuple[int, int, int]] = field(default_factory=list)
    not_found: list[int] = field(default_factory=list)
    conflicts: dict[int, list[tuple[str, int]]] = field(default_factory=dict)
    refused: list[tuple[int, str]] = field(default_factory=list)
    table_absent: bool = False

    def lines(self, *, dry_run: bool) -> list[str]:
        if self.table_absent:
            return [f"{TABLE} does not exist: nothing to copy."]
        verb = "would copy" if dry_run else "copied"
        out = [
            f"{self.rows} row(s) in {TABLE}; {verb} {len(self.copied)}; "
            f"{len(self.already_ranked)} already ranked in TheHub; "
            f"{len(self.not_found)} not in TheHub; "
            f"{len(self.conflicts)} ranked by more than one repository; "
            f"{len(self.refused)} refused."
        ]
        out += [f"  {verb}: story {sid} -> po_rank {rank}" for sid, rank in self.copied]
        out += [
            f"  left alone: story {sid} has po_rank {hub} in TheHub (MyKronos had {ours})"
            for sid, ours, hub in self.already_ranked
        ]
        out += [f"  skipped: story {sid} is not in TheHub (404)" for sid in self.not_found]
        for sid, ranks in sorted(self.conflicts.items()):
            held = ", ".join(f"repo {repo} rank {rank}" for repo, rank in ranks)
            out.append(f"  NOT RESOLVED: story {sid} is ranked by {held}")
        out += [f"  refused: story {sid}: {detail}" for sid, detail in self.refused]
        if dry_run:
            out.append("(dry run, nothing written)")
        return out


def read_rows(engine: Engine) -> list[tuple[str, int, int]] | None:
    """(repo id, story id, rank), or None when the table is gone."""
    if TABLE not in inspect(engine).get_table_names():
        return None
    with engine.connect() as connection:
        result = connection.execute(
            text(f"SELECT repo_id, story_id, rank FROM {TABLE} ORDER BY story_id, repo_id")
        )
        return [(str(r[0]), int(r[1]), int(r[2])) for r in result]


async def backfill_po_rank(
    engine: Engine, hub: po.HubClient, *, dry_run: bool
) -> BackfillReport:
    report = BackfillReport()
    rows = read_rows(engine)
    if rows is None:
        report.table_absent = True
        return report
    report.rows = len(rows)

    by_story: dict[int, list[tuple[str, int]]] = defaultdict(list)
    for repo_id, story_id, rank in rows:
        by_story[story_id].append((repo_id, rank))

    for story_id, ranks in sorted(by_story.items()):
        if len(ranks) > 1:
            report.conflicts[story_id] = ranks
            continue
        rank = ranks[0][1]
        story = await hub.get_story(story_id)
        if story is None:
            report.not_found.append(story_id)
            continue
        if story.get("po_rank") is not None:
            report.already_ranked.append((story_id, rank, int(story["po_rank"])))
            continue
        if not dry_run:
            result = await hub.set_rank(story_id, rank)
            if not result.ok:
                report.refused.append((story_id, result.detail or ""))
                continue
        report.copied.append((story_id, rank))
    return report


def main(argv: list[str] | None = None) -> int:
    from mykronos.config import get_settings
    from mykronos.db.session import Database

    parser = argparse.ArgumentParser(prog="backfill-po-rank", description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="Read only; write nothing.")
    args = parser.parse_args(argv)

    settings = get_settings()
    hub = po.HubClient.from_settings(settings)
    if hub is None:
        sys.stderr.write("TheHub is not connected: set MYKRONOS_HUB_API_URL and _TOKEN.\n")
        return 2
    # Deliberately not `create_all`: that is where the table is dropped.
    engine = Database(settings.database_url).engine
    try:
        report = asyncio.run(backfill_po_rank(engine, hub, dry_run=args.dry_run))
    except po.HubUnavailableError as exc:
        sys.stderr.write(f"{exc}\n")
        return 1
    sys.stdout.write("\n".join(report.lines(dry_run=args.dry_run)) + "\n")
    return 1 if report.conflicts or report.refused else 0


if __name__ == "__main__":
    raise SystemExit(main())
