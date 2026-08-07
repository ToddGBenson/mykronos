"""Operator CLI.

    mykronos init-lake
    mykronos mint-token <owner/repo> <capability>
    mykronos revoke-token <owner/repo> <capability>
    mykronos list-tokens
    mykronos compact
    mykronos query "SELECT ..."
    mykronos stats

`query` is the Phase 0 demo's second half (spec 13 §3): curl a finding in,
then read it back out of the lake with SQL.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Sequence

from mykronos.auth import TokenRegistry
from mykronos.config import get_settings
from mykronos.lake import Catalog, WriteAheadBuffer, compact
from mykronos.schemas import Capability


def _print_table(columns: Sequence[str], rows: Sequence[Sequence[object]]) -> None:
    if not rows:
        print("(no rows)")
        return
    rendered = [[("" if v is None else str(v)) for v in row] for row in rows]
    widths = [
        max(len(str(col)), *(len(r[i]) for r in rendered)) for i, col in enumerate(columns)
    ]
    print("  ".join(str(c).ljust(w) for c, w in zip(columns, widths, strict=True)))
    print("  ".join("-" * w for w in widths))
    for row in rendered:
        print("  ".join(v.ljust(w) for v, w in zip(row, widths, strict=True)))


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    settings = get_settings()

    parser = argparse.ArgumentParser(prog="mykronos", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init-lake", help="Create the data lake directory layout and catalog views")

    mint = sub.add_parser("mint-token", help="Issue an ingestion token for one (repo, capability)")
    mint.add_argument("repo", help="owner/repo")
    mint.add_argument("capability", choices=[c.value for c in Capability])
    mint.add_argument("--label", default="", help="Free-text note recorded with the token")

    revoke = sub.add_parser("revoke-token", help="Revoke all tokens for one (repo, capability)")
    revoke.add_argument("repo")
    revoke.add_argument("capability", choices=[c.value for c in Capability])

    sub.add_parser("list-tokens", help="List token scopes (hashes only, never plaintext)")
    sub.add_parser("compact", help="Fold the write-ahead buffer into Parquet now")
    sub.add_parser("stats", help="Row counts and buffer depth")

    query = sub.add_parser("query", help="Run read-only SQL against the lake")
    query.add_argument("sql")
    query.add_argument("--json", action="store_true", help="Emit JSON instead of a table")

    args = parser.parse_args(argv)
    catalog = Catalog(settings.datalake_dir)
    buffer = WriteAheadBuffer(settings.buffer_dir)

    if args.command == "init-lake":
        catalog.initialise()
        print(f"Data lake ready at {settings.datalake_dir.resolve()}")
        return 0

    if args.command == "mint-token":
        registry = TokenRegistry(settings.token_registry_path)
        plaintext = registry.issue(args.repo, args.capability, label=args.label)
        print(f"Scope     : {args.repo} / {args.capability}")
        print(f"Token     : {plaintext}")
        print("")
        print("Store it now - only its SHA-256 is persisted; it cannot be shown again.")
        print("In Phase 1 the Workflow Installer seals this into a repo secret for you.")
        return 0

    if args.command == "revoke-token":
        registry = TokenRegistry(settings.token_registry_path)
        count = registry.revoke(args.repo, args.capability)
        print(f"Revoked {count} token(s) for {args.repo} / {args.capability}")
        return 0

    if args.command == "list-tokens":
        registry = TokenRegistry(settings.token_registry_path)
        scopes = registry.list_scopes()
        _print_table(
            ["repo", "capability", "issued_at", "rotate_after", "revoked", "sha256"],
            [
                [s.repo_full_name, s.capability, s.issued_at, s.rotate_after,
                 s.revoked, s.token_sha256[:12] + "..."]
                for s in scopes
            ],
        )
        return 0

    if args.command == "compact":
        result = compact(catalog, buffer)
        print(
            f"Consumed {result.segments_consumed} segment(s); "
            f"inserted {sum(result.inserted.values())}, "
            f"updated {sum(result.updated.values())}, "
            f"reopened {len(result.reopened)}; "
            f"wrote {result.partitions_written} partition file(s)."
        )
        return 0

    if args.command == "stats":
        _print_table(
            ["metric", "value"],
            [
                ["scan_runs", catalog.count("scan_runs")],
                ["findings", catalog.count("findings")],
                ["buffered segments", buffer.count_sealed()],
            ],
        )
        return 0

    if args.command == "query":
        with catalog.connect_readonly() as con:
            cursor = con.execute(args.sql)
            columns = [d[0] for d in cursor.description or []]
            rows = cursor.fetchall()
        if args.json:
            records = [dict(zip(columns, r, strict=True)) for r in rows]
            print(json.dumps(records, default=str, indent=2))
        else:
            _print_table(columns, rows)
        return 0

    parser.error(f"Unhandled command {args.command!r}")  # exits non-zero


if __name__ == "__main__":
    sys.exit(main())
