"""Operator CLI.

    mykronos init-lake
    mykronos mint-token <owner/repo> [--grant sast ...]
    mykronos rotate-token <owner/repo>
    mykronos grant <owner/repo> <capability>
    mykronos revoke-grant <owner/repo> <capability>
    mykronos revoke-repo <owner/repo>
    mykronos list-tokens
    mykronos purge-tokens
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

from sqlalchemy.orm import Session

from mykronos.auth import TokenRegistry
from mykronos.config import get_settings
from mykronos.db import Database
from mykronos.lake import Catalog, WriteAheadBuffer, compact
from mykronos.schemas import Capability

CAPABILITIES = [c.value for c in Capability]


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


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mykronos", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init-lake", help="Create the data lake and the operational database")

    mint = sub.add_parser("mint-token", help="Issue this repo's ingestion token")
    mint.add_argument("repo", help="owner/repo")
    mint.add_argument("--label", default="", help="Free-text note recorded with the token")
    mint.add_argument(
        "--grant",
        action="append",
        default=[],
        choices=CAPABILITIES,
        help="Capability to grant. Repeatable.",
    )

    rotate = sub.add_parser(
        "rotate-token", help="Rotate, keeping the previous token valid for the overlap window"
    )
    rotate.add_argument("repo")

    grant = sub.add_parser("grant", help="Allow a capability to write for this repo")
    grant.add_argument("repo")
    grant.add_argument("capability", choices=CAPABILITIES)

    ungrant = sub.add_parser("revoke-grant", help="Stop a capability writing, effective now")
    ungrant.add_argument("repo")
    ungrant.add_argument("capability", choices=CAPABILITIES)

    revoke = sub.add_parser("revoke-repo", help="Offboard: revoke every token and grant")
    revoke.add_argument("repo")

    sub.add_parser("list-tokens", help="List tokens and grants (hashes only, never plaintext)")
    sub.add_parser("purge-tokens", help="Drop superseded tokens past their overlap window")
    sub.add_parser("compact", help="Fold the write-ahead buffer into Parquet now")
    sub.add_parser("stats", help="Row counts and buffer depth")

    query = sub.add_parser("query", help="Run read-only SQL against the lake")
    query.add_argument("sql")
    query.add_argument("--json", action="store_true", help="Emit JSON instead of a table")

    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    settings = get_settings()

    parser = _build_parser()
    args = parser.parse_args(argv)

    catalog = Catalog(settings.datalake_dir)
    buffer = WriteAheadBuffer(settings.buffer_dir)
    db = Database(settings.database_url)

    def registry(session: Session) -> TokenRegistry:
        return TokenRegistry(session, overlap_hours=settings.token_overlap_hours)

    try:
        if args.command == "init-lake":
            catalog.initialise()
            db.create_all()
            print(f"Data lake     {settings.datalake_dir.resolve()}")
            print(f"Operational   {settings.database_url}")
            return 0

        if args.command == "mint-token":
            db.create_all()
            with db.session() as session:
                reg = registry(session)
                plaintext = reg.issue(args.repo, label=args.label)
                for capability in args.grant:
                    reg.grant(args.repo, capability)
                granted = sorted(reg.granted_capabilities(args.repo))
            print(f"Repo      : {args.repo}")
            print(f"Grants    : {', '.join(granted) or '(none yet - use `mykronos grant`)'}")
            print(f"Token     : {plaintext}")
            print("")
            print("Store it now - only its SHA-256 is persisted; it cannot be shown again.")
            print("The Workflow Installer seals this into MYKRONOS_INGESTION_TOKEN for you.")
            return 0

        if args.command == "rotate-token":
            with db.session() as session:
                plaintext = registry(session).rotate(args.repo)
            print(f"Repo      : {args.repo}")
            print(f"New token : {plaintext}")
            print("")
            print(
                f"The previous token stays valid for {settings.token_overlap_hours}h so "
                "workflows already running finish cleanly."
            )
            print("Update the repo secret now.")
            return 0

        if args.command == "grant":
            with db.session() as session:
                changed = registry(session).grant(args.repo, args.capability)
            verb = "Granted" if changed else "Already granted"
            print(f"{verb}: {args.capability} on {args.repo}")
            return 0

        if args.command == "revoke-grant":
            with db.session() as session:
                changed = registry(session).revoke_grant(args.repo, args.capability)
            verb = "Revoked" if changed else "No grant found"
            print(f"{verb}: {args.capability} on {args.repo}")
            return 0

        if args.command == "revoke-repo":
            with db.session() as session:
                count = registry(session).revoke_repo(args.repo)
            print(f"Offboarded {args.repo}: revoked {count} token(s) and every grant")
            return 0

        if args.command == "list-tokens":
            with db.session() as session:
                reg = registry(session)
                rows: list[Sequence[object]] = [
                    [
                        token.repo_full_name,
                        token.status,
                        ", ".join(sorted(reg.granted_capabilities(token.repo_full_name)))
                        or "-",
                        token.issued_at.isoformat(timespec="seconds"),
                        token.rotate_after.isoformat(timespec="seconds"),
                        token.token_sha256[:12] + "...",
                    ]
                    for token in reg.list_tokens()
                ]
            _print_table(
                ["repo", "status", "grants", "issued", "rotate after", "sha256"], rows
            )
            return 0

        if args.command == "purge-tokens":
            with db.session() as session:
                purged = registry(session).purge_expired()
            print(f"Purged {purged} superseded token(s) past their overlap window")
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
                results: list[Sequence[object]] = list(cursor.fetchall())
            if args.json:
                records = [dict(zip(columns, r, strict=True)) for r in results]
                print(json.dumps(records, default=str, indent=2))
            else:
                _print_table(columns, results)
            return 0

        parser.error(f"Unhandled command {args.command!r}")  # exits non-zero
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
