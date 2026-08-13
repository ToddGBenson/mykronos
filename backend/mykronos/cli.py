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
import asyncio
import json
import logging
import sys
from collections.abc import Sequence

from sqlalchemy.orm import Session

from mykronos.auth import TokenRegistry
from mykronos.config import get_settings
from mykronos.db import Database
from mykronos.db.models import RepoOnboarding
from mykronos.installer import DEFAULT_SECRET_NAME, TemplateLibrary
from mykronos.installer.resync import resync_templates
from mykronos.jobs import (
    purge_expired_insider_risk,
    reconcile_installations,
    rotate_ingestion_tokens,
    score_portfolio,
)
from mykronos.lake import Catalog, WriteAheadBuffer, compact, reconcile_absences
from mykronos.main import _build_github_factory as _github_factory
from mykronos.oracle import load_policy
from mykronos.oracle.service import OracleService
from mykronos.reprocess import reprocess
from mykronos.rescore_sscs import rescore_sscs
from mykronos.schemas import Capability

CAPABILITIES = [c.value for c in Capability]


def _print_table(columns: Sequence[str], rows: Sequence[Sequence[object]]) -> None:
    if not rows:
        print("(no rows)")
        return
    rendered = [[("" if v is None else str(v)) for v in row] for row in rows]
    widths = [max(len(str(col)), *(len(r[i]) for r in rendered)) for i, col in enumerate(columns)]
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
    rotate.add_argument(
        "--immediate",
        action="store_true",
        help=(
            "Expire the previous token now instead of after the overlap "
            "window. For a leaked credential, where the graceful default "
            "leaves the disclosed value working for another 24 hours. "
            "Breaks any job still holding it, which is the point."
        ),
    )

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
    sub.add_parser(
        "reconcile-absences",
        help="Close findings absent from two consecutive scans (spec 05 §5)",
    )
    sub.add_parser("rotate-due", help="Run the token rotation sweep now")
    sub.add_parser("sync-installations", help="Check each installation still exists on GitHub")
    sub.add_parser(
        "score-portfolio",
        help="Give every Oracle-enabled repo a fresh standing risk decision",
    )
    sub.add_parser(
        "purge-insider-risk",
        help="Delete insider-risk rows past their retention window (spec 06 §9)",
    )
    ghtoken = sub.add_parser(
        "github-token",
        help="Mint a short-lived GitHub App installation token (spec 02 §4)",
    )
    ghtoken.add_argument("repo", help="owner/repo the token should be scoped to.")

    reproc = sub.add_parser(
        "reprocess",
        help="Re-derive findings from archived tool output (spec 05 §5a)",
    )
    reproc.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Report what would change and write nothing. Do this first: a "
            "real run can retire hundreds of records."
        ),
    )
    reproc.add_argument("--repo", default=None, help="Limit to one repository.")
    reproc.add_argument(
        "--all-history",
        action="store_true",
        help=(
            "Re-derive every archived scan, not just the latest per repo and "
            "capability. Rarely what you want: older scans are history, and "
            "re-materialising them resurrects findings later scans resolved."
        ),
    )
    reproc.add_argument(
        "--capability",
        default=None,
        choices=CAPABILITIES,
        help="Limit to one capability — usually the one whose adapter changed.",
    )

    rescore = sub.add_parser(
        "rescore-sscs",
        help="Re-score archived supply-chain evidence (spec 07 §5a)",
    )
    rescore.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what would change and write nothing.",
    )
    rescore.add_argument("--repo", default=None, help="Limit to one repository.")

    resync = sub.add_parser(
        "resync-templates",
        help="Open update PRs where rendered workflows have drifted (spec 03 §6)",
    )
    resync.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what would change without opening anything. Do this first.",
    )
    resync.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Maximum pull requests to open in one run (default 10).",
    )
    resync.add_argument(
        "--capability",
        action="append",
        default=[],
        choices=CAPABILITIES,
        help="Limit the sweep to these capabilities. Repeatable.",
    )
    resync.add_argument(
        "--repo",
        action="append",
        default=None,
        dest="repos",
        help=(
            "Limit the sweep to these repositories. Repeatable. A workflow a "
            "repository deleted on purpose reads as drift, so an unfiltered "
            "sweep would open a pull request putting it back."
        ),
    )

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
                plaintext = registry(session).rotate(args.repo, immediate=args.immediate)
            print(f"Repo      : {args.repo}")
            print(f"New token : {plaintext}")
            print("")
            if args.immediate:
                print(
                    "The previous token was expired immediately. Anything still "
                    "holding it is now failing with 401, which is the point."
                )
            else:
                print(
                    f"The previous token stays valid for {settings.token_overlap_hours}h so "
                    "workflows already running finish cleanly."
                )
                print(
                    "That overlap is wrong for a leaked credential - it keeps the "
                    "disclosed value working. Use --immediate for that."
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
                        ", ".join(sorted(reg.granted_capabilities(token.repo_full_name))) or "-",
                        token.issued_at.isoformat(timespec="seconds"),
                        token.rotate_after.isoformat(timespec="seconds"),
                        token.token_sha256[:12] + "...",
                    ]
                    for token in reg.list_tokens()
                ]
            _print_table(["repo", "status", "grants", "issued", "rotate after", "sha256"], rows)
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

        if args.command == "reconcile-absences":
            outcome = reconcile_absences(catalog)
            print(f"Closed {outcome.total_fixed} absent finding(s).")
            for repo, capability in outcome.insufficient_history:
                print(f"  skipped {repo}/{capability}: fewer than 2 qualifying scans")
            return 0

        if args.command in {"rotate-due", "sync-installations"}:
            db.create_all()
            factory = _github_factory(settings)
            if args.command == "rotate-due":
                rotation = asyncio.run(
                    rotate_ingestion_tokens(db, factory, overlap_hours=settings.token_overlap_hours)
                )
                print(f"Token rotation: {rotation.summary()}")
                for repo, reason in rotation.failed:
                    print(f"  FAILED {repo}: {reason}")
            else:
                sync = asyncio.run(reconcile_installations(db, factory))
                print(
                    f"Checked {sync.checked}; removed {len(sync.removed)}, "
                    f"suspended {len(sync.suspended)}, unreachable {len(sync.unreachable)}"
                )
            return 0

        if args.command == "score-portfolio":
            db.create_all()
            run = asyncio.run(
                score_portfolio(
                    db,
                    OracleService(catalog, buffer, load_policy(settings.oracle_policy_path)),
                )
            )
            # Bound before the call: passing sorted() straight in makes mypy
            # infer its element type from _print_table's Sequence[object]
            # parameter, and the key function stops seeing an int.
            worst_first = sorted(run.scored, key=lambda row: -row[1])
            _print_table(["repo", "score", "recommendation"], worst_first)
            for repo, reason in run.failed:
                print(f"  FAILED {repo}: {reason}")
            print(
                "\nDecisions are in the write-ahead buffer; run `compact` to make them queryable."
            )
            return 0

        if args.command == "purge-insider-risk":
            db.create_all()
            purge = purge_expired_insider_risk(
                db,
                catalog,
                default_retention_days=settings.insider_risk_default_retention_days,
            )
            print(
                f"Deleted {purge.rows_deleted} insider-risk row(s) across "
                f"{purge.partitions_rewritten} partition(s)."
            )
            if purge.applied:
                _print_table(["repo", "retention days"], sorted(purge.applied.items()))
            return 0

        if args.command == "github-token":
            # Prints the token, deliberately. It is a one-hour credential for
            # a caller that is about to use it, and the alternative — writing
            # it somewhere — leaves a credential outliving the need for it.
            # Nothing here logs or persists it.
            db.create_all()
            with db.session() as session:
                onboarding = (
                    session.query(RepoOnboarding)
                    .filter(RepoOnboarding.github_repo_full_name == args.repo)
                    .one_or_none()
                )
                if onboarding is None:
                    print(f"{args.repo} is not onboarded.", file=sys.stderr)
                    return 1
                installation_id = onboarding.github_installation_id

            client = _github_factory(settings).for_installation(installation_id)
            minter = getattr(client, "_token", None)
            if minter is None:
                print(
                    "No GitHub App is configured, so there is no installation to mint a token for.",
                    file=sys.stderr,
                )
                return 1
            # The client's own minting path, cache included. Reimplementing it
            # here would be a second place for App credential handling to
            # drift from the one the platform actually uses.
            print(asyncio.run(minter()))
            return 0

        if args.command == "reprocess":
            # Distinct names: `outcome` and `rows` are already bound above by
            # other subcommands, and reusing them made mypy infer the wrong
            # type rather than fail at runtime.
            rederived = reprocess(
                catalog,
                buffer,
                settings.raw_dir,
                repo_full_name=args.repo,
                capability=args.capability,
                dry_run=args.dry_run,
                all_history=args.all_history,
            )
            reprocess_rows = [
                (
                    scan.repo_full_name,
                    scan.capability,
                    scan.scan_run_id[:12],
                    scan.produced,
                    scan.unchanged,
                    scan.superseded,
                    scan.error[:40] or "",
                )
                for scan in rederived.scans
            ]
            _print_table(
                ["repo", "capability", "scan", "produced", "same", "superseded", "error"],
                reprocess_rows,
            )
            print()
            print(rederived.summary())
            if args.dry_run:
                print("Dry run - nothing was written.")
            else:
                print("Run `compact` to make the re-derived findings queryable.")
            return 0

        if args.command == "rescore-sscs":
            rescored = rescore_sscs(catalog, buffer, repo_full_name=args.repo, dry_run=args.dry_run)
            _print_table(
                ["repo", "commit", "deps", "was", "now"],
                [
                    (
                        row.repo_full_name,
                        row.commit_sha[:12],
                        row.dependency_count,
                        "null" if row.was is None else row.was,
                        "null" if row.now is None else row.now,
                    )
                    for row in rescored.changed
                ],
            )
            print()
            print(
                f"{rescored.examined} rows examined, {rescored.wrote} corrected, "
                f"{len(rescored.unscoreable)} without usable counts."
            )
            if rescored.unscoreable:
                print(
                    "Rows without per-ecosystem counts keep their stored score. "
                    "Re-running the scan is the only honest way to fix those."
                )
            if args.dry_run:
                print("Dry run - nothing was written.")
            else:
                print("Run `compact` to fold the corrections into Parquet.")
            return 0

        if args.command == "resync-templates":
            db.create_all()
            sweep = asyncio.run(
                resync_templates(
                    db,
                    TemplateLibrary(settings.workflow_templates_dir),
                    _github_factory(settings),
                    ingestion_api_url=settings.ingestion_api_url,
                    upload_action_ref=settings.upload_action_ref,
                    package_spec=settings.mykronos_package_spec,
                    secret_name=DEFAULT_SECRET_NAME,
                    capabilities=set(args.capability) or None,
                    repos=set(args.repos) if args.repos else None,
                    max_pull_requests=args.limit,
                    dry_run=args.dry_run,
                )
            )
            print(f"Template resync: {sweep.summary()}")
            drifted: list[Sequence[object]] = [
                [
                    r.repo_full_name,
                    ", ".join(r.drifted) or "-",
                    f"#{r.pull_request_number}" if r.pull_request_number else "-",
                    r.error or r.skipped_reason or "",
                ]
                for r in sweep.repos
            ]
            if drifted:
                _print_table(["repo", "drifted", "pr", "note"], drifted)
            if args.dry_run:
                print("\nDry run — nothing was opened.")
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
