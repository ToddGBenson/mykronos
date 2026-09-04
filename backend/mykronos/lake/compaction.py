"""Buffer -> Parquet compaction with upsert semantics (spec 05 §2, §5).

Runs on a timer (default every 5 minutes) and on demand. For each table it
folds every sealed buffer segment into the Parquet partitions, upserting on
the table's primary key so that re-ingesting the same finding updates it
rather than duplicating it.

Partitioning rule: a row lives in the partition of the date it was *first*
seen, permanently. An update therefore rewrites one known partition instead of
migrating the row, and yesterday's partitions stop changing once their
findings stop recurring.

Crash safety: segments are deleted only after their Parquet write is
confirmed. A crash in between replays those rows on the next run, which the
upsert makes idempotent.
"""

from __future__ import annotations

import logging
import os
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

import duckdb

from mykronos.lake.buffer import WriteAheadBuffer
from mykronos.lake.catalog import Catalog, sql_path
from mykronos.lake.tables import (
    MUTATION_TS,
    PARTITION_SOURCE,
    PATCH_COLUMNS,
    PRIMARY_KEY,
    TABLES,
    add_missing_columns,
    column_names,
)

logger = logging.getLogger(__name__)

# Columns refreshed from the incoming row when a key already exists.
# Everything absent from these lists is immutable after first write —
# notably first_seen_at and first_seen_scan_run_id, which are the whole point
# of upserting rather than appending.
_UPDATE_SETS: dict[str, str] = {
    "findings": """
        scan_run_id            = i.scan_run_id,
        last_seen_scan_run_id  = i.last_seen_scan_run_id,
        last_seen_at           = i.last_seen_at,
        line_start             = i.line_start,
        line_end               = i.line_end,
        symbol                 = i.symbol,
        code_snippet           = i.code_snippet,
        -- Refreshed, though for most findings it cannot change: `file_path`
        -- is part of identity for the snippet and line fingerprints, so a
        -- different path is a different finding by construction.
        --
        -- It can drift for the two fingerprints that exclude it — `v2-package`
        -- and `v2-repo`. A container CVE is keyed on the package, not the
        -- image (spec 05 §5), so the row keeps whatever image name it was
        -- first seen under. TheHub's Perl findings were still displaying
        -- `library/mykronos-scan` — the tag the retired Actions workflow
        -- used — a week after every scan had been reporting `thehub`. The
        -- findings were current; only the name was six days stale, and it
        -- named an image that no longer exists in the registry.
        file_path              = i.file_path,
        fingerprint_version    = i.fingerprint_version,
        severity               = i.severity,
        title                  = i.title,
        description            = i.description,
        cvss_score             = i.cvss_score,
        package_version        = i.package_version,
        raw_finding_json       = i.raw_finding_json,
        -- A finding that was marked fixed and has come back reopens
        -- (spec 05 §5). Human dispositions -- false_positive, accepted_risk,
        -- suppressed -- are decisions, not observations, so a rescan does not
        -- overturn them.
        status      = CASE WHEN part.status = 'fixed' THEN 'open' ELSE part.status END,
        resolved_at = CASE WHEN part.status = 'fixed' THEN NULL ELSE part.resolved_at END,
        -- A person who reassigned a finding made a decision; a re-scan is not
        -- new information about who should fix it, so ingest's CODEOWNERS
        -- answer does not overwrite one (spec 24 §1.2). Same shape as the
        -- disposition rule directly above: observations refresh, decisions
        -- stand.
        owner = CASE
            WHEN part.owner_source = 'manual' THEN part.owner ELSE i.owner
        END,
        owner_source = CASE
            WHEN part.owner_source = 'manual' THEN 'manual' ELSE i.owner_source
        END
    """,
    # A decision is immutable once made -- re-evaluating produces a *new*
    # decision, because spec 09 §10 requires past decisions to stay
    # reproducible. The only thing that changes afterwards is a human
    # override, and the check run id once it is posted.
    "risk_decisions": """
        human_override      = coalesce(i.human_override, part.human_override),
        github_check_run_id = coalesce(i.github_check_run_id, part.github_check_run_id),
        gate_outcome        = coalesce(i.gate_outcome, part.gate_outcome)
    """,
    # Re-evaluating a head commit replaces the whole assessment. Unlike a risk
    # decision, an insider-risk signal is not a historical verdict to preserve
    # -- it is the current read on one specific commit, and keeping a series of
    # them per commit would build exactly the per-author history spec 06 §9
    # forbids.
    "insider_risk_signals": """
        author_login        = i.author_login,
        insider_risk_score  = i.insider_risk_score,
        signal_breakdown    = i.signal_breakdown,
        ai_authorship_flag  = i.ai_authorship_flag,
        recommendation      = i.recommendation,
        evaluated_at        = i.evaluated_at,
        github_check_run_id = coalesce(i.github_check_run_id, part.github_check_run_id)
    """,
    # A release adds the SBOM and tag to the row a push already created for
    # that commit, so those two coalesce rather than overwrite -- a later push
    # scan of the same commit must not blank the release evidence.
    "sscs_evidence": """
        tag_or_release              = coalesce(i.tag_or_release, part.tag_or_release),
        sbom_ref                    = coalesce(i.sbom_ref, part.sbom_ref),
        dependency_count            = i.dependency_count,
        vulnerable_dependency_count = i.vulnerable_dependency_count,
        trust_score                 = i.trust_score,
        raw_trust_score             = i.raw_trust_score,
        provenance_json             = i.provenance_json,
        ecosystems_json             = i.ecosystems_json,
        evaluated_at                = i.evaluated_at
    """,
    # The pipeline advances a finding through stages across runs, so an
    # update refreshes the assessment -- but the PR fields coalesce, because
    # the webhook writes pr_status long after the pipeline wrote the rest and
    # a later pipeline run must not blank the pull request it already opened.
    "remediation_events": """
        pipeline_stage_reached   = i.pipeline_stage_reached,
        triage_classification    = i.triage_classification,
        contributing_finding_ids = i.contributing_finding_ids,
        toxic_combination_id     = coalesce(i.toxic_combination_id, part.toxic_combination_id),
        rationale                = i.rationale,
        -- Coalesced, not refreshed: the webhook and the verification job both
        -- write this row and neither of them knows which fixer produced it
        -- (spec 25 §3.1).
        fixer_name               = coalesce(i.fixer_name, part.fixer_name),
        -- Written once, by the webhook, and unknown to every other writer.
        rejection_reason_code    = coalesce(
            i.rejection_reason_code, part.rejection_reason_code
        ),
        rejection_reason         = coalesce(i.rejection_reason, part.rejection_reason),
        fix_pr_number            = coalesce(i.fix_pr_number, part.fix_pr_number),
        fix_pr_url               = coalesce(i.fix_pr_url, part.fix_pr_url),
        pr_status                = coalesce(i.pr_status, part.pr_status),
        -- Three writers, three moments (spec 25 §2): the webhook knows the
        -- merge commit, the job knows it dispatched, the resolver knows the
        -- verdict. None of them holds the other two's values, so each
        -- coalesces rather than blanking what it does not know.
        verification_commit_sha    = coalesce(
            i.verification_commit_sha, part.verification_commit_sha
        ),
        verification_dispatched_at = coalesce(
            i.verification_dispatched_at, part.verification_dispatched_at
        ),
        verification_scan_run_id   = coalesce(
            i.verification_scan_run_id, part.verification_scan_run_id
        ),
        verification_outcome       = coalesce(
            i.verification_outcome, part.verification_outcome
        ),
        verified_at                = coalesce(i.verified_at, part.verified_at),
        time_to_verified_seconds   = coalesce(
            i.time_to_verified_seconds, part.time_to_verified_seconds
        ),
        updated_at               = i.updated_at
    """,
    # A link is written once and then only ever refreshed by evidence: the
    # lane's last green run, and a promotion from `asserted` to
    # `demonstrated`. `evidence` coalesces so a later `asserted` write cannot
    # demote a link the platform has actually watched work (spec 31 §1).
    # A component row is rewritten whole on every scan that still sees it, so
    # everything refreshes except `first_seen_at` — which is the entire reason
    # for upserting rather than appending. "When did this repository first
    # take this version" is answerable from that column alone, and appending
    # would need a second table to answer it (spec 29 §1).
    "sbom_components": """
        commit_sha       = i.commit_sha,
        scan_run_id      = i.scan_run_id,
        direct           = i.direct,
        purl             = i.purl,
        license_ids_json = i.license_ids_json,
        observed_at      = i.observed_at
    """,
    "finding_tests": """
        test_identifier    = i.test_identifier,
        capability         = i.capability,
        evidence           = CASE
            WHEN part.evidence = 'demonstrated' THEN 'demonstrated'
            ELSE coalesce(i.evidence, part.evidence)
        END,
        lane_last_green_at = coalesce(i.lane_last_green_at, part.lane_last_green_at),
        updated_at         = i.updated_at
    """,
    "scan_runs": """
        repo_full_name         = i.repo_full_name,
        capability             = i.capability,
        tool_name              = i.tool_name,
        tool_version           = i.tool_version,
        commit_sha             = i.commit_sha,
        branch                 = i.branch,
        pr_number              = i.pr_number,
        triggered_by           = i.triggered_by,
        github_workflow_run_id = i.github_workflow_run_id,
        completed_at           = i.completed_at,
        scan_status            = i.scan_status,
        finding_count          = i.finding_count,
        raw_output_ref         = i.raw_output_ref,
        -- spec 19 §1.2. Only ever set on the finalising post (D-002), which
        -- is an UPDATE whenever compaction ran between the two — i.e. for
        -- any scan longer than the compaction interval. Omitting it here
        -- dropped the message silently for exactly those scans.
        detail                 = i.detail,
        ingested_at            = i.ingested_at
    """,
}


@dataclass
class CompactionResult:
    inserted: dict[str, int] = field(default_factory=dict)
    updated: dict[str, int] = field(default_factory=dict)
    reopened: list[str] = field(default_factory=list)
    segments_consumed: int = 0
    partitions_written: int = 0

    @property
    def total_rows(self) -> int:
        return sum(self.inserted.values()) + sum(self.updated.values())


def _stage_incoming(
    con: duckdb.DuckDBPyConnection,
    table: str,
    segments: list[Path],
) -> None:
    """Load buffered segments into a temp table, collapsing duplicate keys.

    DuckDB reads the JSONL segments directly. Round-tripping them through
    Python and `executemany` costs roughly 20s per 10k rows — DuckDB's
    prepared-statement path inserts row by row — which alone would blow the
    30-second budget in spec 05 §9. Reading the files natively is a vectorised
    scan, and it deletes the hand-written type-coercion layer that sat between
    the buffer's JSON and the table's types.

    Within one batch the same key can appear repeatedly (a retried workflow,
    two scans of one commit). Last write wins, ordered by the API-stamped
    mutation timestamp rather than by file scan order.

    Except for `PATCH_COLUMNS`. Those arrive on rows that are otherwise empty
    and mean "set this field, leave the rest alone", so a plain last-write-wins
    collapse would throw the earlier patch away before the upsert ever saw it —
    overriding a risk decision and then merging its pull request within one
    compaction window would silently lose the override. For those columns the
    collapse takes the newest *non-null* value instead.
    """
    names = column_names(table)
    pk = PRIMARY_KEY[table]
    mutation_ts = MUTATION_TS[table]
    patches = PATCH_COLUMNS[table]

    columns_spec = ", ".join(f"'{name}': '{sql_type}'" for name, sql_type in TABLES[table])
    file_list = ", ".join(f"'{sql_path(path)}'" for path in segments)

    con.execute("DROP TABLE IF EXISTS incoming_raw")
    con.execute("DROP TABLE IF EXISTS incoming")
    con.execute(
        f"""
        CREATE TEMP TABLE incoming_raw AS
        SELECT *, row_number() OVER () AS _seq
        FROM read_json(
            [{file_list}],
            format = 'newline_delimited',
            columns = {{{columns_spec}}},
            ignore_errors = true
        )
        """
    )
    # Newest first, so first_value is the latest write and — with IGNORE NULLS
    # over the whole partition — the latest write that actually set the column.
    window = (
        f"PARTITION BY {pk} ORDER BY {mutation_ts} DESC NULLS LAST, _seq DESC "
        "ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING"
    )
    patched = [
        f"first_value({name} IGNORE NULLS) OVER w AS _patch_{name}" for name in patches
    ]
    projection = ", ".join(
        f"_patch_{name} AS {name}" if name in patches else name for name in names
    )

    con.execute(
        f"""
        CREATE TEMP TABLE incoming AS
        SELECT {projection} FROM (
            SELECT *,
                   row_number() OVER w AS _rn
                   {''.join(f', {expr}' for expr in patched)}
            FROM incoming_raw
            WINDOW w AS ({window})
        ) WHERE _rn = 1
        """
    )
    con.execute("DROP TABLE incoming_raw")


def _write_parquet(con: duckdb.DuckDBPyConnection, select_sql: str, destination: Path) -> None:
    """Write a relation to Parquet atomically."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    pending = destination.with_suffix(".parquet.tmp")
    con.execute(f"COPY ({select_sql}) TO '{sql_path(pending)}' (FORMAT PARQUET)")
    os.replace(pending, destination)


def _compact_table(
    con: duckdb.DuckDBPyConnection,
    catalog: Catalog,
    table: str,
    segments: list[Path],
    result: CompactionResult,
) -> None:
    names = column_names(table)
    projection = ", ".join(names)
    pk = PRIMARY_KEY[table]
    partition_col = PARTITION_SOURCE[table]

    _stage_incoming(con, table, segments)

    # Which incoming keys already exist, and in which partition?
    existing = con.execute(
        f"""
        SELECT i.{pk}, t.dt
        FROM incoming i
        JOIN {table} t ON t.{pk} = i.{pk}
        """
    ).fetchall()

    by_partition: dict[str, list[str]] = defaultdict(list)
    for key, dt in existing:
        by_partition[str(dt)].append(str(key))

    updated = 0
    for dt, keys in by_partition.items():
        files = catalog.partition_files(table, dt)
        if not files:
            continue
        pattern = sql_path(catalog.partition_dir(table, dt) / "*.parquet")

        con.execute("DROP TABLE IF EXISTS part")
        con.execute(
            f"CREATE TEMP TABLE part AS "
            f"SELECT * FROM read_parquet('{pattern}', union_by_name = 1)"
        )
        # Schema evolution. `union_by_name` reconciles columns *across* files;
        # it cannot invent one that no file has. A column added to the schema
        # after a partition was written is absent from every file in it, and
        # naming it in the projection fails with a binder error pointing at
        # the column rather than at the cause.
        #
        # Adding a finding column is not exotic — `superseded_by` arrived with
        # spec 05 §5a — so missing columns are filled with NULL here, which is
        # what a row written before the column existed truthfully has.
        add_missing_columns(con, "part", table)

        if table == "findings":
            reopened = con.execute(
                "SELECT part.finding_id FROM part "
                "JOIN incoming i ON i.finding_id = part.finding_id "
                "WHERE part.status = 'fixed'"
            ).fetchall()
            result.reopened.extend(str(r[0]) for r in reopened)

        con.execute(
            f"UPDATE part SET {_UPDATE_SETS[table]} FROM incoming i WHERE part.{pk} = i.{pk}"
        )

        # One consolidated part file per partition. Rewriting is what lets a
        # row be updated in place; consolidating keeps file count bounded.
        target = catalog.partition_dir(table, dt) / "part-0000.parquet"
        _write_parquet(con, f"SELECT {projection} FROM part", target)
        for stale in files:
            if stale != target:
                stale.unlink(missing_ok=True)
        con.execute("DROP TABLE part")

        updated += len(keys)
        result.partitions_written += 1

    # Everything not matched is new. Group it by its own partition date.
    fresh_partitions = con.execute(
        f"""
        SELECT strftime(i.{partition_col}, '%Y-%m-%d') AS dt, count(*)
        FROM incoming i
        LEFT JOIN {table} t ON t.{pk} = i.{pk}
        WHERE t.{pk} IS NULL
        GROUP BY 1 ORDER BY 1
        """
    ).fetchall()

    inserted = 0
    for dt, count in fresh_partitions:
        dt = str(dt)
        index = catalog.next_part_index(table, dt)
        target = catalog.partition_dir(table, dt) / f"part-{index:04d}.parquet"
        _write_parquet(
            con,
            f"""
            SELECT {', '.join(f'i.{n}' for n in names)}
            FROM incoming i
            LEFT JOIN {table} t ON t.{pk} = i.{pk}
            WHERE t.{pk} IS NULL
              AND strftime(i.{partition_col}, '%Y-%m-%d') = '{dt}'
            """,
            target,
        )
        inserted += int(count)
        result.partitions_written += 1

    con.execute("DROP TABLE IF EXISTS incoming")
    catalog.refresh_views(con)

    if inserted:
        result.inserted[table] = result.inserted.get(table, 0) + inserted
    if updated:
        result.updated[table] = result.updated.get(table, 0) + updated


def compact(
    catalog: Catalog,
    buffer: WriteAheadBuffer,
    tables: list[str] | None = None,
) -> CompactionResult:
    """Fold all sealed buffer segments into Parquet. Safe to run concurrently
    with ingestion — new segments simply land in the next run."""
    result = CompactionResult()
    targets = tables or list(TABLES)

    # scan_runs first: findings reference a scan_run_id, so a reader that
    # catches the lake mid-compaction sees the run before its findings rather
    # than orphaned findings.
    targets.sort(key=lambda t: 0 if t == "scan_runs" else 1)

    with catalog.connect() as con:
        for table in targets:
            segments = buffer.sealed_segments(table)
            if not segments:
                continue

            # A zero-byte segment would make read_json fail on a schema it
            # cannot sample; there is nothing in it to compact either way.
            usable = [s for s in segments if s.stat().st_size > 0]

            if usable:
                try:
                    _compact_table(con, catalog, table, usable, result)
                except Exception:
                    # Leave the segments in place — the buffer stays the source
                    # of truth until a write is confirmed (spec 05 §10).
                    logger.exception("Compaction failed for %s; segments retained", table)
                    raise

            buffer.consume(segments)
            result.segments_consumed += len(segments)

    if result.reopened:
        # Feeds spec 11 retro signals once the Knowledge Store exists (Phase 5).
        logger.info("Findings reopened during compaction: %s", len(result.reopened))

    return result
