"""Physical table definitions.

One place defines each table's columns and DuckDB types. The catalog, the
compaction writer and the empty-lake bootstrap all read from here, so the
Parquet schema cannot drift between the code that writes it and the code that
reads it.

`dt` is a Hive partition key encoded in the directory path, not a column
inside the files — it is therefore absent from `COLUMNS` and present in the
catalog views.
"""

from __future__ import annotations

from typing import Any, Final

Column = tuple[str, str]

FINDINGS_COLUMNS: Final[list[Column]] = [
    ("finding_id", "VARCHAR"),
    ("scan_run_id", "VARCHAR"),
    # The subject of the finding (spec 14 §5). A repository is an asset; a
    # network segment is an asset. `asset_id` holds `owner/repo` for a repo
    # and the operator-chosen network name for a network.
    #
    # For a repository asset, `asset_id` is exactly `repo_full_name` - the
    # same string. That is what makes this migration safe: `finding_id` is
    # derived from it (spec 05 §5), so every existing finding keeps its
    # identity and nothing reopens as new work.
    ("asset_type", "VARCHAR"),
    ("asset_id", "VARCHAR"),
    # Retired in favour of asset_id and kept for one migration step only, so
    # `migrate-assets` has something to read the mapping from. Spec 14 §5 is
    # explicit that two columns meaning the same thing is how a data model
    # rots; this one is on its way out, not settling in.
    ("repo_full_name", "VARCHAR"),
    ("capability", "VARCHAR"),
    ("rule_id", "VARCHAR"),
    ("title", "VARCHAR"),
    ("description", "VARCHAR"),
    ("severity", "VARCHAR"),
    ("cvss_score", "DOUBLE"),
    ("file_path", "VARCHAR"),
    ("line_start", "INTEGER"),
    ("line_end", "INTEGER"),
    ("symbol", "VARCHAR"),
    ("code_snippet", "VARCHAR"),
    ("fingerprint_version", "VARCHAR"),
    ("package_name", "VARCHAR"),
    ("package_version", "VARCHAR"),
    # Network findings (spec 14 §5). Null for everything with a file.
    ("address", "VARCHAR"),
    ("port", "INTEGER"),
    ("status", "VARCHAR"),
    # The finding_id that replaced this record, when `status = superseded`
    # (spec 05 §5a). Null otherwise, which is the overwhelming majority.
    ("superseded_by", "VARCHAR"),
    ("first_seen_scan_run_id", "VARCHAR"),
    ("last_seen_scan_run_id", "VARCHAR"),
    ("first_seen_at", "TIMESTAMP"),
    ("last_seen_at", "TIMESTAMP"),
    ("resolved_at", "TIMESTAMP"),
    # Who this is addressed to (spec 24 §1). Two columns rather than one
    # nullable string: "nobody owns this" and "we never worked out who owns
    # this" are different problems with different fixes, and a reader of a
    # single blank column cannot tell which they are looking at.
    # `owner_source` is codeowners | profile | manual | unresolved.
    ("owner", "VARCHAR"),
    ("owner_source", "VARCHAR"),
    # When this is due, and who set that date (spec 24 §2). Absent from the
    # compaction update set on purpose: like first_seen_at, a due date is
    # fixed at first sight, so re-running a scanner does not hand a
    # sixty-day-old finding a fresh thirty days. `due_source` is
    # kev | policy | manual.
    ("due_at", "TIMESTAMP"),
    ("due_source", "VARCHAR"),
    ("raw_finding_json", "VARCHAR"),
]

SCAN_RUNS_COLUMNS: Final[list[Column]] = [
    ("scan_run_id", "VARCHAR"),
    ("repo_full_name", "VARCHAR"),
    ("capability", "VARCHAR"),
    ("tool_name", "VARCHAR"),
    ("tool_version", "VARCHAR"),
    ("commit_sha", "VARCHAR"),
    ("branch", "VARCHAR"),
    ("pr_number", "INTEGER"),
    ("triggered_by", "VARCHAR"),
    ("github_workflow_run_id", "VARCHAR"),
    ("started_at", "TIMESTAMP"),
    ("completed_at", "TIMESTAMP"),
    ("scan_status", "VARCHAR"),
    ("finding_count", "INTEGER"),
    ("raw_output_ref", "VARCHAR"),
    ("ingested_at", "TIMESTAMP"),
    # A one-line summary (spec 19 §1.2) — nullable, no default, so it needs
    # no GRANDFATHERED entry in the schema-drift guard (D-052): a column
    # that's fine to be absent on an old row needs neither.
    ("detail", "VARCHAR"),
]

RISK_DECISIONS_COLUMNS: Final[list[Column]] = [
    ("decision_id", "VARCHAR"),
    ("repo_full_name", "VARCHAR"),
    ("decision_type", "VARCHAR"),
    ("pr_number", "INTEGER"),
    ("release_tag", "VARCHAR"),
    ("commit_sha", "VARCHAR"),
    ("overall_risk_score", "INTEGER"),
    ("recommendation", "VARCHAR"),
    # The explainability record (spec 09 §3). Stored as JSON text: it is read
    # whole and rendered, never filtered on, so a column-per-term would be
    # schema churn for nothing.
    ("inputs_snapshot", "VARCHAR"),
    ("reasoning", "VARCHAR"),
    ("policy_version", "VARCHAR"),
    ("evaluated_at", "TIMESTAMP"),
    # Populated when a human overrides the recommendation (spec 09 §6). The
    # single highest-value retro signal in the system, per spec 11 §4.
    ("human_override", "VARCHAR"),
    ("github_check_run_id", "VARCHAR"),
    # What happened to the change this gate judged: merged, closed_unmerged,
    # or null while still open. Filled in by the pull_request webhook.
    #
    # This is the shadow-mode evidence (spec 09 §6, open question 5): a
    # no_go decision on a PR that merged anyway is exactly the data that
    # argues for -- or against -- ever turning blocking on.
    ("gate_outcome", "VARCHAR"),
]

INSIDER_RISK_SIGNALS_COLUMNS: Final[list[Column]] = [
    # Derived from repo + pr_number + commit_sha (spec 06 §3), not random: the
    # workflow triggers on `synchronize`, so an unchanged head commit
    # re-evaluated must upsert rather than append.
    ("signal_id", "VARCHAR"),
    ("repo_full_name", "VARCHAR"),
    ("pr_number", "INTEGER"),
    ("commit_sha", "VARCHAR"),
    # Personal data. Required, and admin-only at the query layer (spec 06 §9).
    # Omitting it would not de-identify the row -- repo plus PR number does
    # that trivially -- it would only make the row unauditable and
    # undeletable.
    ("author_login", "VARCHAR"),
    ("insider_risk_score", "INTEGER"),
    # Per-signal sub-scores each carrying a rationale string (spec 06 §6). A
    # number with no reason attached is not something a person can dispute.
    ("signal_breakdown", "VARCHAR"),
    # Three states, not two: true (likely and undisclosed), false (evaluated,
    # human), null (not evaluated -- no classifier configured, or it was
    # unreachable). Collapsing null into false would report "we checked, it is
    # human" when nothing checked.
    ("ai_authorship_flag", "BOOLEAN"),
    ("recommendation", "VARCHAR"),
    ("evaluated_at", "TIMESTAMP"),
    ("github_check_run_id", "VARCHAR"),
]

SSCS_EVIDENCE_COLUMNS: Final[list[Column]] = [
    # Derived from repo + commit_sha (spec 07 §3). A random UUID could not
    # satisfy §7's "exactly one row per tagged release".
    ("evidence_id", "VARCHAR"),
    ("repo_full_name", "VARCHAR"),
    ("commit_sha", "VARCHAR"),
    ("tag_or_release", "VARCHAR"),
    ("sbom_ref", "VARCHAR"),
    ("dependency_count", "INTEGER"),
    ("vulnerable_dependency_count", "INTEGER"),
    ("trust_score", "INTEGER"),
    # Pre-clamp. Ranking has to survive the floor at 0, exactly as Oracle's
    # raw_score has to survive the ceiling at 100 (D-018).
    ("raw_trust_score", "DOUBLE"),
    ("provenance_json", "VARCHAR"),
    # Kept alongside the aggregate so a monorepo's per-ecosystem detail is not
    # lost to the sum (spec 07 §8).
    ("ecosystems_json", "VARCHAR"),
    ("evaluated_at", "TIMESTAMP"),
]

REMEDIATION_EVENTS_COLUMNS: Final[list[Column]] = [
    # Derived from repo + finding, or from the sorted contributing findings
    # for a combination (spec 08 §4). The pipeline re-runs on every push to a
    # pull request, so a random id would append a row per run and §7's "exactly
    # one event per finding routed" would quietly stop holding.
    ("event_id", "VARCHAR"),
    ("repo_full_name", "VARCHAR"),
    ("finding_id", "VARCHAR"),
    ("toxic_combination_id", "VARCHAR"),
    # JSON array. §7 requires a combination event to reference every finding
    # it is made of, and the original model had nowhere to put them.
    ("contributing_finding_ids", "VARCHAR"),
    ("pipeline_stage_reached", "VARCHAR"),
    ("triage_classification", "VARCHAR"),
    ("fix_pr_number", "INTEGER"),
    ("fix_pr_url", "VARCHAR"),
    # draft_open | human_edited | merged | closed_unmerged. Kept in sync by
    # the pull_request webhook, and the richest retro signal in the system
    # (spec 11 §9): a merged auto-fix and an abandoned one are the clearest
    # verdicts a human ever gives this platform.
    ("pr_status", "VARCHAR"),
    ("rationale", "VARCHAR"),
    ("created_at", "TIMESTAMP"),
    ("updated_at", "TIMESTAMP"),
]

TABLES: Final[dict[str, list[Column]]] = {
    "findings": FINDINGS_COLUMNS,
    "scan_runs": SCAN_RUNS_COLUMNS,
    "risk_decisions": RISK_DECISIONS_COLUMNS,
    "insider_risk_signals": INSIDER_RISK_SIGNALS_COLUMNS,
    "sscs_evidence": SSCS_EVIDENCE_COLUMNS,
    "remediation_events": REMEDIATION_EVENTS_COLUMNS,
}

#: Primary key per table — the column compaction upserts on.
PRIMARY_KEY: Final[dict[str, str]] = {
    "findings": "finding_id",
    "scan_runs": "scan_run_id",
    "risk_decisions": "decision_id",
    "insider_risk_signals": "signal_id",
    "sscs_evidence": "evidence_id",
    "remediation_events": "event_id",
}

#: Timestamp whose date determines a row's Hive partition. A row stays in the
#: partition it was first written to, so updates rewrite one known partition
#: rather than migrating rows between them.
PARTITION_SOURCE: Final[dict[str, str]] = {
    "findings": "first_seen_at",
    "scan_runs": "started_at",
    "risk_decisions": "evaluated_at",
    "insider_risk_signals": "evaluated_at",
    "sscs_evidence": "evaluated_at",
    "remediation_events": "created_at",
}

#: Timestamp that orders two writes of the same key within one compaction
#: batch. Stamped by the API at request time, so it is a real logical ordering
#: rather than a dependence on file scan order.
MUTATION_TS: Final[dict[str, str]] = {
    "findings": "last_seen_at",
    "scan_runs": "ingested_at",
    "risk_decisions": "evaluated_at",
    "insider_risk_signals": "evaluated_at",
    "sscs_evidence": "evaluated_at",
    "remediation_events": "updated_at",
}


#: Columns written by *partial* updates — a row that sets one of these leaves
#: the others null and means "leave them alone", which is why the upsert
#: coalesces them against the stored row rather than overwriting.
#:
#: Compaction has to know about them separately, because its normal
#: last-write-wins collapse of duplicate keys within a batch would discard the
#: earlier patch entirely. Overriding a decision and then merging its pull
#: request inside one five-minute compaction window is an ordinary sequence,
#: and it must not cost the override.
PATCH_COLUMNS: Final[dict[str, tuple[str, ...]]] = {
    "findings": (),
    "scan_runs": (),
    "risk_decisions": ("human_override", "github_check_run_id", "gate_outcome"),
    # The Check Run is posted after the score is computed, so its id can
    # arrive on a later row than the assessment it belongs to.
    "insider_risk_signals": ("github_check_run_id",),
    # A push scan and a release scan of the same commit can land in one batch.
    # The release row carries the SBOM and the tag; the push row carries
    # neither. Without these declared, the collapse would keep whichever
    # arrived last and a release could silently lose its evidence -- which is
    # precisely the failure D-020 describes.
    "sscs_evidence": ("tag_or_release", "sbom_ref"),
    # The webhook sets pr_status long after the pipeline set everything else,
    # and a later pipeline run must not blank the PR it already opened.
    "remediation_events": ("pr_status", "fix_pr_number", "fix_pr_url"),
}


def column_names(table: str) -> list[str]:
    return [name for name, _ in TABLES[table]]


def empty_select(table: str) -> str:
    """A typed, zero-row SELECT — the shape of a table before any data exists.

    Lets the catalog expose every view from the moment the lake is created, so
    dashboard and Oracle queries return empty results rather than failing on a
    missing relation.
    """
    cols = ", ".join(f"CAST(NULL AS {sql_type}) AS {name}" for name, sql_type in TABLES[table])
    return f"SELECT {cols}, CAST(NULL AS VARCHAR) AS dt WHERE 1=0"


def add_missing_columns(con: Any, temp_table: str, table: str) -> None:
    """Give an in-memory copy of a partition every column the schema declares.

    Parquet files are immutable and carry the schema they were written with.
    `union_by_name` reconciles columns *across* files; it cannot invent one
    that no file has, so a column added after a partition was written is
    absent from all of them and any query naming it fails with a binder error
    pointing at the column rather than at the cause.

    Adding a column is not exotic — `superseded_by` arrived with spec 05 §5a —
    and the correct value for a row written before the column existed is NULL.
    Partitions are therefore upgraded lazily, as they are rewritten, rather
    than by a migration that touches every file in the lake at once.
    """
    present = {str(row[0]) for row in con.execute(f"DESCRIBE {temp_table}").fetchall()}
    for name, sql_type in TABLES[table]:
        if name not in present:
            con.execute(f"ALTER TABLE {temp_table} ADD COLUMN {name} {sql_type}")
