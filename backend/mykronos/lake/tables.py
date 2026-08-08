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

from typing import Final

Column = tuple[str, str]

FINDINGS_COLUMNS: Final[list[Column]] = [
    ("finding_id", "VARCHAR"),
    ("scan_run_id", "VARCHAR"),
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
    ("status", "VARCHAR"),
    ("first_seen_scan_run_id", "VARCHAR"),
    ("last_seen_scan_run_id", "VARCHAR"),
    ("first_seen_at", "TIMESTAMP"),
    ("last_seen_at", "TIMESTAMP"),
    ("resolved_at", "TIMESTAMP"),
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
]

TABLES: Final[dict[str, list[Column]]] = {
    "findings": FINDINGS_COLUMNS,
    "scan_runs": SCAN_RUNS_COLUMNS,
    "risk_decisions": RISK_DECISIONS_COLUMNS,
}

#: Primary key per table — the column compaction upserts on.
PRIMARY_KEY: Final[dict[str, str]] = {
    "findings": "finding_id",
    "scan_runs": "scan_run_id",
    "risk_decisions": "decision_id",
}

#: Timestamp whose date determines a row's Hive partition. A row stays in the
#: partition it was first written to, so updates rewrite one known partition
#: rather than migrating rows between them.
PARTITION_SOURCE: Final[dict[str, str]] = {
    "findings": "first_seen_at",
    "scan_runs": "started_at",
    "risk_decisions": "evaluated_at",
}

#: Timestamp that orders two writes of the same key within one compaction
#: batch. Stamped by the API at request time, so it is a real logical ordering
#: rather than a dependence on file scan order.
MUTATION_TS: Final[dict[str, str]] = {
    "findings": "last_seen_at",
    "scan_runs": "ingested_at",
    "risk_decisions": "evaluated_at",
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
