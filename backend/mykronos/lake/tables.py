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
    # What the reporting tool said this is, taxonomically (spec 28 §1). JSON
    # array of `CWE-89`-shaped strings. Spec 18 §6 explained the Threat Model
    # tab's capability-level mapping by saying no finding carries a structured
    # CWE — true of this schema until now, and never true of the SARIF at the
    # door, which `adapters/sarif.py` was reading one property from and
    # discarding the rest of.
    ("cwe_ids_json", "VARCHAR"),
    ("owner", "VARCHAR"),
    ("owner_source", "VARCHAR"),
    # When this is due, and who set that date (spec 24 §2). Absent from the
    # compaction update set on purpose: like first_seen_at, a due date is
    # fixed at first sight, so re-running a scanner does not hand a
    # sixty-day-old finding a fresh thirty days. `due_source` is
    # kev | policy | manual.
    ("due_at", "TIMESTAMP"),
    ("due_source", "VARCHAR"),
    # An acceptance with a review date, and the premise it rests on
    # (spec 24 §3). Written only by the disposition endpoint, never by
    # ingest, and absent from the compaction update set so a re-scan cannot
    # clear them. `accepted_reason_code` is what makes an acceptance
    # revisitable by a machine: "no vendor fix" as prose is a sentence, and
    # as a code it is a claim a later scan can contradict.
    ("accepted_until", "DATE"),
    ("accepted_reason_code", "VARCHAR"),
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
    # Coverage where the runner reported it, 0..1 (spec 31 §4). NULL means the
    # report did not carry it, which is not the same fact as 0.0 — the runner
    # measured and found none. Explicitly not a security metric: it is context
    # that stops a green pass rate being read as more than it is.
    ("line_coverage", "DOUBLE"),
    ("branch_coverage", "DOUBLE"),
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
    # Which fixer produced this (spec 25 §3.1). Held in memory since spec 08
    # and never stored, so "does this fixer work" could not be asked. It is
    # the name only — the generated file content stays out of the lake, which
    # is what `StageOutcome.fix_files`'s comment is actually about.
    ("fixer_name", "VARCHAR"),
    # Why somebody closed this fix without merging it (spec 25 §3.3).
    # `fix_was_wrong` stops this fixer offering the same change for the same
    # rule here; `fix_was_unwanted` dampens nothing at all, because a correct
    # fix nobody wanted is a scheduling disagreement rather than a defect.
    # `unstated` is recorded as itself rather than guessed at.
    ("rejection_reason_code", "VARCHAR"),
    ("rejection_reason", "VARCHAR"),
    # Did the fix work? (spec 25 §1, §2). Written across three moments by
    # three different writers — the webhook records the merge commit, the
    # verification job records the dispatch, and the resolver records the
    # verdict — so every one of them coalesces rather than overwrites.
    #
    # `verification_outcome` is pending | verified_fixed | still_open |
    # not_scanned | inconclusive. `inconclusive` is a real answer and is
    # reported as one: folding a failed verifying scan into `still_open`
    # would slander a fix that may well have worked, and folding it into
    # `verified_fixed` would flatter one that may not have.
    ("verification_commit_sha", "VARCHAR"),
    ("verification_dispatched_at", "TIMESTAMP"),
    ("verification_scan_run_id", "VARCHAR"),
    ("verification_outcome", "VARCHAR"),
    ("verified_at", "TIMESTAMP"),
    ("time_to_verified_seconds", "INTEGER"),
    ("created_at", "TIMESTAMP"),
    ("updated_at", "TIMESTAMP"),
]

#: A test that exists because of a finding (spec 31 §1).
#:
#: The one link in this platform that points from a vulnerability to the thing
#: that would notice it coming back. Everything else records what was found;
#: this records what was learned.
FINDING_TESTS_COLUMNS: Final[list[Column]] = [
    ("link_id", "VARCHAR"),
    ("finding_id", "VARCHAR"),
    ("repo_full_name", "VARCHAR"),
    #: The JUnit `classname.name`, as the runner reports it.
    ("test_identifier", "VARCHAR"),
    #: unit | functional | qa — which lane runs it.
    ("capability", "VARCHAR"),
    #: `asserted` = somebody said this test covers that finding.
    #: `demonstrated` = the platform watched it fail against the vulnerable
    #: code and pass against the fixed code. Both are useful; they are not the
    #: same claim and are never displayed as one.
    ("evidence", "VARCHAR"),
    ("linked_by", "VARCHAR"),
    ("linked_at", "TIMESTAMP"),
    #: When the lane that runs this test last completed successfully. Not
    #: per-test: the JUnit adapter records suite totals, not case names
    #: (D-046), so this catches "the suite stopped running" and cannot catch
    #: "this one test was deleted". Said here because a coverage number that
    #: only ever goes up is the failure mode this column exists to limit.
    ("lane_last_green_at", "TIMESTAMP"),
    ("updated_at", "TIMESTAMP"),
]

#: What a repository actually resolved to (spec 29 §1).
#:
#: The SBOM has been generated on every Atlas run since spec 07 and only ever
#: archived: downloadable per repository, queryable across none of them. So the
#: platform could not answer the one question that matters at 2am — *which of
#: our repositories contain this package* — about data it had already
#: collected and was storing as an opaque blob.
#:
#: A third read of a file the runner has already produced, not a new scan.
#:
#: **Rewritten per scan, keyed on content.** `component_id` hashes repo,
#: ecosystem, name and version, so a dependency that has not changed keeps its
#: row and its `first_seen_at`, and one that has gone stops being refreshed.
#: That makes "when did this repository first take this version" answerable
#: without a second table.
SBOM_COMPONENTS_COLUMNS: Final[list[Column]] = [
    ("component_id", "VARCHAR"),
    ("repo_full_name", "VARCHAR"),
    #: Provenance of the row itself: which scan of which commit saw it. An
    #: inventory that cannot say when it was taken is one nobody can trust
    #: under time pressure, which is the only time it gets read.
    ("commit_sha", "VARCHAR"),
    ("scan_run_id", "VARCHAR"),
    ("ecosystem", "VARCHAR"),
    ("package_name", "VARCHAR"),
    ("package_version", "VARCHAR"),
    #: NULL where the SBOM does not distinguish, which is most of them. Not
    #: `false`: "Syft did not say" and "this is transitive" are different
    #: facts and the second is a claim this platform cannot make.
    ("direct", "BOOLEAN"),
    #: `pkg:npm/lodash@4.17.21`. The join key that survives naming
    #: differences between ecosystems, and empty where Syft emitted none.
    ("purl", "VARCHAR"),
    #: Already computed by spec 22 §1 and aggregated away into counts. Kept
    #: per component here, because "which repository has the GPL one" is a
    #: question the aggregate cannot answer.
    ("license_ids_json", "VARCHAR"),
    ("first_seen_at", "TIMESTAMP"),
    ("observed_at", "TIMESTAMP"),
]

TABLES: Final[dict[str, list[Column]]] = {
    "findings": FINDINGS_COLUMNS,
    "scan_runs": SCAN_RUNS_COLUMNS,
    "risk_decisions": RISK_DECISIONS_COLUMNS,
    "insider_risk_signals": INSIDER_RISK_SIGNALS_COLUMNS,
    "sscs_evidence": SSCS_EVIDENCE_COLUMNS,
    "remediation_events": REMEDIATION_EVENTS_COLUMNS,
    "finding_tests": FINDING_TESTS_COLUMNS,
    "sbom_components": SBOM_COMPONENTS_COLUMNS,
}

#: Primary key per table — the column compaction upserts on.
PRIMARY_KEY: Final[dict[str, str]] = {
    "findings": "finding_id",
    "scan_runs": "scan_run_id",
    "risk_decisions": "decision_id",
    "insider_risk_signals": "signal_id",
    "sscs_evidence": "evidence_id",
    "remediation_events": "event_id",
    "finding_tests": "link_id",
    "sbom_components": "component_id",
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
    "finding_tests": "linked_at",
    # `first_seen_at`, so a component that has been present for a year stays
    # in the partition it arrived in and a rescan rewrites one known
    # partition rather than migrating thousands of rows every week.
    "sbom_components": "first_seen_at",
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
    "finding_tests": "updated_at",
    "sbom_components": "observed_at",
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
    "finding_tests": ("lane_last_green_at", "evidence"),
    # Nothing. Every component row is written whole by one SBOM read, so
    # there is no partial writer to coalesce against.
    "sbom_components": (),
    "remediation_events": (
        "pr_status",
        "fix_pr_number",
        "fix_pr_url",
        # Spec 25 §2 — see the compaction update set for why each of these
        # coalesces. Declared here too so a dispatch and a verdict landing in
        # one five-minute compaction window do not cost the earlier one.
        "fixer_name",
        "rejection_reason_code",
        "rejection_reason",
        "verification_commit_sha",
        "verification_dispatched_at",
        "verification_scan_run_id",
        "verification_outcome",
        "verified_at",
        "time_to_verified_seconds",
    ),
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
