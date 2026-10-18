"""One scan run, reported on its own (TheHub #60761).

`scan-health` and `/scan-runs/trend` answer whether a lane is working, in
aggregate. Neither answers "what did run X find, and what did the tool
actually say" — triaging a finding that "the scanner never reported" meant
reading the raw archive on disk inside the container. This module is the
read side of that question: one run's metadata, what it changed against the
previous run on its lane, and the raw files ingest archived for it.

**A lane is a repository, a capability, a branch and a tool** — the same lane
`lake/reconcile.py` closes findings on (B-056). The previous run is the one
before this on that lane, so a `develop` scan is never compared with a `main`
scan, nor ShellCheck with CodeQL.

**What the finding columns can and cannot say.** A finding stores the run that
first saw it and the run that last saw it, not every run in between. So:

- `new` (first seen in this run) is exact, always.
- `still_reported` (last seen in this run, first seen earlier) and
  `not_reported` (last seen in the previous run, so this run did not report
  it) are exact only while no later run has seen those findings again. For
  the newest run on a lane that holds; for an older run they are lower bounds,
  and `exact` says which you are reading.

`not_reported` is not "resolved": spec 05 §5 closes a finding only after two
consecutive confirming scans miss it, so `closed` counts the ones that have
since been closed as fixed. A run that did not complete (`failure`,
`partial_failure`) is not evidence of absence, and `observed` is false for it.
"""

from __future__ import annotations

from contextlib import suppress
from pathlib import Path
from typing import Any

from mykronos.lake.catalog import Catalog
from mykronos.lake.reconcile import CONFIRMING_STATUSES
from mykronos.schemas import Severity

#: Highest first, the order every severity breakdown on the platform reads in.
SEVERITIES: tuple[str, ...] = tuple(s.value for s in reversed(Severity))

_RUN_COLUMNS = (
    "scan_run_id",
    "repo_full_name",
    "capability",
    "tool_name",
    "tool_version",
    "commit_sha",
    "branch",
    "pr_number",
    "triggered_by",
    "github_workflow_run_id",
    "started_at",
    "completed_at",
    "scan_status",
    "finding_count",
    "raw_output_ref",
    "detail",
    "line_coverage",
    "branch_coverage",
    "job",
)

#: The lane's ordering, with the same tie-breaks `_recent_scan_runs` uses so
#: "previous" never flips between two identical calls.
_LANE_ORDER = (
    "coalesce(completed_at, started_at) {d}, ingested_at {d}, scan_run_id {d}"
)


def _bucket(rows: list[tuple[Any, ...]]) -> dict[str, Any]:
    by_severity = dict.fromkeys(SEVERITIES, 0)
    for severity, count in rows:
        key = str(severity) if severity in by_severity else "info"
        by_severity[key] += int(count)
    return {"total": sum(by_severity.values()), "by_severity": by_severity}


class ScanRunReport:
    """Reads one run, and the runs of one lane, from the lake."""

    def __init__(self, catalog: Catalog, raw_dir: Path, datalake_dir: Path) -> None:
        self.catalog = catalog
        self.raw_dir = raw_dir
        self.datalake_dir = datalake_dir

    # -- the run ---------------------------------------------------------

    def _row(self, scan_run_id: str) -> dict[str, Any] | None:
        rows = self.catalog.query(
            f"SELECT {', '.join(_RUN_COLUMNS)} FROM scan_runs WHERE scan_run_id = ? "
            f"ORDER BY {_LANE_ORDER.format(d='DESC')} LIMIT 1",
            [scan_run_id],
        )
        return dict(zip(_RUN_COLUMNS, rows[0], strict=True)) if rows else None

    def exists(self, scan_run_id: str) -> bool:
        return self._row(scan_run_id) is not None

    def _lane_neighbours(self, run: dict[str, Any]) -> tuple[str | None, str | None]:
        """The run before this one on its lane, and the one after it."""
        rows = self.catalog.query(
            f"""
            SELECT scan_run_id FROM scan_runs
            WHERE repo_full_name = ? AND capability = ?
              AND coalesce(branch, '') = ? AND coalesce(tool_name, '') = ?
            ORDER BY {_LANE_ORDER.format(d='ASC')}
            """,
            [
                run["repo_full_name"],
                run["capability"],
                run["branch"] or "",
                run["tool_name"] or "",
            ],
        )
        # De-duplicated in order: a run re-POSTed at completion can be read
        # from the buffer and a partition at once until compaction folds it.
        ids = list(dict.fromkeys(str(r[0]) for r in rows))
        if run["scan_run_id"] not in ids:
            return None, None
        at = ids.index(run["scan_run_id"])
        previous = ids[at - 1] if at > 0 else None
        following = ids[at + 1] if at + 1 < len(ids) else None
        return previous, following

    def _counts(self, where: str, params: list[Any]) -> dict[str, Any]:
        rows = self.catalog.query(
            f"SELECT severity, count(*) FROM findings WHERE {where} GROUP BY severity",
            params,
        )
        return _bucket(rows)

    def report(self, scan_run_id: str) -> dict[str, Any] | None:
        run = self._row(scan_run_id)
        if run is None:
            return None
        previous, following = self._lane_neighbours(run)
        observed = str(run["scan_status"]) in CONFIRMING_STATUSES

        new = self._counts("first_seen_scan_run_id = ?", [scan_run_id])
        still = self._counts(
            "last_seen_scan_run_id = ? AND coalesce(first_seen_scan_run_id, '') <> ?",
            [scan_run_id, scan_run_id],
        )
        if previous is not None:
            not_reported = self._counts("last_seen_scan_run_id = ?", [previous])
            closed_rows = self.catalog.query(
                "SELECT count(*) FROM findings "
                "WHERE last_seen_scan_run_id = ? AND status = 'fixed'",
                [previous],
            )
            not_reported["closed"] = int(closed_rows[0][0]) if closed_rows else 0
        else:
            not_reported = None

        return {
            **run,
            "lane": {
                "repo_full_name": run["repo_full_name"],
                "capability": run["capability"],
                "branch": run["branch"],
                "tool_name": run["tool_name"],
            },
            "previous_scan_run_id": previous,
            "next_scan_run_id": following,
            #: True for the newest run on its lane, where every count is exact.
            "exact": following is None,
            #: False when the run did not complete: its silence is not evidence.
            "observed": observed,
            "changes": {
                "new": new,
                "still_reported": still,
                "not_reported": not_reported if observed else None,
            },
            "raw_files": self.raw_files(run),
        }

    # -- the lane --------------------------------------------------------

    def lane_runs(
        self, repo_full_name: str, capability: str | None = None, limit: int = 50
    ) -> list[dict[str, Any]]:
        """Recent runs of a repository, newest first — the list that makes a
        run id discoverable without reading the lake."""
        columns = (
            "scan_run_id",
            "capability",
            "tool_name",
            "branch",
            "commit_sha",
            "started_at",
            "completed_at",
            "scan_status",
            "finding_count",
            "detail",
        )
        params: list[Any] = [repo_full_name]
        where = "repo_full_name = ?"
        if capability:
            where += " AND capability = ?"
            params.append(capability)
        rows = self.catalog.query(
            f"SELECT {', '.join(columns)} FROM scan_runs WHERE {where} "
            f"ORDER BY {_LANE_ORDER.format(d='DESC')} LIMIT ?",
            [*params, limit],
        )
        return [dict(zip(columns, row, strict=True)) for row in rows]

    # -- raw output ------------------------------------------------------

    def _run_dir(self, run: dict[str, Any]) -> Path:
        # Mirrors `ingest_raw_output`'s layout, segment cleaning included, so
        # the directory read here is the one ingest wrote.
        from mykronos.api.ingest import _safe_segment

        owner, _, name = str(run["repo_full_name"]).partition("/")
        return (
            self.raw_dir
            / _safe_segment(owner)
            / _safe_segment(name)
            / _safe_segment(str(run["scan_run_id"]))
        )

    def _raw_paths(self, run: dict[str, Any]) -> dict[str, Path]:
        """Every archived file for this run, by its file name.

        The run's own directory, plus `raw_output_ref` where it names a file
        elsewhere in the lake. Only paths that resolve inside the lake are
        returned, so serving by name can never name anything else.
        """
        lake = self.datalake_dir.resolve()
        found: dict[str, Path] = {}
        directory = self._run_dir(run)
        if directory.is_dir():
            for path in sorted(directory.iterdir()):
                if path.is_file():
                    found[path.name] = path
        ref = run.get("raw_output_ref")
        if ref:
            with suppress(OSError):
                path = (self.datalake_dir / str(ref)).resolve()
                if lake in path.parents and path.is_file():
                    found.setdefault(path.name, path)
        return {
            name: path
            for name, path in found.items()
            if lake in path.resolve().parents
        }

    def raw_files(self, run: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            {"filename": name, "bytes": path.stat().st_size}
            for name, path in self._raw_paths(run).items()
        ]

    def raw_file(self, scan_run_id: str, filename: str) -> Path | None:
        run = self._row(scan_run_id)
        if run is None:
            return None
        return self._raw_paths(run).get(filename)
