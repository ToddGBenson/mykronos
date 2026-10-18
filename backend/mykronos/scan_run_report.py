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

import re
from contextlib import suppress
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from defusedxml import ElementTree as SafeElementTree
from defusedxml.common import DefusedXmlException

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


#: The columns a row of a check's run history carries (TheHub #60819): enough
#: to tell the runs apart and pick one without opening each.
_LIST_COLUMNS = (
    "scan_run_id",
    "capability",
    "tool_name",
    "tool_version",
    "job",
    "branch",
    "commit_sha",
    "pr_number",
    "triggered_by",
    "github_workflow_run_id",
    "started_at",
    "completed_at",
    "scan_status",
    "finding_count",
    "detail",
    "line_coverage",
    "branch_coverage",
)

#: How many of a run's findings the report lists by name. The counts are
#: always whole; past this the list says it was cut, and the findings page has
#: the rest.
FINDINGS_SHOWN = 500

#: The largest archived XML file read for test results. The archive holds up
#: to `max_raw_output_bytes`; parsing that on every page view is not worth a
#: test summary, and the raw file stays one click away.
JUNIT_MAX_BYTES = 5 * 1024 * 1024
JUNIT_CASES_SHOWN = 200
_MESSAGE_CHARS = 500
_OUTPUT_CHARS = 4000

_SHA = re.compile(r"[0-9a-fA-F]{7,64}")


def commit_url(repo_full_name: str, commit_sha: Any) -> str | None:
    """The commit on GitHub, the same host the portfolio's `github_url` names.

    Only for something shaped like a SHA: a lane that recorded `HEAD` or a tag
    gets no link rather than a link to a 404.
    """
    if not commit_sha or not _SHA.fullmatch(str(commit_sha)):
        return None
    return f"https://github.com/{repo_full_name}/commit/{commit_sha}"


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

    def report(
        self, scan_run_id: str, *, include_output: bool = False
    ) -> dict[str, Any] | None:
        """The whole run. `include_output` adds test failure bodies, which are
        the tool's own output and are withheld from viewers as the raw files
        are (spec 12 §5); the case names and counts are not."""
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
            "commit_url": commit_url(str(run["repo_full_name"]), run["commit_sha"]),
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
            "findings": self._findings(scan_run_id),
            "tests": self.junit_results(run, include_output=include_output),
        }

    def _findings(self, scan_run_id: str) -> dict[str, Any]:
        """The findings this run first or last saw, worst first, by name.

        The same two sets `new` and `still_reported` count, so the list and the
        counts above it agree.
        """
        columns = (
            "finding_id",
            "rule_id",
            "title",
            "severity",
            "status",
            "file_path",
            "line_start",
            "package_name",
            "package_version",
            "first_seen_scan_run_id",
        )
        rank = " ".join(
            f"WHEN '{severity}' THEN {i}" for i, severity in enumerate(SEVERITIES)
        )
        rows = self.catalog.query(
            f"SELECT {', '.join(columns)} FROM findings "
            "WHERE first_seen_scan_run_id = ? OR last_seen_scan_run_id = ? "
            f"ORDER BY CASE severity {rank} ELSE {len(SEVERITIES)} END, "
            "rule_id, finding_id",
            [scan_run_id, scan_run_id],
        )
        seen: dict[str, dict[str, Any]] = {}
        for row in rows:
            record = dict(zip(columns, row, strict=True))
            # A finding re-written at compaction can be read twice until the
            # buffer is folded; one row per finding.
            seen.setdefault(str(record["finding_id"]), record)
        listed = [
            {
                **{k: v for k, v in record.items() if k != "first_seen_scan_run_id"},
                "new": record["first_seen_scan_run_id"] == scan_run_id,
            }
            for record in seen.values()
        ]
        return {
            "total": len(listed),
            "items": listed[:FINDINGS_SHOWN],
            "truncated": len(listed) > FINDINGS_SHOWN,
        }

    # -- the lane --------------------------------------------------------

    def lane_runs(
        self,
        repo_full_name: str,
        capability: str | None = None,
        limit: int = 50,
        *,
        tool: str | None = None,
        job: str | None = None,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Recent runs of a repository, newest first — the list that makes a
        run id discoverable without reading the lake, and a check's run
        history (TheHub #60819) when narrowed to a capability, and to a tool
        or job where a capability has several.

        One row per run: a run re-POSTed at completion can be read from the
        buffer and a partition at once until compaction folds it, and the
        history would otherwise list it twice.
        """
        params: list[Any] = [repo_full_name]
        where = "repo_full_name = ?"
        for column, value in (("capability", capability), ("tool_name", tool), ("job", job)):
            if value:
                where += f" AND {column} = ?"
                params.append(value)
        rows = self.catalog.query(
            f"""
            SELECT {', '.join(_LIST_COLUMNS)} FROM (
                SELECT *, row_number() OVER (
                    PARTITION BY scan_run_id
                    ORDER BY {_LANE_ORDER.format(d='DESC')}
                ) AS rn
                FROM scan_runs WHERE {where}
            ) WHERE rn = 1
            ORDER BY {_LANE_ORDER.format(d='DESC')}
            LIMIT ? OFFSET ?
            """,
            [*params, limit, offset],
        )
        out: list[dict[str, Any]] = []
        for row in rows:
            record = dict(zip(_LIST_COLUMNS, row, strict=True))
            record["commit_url"] = commit_url(repo_full_name, record["commit_sha"])
            out.append(record)
        return out

    def lanes(self, repo_full_name: str, capability: str) -> list[dict[str, Any]]:
        """The tools and jobs that report under one capability, most recently
        run first — what the history page offers to narrow by when a
        capability has more than one (`dast-demo` and `dast-staging`, #449)."""
        rows = self.catalog.query(
            """
            SELECT tool_name, job, count(DISTINCT scan_run_id),
                   max(coalesce(completed_at, started_at)) AS last_run_at
            FROM scan_runs WHERE repo_full_name = ? AND capability = ?
            GROUP BY tool_name, job
            ORDER BY last_run_at DESC NULLS LAST, tool_name, job
            """,
            [repo_full_name, capability],
        )
        return [
            {"tool_name": tool, "job": job, "runs": int(runs), "last_run_at": last}
            for tool, job, runs, last in rows
        ]

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

    # -- test results ----------------------------------------------------

    def junit_results(
        self, run: dict[str, Any], *, include_output: bool = False
    ) -> dict[str, Any] | None:
        """The JUnit reports archived for a run, read case by case.

        A test lane records a run and a count, never a finding (D-046), so the
        run's `detail` is all the lake says about which test failed. The
        archived XML says the rest. Null when the run archived no JUnit report;
        a file that is not JUnit (SARIF, a Cobertura coverage report) is
        skipped rather than reported as broken.
        """
        suites: list[dict[str, Any]] = []
        failing: list[dict[str, Any]] = []
        unreadable: list[str] = []
        totals = dict.fromkeys(("tests", "failures", "errors", "skipped"), 0)
        for name, path in self._raw_paths(run).items():
            if not name.lower().endswith(".xml"):
                continue
            try:
                if path.stat().st_size > JUNIT_MAX_BYTES:
                    unreadable.append(name)
                    continue
                root = SafeElementTree.fromstring(path.read_bytes())
            except (OSError, ElementTree.ParseError, DefusedXmlException):
                unreadable.append(name)
                continue
            if root.tag == "testsuite":
                found = [root]
            elif root.tag == "testsuites":
                found = list(root.iter("testsuite"))
            else:
                continue
            for suite in found:
                counts = _junit_counts(suite)
                for key in totals:
                    totals[key] += counts[key]
                suites.append({"file": name, "name": suite.get("name") or None, **counts})
                for case in suite.findall("testcase"):
                    outcome = _junit_outcome(case)
                    if outcome is None:
                        continue
                    kind, element = outcome
                    entry: dict[str, Any] = {
                        "suite": suite.get("name") or None,
                        "classname": case.get("classname") or None,
                        "name": case.get("name") or "",
                        "outcome": kind,
                        "message": (element.get("message") or "")[:_MESSAGE_CHARS] or None,
                    }
                    if include_output:
                        entry["output"] = (element.text or "").strip()[:_OUTPUT_CHARS] or None
                    failing.append(entry)
        if not suites and not unreadable:
            return None
        return {
            **totals,
            "passed": max(
                0, totals["tests"] - totals["failures"] - totals["errors"] - totals["skipped"]
            ),
            "suites": suites,
            "failing": failing[:JUNIT_CASES_SHOWN],
            "failing_truncated": len(failing) > JUNIT_CASES_SHOWN,
            "output_withheld": not include_output,
            "unreadable": unreadable,
        }


def _junit_counts(suite: ElementTree.Element) -> dict[str, int]:
    """A suite's own totals, or counted from its cases when it gives none."""
    cases = suite.findall("testcase")
    counted = {
        "tests": len(cases),
        "failures": sum(1 for c in cases if c.find("failure") is not None),
        "errors": sum(1 for c in cases if c.find("error") is not None),
        "skipped": sum(1 for c in cases if c.find("skipped") is not None),
    }
    out: dict[str, int] = {}
    for key, fallback in counted.items():
        try:
            out[key] = int(suite.get(key) or fallback)
        except ValueError:
            out[key] = fallback
    return out


def _junit_outcome(case: ElementTree.Element) -> tuple[str, ElementTree.Element] | None:
    for kind in ("failure", "error"):
        element = case.find(kind)
        if element is not None:
            return kind, element
    return None
