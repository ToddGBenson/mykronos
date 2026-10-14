"""Findings, exported: CSV, SARIF 2.1.0 and a printable HTML report (TheHub #60762).

Findings were visible only as JSON and in the dashboard, so handing a
repository's state to someone outside Mykronos (an auditor, a ticketing
system, GitHub code scanning) meant scraping. These are the three shapes
those readers take, behind the filters the findings list already has.

**No raw tool output, for anyone.** `code_snippet` and `raw_finding_json` can
quote a secret (spec 12 §5). An export leaves the platform by design, into
places whose access control Mykronos cannot see, so it carries the normalised
finding only, whatever the caller's role. The archived output is one call
away for those allowed it (`/api/dashboard/scan-runs/{id}/raw/{filename}`).

**A disposition travels with its reason.** A finding someone closed as a
false positive, suppressed or accepted is still exported, and SARIF marks it
as a suppression whose justification is the reason recorded with the
decision (the latest `finding.status` audit entry), or the acceptance's reason
code where that is all there is. A suppression with no reason would read as
the platform hiding something.
"""

from __future__ import annotations

import csv
import html
import io
import json
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from mykronos.db.models import AuditLogEntry
from mykronos.lake.catalog import Catalog

#: The most rows one export returns. Past it the export says it is partial
#: (`truncated`, and a line in each format) rather than silently stopping.
EXPORT_LIMIT = 20_000

SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")

#: Statuses SARIF reports as a suppressed result: a person decided them.
DISPOSITIONED = ("false_positive", "suppressed", "accepted_risk")

#: The CSV's columns, in order. Stable: a spreadsheet or ticket import keyed
#: on a header must not break because a column moved. Add at the end.
CSV_COLUMNS: tuple[str, ...] = (
    "finding_id",
    "repo_full_name",
    "capability",
    "tool",
    "rule_id",
    "title",
    "severity",
    "status",
    "cvss_score",
    "cwe_ids",
    "file_path",
    "line_start",
    "line_end",
    "symbol",
    "package_name",
    "package_version",
    "owner",
    "due_at",
    "first_seen_at",
    "last_seen_at",
    "resolved_at",
    "accepted_reason_code",
    "accepted_until",
    "disposition_reason",
    "disposition_by",
    "superseded_by",
)

_SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/"
    "sarif-schema-2.1.0.json"
)
_LEVEL = {"critical": "error", "high": "error", "medium": "warning"}


@dataclass
class Export:
    repo_full_name: str
    generated_at: datetime
    filters: dict[str, Any]
    rows: list[dict[str, Any]]
    total: int
    #: The newest scan of this repository: what the export describes.
    commit_sha: str | None = None
    branch: str | None = None
    #: Open findings by severity across the whole repository, unfiltered.
    open_by_severity: dict[str, int] = field(default_factory=dict)

    @property
    def truncated(self) -> bool:
        return self.total > len(self.rows)


# -- collecting --------------------------------------------------------------


def _chunks(items: list[str], size: int = 500) -> list[list[str]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


def _extras(catalog: Catalog, ids: list[str]) -> dict[str, dict[str, Any]]:
    """What the findings list does not select: the tool that last saw each
    finding, its CWEs, owner, due date and acceptance terms."""
    found: dict[str, dict[str, Any]] = {}
    for chunk in _chunks(ids):
        marks = ", ".join("?" for _ in chunk)
        for row in catalog.query(
            f"""
            SELECT f.finding_id, s.tool_name, s.tool_version, f.cwe_ids_json,
                   f.owner, f.due_at, f.accepted_reason_code, f.accepted_until
            FROM findings f
            LEFT JOIN scan_runs s ON s.scan_run_id = f.last_seen_scan_run_id
            WHERE f.finding_id IN ({marks})
            """,
            chunk,
        ):
            cwes: list[str] = []
            with suppress(TypeError, json.JSONDecodeError):
                parsed = json.loads(row[3]) if row[3] else []
                cwes = [str(c) for c in parsed] if isinstance(parsed, list) else []
            found.setdefault(
                str(row[0]),
                {
                    "tool": row[1],
                    "tool_version": row[2],
                    "cwe_ids": cwes,
                    "owner": row[4],
                    "due_at": row[5],
                    "accepted_reason_code": row[6],
                    "accepted_until": row[7],
                },
            )
    return found


def _dispositions(session: Session, ids: list[str]) -> dict[str, dict[str, Any]]:
    """The latest recorded status change for each finding, with its reason."""
    latest: dict[str, dict[str, Any]] = {}
    for chunk in _chunks(ids):
        entries = session.scalars(
            select(AuditLogEntry)
            .where(AuditLogEntry.action == "finding.status")
            .where(AuditLogEntry.entity_id.in_(chunk))
            .order_by(AuditLogEntry.created_at)
        )
        for entry in entries:
            detail = entry.detail or {}
            latest[entry.entity_id] = {
                "status": detail.get("new_status"),
                "reason": str(detail.get("reason") or ""),
                "by": entry.actor,
                "at": entry.created_at,
            }
    return latest


def _newest_scan(catalog: Catalog, repo_full_name: str) -> tuple[str | None, str | None]:
    rows = catalog.query(
        """
        SELECT commit_sha, branch FROM scan_runs WHERE repo_full_name = ?
        ORDER BY coalesce(completed_at, started_at) DESC, ingested_at DESC LIMIT 1
        """,
        [repo_full_name],
    )
    return (rows[0][0], rows[0][1]) if rows else (None, None)


def _open_by_severity(catalog: Catalog, repo_full_name: str) -> dict[str, int]:
    counts = dict.fromkeys(SEVERITIES, 0)
    for severity, count in catalog.query(
        "SELECT severity, count(*) FROM findings WHERE asset_id = ? AND status = 'open' "
        "GROUP BY severity",
        [repo_full_name],
    ):
        counts[str(severity) if severity in counts else "info"] += int(count)
    return counts


def collect(
    rows: list[dict[str, Any]],
    total: int,
    *,
    catalog: Catalog,
    session: Session,
    repo_full_name: str,
    filters: dict[str, Any],
    generated_at: datetime,
) -> Export:
    """Join the findings list's rows with what an export needs besides.

    `rows` come from `DashboardQueries.findings(..., include_raw=False)`, so
    the filters mean exactly what they mean on the list.
    """
    ids = [str(r["finding_id"]) for r in rows]
    extras = _extras(catalog, ids)
    decided = _dispositions(session, ids)
    merged = []
    for row in rows:
        record = {k: v for k, v in row.items() if k not in ("code_snippet", "raw_finding_json")}
        record["repo_full_name"] = repo_full_name
        record.update(extras.get(str(row["finding_id"]), {}))
        decision = decided.get(str(row["finding_id"]))
        # Only a decision that matches the current status explains it: a
        # false positive later reopened carries no justification.
        if decision and decision["status"] == record.get("status"):
            record["disposition_reason"] = decision["reason"]
            record["disposition_by"] = decision["by"]
        merged.append(record)
    commit, branch = _newest_scan(catalog, repo_full_name)
    return Export(
        repo_full_name=repo_full_name,
        generated_at=generated_at,
        filters={k: v for k, v in filters.items() if v is not None},
        rows=merged,
        total=total,
        commit_sha=commit,
        branch=branch,
        open_by_severity=_open_by_severity(catalog, repo_full_name),
    )


# -- CSV ---------------------------------------------------------------------


def _cell(value: Any) -> str:
    """One CSV cell, safe to open in a spreadsheet.

    A scanner writes the title, and a title starting `=`, `+`, `-` or `@` is a
    formula to Excel and LibreOffice (CSV injection). A leading apostrophe
    makes it text and is how both expect it escaped.
    """
    if value is None:
        return ""
    if isinstance(value, list):
        value = ";".join(str(v) for v in value)
    if isinstance(value, datetime):
        value = value.isoformat()
    text = str(value)
    if text[:1] in ("=", "+", "-", "@", "\t", "\r"):
        text = "'" + text
    return text


def to_csv(export: Export) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\r\n")
    writer.writerow(CSV_COLUMNS)
    for row in export.rows:
        writer.writerow([_cell(row.get(column)) for column in CSV_COLUMNS])
    return buffer.getvalue()


# -- SARIF -------------------------------------------------------------------


def _justification(row: dict[str, Any]) -> str:
    reason = str(row.get("disposition_reason") or "").strip()
    if reason:
        return reason
    if row.get("status") == "accepted_risk" and row.get("accepted_reason_code"):
        until = row.get("accepted_until")
        return f"Accepted risk: {row['accepted_reason_code']}" + (
            f", until {until}" if until else ""
        )
    return f"Marked {row.get('status')} in Mykronos; no reason was recorded."


def _result(row: dict[str, Any]) -> dict[str, Any]:
    status = str(row.get("status") or "")
    result: dict[str, Any] = {
        "ruleId": str(row.get("rule_id") or "unknown"),
        "level": _LEVEL.get(str(row.get("severity")), "note"),
        "message": {"text": str(row.get("title") or row.get("rule_id") or "")},
        # Closed and withdrawn findings are reported, not dropped: a reader
        # filtering on `kind` sees what was fixed, and nothing is lost by
        # filtering the export to `finding_status=open` first.
        "kind": {"fixed": "pass", "superseded": "informational"}.get(status, "fail"),
        "partialFingerprints": {"mykronosFindingId/v1": str(row["finding_id"])},
        "properties": {
            "severity": row.get("severity"),
            "status": status,
            "capability": row.get("capability"),
            **({"cvss": row["cvss_score"]} if row.get("cvss_score") is not None else {}),
        },
    }
    if row.get("file_path"):
        region: dict[str, int] = {}
        if (row.get("line_start") or 0) >= 1:
            region["startLine"] = int(row["line_start"])
            if (row.get("line_end") or 0) >= region["startLine"]:
                region["endLine"] = int(row["line_end"])
        physical: dict[str, Any] = {"artifactLocation": {"uri": str(row["file_path"])}}
        if region:
            physical["region"] = region
        result["locations"] = [{"physicalLocation": physical}]
    elif row.get("package_name"):
        name = str(row["package_name"])
        if row.get("package_version"):
            name += f"@{row['package_version']}"
        result["locations"] = [
            {"logicalLocations": [{"name": name, "kind": "module"}]}
        ]
    if status in DISPOSITIONED:
        result["suppressions"] = [
            {"kind": "external", "status": "accepted", "justification": _justification(row)}
        ]
    return result


def to_sarif(export: Export) -> dict[str, Any]:
    """One run per tool (spec: SARIF 2.1.0 §3.14), rules from the findings."""
    by_tool: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in export.rows:
        key = (str(row.get("tool") or "mykronos"), str(row.get("tool_version") or ""))
        by_tool.setdefault(key, []).append(row)

    runs = []
    for (tool, version), rows in sorted(by_tool.items()):
        rules: dict[str, dict[str, Any]] = {}
        for row in rows:
            rule_id = str(row.get("rule_id") or "unknown")
            if rule_id not in rules:
                rule: dict[str, Any] = {
                    "id": rule_id,
                    "shortDescription": {"text": str(row.get("title") or rule_id)},
                }
                if row.get("cwe_ids"):
                    rule["properties"] = {"tags": list(row["cwe_ids"])}
                rules[rule_id] = rule
        driver: dict[str, Any] = {"name": tool, "rules": list(rules.values())}
        if version:
            driver["version"] = version
        run: dict[str, Any] = {
            "tool": {"driver": driver},
            "results": [_result(row) for row in rows],
            "properties": {
                "exportedBy": "mykronos",
                "generatedAt": export.generated_at.isoformat(),
                "filters": {k: str(v) for k, v in export.filters.items()},
                "truncated": export.truncated,
            },
        }
        if export.commit_sha:
            provenance: dict[str, Any] = {
                "repositoryUri": f"https://github.com/{export.repo_full_name}",
                "revisionId": export.commit_sha,
            }
            if export.branch:
                provenance["branch"] = export.branch
            run["versionControlProvenance"] = [provenance]
        runs.append(run)
    return {"$schema": _SARIF_SCHEMA, "version": "2.1.0", "runs": runs}


# -- HTML --------------------------------------------------------------------

_CSS = """
body{font:13px/1.45 system-ui,sans-serif;color:#111;background:#fff;margin:24px}
h1{font-size:20px;margin:0 0 4px}h2{font-size:15px;margin:20px 0 6px}
.meta{color:#555;font-family:ui-monospace,monospace;font-size:12px}
table{border-collapse:collapse;width:100%}th,td{border-bottom:1px solid #ddd;
padding:4px 6px;text-align:left;vertical-align:top}th{background:#f4f4f4}
.sum td,.sum th{text-align:center}.critical{color:#a00;font-weight:700}
.high{color:#b45309;font-weight:700}.warn{border-left:3px solid #b45309;
padding:4px 8px;background:#fff7ed}td.loc{font-family:ui-monospace,monospace;
font-size:11px;word-break:break-all}
@media print{body{margin:0}tr{break-inside:avoid}}
"""


def to_html(export: Export) -> str:
    e = html.escape
    filters = ", ".join(f"{k}={v}" for k, v in export.filters.items()) or "none"
    summary = "".join(
        f"<td class='{s}'>{export.open_by_severity.get(s, 0)}</td>" for s in SEVERITIES
    )
    head = "".join(f"<th>{s}</th>" for s in SEVERITIES)
    body_rows = []
    for row in export.rows:
        where = row.get("file_path") or row.get("package_name") or ""
        if row.get("file_path") and row.get("line_start"):
            where = f"{where}:{row['line_start']}"
        elif row.get("package_name") and row.get("package_version"):
            where = f"{where} {row['package_version']}"
        decided = ""
        if row.get("status") in DISPOSITIONED:
            decided = f"<br><small>{e(_justification(row))}</small>"
        severity = e(str(row.get("severity") or ""))
        body_rows.append(
            "<tr>"
            f"<td class='{severity}'>{severity}</td>"
            f"<td>{e(str(row.get('status') or ''))}{decided}</td>"
            f"<td>{e(str(row.get('capability') or ''))}</td>"
            f"<td>{e(str(row.get('rule_id') or ''))}</td>"
            f"<td>{e(str(row.get('title') or ''))}</td>"
            f"<td class='loc'>{e(str(where))}</td>"
            f"<td>{e(str(row.get('first_seen_at') or '')[:10])}</td>"
            "</tr>"
        )
    truncated = (
        f"<p class='warn'>Partial: {len(export.rows)} of {export.total} findings. "
        "Narrow the filters to export the rest.</p>"
        if export.truncated
        else ""
    )
    commit = (
        f"{e(export.commit_sha)}" + (f" on {e(export.branch)}" if export.branch else "")
        if export.commit_sha
        else "no scan recorded"
    )
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        f"<title>Findings: {e(export.repo_full_name)}</title><style>{_CSS}</style></head>"
        f"<body><h1>Findings: {e(export.repo_full_name)}</h1>"
        f"<div class='meta'>Generated {e(export.generated_at.isoformat(timespec='seconds'))} UTC"
        f" · latest scanned commit {commit} · filters: {e(filters)}</div>"
        "<h2>Open findings by severity (whole repository)</h2>"
        f"<table class='sum'><tr>{head}</tr><tr>{summary}</tr></table>"
        f"<h2>{len(export.rows)} finding(s) matching the filters</h2>{truncated}"
        "<table><tr><th>Severity</th><th>Status</th><th>Capability</th><th>Rule</th>"
        "<th>Title</th><th>Where</th><th>First seen</th></tr>"
        f"{''.join(body_rows)}</table>"
        "<p class='meta'>Normalised findings only: raw tool output is never exported.</p>"
        "</body></html>"
    )
