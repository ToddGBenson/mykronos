"""Dashboard query service (spec 10 §3).

Read-only, and structurally so: every query here goes through
`Catalog.connect_readonly()`, which is an in-memory DuckDB with views over the
Parquet files. It cannot write to the lake even by mistake.

**Why the lake and the operational database are joined in Python.** Portfolio
rows come from two stores — aggregates from DuckDB, onboarding state from
SQLite — and DuckDB can attach SQLite directly. It is not worth it: the join
is a few hundred rows against a few hundred rows, and an extension dependency
for that would buy nothing while adding a way for the dashboard to fail that
has nothing to do with the dashboard.

**On materialization.** Spec 10 §3 calls for pre-computed aggregates on a
15-minute refresh, to meet §6's two-second budget for 200 repos. The live
aggregate is measured against that budget by
`tests/test_acceptance.py::test_portfolio_endpoint_stays_within_budget`, and
is comfortably inside it. Building a cache for a query that is already fast
would add a staleness window and a refresh job to maintain, in exchange for
nothing measurable. Deferred with the measurement kept as an enforced test —
see docs/DECISIONS.md D-016.
"""

from __future__ import annotations

import json
import logging
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from mykronos.db.models import RepoOnboarding
from mykronos.lake.catalog import Catalog
from mykronos.schemas import Severity

logger = logging.getLogger(__name__)

SEVERITIES = [s.value for s in Severity]

#: Beyond this, a repo's most recent scan is old enough to be worth flagging
#: (spec 10 §2.1).
STALE_AFTER_DAYS = 7


@dataclass
class CapabilityState:
    """Per-capability scan state for one repo.

    spec 10 §7: a freshly-onboarded repo must show "awaiting first scan"
    rather than "0 findings", which would read as clean.
    """

    capability: str
    has_scanned: bool
    last_scan_at: datetime | None = None
    last_scan_status: str | None = None
    open_findings: int = 0


@dataclass
class PortfolioRow:
    repo_full_name: str
    repo_id: str
    status: str
    enabled_capabilities: list[str]
    pending_capabilities: list[str] | None
    severity_counts: dict[str, int] = field(default_factory=dict)
    total_open: int = 0
    last_scan_at: datetime | None = None
    capability_states: list[CapabilityState] = field(default_factory=list)
    #: Oracle's score. None until Phase 3 — deliberately not 0, which would
    #: read as "assessed, no risk" rather than "not assessed".
    risk_score: int | None = None
    recommendation: str | None = None

    @property
    def awaiting_first_scan(self) -> bool:
        return self.total_open == 0 and self.last_scan_at is None

    @property
    def is_stale(self) -> bool:
        if self.last_scan_at is None:
            return False  # "never scanned" is its own state, not staleness.
        from mykronos.schemas import utcnow

        return (utcnow() - self.last_scan_at).days > STALE_AFTER_DAYS


@dataclass
class PortfolioSummary:
    """The cards above the table (spec 10 §2.1)."""

    active_repos: int = 0
    open_critical: int = 0
    open_high: int = 0
    repos_awaiting_first_scan: int = 0
    repos_with_stale_scans: int = 0
    repos_no_go: int = 0


class DashboardQueries:
    def __init__(self, catalog: Catalog) -> None:
        self.catalog = catalog

    # -- portfolio ------------------------------------------------------

    def portfolio(
        self, session: Session, *, include_removed: bool = False
    ) -> tuple[list[PortfolioRow], PortfolioSummary]:
        statement = select(RepoOnboarding).order_by(RepoOnboarding.github_repo_full_name)
        if not include_removed:
            statement = statement.where(RepoOnboarding.status != "removed")
        onboardings = list(session.execute(statement).scalars())

        severity_by_repo = self._open_severity_counts()
        scans_by_repo = self._capability_scan_state()

        rows: list[PortfolioRow] = []
        for onboarding in onboardings:
            repo = onboarding.github_repo_full_name
            counts = severity_by_repo.get(repo, {})
            scan_state = scans_by_repo.get(repo, {})

            capability_states = [
                CapabilityState(
                    capability=capability,
                    has_scanned=capability in scan_state,
                    last_scan_at=scan_state.get(capability, {}).get("last_scan_at"),
                    last_scan_status=scan_state.get(capability, {}).get("status"),
                    open_findings=scan_state.get(capability, {}).get("open_findings", 0),
                )
                for capability in sorted(onboarding.enabled_capabilities or [])
            ]

            last_scan_values = [
                state["last_scan_at"]
                for state in scan_state.values()
                if state.get("last_scan_at")
            ]

            rows.append(
                PortfolioRow(
                    repo_full_name=repo,
                    repo_id=onboarding.id,
                    status=onboarding.status,
                    enabled_capabilities=sorted(onboarding.enabled_capabilities or []),
                    pending_capabilities=(
                        sorted(onboarding.pending_capabilities)
                        if onboarding.pending_capabilities
                        else None
                    ),
                    severity_counts={s: counts.get(s, 0) for s in SEVERITIES},
                    total_open=sum(counts.values()),
                    last_scan_at=max(last_scan_values) if last_scan_values else None,
                    capability_states=capability_states,
                )
            )

        summary = PortfolioSummary(
            active_repos=sum(1 for r in rows if r.status == "active"),
            open_critical=sum(r.severity_counts.get("critical", 0) for r in rows),
            open_high=sum(r.severity_counts.get("high", 0) for r in rows),
            repos_awaiting_first_scan=sum(1 for r in rows if r.awaiting_first_scan),
            repos_with_stale_scans=sum(1 for r in rows if r.is_stale),
            # Oracle lands in Phase 3; until then this is honestly zero
            # because nothing has been assessed, not because nothing is risky.
            repos_no_go=0,
        )
        return rows, summary

    def _open_severity_counts(self) -> dict[str, dict[str, int]]:
        rows = self.catalog.query(
            """
            SELECT repo_full_name, severity, count(*)
            FROM findings
            WHERE status = 'open'
            GROUP BY 1, 2
            """
        )
        counts: dict[str, dict[str, int]] = {}
        for repo, severity, count in rows:
            counts.setdefault(str(repo), {})[str(severity)] = int(count)
        return counts

    def _capability_scan_state(self) -> dict[str, dict[str, dict[str, Any]]]:
        """Latest scan per (repo, capability), plus its open finding count."""
        scans = self.catalog.query(
            """
            SELECT repo_full_name, capability, last_scan_at, scan_status FROM (
                SELECT repo_full_name, capability,
                       coalesce(completed_at, started_at) AS last_scan_at,
                       scan_status,
                       row_number() OVER (
                           PARTITION BY repo_full_name, capability
                           ORDER BY coalesce(completed_at, started_at) DESC
                       ) AS rn
                FROM scan_runs
            ) WHERE rn = 1
            """
        )
        open_counts = self.catalog.query(
            """
            SELECT repo_full_name, capability, count(*)
            FROM findings WHERE status = 'open' GROUP BY 1, 2
            """
        )
        by_pair = {(str(r), str(c)): int(n) for r, c, n in open_counts}

        state: dict[str, dict[str, dict[str, Any]]] = {}
        for repo, capability, last_scan_at, scan_status in scans:
            state.setdefault(str(repo), {})[str(capability)] = {
                "last_scan_at": last_scan_at,
                "status": str(scan_status),
                "open_findings": by_pair.get((str(repo), str(capability)), 0),
            }
        return state

    # -- findings -------------------------------------------------------

    def findings(
        self,
        repo_full_name: str,
        *,
        capability: str | None = None,
        severity: str | None = None,
        finding_status: str | None = None,
        limit: int = 100,
        offset: int = 0,
        include_raw: bool = False,
    ) -> tuple[list[dict[str, Any]], int]:
        """Filterable finding list for one repo (spec 10 §2.2).

        `include_raw` is admin-only (spec 12 §5): a Secrets finding's raw
        record necessarily quotes context around the secret, so it is withheld
        from viewer roles rather than merely hidden in the UI.
        """
        where = ["repo_full_name = ?"]
        params: list[Any] = [repo_full_name]
        for column, value in (
            ("capability", capability),
            ("severity", severity),
            ("status", finding_status),
        ):
            if value:
                where.append(f"{column} = ?")
                params.append(value)
        clause = " AND ".join(where)

        total_rows = self.catalog.query(
            f"SELECT count(*) FROM findings WHERE {clause}", params
        )
        total = int(total_rows[0][0]) if total_rows else 0

        columns = [
            "finding_id",
            "capability",
            "rule_id",
            "title",
            "description",
            "severity",
            "cvss_score",
            "file_path",
            "line_start",
            "line_end",
            "symbol",
            "package_name",
            "package_version",
            "status",
            "fingerprint_version",
            "first_seen_at",
            "last_seen_at",
            "resolved_at",
        ]
        if include_raw:
            columns += ["code_snippet", "raw_finding_json"]

        rows = self.catalog.query(
            f"SELECT {', '.join(columns)} FROM findings WHERE {clause} "
            # Worst first: the top of the list should be what to work on.
            "ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, first_seen_at "
            "LIMIT ? OFFSET ?",
            [*params, limit, offset],
        )

        findings = []
        for row in rows:
            record = dict(zip(columns, row, strict=True))
            if include_raw and record.get("raw_finding_json"):
                # Unparseable raw output is still worth returning as-is: it is
                # the tool's own record, and a dispute is exactly when you want
                # the bytes rather than nothing.
                with suppress(TypeError, json.JSONDecodeError):
                    record["raw_finding_json"] = json.loads(record["raw_finding_json"])
            findings.append(record)
        return findings, total

    # -- scan health ----------------------------------------------------

    def scan_health(self, repo_full_name: str, limit: int = 50) -> list[dict[str, Any]]:
        """Per-capability run history and failure rate (spec 10 §2.2)."""
        rows = self.catalog.query(
            """
            SELECT capability,
                   count(*)                                                AS runs,
                   sum(CASE WHEN scan_status = 'success' THEN 1 ELSE 0 END) AS succeeded,
                   sum(CASE WHEN scan_status IN ('failure', 'partial_failure')
                            THEN 1 ELSE 0 END)                              AS failed,
                   sum(CASE WHEN scan_status = 'no_applicable_targets'
                            THEN 1 ELSE 0 END)                              AS no_targets,
                   max(coalesce(completed_at, started_at))                  AS last_run_at,
                   max(finding_count)                                       AS peak_findings
            FROM scan_runs
            WHERE repo_full_name = ?
            GROUP BY capability
            ORDER BY capability
            LIMIT ?
            """,
            [repo_full_name, limit],
        )
        health = []
        for capability, runs, succeeded, failed, no_targets, last_run_at, peak in rows:
            total = int(runs) or 1
            health.append(
                {
                    "capability": str(capability),
                    "runs": int(runs),
                    "succeeded": int(succeeded or 0),
                    "failed": int(failed or 0),
                    "no_applicable_targets": int(no_targets or 0),
                    "failure_rate": round(int(failed or 0) / total, 3),
                    "last_run_at": last_run_at,
                    "peak_findings": int(peak or 0),
                }
            )
        return health

    def finding(self, finding_id: str, *, include_raw: bool = False) -> dict[str, Any] | None:
        columns = ["finding_id", "repo_full_name", "capability", "status", "severity", "title"]
        if include_raw:
            columns += ["code_snippet", "raw_finding_json"]
        rows = self.catalog.query(
            f"SELECT {', '.join(columns)} FROM findings WHERE finding_id = ?", [finding_id]
        )
        if not rows:
            return None
        return dict(zip(columns, rows[0], strict=True))
