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
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from mykronos.db.models import CapabilityGrant, RepoOnboarding
from mykronos.knowledge.store import KnowledgeStore
from mykronos.lake.catalog import Catalog
from mykronos.patchwork import correlate
from mykronos.patchwork.pipeline import DEFAULT_CORRELATION_CAPABILITIES
from mykronos.patchwork.triage import classify
from mykronos.schemas import Severity, utcnow

logger = logging.getLogger(__name__)

SEVERITIES = [s.value for s in Severity]

#: `Severity` is declared ascending (info … critical), so "worse than" is an
#: index comparison.
_SEVERITY_RANK = {level: index for index, level in enumerate(SEVERITIES)}

#: Which capabilities may take part in a correlation. Borrowed from Patchwork
#: rather than redefined: the dashboard and the pipeline detecting *different*
#: combinations over the same findings would be worse than either doing it
#: alone, because there would be no way to tell which page was right.
CORRELATION_CAPABILITIES = frozenset(DEFAULT_CORRELATION_CAPABILITIES)

#: How many findings the open-findings view will hold at once. Correlation
#: needs the whole set in memory to pair a DAST finding with a SAST one, and
#: spec 10 §6 gives the page a two-second budget; this is where the two meet.
#: Rows are taken worst-first, so what falls off the end is the least severe.
CORRELATION_CEILING = 5000

#: Beyond this, a repo's most recent scan is old enough to be worth flagging
#: (spec 10 §2.1).
STALE_AFTER_DAYS = 7


def _worse(candidate: str, current: str) -> bool:
    """Whether `candidate` is a more severe level than `current`."""
    return _SEVERITY_RANK.get(candidate, -1) > _SEVERITY_RANK.get(current, -1)


def _age_days(first_seen_at: Any) -> int | None:
    """How long this has been outstanding.

    From `first_seen_at`, which survives a rescan because finding identity is
    anchored to content rather than line numbers (D-001) — without that, every
    refactor would reset the clock and nothing would ever look old.
    """
    if not isinstance(first_seen_at, datetime):
        return None
    # Lake timestamps are naive UTC (spec 01 §6), and `utcnow()` matches them.
    # An aware value can only have come from elsewhere, so it is converted
    # rather than assumed.
    seen = (
        first_seen_at.astimezone(UTC).replace(tzinfo=None)
        if first_seen_at.tzinfo
        else first_seen_at
    )
    return max(0, (utcnow() - seen).days)


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
    #: Oracle's standing score, from the most recent portfolio decision.
    #: None means Oracle has not judged this repo — deliberately not 0, which
    #: would read as "assessed, no risk" rather than "not assessed". A repo
    #: that enabled scanning but not `oracle` stays None forever, on purpose.
    risk_score: int | None = None
    recommendation: str | None = None
    #: Pre-clamp score. Ranking has to survive the clamp (D-018): two repos
    #: both displaying 100 still need an order in the triage queue.
    raw_risk_score: float | None = None
    risk_assessed_at: datetime | None = None

    @property
    def awaiting_first_scan(self) -> bool:
        return self.total_open == 0 and self.last_scan_at is None

    @property
    def is_stale(self) -> bool:
        if self.last_scan_at is None:
            return False  # "never scanned" is its own state, not staleness.
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
    #: Onboarded but never judged — Oracle is opt-in, so this is a coverage
    #: number, not an error. It belongs next to repos_no_go so the portfolio
    #: cannot be read as "three at risk" when forty were never looked at.
    repos_not_assessed: int = 0


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
        decisions_by_repo = self._latest_portfolio_decisions()

        # `enabled_capabilities` is the Actions installer's ledger; a
        # Concourse-scanned repo never merges an install PR, so for those the
        # grants are what "enabled" means. Same reasoning as the /ci stages
        # view, applied at the portfolio - the landing page showed three
        # capabilities per repo while eleven were reporting (2026-08-15).
        grants_by_repo: dict[str, set[str]] = {}
        for repo_name, capability in session.execute(
            select(CapabilityGrant.repo_full_name, CapabilityGrant.capability)
        ):
            grants_by_repo.setdefault(repo_name, set()).add(capability)

        rows: list[PortfolioRow] = []
        for onboarding in onboardings:
            repo = onboarding.github_repo_full_name
            counts = severity_by_repo.get(repo, {})
            scan_state = scans_by_repo.get(repo, {})

            enabled = set(onboarding.enabled_capabilities or [])
            if onboarding.scanned_by != "github_actions":
                enabled |= grants_by_repo.get(repo, set())

            capability_states = [
                CapabilityState(
                    capability=capability,
                    has_scanned=capability in scan_state,
                    last_scan_at=scan_state.get(capability, {}).get("last_scan_at"),
                    last_scan_status=scan_state.get(capability, {}).get("status"),
                    open_findings=scan_state.get(capability, {}).get("open_findings", 0),
                )
                for capability in sorted(enabled)
            ]

            last_scan_values = [
                state["last_scan_at"] for state in scan_state.values() if state.get("last_scan_at")
            ]

            rows.append(
                PortfolioRow(
                    repo_full_name=repo,
                    repo_id=onboarding.id,
                    status=onboarding.status,
                    enabled_capabilities=sorted(enabled),
                    pending_capabilities=(
                        sorted(onboarding.pending_capabilities)
                        if onboarding.pending_capabilities
                        else None
                    ),
                    severity_counts={s: counts.get(s, 0) for s in SEVERITIES},
                    total_open=sum(counts.values()),
                    last_scan_at=max(last_scan_values) if last_scan_values else None,
                    capability_states=capability_states,
                    **self._risk_fields(decisions_by_repo.get(repo)),
                )
            )

        summary = PortfolioSummary(
            active_repos=sum(1 for r in rows if r.status == "active"),
            open_critical=sum(r.severity_counts.get("critical", 0) for r in rows),
            open_high=sum(r.severity_counts.get("high", 0) for r in rows),
            repos_awaiting_first_scan=sum(1 for r in rows if r.awaiting_first_scan),
            repos_with_stale_scans=sum(1 for r in rows if r.is_stale),
            repos_no_go=sum(1 for r in rows if r.recommendation == "no_go"),
            repos_not_assessed=sum(1 for r in rows if r.recommendation is None),
        )
        return rows, summary

    def _latest_portfolio_decisions(self) -> dict[str, tuple[Any, ...]]:
        """Most recent portfolio decision per repo.

        `portfolio` decisions only. A pr_gate score is about one pull request
        against one commit, and showing it as the repo's standing risk would
        mean the portfolio changed every time somebody opened a branch.
        """
        rows = self.catalog.query(
            """
            SELECT repo_full_name, overall_risk_score, recommendation, evaluated_at,
                   TRY_CAST(
                       json_extract_string(inputs_snapshot, '$.totals.raw_score') AS DOUBLE
                   ) AS raw_score
            FROM (
                SELECT *, row_number() OVER (
                    PARTITION BY repo_full_name ORDER BY evaluated_at DESC
                ) AS rn
                FROM risk_decisions
                WHERE decision_type = 'portfolio'
            ) WHERE rn = 1
            """
        )
        return {str(row[0]): tuple(row[1:]) for row in rows}

    @staticmethod
    def _risk_fields(decision: tuple[Any, ...] | None) -> dict[str, Any]:
        if decision is None:
            return {}
        score, recommendation, evaluated_at, raw = decision
        return {
            "risk_score": int(score),
            "recommendation": str(recommendation),
            "risk_assessed_at": evaluated_at,
            "raw_risk_score": float(raw) if raw is not None else float(score),
        }

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
        # asset_id, not repo_full_name (spec 14 §5). For a repository
        # asset the two hold the same string, so this is a rename
        # rather than a behaviour change.
        where = ["asset_id = ?"]
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

        total_rows = self.catalog.query(f"SELECT count(*) FROM findings WHERE {clause}", params)
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

    # -- open findings, triaged and deduplicated ------------------------

    def open_findings(
        self,
        repo_full_name: str,
        *,
        store: KnowledgeStore | None = None,
        capability: str | None = None,
        severity: str | None = None,
        finding_status: str = "open",
        limit: int = 400,
    ) -> dict[str, Any]:
        """One repo's outstanding work: deduplicated, triaged, correlated.

        The flat list `findings()` returns is the record. This is the view a
        person is supposed to act on, and the three differences are the point:

        **Open only, by default.** A list mixing open findings with ones
        somebody already accepted or dismissed cannot be counted. Dispositioned
        findings are still reachable by asking for their status by name; they
        are simply not what "what is outstanding" means.

        **Deduplicated.** One rule firing in forty files is one decision and
        forty rows, and the same CVE reported by both the dependency scan and
        the container scan is one vulnerability reported twice. Rows are
        grouped on `(rule_id, package)` so the count on screen is a count of
        decisions; every occurrence is still carried, so nothing is hidden and
        each one keeps its own disposition.

        **Correlated.** Toxic combinations are detected here rather than read
        from `remediation_events`, because those only exist where Patchwork has
        run — and a repository that never enabled auto-remediation is exactly
        the one nobody has told about its unauthenticated database.
        """
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
            "package_name",
            "package_version",
            "status",
            "first_seen_at",
            "last_seen_at",
        ]

        counts = self._severity_counts(repo_full_name, finding_status)
        total = sum(counts.values())

        # The correlation pool is fetched separately from the rows on screen,
        # for the reason Patchwork's pipeline does the same (spec 08 §5a): a
        # single severity-ordered query lets 400 SAST findings crowd out the
        # one DAST finding that makes a combination. It also ignores the
        # caller's filters — half a combination is routinely a medium from
        # another scanner, so a view filtered to `critical` would report no
        # combinations at exactly the moment somebody is looking at the worst
        # row.
        pool = self._finding_rows(
            repo_full_name, columns, finding_status, capabilities=CORRELATION_CAPABILITIES
        )
        combinations = correlate.detect(pool)
        by_id = {str(f["finding_id"]): f for f in pool}
        combination_of: dict[str, str] = {}
        for combo in combinations:
            for member in combo.finding_ids:
                combination_of[member] = combo.combination_id

        rows = self._finding_rows(
            repo_full_name,
            columns,
            finding_status,
            capability=capability,
            severity=severity,
            limit=limit + 1,
        )
        truncated = len(rows) > limit
        rows = rows[:limit]

        groups = self._group_findings(
            rows, repo_full_name, store=store, combination_of=combination_of
        )

        return {
            "repo_full_name": repo_full_name,
            "finding_status": finding_status,
            "total": total,
            "matching": (
                total
                if capability is None and severity is None
                else self._finding_count(
                    repo_full_name, finding_status, capability=capability, severity=severity
                )
            ),
            "shown": sum(g["occurrences"] for g in groups),
            "deduplicated": max(0, len(rows) - len(groups)),
            "by_severity": counts,
            "groups": groups,
            "toxic_combinations": [
                self._describe_combination(combo, by_id) for combo in combinations
            ],
            "truncated": truncated,
        }

    def _status_clause(
        self,
        repo_full_name: str,
        finding_status: str,
        *,
        capability: str | None = None,
        severity: str | None = None,
    ) -> tuple[str, list[Any]]:
        # asset_id, not repo_full_name (spec 14 §5): for a repository asset the
        # two hold the same string, so this is a rename rather than a change.
        where = ["asset_id = ?", "status = ?"]
        params: list[Any] = [repo_full_name, finding_status]
        for column, value in (("capability", capability), ("severity", severity)):
            if value:
                where.append(f"{column} = ?")
                params.append(value)
        return " AND ".join(where), params

    def _finding_count(
        self,
        repo_full_name: str,
        finding_status: str,
        *,
        capability: str | None = None,
        severity: str | None = None,
    ) -> int:
        clause, params = self._status_clause(
            repo_full_name, finding_status, capability=capability, severity=severity
        )
        rows = self.catalog.query(f"SELECT count(*) FROM findings WHERE {clause}", params)
        return int(rows[0][0]) if rows else 0

    def _severity_counts(self, repo_full_name: str, finding_status: str) -> dict[str, int]:
        """How much of each severity is outstanding, before any filter.

        Before the filter deliberately: these numbers sit on the filter
        buttons, and a count that changed when you pressed the button next to
        it would be describing the answer rather than the choice.
        """
        clause, params = self._status_clause(repo_full_name, finding_status)
        counts = dict.fromkeys(SEVERITIES, 0)
        for level, count in self.catalog.query(
            f"SELECT severity, count(*) FROM findings WHERE {clause} GROUP BY 1", params
        ):
            if str(level) in counts:
                counts[str(level)] = int(count)
        return counts

    def _finding_rows(
        self,
        repo_full_name: str,
        columns: list[str],
        finding_status: str,
        *,
        capability: str | None = None,
        severity: str | None = None,
        capabilities: frozenset[str] | None = None,
        limit: int = CORRELATION_CEILING,
    ) -> list[dict[str, Any]]:
        """Findings of one status for one repo, worst first.

        Always bounded: correlation holds its whole pool in memory, and spec 10
        §6 gives the page a two-second budget. Worst-first ordering is what
        makes a ceiling survivable — what falls off the end is the least severe
        and the newest — and the caller reports the truncation rather than
        letting a shorter list read as a shorter backlog.

        Raw output is never selected here whatever the caller's role. This view
        is a list of decisions; the bytes of a secrets finding belong on the
        detail pane behind the same admin check they always were (spec 12 §5).
        """
        clause, params = self._status_clause(
            repo_full_name, finding_status, capability=capability, severity=severity
        )
        if capabilities is not None:
            placeholders = ", ".join("?" for _ in capabilities)
            clause += f" AND capability IN ({placeholders})"
            params += sorted(capabilities)

        rows = self.catalog.query(
            f"SELECT {', '.join(columns)} FROM findings WHERE {clause} "
            "ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, first_seen_at "
            "LIMIT ?",
            [*params, min(limit, CORRELATION_CEILING)],
        )
        return [dict(zip(columns, row, strict=True)) for row in rows]

    def _group_findings(
        self,
        findings: list[dict[str, Any]],
        repo_full_name: str,
        *,
        store: KnowledgeStore | None,
        combination_of: dict[str, str],
    ) -> list[dict[str, Any]]:
        """Collapse repeat occurrences of the same problem into one row.

        The key is the rule and the package it is about — not the file. A rule
        that fires in forty files is one thing to decide and forty places to
        change it, and the version is deliberately excluded so the same CVE on
        two pinned versions of one library does not read as two problems.
        """
        grouped: dict[tuple[str, str], dict[str, Any]] = {}
        order: list[tuple[str, str]] = []

        for finding in findings:
            key = (str(finding["rule_id"]), str(finding.get("package_name") or ""))
            group = grouped.get(key)
            if group is None:
                grouped[key] = group = {
                    # Readable, and safe in a query string — the UI round-trips
                    # this to say which row is open. A separator a rule id
                    # could contain would at worst merge two rows on screen;
                    # the grouping itself keys on the tuple, not this string.
                    "group_key": "::".join(key),
                    "rule_id": str(finding["rule_id"]),
                    "title": str(finding["title"]),
                    "description": finding.get("description"),
                    "severity": str(finding["severity"]),
                    "package_name": finding.get("package_name"),
                    "capabilities": [],
                    "occurrences": 0,
                    "locations": [],
                    "first_seen_at": finding.get("first_seen_at"),
                    "last_seen_at": finding.get("last_seen_at"),
                    "cvss_score": finding.get("cvss_score"),
                    "toxic_combination_ids": [],
                }
                order.append(key)

            group["occurrences"] += 1
            capability = str(finding["capability"])
            if capability not in group["capabilities"]:
                group["capabilities"].append(capability)
            group["locations"].append(
                {
                    "finding_id": str(finding["finding_id"]),
                    "capability": capability,
                    "severity": str(finding["severity"]),
                    "file_path": finding.get("file_path"),
                    "line_start": finding.get("line_start"),
                    "package_version": finding.get("package_version"),
                    "first_seen_at": finding.get("first_seen_at"),
                }
            )

            # The group's severity is its worst member's. Two scanners
            # disagreeing about one CVE is common, and the low one is never the
            # safe number to display.
            if _worse(str(finding["severity"]), str(group["severity"])):
                group["severity"] = str(finding["severity"])
            for field_name, better in (("first_seen_at", min), ("last_seen_at", max)):
                current, incoming = group.get(field_name), finding.get(field_name)
                if incoming is not None:
                    group[field_name] = (
                        incoming if current is None else better(current, incoming)
                    )

            combination_id = combination_of.get(str(finding["finding_id"]))
            if combination_id and combination_id not in group["toxic_combination_ids"]:
                group["toxic_combination_ids"].append(combination_id)

        # Read once, not once per row: `active_entries()` parses the whole
        # knowledge file, and this loop runs for every group on the page.
        learned = [] if store is None else store.active_entries()

        result = []
        for key in order:
            group = grouped[key]
            classification, rationale = classify(
                {
                    "rule_id": group["rule_id"],
                    "severity": group["severity"],
                    "capability": group["capabilities"][0],
                },
                repo_full_name,
                entries=learned,
            )
            if group["toxic_combination_ids"]:
                # A combination overrides the per-finding verdict, including a
                # dismissal. Each half being individually unremarkable is what
                # a toxic combination *is*, so triaging on the halves is how
                # one gets waved through twice.
                classification, rationale = (
                    "toxic_combination",
                    "Part of a toxic combination: this cannot be judged on its "
                    "own, and fixing it in isolation would close the finding "
                    "without closing the risk.",
                )
            group["triage"] = classification
            group["triage_rationale"] = rationale
            group["age_days"] = _age_days(group["first_seen_at"])
            result.append(group)
        return result

    @staticmethod
    def _describe_combination(
        combination: correlate.Combination, by_id: dict[str, dict[str, Any]]
    ) -> dict[str, Any]:
        members = [by_id[fid] for fid in sorted(combination.finding_ids) if fid in by_id]
        rule = next(
            (r for r in correlate.BUILT_IN_RULES if r.rule_id == combination.rule_id),
            None,
        )
        severity = "info"
        for member in members:
            if _worse(str(member["severity"]), severity):
                severity = str(member["severity"])
        return {
            "combination_id": combination.combination_id,
            "rule_id": combination.rule_id,
            "name": rule.name if rule else combination.rule_id,
            "severity": severity,
            "rationale": combination.rationale,
            "members": [
                {
                    "finding_id": str(member["finding_id"]),
                    "capability": str(member["capability"]),
                    "rule_id": str(member["rule_id"]),
                    "title": str(member["title"]),
                    "severity": str(member["severity"]),
                    "file_path": member.get("file_path"),
                }
                for member in members
            ],
        }

    # -- triage queue ---------------------------------------------------

    def triage_queue(
        self,
        session: Session,
        *,
        severity: str | None = None,
        capability: str | None = None,
        limit: int = 100,
    ) -> tuple[list[dict[str, Any]], dict[str, int]]:
        """The highest-priority open findings across every active repo.

        The portfolio table answers "which repo is worst". This answers "what
        do I do next", which is a different question and the one somebody
        actually has on a Monday morning. A per-repo view makes you visit
        forty pages to find the three things that matter.

        Ordering is severity, then age. Age rather than recency deliberately:
        an old critical is worse than a new one — it has been exploitable for
        longer and it has already survived somebody deciding not to fix it.

        Repos that are not active are excluded. Their findings are still in the
        lake and still on their own pages, but a queue is a list of work, and
        work on a repo nobody is scanning any more is not work.
        """
        active = {
            row.github_repo_full_name: row
            for row in session.execute(
                select(RepoOnboarding).where(RepoOnboarding.status == "active")
            ).scalars()
        }
        if not active:
            return [], dict.fromkeys(SEVERITIES, 0)

        placeholders = ", ".join("?" for _ in active)
        where = [f"repo_full_name IN ({placeholders})", "status = 'open'"]
        params: list[Any] = list(active)
        for column, value in (("severity", severity), ("capability", capability)):
            if value:
                where.append(f"{column} = ?")
                params.append(value)
        clause = " AND ".join(where)

        counts_rows = self.catalog.query(
            f"SELECT severity, count(*) FROM findings WHERE {clause} GROUP BY 1",
            params,
        )
        counts = dict.fromkeys(SEVERITIES, 0)
        for level, count in counts_rows:
            counts[str(level)] = int(count)

        columns = [
            "finding_id",
            "repo_full_name",
            "capability",
            "rule_id",
            "title",
            "severity",
            "file_path",
            "line_start",
            "package_name",
            "package_version",
            "first_seen_at",
        ]
        rows = self.catalog.query(
            f"SELECT {', '.join(columns)} FROM findings WHERE {clause} "
            "ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, first_seen_at "
            "LIMIT ?",
            [*params, limit],
        )

        decisions = self._latest_portfolio_decisions()
        queue = []
        for row in rows:
            record = dict(zip(columns, row, strict=True))
            repo = str(record["repo_full_name"])
            onboarding = active[repo]
            record["repo_id"] = onboarding.id
            # Carried per row so the queue can be read without cross-referencing
            # the portfolio table: the same critical means something different
            # in a repo Oracle already calls no_go.
            decision = decisions.get(repo)
            record["repo_recommendation"] = str(decision[1]) if decision else None
            queue.append(record)
        return queue, counts

    # -- Aegis and Atlas ------------------------------------------------

    def insider_risk(
        self, repo_full_name: str, *, include_detail: bool, limit: int = 50
    ) -> list[dict[str, Any]]:
        """Insider-risk assessments for one repo, newest first (spec 06 §9).

        `include_detail` is the admin gate, applied *here* rather than in the
        endpoint or the UI. The author's login and the signal breakdown are
        simply not selected for a viewer, on the same principle as raw output:
        "not rendered" is not "not sent".

        What a viewer keeps is the verdict per pull request, which is already
        visible to anyone who can see the Check Run. Withholding that too would
        be theatre rather than privacy.
        """
        columns = [
            "signal_id",
            "pr_number",
            "commit_sha",
            "insider_risk_score",
            "recommendation",
            "ai_authorship_flag",
            "evaluated_at",
            "github_check_run_id",
        ]
        if include_detail:
            columns += ["author_login", "signal_breakdown"]

        rows = self.catalog.query(
            f"SELECT {', '.join(columns)} FROM insider_risk_signals "
            "WHERE repo_full_name = ? ORDER BY evaluated_at DESC LIMIT ?",
            [repo_full_name, limit],
        )

        signals = []
        for row in rows:
            record = dict(zip(columns, row, strict=True))
            if record.get("signal_breakdown"):
                with suppress(TypeError, json.JSONDecodeError):
                    record["signal_breakdown"] = json.loads(record["signal_breakdown"])
            if not include_detail:
                # Present as explicit nulls rather than absent keys, so a
                # caller does not have to guess whether the field is missing
                # because it was withheld or because nothing recorded it.
                record["author_login"] = None
                record["signal_breakdown"] = None
            signals.append(record)
        return signals

    def sscs_evidence(self, repo_full_name: str, limit: int = 50) -> list[dict[str, Any]]:
        """Supply-chain evidence per commit, newest first (spec 10 §9)."""
        columns = [
            "evidence_id",
            "commit_sha",
            "tag_or_release",
            "sbom_ref",
            "dependency_count",
            "vulnerable_dependency_count",
            "trust_score",
            "raw_trust_score",
            "provenance_json",
            "ecosystems_json",
            "evaluated_at",
        ]
        rows = self.catalog.query(
            f"SELECT {', '.join(columns)} FROM sscs_evidence "
            "WHERE repo_full_name = ? ORDER BY evaluated_at DESC LIMIT ?",
            [repo_full_name, limit],
        )

        evidence = []
        for row in rows:
            record = dict(zip(columns, row, strict=True))
            for field_name in ("provenance_json", "ecosystems_json"):
                if record.get(field_name):
                    with suppress(TypeError, json.JSONDecodeError):
                        record[field_name] = json.loads(record[field_name])
            evidence.append(record)
        return evidence

    # -- scan health ----------------------------------------------------

    def introduced_by(self, repo_full_name: str, commit_sha: str) -> dict[str, int]:
        """Open findings this commit *introduced*, by severity (D-048).

        The question a gate on a commit should ask. Oracle's score describes
        the whole open backlog, which is the right answer to "how much risk
        does this repository carry" and the wrong one to "should this change
        ship" - a repository with 243 accepted container risks refuses every
        commit regardless of content, and a gate that refuses everything gets
        switched off.

        "Introduced" is `first_seen_scan_run_id` belonging to a scan of this
        commit, not `first_seen_at` near it in time. Time would sweep in
        whatever a concurrent scan of a different commit happened to report,
        and this has to be attributable to the change in front of it.

        Only `open` counts. A finding introduced and already dispositioned -
        a false positive, an accepted risk - is not a reason to refuse the
        commit that introduced it.
        """
        rows = self.catalog.query(
            """
            SELECT f.severity, count(*)
            FROM findings f
            WHERE f.asset_id = ?
              AND f.status = 'open'
              AND f.first_seen_scan_run_id IN (
                    SELECT scan_run_id FROM scan_runs
                    WHERE repo_full_name = ? AND commit_sha = ?
              )
            GROUP BY 1
            """,
            [repo_full_name, repo_full_name, commit_sha],
        )
        return {str(severity): int(count) for severity, count in rows}

    def vulnerability_management(self, repo_full_name: str | None = None) -> dict[str, Any]:
        """What is outstanding, how old, and what was accepted (PIP-9).

        The platform could always answer "what is open" and never "how long
        has it been open, and what did we decide not to fix". Those are the
        two questions a vulnerability management programme is actually made
        of, and the data for both was already here - open findings carry
        `first_seen_at`, and an acceptance is a status with a reason in the
        audit log.

        Age is measured from `first_seen_at`, which survives rescans because
        finding identity is anchored to content rather than line numbers
        (D-001). Without that, every refactor would reset the clock and
        nothing would ever look old.
        """
        scope = "AND asset_id = ?" if repo_full_name else ""
        params: list[Any] = [repo_full_name] if repo_full_name else []

        aging = self.catalog.query(
            f"""
            SELECT severity,
                   CASE
                     WHEN first_seen_at > now() - INTERVAL 7 DAY  THEN '0-7'
                     WHEN first_seen_at > now() - INTERVAL 30 DAY THEN '8-30'
                     WHEN first_seen_at > now() - INTERVAL 90 DAY THEN '31-90'
                     ELSE '90+'
                   END AS age_band,
                   count(*)
            FROM findings
            WHERE status = 'open' {scope}
            GROUP BY 1, 2
            """,
            params,
        )

        # Accepted risk is not a resolved finding and must never be counted as
        # one. It is a decision with an owner and a reason, and the reason is
        # the part that decays - "no vendor fix" stops being true the day a
        # vendor ships one.
        accepted = self.catalog.query(
            f"""
            SELECT capability, severity, count(*)
            FROM findings
            WHERE status = 'accepted_risk' {scope}
            GROUP BY 1, 2
            ORDER BY 3 DESC
            """,
            params,
        )

        oldest = self.catalog.query(
            f"""
            SELECT finding_id, severity, capability, title, first_seen_at
            FROM findings
            WHERE status = 'open' AND severity IN ('critical', 'high') {scope}
            ORDER BY first_seen_at
            LIMIT 10
            """,
            params,
        )

        # One row per combination, not per member. A toxic combination is one
        # decision to make; listing its members separately is how it stops
        # looking like a single thing.
        combinations = self.catalog.query(
            f"""
            SELECT count(DISTINCT toxic_combination_id)
            FROM remediation_events
            WHERE toxic_combination_id IS NOT NULL
              {"AND repo_full_name = ?" if repo_full_name else ""}
            """,
            params,
        )

        return {
            "scope": repo_full_name or "portfolio",
            "aging": [
                {"severity": str(sev), "age_band": str(band), "count": int(n)}
                for sev, band, n in aging
            ],
            "accepted_risk": [
                {"capability": str(cap), "severity": str(sev), "count": int(n)}
                for cap, sev, n in accepted
            ],
            "oldest_open": [
                {
                    "finding_id": str(fid),
                    "severity": str(sev),
                    "capability": str(cap),
                    "title": str(title),
                    "first_seen_at": seen,
                }
                for fid, sev, cap, title, seen in oldest
            ],
            "toxic_combinations": int(combinations[0][0]) if combinations else 0,
        }

    def last_successful_scan_at(self, repo_full_name: str) -> dict[str, datetime]:
        """Newest successful scan run per capability (spec 15 §4a).

        Successful only. A capability whose every run failed has reported
        nothing usable, and treating a recorded failure as evidence of
        reporting is how a broken lane hides behind its own error rows.
        """
        rows = self.catalog.query(
            """
            SELECT capability, max(coalesce(completed_at, started_at))
            FROM scan_runs
            WHERE repo_full_name = ? AND scan_status = 'success'
            GROUP BY capability
            """,
            [repo_full_name],
        )
        latest = {str(c): at for c, at in rows if at is not None}

        # Aegis is the exception, and it is not an oversight in either place.
        # It assesses a pull request rather than scanning a tree, so it writes
        # an InsiderRiskSignal and never a ScanRun (spec 06 §3). Looking for
        # it in scan_runs reports every insider job as having reported
        # nothing, which is both wrong and the kind of permanent false alarm
        # that trains people to ignore the panel.
        aegis = self.catalog.query(
            "SELECT max(evaluated_at) FROM insider_risk_signals WHERE repo_full_name = ?",
            [repo_full_name],
        )
        if aegis and aegis[0][0] is not None:
            latest["aegis"] = aegis[0][0]

        return latest

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
        # `rule_id` is here because the disposition endpoint turns a dismissal
        # into a KnowledgeEntry keyed on it (spec 11 §3). Omitting it produced
        # entries with an empty subject that could never match a rule, so
        # dampening silently never fired.
        #
        # The rest is what a detail pane needs. Fetched by id rather than found
        # in a page of the flat list, because the dashboard groups occurrences
        # and the one somebody clicked is routinely not in the first hundred
        # rows of anything.
        columns = [
            "finding_id",
            "repo_full_name",
            "capability",
            "rule_id",
            "status",
            "severity",
            "title",
            "description",
            "cvss_score",
            "file_path",
            "line_start",
            "line_end",
            "symbol",
            "package_name",
            "package_version",
            "fingerprint_version",
            "first_seen_at",
            "last_seen_at",
            "resolved_at",
        ]
        if include_raw:
            columns += ["code_snippet", "raw_finding_json"]
        rows = self.catalog.query(
            f"SELECT {', '.join(columns)} FROM findings WHERE finding_id = ?", [finding_id]
        )
        if not rows:
            return None
        record = dict(zip(columns, rows[0], strict=True))
        if include_raw and record.get("raw_finding_json"):
            # Parsed here as well as in `findings()`, so one finding served two
            # ways is the same shape both times. Unparseable output is returned
            # as the tool wrote it: a dispute is exactly when you want the bytes.
            with suppress(TypeError, json.JSONDecodeError):
                record["raw_finding_json"] = json.loads(record["raw_finding_json"])
        return record
