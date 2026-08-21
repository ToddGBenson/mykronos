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
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from mykronos.db.models import CapabilityGrant, RepoOnboarding, ThreatIntelMatch
from mykronos.knowledge.store import KnowledgeStore
from mykronos.lake.catalog import Catalog
from mykronos.patchwork import correlate
from mykronos.patchwork.pipeline import DEFAULT_CORRELATION_CAPABILITIES
from mykronos.patchwork.triage import classify
from mykronos.schemas import Severity, utcnow
from mykronos.threat_intel import extract_cve

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

#: Patchwork stages that mean it produced something (spec 19 §3.2). Read from
#: `remediation_events` rather than predicted: a fixer cannot say whether it
#: applies without the file content, so the only honest answer to "is this
#: fixable" is what Patchwork actually did when it looked.
_FIX_PRODUCED = frozenset({"pr_opened", "fix_generated", "queued"})

#: Stages that mean it looked and could not help. Distinct from never having
#: looked, which stays `None` — "we tried and there is no mechanical fix" and
#: "nobody has checked" send a reader to different places.
_FIX_REFUSED = frozenset({"no_fix_available", "skipped_low_confidence"})

#: The Threat Model tab's whole vocabulary (spec 18 §6.2). Repudiation has no
#: capability mapped to it deliberately — nothing this platform scans speaks
#: to "can an action be denied after the fact," and a category with an
#: invented capability behind it would be less honest than one that always
#: renders empty and says why.
STRIDE_CATEGORIES = (
    "spoofing",
    "tampering",
    "repudiation",
    "information_disclosure",
    "denial_of_service",
    "elevation_of_privilege",
)

#: Capability -> the STRIDE categories its findings can speak to (spec 18
#: §6.2). Coarser than a CWE-level mapping would be, and said so in the
#: response (`mapping_resolution`) rather than presented as more precise than
#: the data supports — no `Finding` carries a structured CWE today. A
#: capability maps to more than one category on purpose: a `sast` finding
#: could be either a tampering issue or an information-disclosure one, and
#: this data cannot tell which without per-rule taxonomy this platform does
#: not have.
STRIDE_BY_CAPABILITY: dict[str, tuple[str, ...]] = {
    "dast": ("spoofing", "tampering"),
    "network": ("spoofing", "denial_of_service"),
    "cloud": ("elevation_of_privilege", "information_disclosure"),
    "iac": ("elevation_of_privilege", "tampering"),
    "secrets": ("information_disclosure",),
    "sast": ("tampering", "information_disclosure"),
    "containers": ("tampering", "elevation_of_privilege"),
    "atlas": ("tampering", "information_disclosure"),
}


def _worse(candidate: str, current: str) -> bool:
    """Whether `candidate` is a more severe level than `current`."""
    return _SEVERITY_RANK.get(candidate, -1) > _SEVERITY_RANK.get(current, -1)


def _is_flaky(recent: list[dict[str, Any]]) -> bool:
    """Same commit, disagreeing status, on the two most recent runs (spec 19
    §1.3) — a lane that fails, then passes, on nothing the repository changed.
    Fewer than two runs, or two runs of different commits, is not evidence of
    either way and reads as not flaky rather than guessed at."""
    if len(recent) < 2:
        return False
    newest, previous = recent[0], recent[1]
    return bool(
        newest.get("commit_sha")
        and newest["commit_sha"] == previous.get("commit_sha")
        and newest.get("scan_status") != previous.get("scan_status")
    )


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
        # `asset_id`, not `repo_full_name` (spec 18 §1, D-061): every other
        # repo-scoped query in this file already keys on asset_id
        # (`_status_clause`) because it is the canonical column (spec 14 §5).
        # This one didn't, so a finding whose asset_id was never backfilled
        # (see migrate_assets.py) was counted here and invisible to
        # open_findings() below it — the portfolio and the Findings tab
        # disagreeing about the same repo's open count.
        rows = self.catalog.query(
            """
            SELECT asset_id, severity, count(*)
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
        # asset_id, matching `_open_severity_counts` above (spec 18 §1) — the
        # `scans` query just above stays on repo_full_name, since scan_runs
        # carries no asset_id and no such drift is possible there.
        open_counts = self.catalog.query(
            """
            SELECT asset_id, capability, count(*)
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
        rule_id: str | None = None,
        first_seen_after: datetime | None = None,
        first_seen_before: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
        include_raw: bool = False,
    ) -> tuple[list[dict[str, Any]], int]:
        """Filterable finding list for one repo (spec 10 §2.2, spec 17 §3).

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
        if rule_id:
            # Same free-text match as open_findings() (spec 17 §3) — matched
            # against rule_id and title, not a category filter with a count.
            where.append("(rule_id ILIKE ? OR title ILIKE ?)")
            needle = f"%{rule_id}%"
            params += [needle, needle]
        if first_seen_after is not None:
            where.append("first_seen_at >= ?")
            params.append(first_seen_after)
        if first_seen_before is not None:
            where.append("first_seen_at <= ?")
            params.append(first_seen_before)
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
            # A `superseded` finding names its replacement (spec 05 §5a); this
            # was previously not selected here, so there was no way to follow
            # a re-fingerprinted finding to what replaced it (spec 17 §5.1).
            "superseded_by",
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
        rule_id: str | None = None,
        finding_status: str = "open",
        limit: int = 400,
        session: Session | None = None,
        kev_only: bool = False,
        min_epss: float | None = None,
        triage: str | None = None,
        fixable: bool | None = None,
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
        the one nobody has told about its unauthenticated database. When
        `session` is supplied, a combination naming a KEV-listed CVE has its
        rationale prefixed to say so (spec 17 §5.6) — omitted (not an error)
        when `session` is `None`, matching every other optional input here.

        `kev_only`/`min_epss` (spec 17 §3, #20) also need `session` — a repo with
        neither filter set behaves exactly as before either way.

        `triage` (spec 18 §5.1) filters on `classify()`'s own output — the same
        classification already rendered per group, now also queryable. It is a
        property of the group, not a column any row carries, so — like
        `kev_only`/`min_epss` — it is applied after grouping, not in SQL.
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
        if session is not None and combinations:
            kev_cves = self._kev_cve_ids(session, by_id.values())
            combinations = correlate.kev_boosted(combinations, by_id, kev_cves)
        combination_of: dict[str, str] = {}
        for combo in combinations:
            for member in combo.finding_ids:
                combination_of[member] = combo.combination_id

        # A KEV/EPSS filter is applied after this fetch, in Python, against
        # data from a different database (spec 17 §4) — SQL has no way to
        # narrow by it directly. When one is requested, the fetch has to stay
        # generous enough that the filter doesn't cut candidates before ever
        # seeing them, so it draws on CORRELATION_CEILING — already the
        # platform's answer to "how large a single-repo pool is safe to hold
        # in memory at once" (spec 08 §5a) — instead of `limit` itself, and
        # the row-level truncation the unfiltered path applies before
        # grouping moves to a group-level one afterward, since a `limit` of
        # *problems worth showing* is what the filter is answering for.
        wants_threat_intel_filter = kev_only or min_epss is not None
        # `triage` joins the same after-grouping path for the same reason —
        # it is not a column a single row carries either — but it needs no
        # session, so it is kept a separate flag from the threat-intel one
        # rather than folded into it and made to look like it does.
        wants_group_filter = (
            wants_threat_intel_filter or triage is not None or fixable is not None
        )

        if wants_group_filter:
            rows = self._finding_rows(
                repo_full_name,
                columns,
                finding_status,
                capability=capability,
                severity=severity,
                rule_id=rule_id,
                limit=CORRELATION_CEILING,
            )
            pool_truncated = len(rows) >= CORRELATION_CEILING
        else:
            rows = self._finding_rows(
                repo_full_name,
                columns,
                finding_status,
                capability=capability,
                severity=severity,
                rule_id=rule_id,
                limit=limit + 1,
            )
            pool_truncated = len(rows) > limit
            rows = rows[:limit]

        groups = self._group_findings(
            rows,
            repo_full_name,
            store=store,
            combination_of=combination_of,
            fix_stage_of=self._fix_stages(repo_full_name),
        )
        if session is not None:
            self._attach_threat_intel(session, groups)
        elif wants_threat_intel_filter:
            # Requested but nothing to check against — the honest answer is
            # "matches nothing", not a silently unfiltered list. Only
            # reachable if a caller reaches this method directly with no
            # session; the API layer always supplies one.
            groups = []

        if kev_only:
            groups = [g for g in groups if g["in_kev"]]
        if min_epss is not None:
            groups = [
                g
                for g in groups
                if g["epss_score"] is not None and g["epss_score"] >= min_epss
            ]
        if triage is not None:
            groups = [g for g in groups if g["triage"] == triage]
        if fixable is not None:
            groups = [g for g in groups if g["fixable"] is fixable]

        if wants_group_filter:
            truncated = pool_truncated or len(groups) > limit
            groups = groups[:limit]
            shown_ids = {loc["finding_id"] for g in groups for loc in g["locations"]}
            rows = [r for r in rows if str(r["finding_id"]) in shown_ids]
        else:
            truncated = pool_truncated

        return {
            "repo_full_name": repo_full_name,
            "finding_status": finding_status,
            "total": total,
            "matching": (
                sum(g["occurrences"] for g in groups)
                if wants_group_filter
                else (
                    total
                    if capability is None and severity is None and rule_id is None
                    else self._finding_count(
                        repo_full_name,
                        finding_status,
                        capability=capability,
                        severity=severity,
                        rule_id=rule_id,
                    )
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

    # -- threat model -----------------------------------------------------

    def threat_model(self, repo_full_name: str) -> dict[str, Any]:
        """A STRIDE-categorized attack-surface inventory (spec 18 §6).

        Capability-level, not per-finding: no `Finding` carries a structured
        CWE — `rule_id` is a free-form string the reporting tool chose, never
        a taxonomy this platform controls — so `STRIDE_BY_CAPABILITY` maps
        each finding's *capability* to the STRIDE categories it can speak to,
        rather than pretending to place each finding in exactly one category
        a CWE would support and this data does not. `mapping_resolution` says
        so in the response itself, the same way Oracle's `inputs_snapshot`
        names which inputs were actually available rather than leaving a
        caller to assume every field means what a finer-grained one would.

        Reuses `_finding_rows`/`_group_findings` rather than a second
        grouping implementation — one rule firing on forty files is one
        attack-surface item here for the identical reason it is one row on
        the Findings tab.
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
        rows = self._finding_rows(
            repo_full_name,
            columns,
            "open",
            capabilities=frozenset(STRIDE_BY_CAPABILITY),
            limit=CORRELATION_CEILING,
        )
        groups = self._group_findings(rows, repo_full_name, store=None, combination_of={})

        by_category: dict[str, list[dict[str, Any]]] = {c: [] for c in STRIDE_CATEGORIES}
        for group in groups:
            categories: set[str] = set()
            for capability in group["capabilities"]:
                categories.update(STRIDE_BY_CAPABILITY.get(capability, ()))
            for category in categories:
                by_category[category].append(group)

        evidence = self.sscs_evidence(repo_full_name, limit=1)
        latest = evidence[0] if evidence else None

        return {
            "repo_full_name": repo_full_name,
            "mapping_resolution": "capability",
            "categories": [
                {"stride": category, "findings": by_category[category]}
                for category in STRIDE_CATEGORIES
            ],
            # Context for the Tampering/Information Disclosure categories'
            # atlas-derived findings, not a finding itself — the dependency
            # graph as a whole, distinct from the vulnerable slice of it the
            # findings above already cover (spec 18 §8).
            "supply_chain": (
                {
                    "trust_score": latest["trust_score"],
                    "dependency_count": latest["dependency_count"],
                    "vulnerable_dependency_count": latest["vulnerable_dependency_count"],
                }
                if latest is not None
                else None
            ),
        }

    def _fix_stages(self, repo_full_name: str) -> dict[str, str]:
        """finding_id -> the stage Patchwork last reached for it (spec 08 §7).

        The same read `jobs.route_open_findings` makes, for the same reason:
        what Patchwork *did* is the only honest answer to "is this fixable",
        since a fixer cannot decide without the file content and this query
        layer has no business fetching one.
        """
        rows = self.catalog.query(
            """
            SELECT finding_id, pipeline_stage_reached FROM (
                SELECT finding_id, pipeline_stage_reached,
                       row_number() OVER (
                           PARTITION BY finding_id ORDER BY updated_at DESC
                       ) AS rn
                FROM remediation_events
                WHERE repo_full_name = ?
            ) WHERE rn = 1
            """,
            [repo_full_name],
        )
        return {str(finding_id): str(stage) for finding_id, stage in rows}

    def _status_clause(
        self,
        repo_full_name: str,
        finding_status: str,
        *,
        capability: str | None = None,
        severity: str | None = None,
        rule_id: str | None = None,
    ) -> tuple[str, list[Any]]:
        # asset_id, not repo_full_name (spec 14 §5): for a repository asset the
        # two hold the same string, so this is a rename rather than a change.
        where = ["asset_id = ?", "status = ?"]
        params: list[Any] = [repo_full_name, finding_status]
        for column, value in (("capability", capability), ("severity", severity)):
            if value:
                where.append(f"{column} = ?")
                params.append(value)
        if rule_id:
            # Free-text, not a category filter with a count on a button
            # (spec 17 §3) — matched against rule_id and title, since Trivy's
            # rule_id *is* the CVE while an OSV-derived title carries it
            # instead. ILIKE: DuckDB's case-insensitive substring match.
            where.append("(rule_id ILIKE ? OR title ILIKE ?)")
            needle = f"%{rule_id}%"
            params += [needle, needle]
        return " AND ".join(where), params

    def _finding_count(
        self,
        repo_full_name: str,
        finding_status: str,
        *,
        capability: str | None = None,
        severity: str | None = None,
        rule_id: str | None = None,
    ) -> int:
        clause, params = self._status_clause(
            repo_full_name,
            finding_status,
            capability=capability,
            severity=severity,
            rule_id=rule_id,
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
        rule_id: str | None = None,
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
            repo_full_name,
            finding_status,
            capability=capability,
            severity=severity,
            rule_id=rule_id,
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
        fix_stage_of: dict[str, str] | None = None,
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
            # `fixable` is about the group, and a group is one decision even
            # when it has forty occurrences: if Patchwork produced a fix for
            # any of them, the row is actionable.
            stages = {
                (fix_stage_of or {}).get(str(location["finding_id"]))
                for location in group["locations"]
            }
            if stages & _FIX_PRODUCED:
                group["fixable"] = True
            elif stages & _FIX_REFUSED:
                group["fixable"] = False
            else:
                group["fixable"] = None
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
        rule_id: str | None = None,
        limit: int = 100,
        kev_only: bool = False,
        min_epss: float | None = None,
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
        if rule_id:
            where.append("(rule_id ILIKE ? OR title ILIKE ?)")
            needle = f"%{rule_id}%"
            params += [needle, needle]
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
        # Same reasoning as open_findings() (spec 17 §3, #20): a KEV/EPSS filter
        # is applied in Python against a different database, so the SQL
        # fetch has to stay generous enough that LIMIT doesn't cut candidates
        # before the filter ever sees them.
        wants_threat_intel_filter = kev_only or min_epss is not None
        fetch_limit = CORRELATION_CEILING if wants_threat_intel_filter else limit
        rows = self.catalog.query(
            f"SELECT {', '.join(columns)} FROM findings WHERE {clause} "
            "ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, first_seen_at "
            "LIMIT ?",
            [*params, fetch_limit],
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

        # cve_id/in_kev/epss_score stamped onto every row (spec 17 §4.4, #20) —
        # not conditional on the filter being active, so a caller can render
        # the badge whether or not they're also filtering by it.
        self._attach_threat_intel(session, queue)
        if kev_only:
            queue = [item for item in queue if item["in_kev"]]
        if min_epss is not None:
            queue = [
                item
                for item in queue
                if item["epss_score"] is not None and item["epss_score"] >= min_epss
            ]
        queue = queue[:limit]

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

    def sscs_evidence_row(self, repo_full_name: str, evidence_id: str) -> dict[str, Any] | None:
        """One evidence row by id, for the SBOM download (spec 18 §8.2).

        Scoped to `repo_full_name` as well as `evidence_id` — an evidence id
        from a different repository should 404, not silently serve a file
        that repository's admin never granted access to.
        """
        rows = self.catalog.query(
            "SELECT sbom_ref FROM sscs_evidence WHERE repo_full_name = ? AND evidence_id = ?",
            [repo_full_name, evidence_id],
        )
        if not rows:
            return None
        return {"sbom_ref": rows[0][0]}

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
        recent = self._recent_scan_runs(repo_full_name)
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
                    # The last run's own detail text (spec 19 §1.2) — the
                    # aggregate above has no room for one run's message, and
                    # a box showing "70% succeeded" says nothing about what
                    # the most recent failure actually was.
                    "detail": recent.get(str(capability), [{}])[0].get("detail"),
                    # Same commit, disagreeing status (spec 19 §1.3) — a
                    # flake, not a regression. Two rows is enough to say so;
                    # a longer streak would only change how loudly, not
                    # whether.
                    "flaky": _is_flaky(recent.get(str(capability), [])),
                }
            )
        return health

    def _recent_scan_runs(
        self, repo_full_name: str, per_capability: int = 2
    ) -> dict[str, list[dict[str, Any]]]:
        """The last `per_capability` runs of every capability, newest first.

        One windowed query rather than one query per capability — this feeds
        `scan_health()`, which already returns every capability for a repo in
        one call, and a per-capability query here would turn that one call
        into fifteen.
        """
        rows = self.catalog.query(
            """
            SELECT capability, commit_sha, scan_status, detail, completed_at FROM (
                SELECT capability, commit_sha, scan_status, detail, completed_at,
                       row_number() OVER (
                           PARTITION BY capability
                           -- `ingested_at` and `scan_run_id` break the tie
                           -- explicitly. Without them two runs whose
                           -- timestamps compare equal — a scan registered
                           -- and finalised inside the same clock tick, which
                           -- is most of them on a fast machine — came back in
                           -- whichever order the Parquet scan happened to
                           -- produce, so "the most recent run" flipped
                           -- between two identical calls.
                           ORDER BY coalesce(completed_at, started_at) DESC,
                                    ingested_at DESC,
                                    scan_run_id DESC
                       ) AS rn
                FROM scan_runs
                WHERE repo_full_name = ?
            ) WHERE rn <= ?
            """,
            [repo_full_name, per_capability],
        )
        by_capability: dict[str, list[dict[str, Any]]] = {}
        for capability, commit_sha, scan_status, detail, completed_at in rows:
            by_capability.setdefault(str(capability), []).append(
                {
                    "commit_sha": commit_sha,
                    "scan_status": str(scan_status),
                    "detail": detail,
                    "completed_at": completed_at,
                }
            )
        return by_capability

    def scan_run_trend(
        self,
        repo_full_name: str,
        capability: str,
        *,
        days: int = 90,
        points: int = 12,
    ) -> list[dict[str, Any]]:
        """One lane's pass rate over time (spec 19 §1.1) — `scan_health()`
        only ever shows the current rate; a lane that has been sliding for
        two weeks looks identical to one that just started failing today
        unless something plots the history.

        Bucketed, not reconstructed: each point is "runs completed in this
        window," not a point-in-time snapshot the way `trend_series` replays
        open findings — a scan either ran in a window or it didn't, there is
        no "was still running" state to reconstruct.
        """
        now = utcnow()
        step = timedelta(days=days / points)
        series: list[dict[str, Any]] = []
        for index in range(points, 0, -1):
            end = now - step * (index - 1)
            start = end - step
            rows = self.catalog.query(
                """
                SELECT count(*),
                       sum(CASE WHEN scan_status = 'success' THEN 1 ELSE 0 END)
                FROM scan_runs
                WHERE repo_full_name = ? AND capability = ?
                  AND coalesce(completed_at, started_at) >= ?
                  AND coalesce(completed_at, started_at) < ?
                """,
                [repo_full_name, capability, start, end],
            )
            runs, succeeded = (int(rows[0][0]), int(rows[0][1] or 0)) if rows else (0, 0)
            series.append(
                {
                    "at": end,
                    "runs": runs,
                    # Null, not zero, for a window with nothing in it — a gap
                    # in coverage and a lane that failed every run both would
                    # otherwise plot at the same point (spec 05 §7a's "not
                    # assessed is not the same as zero" convention).
                    "success_rate": round(succeeded / runs, 3) if runs else None,
                }
            )
        return series

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
            "owner",
            "owner_source",
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

    # -- threat intelligence ---------------------------------------------

    @staticmethod
    def _kev_cve_ids(session: Session, findings: Any) -> set[str]:
        """Which CVEs named by `findings` are KEV-listed (spec 17 §5.6).

        `findings` is any iterable of finding dicts with `rule_id`/`title` —
        the correlation pool here, but nothing about this method is specific
        to it. A pure lookup, not a fetch: this reads `ThreatIntelMatch` rows
        already in the operational database and never calls a feed itself.
        """
        cves = {
            extract_cve(str(f.get("rule_id") or ""), str(f.get("title") or ""))
            for f in findings
        }
        cves.discard(None)
        if not cves:
            return set()
        rows = session.execute(
            select(ThreatIntelMatch.cve_id).where(
                ThreatIntelMatch.cve_id.in_(cves), ThreatIntelMatch.in_kev.is_(True)
            )
        ).scalars()
        return {str(row) for row in rows}

    @staticmethod
    def _attach_threat_intel(session: Session, rows: list[dict[str, Any]]) -> None:
        """Stamp `cve_id`/`in_kev`/`epss_score` onto each row, in place
        (spec 17 §4.4, #20). `None` for a row naming no CVE — distinct from
        `in_kev: False`, which means a CVE was found and checked. Mutates
        rather than returns a new list: every other per-row field here is
        already attached this way (`_group_findings`), and a second
        convention would be the odd one out.

        Generic over what `rows` actually are — grouped findings
        (`group_key`) or flat triage-queue rows (`finding_id`) both work,
        keyed here by Python object identity rather than either field name,
        since the two callers don't share one.
        """
        cve_by_key: dict[int, str] = {}
        for row in rows:
            cve_id = extract_cve(str(row.get("rule_id") or ""), str(row.get("title") or ""))
            row["cve_id"] = cve_id
            row["in_kev"] = None
            row["epss_score"] = None
            if cve_id:
                cve_by_key[id(row)] = cve_id

        if not cve_by_key:
            return

        matches = {
            match.cve_id: match
            for match in session.execute(
                select(ThreatIntelMatch).where(
                    ThreatIntelMatch.cve_id.in_(set(cve_by_key.values()))
                )
            ).scalars()
        }
        for row in rows:
            cve_id = cve_by_key.get(id(row))
            if cve_id is None:
                continue
            match = matches.get(cve_id)
            # Three states, not two: `in_kev` stays `None` above when the
            # row names no CVE at all; it becomes `False` here — "a CVE was
            # checked, and it isn't KEV-listed (or hasn't been fetched yet)"
            # — only once one was found to check.
            row["in_kev"] = bool(match and match.in_kev)
            row["epss_score"] = match.epss_score if match else None

    def threat_intel(self, session: Session) -> list[dict[str, Any]]:
        """Every CVE currently matched to an open finding somewhere in the
        portfolio, KEV first then EPSS descending (spec 17 §4.4).

        A different ordering from the triage queue's severity-then-age on
        purpose: EPSS moves day to day in a way severity doesn't, and this
        answers "what does the outside world think matters right now"
        rather than "what is worst by our own static rating".

        Joined in Python against the operational database — same rule as
        `portfolio()` (module docstring): the row count on either side is a
        few hundred at most, and an extension dependency to join across
        stores would buy nothing a Python dict doesn't already do.
        """
        rows = self.catalog.query(
            "SELECT repo_full_name, finding_id, rule_id, title, severity "
            "FROM findings WHERE status = 'open'"
        )

        by_cve: dict[str, dict[str, Any]] = {}
        for repo, finding_id, rule_id, title, severity in rows:
            cve_id = extract_cve(str(rule_id), str(title))
            if cve_id is None:
                continue
            entry = by_cve.setdefault(
                cve_id,
                {
                    "cve_id": cve_id,
                    "repos": set(),
                    "finding_ids": set(),
                    "worst_severity": str(severity),
                },
            )
            entry["repos"].add(str(repo))
            entry["finding_ids"].add(str(finding_id))
            if _worse(str(severity), str(entry["worst_severity"])):
                entry["worst_severity"] = str(severity)

        if not by_cve:
            return []

        matches = {
            row.cve_id: row
            for row in session.execute(
                select(ThreatIntelMatch).where(ThreatIntelMatch.cve_id.in_(by_cve))
            ).scalars()
        }

        results = []
        for cve_id, entry in by_cve.items():
            match = matches.get(cve_id)
            results.append(
                {
                    "cve_id": cve_id,
                    "in_kev": match.in_kev if match else False,
                    "kev_added_at": match.kev_added_at if match else None,
                    "kev_due_date": match.kev_due_date if match else None,
                    "epss_score": match.epss_score if match else None,
                    "epss_percentile": match.epss_percentile if match else None,
                    "fetched_at": match.fetched_at if match else None,
                    "worst_severity": entry["worst_severity"],
                    "repo_full_names": sorted(entry["repos"]),
                    "finding_count": len(entry["finding_ids"]),
                }
            )

        # KEV first, then EPSS descending (nulls last) — spec 17 §4.4.
        results.sort(key=lambda r: (not r["in_kev"], -(r["epss_score"] or 0.0)))
        return results
