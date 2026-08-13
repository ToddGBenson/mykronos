"""Maturity tiers and trend series (spec 10 §2.3).

Two things a portfolio owner asks that no other view answers: *is this getting
better*, and *what should this team do next*.

**Every tier shows its working.** A tier is a derived label, and spec 10 §6
forbids dashboard-only numbers that cannot be traced back to lake rows. So the
assessment carries every criterion with its measured value, its threshold and
its verdict, and names the specific thing standing between the repo and the
next tier. "Tier 2" on its own would be exactly the kind of number this spec
exists to prevent.

**No time-series table.** Every series is reconstructed from records already
held: a `Finding` carries `first_seen_at` and `resolved_at`, so the open count
on any past date is a query rather than a snapshot. A parallel table of daily
rollups would be a second copy of the truth, able to disagree with the first.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from mykronos.lake.catalog import Catalog
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)


class MaturityModelError(ValueError):
    """A model that cannot be loaded. Refused rather than half-applied."""


@dataclass(frozen=True)
class Criterion:
    key: str
    label: str
    metric: str
    why: str
    at_least: float | None = None
    at_most: float | None = None

    def passes(self, value: float | None) -> bool:
        if value is None:
            return False
        if self.at_least is not None and value < self.at_least:
            return False
        return not (self.at_most is not None and value > self.at_most)

    def threshold(self) -> str:
        if self.at_least is not None:
            return f"≥ {self.at_least:g}"
        if self.at_most is not None:
            return f"≤ {self.at_most:g}"
        return "—"


@dataclass(frozen=True)
class Tier:
    id: str
    name: str
    summary: str
    requires: tuple[str, ...]


@dataclass(frozen=True)
class MaturityModel:
    version: str
    tiers: tuple[Tier, ...]
    criteria: dict[str, Criterion]


def parse_model(document: dict[str, Any]) -> MaturityModel:
    if not isinstance(document, dict):
        raise MaturityModelError("The maturity model must be a YAML mapping.")

    raw_criteria = document.get("criteria") or {}
    criteria: dict[str, Criterion] = {}
    for key, body in raw_criteria.items():
        if "at_least" not in body and "at_most" not in body:
            raise MaturityModelError(
                f"Criterion {key!r} sets neither at_least nor at_most, so it "
                "can never fail. A criterion that always passes is worse than "
                "no criterion: it inflates every tier silently."
            )
        criteria[key] = Criterion(
            key=key,
            label=str(body.get("label", key)),
            metric=str(body["metric"]),
            why=str(body.get("why", "")).strip(),
            at_least=body.get("at_least"),
            at_most=body.get("at_most"),
        )

    tiers = []
    for entry in document.get("tiers") or []:
        requires = tuple(entry.get("requires") or ())
        unknown = [r for r in requires if r not in criteria]
        if unknown:
            raise MaturityModelError(
                f"Tier {entry.get('id')!r} requires unknown criteria: "
                f"{', '.join(unknown)}. A tier gated on a criterion that does "
                "not exist is a tier nothing can reach."
            )
        tiers.append(
            Tier(
                id=str(entry["id"]),
                name=str(entry.get("name", entry["id"])),
                summary=str(entry.get("summary", "")).strip(),
                requires=requires,
            )
        )

    if not tiers:
        raise MaturityModelError("The maturity model defines no tiers.")

    return MaturityModel(
        version=str(document.get("version", "0")),
        tiers=tuple(tiers),
        criteria=criteria,
    )


def load_model(path: Path) -> MaturityModel:
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise MaturityModelError(
            f"No maturity model at {path}. Expected {path.name} at the "
            "repository root, versioned alongside the Oracle policy."
        ) from exc
    except yaml.YAMLError as exc:
        raise MaturityModelError(f"{path} is not valid YAML: {exc}") from exc
    return parse_model(document)


@lru_cache(maxsize=4)
def cached_model(path: Path) -> MaturityModel:
    return load_model(path)


# --------------------------------------------------------------------------
# Metrics
# --------------------------------------------------------------------------
#
# Each returns a number, or None when the question cannot be answered for this
# repo. None fails its criterion — "we could not tell" is not a pass, and a
# maturity model that awarded tiers for absent data would reward having no
# data at all.

Metric = Callable[[Catalog, str, datetime], float | None]


def _scalar(catalog: Catalog, sql: str, params: list[Any]) -> float | None:
    rows = catalog.query(sql, params)
    if not rows or rows[0][0] is None:
        return None
    return float(rows[0][0])


def capabilities_with_scans(catalog: Catalog, repo: str, now: datetime) -> float | None:
    return _scalar(
        catalog,
        "SELECT count(DISTINCT capability) FROM scan_runs WHERE repo_full_name = ?",
        [repo],
    )


def days_since_last_scan(catalog: Catalog, repo: str, now: datetime) -> float | None:
    rows = catalog.query(
        "SELECT max(coalesce(completed_at, started_at)) FROM scan_runs "
        "WHERE repo_full_name = ?",
        [repo],
    )
    if not rows or rows[0][0] is None:
        return None
    return float((now - rows[0][0]).total_seconds()) / 86_400


def stale_untouched_ratio(catalog: Catalog, repo: str, now: datetime) -> float | None:
    """Open findings older than 30 days, as a share of all open findings.

    Deliberately a ratio rather than a count. A repository with four hundred
    findings and a team working steadily through them is not less mature than
    one with four; penalising volume would reward scanning less.
    """
    rows = catalog.query(
        "SELECT count(*), count(*) FILTER (WHERE first_seen_at <= ?) "
        "FROM findings WHERE repo_full_name = ? AND status = 'open'",
        [now - timedelta(days=30), repo],
    )
    if not rows:
        return None
    total, stale = int(rows[0][0]), int(rows[0][1])
    if total == 0:
        # Nothing open. Not "unknown" — there is nothing rotting, which is
        # what this measures.
        return 0.0
    return stale / total


def portfolio_decisions(catalog: Catalog, repo: str, now: datetime) -> float | None:
    return _scalar(
        catalog,
        "SELECT count(*) FROM risk_decisions "
        "WHERE repo_full_name = ? AND decision_type = 'portfolio'",
        [repo],
    )


def sscs_evidence_count(catalog: Catalog, repo: str, now: datetime) -> float | None:
    """Rows that actually assessed something (spec 07 §5a).

    A row with a null trust score records that a scan ran and resolved no
    dependencies. That is worth keeping — it is how the dashboard says "not
    assessed" rather than showing nothing — but it is not supply-chain
    evidence, and counting it would let a repository climb a maturity tier on
    scans that inspected nothing.
    """
    return _scalar(
        catalog,
        "SELECT count(*) FROM sscs_evidence "
        "WHERE repo_full_name = ? AND trust_score IS NOT NULL",
        [repo],
    )


def aged_criticals(catalog: Catalog, repo: str, now: datetime) -> float | None:
    return _scalar(
        catalog,
        "SELECT count(*) FROM findings WHERE repo_full_name = ? "
        "AND status = 'open' AND severity = 'critical' AND first_seen_at <= ?",
        [repo, now - timedelta(days=30)],
    )


def decided_pull_requests(catalog: Catalog, repo: str, now: datetime) -> float | None:
    """Judged pull requests with a known outcome — the shadow-mode signal."""
    return _scalar(
        catalog,
        "SELECT count(*) FROM risk_decisions WHERE repo_full_name = ? "
        "AND decision_type = 'pr_gate' AND gate_outcome IS NOT NULL",
        [repo],
    )


#: Lake-only metrics. `reasoned_dismissal_ratio` is deliberately absent: its
#: numerator lives in the Knowledge Store, so `assess` handles it separately
#: rather than pretending it has the same shape as the others.
METRICS: dict[str, Metric] = {
    "capabilities_with_scans": capabilities_with_scans,
    "days_since_last_scan": days_since_last_scan,
    "stale_untouched_ratio": stale_untouched_ratio,
    "portfolio_decisions": portfolio_decisions,
    "sscs_evidence_count": sscs_evidence_count,
    "aged_criticals": aged_criticals,
    "decided_pull_requests": decided_pull_requests,
}


# --------------------------------------------------------------------------
# Assessment
# --------------------------------------------------------------------------


@dataclass
class CriterionResult:
    key: str
    label: str
    why: str
    threshold: str
    value: float | None
    passed: bool

    @property
    def measured(self) -> str:
        if self.value is None:
            return "no data"
        if self.value == int(self.value):
            return str(int(self.value))
        return f"{self.value:.2f}"


@dataclass
class MaturityAssessment:
    repo_full_name: str
    model_version: str
    tier_id: str
    tier_name: str
    tier_summary: str
    tier_index: int
    total_tiers: int
    criteria: list[CriterionResult] = field(default_factory=list)
    next_tier_name: str | None = None
    blocking: list[CriterionResult] = field(default_factory=list)

    @property
    def at_top(self) -> bool:
        return self.tier_index == self.total_tiers - 1


def assess(
    catalog: Catalog,
    repo_full_name: str,
    model: MaturityModel,
    *,
    store: Any = None,
    as_of: datetime | None = None,
) -> MaturityAssessment:
    """Score one repository against the model (spec 10 §2.3).

    `store` is the Knowledge Store, needed only for the reasoned-dismissal
    ratio — it is the one criterion whose numerator lives outside the lake,
    because "did somebody write a reason" is a fact about the learning, not
    about the finding.
    """
    now = as_of or utcnow()
    measured: dict[str, float | None] = {}

    for key, criterion in model.criteria.items():
        if criterion.metric == "reasoned_dismissal_ratio":
            measured[key] = _reasoned_ratio(catalog, store, repo_full_name)
            continue
        metric = METRICS.get(criterion.metric)
        if metric is None:
            logger.warning(
                "Criterion %s names unknown metric %s; treating as unmet",
                key,
                criterion.metric,
            )
            measured[key] = None
            continue
        try:
            measured[key] = metric(catalog, repo_full_name, now)
        except Exception as exc:  # noqa: BLE001
            # One unreadable partition must not cost the whole assessment.
            logger.warning("Metric %s failed for %s: %s", criterion.metric, repo_full_name, exc)
            measured[key] = None

    results = {
        key: CriterionResult(
            key=key,
            label=criterion.label,
            why=criterion.why,
            threshold=criterion.threshold(),
            value=measured[key],
            passed=criterion.passes(measured[key]),
        )
        for key, criterion in model.criteria.items()
    }

    # Highest tier whose criteria all pass. Cumulative and non-skipping: the
    # scan stops at the first tier that fails, so a repo cannot leapfrog a gap.
    reached = 0
    for index, tier in enumerate(model.tiers):
        if all(results[key].passed for key in tier.requires):
            reached = index
        else:
            break

    tier = model.tiers[reached]
    next_tier = model.tiers[reached + 1] if reached + 1 < len(model.tiers) else None

    return MaturityAssessment(
        repo_full_name=repo_full_name,
        model_version=model.version,
        tier_id=tier.id,
        tier_name=tier.name,
        tier_summary=tier.summary,
        tier_index=reached,
        total_tiers=len(model.tiers),
        criteria=[results[key] for key in model.criteria],
        next_tier_name=next_tier.name if next_tier else None,
        # Only what actually stands in the way. A list of every unmet
        # criterion in the model would bury the one thing to do next.
        blocking=(
            [results[k] for k in next_tier.requires if not results[k].passed]
            if next_tier
            else []
        ),
    )


def _reasoned_ratio(catalog: Catalog, store: Any, repo_full_name: str) -> float | None:
    """Share of this repo's dismissals that carry a written reason.

    Denominator from the lake (every finding marked `false_positive`),
    numerator from the Knowledge Store (dismissals that produced a reasoned
    entry). Taking both from the store would be asking a population filtered
    on the property being measured.
    """
    rows = catalog.query(
        "SELECT count(*) FROM findings "
        "WHERE repo_full_name = ? AND status = 'false_positive'",
        [repo_full_name],
    )
    dismissals = int(rows[0][0]) if rows else 0
    if dismissals == 0:
        return None
    if store is None:
        return None

    try:
        reasoned = sum(
            entry.observations
            for entry in store.list_entries()
            if entry.source_type == "finding_dismissal"
            and entry.repo_full_name == repo_full_name
            and entry.has_reason
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not read the Knowledge Store for %s: %s", repo_full_name, exc)
        return None

    return float(min(1.0, reasoned / dismissals))


# --------------------------------------------------------------------------
# Trends
# --------------------------------------------------------------------------


@dataclass
class TrendPoint:
    at: datetime
    open_critical: int = 0
    open_high: int = 0
    open_total: int = 0
    risk_score: int | None = None
    trust_score: int | None = None


def trend_series(
    catalog: Catalog,
    repo_full_name: str | None = None,
    *,
    days: int = 90,
    points: int = 12,
    as_of: datetime | None = None,
) -> list[TrendPoint]:
    """Open findings, risk and supply-chain trust over time (spec 10 §2.3).

    Reconstructed, not stored. A finding was open at instant *t* if it was
    first seen before *t* and had not been resolved by *t* — so the whole
    series comes out of the rows already held, and there is no rollup table
    able to disagree with them.

    `repo_full_name` of None means the whole portfolio.
    """
    now = as_of or utcnow()
    step = timedelta(days=days / points)
    scope = "AND repo_full_name = ?" if repo_full_name else ""
    repo_param: list[Any] = [repo_full_name] if repo_full_name else []

    series: list[TrendPoint] = []
    for index in range(points, 0, -1):
        at = now - step * (index - 1)

        rows = catalog.query(
            f"""
            SELECT
                count(*) FILTER (WHERE severity = 'critical'),
                count(*) FILTER (WHERE severity = 'high'),
                count(*)
            FROM findings
            WHERE first_seen_at <= ?
              AND (resolved_at IS NULL OR resolved_at > ?)
              {scope}
            """,
            [at, at, *repo_param],
        )
        critical, high, total = (int(v or 0) for v in rows[0]) if rows else (0, 0, 0)

        # The most recent decision and evidence *as of that instant* — not the
        # latest overall, which would draw a flat line at today's value.
        risk = catalog.query(
            f"""
            SELECT overall_risk_score FROM risk_decisions
            WHERE decision_type = 'portfolio' AND evaluated_at <= ? {scope}
            ORDER BY evaluated_at DESC LIMIT 1
            """,
            [at, *repo_param],
        )
        # Not filtered to assessed rows. If the most recent evidence at this
        # instant resolved nothing, the point is a gap (spec 07 §5a) rather
        # than the last real score carried forward — the line should break
        # where the measurement stopped, not coast on an older number.
        trust = catalog.query(
            f"""
            SELECT trust_score FROM sscs_evidence
            WHERE evaluated_at <= ? {scope}
            ORDER BY evaluated_at DESC LIMIT 1
            """,
            [at, *repo_param],
        )

        series.append(
            TrendPoint(
                at=at,
                open_critical=critical,
                open_high=high,
                open_total=total,
                risk_score=int(risk[0][0]) if risk else None,
                trust_score=(
                    int(trust[0][0])
                    if trust and trust[0][0] is not None
                    else None
                ),
            )
        )
    return series


def mean_time_to_fix(
    catalog: Catalog, repo_full_name: str | None = None, *, days: int = 180
) -> float | None:
    """Average days from first seen to resolved, over recently-fixed findings.

    Windowed rather than all-time, because an all-time mean is dominated by
    whatever happened when the platform was first switched on and stops
    responding to the present. Only `fixed` counts: a finding somebody
    dismissed was not fixed, and letting dismissals into this number would
    make the fastest way to improve it a click.
    """
    scope = "AND repo_full_name = ?" if repo_full_name else ""
    params: list[Any] = [utcnow() - timedelta(days=days)]
    if repo_full_name:
        params.append(repo_full_name)

    rows = catalog.query(
        f"""
        SELECT avg(date_diff('second', first_seen_at, resolved_at))
        FROM findings
        WHERE status = 'fixed' AND resolved_at IS NOT NULL AND resolved_at >= ?
        {scope}
        """,
        params,
    )
    if not rows or rows[0][0] is None:
        return None
    return float(rows[0][0]) / 86_400
