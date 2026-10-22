"""Product-specific signals in the per-product briefing (TheHub #60863, epic
#60858).

The per-product page answers the same questions for every repository: is
production current, what changed in the findings, can the lanes be believed,
what is worth a sprint. Each product also has questions only it has. This is
the block that asks them:

- **TheHub**: feature use, agent run success, AI gateway spend, scheduler
  failures, data freshness, backups.
- **MyKronos**: ingestion success, scan freshness, Oracle shadow agreement,
  premise transitions, false-positive rate, time to close. These are the
  platform's own health, so they are measured across the estate.
- **personal-soc**: new LAN hosts, WAN ports against the allowlist, NAS
  posture, scan age.
- **keel**: template drift and scanner versions.
- **binnacle**: ingestion volume and gaps.

**Every listed signal is on the page.** One MyKronos can measure today is
`measured`. One it cannot measure yet is `not_measurable`, and the section's
reason names it with the reason (`not measurable yet: ...`). One whose source
failed this time is `unavailable`, with the reason. None is ever left out:
leaving a signal out reads as all clear, which is the failure the briefing
was built against (#401).

**Sources are what MyKronos already holds, plus TheHub's read API.** The lake
(scan runs, findings, risk decisions), `netassess_runs`,
`control_observations` and the audit log. TheHub's signals come through the
Product Owner tab's `HubClient`, read-only, from routes TheHub already serves.
Those reads run in parallel under one timeout and are cached for
`HUB_TTL_SECONDS`, like the board read in `delivery_sources`.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import Counter
from contextlib import suppress
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select

from mykronos.daily_briefing import (
    CURRENT_FINDINGS,
    DECISION,
    NOT_AVAILABLE,
    OK,
    PARTIAL,
    STORY,
    Line,
    Section,
    _error,
    _naive,
)
from mykronos.lake.catalog import Catalog

logger = logging.getLogger(__name__)

MEASURED = "measured"
NOT_MEASURABLE = "not_measurable"
UNAVAILABLE = "unavailable"

#: Which signals each product's block carries, in the order it shows them.
#: The key is the repository's name (`owner/<name>`), lower-cased.
EXPECTED: dict[str, tuple[tuple[str, str], ...]] = {
    "thehub": (
        ("feature_use", "Feature use"),
        ("agent_run_success", "Agent run success"),
        ("ai_gateway_spend", "AI gateway spend"),
        ("scheduler_failures", "Scheduler failures"),
        ("data_freshness", "Data freshness"),
        ("backups", "Backups"),
    ),
    "mykronos": (
        ("ingestion_success", "Ingestion success"),
        ("scan_freshness", "Scan freshness"),
        ("oracle_shadow_agreement", "Oracle shadow agreement"),
        ("premise_transitions", "Premise transitions"),
        ("false_positive_rate", "False-positive rate"),
        ("time_to_close", "Time to close"),
    ),
    "personal-soc": (
        ("new_lan_hosts", "New LAN hosts"),
        ("wan_ports", "WAN ports vs the allowlist"),
        ("nas_posture", "NAS posture"),
        ("scan_age", "Scan age"),
    ),
    "keel": (
        ("template_drift", "Template drift"),
        ("scanner_versions", "Scanner versions"),
    ),
    "binnacle": (
        ("ingestion_volume", "Ingestion volume"),
        ("ingestion_gaps", "Ingestion gaps"),
    ),
}

#: The window the rates are measured over.
WEEK = timedelta(days=7)
MONTH = timedelta(days=30)

#: A repository with no scan for this long is stale.
STALE_SCAN_HOURS = 72
#: `netassess.freshness`'s own limit: a weekly scan older than this is late.
NETASSESS_MAX_AGE_DAYS = 10
#: binnacle's window, and how many silent days running count as a gap.
INGESTION_WINDOW_DAYS = 14
GAP_DAYS = 2

#: How long one TheHub answer is reused, and how long all of them may take.
HUB_TTL_SECONDS = 120.0
HUB_TIMEOUT_SECONDS = 15.0
#: Freshness contracts read per page, at most, a few at a time.
MAX_CONTRACTS = 25
HUB_CONCURRENCY = 5

#: Agent run outcomes TheHub's autonomy dashboard counts as a success.
AGENT_SUCCESS = ("success", "succeeded", "completed", "merged", "done", "shipped")
#: A freshness run in one of these states is within its contract.
FRESH_STATES = ("ok", "pass", "passed", "fresh", "healthy")

SECTION_KEY = "product_signals"
SECTION_TITLE = "Product signals"


@dataclass
class Signal:
    key: str
    label: str
    #: measured | not_measurable | unavailable
    status: str
    #: Where it was read from, or would be.
    source: str
    #: One line a person reads: the measurement.
    value: str = ""
    #: The numbers behind `value`.
    detail: dict[str, Any] = field(default_factory=dict)
    #: For `not_measurable`, why not yet; for `unavailable`, what failed.
    reason: str = ""


def product_of(repo_full_name: str) -> str | None:
    name = repo_full_name.rsplit("/", 1)[-1].lower()
    return name if name in EXPECTED else None


def _not_measurable(key: str, label: str, source: str, why: str) -> Signal:
    return Signal(key=key, label=label, status=NOT_MEASURABLE, source=source,
                  reason=f"not measurable yet: {why}")


def _unavailable(key: str, label: str, source: str, why: str) -> Signal:
    return Signal(key=key, label=label, status=UNAVAILABLE, source=source, reason=why)


def _pct(part: int, whole: int) -> float | None:
    return round(part / whole, 3) if whole else None


def _fmt_pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.0%}"


# ---------------------------------------------------------------------------
# TheHub: the reads
# ---------------------------------------------------------------------------


@dataclass
class HubRead:
    """One TheHub answer: the body, or why there is none. `missing` is a 404:
    the route is not on that TheHub, which is not the same as a failure."""

    body: Any = None
    error: str = ""
    missing: bool = False


@dataclass
class ProductSignalInputs:
    """What was read from outside the lake and the database for one product."""

    #: path -> answer, for TheHub's page only.
    hub: dict[str, HubRead] = field(default_factory=dict)
    #: Why TheHub was not asked, when it was not.
    hub_error: str = ""
    as_of: datetime | None = None


AUTONOMY = "/api/devops/autonomy/dashboard"
USAGE = "/api/aiops/usage-summary"
SCHEDULER = "/api/ops/scheduler/health"
BACKUPS = "/api/backup/health"
CONTRACTS = "/api/dataops/contracts"

_hub_cache: dict[int, tuple[float, Any, ProductSignalInputs]] = {}


def clear_cache() -> None:
    _hub_cache.clear()


async def _one(hub: Any, path: str, params: dict[str, Any] | None = None) -> HubRead:
    from mykronos.delivery_sources import _error as delivery_error

    try:
        body = await hub.get_json(path, params=params)
    except Exception as exc:  # noqa: BLE001 - one read must not lose the rest
        return HubRead(error=delivery_error(exc))
    if body is None:
        return HubRead(missing=True)
    return HubRead(body=body)


async def _read_hub(hub: Any) -> dict[str, HubRead]:
    autonomy, usage, scheduler, backups, contracts = await asyncio.gather(
        _one(hub, AUTONOMY),
        _one(hub, USAGE, {"top_features_window": "7d"}),
        _one(hub, SCHEDULER),
        _one(hub, BACKUPS),
        _one(hub, CONTRACTS, {"enabled_only": "true"}),
    )
    reads = {AUTONOMY: autonomy, USAGE: usage, SCHEDULER: scheduler, BACKUPS: backups,
             CONTRACTS: contracts}
    if isinstance(contracts.body, list):
        gate = asyncio.Semaphore(HUB_CONCURRENCY)
        ids = [c.get("id") for c in contracts.body if isinstance(c, dict)][:MAX_CONTRACTS]

        async def runs(contract_id: Any) -> tuple[str, HubRead]:
            path = f"{CONTRACTS}/{contract_id}/runs"
            async with gate:
                return path, await _one(hub, path, {"limit": 1})

        for path, read in await asyncio.gather(*(runs(i) for i in ids)):
            reads[path] = read
    return reads


async def gather(state: Any, repo_full_name: str) -> ProductSignalInputs:
    """TheHub's reads, for TheHub's own page; nothing for any other. Never
    raises."""
    from mykronos.delivery_sources import HUB_NOT_CONNECTED
    from mykronos.schemas import utcnow

    if product_of(repo_full_name) != "thehub":
        return ProductSignalInputs()
    hub = getattr(state, "hub", None)
    if hub is None:
        return ProductSignalInputs(hub_error=HUB_NOT_CONNECTED)
    now = time.monotonic()
    cached = _hub_cache.get(id(hub))
    if cached is not None and cached[1] is hub and now - cached[0] < HUB_TTL_SECONDS:
        return cached[2]
    try:
        reads = await asyncio.wait_for(_read_hub(hub), HUB_TIMEOUT_SECONDS)
    except Exception:  # noqa: BLE001 - reported per signal, never as all clear
        logger.debug("Could not read TheHub's product signals")
        return ProductSignalInputs(hub_error="TheHub did not answer in time.")
    inputs = ProductSignalInputs(hub=reads, as_of=utcnow())
    _hub_cache[id(hub)] = (now, hub, inputs)
    return inputs


# ---------------------------------------------------------------------------
# TheHub: the signals
# ---------------------------------------------------------------------------


def _hub_signal(
    inputs: ProductSignalInputs, path: str, key: str, label: str
) -> tuple[Any, Signal | None]:
    """The body to measure from, or the signal that says why there is none."""
    source = f"TheHub GET {path}"
    if inputs.hub_error:
        return None, _unavailable(key, label, source, inputs.hub_error)
    read = inputs.hub.get(path)
    if read is None:
        return None, _unavailable(key, label, source, "TheHub was not asked.")
    if read.missing:
        return None, _not_measurable(
            key, label, source, f"TheHub answered 404 for {path}, so this TheHub does "
            "not serve it."
        )
    if read.error:
        return None, _unavailable(key, label, source, read.error)
    return read.body, None


def thehub_signals(inputs: ProductSignalInputs) -> tuple[list[Signal], list[Line]]:
    signals: list[Signal] = []
    lines: list[Line] = []
    repo = "ToddGBenson/TheHub"

    signals.append(_not_measurable(
        "feature_use", "Feature use", "TheHub API",
        "TheHub serves no read route for product feature use; AI spend by feature "
        "is under AI gateway spend.",
    ))

    body, gap = _hub_signal(inputs, AUTONOMY, "agent_run_success", "Agent run success")
    if gap is None:
        outcomes = body.get("last_7d_outcomes") if isinstance(body, dict) else None
        if not isinstance(outcomes, dict):
            gap = _unavailable("agent_run_success", "Agent run success", f"TheHub GET {AUTONOMY}",
                               "TheHub's answer had no last_7d_outcomes.")
        else:
            counts = {str(k): int(v or 0) for k, v in outcomes.items()}
            total = sum(counts.values())
            ok = sum(n for k, n in counts.items() if k.lower() in AGENT_SUCCESS)
            rate = _pct(ok, total)
            signals.append(Signal(
                key="agent_run_success", label="Agent run success", status=MEASURED,
                source=f"TheHub GET {AUTONOMY} (last_7d_outcomes)",
                value=f"{ok} of {total} autonomous run(s) succeeded in 7 days "
                f"({_fmt_pct(rate)})." if total else "No autonomous runs in 7 days.",
                detail={"outcomes": counts, "succeeded": ok, "total": total, "rate": rate,
                        "success_outcomes": list(AGENT_SUCCESS)},
            ))
    if gap is not None:
        signals.append(gap)

    body, gap = _hub_signal(inputs, USAGE, "ai_gateway_spend", "AI gateway spend")
    if gap is None:
        series = (body.get("daily_trend") or {}).get("series") if isinstance(body, dict) else None
        if not isinstance(series, list):
            gap = _unavailable("ai_gateway_spend", "AI gateway spend", f"TheHub GET {USAGE}",
                               "TheHub's answer had no daily_trend series.")
        else:
            days = [d for d in series if isinstance(d, dict)]
            week = days[-7:]
            spend = round(sum(float(d.get("total_cost_usd") or 0) for d in week), 2)
            today = float(week[-1].get("total_cost_usd") or 0) if week else 0.0
            requests = sum(int(d.get("total_requests") or 0) for d in week)
            signals.append(Signal(
                key="ai_gateway_spend", label="AI gateway spend", status=MEASURED,
                source=f"TheHub GET {USAGE} (daily_trend)",
                value=f"${spend:,.2f} over {len(week)} day(s), {requests} request(s); "
                f"${today:,.2f} today.",
                detail={"usd_7d": spend, "usd_today": round(today, 2), "requests_7d": requests,
                        "by_day": [{"date": d.get("date"),
                                    "usd": d.get("total_cost_usd")} for d in week]},
            ))
    if gap is not None:
        signals.append(gap)

    body, gap = _hub_signal(inputs, SCHEDULER, "scheduler_failures", "Scheduler failures")
    if gap is None:
        jobs = [j for j in body if isinstance(j, dict)] if isinstance(body, list) else None
        if jobs is None:
            gap = _unavailable("scheduler_failures", "Scheduler failures",
                               f"TheHub GET {SCHEDULER}", "TheHub's answer was not a list.")
        else:
            failing = sorted(
                (j for j in jobs if int(j.get("failure_count_7d") or 0) > 0
                 or str(j.get("last_status") or "").lower() in ("failed", "failure", "error")),
                key=lambda j: -int(j.get("failure_count_7d") or 0),
            )
            signals.append(Signal(
                key="scheduler_failures", label="Scheduler failures", status=MEASURED,
                source=f"TheHub GET {SCHEDULER}",
                value=f"{len(failing)} of {len(jobs)} scheduled job(s) failed in 7 days.",
                detail={"jobs": len(jobs), "failing": [
                    {"job_name": j.get("job_name"), "failures_7d": j.get("failure_count_7d"),
                     "runs_7d": j.get("total_runs_7d"), "last_status": j.get("last_status")}
                    for j in failing
                ]},
            ))
            for j in failing[:5]:
                lines.append(Line(
                    what=f"TheHub scheduler job {j.get('job_name')} failed "
                    f"{int(j.get('failure_count_7d') or 0)} of "
                    f"{int(j.get('total_runs_7d') or 0)} run(s) in 7 days "
                    f"(last: {j.get('last_status') or 'unknown'}).",
                    so_what="Whatever it maintains is going stale on TheHub.",
                    work=STORY, repo_full_name=repo,
                ))
    if gap is not None:
        signals.append(gap)

    signals.append(_freshness(inputs, lines, repo))

    body, gap = _hub_signal(inputs, BACKUPS, "backups", "Backups")
    if gap is None:
        if not isinstance(body, dict) or "healthy" not in body:
            gap = _unavailable("backups", "Backups", f"TheHub GET {BACKUPS}",
                               "TheHub's answer had no healthy flag.")
        else:
            latest = body.get("latest_backup") or {}
            verification = body.get("verification") or {}
            healthy = bool(body.get("healthy"))
            age = latest.get("age_hours") if isinstance(latest, dict) else None
            signals.append(Signal(
                key="backups", label="Backups", status=MEASURED,
                source=f"TheHub GET {BACKUPS}",
                value=("healthy" if healthy else "NOT healthy")
                + (f"; newest {age:g}h old" if isinstance(age, (int, float)) else "")
                + f"; verification {verification.get('status') or 'unknown'}.",
                detail={"healthy": healthy, "latest_age_hours": age,
                        "verification": verification.get("status"),
                        "total_backups": body.get("total_backups")},
            ))
            if not healthy:
                lines.append(Line(
                    what="TheHub's backups are not healthy "
                    f"(verification {verification.get('status') or 'unknown'}).",
                    so_what="A restore may not be possible from what is on disk.",
                    work=STORY, repo_full_name=repo,
                ))
    if gap is not None:
        signals.append(gap)
    return signals, lines


def _freshness(inputs: ProductSignalInputs, lines: list[Line], repo: str) -> Signal:
    key, label = "data_freshness", "Data freshness"
    body, gap = _hub_signal(inputs, CONTRACTS, key, label)
    if gap is not None:
        return gap
    contracts = [c for c in body if isinstance(c, dict)] if isinstance(body, list) else None
    if contracts is None:
        return _unavailable(key, label, f"TheHub GET {CONTRACTS}",
                            "TheHub's answer was not a list.")
    states: Counter[str] = Counter()
    stale: list[dict[str, Any]] = []
    unread = 0
    for contract in contracts[:MAX_CONTRACTS]:
        read = inputs.hub.get(f"{CONTRACTS}/{contract.get('id')}/runs")
        runs = read.body if read is not None and isinstance(read.body, list) else None
        if runs is None:
            unread += 1
            continue
        status = str((runs[0] or {}).get("status") or "never run") if runs else "never run"
        states[status] += 1
        if status.lower() not in FRESH_STATES:
            stale.append({
                "contract": f"{contract.get('domain') or ''}.{contract.get('field_name') or ''}"
                .strip("."),
                "status": status,
                "age_minutes": (runs[0] or {}).get("age_minutes") if runs else None,
            })
    measured = sum(states.values())
    signal = Signal(
        key=key, label=label, status=MEASURED,
        source=f"TheHub GET {CONTRACTS} and each contract's latest run",
        value=f"{measured - len(stale)} of {measured} freshness contract(s) within their "
        "limit" + (f"; {unread} not read" if unread else "") + ".",
        detail={"contracts": len(contracts), "read": measured, "unread": unread,
                "by_status": dict(states), "outside_limit": stale,
                "not_read_over_cap": max(0, len(contracts) - MAX_CONTRACTS)},
    )
    if stale:
        lines.append(Line(
            what=f"{len(stale)} TheHub data freshness contract(s) are outside their limit: "
            + ", ".join(s["contract"] or "?" for s in stale[:5]) + ".",
            so_what="The pages built on that data show old numbers as current.",
            work=STORY, repo_full_name=repo,
        ))
    return signal


# ---------------------------------------------------------------------------
# MyKronos: the platform's own health, across the estate
# ---------------------------------------------------------------------------


def _repos(db: Any) -> list[str]:
    """Every product the portfolio shows: not removed, not synthetic."""
    from mykronos.db.models import RepoOnboarding

    with db.session() as session:
        return [
            str(name)
            for name in session.execute(
                select(RepoOnboarding.github_repo_full_name)
                .where(RepoOnboarding.status != "removed")
                .where(RepoOnboarding.synthetic.is_(False))
                .order_by(RepoOnboarding.github_repo_full_name)
            ).scalars()
        ]


def mykronos_signals(
    catalog: Catalog, db: Any, *, now: datetime
) -> tuple[list[Signal], list[Line]]:
    signals: list[Signal] = []
    lines: list[Line] = []
    moment = _naive(now)

    def guarded(key: str, label: str, source: str, build: Any) -> None:
        try:
            signals.append(build())
        except Exception as exc:  # noqa: BLE001 - one signal must not lose the rest
            logger.debug("Could not measure %s", key)
            signals.append(_unavailable(key, label, source, _error(exc)))

    def ingestion() -> Signal:
        rows = catalog.query(
            """
            SELECT lower(coalesce(scan_status, 'unknown')), count(*) FROM scan_runs
            WHERE coalesce(ingested_at, completed_at, started_at) >= ?
            GROUP BY 1
            """,
            [moment - WEEK],
        )
        counts = {str(s): int(n) for s, n in rows}
        total = sum(counts.values())
        ok = counts.get("success", 0)
        return Signal(
            key="ingestion_success", label="Ingestion success", status=MEASURED,
            source="lake scan_runs, last 7 days, every repository",
            value=f"{ok} of {total} scan run(s) ingested in 7 days succeeded "
            f"({_fmt_pct(_pct(ok, total))})." if total else "No scan runs ingested in 7 days.",
            detail={"by_status": counts, "total": total, "rate": _pct(ok, total)},
        )

    def freshness() -> Signal:
        repos = _repos(db)
        rows = catalog.query(
            """
            SELECT repo_full_name, max(coalesce(ingested_at, completed_at, started_at))
            FROM scan_runs GROUP BY 1
            """
        )
        newest = {str(r): t for r, t in rows if isinstance(t, datetime)}
        stale = []
        for repo in repos:
            last = newest.get(repo)
            hours = None if last is None else round((moment - last).total_seconds() / 3600, 1)
            if hours is None or hours > STALE_SCAN_HOURS:
                stale.append({"repo_full_name": repo, "hours_since_scan": hours})
        for item in stale:
            lines.append(Line(
                what=f"{item['repo_full_name']} has "
                + ("never been scanned." if item["hours_since_scan"] is None
                   else f"not been scanned for {item['hours_since_scan']:g} hour(s)."),
                so_what=f"Past {STALE_SCAN_HOURS}h every number about it is old news.",
                work=STORY, repo_full_name=str(item["repo_full_name"]),
            ))
        return Signal(
            key="scan_freshness", label="Scan freshness", status=MEASURED,
            source="lake scan_runs (newest per repository); onboarded repositories",
            value=f"{len(repos) - len(stale)} of {len(repos)} repositories scanned within "
            f"{STALE_SCAN_HOURS}h.",
            detail={"repositories": len(repos), "stale_hours": STALE_SCAN_HOURS,
                    "stale": stale},
        )

    def shadow() -> Signal:
        from mykronos.oracle.environmental import build_report

        rows = catalog.query(
            """
            SELECT decision_id, repo_full_name, decision_type, pr_number, commit_sha,
                   evaluated_at, overall_risk_score, recommendation, gate_outcome,
                   CAST(json_extract(inputs_snapshot, '$.environmental') AS VARCHAR)
            FROM risk_decisions WHERE evaluated_at >= ?
            ORDER BY evaluated_at DESC LIMIT 1000
            """,
            [moment - MONTH],
        )
        columns = ("decision_id", "repo_full_name", "decision_type", "pr_number",
                   "commit_sha", "evaluated_at", "overall_risk_score", "recommendation",
                   "gate_outcome")
        records = []
        for row in rows:
            record: dict[str, Any] = dict(zip(columns, row[:-1], strict=True))
            record["environmental"] = None
            if row[-1]:
                with suppress(TypeError, json.JSONDecodeError):
                    record["environmental"] = json.loads(row[-1])
            records.append(record)
        report = build_report(records)
        shadowed, agree = int(report["shadowed"]), int(report["agree"])
        if not shadowed:
            return _not_measurable(
                "oracle_shadow_agreement", "Oracle shadow agreement",
                "lake risk_decisions (environmental shadow verdicts), last 30 days",
                f"none of the {report['decisions']} decision(s) in 30 days carries an "
                "environmental shadow verdict.",
            )
        return Signal(
            key="oracle_shadow_agreement", label="Oracle shadow agreement", status=MEASURED,
            source="lake risk_decisions (environmental shadow verdicts), last 30 days",
            value=f"The shadow agreed with the live verdict on {agree} of {shadowed} "
            f"decision(s) ({_fmt_pct(_pct(agree, shadowed))}).",
            detail={"decisions": report["decisions"], "shadowed": shadowed, "agree": agree,
                    "differ": report["differ"], "rate": _pct(agree, shadowed),
                    "transitions": report["transitions"]},
        )

    def premises() -> Signal:
        from mykronos.db.models import AuditLogEntry

        with db.session() as session:
            rows = session.execute(
                select(AuditLogEntry.action, func.count())
                .where(AuditLogEntry.action.in_(
                    ("risk_acceptance.premise_failed", "risk_acceptance.premise_checked")))
                .where(AuditLogEntry.created_at >= moment - WEEK)
                .group_by(AuditLogEntry.action)
            ).all()
        counts = {str(a): int(n) for a, n in rows}
        failed = counts.get("risk_acceptance.premise_failed", 0)
        checked = counts.get("risk_acceptance.premise_checked", 0)
        return Signal(
            key="premise_transitions", label="Premise transitions", status=MEASURED,
            source="audit_log (risk_acceptance.premise_failed / premise_checked), 7 days",
            value=f"{failed} acceptance(s) failed their premise in 7 days; "
            f"{checked} premise check(s) recorded.",
            detail={"premise_failed_7d": failed, "premise_checked_7d": checked},
        )

    def closures() -> tuple[Signal, Signal]:
        rows = catalog.query(
            f"""
            WITH current AS ({CURRENT_FINDINGS})
            SELECT status, count(*),
                   median(epoch(resolved_at) - epoch(first_seen_at))
                       FILTER (WHERE status = 'fixed')
            FROM current
            WHERE resolved_at >= ? AND status IN
                ('fixed', 'false_positive', 'accepted_risk', 'suppressed', 'superseded')
            GROUP BY 1
            """,
            [moment - MONTH],
        )
        counts = {str(s): int(n) for s, n, _ in rows}
        total = sum(counts.values())
        fp = counts.get("false_positive", 0)
        median_s = next((m for s, _, m in rows if s == "fixed" and m is not None), None)
        source = "lake findings (current row per finding_id), closed in the last 30 days"
        fp_signal = Signal(
            key="false_positive_rate", label="False-positive rate", status=MEASURED,
            source=source,
            value=f"{fp} of {total} closure(s) in 30 days were false positives "
            f"({_fmt_pct(_pct(fp, total))})." if total else "No closures in 30 days.",
            detail={"closed_30d": total, "false_positive_30d": fp, "rate": _pct(fp, total),
                    "by_status": counts},
        )
        if median_s is None:
            ttc = _not_measurable(
                "time_to_close", "Time to close", source,
                "no finding was closed as fixed in the last 30 days.",
            )
        else:
            days = round(float(median_s) / 86400, 1)
            ttc = Signal(
                key="time_to_close", label="Time to close", status=MEASURED, source=source,
                value=f"Median {days:g} day(s) from first seen to fixed, over "
                f"{counts.get('fixed', 0)} fix(es) in 30 days.",
                detail={"median_days": days, "fixed_30d": counts.get("fixed", 0)},
            )
        return fp_signal, ttc

    lake = "lake"
    guarded("ingestion_success", "Ingestion success", lake, ingestion)
    guarded("scan_freshness", "Scan freshness", lake, freshness)
    guarded("oracle_shadow_agreement", "Oracle shadow agreement", lake, shadow)
    guarded("premise_transitions", "Premise transitions", "audit_log", premises)
    try:
        fp_signal, ttc = closures()
        signals.extend([fp_signal, ttc])
    except Exception as exc:  # noqa: BLE001 - one signal must not lose the rest
        signals.append(_unavailable("false_positive_rate", "False-positive rate", lake,
                                    _error(exc)))
        signals.append(_unavailable("time_to_close", "Time to close", lake, _error(exc)))
    return signals, lines


# ---------------------------------------------------------------------------
# personal-soc
# ---------------------------------------------------------------------------


def personal_soc_signals(
    db: Any, repo: str, *, now: datetime
) -> tuple[list[Signal], list[Line]]:
    from mykronos.control_observations import parse_subject
    from mykronos.db.models import ControlObservation, NetassessRun

    signals: list[Signal] = []
    lines: list[Line] = []
    moment = _naive(now)
    obs_source = "control_observations"
    try:
        with db.session() as session:
            run = session.get(NetassessRun, repo)
            netassess = (
                (run.run_key, run.run_date, run.believable, run.received_at)
                if run is not None else None
            )
            lan = session.execute(
                select(ControlObservation.subject, func.min(ControlObservation.collected_at))
                .where(ControlObservation.repo_full_name == repo)
                .where(ControlObservation.vantage == "lan")
                .group_by(ControlObservation.subject)
            ).all()
            wan = session.execute(
                select(ControlObservation)
                .where(ControlObservation.repo_full_name == repo)
                .where(ControlObservation.vantage == "internet")
                .where(ControlObservation.assertion == "port_published")
                .order_by(ControlObservation.collected_at.desc())
            ).scalars().all()
            wan_rows = [
                (o.subject, o.state, o.surface_id, o.control_id, o.collected_at) for o in wan
            ]
    except Exception as exc:  # noqa: BLE001 - reported per signal
        logger.debug("Could not read personal-soc's observations")
        why = _error(exc)
        return [
            _unavailable(k, label, "netassess_runs; control_observations", why)
            for k, label in EXPECTED["personal-soc"]
        ], []

    # New LAN hosts: a host first observed from the LAN in the last week.
    first_seen: dict[str, datetime] = {}
    for subject, when in lan:
        host = parse_subject(str(subject)).host or str(subject)
        if when is not None and (host not in first_seen or when < first_seen[host]):
            first_seen[host] = when
    if not first_seen:
        signals.append(_not_measurable(
            "new_lan_hosts", "New LAN hosts", f"{obs_source} (vantage lan)",
            f"no LAN-vantage observation is recorded for {repo}; the weekly netassess "
            "ingest keeps only the latest inventory, and its host diff is sent as a "
            "notification, not stored.",
        ))
    else:
        new = sorted(h for h, t in first_seen.items() if t >= moment - WEEK)
        signals.append(Signal(
            key="new_lan_hosts", label="New LAN hosts", status=MEASURED,
            source=f"{obs_source} (vantage lan, first observation per host)",
            value=f"{len(new)} host(s) first seen on the LAN in 7 days, of "
            f"{len(first_seen)} ever observed.",
            detail={"new_7d": new, "hosts_observed": len(first_seen)},
        ))
        if new:
            lines.append(Line(
                what=f"{len(new)} new host(s) on the LAN this week: {', '.join(new[:8])}.",
                so_what="A device nobody recognises on the home network is the first "
                "sign of trouble: confirm each is known.",
                work=DECISION, repo_full_name=repo,
            ))

    # WAN ports: published to the internet, against the declared allowlist.
    latest: dict[str, tuple[str, str | None, str | None, datetime]] = {}
    for subject, state, surface_id, control_id, when in wan_rows:
        latest.setdefault(str(subject), (str(state), surface_id, control_id, when))
    if not latest:
        signals.append(_not_measurable(
            "wan_ports", "WAN ports vs the allowlist", f"{obs_source} (vantage internet)",
            f"no internet-vantage port observation is recorded for {repo}.",
        ))
    else:
        open_ports = {s: v for s, v in latest.items() if v[0] == "pass"}
        unlisted = sorted(s for s, v in open_ports.items() if not (v[1] or v[2]))
        signals.append(Signal(
            key="wan_ports", label="WAN ports vs the allowlist", status=MEASURED,
            source=f"{obs_source} (vantage internet, port_published, latest per subject); "
            "repo_surfaces (the allowlist: a declared surface or control covers the port)",
            value=f"{len(open_ports)} port(s) reachable from the internet; {len(unlisted)} "
            "not on the allowlist.",
            detail={"reachable": sorted(open_ports), "not_on_allowlist": unlisted},
        ))
        for subject in unlisted[:5]:
            lines.append(Line(
                what=f"{subject} is reachable from the internet and no declared surface "
                "covers it.",
                so_what="Either it is meant to be open and belongs on the allowlist, or "
                "it is not and should be closed.",
                work=DECISION, repo_full_name=repo,
            ))

    signals.append(_not_measurable(
        "nas_posture", "NAS posture", "netassess_runs",
        "the netassess ingest judges network-status.md (NFS exports, SMBv1) and keeps "
        "only whether the run was believable, not the NAS checks.",
    ))
    if netassess is not None:
        signals[-1].detail = {"last_run_believable": bool(netassess[2])}

    if netassess is None or netassess[1] is None:
        signals.append(_not_measurable(
            "scan_age", "Scan age", "netassess_runs",
            f"no network-assessment run is recorded for {repo}."
            if netassess is None else "the last run's key carried no date.",
        ))
    else:
        key, run_date, believable, received = netassess
        age = (moment.date() - run_date.date()).days
        signals.append(Signal(
            key="scan_age", label="Scan age", status=MEASURED, source="netassess_runs",
            value=f"Last network scan {run_date.date().isoformat()} ({age} day(s) old, "
            f"limit {NETASSESS_MAX_AGE_DAYS}); "
            + ("believable." if believable else "NOT believable."),
            detail={"run_key": key, "age_days": age, "believable": bool(believable),
                    "max_age_days": NETASSESS_MAX_AGE_DAYS,
                    "received_at": received.isoformat() if received else None},
        ))
        if age > NETASSESS_MAX_AGE_DAYS or not believable:
            lines.append(Line(
                what=f"The weekly network scan is {age} day(s) old"
                + ("" if believable else " and its last run was not believable") + ".",
                so_what="The LAN inventory and NAS checks are not being refreshed: the "
                "Scheduled Task may be degrading rather than dying.",
                work=STORY, repo_full_name=repo,
            ))
    return signals, lines


# ---------------------------------------------------------------------------
# keel
# ---------------------------------------------------------------------------


def keel_signals(
    catalog: Catalog, db: Any, repo: str
) -> tuple[list[Signal], list[Line]]:
    from mykronos.db.models import RepoOnboarding

    signals: list[Signal] = []
    lines: list[Line] = []
    scanned_by = ""
    with suppress(Exception), db.session() as session:
        row = session.execute(
            select(RepoOnboarding.scanned_by)
            .where(RepoOnboarding.github_repo_full_name == repo)
        ).scalar()
        scanned_by = str(row or "")
    signals.append(_not_measurable(
        "template_drift", "Template drift", "installer resync (spec 03 §6)",
        "the template resync compares workflow content only when it runs and keeps no "
        "record MyKronos can read"
        + (f"; {repo} is scanned by {scanned_by}, so it carries no MyKronos-rendered "
           "Actions workflows to drift" if scanned_by and scanned_by != "github_actions"
           else "") + ".",
    ))

    source = "lake scan_runs (newest tool version per tool, this repository and the estate)"
    try:
        rows = catalog.query(
            """
            SELECT repo_full_name, capability, tool_name, tool_version, ts FROM (
                SELECT repo_full_name, capability, tool_name, tool_version,
                       coalesce(completed_at, started_at) AS ts,
                       row_number() OVER (
                           PARTITION BY repo_full_name, tool_name
                           ORDER BY coalesce(completed_at, started_at) DESC
                       ) AS rn
                FROM scan_runs
                WHERE coalesce(tool_name, '') <> '' AND coalesce(tool_version, '') <> ''
            ) WHERE rn = 1
            """
        )
    except Exception as exc:  # noqa: BLE001 - reported, never omitted
        signals.append(_unavailable("scanner_versions", "Scanner versions", source,
                                    _error(exc)))
        return signals, lines

    from mykronos.guidance import _highest

    estate: dict[str, set[str]] = {}
    mine: list[tuple[str, str, str]] = []
    for r, capability, tool, version, _ in rows:
        estate.setdefault(str(tool), set()).add(str(version))
        if str(r) == repo:
            mine.append((str(capability), str(tool), str(version)))
    if not mine:
        signals.append(_not_measurable(
            "scanner_versions", "Scanner versions", source,
            f"no scan run for {repo} records a tool name and version.",
        ))
        return signals, lines
    tools = []
    behind = []
    for capability, tool, version in sorted(mine):
        newest = _highest(estate[tool])
        tools.append({"capability": capability, "tool": tool, "version": version,
                      "estate_newest": newest})
        if newest != version:
            behind.append((capability, tool, version, newest))
    signals.append(Signal(
        key="scanner_versions", label="Scanner versions", status=MEASURED, source=source,
        value=f"{len(tools)} scanner(s); {len(behind)} behind the newest version the "
        "estate runs.",
        detail={"tools": tools},
    ))
    for capability, tool, version, newest in behind:
        lines.append(Line(
            what=f"keel's {capability} lane runs {tool} {version}; the estate runs {newest}.",
            so_what="Repositories built from keel inherit the older scanner, and its "
            "findings will not match the rest of the estate.",
            work=STORY, repo_full_name=repo,
        ))
    return signals, lines


# ---------------------------------------------------------------------------
# binnacle
# ---------------------------------------------------------------------------


def binnacle_signals(
    catalog: Catalog, repo: str, *, now: datetime
) -> tuple[list[Signal], list[Line]]:
    source = f"lake scan_runs ingested for this repository, last {INGESTION_WINDOW_DAYS} days"
    moment = _naive(now)
    start = (moment - timedelta(days=INGESTION_WINDOW_DAYS - 1)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    try:
        rows = catalog.query(
            """
            SELECT CAST(coalesce(ingested_at, completed_at, started_at) AS DATE),
                   count(*), sum(coalesce(finding_count, 0))
            FROM scan_runs
            WHERE repo_full_name = ? AND coalesce(ingested_at, completed_at, started_at) >= ?
            GROUP BY 1
            """,
            [repo, start],
        )
        last_rows = catalog.query(
            "SELECT max(coalesce(ingested_at, completed_at, started_at)) FROM scan_runs "
            "WHERE repo_full_name = ?",
            [repo],
        )
    except Exception as exc:  # noqa: BLE001 - reported, never omitted
        why = _error(exc)
        return [_unavailable(k, label, source, why) for k, label in EXPECTED["binnacle"]], []

    by_day = {d.isoformat() if hasattr(d, "isoformat") else str(d): (int(n), int(f or 0))
              for d, n, f in rows}
    days = [(start + timedelta(days=i)).date().isoformat()
            for i in range(INGESTION_WINDOW_DAYS)]
    runs = sum(by_day.get(d, (0, 0))[0] for d in days)
    findings = sum(by_day.get(d, (0, 0))[1] for d in days)
    last = last_rows[0][0] if last_rows and isinstance(last_rows[0][0], datetime) else None

    signals = [Signal(
        key="ingestion_volume", label="Ingestion volume", status=MEASURED, source=source,
        value=f"{runs} scan run(s), {findings} finding row(s) ingested over "
        f"{INGESTION_WINDOW_DAYS} days.",
        detail={"runs": runs, "findings": findings,
                "by_day": [{"date": d, "runs": by_day.get(d, (0, 0))[0]} for d in days]},
    )]
    gaps: list[dict[str, Any]] = []
    streak: list[str] = []
    for day in [*days, ""]:
        if day and by_day.get(day, (0, 0))[0] == 0:
            streak.append(day)
            continue
        if len(streak) >= GAP_DAYS:
            gaps.append({"from": streak[0], "to": streak[-1], "days": len(streak)})
        streak = []
    since = None if last is None else round((moment - last).total_seconds() / 3600, 1)
    signals.append(Signal(
        key="ingestion_gaps", label="Ingestion gaps", status=MEASURED, source=source,
        value=f"{len(gaps)} gap(s) of {GAP_DAYS}+ silent day(s) in {INGESTION_WINDOW_DAYS} "
        "days; last ingestion "
        + ("never." if since is None else f"{since:g}h ago."),
        detail={"gaps": gaps, "hours_since_last": since, "gap_days": GAP_DAYS},
    ))
    lines: list[Line] = []
    if gaps and (since is None or since > GAP_DAYS * 24):
        lines.append(Line(
            what=f"Nothing from {repo} has been ingested for "
            + ("ever" if since is None else f"{since:g} hour(s)") + ".",
            so_what="Its lanes are silent, so its findings are frozen as of the last "
            "scan.",
            work=STORY, repo_full_name=repo,
        ))
    return signals, lines


# ---------------------------------------------------------------------------
# The section
# ---------------------------------------------------------------------------


def section(
    catalog: Catalog,
    db: Any,
    repo: str,
    inputs: ProductSignalInputs | None,
    *,
    now: datetime,
) -> Section:
    """This product's own signals, every listed one measured or said not to be."""
    product = product_of(repo)
    source = "lake; netassess_runs; control_observations; audit_log; TheHub API"
    if product is None:
        return Section(
            key=SECTION_KEY, title=SECTION_TITLE, status=NOT_AVAILABLE, source=source,
            as_of=None,
            reason=f"No product-specific signals are defined for {repo}.",
            data={"product": None, "signals": []},
        )
    inputs = inputs or ProductSignalInputs()
    if product == "thehub":
        signals, lines = thehub_signals(inputs)
        source = "TheHub API (autonomy dashboard, AI usage summary, scheduler health, " \
            "data freshness contracts, backup health)"
    elif product == "mykronos":
        signals, lines = mykronos_signals(catalog, db, now=now)
        source = "lake scan_runs, findings and risk_decisions; audit_log; onboarded " \
            "repositories (estate-wide: the platform's own health)"
    elif product == "personal-soc":
        signals, lines = personal_soc_signals(db, repo, now=now)
        source = "netassess_runs; control_observations; repo_surfaces"
    elif product == "keel":
        signals, lines = keel_signals(catalog, db, repo)
        source = "lake scan_runs (tool versions); onboarding ledger"
    else:
        signals, lines = binnacle_signals(catalog, repo, now=now)
        source = "lake scan_runs"

    # Every listed signal is present, in the listed order; a builder that
    # missed one is a bug, and the page says so rather than dropping it.
    by_key = {s.key: s for s in signals}
    ordered = [
        by_key.get(key) or _unavailable(key, label, source, "It was not measured.")
        for key, label in EXPECTED[product]
    ]
    gaps = [f"{s.label} ({s.reason})" for s in ordered if s.status == NOT_MEASURABLE]
    failed = [f"{s.label} ({s.reason})" for s in ordered if s.status == UNAVAILABLE]
    reason = " ".join(
        part for part in (
            f"Not measurable yet: {'; '.join(gaps)}." if gaps else "",
            f"Could not read: {'; '.join(failed)}." if failed else "",
        ) if part
    )
    return Section(
        key=SECTION_KEY,
        title=SECTION_TITLE,
        status=PARTIAL if reason else OK,
        source=source,
        as_of=inputs.as_of if product == "thehub" and inputs.as_of else now,
        reason=reason,
        lines=lines,
        data={"product": product, "signals": [asdict(s) for s in ordered]},
    )
