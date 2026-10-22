"""The daily briefing: what changed, so what, and whether it is work (TheHub #60860).

`briefing.py` answers the question somebody has after a deploy: which lanes
cannot close anything, and what the cheapest work is. This is the page they
read first thing in the morning, overall and per product, and it is held to
one design rule Todd approved with the prototype:

    every line answers what changed, so what, and whether it is work;
    an item that cannot become a merge, a decision or a story does not belong.

So a `Line` cannot be built without a `work` kind, and a count that nobody can
act on lives in a section's `data`, never in its lines.

**Every section says where it came from and how old that is.** A section
carries a `source`, an `as_of` and a `status`:

- ``ok`` -- every source it needs was read.
- ``partial`` -- some were, and `reason` names the ones that were not.
- ``unavailable`` -- its source could not be read. It says so, with the
  reason, and never renders as an empty section that looks like "all clear".
  That gap is what kept four security lanes paused for thirty-two days (#401).
- ``not_available`` -- not built yet: present, named, and empty on purpose
  rather than invented. Since B3 (TheHub #60861) no section is; "needs you",
  sprint health and the board check behind suggested focus and next-sprint
  candidates read TheHub's board and GitHub through `delivery_sources`.

Every builder here catches its own failure and returns an ``unavailable``
section: one unreadable store must never take the rest of the page with it.
"""

from __future__ import annotations

import logging
import re
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import select

from mykronos import briefing as briefing_report
from mykronos.lake.catalog import Catalog

logger = logging.getLogger(__name__)

#: ok | partial | unavailable | not_available -- see the module docstring.
OK = "ok"
PARTIAL = "partial"
UNAVAILABLE = "unavailable"
NOT_AVAILABLE = "not_available"
STATUSES = (OK, PARTIAL, UNAVAILABLE, NOT_AVAILABLE)

#: What a line can become. Nothing else belongs on the page.
MERGE = "merge"
DECISION = "decision"
STORY = "story"
WORK_KINDS = (MERGE, DECISION, STORY)

#: The window "what changed" is measured over.
WINDOW = timedelta(hours=24)

#: An acceptance this close to its end date needs a renew-or-let-lapse call.
ACCEPTANCE_EXPIRING_DAYS = 7

#: Closures in one repository inside the window, with nothing on record to
#: explain them, above which the drop in the open count is not to be trusted
#: until somebody confirms it. "Hundreds closed overnight" is either a large
#: real fix or a scanner that stopped seeing things, and the page must not
#: present the second as good news.
MASS_CLOSURE_THRESHOLD = 100

#: An EPSS probability at or above this is worth naming on an introduced
#: finding: roughly the top few percent of scored CVEs.
EPSS_NOTABLE = 0.1

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

#: Which statuses count as a closure, and the ones a person decided.
CLOSED_STATUSES = ("fixed", "false_positive", "accepted_risk", "suppressed", "superseded")
HUMAN_DISPOSITIONS = ("false_positive", "suppressed")

@dataclass
class Line:
    """One thing that changed, why it matters, and the work it becomes."""

    #: What changed.
    what: str
    #: So what: why a reader should care.
    so_what: str
    #: merge | decision | story. Required: a line that is none of these is
    #: not on the page.
    work: str
    repo_full_name: str = ""
    #: A route or id to act on, when one exists.
    ref: str = ""

    def __post_init__(self) -> None:
        if self.work not in WORK_KINDS:
            raise ValueError(f"work must be one of {WORK_KINDS}, not {self.work!r}")


@dataclass
class Section:
    key: str
    title: str
    status: str
    #: The store(s) this section reads, named.
    source: str
    #: How old the data is: the newest scan the lake holds, the oldest cached
    #: probe answer, or the moment a live store was read. None when nothing
    #: was read.
    as_of: datetime | None
    #: Why the status is not `ok`. Empty when it is.
    reason: str = ""
    lines: list[Line] = field(default_factory=list)
    #: Counts and structure behind the lines. Not work on its own.
    data: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}, not {self.status!r}")
        if self.status != OK and not self.reason:
            raise ValueError(f"a {self.status} section must say why")


@dataclass
class DailyBriefing:
    generated_at: datetime
    #: "overall" or "product".
    scope: str
    repo_full_name: str | None
    sections: list[Section]


def unavailable(key: str, title: str, source: str, why: str) -> Section:
    """The section a builder returns when its source could not be read."""
    return Section(
        key=key, title=title, status=UNAVAILABLE, source=source, as_of=None, reason=why
    )


def _naive(value: datetime) -> datetime:
    """Naive UTC, the lake's convention, so stamps from different stores compare."""
    if value.tzinfo is not None:
        return value.astimezone(UTC).replace(tzinfo=None)
    return value


def _error(exc: BaseException) -> str:
    """A reason that names the failure's kind without echoing its text, which
    can carry a path, a query or a connection string."""
    return f"{type(exc).__name__} while reading it."


# ---------------------------------------------------------------------------
# The lake
# ---------------------------------------------------------------------------


def lake_as_of(catalog: Catalog, asset_id: str | None = None) -> datetime | None:
    """When the lake last heard from a scan: the newest run it holds."""
    where = "WHERE repo_full_name = ?" if asset_id else ""
    rows = catalog.query(
        f"SELECT max(coalesce(ingested_at, completed_at, started_at)) FROM scan_runs {where}",
        [asset_id] if asset_id else None,
    )
    value = rows[0][0] if rows else None
    return value if isinstance(value, datetime) else None


#: The current state of each finding: the newest row per `finding_id`.
#: Compaction upserts on the key, so there is normally one row; this does not
#: rely on it, because a duplicate would count a closure twice.
CURRENT_FINDINGS = """
    SELECT * EXCLUDE (rn) FROM (
        SELECT *, row_number() OVER (
            PARTITION BY finding_id ORDER BY dt DESC, last_seen_at DESC
        ) AS rn
        FROM findings
    ) WHERE rn = 1
"""


@dataclass
class ChangedFinding:
    finding_id: str
    repo_full_name: str
    capability: str
    rule_id: str
    title: str
    severity: str
    status: str
    superseded_source: str
    introduced: bool
    closed: bool


@dataclass
class MassClosure:
    """Many closures in one repository with nothing on record to explain them."""

    repo_full_name: str
    closed: int
    unexplained: int
    #: status -> count among the unexplained.
    by_status: dict[str, int]


@dataclass
class RiskDeltaRead:
    """Everything the risk delta read, and what it could not."""

    as_of: datetime | None
    since: datetime
    changed: list[ChangedFinding]
    #: finding_id -> (base_band, env_band). None when the store was unreadable.
    environmental: dict[str, tuple[str, str]] | None
    #: cve -> (in_kev, epss_score). None when the store was unreadable.
    threat_intel: dict[str, tuple[bool, float | None]] | None
    #: finding ids covered by an acceptance record. None when unreadable.
    accepted_ids: set[str] | None
    #: finding ids with a merged Patchwork fix.
    merged_fix_ids: set[str]
    mass_closures: list[MassClosure]


def _changed_findings(
    catalog: Catalog, since: datetime, asset_id: str | None
) -> list[ChangedFinding]:
    scope = " AND asset_id = ?" if asset_id else ""
    closed = ", ".join(f"'{s}'" for s in CLOSED_STATUSES)
    rows = catalog.query(
        f"""
        WITH current AS ({CURRENT_FINDINGS})
        SELECT finding_id, asset_id, capability, rule_id, title,
               lower(coalesce(severity, '')), status, coalesce(superseded_source, ''),
               first_seen_at >= ? AS introduced,
               (status IN ({closed}) AND resolved_at >= ?) AS closed
        FROM current
        WHERE (first_seen_at >= ? OR (status IN ({closed}) AND resolved_at >= ?)){scope}
        """,
        [since, since, since, since, *([asset_id] if asset_id else [])],
    )
    return [
        ChangedFinding(
            finding_id=str(fid),
            repo_full_name=str(repo or ""),
            capability=str(capability or ""),
            rule_id=str(rule_id or ""),
            title=str(title or ""),
            severity=str(severity or ""),
            status=str(status or ""),
            superseded_source=str(source or ""),
            introduced=bool(introduced),
            closed=bool(was_closed),
        )
        for fid, repo, capability, rule_id, title, severity, status, source, introduced, was_closed
        in rows
    ]


def _merged_fix_ids(catalog: Catalog, finding_ids: list[str]) -> set[str]:
    if not finding_ids:
        return set()
    placeholders = ", ".join("?" for _ in finding_ids)
    rows = catalog.query(
        f"""
        SELECT DISTINCT finding_id FROM remediation_events
        WHERE pr_status = 'merged' AND finding_id IN ({placeholders})
        """,
        finding_ids,
    )
    return {str(row[0]) for row in rows}


def _environmental(db: Any, finding_ids: list[str]) -> dict[str, tuple[str, str]]:
    from mykronos.db.models import EnvironmentalScore

    if not finding_ids:
        return {}
    with db.session() as session:
        rows = session.execute(
            select(
                EnvironmentalScore.finding_id,
                EnvironmentalScore.base_band,
                EnvironmentalScore.env_band,
            ).where(EnvironmentalScore.finding_id.in_(finding_ids))
        ).all()
    return {str(fid): (str(base or ""), str(env or "")) for fid, base, env in rows}


def _threat_intel(db: Any, cves: set[str]) -> dict[str, tuple[bool, float | None]]:
    from mykronos.db.models import ThreatIntelMatch

    if not cves:
        return {}
    with db.session() as session:
        rows = session.execute(
            select(
                ThreatIntelMatch.cve_id, ThreatIntelMatch.in_kev, ThreatIntelMatch.epss_score
            ).where(ThreatIntelMatch.cve_id.in_(sorted(cves)))
        ).all()
    return {
        str(cve): (bool(kev), float(epss) if epss is not None else None)
        for cve, kev, epss in rows
    }


def _accepted_ids(db: Any, asset_id: str | None) -> set[str]:
    from mykronos.db.models import RiskAcceptance

    with db.session() as session:
        query = select(RiskAcceptance.covered_finding_ids)
        if asset_id:
            query = query.where(RiskAcceptance.repo_full_name == asset_id)
        out: set[str] = set()
        for covered in session.execute(query).scalars():
            out.update(str(fid) for fid in (covered or []))
    return out


def _explained(
    finding: ChangedFinding, accepted: set[str] | None, merged: set[str]
) -> bool:
    """Whether something on record accounts for this closure.

    A merged fix, an acceptance that covers it, a person's disposition, or a
    withdrawal whose machine setter is named (spec 05 §5a). A `fixed` closure
    by absence alone is the case this exists for: it is what a real fix looks
    like, and also what a scanner that stopped seeing things looks like.
    """
    if finding.finding_id in merged:
        return True
    if finding.status in HUMAN_DISPOSITIONS:
        return True
    if finding.status == "superseded":
        return bool(finding.superseded_source)
    if finding.status == "accepted_risk":
        # Unknown acceptances count as explained: the trust signal must not
        # fire on a store this briefing failed to read.
        return accepted is None or finding.finding_id in accepted
    return False


def mass_closures(
    changed: list[ChangedFinding],
    accepted: set[str] | None,
    merged: set[str],
    *,
    threshold: int | None = None,
) -> list[MassClosure]:
    by_repo: dict[str, list[ChangedFinding]] = {}
    for finding in changed:
        if finding.closed:
            by_repo.setdefault(finding.repo_full_name, []).append(finding)
    # Read at call time, not bound as a default, so the constant stays the
    # one place to change it.
    limit = MASS_CLOSURE_THRESHOLD if threshold is None else threshold
    out = []
    for repo, closed in sorted(by_repo.items()):
        unexplained = [f for f in closed if not _explained(f, accepted, merged)]
        if len(unexplained) >= limit:
            out.append(
                MassClosure(
                    repo_full_name=repo,
                    closed=len(closed),
                    unexplained=len(unexplained),
                    by_status=dict(Counter(f.status for f in unexplained)),
                )
            )
    out.sort(key=lambda m: -m.unexplained)
    return out


def read_risk_delta(
    catalog: Catalog,
    db: Any,
    *,
    now: datetime,
    asset_id: str | None = None,
    threshold: int | None = None,
) -> RiskDeltaRead:
    """The last day's findings, joined to what the operational stores say.

    Raises when the lake cannot be read: without it there is no delta at all.
    Each operational join fails to `None` on its own, and the section built
    from it says `partial` and names which.
    """
    from mykronos.threat_intel import extract_cve

    since = now - WINDOW
    changed = _changed_findings(catalog, since, asset_id)
    ids = [f.finding_id for f in changed]
    as_of = lake_as_of(catalog, asset_id)

    environmental: dict[str, tuple[str, str]] | None
    try:
        environmental = _environmental(db, [f.finding_id for f in changed if f.introduced])
    except Exception:  # noqa: BLE001 - reported as partial, never as none
        logger.debug("Could not read environmental scores")
        environmental = None

    cves = {
        cve
        for f in changed
        if f.introduced and (cve := extract_cve(f.rule_id, f.title)) is not None
    }
    threat: dict[str, tuple[bool, float | None]] | None
    try:
        threat = _threat_intel(db, cves)
    except Exception:  # noqa: BLE001 - reported as partial, never as none
        logger.debug("Could not read threat intelligence")
        threat = None

    accepted: set[str] | None
    try:
        accepted = _accepted_ids(db, asset_id)
    except Exception:  # noqa: BLE001 - reported as partial, never as none
        logger.debug("Could not read risk acceptances")
        accepted = None

    merged = _merged_fix_ids(catalog, [f.finding_id for f in changed if f.closed])
    return RiskDeltaRead(
        as_of=as_of,
        since=since,
        changed=changed,
        environmental=environmental,
        threat_intel=threat,
        accepted_ids=accepted,
        merged_fix_ids=merged,
        mass_closures=mass_closures(changed, accepted, merged, threshold=threshold)
        if ids
        else [],
    )


def _by_severity(values: list[str]) -> dict[str, int]:
    counts = Counter(v or "unknown" for v in values)
    ordered = {s: counts.pop(s) for s in SEVERITY_ORDER if s in counts}
    ordered.update(sorted(counts.items()))
    return ordered


RISK_DELTA_SOURCE = (
    "lake findings (current row per finding_id) + remediation_events; "
    "environmental_scores; threat_intel_matches (KEV, EPSS); risk_acceptances"
)


def risk_delta_section(read: RiskDeltaRead | None, why: str = "") -> Section:
    """Introduced and closed in the window, base against environmental
    severity, and which introduced findings are KEV-listed or likely to be
    exploited."""
    key, title = "risk_delta", "Risk delta"
    if read is None:
        return unavailable(key, title, RISK_DELTA_SOURCE, why or "The lake could not be read.")

    from mykronos.threat_intel import extract_cve

    introduced = [f for f in read.changed if f.introduced]
    closed = [f for f in read.changed if f.closed]
    missing = []
    if read.environmental is None:
        missing.append("environmental scores could not be read")
    if read.threat_intel is None:
        missing.append("threat intelligence (KEV/EPSS) could not be read")
    if read.accepted_ids is None:
        missing.append(
            "risk acceptances could not be read, so accepted closures are not checked"
        )

    env = read.environmental or {}
    base_bands = [env[f.finding_id][0] for f in introduced if f.finding_id in env]
    env_bands = [env[f.finding_id][1] for f in introduced if f.finding_id in env]

    kev: list[ChangedFinding] = []
    epss: list[tuple[ChangedFinding, float]] = []
    intel = read.threat_intel or {}
    for f in introduced:
        cve = extract_cve(f.rule_id, f.title)
        if cve is None or cve not in intel:
            continue
        in_kev, score = intel[cve]
        if in_kev:
            kev.append(f)
        elif score is not None and score >= EPSS_NOTABLE:
            epss.append((f, score))

    lines: list[Line] = []
    for f in kev:
        lines.append(
            Line(
                what=f"{f.rule_id} introduced in {f.repo_full_name} ({f.capability}).",
                so_what="It is on CISA's Known Exploited Vulnerabilities list: "
                "exploited in the wild, with a federal due date.",
                work=STORY,
                repo_full_name=f.repo_full_name,
                ref=f.finding_id,
            )
        )
    for f, score in sorted(epss, key=lambda pair: -pair[1]):
        lines.append(
            Line(
                what=f"{f.rule_id} introduced in {f.repo_full_name} ({f.capability}).",
                so_what=f"EPSS {score:.0%}: likely to be exploited within 30 days.",
                work=STORY,
                repo_full_name=f.repo_full_name,
                ref=f.finding_id,
            )
        )
    serious = Counter(
        (f.repo_full_name, f.capability)
        for f in introduced
        if f not in kev
        and (env.get(f.finding_id, ("", f.severity))[1] or f.severity) in ("critical", "high")
    )
    for (repo, capability), count in sorted(serious.items(), key=lambda kv: -kv[1]):
        lines.append(
            Line(
                what=f"{count} critical/high {capability} finding(s) introduced in {repo}.",
                so_what="New since yesterday at critical or high, in this environment "
                "where a score exists and as the scanner said otherwise.",
                work=STORY,
                repo_full_name=repo,
            )
        )

    return Section(
        key=key,
        title=title,
        status=PARTIAL if missing else OK,
        source=RISK_DELTA_SOURCE,
        as_of=read.as_of,
        reason="; ".join(missing).capitalize() + "." if missing else "",
        lines=lines,
        data={
            "window_hours": int(WINDOW.total_seconds() // 3600),
            "since": read.since.isoformat(),
            "introduced": {
                "total": len(introduced),
                "by_severity": _by_severity([f.severity for f in introduced]),
                # Only findings with a CVSS vector have these; the rest are
                # counted under `unscored`, never guessed.
                "by_base_severity": _by_severity(base_bands),
                "by_environmental_severity": _by_severity(env_bands),
                "unscored": len(introduced) - len(base_bands),
            },
            "closed": {
                "total": len(closed),
                "by_severity": _by_severity([f.severity for f in closed]),
                "by_status": dict(Counter(f.status for f in closed)),
            },
            "kev": [f.finding_id for f in kev],
            "epss": [
                {"finding_id": f.finding_id, "epss": score} for f, score in epss
            ],
            "mass_closures": [asdict(m) for m in read.mass_closures],
        },
    )


# ---------------------------------------------------------------------------
# Acceptances
# ---------------------------------------------------------------------------


ACCEPTANCES_SOURCE = "risk_acceptances"


def acceptances_section(db: Any, *, now: datetime, asset_id: str | None = None) -> Section:
    """Acceptances ending within a week, those whose premise has failed, and
    those owing the interim review nothing else would prompt (TheHub #60817)."""
    key, title = "acceptances", "Acceptances"
    from mykronos import risk_acceptance as ra
    from mykronos.db.models import RiskAcceptance

    try:
        with db.session() as session:
            query = select(RiskAcceptance).where(
                RiskAcceptance.status.in_(("premise_failed", *ra.LIVE))
            )
            if asset_id:
                query = query.where(RiskAcceptance.repo_full_name == asset_id)
            records = [
                (
                    str(r.id),
                    str(r.repo_full_name),
                    str(r.status),
                    r.expires_at,
                    len(r.covered_finding_ids or []),
                    str(r.residual_severity or ""),
                    r.interim_review_by if r.interim_reviewed_at is None else None,
                )
                for r in session.execute(query).scalars()
            ]
    except Exception as exc:  # noqa: BLE001 - reported, never shown as none
        logger.debug("Could not read risk acceptances")
        return unavailable(key, title, ACCEPTANCES_SOURCE, _error(exc))

    today: date = now.date()
    horizon = today + timedelta(days=ACCEPTANCE_EXPIRING_DAYS)
    failed = [r for r in records if r[2] == "premise_failed"]
    # Owing the interim review: its date has come, nobody has recorded it.
    interim = sorted(
        (r for r in records if r[2] in ra.LIVE and r[6] is not None and r[6] <= today),
        key=lambda r: r[6] or today,
    )
    expiring = sorted(
        (r for r in records if r[2] in ra.LIVE and r[3] is not None and r[3] <= horizon),
        key=lambda r: r[3] or horizon,
    )
    lines = [
        Line(
            what=f"An acceptance covering {count} finding(s) in {repo} failed its premise.",
            so_what="What it rested on is no longer true, so its findings are open "
            "risk again: fix them, or re-accept on a premise that holds.",
            work=DECISION,
            repo_full_name=repo,
            ref=f"/api/risk-acceptances/{rid}",
        )
        for rid, repo, _, _, count, _, _ in failed
    ]
    for rid, repo, record_status, _, count, _, due in interim:
        assert due is not None
        lapsed = record_status == "needs_review"
        lines.append(
            Line(
                what=(
                    f"An acceptance covering {count} finding(s) in {repo} "
                    + (
                        f"needs review: its interim review, due {due.isoformat()}, lapsed."
                        if lapsed
                        else f"is due its interim review ({due.isoformat()})."
                    )
                ),
                so_what="Nothing watches the reason it was accepted for, so only a person "
                "looking again would notice it stopped being true: record the review, "
                "renew or revoke it.",
                work=DECISION,
                repo_full_name=repo,
                ref=f"/api/risk-acceptances/{rid}",
            )
        )
    for rid, repo, _, expires, count, _, _ in expiring:
        assert expires is not None
        left = (expires - today).days
        when = "today" if left == 0 else ("already" if left < 0 else f"in {left} day(s)")
        lines.append(
            Line(
                what=f"An acceptance covering {count} finding(s) in {repo} ends {when} "
                f"({expires.isoformat()}).",
                so_what="When it lapses its findings count as open risk again.",
                work=DECISION,
                repo_full_name=repo,
                ref=f"/api/risk-acceptances/{rid}",
            )
        )
    return Section(
        key=key,
        title=title,
        status=OK,
        source=ACCEPTANCES_SOURCE,
        as_of=now,
        lines=lines,
        data={
            "live": sum(1 for r in records if r[2] in ra.LIVE),
            "expiring_within_days": ACCEPTANCE_EXPIRING_DAYS,
            "expiring": [
                {
                    "id": rid,
                    "repo_full_name": repo,
                    "expires_at": expires.isoformat() if expires else None,
                    "covered_findings": count,
                    "residual_severity": severity,
                }
                for rid, repo, _, expires, count, severity, _ in expiring
            ],
            "review_due": [
                {
                    "id": rid,
                    "repo_full_name": repo,
                    "interim_review_by": due.isoformat() if due else None,
                    "needs_review": record_status == "needs_review",
                    "covered_findings": count,
                    "residual_severity": severity,
                }
                for rid, repo, record_status, _, count, severity, due in interim
            ],
            "premise_failed": [
                {"id": rid, "repo_full_name": repo, "covered_findings": count,
                 "residual_severity": severity}
                for rid, repo, _, _, count, severity, _ in failed
            ],
        },
    )


# ---------------------------------------------------------------------------
# Production truth
# ---------------------------------------------------------------------------


PRODUCTION_SOURCE = "deployments (deployment-probe sweep, #946); public endpoint probes"


def production_section(
    report: briefing_report.Briefing,
    *,
    key: str = "production_truth",
    title: str = "Production truth",
) -> Section:
    """Is production running what the branch says, and what can the internet see."""
    if report.production_lag_unknown and report.exposure_unknown:
        return unavailable(
            key,
            title,
            PRODUCTION_SOURCE,
            "The deployment record and the public endpoint probes could not be read.",
        )

    lines: list[Line] = []
    unknown_repos: list[str] = []
    for lag in report.production_lag:
        if lag.status == "behind":
            fixes = len(lag.undeployed_fixes)
            lines.append(
                Line(
                    what=f"{lag.repo_full_name} production is {lag.behind_by} commit(s) "
                    f"behind {lag.branch or 'its branch'}.",
                    so_what=(
                        f"{fixes} merged fix(es) are not running, so their findings are "
                        "closed on the branch and open in production."
                        if fixes
                        else "What the branch says is fixed is not what production runs."
                    ),
                    work=DECISION,
                    repo_full_name=lag.repo_full_name,
                )
            )
        elif lag.status == "diverged":
            lines.append(
                Line(
                    what=f"{lag.repo_full_name} production runs {lag.not_on_branch} "
                    f"commit(s) that are not on {lag.branch or 'its branch'}.",
                    so_what="Production is running code nobody reviewed on the branch.",
                    work=DECISION,
                    repo_full_name=lag.repo_full_name,
                )
            )
        elif lag.status == "unknown":
            unknown_repos.append(lag.repo_full_name)
            lines.append(
                Line(
                    what=f"{lag.repo_full_name} has a deployment probe and no answer.",
                    so_what=lag.detail or "Whether production is current is unknown.",
                    work=STORY,
                    repo_full_name=lag.repo_full_name,
                )
            )
    # Repositories nothing probes (TheHub #60918). Named, because leaving them
    # out is how "production is current" and "production is not measured"
    # read the same; each one's missing settings are in `data.probe_setup`.
    unprobed = sorted(p["repo_full_name"] for p in report.probe_setup if not p.get("source"))
    if unprobed:
        total = len(report.probe_setup)
        lines.append(
            Line(
                what=f"Production truth covers {total - len(unprobed)} of {total} "
                f"repositories: {', '.join(unprobed)} "
                f"{'has' if len(unprobed) == 1 else 'have'} no deployment probe.",
                so_what="Nothing compares what they run with what was scanned. Set a "
                "probe URL for each that has a deployment; one with none needs nothing.",
                work=DECISION,
                ref="/api/dashboard/deployments",
            )
        )
    for endpoint in report.exposure:
        serious = [
            o for o in endpoint.get("observations") or []
            if o.get("severity") in ("critical", "high")
        ]
        if serious:
            lines.append(
                Line(
                    what=f"{endpoint.get('url')} shows anonymous visitors "
                    f"{len(serious)} critical/high exposure(s).",
                    so_what="; ".join(str(o.get("title")) for o in serious),
                    work=STORY,
                    repo_full_name=str(endpoint.get("repo_full_name") or ""),
                    ref="/api/exposure",
                )
            )

    missing = []
    if report.production_lag_unknown:
        missing.append("the deployment record could not be read")
    if report.exposure_unknown:
        missing.append("public endpoint probes could not be read")
    checked = [_naive(lag.checked_at) for lag in report.production_lag if lag.checked_at]
    probed = [
        _naive(datetime.fromisoformat(str(e["last_probed_at"])))
        for e in report.exposure
        if e.get("last_probed_at")
    ]
    stamps = checked + probed
    return Section(
        key=key,
        title=title,
        status=PARTIAL if missing else OK,
        source=PRODUCTION_SOURCE,
        # The oldest cached answer: the page is no fresher than that.
        as_of=min(stamps) if stamps else report.generated_at,
        reason="; ".join(missing).capitalize() + "." if missing else "",
        lines=lines,
        data={
            "deployments": [
                {
                    "repo_full_name": lag.repo_full_name,
                    "status": lag.status,
                    "branch": lag.branch,
                    "behind_by": lag.behind_by,
                    "not_on_branch": lag.not_on_branch,
                    "deployed_revision": lag.deployed_revision,
                    "undeployed_fixes": len(lag.undeployed_fixes),
                    "checked_at": lag.checked_at.isoformat() if lag.checked_at else None,
                }
                for lag in report.production_lag
            ],
            "deployments_unknown": unknown_repos,
            "deployments_not_configured": unprobed,
            "probe_setup": [
                {
                    "repo_full_name": p["repo_full_name"],
                    "source": p.get("source", ""),
                    "missing": list(p.get("missing") or []),
                }
                for p in report.probe_setup
            ],
            "public_endpoints": len(report.exposure),
        },
    )


# ---------------------------------------------------------------------------
# Can we trust our signals
# ---------------------------------------------------------------------------


TRUST_SOURCE = (
    "lake scan_runs (stalled and stale lanes); concourse (paused, failing, held-back "
    "jobs); job_runs (scheduled jobs); lake findings (unexplained mass closures)"
)


def _failing_line(failing: briefing_report.FailingLane) -> Line:
    """One red CI job, worded by its streak (TheHub #60906).

    One failure is not a trend: `ci_repeat` measured that a lane under three
    consecutive same-class failures usually heals on the next build, so a
    fresh failure is a decision (retrigger, or wait for the next run) rather
    than a story. A streak that could not be read keeps the story: unknown is
    not permission to downgrade.
    """
    from mykronos.ci_repeat import REPEAT_THRESHOLD

    name = f"{failing.pipeline}/{failing.job}"
    ref = failing.build_url or ""
    if failing.repeated is False:
        streak = failing.consecutive_failures or 1
        return Line(
            what=f"CI job {name} failed its last build"
            + (f" ({streak} in a row)." if streak > 1 else ", after a pass."),
            so_what=(
                "One failure is not a trend: a retrigger often clears it. It becomes "
                f"a story if it fails {REPEAT_THRESHOLD} builds running."
            ),
            work=DECISION,
            ref=ref,
        )
    if failing.repeated:
        return Line(
            what=f"CI job {name} has failed {failing.consecutive_failures} builds running "
            f"({failing.last_status}).",
            so_what="Its evidence is stale until it passes again, and waiting has not "
            "fixed it.",
            work=STORY,
            ref=ref,
        )
    return Line(
        what=f"CI job {name} is {failing.last_status}.",
        so_what="Its evidence is stale until it passes again. Its build history could "
        "not be read, so whether this is a pattern is unknown.",
        work=STORY,
        ref=ref,
    )


def trust_section(
    report: briefing_report.Briefing | None,
    risk: RiskDeltaRead | None,
    *,
    as_of: datetime | None,
    lake_error: str = "",
) -> Section:
    """Which signals the rest of the page rests on are not to be believed today."""
    key, title = "trust", "Can we trust our signals"
    if report is None:
        return unavailable(key, title, TRUST_SOURCE, lake_error or "The lake could not be read.")

    lines: list[Line] = []
    for lane in report.stalled:
        lines.append(
            Line(
                what=f"{lane.repo_full_name} {lane.capability} lane is {lane.reason}"
                + (
                    f" ({lane.consecutive_failures} failed run(s))"
                    if lane.consecutive_failures
                    else ""
                )
                + ".",
                so_what=f"{lane.open_findings} open finding(s) cannot close until it "
                "scans successfully twice, however well they were fixed.",
                work=STORY,
                repo_full_name=lane.repo_full_name,
            )
        )
    for stale in report.stale:
        lines.append(
            Line(
                what=f"{stale.repo_full_name} {stale.capability} lane keeps scanning "
                f"{stale.commit_sha} on {stale.branch} ({stale.reason}).",
                so_what="It reports success against a tree the repository has left: "
                "green, and covering nothing new.",
                work=STORY,
                repo_full_name=stale.repo_full_name,
            )
        )
    for paused in report.paused:
        lines.append(
            Line(
                what=f"CI job {paused.pipeline}/{paused.job} is paused.",
                so_what="A paused lane produces no scans, which looks like a quiet one.",
                work=DECISION,
                ref=paused.build_url or "",
            )
        )
    for failing in report.failing:
        lines.append(_failing_line(failing))
    for held in report.blocked:
        lines.append(
            Line(
                what=f"CI job {held.pipeline}/{held.job} is held behind {held.root} "
                f"({held.root_state}).",
                so_what="It shows its last green build and is not running.",
                work=STORY,
                repo_full_name=held.repo_full_name,
                ref=held.build_url or "",
            )
        )
    for job in report.unhealthy_jobs:
        lines.append(
            Line(
                what=f"Scheduled job {getattr(job, 'name', '?')} is "
                f"{getattr(job, 'status', '?')}.",
                so_what=str(getattr(job, "detail", "") or "Whatever it maintains is stale."),
                work=STORY,
            )
        )
    for mass in risk.mass_closures if risk else []:
        lines.append(
            Line(
                what=f"{mass.unexplained} finding(s) closed in {mass.repo_full_name} in "
                "24 hours with no merged fix or acceptance on record.",
                so_what="A real fix can do that; so can a scanner that stopped seeing "
                "things. Until somebody confirms which, the drop in the open count is "
                "not to be trusted.",
                work=DECISION,
                repo_full_name=mass.repo_full_name,
            )
        )

    missing = [
        why for name, why in report.unknown_sources() if name in ("concourse", "job_runs")
    ]
    if risk is None:
        missing.append("Closures could not be checked for an explanation.")
    return Section(
        key=key,
        title=title,
        status=PARTIAL if missing else OK,
        source=TRUST_SOURCE,
        as_of=as_of,
        reason=" ".join(missing),
        lines=lines,
        data={
            "stalled_lanes": len(report.stalled),
            "findings_held_open": report.blocked_findings,
            "stale_lanes": len(report.stale),
            "paused_jobs": len(report.paused),
            "failing_jobs": len(report.failing),
            # Of those, the ones past `ci_repeat.REPEAT_THRESHOLD` (#60906).
            "failing_repeatedly": sum(1 for f in report.failing if f.repeated),
            "held_back_jobs": len(report.blocked),
            "unhealthy_scheduled_jobs": len(report.unhealthy_jobs),
            # Needs no work: fixed, waiting only for scans to confirm.
            "closing_on_their_own": report.closing_soon,
            "mass_closures": len(risk.mass_closures) if risk else None,
        },
    )


# ---------------------------------------------------------------------------
# The board and the pull requests (B3, TheHub #60861)
# ---------------------------------------------------------------------------


#: Board conventions: the icebox holds what needs Todd's action, the backlog
#: what needs his decision, each titled so (TheHub's own routing rule).
OPERATOR_ACTION_PREFIX = "operator action:"
DECISION_PREFIX = "decision:"

#: A sprint story whose TheHub record has not changed in this many days is
#: stuck. Measured by `updated_at`, the only move stamp the story list
#: carries: an edit counts as a move, so this under-reports rather than
#: over-reports.
STUCK_DAYS = 3

#: Gates at which a sprint story should have a change open or merged.
#: `tested` and later have merged one already.
PRE_MERGE_GATES = ("intake", "clarified", "designed", "ready", "in_progress")
SHIPPED_GATES = ("deployed", "verified")

#: GitHub `mergeable_state` values that do not stop a green, mergeable pull
#: request from being merged by the person who merges every pull request:
#: `blocked` is branch protection waiting on that person's review.
_MERGEABLE_STATES = ("clean", "has_hooks", "unstable", "blocked", "")

NEEDS_YOU_SOURCE = (
    "TheHub board (icebox OPERATOR ACTION:, backlog DECISION:); GitHub open pull "
    "requests on onboarded repositories (mergeable, checks, age)"
)
SPRINT_SOURCE = "TheHub board (sprint and done buckets); GitHub open pull requests"


def _title(story: dict[str, Any]) -> str:
    return str(story.get("title") or "").strip()


def _story_ref(story: dict[str, Any]) -> str:
    return f"TheHub #{story.get('id')}"


def _parse(value: Any) -> datetime | None:
    from mykronos.po_console import parse_time

    return parse_time(value)


def _days(since: datetime | None, now: datetime) -> int | None:
    return max(0, (_naive(now) - since).days) if since is not None else None


def _age(days: int | None) -> str:
    return "" if days is None else f"open {days} day(s)"


@dataclass
class Readiness:
    """Where one pull request stands, for the person who merges it."""

    repo_full_name: str
    number: int
    url: str
    title: str
    #: ready | red | conflict | behind | waiting | pending | unknown | draft
    state: str
    why: str
    age_days: int | None
    checks: dict[str, int] | None
    mergeable_state: str
    story_ids: list[int]


#: Which states are a blocker, as against "not decided yet".
BLOCKED_STATES = ("red", "conflict", "behind", "waiting")


def pr_readiness(pr: Any, *, now: datetime) -> Readiness:
    """Ready to merge (mergeable and green), blocked (conflict, red checks, or
    waiting on another pull request), or not yet known -- never guessed ready."""
    checks = pr.checks
    counts = (
        {"total": checks.total, "passed": checks.passed, "failed": checks.failed,
         "pending": checks.pending}
        if checks is not None
        else None
    )
    stacked = bool(pr.base_branch) and bool(pr.default_branch) and (
        pr.base_branch != pr.default_branch
    )
    if pr.draft:
        state, why = "draft", "A draft: not offered for merge yet."
    elif stacked or pr.depends_on:
        on = ", ".join(f"#{n}" for n in pr.depends_on) or pr.base_branch
        state, why = "waiting", f"Stacked on {on}; it merges after that does."
    elif pr.mergeable is False or pr.mergeable_state == "dirty":
        state, why = "conflict", f"Conflicts with {pr.base_branch or 'its base'}."
    elif checks is not None and checks.failed:
        state, why = "red", f"{checks.failed} of {checks.total} check(s) failed."
    elif pr.mergeable_state == "behind":
        state, why = "behind", "Behind its base branch and must be updated first."
    elif checks is None:
        state, why = "unknown", "Its checks could not be read."
    elif checks.pending:
        state, why = "pending", f"{checks.pending} check(s) still running."
    elif pr.mergeable is None:
        state, why = "unknown", (
            "GitHub has not said whether it can merge."
            if pr.detail_read
            else "Its mergeable state was not read."
        )
    elif pr.mergeable_state not in _MERGEABLE_STATES:
        state, why = "unknown", f"GitHub says {pr.mergeable_state}."
    else:
        state, why = "ready", (
            f"Mergeable, {checks.passed}/{checks.total} check(s) green."
            if checks.total
            else "Mergeable; no checks ran on it."
        )
    return Readiness(
        repo_full_name=pr.repo_full_name,
        number=pr.number,
        url=pr.url,
        title=pr.title,
        state=state,
        why=why,
        age_days=_days(_naive(pr.opened_at) if pr.opened_at else None, now),
        checks=counts,
        mergeable_state=pr.mergeable_state,
        story_ids=list(pr.story_ids),
    )


def _pr_line(r: Readiness) -> Line | None:
    name = f"{r.repo_full_name}#{r.number}"
    age = _age(r.age_days)
    tail = f" ({age})" if age else ""
    if r.state == "ready":
        return Line(
            what=f"Merge {name}: {r.title}",
            so_what=f"{r.why} Waiting only on you{tail}.",
            work=MERGE, repo_full_name=r.repo_full_name, ref=r.url,
        )
    if r.state == "waiting":
        return Line(
            what=f"{name} waits on another pull request: {r.title}",
            so_what=f"{r.why} Merge that first{tail}.",
            work=MERGE, repo_full_name=r.repo_full_name, ref=r.url,
        )
    if r.state in ("red", "conflict", "behind"):
        fix = {
            "red": "Its checks failed, so it cannot merge until they pass",
            "conflict": "It cannot merge until it is rebased",
            "behind": "It cannot merge until the branch is updated",
        }[r.state]
        return Line(
            what=f"{name} is blocked: {r.why}",
            so_what=f"{fix}: {r.title}{tail}.",
            work=STORY, repo_full_name=r.repo_full_name, ref=r.url,
        )
    return None


def _board_items(board: Any, now: datetime) -> tuple[list[Line], list[Line], dict[str, Any]]:
    actions = [
        s for s in board.stories.get("icebox", [])
        if _title(s).lower().startswith(OPERATOR_ACTION_PREFIX)
    ]
    decisions = [
        s for s in board.stories.get("backlog", [])
        if _title(s).lower().startswith(DECISION_PREFIX)
    ]

    def waited(story: dict[str, Any]) -> int | None:
        return _days(_parse(story.get("moved_at")) or _parse(story.get("created_at")), now)

    def oldest_first(stories: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return sorted(stories, key=lambda s: -(waited(s) or 0))

    action_lines = [
        Line(
            what=_title(s),
            so_what="Needs your action, and nobody else can take it"
            + (f": in the icebox {waited(s)} day(s)." if waited(s) is not None else "."),
            work=STORY,
            ref=_story_ref(s),
        )
        for s in oldest_first(actions)
    ]
    decision_lines = [
        Line(
            what=_title(s),
            so_what="A call only you can make; the work behind it waits"
            + (f" ({waited(s)} day(s) so far)." if waited(s) is not None else "."),
            work=DECISION,
            ref=_story_ref(s),
        )
        for s in oldest_first(decisions)
    ]
    data = {
        "operator_actions": [
            {"id": s.get("id"), "title": _title(s), "waiting_days": waited(s)} for s in actions
        ],
        "decisions": [
            {"id": s.get("id"), "title": _title(s), "waiting_days": waited(s)} for s in decisions
        ],
    }
    return action_lines, decision_lines, data


def _stamps(*reads: Any) -> list[datetime]:
    return [_naive(r.as_of) for r in reads if r is not None]


def needs_you_section(delivery: Any, *, now: datetime) -> Section:
    """What is waiting on the operator today: pull requests to merge or
    unblock, and the board items only he can act on or decide."""
    key, title = "needs_you_today", "Needs you today"
    board, prs = delivery.board, delivery.pull_requests
    if board is None and prs is None:
        return unavailable(
            key, title, NEEDS_YOU_SOURCE, f"{delivery.board_error} {delivery.pull_requests_error}"
        )

    missing: list[str] = []
    lines: list[Line] = []
    data: dict[str, Any] = {}

    if prs is not None:
        readiness = [pr_readiness(pr, now=now) for pr in prs.pull_requests]
        readiness.sort(key=lambda r: -(r.age_days or 0))
        ready = [r for r in readiness if r.state == "ready"]
        blocked = [r for r in readiness if r.state in BLOCKED_STATES]
        lines.extend(line for r in ready if (line := _pr_line(r)) is not None)
        data["pr_readiness"] = {
            "open": len(readiness),
            "ready": [asdict(r) for r in ready],
            "blocked": [asdict(r) for r in blocked],
            "failed_checks": [asdict(r) for r in readiness if r.state == "red"],
            "pending": [asdict(r) for r in readiness if r.state == "pending"],
            "unknown": [asdict(r) for r in readiness if r.state == "unknown"],
            "drafts": sum(1 for r in readiness if r.state == "draft"),
            "unreachable_repos": [repo for repo, _ in prs.unreachable],
            "details_unread": prs.details_unread,
        }
        if prs.stale:
            missing.append(f"{prs.reason} Pull requests are as of {prs.as_of.isoformat()}.")
        if prs.unreachable:
            missing.append(
                "GitHub would not list pull requests for "
                + ", ".join(sorted({repo for repo, _ in prs.unreachable}))
                + "."
            )
        if prs.details_unread:
            missing.append(
                f"{prs.details_unread} pull request(s) had no mergeable verdict read, so "
                "they are not counted as ready."
            )
    else:
        missing.append(delivery.pull_requests_error)
        blocked = []

    if board is not None:
        action_lines, decision_lines, board_data = _board_items(board, now)
        lines.extend(decision_lines)
        lines.extend(action_lines)
        data["board"] = board_data
        if board.stale:
            missing.append(f"{board.reason} The board is as of {board.as_of.isoformat()}.")
    else:
        missing.append(delivery.board_error)

    lines.extend(line for r in blocked if (line := _pr_line(r)) is not None)
    stamps = _stamps(board, prs)
    return Section(
        key=key,
        title=title,
        status=PARTIAL if missing else OK,
        source=NEEDS_YOU_SOURCE,
        # The oldest answer: the section is no fresher than that.
        as_of=min(stamps) if stamps else None,
        reason=" ".join(missing),
        lines=lines,
        data=data,
    )


def sprint_health_section(delivery: Any, *, now: datetime) -> Section:
    """Sprint stories by gate, the stuck ones, the ones with no change open,
    and what reached `deployed` in the window."""
    from mykronos.product_owner import HUB_GATES

    key, title = "sprint_health", "Sprint health"
    board, prs = delivery.board, delivery.pull_requests
    if board is None:
        return unavailable(key, title, SPRINT_SOURCE, delivery.board_error)

    sprint = board.stories.get("sprint", [])
    counts = Counter(str(s.get("gate") or "intake") for s in sprint)
    by_gate = {gate: counts.pop(gate, 0) for gate in HUB_GATES}
    by_gate.update(sorted(counts.items()))

    def is_board_item(story: dict[str, Any]) -> bool:
        lowered = _title(story).lower()
        return lowered.startswith((OPERATOR_ACTION_PREFIX, DECISION_PREFIX))

    lines: list[Line] = []
    stuck = []
    for story in sprint:
        gate = str(story.get("gate") or "intake")
        idle = _days(_parse(story.get("updated_at")), now)
        if gate in SHIPPED_GATES or idle is None or idle < STUCK_DAYS:
            continue
        stuck.append({"id": story.get("id"), "title": _title(story), "gate": gate,
                      "idle_days": idle})
    stuck.sort(key=lambda s: -int(s["idle_days"]))
    for s in stuck:
        lines.append(
            Line(
                what=f"TheHub #{s['id']} has not moved in {s['idle_days']} day(s) "
                f"(at {s['gate']}): {s['title']}",
                so_what="Stuck in the sprint: unblock it, split it, or take it out.",
                work=DECISION,
                ref=f"TheHub #{s['id']}",
            )
        )

    missing: list[str] = []
    no_pr: list[dict[str, Any]] | None = None
    if prs is not None:
        referenced = {sid for pr in prs.pull_requests for sid in pr.story_ids}
        no_pr = [
            {"id": s.get("id"), "title": _title(s), "gate": str(s.get("gate") or "intake")}
            for s in sprint
            if str(s.get("gate") or "intake") in PRE_MERGE_GATES
            and not is_board_item(s)
            and _int(s.get("id")) not in referenced
        ]
        for s in no_pr:
            lines.append(
                Line(
                    what=f"TheHub #{s['id']} is in the sprint with no open pull request: "
                    f"{s['title']}",
                    so_what="Committed work nobody has opened a change for.",
                    work=STORY,
                    ref=f"TheHub #{s['id']}",
                )
            )
        if prs.unreachable or prs.stale:
            missing.append(
                "Pull requests were not read for every repository, so a story counted "
                "as having none may have one."
            )
    else:
        missing.append(
            "Which sprint stories have no pull request needs GitHub: "
            + delivery.pull_requests_error
        )
    if board.stale:
        missing.append(f"{board.reason} The board is as of {board.as_of.isoformat()}.")

    since = _naive(now) - WINDOW
    deployed = []
    for story in [*sprint, *board.stories.get("done", [])]:
        if str(story.get("gate") or "") not in SHIPPED_GATES:
            continue
        moved = [
            t for t in (_parse(story.get(f)) for f in ("updated_at", "moved_at", "closed_at"))
            if t is not None
        ]
        if moved and max(moved) >= since:
            deployed.append({"id": story.get("id"), "title": _title(story),
                             "gate": story.get("gate"), "at": max(moved).isoformat()})

    return Section(
        key=key,
        title=title,
        status=PARTIAL if missing else OK,
        source=SPRINT_SOURCE,
        as_of=_naive(board.as_of),
        reason=" ".join(missing),
        lines=lines,
        data={
            "sprint_stories": len(sprint),
            "by_gate": by_gate,
            "stuck_days": STUCK_DAYS,
            "moves_measured_by": "updated_at",
            "stuck": stuck,
            "no_pull_request": no_pr,
            "deployed_last_24h": deployed,
        },
    )


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Already on the board
# ---------------------------------------------------------------------------


def _norm(text: str) -> str:
    return " ".join(re.sub(r"[^a-z0-9]+", " ", text.lower()).split())


#: A title shorter than this is too generic to match by containment.
_MIN_TITLE_MATCH = 20


def on_board(line: Line, stories: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The board story this line already is, by the finding or fix id it
    references, or by title. None when it is new work."""
    ref = line.ref.strip()
    what = _norm(line.what)
    for story in stories:
        haystack = " ".join(
            str(story.get(f) or "") for f in ("title", "detail", "source_ref")
        )
        if ref and len(ref) >= 6 and not ref.startswith(("/", "http")) and ref in haystack:
            return story
        title = _norm(_title(story))
        if not title or not what:
            continue
        if title == what:
            return story
        shorter, longer = sorted((title, what), key=len)
        if len(shorter) >= _MIN_TITLE_MATCH and shorter in longer:
            return story
    return None


def _not_on_board(
    lines: list[Line], stories: list[dict[str, Any]] | None
) -> tuple[list[Line], list[dict[str, Any]]]:
    if stories is None:
        return lines, []
    kept, dropped = [], []
    for line in lines:
        story = on_board(line, stories)
        if story is None:
            kept.append(line)
        else:
            dropped.append({"what": line.what, "story": _story_ref(story)})
    return kept, dropped


# ---------------------------------------------------------------------------
# The roll-up
# ---------------------------------------------------------------------------


#: Decisions before stories: a decision unblocks the work behind it.
_FOCUS_ORDER = {DECISION: 0, MERGE: 1, STORY: 2}
FOCUS_LIMIT = 5

#: Sections whose lines are board items or pull requests already: never
#: filtered as "already on the board".
_FROM_THE_BOARD = ("needs_you_today", "sprint_health")


def focus_section(
    sections: list[Section],
    *,
    now: datetime,
    board: Any = None,
    board_error: str = "TheHub's board was not read.",
    key: str = "suggested_focus",
    title: str = "Suggested focus",
) -> Section:
    """The few lines from the rest of the page to start with, leaving out
    the lake's items that are already a story on TheHub's board."""
    source = "this briefing's sections; TheHub board (what is already a story)"
    readable = [s for s in sections if s.status in (OK, PARTIAL)]
    if not readable:
        return unavailable(key, title, source, "None of the sections it ranks could be read.")
    stories = board.open_stories() if board is not None else None
    board_lines = [line for s in readable if s.key in _FROM_THE_BOARD for line in s.lines]
    lake_lines, dropped = _not_on_board(
        [line for s in readable if s.key not in _FROM_THE_BOARD for line in s.lines], stories
    )
    ranked = sorted(board_lines + lake_lines, key=lambda line: _FOCUS_ORDER[line.work])

    missing = []
    if board is None:
        missing.append(
            f"Items already on the board could not be left out. {board_error}"
        )
    elif board.stale:
        missing.append(f"{board.reason} The board is as of {board.as_of.isoformat()}.")
    unread = [s.title for s in sections if s.status != OK]
    if unread:
        missing.append(f"Ranked without: {', '.join(unread)}.")
    return Section(
        key=key,
        title=title,
        status=PARTIAL if missing else OK,
        source=source,
        as_of=now,
        reason=" ".join(missing),
        lines=ranked[:FOCUS_LIMIT],
        data={"candidates": len(ranked), "already_on_board": dropped},
    )


# ---------------------------------------------------------------------------
# Per product
# ---------------------------------------------------------------------------


LANES_SOURCE = "lake scan_runs; stalled and stale lane analysis"


def lane_strip(
    catalog: Catalog,
    report: briefing_report.Briefing | None,
    asset_id: str,
    *,
    as_of: datetime | None,
) -> Section:
    """One cell per capability: the newest run and whether it can be believed."""
    key, title = "capability_lanes", "Capability lanes"
    try:
        rows = catalog.query(
            """
            SELECT capability, scan_status, ts, scan_run_id FROM (
                SELECT capability, scan_status, scan_run_id,
                       coalesce(completed_at, started_at) AS ts,
                       row_number() OVER (
                           PARTITION BY capability
                           ORDER BY coalesce(completed_at, started_at) DESC
                       ) AS rn
                FROM scan_runs WHERE repo_full_name = ?
            ) WHERE rn = 1 ORDER BY capability
            """,
            [asset_id],
        )
    except Exception as exc:  # noqa: BLE001 - reported, never shown as none
        logger.debug("Could not read scan runs")
        return unavailable(key, title, LANES_SOURCE, _error(exc))
    if report is None:
        return unavailable(key, title, LANES_SOURCE, "The lane analysis could not be built.")

    stalled = {lane.capability: lane for lane in report.stalled}
    stale = {lane.capability: lane for lane in report.stale}
    cells = []
    lines: list[Line] = []
    for capability, scan_status, ts, run_id in rows:
        cap = str(capability)
        state = "ok"
        if cap in stalled:
            state = stalled[cap].reason
        elif cap in stale:
            state = "stale"
        cells.append(
            {
                "capability": cap,
                "state": state,
                "last_status": str(scan_status or ""),
                "last_run_at": ts.isoformat() if isinstance(ts, datetime) else None,
                "last_scan_run_id": str(run_id or ""),
                "open_findings_held": stalled[cap].open_findings if cap in stalled else 0,
            }
        )
        if cap in stalled:
            lane = stalled[cap]
            lines.append(
                Line(
                    what=f"{cap} lane is {lane.reason}.",
                    so_what=f"{lane.open_findings} open finding(s) cannot close until it "
                    "scans successfully twice.",
                    work=STORY,
                    repo_full_name=asset_id,
                    ref=f"/api/dashboard/scan-runs/{lane.last_scan_run_id}"
                    if lane.last_scan_run_id
                    else "",
                )
            )
    return Section(
        key=key,
        title=title,
        status=OK,
        source=LANES_SOURCE,
        as_of=as_of,
        lines=lines,
        data={"lanes": cells},
    )


def deploy_and_health(report: briefing_report.Briefing, asset_id: str) -> Section:
    """This product's production lag and endpoints, from the overall builder."""
    section = production_section(report, key="deploy_and_health", title="Deploy and health")
    if section.status == UNAVAILABLE or report.production_lag_unknown:
        return section
    if not report.production_lag:
        # Not a fault -- a library has no production -- but the page must not
        # read as "production is current" either.
        return Section(
            key=section.key,
            title=section.title,
            status=PARTIAL,
            source=section.source,
            as_of=section.as_of,
            reason=f"{asset_id} has no deployment probe, so what production runs is "
            "unknown.",
            lines=section.lines,
            data={**section.data, "probe_configured": False},
        )
    section.data["probe_configured"] = True
    return section


CANDIDATES_SOURCE = (
    "lake findings (guidance fix groups); stalled lanes; TheHub board (what is "
    "already a story)"
)
CANDIDATE_LIMIT = 5


def next_sprint_candidates(
    catalog: Catalog,
    report: briefing_report.Briefing | None,
    asset_id: str,
    *,
    as_of: datetime | None,
    board: Any = None,
    board_error: str = "TheHub's board was not read.",
) -> Section:
    """Changes that would close the most of this product's open findings.

    Derived from the scanner's own fix text (`guidance.fix_groups`), largest
    first, after any lane repair: a fix nobody can scan closes nothing.
    New work only: a candidate that is already a story on TheHub's board (by
    the fix id it carries, or by title) is left out and listed in `data`.
    `partial` when the board could not be read to check.
    """
    from mykronos import guidance

    key, title = "next_sprint_candidates", "Next-sprint candidates"
    try:
        groups = guidance.fix_groups(catalog, asset_id=asset_id)
    except Exception as exc:  # noqa: BLE001 - reported, never shown as none
        logger.debug("Could not group fixes")
        return unavailable(key, title, CANDIDATES_SOURCE, _error(exc))

    lines: list[Line] = []
    for lane in report.stalled if report else []:
        lines.append(
            Line(
                what=f"Repair the {lane.capability} lane ({lane.reason}).",
                so_what=f"Holds {lane.open_findings} open finding(s) that cannot close "
                "otherwise.",
                work=STORY,
                repo_full_name=asset_id,
            )
        )
    for group in sorted(groups, key=lambda g: -g.findings):
        lines.append(
            Line(
                what=group.action,
                so_what=f"Closes {group.findings} open {group.capability} finding(s) "
                f"across {len(group.rules)} rule(s); effort: {group.effort}.",
                work=STORY,
                repo_full_name=asset_id,
                ref=group.fix_id,
            )
        )
    stories = board.open_stories() if board is not None else None
    repairs = len(report.stalled) if report else 0
    kept_repairs, dropped_repairs = _not_on_board(lines[:repairs], stories)
    # The cap applies to the fix groups left after the board check, so a
    # filtered one makes room for the next rather than shortening the list.
    kept_fixes, dropped_fixes = _not_on_board(lines[repairs:], stories)
    kept_fixes = kept_fixes[:CANDIDATE_LIMIT]
    dropped = dropped_repairs + dropped_fixes
    missing = ""
    if board is None:
        missing = f"Candidates already on the board could not be left out. {board_error}"
    elif board.stale:
        missing = f"{board.reason} The board is as of {board.as_of.isoformat()}."
    return Section(
        key=key,
        title=title,
        status=PARTIAL if missing else OK,
        source=CANDIDATES_SOURCE,
        as_of=as_of,
        reason=missing,
        lines=kept_repairs + kept_fixes,
        data={"fix_groups": len(groups), "already_on_board": dropped},
    )


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------


def _report(
    catalog: Catalog, inputs: dict[str, Any], *, now: datetime, asset_id: str | None
) -> tuple[briefing_report.Briefing | None, str]:
    try:
        return briefing_report.build(catalog, now=now, asset_id=asset_id, **inputs), ""
    except Exception as exc:  # noqa: BLE001 - one store must not take the page
        logger.debug("Could not build the lane briefing")
        return None, _error(exc)


def _risk(
    catalog: Catalog, db: Any, *, now: datetime, asset_id: str | None, threshold: int | None
) -> tuple[RiskDeltaRead | None, str]:
    try:
        return (
            read_risk_delta(catalog, db, now=now, asset_id=asset_id, threshold=threshold),
            "",
        )
    except Exception as exc:  # noqa: BLE001 - one store must not take the page
        logger.debug("Could not read the risk delta")
        return None, _error(exc)


def _as_of(catalog: Catalog, asset_id: str | None) -> datetime | None:
    try:
        return lake_as_of(catalog, asset_id)
    except Exception:  # noqa: BLE001 - a missing stamp is reported as None
        return None


def build_overall(
    catalog: Catalog,
    db: Any,
    build_inputs: dict[str, Any],
    *,
    now: datetime,
    threshold: int | None = None,
    delivery: Any = None,
) -> DailyBriefing:
    """Every overall section, in the order the prototype reads them.

    `build_inputs` are `briefing.build`'s keyword arguments from outside the
    lake (`briefing_sources.gather` and the onboarding ledger); `delivery` is
    `delivery_sources.gather`'s board and pull requests. Without it those
    sections say they were not read.
    """
    from mykronos.delivery_sources import DeliveryInputs

    delivery = delivery if delivery is not None else DeliveryInputs()
    report, lake_error = _report(catalog, build_inputs, now=now, asset_id=None)
    risk, risk_error = _risk(catalog, db, now=now, asset_id=None, threshold=threshold)
    as_of = _as_of(catalog, None)

    production = (
        production_section(report)
        if report
        else unavailable("production_truth", "Production truth", PRODUCTION_SOURCE, lake_error)
    )
    trust = trust_section(report, risk, as_of=as_of, lake_error=lake_error)
    delta = risk_delta_section(risk, risk_error)
    acceptances = acceptances_section(db, now=now)
    needs_you = needs_you_section(delivery, now=now)
    sprint = sprint_health_section(delivery, now=now)
    focus = focus_section(
        [needs_you, production, trust, delta, acceptances, sprint],
        now=now,
        board=delivery.board,
        board_error=delivery.board_error,
    )
    return DailyBriefing(
        generated_at=now,
        scope="overall",
        repo_full_name=None,
        sections=[needs_you, production, trust, delta, acceptances, sprint, focus],
    )


def build_product(
    catalog: Catalog,
    db: Any,
    build_inputs: dict[str, Any],
    *,
    asset_id: str,
    now: datetime,
    threshold: int | None = None,
    delivery: Any = None,
) -> DailyBriefing:
    """One product: deploy and health, findings delta, lanes, candidates."""
    from mykronos.delivery_sources import DeliveryInputs

    delivery = delivery if delivery is not None else DeliveryInputs()
    report, lake_error = _report(catalog, build_inputs, now=now, asset_id=asset_id)
    risk, risk_error = _risk(catalog, db, now=now, asset_id=asset_id, threshold=threshold)
    as_of = _as_of(catalog, asset_id)

    deploy = (
        deploy_and_health(report, asset_id)
        if report
        else unavailable("deploy_and_health", "Deploy and health", PRODUCTION_SOURCE, lake_error)
    )
    delta = risk_delta_section(risk, risk_error)
    delta.key, delta.title = "findings_delta", "Findings delta"
    return DailyBriefing(
        generated_at=now,
        scope="product",
        repo_full_name=asset_id,
        sections=[
            deploy,
            delta,
            lane_strip(catalog, report, asset_id, as_of=as_of),
            next_sprint_candidates(
                catalog,
                report,
                asset_id,
                as_of=as_of,
                board=delivery.board,
                board_error=delivery.board_error,
            ),
        ],
    )
