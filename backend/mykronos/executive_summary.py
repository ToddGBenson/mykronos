"""One repository's security posture on one page, for a reader who will not
open the other tabs.

Every tab on the repository page answers an operator's question. The person
this answers is the one who asks "are we all right?" and has five minutes:
how much is open and how bad, whether it is getting better, what is causing
it, how much of it anybody can do anything about, whether the scanners behind
the numbers are actually running, and what is waiting on a decision.

**Nothing here is new reasoning.** Every section is a reading the platform
already makes somewhere else, gathered: severity counts are the Findings
tab's `status = 'open'` rows; fixability is `guidance`'s effort classes, which
the Remediate today tab ranks by; lane health is the briefing's
`stalled_lanes` and `stale_lanes`; "closing on their own" is the briefing's
`awaiting_closure`. A second, quietly different answer to a question the
platform already answers would be worse than no page.

**A gap is stated, never filled.** The trend is reconstructed from
`first_seen_at` and `resolved_at`, as `maturity.trend_series` does, and a
comparison point earlier than this repository's first scan is reported as
unavailable rather than as zero: "nothing was open" and "nothing was looking"
are different facts, and only one of them is good news. A lane that has never
run, or has stopped, is named beside the counts it makes doubtful.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Any

from mykronos import briefing, guidance
from mykronos.lake.catalog import Catalog
from mykronos.schemas import Capability, Severity, utcnow

#: Worst first, every level always present: a zero is an answer.
SEVERITY_ORDER: tuple[str, ...] = tuple(s.value for s in reversed(Severity))
SERIOUS: tuple[str, ...] = (Severity.CRITICAL.value, Severity.HIGH.value)

#: The lanes that look for security findings, in the order the repository
#: page lists them. Quality stages report a pass/fail and never a finding
#: (D-046), and Aegis, Oracle and Patchwork run no scan, so a "never ran" for
#: any of those would be a fault that does not exist.
SCAN_CAPABILITIES: tuple[str, ...] = tuple(
    c.value
    for c in (
        Capability.SAST,
        Capability.SECRETS,
        Capability.ATLAS,
        Capability.CONTAINERS,
        Capability.IAC,
        Capability.DAST,
        Capability.CLOUD,
        Capability.NETWORK,
        Capability.AI,
    )
)

#: How far back the severity comparison looks.
COMPARE_DAYS: tuple[int, ...] = (7, 30)
#: The window "recent progress" counts over.
PROGRESS_DAYS = 30
DRIVER_LIMIT = 5
EXPIRY_LIMIT = 3

#: `guidance.EFFORT` folded into the three answers a reader wants. A
#: credential to rotate is work somebody can do today; a judgement is work
#: too, but it starts with somebody reading the finding, and a page that
#: called it "fixable now" would be promising a fix nobody has identified.
FIXABLE_NOW = ("config", "upgrade", "rotate")
NEEDS_REVIEW = ("judgement",)
NO_VENDOR_FIX = ("no_fix",)


@dataclass
class TrendPoint:
    days_ago: int
    at: datetime
    #: False when the point is earlier than this repository's first scan. The
    #: counts are then None, not zero.
    available: bool
    open_by_severity: dict[str, int] | None = None
    open_total: int | None = None


@dataclass
class Driver:
    """One place the open findings pile up."""

    capability: str
    #: "image", "package" or "rule" -- what `name` is.
    kind: str
    name: str
    findings: int
    critical: int
    high: int


@dataclass
class FixBucket:
    #: "fixable_now", "needs_review" or "no_vendor_fix".
    key: str
    findings: int
    #: The critical and high subset.
    serious: int


@dataclass
class Expiry:
    on: date
    findings: int


@dataclass
class Accepted:
    """Accepted risk: findings a person decided to live with, and until when."""

    findings: int = 0
    serious: int = 0
    #: Accepted with no date to look again. A decision, but one nobody is
    #: scheduled to revisit.
    no_review_date: int = 0
    #: Past their date and still accepted. The daily sweep re-opens these, so
    #: a number here is either mid-flight or a sweep that is not running.
    overdue: int = 0
    #: Accepted because no fix existed, and a fix has since been published.
    now_fixable: int = 0
    next_expiries: list[Expiry] = field(default_factory=list)
    #: Spec 33 acceptance decisions for this repository, by state. One
    #: decision covers many findings, which is why these are counted apart.
    decisions_active: int = 0
    decisions_review_due: int = 0
    decisions_pending: int = 0
    nearest_decision_expiry: date | None = None


@dataclass
class Lane:
    capability: str
    #: "ok", "failing", "silent", "blocked", "not_covering" or "never_ran".
    #: Everything but "ok" means the counts from this lane cannot be trusted
    #: to be current: a finding closes only after two successful scans see it
    #: gone (`reconcile.REQUIRED_ABSENCES`).
    status: str
    last_run_at: datetime | None = None
    last_run_status: str | None = None
    last_success_at: datetime | None = None
    open_findings: int = 0
    #: For "blocked", the upstream lane it is waiting on.
    blocked_by: str = ""
    #: For "failing", how many runs in a row.
    consecutive_failures: int = 0
    #: For "not_covering", "same_commit" or "wrong_branch".
    stale_reason: str = ""


@dataclass
class Progress:
    days: int
    #: Reached `fixed`: two successful scans in a row no longer saw it.
    fixed: int = 0
    fixed_serious: int = 0
    #: Dismissed by a person as not a real problem.
    false_positive: int = 0
    #: Moved to accepted risk inside the window.
    accepted: int = 0
    #: First seen inside the window (re-identified records excluded).
    new: int = 0
    new_serious: int = 0
    #: Withdrawn because the same problem was re-identified under a new id,
    #: which happens when code moves or an adapter changes. Neither progress
    #: nor regression, so it is counted apart rather than inside "fixed"; the
    #: successor inherits the original first-seen date, so it is not in `new`.
    reidentified: int = 0
    #: When the window starts before this repository's first scan, the first
    #: scan: the window is shorter than it says.
    window_starts: datetime | None = None


@dataclass
class Decision:
    """Something waiting on a person."""

    #: "approval" (a spec 34 request) or "acceptance_review" (a spec 33
    #: acceptance whose review date has arrived).
    kind: str
    id: str
    #: The duty, for an approval: `pull_request_merge`, `risk_acceptance`,
    #: `finding_disposition`.
    duty: str
    summary: str
    created_at: datetime | None = None
    due: datetime | None = None
    overdue: bool = False


@dataclass
class ExecutiveSummary:
    repo_full_name: str
    generated_at: datetime
    open_by_severity: dict[str, int]
    open_total: int
    #: This repository's first recorded scan. None when it has never scanned,
    #: and then every zero on the page measured nothing.
    history_since: datetime | None
    trend: list[TrendPoint]
    drivers: list[Driver]
    #: What `drivers` is a breakdown of: "critical_high" when anything serious
    #: is open, "all_open" when only lower severities are, "none" when nothing
    #: is.
    drivers_basis: str
    drivers_basis_total: int
    #: Open findings in the basis, per scan type.
    basis_by_capability: dict[str, int]
    fixability: list[FixBucket]
    #: Open findings already absent from their lane's newest successful scan,
    #: closing on their own once one more scan confirms it.
    closing_on_their_own: int
    accepted: Accepted
    lanes: list[Lane]
    progress: Progress
    decisions: list[Decision]
    #: What this report could not establish, in plain language.
    gaps: list[str]


def image_name(reference: str) -> str:
    """An image reference as somebody would say it: no registry, no digest.

    `registry.example:5000/team/app:1.2@sha256:...` is `team/app:1.2`. The
    registry host is an address on somebody's network rather than part of
    what the image is, and a digest is a checksum; neither belongs in a
    sentence a person reads aloud. The first path segment is a registry only
    when it looks like a host (a dot, a port or `localhost`), Docker's own
    rule, so `team/app` keeps its namespace.
    """
    ref = reference.strip()
    ref = ref.split("@", 1)[0]
    parts = ref.split("/")
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        parts = parts[1:]
    return "/".join(parts) or reference


def _counts(rows: list[tuple[Any, ...]]) -> dict[str, int]:
    out = dict.fromkeys(SEVERITY_ORDER, 0)
    for severity, count in rows:
        if str(severity) in out:
            out[str(severity)] = int(count)
    return out


def _raw(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    try:
        parsed = json.loads(value) if value else {}
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _bucket(effort: str) -> str:
    if effort in FIXABLE_NOW:
        return "fixable_now"
    if effort in NO_VENDOR_FIX:
        return "no_vendor_fix"
    return "needs_review"


def _rule_name(rule_id: str, title: str) -> str:
    """A rule as a person would say it.

    Semgrep titles are "Semgrep Finding: " and then the whole namespaced rule
    id; the last segment is the name, as the briefing shortens it.
    """
    name = guidance.rule_title(title) or rule_id
    if "." in rule_id and rule_id in name:
        tail = rule_id.rsplit(".", 1)[-1]
        return tail if len(tail) > 3 else rule_id
    return name


def _drivers(rows: list[tuple[Any, ...]]) -> list[Driver]:
    """Group the basis findings by what a person would fix once.

    An image for container findings and a package for dependency findings,
    because that is the unit of the fix -- "55 of 57 come from one database
    image" is a rebuild, not 55 tickets. A rule for everything else, for the
    reason `guidance.by_rule` groups by rule.
    """
    groups: dict[tuple[str, str, str], Driver] = {}
    for capability, severity, package, image, rule_id, title in rows:
        capability = str(capability)
        if capability == Capability.CONTAINERS.value and image:
            kind, key, name = "image", str(image), image_name(str(image))
        elif capability in (Capability.CONTAINERS.value, Capability.ATLAS.value) and package:
            kind, key, name = "package", str(package), str(package)
        else:
            kind, key = "rule", str(rule_id or "(unattributed)")
            name = _rule_name(key, str(title or ""))
        entry = groups.get((capability, kind, key))
        if entry is None:
            entry = groups[(capability, kind, key)] = Driver(
                capability=capability, kind=kind, name=name, findings=0, critical=0, high=0
            )
        entry.findings += 1
        if severity == Severity.CRITICAL.value:
            entry.critical += 1
        elif severity == Severity.HIGH.value:
            entry.high += 1
    ranked = sorted(
        groups.values(), key=lambda d: (-d.critical, -d.findings, d.capability, d.name)
    )
    return ranked[:DRIVER_LIMIT]


def _lanes(
    catalog: Catalog,
    repo_full_name: str,
    *,
    now: datetime,
    enabled: set[str],
    default_branch: str,
    open_by_capability: dict[str, int],
) -> list[Lane]:
    """Every scanning lane enabled here or that has ever reported, and whether
    its numbers can be believed today -- the briefing's verdict, scoped."""
    runs: dict[str, tuple[Any, ...]] = {}
    if catalog.all_files("scan_runs"):
        for capability, last_run, last_status, last_success in catalog.query(
            """
            SELECT capability,
                   max(ran_at),
                   arg_max(scan_status, ran_at),
                   max(ran_at) FILTER (WHERE scan_status = 'success')
            FROM (
                SELECT capability, scan_status,
                       coalesce(completed_at, started_at) AS ran_at
                FROM scan_runs WHERE repo_full_name = ?
            )
            GROUP BY 1
            """,
            [repo_full_name],
        ):
            runs[str(capability)] = (last_run, last_status, last_success)

    stalled = {
        lane.capability: lane
        for lane in briefing.stalled_lanes(catalog, now=now)
        if lane.repo_full_name == repo_full_name
    }
    stale = {
        lane.capability: lane
        for lane in briefing.stale_lanes(
            catalog,
            now=now,
            default_branches={repo_full_name: default_branch} if default_branch else None,
        )
        if lane.repo_full_name == repo_full_name
    }

    lanes: list[Lane] = []
    for capability in SCAN_CAPABILITIES:
        if capability not in enabled and capability not in runs:
            continue
        lane = Lane(capability=capability, status="ok")
        lane.open_findings = open_by_capability.get(capability, 0)
        if capability not in runs:
            lane.status = "never_ran"
            lanes.append(lane)
            continue
        last_run, last_status, last_success = runs[capability]
        lane.last_run_at = last_run
        lane.last_run_status = str(last_status) if last_status is not None else None
        lane.last_success_at = last_success
        if capability in stalled:
            lane.status = stalled[capability].reason
            lane.blocked_by = stalled[capability].blocked_by
            lane.consecutive_failures = stalled[capability].consecutive_failures
        elif capability in stale:
            lane.status = "not_covering"
            lane.stale_reason = stale[capability].reason
        lanes.append(lane)
    return lanes


def build(
    catalog: Catalog,
    repo_full_name: str,
    *,
    now: datetime | None = None,
    enabled: set[str] | None = None,
    default_branch: str = "",
    acceptance_records: list[dict[str, Any]] | None = None,
    decisions: list[Decision] | None = None,
    gaps: list[str] | None = None,
) -> ExecutiveSummary:
    """The page, from the lake.

    `enabled`, `default_branch`, `acceptance_records` and `decisions` live in
    the operational database and are handed in, the way the briefing takes
    its operational inputs: this module reads only the lake. Each acceptance
    record needs `status`, `expires_at` and nothing else.
    """
    stamp = now or utcnow()
    today = stamp.date()
    notes = list(gaps or [])
    has_findings = bool(catalog.all_files("findings"))

    def query(sql: str, params: list[Any]) -> list[tuple[Any, ...]]:
        return catalog.query(sql, params) if has_findings else []

    open_by_severity = _counts(
        query(
            "SELECT severity, count(*) FROM findings "
            "WHERE asset_id = ? AND status = 'open' GROUP BY 1",
            [repo_full_name],
        )
    )
    open_total = sum(open_by_severity.values())
    open_by_capability = {
        str(capability): int(count)
        for capability, count in query(
            "SELECT capability, count(*) FROM findings "
            "WHERE asset_id = ? AND status = 'open' GROUP BY 1",
            [repo_full_name],
        )
    }

    history_since: datetime | None = None
    if catalog.all_files("scan_runs"):
        first = catalog.query(
            "SELECT min(coalesce(completed_at, started_at)) FROM scan_runs "
            "WHERE repo_full_name = ?",
            [repo_full_name],
        )
        history_since = first[0][0] if first and first[0][0] is not None else None
    if history_since is None:
        notes.append(
            "This repository has never been scanned, so every count on this page "
            "is a zero that measured nothing."
        )

    # Reconstructed the way `maturity.trend_series` reconstructs its series --
    # open at an instant if first seen by then and not yet resolved -- with one
    # difference: `superseded` rows are left out. A successor inherits its
    # predecessor's `first_seen_at` (`lake.carry_forward`, `rekey_containers`),
    # so counting the predecessor as well counts one problem twice for its
    # whole life. Measured 2026-10-18, that doubled TheHub's figure for thirty
    # days ago (386 against 92). Today's point is the live status count, and
    # the reconstruction agrees with it because every non-open row carries a
    # `resolved_at` and no open row is superseded.
    trend: list[TrendPoint] = []
    for days in COMPARE_DAYS:
        at = stamp - timedelta(days=days)
        if history_since is None or history_since > at:
            trend.append(TrendPoint(days_ago=days, at=at, available=False))
            continue
        counts = _counts(
            query(
                "SELECT severity, count(*) FROM findings WHERE asset_id = ? "
                "AND status <> 'superseded' "
                "AND first_seen_at <= ? AND (resolved_at IS NULL OR resolved_at > ?) "
                "GROUP BY 1",
                [repo_full_name, at, at],
            )
        )
        trend.append(
            TrendPoint(
                days_ago=days,
                at=at,
                available=True,
                open_by_severity=counts,
                open_total=sum(counts.values()),
            )
        )
    missing = [p.days_ago for p in trend if not p.available]
    if missing and history_since is not None:
        notes.append(
            f"No comparison with {' or '.join(str(d) for d in missing)} days ago: "
            f"this repository's scan history starts on {history_since.date().isoformat()}."
        )

    # What is driving it: the serious findings if there are any, otherwise
    # everything open, and the page says which.
    serious_open = sum(open_by_severity[s] for s in SERIOUS)
    if serious_open:
        basis, basis_total, severity_clause = "critical_high", serious_open, (
            "AND severity IN ('critical', 'high')"
        )
    elif open_total:
        basis, basis_total, severity_clause = "all_open", open_total, ""
    else:
        basis, basis_total, severity_clause = "none", 0, ""
    basis_rows = (
        query(
            f"""
            SELECT capability, severity, package_name,
                   json_extract_string(raw_finding_json, '$.image'),
                   rule_id, title
            FROM findings
            WHERE asset_id = ? AND status = 'open' {severity_clause}
            """,
            [repo_full_name],
        )
        if basis != "none"
        else []
    )
    basis_by_capability: dict[str, int] = {}
    for row in basis_rows:
        basis_by_capability[str(row[0])] = basis_by_capability.get(str(row[0]), 0) + 1

    # Fixability per finding, by the classifier the Remediate today tab ranks
    # with, so "no fix from the vendor" here is the same count as there.
    buckets = {key: FixBucket(key=key, findings=0, serious=0) for key in (
        "fixable_now", "needs_review", "no_vendor_fix"
    )}
    for capability, severity, title, raw_json in query(
        "SELECT capability, severity, title, raw_finding_json FROM findings "
        "WHERE asset_id = ? AND status = 'open'",
        [repo_full_name],
    ):
        _, _, effort = guidance.remediation_for(
            str(capability), _raw(raw_json), str(title or "")
        )
        bucket = buckets[_bucket(effort)]
        bucket.findings += 1
        if str(severity) in SERIOUS:
            bucket.serious += 1

    closing = (
        sum(
            a.open_findings
            for a in briefing.awaiting_closure(catalog)
            if a.repo_full_name == repo_full_name
        )
        if has_findings
        else 0
    )

    accepted = Accepted()
    expiries: dict[date, int] = {}
    for severity, until, reason, fixed_version in query(
        """
        SELECT severity, accepted_until, accepted_reason_code,
               coalesce(json_extract_string(raw_finding_json, '$.fixed_version'), '')
        FROM findings WHERE asset_id = ? AND status = 'accepted_risk'
        """,
        [repo_full_name],
    ):
        accepted.findings += 1
        if str(severity) in SERIOUS:
            accepted.serious += 1
        if str(reason or "") == "no_vendor_fix" and fixed_version:
            accepted.now_fixable += 1
        if until is None:
            accepted.no_review_date += 1
            continue
        day = until.date() if isinstance(until, datetime) else until
        if day < today:
            accepted.overdue += 1
        else:
            expiries[day] = expiries.get(day, 0) + 1
    accepted.next_expiries = [
        Expiry(on=day, findings=count) for day, count in sorted(expiries.items())[:EXPIRY_LIMIT]
    ]
    upcoming: list[date] = []
    for record in acceptance_records or []:
        state = str(record.get("status") or "")
        if state == "active":
            accepted.decisions_active += 1
        elif state in ("review_due", "needs_review"):
            accepted.decisions_review_due += 1
        elif state == "pending_approval":
            accepted.decisions_pending += 1
        expires = record.get("expires_at")
        if state in ("active", "review_due", "needs_review") and isinstance(expires, date):
            upcoming.append(expires.date() if isinstance(expires, datetime) else expires)
    accepted.nearest_decision_expiry = min(upcoming) if upcoming else None

    lanes = _lanes(
        catalog,
        repo_full_name,
        now=stamp,
        enabled=set(enabled or ()),
        default_branch=default_branch,
        open_by_capability=open_by_capability,
    )
    never = [lane.capability for lane in lanes if lane.status == "never_ran"]
    if never:
        notes.append(
            f"Enabled but never run: {', '.join(never)}. Nothing is known about "
            "what those scans would find."
        )

    since = stamp - timedelta(days=PROGRESS_DAYS)
    progress = Progress(days=PROGRESS_DAYS)
    if history_since is not None and history_since > since:
        progress.window_starts = history_since
    for state, severity, count in query(
        "SELECT status, severity, count(*) FROM findings WHERE asset_id = ? "
        "AND resolved_at >= ? AND resolved_at <= ? GROUP BY 1, 2",
        [repo_full_name, since, stamp],
    ):
        count = int(count)
        if state == "fixed":
            progress.fixed += count
            if str(severity) in SERIOUS:
                progress.fixed_serious += count
        elif state == "false_positive":
            progress.false_positive += count
        elif state == "accepted_risk":
            progress.accepted += count
        elif state == "superseded":
            progress.reidentified += count
    for severity, count in query(
        "SELECT severity, count(*) FROM findings WHERE asset_id = ? "
        "AND status <> 'superseded' "
        "AND first_seen_at >= ? AND first_seen_at <= ? GROUP BY 1",
        [repo_full_name, since, stamp],
    ):
        progress.new += int(count)
        if str(severity) in SERIOUS:
            progress.new_serious += int(count)

    return ExecutiveSummary(
        repo_full_name=repo_full_name,
        generated_at=stamp,
        open_by_severity=open_by_severity,
        open_total=open_total,
        history_since=history_since,
        trend=trend,
        drivers=_drivers(basis_rows),
        drivers_basis=basis,
        drivers_basis_total=basis_total,
        basis_by_capability=basis_by_capability,
        fixability=list(buckets.values()),
        closing_on_their_own=closing,
        accepted=accepted,
        lanes=lanes,
        progress=progress,
        decisions=list(decisions or []),
        gaps=notes,
    )
