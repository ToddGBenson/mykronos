"""Premise monitoring for risk acceptances (spec 33 §4, TheHub #60831).

A `risk_adjustment` acceptance must name a premise the platform can check
(`risk_acceptance._validate`). Until now nothing checked one: the premise was
recorded, approved, and never read again. This module reads them against the
machine-collected evidence `control_observations` holds and the EPSS scores
`threat_intel` keeps, and takes spec 33 §4.2's path when one fails.

**Three outcomes, and only one of them is good news.**

* `failed` - a fresh observation contradicts the premise.
* `holds` - a fresh observation affirms it.
* `unverified` - nothing fresh says either way: no observation, only stale
  ones, only `unknown` / `not_measured` rows, a premise that names nothing
  to check, or a type with no monitor yet. §4.2: "a monitor that cannot run is
  not a pass." `unverified` is never reported, scored or treated as `holds`.

"Fresh" is `fresh_days` (default `control_observations.FRESH_DAYS`, 14,
configurable as `premise_fresh_days`). Only `pass` / `fail` are evidence, the
rule `control_observations` already states, and only the newest row per
(subject, assertion) is read - a port published last week and closed today
is closed.

**What each premise names.** Premises are free-form JSON beyond `type`; these
are the keys the monitors read.

* `port_not_published` - keys `port`, `host`?, `surface_id`?, `container`?.
  Fails on `port_published` pass from internet/lan, `ingress_published` pass
  routing to the port, or `bound_loopback` fail on the host. Holds on
  `port_published` fail from internet/lan or `bound_loopback` pass.
* `firewall_scope` - keys `port`, `host`?, `surface_id`?. Fails on
  `firewall_scope` fail; holds on `firewall_scope` pass.
* `not_internet_facing` - keys `hostnames` / `hostname`, `surface_id`? (whose
  `hostnames` selectors are added). Fails on internet `port_published` pass,
  internet `anonymous_401` pass or fail (either is an answer from outside), or
  `ingress_published` pass. Holds on internet `port_published` fail.
* `epss_below` - keys `threshold` (0-1), `cves`? (default: the CVEs in
  scope). Fails when any CVE's EPSS is above the threshold; holds only when
  every CVE has a fresh score at or under it.

A host-vantage `port_published` alone never fails `port_not_published`: every
published port answers its own host, and spec 33 §4.1's premise is "publishes
no host port / binds loopback only" - which `bound_loopback` answers.

**On failure (spec 33 §4.2).** The acceptance moves to `premise_failed`;
every finding it covers reopens (unless another live record still covers it,
the rule `risk_acceptance.revoke` keeps) with a `finding.reopened_by_premise`
note naming the premise and the observation ids; the risk owner and approver
are named in a notification; and the record lands on the agent work queue as
`acceptance_attention`, which is the tracking item this platform opens
(`agent_work._acceptance_items`). The lake is written first and the record
second, so a write that fails leaves the record live and the next run retries
it - and the run then raises, so `job_runs` reads failing rather than clean.
"""

from __future__ import annotations

import asyncio
import fnmatch
import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from mykronos import control_observations, risk_evidence
from mykronos import risk_acceptance as ra
from mykronos.db.models import (
    AuditLogEntry,
    ControlObservation,
    RepoSurface,
    RiskAcceptance,
)
from mykronos.lake.catalog import Catalog
from mykronos.notify import Notification, Notifier
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

#: Who the audit log names. Automation, and it says so (spec 34 §1).
ACTOR = "job:premise-monitor"

#: The premise types a monitor here evaluates. The rest of
#: `risk_acceptance.PREMISE_TYPES` are reported `unverified`.
MONITORED = ("port_not_published", "firewall_scope", "not_internet_facing", "epss_below")

STATUSES = ("holds", "failed", "unverified")

FRESH_DAYS = control_observations.FRESH_DAYS

#: Why an unmonitored type is unverified, where there is more to say.
_UNMONITORED_REASON = {
    "no_fixed_version": (
        "Checked per finding by the acceptance sweep, which reopens any finding a "
        "fix appears for; not evaluated here, which is not the same as holding."
    ),
    "not_kev_listed": (
        "KEV-listed CVEs are refused at proposal; a CVE joining KEV later is not "
        "evaluated here, which is not the same as holding."
    ),
}

_EXPOSED_VANTAGES = ("internet", "lan")


@dataclass
class Facts:
    """Everything a premise is evaluated against, read once per repository."""

    #: The newest observation per (subject, assertion).
    observations: list[ControlObservation]
    #: Surface id -> its `hostnames` selectors.
    surface_hostnames: dict[str, list[str]]
    #: CVE -> (EPSS score or None, when the row was last refreshed).
    epss: dict[str, tuple[float | None, datetime]]
    now: datetime
    fresh_days: int = FRESH_DAYS

    def fresh(self, when: datetime) -> bool:
        return when >= self.now - timedelta(days=self.fresh_days)


@dataclass
class PremiseCheck:
    """One premise's status and the evidence for it."""

    index: int
    type: str
    status: str
    reason: str
    evidence: list[dict[str, Any]] = field(default_factory=list)

    @property
    def observation_ids(self) -> list[str]:
        return [str(e["observation_id"]) for e in self.evidence if e.get("observation_id")]

    def as_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "type": self.type,
            "status": self.status,
            "reason": self.reason,
            "evidence": self.evidence,
        }


def _evidence(row: ControlObservation, facts: Facts) -> dict[str, Any]:
    return {
        "observation_id": row.id,
        "assertion": row.assertion,
        "subject": row.subject,
        "vantage": row.vantage,
        "state": row.state,
        "tool": row.tool,
        "collector": row.collector,
        "collected_at": row.collected_at.isoformat(),
        "fresh": facts.fresh(row.collected_at),
        "detail": (row.detail or "")[:500],
    }


def _int(value: Any) -> int | None:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if 0 < number <= 65535 else None


def _subject(row: ControlObservation) -> control_observations.Subject | None:
    try:
        return control_observations.parse_subject(row.subject)
    except control_observations.ObservationError:
        return None


def _decide(
    premise_type: str,
    index: int,
    rows: Iterable[ControlObservation],
    facts: Facts,
    *,
    failing: Any,
    holding: Any,
    what: str,
) -> PremiseCheck:
    """The common shape: fresh failing evidence wins, then fresh holding
    evidence; anything else is unverified, saying whether stale evidence or
    none was found."""
    matched = list(rows)
    fresh = [r for r in matched if facts.fresh(r.collected_at)]
    bad = [r for r in fresh if r.state in control_observations.EVIDENCE_STATES and failing(r)]
    if bad:
        return PremiseCheck(
            index,
            premise_type,
            "failed",
            f"{len(bad)} fresh observation(s) contradict it: "
            + "; ".join(f"{r.assertion}={r.state} from {r.vantage} on {r.subject}" for r in bad),
            [_evidence(r, facts) for r in bad],
        )
    good = [r for r in fresh if r.state in control_observations.EVIDENCE_STATES and holding(r)]
    if good:
        return PremiseCheck(
            index,
            premise_type,
            "holds",
            f"{len(good)} fresh observation(s) affirm it.",
            [_evidence(r, facts) for r in good],
        )
    stale = [
        r
        for r in matched
        if not facts.fresh(r.collected_at)
        and r.state in control_observations.EVIDENCE_STATES
        and (failing(r) or holding(r))
    ]
    if stale:
        return PremiseCheck(
            index,
            premise_type,
            "unverified",
            f"Only stale evidence about {what} (older than {facts.fresh_days} days); "
            "stale evidence neither fails nor affirms a premise.",
            [_evidence(r, facts) for r in stale],
        )
    return PremiseCheck(
        index,
        premise_type,
        "unverified",
        f"No fresh pass/fail observation about {what}; not evaluated is not holding.",
    )


def _port_rows(premise: dict[str, Any], facts: Facts) -> tuple[list[ControlObservation], str]:
    """Observations about the port, surface or container a premise names."""
    port = _int(premise.get("port"))
    host = str(premise.get("host") or "").strip().lower()
    surface_id = str(premise.get("surface_id") or "")
    container = str(premise.get("container") or "")
    names = []
    if port is not None:
        names.append(f"port {port}" + (f" on {host}" if host else ""))
    if surface_id:
        names.append(f"surface {surface_id}")
    if container:
        names.append(f"container {container}")
    if not names:
        return [], ""

    def matches(row: ControlObservation) -> bool:
        if surface_id and row.surface_id == surface_id:
            return True
        evidence = row.evidence or {}
        if container and evidence.get("container") == container:
            return True
        if port is None:
            return False
        subject = _subject(row)
        if subject is not None and subject.port == port and (not host or subject.host == host):
            return True
        # A tunnel rule routes a hostname to a local port; a firewall row
        # carries the port it scopes.
        return evidence.get("service_port") == port or _int(evidence.get("port")) == port

    return [r for r in facts.observations if matches(r)], " / ".join(names)


def _port_not_published(index: int, premise: dict[str, Any], facts: Facts) -> PremiseCheck:
    rows, what = _port_rows(premise, facts)
    if not what:
        return PremiseCheck(
            index,
            "port_not_published",
            "unverified",
            "The premise names no port, surface or container to check.",
        )

    def failing(r: ControlObservation) -> bool:
        if r.assertion == "port_published":
            return r.vantage in _EXPOSED_VANTAGES and r.state == "pass"
        if r.assertion == "ingress_published":
            return r.state == "pass"
        if r.assertion == "bound_loopback":
            return r.vantage == "host" and r.state == "fail"
        return False

    def holding(r: ControlObservation) -> bool:
        if r.assertion == "port_published":
            return r.vantage in _EXPOSED_VANTAGES and r.state == "fail"
        if r.assertion == "bound_loopback":
            return r.vantage == "host" and r.state == "pass"
        return False

    return _decide(
        "port_not_published", index, rows, facts, failing=failing, holding=holding, what=what
    )


def _firewall_scope(index: int, premise: dict[str, Any], facts: Facts) -> PremiseCheck:
    rows, what = _port_rows({k: v for k, v in premise.items() if k != "container"}, facts)
    if not what:
        return PremiseCheck(
            index, "firewall_scope", "unverified", "The premise names no port or surface to check."
        )
    rows = [r for r in rows if r.assertion == "firewall_scope"]
    return _decide(
        "firewall_scope",
        index,
        rows,
        facts,
        failing=lambda r: r.state == "fail",
        holding=lambda r: r.state == "pass",
        what=f"the firewall scope of {what}",
    )


def _hostnames(premise: dict[str, Any], facts: Facts) -> list[str]:
    names: list[str] = []
    raw = premise.get("hostnames")
    if isinstance(raw, list):
        names += [str(h) for h in raw]
    if premise.get("hostname"):
        names.append(str(premise["hostname"]))
    surface_id = str(premise.get("surface_id") or "")
    if surface_id:
        names += facts.surface_hostnames.get(surface_id, [])
    return sorted({n.strip().lower() for n in names if n and n.strip()})


def _not_internet_facing(index: int, premise: dict[str, Any], facts: Facts) -> PremiseCheck:
    hostnames = _hostnames(premise, facts)
    surface_id = str(premise.get("surface_id") or "")
    if not hostnames and not surface_id:
        return PremiseCheck(
            index,
            "not_internet_facing",
            "unverified",
            "The premise names no hostname or surface to check.",
        )

    def matches(row: ControlObservation) -> bool:
        if surface_id and row.surface_id == surface_id:
            return True
        subject = _subject(row)
        host = subject.host if subject is not None else None
        return bool(host) and any(fnmatch.fnmatchcase(str(host), h) for h in hostnames)

    def failing(r: ControlObservation) -> bool:
        if r.assertion == "ingress_published":
            return r.state == "pass"
        if r.vantage != "internet":
            return False
        if r.assertion == "port_published":
            return r.state == "pass"
        # A 401 or anything else: either way something answered from outside.
        return r.assertion == "anonymous_401"

    def holding(r: ControlObservation) -> bool:
        return r.assertion == "port_published" and r.vantage == "internet" and r.state == "fail"

    what = ", ".join(hostnames) or f"surface {surface_id}"
    return _decide(
        "not_internet_facing",
        index,
        [r for r in facts.observations if matches(r)],
        facts,
        failing=failing,
        holding=holding,
        what=what,
    )


def _epss_below(
    index: int, premise: dict[str, Any], facts: Facts, cves_in_scope: list[str]
) -> PremiseCheck:
    try:
        threshold = float(premise.get("threshold"))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        threshold = -1.0
    if not 0.0 < threshold <= 1.0:
        return PremiseCheck(
            index,
            "epss_below",
            "unverified",
            "The premise names no threshold between 0 and 1 to compare EPSS with.",
        )
    named = premise.get("cves")
    cves = sorted(
        {str(c).upper() for c in (named if isinstance(named, list) and named else cves_in_scope)}
    )
    if not cves:
        return PremiseCheck(
            index, "epss_below", "unverified", "No CVE is in scope to read EPSS for."
        )
    failed: list[dict[str, Any]] = []
    holding: list[dict[str, Any]] = []
    unknown: list[str] = []
    for cve in cves:
        score, fetched = facts.epss.get(cve, (None, None))
        if score is None or fetched is None or not facts.fresh(fetched):
            unknown.append(cve)
            continue
        item = {
            "source": "threat_intel",
            "cve": cve,
            "epss": score,
            "threshold": threshold,
            "fetched_at": fetched.isoformat(),
        }
        (failed if score > threshold else holding).append(item)
    if failed:
        return PremiseCheck(
            index,
            "epss_below",
            "failed",
            f"EPSS is above {threshold} for "
            + ", ".join(f"{e['cve']} ({e['epss']})" for e in failed),
            failed,
        )
    if unknown:
        return PremiseCheck(
            index,
            "epss_below",
            "unverified",
            f"No fresh EPSS score for {', '.join(unknown[:10])}"
            + (f" and {len(unknown) - 10} more" if len(unknown) > 10 else "")
            + "; not evaluated is not holding.",
            holding,
        )
    return PremiseCheck(
        index, "epss_below", "holds", f"EPSS is at or under {threshold} for every CVE.", holding
    )


def evaluate(
    premise: dict[str, Any], facts: Facts, *, cves_in_scope: list[str], index: int = 0
) -> PremiseCheck:
    """One premise against the facts. Never raises on a malformed premise:
    a premise the monitor cannot read is unverified, and says why."""
    kind = str(premise.get("type") or "")
    if kind == "port_not_published":
        return _port_not_published(index, premise, facts)
    if kind == "firewall_scope":
        return _firewall_scope(index, premise, facts)
    if kind == "not_internet_facing":
        return _not_internet_facing(index, premise, facts)
    if kind == "epss_below":
        return _epss_below(index, premise, facts, cves_in_scope)
    return PremiseCheck(
        index,
        kind,
        "unverified",
        _UNMONITORED_REASON.get(
            kind,
            f"No monitor checks a {kind or 'typeless'} premise yet; it is not evaluated, "
            "which is not the same as holding.",
        ),
    )


# ---------------------------------------------------------------------------
# Reading the facts
# ---------------------------------------------------------------------------


def load_facts(
    session: Session,
    repo: str,
    *,
    cves: Iterable[str] = (),
    now: datetime | None = None,
    fresh_days: int = FRESH_DAYS,
) -> Facts:
    surfaces = session.scalars(select(RepoSurface).where(RepoSurface.repo_full_name == repo)).all()
    hostnames = {
        s.id: [str(h) for h in (s.selectors or {}).get("hostnames", []) or []]
        for s in surfaces
        if isinstance(s.selectors, dict)
    }
    # The shared evidence model (TheHub #60901): the same threat-intel read
    # the Oracle makes.
    signals = risk_evidence.threat_signals(session, cves)
    epss: dict[str, tuple[float | None, datetime]] = {
        cve: (s.epss, s.fetched_at) for cve, s in signals.items() if s.fetched_at is not None
    }
    return Facts(
        observations=control_observations.latest(session, repo),
        surface_hostnames=hostnames,
        epss=epss,
        now=now or utcnow(),
        fresh_days=fresh_days,
    )


def scope_cves(
    scope: dict[str, Any], covered_finding_ids: list[str], catalog: Catalog | None
) -> list[str]:
    """The CVEs an acceptance covers: its scope's rule ids, else its findings'."""
    named = [
        str(r).upper() for r in scope.get("rule_ids") or [] if str(r).upper().startswith("CVE-")
    ]
    if named or catalog is None or not covered_finding_ids:
        return sorted(set(named))
    if not catalog.all_files("findings"):
        return []
    placeholders = ", ".join("?" for _ in covered_finding_ids)
    rows = catalog.query(
        f"SELECT DISTINCT upper(rule_id) FROM findings WHERE finding_id IN ({placeholders})",
        list(covered_finding_ids),
    )
    return sorted({str(r[0]) for r in rows if str(r[0]).startswith("CVE-")})


def check_premises(
    session: Session,
    *,
    repo: str,
    premises: list[dict[str, Any]],
    scope: dict[str, Any],
    covered_finding_ids: list[str],
    catalog: Catalog | None,
    now: datetime | None = None,
    fresh_days: int = FRESH_DAYS,
) -> list[PremiseCheck]:
    """Every premise of one acceptance, proposed or approved."""
    if not premises:
        return []
    premises = [p if isinstance(p, dict) else {} for p in premises]
    if not any(p.get("type") in MONITORED for p in premises):
        # Nothing here reads evidence; the legacy migration's thousands of
        # `no_fixed_version` records need no query each.
        facts = Facts([], {}, {}, now or utcnow(), fresh_days)
        return [evaluate(p, facts, cves_in_scope=[], index=i) for i, p in enumerate(premises)]
    needs_cves = any(p.get("type") == "epss_below" for p in premises)
    cves = scope_cves(scope, covered_finding_ids, catalog) if needs_cves else []
    named = [
        str(c)
        for p in premises
        if p.get("type") == "epss_below" and isinstance(p.get("cves"), list)
        for c in p["cves"]
    ]
    facts = load_facts(session, repo, cves=[*cves, *named], now=now, fresh_days=fresh_days)
    return [evaluate(p, facts, cves_in_scope=cves, index=i) for i, p in enumerate(premises)]


def check_record(
    session: Session,
    record: RiskAcceptance,
    catalog: Catalog | None,
    *,
    now: datetime | None = None,
    fresh_days: int = FRESH_DAYS,
) -> list[PremiseCheck]:
    return check_premises(
        session,
        repo=record.repo_full_name,
        premises=list(record.premises or []),
        scope=dict(record.scope or {}),
        covered_finding_ids=list(record.covered_finding_ids or []),
        catalog=catalog,
        now=now,
        fresh_days=fresh_days,
    )


# ---------------------------------------------------------------------------
# The monitor
# ---------------------------------------------------------------------------


@dataclass
class FailedAcceptance:
    record_id: str
    repo: str
    risk_owner: str
    approved_by: str | None
    tracking_ref: str | None
    failed: list[PremiseCheck]
    reopened: int = 0

    @property
    def observation_ids(self) -> list[str]:
        return sorted({i for c in self.failed for i in c.observation_ids})


@dataclass
class Unverified:
    record_id: str
    repo: str
    risk_owner: str
    approved_by: str | None
    checks: list[PremiseCheck]


@dataclass
class MonitorResult:
    acceptances: int = 0
    premises: int = 0
    holds: int = 0
    unverified: int = 0
    failed: list[FailedAcceptance] = field(default_factory=list)
    newly_unverified: list[Unverified] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"{self.acceptances} acceptance(s), {self.premises} premise(s): "
            f"{self.holds} hold, {self.unverified} unverified, "
            f"{sum(len(f.failed) for f in self.failed)} failed "
            f"({len(self.failed)} acceptance(s) moved to premise_failed)"
        )


def _signature(checks: list[PremiseCheck]) -> list[list[Any]]:
    return [[c.index, c.type, c.status] for c in checks]


def _last_signature(session: Session, record_id: str) -> list[list[Any]] | None:
    entry = session.scalars(
        select(AuditLogEntry)
        .where(
            AuditLogEntry.action == "risk_acceptance.premise_checked",
            AuditLogEntry.entity_id == record_id,
        )
        .order_by(AuditLogEntry.created_at.desc())
        .limit(1)
    ).first()
    if entry is None:
        return None
    return list((entry.detail or {}).get("signature") or [])


def _compact(check: PremiseCheck) -> dict[str, Any]:
    """A check as the audit log keeps it: the ids, not the whole rows."""
    return {
        "index": check.index,
        "type": check.type,
        "status": check.status,
        "reason": check.reason[:500],
        "observation_ids": check.observation_ids,
        **(
            {"epss": [e for e in check.evidence if e.get("source") == "threat_intel"]}
            if check.type == "epss_below"
            else {}
        ),
    }


def run(
    db: Any,
    catalog: Catalog,
    *,
    repo: str | None = None,
    now: datetime | None = None,
    fresh_days: int = FRESH_DAYS,
) -> MonitorResult:
    """Evaluate every live acceptance's premises; take §4.2's path on failure.

    Raises after doing everything it could when an acceptance whose premise
    failed could not be applied, so the job reads failing, not clean.
    """
    from mykronos.adminauth import ActorKind, Principal, Role, current_principal

    token = current_principal.set(
        Principal(actor=ACTOR, role=Role.VIEWER, kind=ActorKind.AUTOMATION)
    )
    try:
        return _run(db, catalog, repo=repo, now=now or utcnow(), fresh_days=fresh_days)
    finally:
        current_principal.reset(token)


def _run(
    db: Any, catalog: Catalog, *, repo: str | None, now: datetime, fresh_days: int
) -> MonitorResult:
    result = MonitorResult()
    to_fail: list[FailedAcceptance] = []
    with db.session() as session:
        query = select(RiskAcceptance).where(RiskAcceptance.status.in_(ra.LIVE))
        if repo:
            query = query.where(RiskAcceptance.repo_full_name == repo)
        for record in session.scalars(query).all():
            if not record.premises:
                continue
            checks = check_record(session, record, catalog, now=now, fresh_days=fresh_days)
            result.acceptances += 1
            result.premises += len(checks)
            result.holds += sum(1 for c in checks if c.status == "holds")
            result.unverified += sum(1 for c in checks if c.status == "unverified")
            monitored = [c for c in checks if c.type in MONITORED]
            if not monitored:
                continue
            previous = _last_signature(session, record.id)
            signature = _signature(checks)
            if previous != signature:
                db.audit(
                    session,
                    actor=ACTOR,
                    action="risk_acceptance.premise_checked",
                    entity_type="risk_acceptance",
                    entity_id=record.id,
                    repo=record.repo_full_name,
                    signature=signature,
                    checks=[_compact(c) for c in checks],
                    fresh_days=fresh_days,
                )
                was = {(i, t): s for i, t, s in (previous or [])}
                newly = [
                    c
                    for c in monitored
                    if c.status == "unverified" and was.get((c.index, c.type)) != "unverified"
                ]
                if newly and not any(c.status == "failed" for c in checks):
                    result.newly_unverified.append(
                        Unverified(
                            record.id,
                            record.repo_full_name,
                            record.risk_owner,
                            record.approved_by,
                            newly,
                        )
                    )
            failed = [c for c in checks if c.status == "failed"]
            if failed:
                to_fail.append(
                    FailedAcceptance(
                        record_id=record.id,
                        repo=record.repo_full_name,
                        risk_owner=record.risk_owner,
                        approved_by=record.approved_by,
                        tracking_ref=record.tracking_ref,
                        failed=failed,
                    )
                )

    for failure in to_fail:
        try:
            _fail(db, catalog, failure)
        except Exception as exc:  # noqa: BLE001 - every other acceptance still runs
            logger.exception("Premise failed on %s but could not be applied", failure.record_id)
            result.errors.append(f"{failure.record_id}: {exc}")
            continue
        result.failed.append(failure)

    if result.errors:
        raise RuntimeError(
            f"Premise monitor could not apply {len(result.errors)} failed premise(s); "
            "the acceptance(s) stay live and are retried next run: " + "; ".join(result.errors)
        )
    return result


def _fail(db: Any, catalog: Catalog, failure: FailedAcceptance) -> None:
    """Spec 33 §4.2 for one acceptance: findings first, then the record."""
    with db.session() as session:
        record = session.get(RiskAcceptance, failure.record_id)
        if record is None or record.status not in ra.LIVE:
            return
        ids = list(record.covered_finding_ids or [])
    reopened = ra.release_findings(db, catalog, record_id=failure.record_id, finding_ids=ids)
    failure.reopened = len(reopened)
    premises = [c.type for c in failure.failed]
    reason = "premise failed: " + ", ".join(premises)
    with db.session() as session:
        record = session.get(RiskAcceptance, failure.record_id)
        if record is None:
            return
        before = record.status
        record.status = "premise_failed"
        record.closed_at = utcnow()
        record.closed_reason = reason[:255]
        db.audit(
            session,
            actor=ACTOR,
            action="risk_acceptance.premise_failed",
            entity_type="risk_acceptance",
            entity_id=record.id,
            repo=record.repo_full_name,
            before=before,
            after="premise_failed",
            failed=[_compact(c) for c in failure.failed],
            observation_ids=failure.observation_ids,
            findings_reopened=len(reopened),
            risk_owner=record.risk_owner,
            approved_by=record.approved_by,
            tracking_ref=record.tracking_ref,
        )
        for finding_id in reopened:
            db.audit(
                session,
                actor=ACTOR,
                action="finding.reopened_by_premise",
                entity_type="finding",
                entity_id=finding_id,
                repo=record.repo_full_name,
                risk_acceptance_id=record.id,
                premises=premises,
                observation_ids=failure.observation_ids,
                reason=f"Risk acceptance {record.id[:8]} rested on {', '.join(premises)}, "
                "which no longer holds.",
            )


# ---------------------------------------------------------------------------
# Telling people (spec 33 §6: risk owner + approver, immediately)
# ---------------------------------------------------------------------------


def _who(risk_owner: str, approved_by: str | None) -> str:
    return f"risk owner {risk_owner or '(none)'}, approver {approved_by or '(none)'}"


def notifications(result: MonitorResult) -> list[Notification]:
    notes = []
    for f in result.failed:
        lines = [
            f"Acceptance {f.record_id[:8]} is now premise_failed "
            f"({_who(f.risk_owner, f.approved_by)}).",
            *(f"- {c.type}: {c.reason}" for c in f.failed),
            f"Evidence: observation(s) {', '.join(f.observation_ids) or '(threat-intel)'}.",
            f"{f.reopened} finding(s) reopened.",
            (
                f"Tracking item: {f.tracking_ref}."
                if f.tracking_ref
                else "On the agent work queue as acceptance_attention until its findings are fixed "
                    "or a new acceptance with corrected premises holds them."
            ),
        ]
        notes.append(
            Notification(
                title="Risk acceptance premise failed",
                detail="\n".join(lines),
                repo_full_name=f.repo,
                level="warning",
            )
        )
    by_repo: dict[str, list[Unverified]] = {}
    for u in result.newly_unverified:
        by_repo.setdefault(u.repo, []).append(u)
    for repo, items in by_repo.items():
        lines = [
            f"Acceptance {u.record_id[:8]} ({_who(u.risk_owner, u.approved_by)}): "
            + ", ".join(c.type for c in u.checks)
            + f" - {u.checks[0].reason}"
            for u in items
        ]
        notes.append(
            Notification(
                title="Risk acceptance premise could not be verified",
                detail="\n".join(lines),
                repo_full_name=repo,
                level="info",
            )
        )
    return notes


async def run_and_notify(
    db: Any,
    catalog: Catalog,
    notifier: Notifier,
    *,
    repo: str | None = None,
    fresh_days: int = FRESH_DAYS,
) -> MonitorResult:
    result = await asyncio.to_thread(run, db, catalog, repo=repo, fresh_days=fresh_days)
    for note in notifications(result):
        await notifier.send(note)
    if result.failed:
        logger.warning("Premise monitor: %s", result.summary())
    else:
        logger.info("Premise monitor: %s", result.summary())
    return result


async def on_ingest(
    db: Any, catalog: Catalog, notifier: Notifier, repo: str, fresh_days: int
) -> None:
    """After observations arrive. Never fails the ingest that triggered it:
    the daily job runs the same check and reports its own failures."""
    try:
        await run_and_notify(db, catalog, notifier, repo=repo, fresh_days=fresh_days)
    except Exception:  # noqa: BLE001 - logged; the scheduled job reports health
        logger.exception("Premise monitor after observation ingest for %s failed", repo)
