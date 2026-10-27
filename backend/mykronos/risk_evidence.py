"""One evidence model for risk decisions (TheHub #60901, epic #60882).

A risk acceptance and an Oracle decision answer the same question about the
same findings - how much risk is really here - and until this each read the
evidence its own way. KEV status was looked up in five places with five
queries, the acceptance page read environmental scores with its own query,
and the Oracle read the risk profile and the reachability report inline. Two
readers of one fact can disagree about it, and the first time they do the
platform says two things about one finding.

This module is the one read path. Every category a risk decision may rest on
is read by one function here, and both the Oracle (`oracle.engine`,
`oracle.environmental`, `toxic`) and the acceptance (`risk_acceptance`,
`premise_monitor`, the acceptance API) call it:

    threat_intel        `threat_signals`        KEV listing and EPSS per CVE
    environmental       `environmental_scores`  stored environmental CVSS
    reachability        `reachability_report`   the import analysis
    toxic_combinations  `toxic_combinations`    `toxic.detect`
    asset_sensitivity   `asset_context`         the repository's RiskProfile
    exposure            `exposure`              declared surfaces and their exposure
    verified_controls   `verified_controls`     declared controls against fresh observations

**Each decision shows the evidence it used.** `RiskEvidence.as_dict()` is the
`risk_evidence` block of both an Oracle decision's `inputs_snapshot` and an
acceptance's approval evidence: every category, present whether or not it has
anything to say (spec 09 §9), with `scored` saying whether this decision's
arithmetic read it or only shows it. Environmental scoring and verified
controls are shown and not yet scored by the Oracle: they go live per
repository after the shadow comparison (TheHub #60904), and this module does
not change any score.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from mykronos.db.models import (
    ControlObservation,
    EnvironmentalScore,
    ReachabilityReport,
    RepoControl,
    RepoOnboarding,
    RepoSurface,
    RiskProfile,
    ThreatIntelMatch,
)
from mykronos.threat_intel import extract_cve

#: The categories, in the order a reader is shown them. Every one appears in
#: every `risk_evidence` block.
CATEGORIES = (
    "threat_intel",
    "environmental",
    "reachability",
    "toxic_combinations",
    "asset_sensitivity",
    "exposure",
    "verified_controls",
)

#: How many items a block lists by name. Counts are always complete.
LISTED = 25

#: An observation older than this verifies nothing (`control_observations`).
FRESH_DAYS = 14

#: The state of each assertion that means the control *holds*. `pass` means
#: the assertion is true, not that the result is good (`ControlObservation`):
#: a published port passing is the opposite of a control holding.
AFFIRMING_STATE = {
    "anonymous_401": "pass",
    "header_csp": "pass",
    "header_hsts": "pass",
    "bound_loopback": "pass",
    "firewall_scope": "pass",
    "port_published": "fail",
    "ingress_published": "fail",
}

_EVIDENCE_STATES = ("pass", "fail")

#: The most ids one `IN (...)` binds. SQLite refuses a statement with more
#: than 32766 variables, and a migrated estate's open findings exceed that,
#: which turned the `risk_evidence` block into `available: false` (review of
#: #1005). Well under every engine's limit, and few round trips.
IN_CHUNK = 900


def chunked(values: Iterable[str], size: int = IN_CHUNK) -> Iterable[list[str]]:
    """`values`, sorted and de-duplicated, in lists of at most `size`."""
    ordered = sorted(set(values))
    for start in range(0, len(ordered), size):
        yield ordered[start : start + size]


# ---------------------------------------------------------------------------
# Threat intelligence: KEV and EPSS
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ThreatSignal:
    """What the threat-intel refresh last said about one CVE."""

    cve: str
    in_kev: bool
    kev_added_at: date | None
    epss: float | None
    fetched_at: datetime | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "cve": self.cve,
            "in_kev": self.in_kev,
            "kev_added_at": self.kev_added_at.isoformat() if self.kev_added_at else None,
            "epss": self.epss,
            "fetched_at": self.fetched_at.isoformat() if self.fetched_at else None,
        }


def threat_signals(session: Session, cves: Iterable[str]) -> dict[str, ThreatSignal]:
    """CVE (upper case) -> its signal, for the CVEs the feed has a row for.

    A CVE with no row is absent from the result: the feed never scored it,
    which is not the same as "not in KEV" and is never reported as such.
    """
    wanted = sorted({str(c).upper() for c in cves if c})
    if not wanted:
        return {}
    rows = [
        row
        for chunk in chunked(wanted)
        for row in session.scalars(
            select(ThreatIntelMatch).where(ThreatIntelMatch.cve_id.in_(chunk))
        ).all()
    ]
    out: dict[str, ThreatSignal] = {}
    for row in rows:
        cve = str(row.cve_id).upper()
        out[cve] = ThreatSignal(
            cve=cve,
            in_kev=bool(row.in_kev),
            kev_added_at=row.kev_added_at,
            epss=row.epss_score,
            fetched_at=row.fetched_at,
        )
    return out


def kev_signals(session: Session) -> dict[str, ThreatSignal]:
    """Every KEV-listed CVE the feed holds a row for, with its signal."""
    listed = session.scalars(
        select(ThreatIntelMatch.cve_id).where(ThreatIntelMatch.in_kev.is_(True))
    ).all()
    return {c: s for c, s in threat_signals(session, listed).items() if s.in_kev}


def kev_listed(session: Session, cves: Iterable[str]) -> list[str]:
    """The CVEs among `cves` that are in CISA KEV, sorted."""
    return sorted(c for c, s in threat_signals(session, cves).items() if s.in_kev)


# ---------------------------------------------------------------------------
# Environmental CVSS
# ---------------------------------------------------------------------------


def environmental_scores(
    session: Session, *, repo: str | None = None, finding_ids: Iterable[str] | None = None
) -> dict[str, EnvironmentalScore]:
    """Finding id -> its stored `EnvironmentalScore`, detached from the session.

    By repository (the Oracle reads a whole repository) or by finding id (an
    acceptance reads the findings it covers); both together intersect.
    """
    query = select(EnvironmentalScore)
    if repo is not None:
        query = query.where(EnvironmentalScore.repo_full_name == repo)
    if finding_ids is None:
        found = list(session.scalars(query).all())
    else:
        ids = {str(f) for f in finding_ids}
        if not ids:
            return {}
        found = [
            row
            for chunk in chunked(ids)
            for row in session.scalars(
                query.where(EnvironmentalScore.finding_id.in_(chunk))
            ).all()
        ]
    rows = {row.finding_id: row for row in found}
    for row in rows.values():
        session.expunge(row)
    return rows


# ---------------------------------------------------------------------------
# What the repository is: asset sensitivity, exposure, reachability
# ---------------------------------------------------------------------------


def _onboarding_join(model: Any) -> Any:
    return select(model).join(RepoOnboarding, RepoOnboarding.id == model.repo_onboarding_id)


def asset_context(session: Session, repo: str) -> dict[str, Any] | None:
    """The repository's recorded RiskProfile (spec 21 §1.4), or None when no
    one has stated what this application is."""
    row = (
        session.execute(
            _onboarding_join(RiskProfile).where(RepoOnboarding.github_repo_full_name == repo)
        )
        .scalars()
        .first()
    )
    if row is None:
        return None
    return {
        "internet_facing": row.internet_facing,
        "data_classification": row.data_classification,
        "business_criticality": row.business_criticality,
        "compliance_scope": list(row.compliance_scope or []),
        "updated_by": row.updated_by,
    }


def reachability_report(session: Session, repo: str) -> dict[str, Any] | None:
    """The stored import analysis (spec 19 §2.1), or None when none has run."""
    row = (
        session.execute(
            _onboarding_join(ReachabilityReport).where(
                RepoOnboarding.github_repo_full_name == repo
            )
        )
        .scalars()
        .first()
    )
    if row is None:
        return None
    return {
        "language": row.language,
        "commit_sha": row.commit_sha,
        "orphaned_paths": [str(p) for p in (row.orphaned_paths or [])],
        "files_analysed": row.files_analysed,
        "files_unparseable": row.files_unparseable,
    }


def exposure(session: Session, repo: str) -> dict[str, Any]:
    """Declared surfaces, by exposure and sensitivity. Declared, never verified
    (`RepoSurface`): the counts say what people asserted."""
    rows = session.scalars(select(RepoSurface).where(RepoSurface.repo_full_name == repo)).all()
    by_exposure: dict[str, int] = {}
    sensitive: list[dict[str, Any]] = []
    for row in rows:
        by_exposure[row.exposure or "unknown"] = by_exposure.get(row.exposure or "unknown", 0) + 1
        if row.kind == "asset":
            sensitive.append(
                {
                    "surface_id": row.id,
                    "name": row.name,
                    "exposure": row.exposure,
                    "sensitivity": row.sensitivity,
                }
            )
    return {
        "surfaces": len(rows),
        "by_exposure": dict(sorted(by_exposure.items())),
        "internet": by_exposure.get("internet", 0),
        "assets": sorted(sensitive, key=lambda a: (a["name"], a["surface_id"]))[:LISTED],
    }


# ---------------------------------------------------------------------------
# Verified controls
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ControlStatus:
    """One control as the observations read it: verified | contradicted | unverified."""

    status: str
    reason: str
    control_id: str | None = None
    observation_id: str | None = None
    assertion: str | None = None
    state: str | None = None
    collected_at: datetime | None = None
    #: The cited observation or control does not exist for this repository.
    missing: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "missing": self.missing,
            "reason": self.reason,
            "control_id": self.control_id,
            "observation_id": self.observation_id,
            "assertion": self.assertion,
            "state": self.state,
            "collected_at": self.collected_at.isoformat() if self.collected_at else None,
        }


def observation_status(
    row: ControlObservation, *, now: datetime, fresh_days: int = FRESH_DAYS
) -> ControlStatus:
    """Whether one observation verifies the control it is about."""

    def status(value: str, reason: str) -> ControlStatus:
        return ControlStatus(
            status=value,
            reason=reason,
            control_id=row.control_id,
            observation_id=row.id,
            assertion=row.assertion,
            state=row.state,
            collected_at=row.collected_at,
        )

    affirming = AFFIRMING_STATE.get(row.assertion)
    if affirming is None:
        return status("unverified", f"No rule says which state of {row.assertion} holds.")
    if row.state not in _EVIDENCE_STATES:
        return status("unverified", f"{row.assertion}={row.state} is not evidence.")
    if row.collected_at < now - timedelta(days=fresh_days):
        return status(
            "unverified",
            f"The newest observation is older than {fresh_days} days; stale evidence "
            "verifies nothing.",
        )
    if row.state == affirming:
        return status(
            "verified", f"{row.assertion}={row.state} from {row.vantage} on {row.subject}."
        )
    return status(
        "contradicted",
        f"{row.assertion}={row.state} from {row.vantage} on {row.subject} says it does not hold.",
    )


def _newest(rows: Iterable[ControlObservation]) -> ControlObservation | None:
    ordered = sorted(rows, key=lambda r: (r.collected_at, r.received_at or r.collected_at))
    return ordered[-1] if ordered else None


def observation_verification(
    session: Session,
    repo: str,
    observation_id: str,
    *,
    now: datetime,
    fresh_days: int = FRESH_DAYS,
) -> ControlStatus:
    """A cited observation, read as the newest of its (subject, assertion).

    Citing last month's pass does not outlive this morning's fail: the
    status is the newest row's, and it names that row.
    """
    cited = session.get(ControlObservation, observation_id)
    if cited is None or cited.repo_full_name != repo:
        return ControlStatus(
            status="unverified",
            reason=f"No observation {observation_id} for this repository.",
            observation_id=observation_id,
            missing=True,
        )
    newest = _newest(
        session.scalars(
            select(ControlObservation).where(
                ControlObservation.repo_full_name == repo,
                ControlObservation.subject == cited.subject,
                ControlObservation.assertion == cited.assertion,
            )
        ).all()
    )
    return observation_status(newest or cited, now=now, fresh_days=fresh_days)


def control_verification(
    session: Session,
    repo: str,
    control_id: str,
    *,
    now: datetime,
    fresh_days: int = FRESH_DAYS,
) -> ControlStatus:
    """A declared control, read against the newest observation tied to it.

    Contradicting evidence wins over affirming evidence when several
    assertions are about the same control.
    """
    control = session.get(RepoControl, control_id)
    if control is None or control.repo_full_name != repo:
        return ControlStatus(
            status="unverified",
            reason=f"No declared control {control_id} for this repository.",
            control_id=control_id,
            missing=True,
        )
    rows = session.scalars(
        select(ControlObservation).where(
            ControlObservation.repo_full_name == repo,
            ControlObservation.control_id == control_id,
        )
    ).all()
    by_key: dict[tuple[str, str], list[ControlObservation]] = {}
    for row in rows:
        by_key.setdefault((row.subject, row.assertion), []).append(row)
    statuses = [
        observation_status(newest, now=now, fresh_days=fresh_days)
        for group in by_key.values()
        if (newest := _newest(group)) is not None
    ]
    for wanted in ("contradicted", "verified"):
        found = [s for s in statuses if s.status == wanted]
        if found:
            return found[0]
    if statuses:
        return statuses[0]
    return ControlStatus(
        status="unverified",
        reason="Declared, and nothing observes it: a declaration is not evidence.",
        control_id=control_id,
    )


def verified_controls(
    session: Session, repo: str, *, now: datetime, fresh_days: int = FRESH_DAYS
) -> dict[str, Any]:
    """Every declared control of the repository, as the observations read it."""
    controls = session.scalars(
        select(RepoControl)
        .where(RepoControl.repo_full_name == repo)
        .order_by(RepoControl.id)
    ).all()
    items = []
    counts = {"verified": 0, "contradicted": 0, "unverified": 0}
    for control in controls:
        status = control_verification(session, repo, control.id, now=now, fresh_days=fresh_days)
        counts[status.status] += 1
        items.append({"kind": control.kind, "stride": control.stride, **status.as_dict()})
    return {
        "declared": len(controls),
        "fresh_days": fresh_days,
        **counts,
        "controls": items[:LISTED],
    }


# ---------------------------------------------------------------------------
# Toxic combinations
# ---------------------------------------------------------------------------


def toxic_combinations(
    catalog: Any, session: Session | None, repo: str, *, escalate_steps: int = 1
) -> list[Any]:
    """`toxic.detect` for one repository: the same combinations either reader sees."""
    from mykronos import toxic

    return toxic.detect(catalog, repo=repo, session=session, escalate_steps=escalate_steps)


# ---------------------------------------------------------------------------
# The block a decision carries
# ---------------------------------------------------------------------------


@dataclass
class RiskEvidence:
    """Every category one decision read, and whether its arithmetic used it.

    `scored` names the categories the decision's score or tier was computed
    from; the rest are shown so the approver or reader sees them, not
    weighed.
    """

    repo: str
    as_of: datetime
    findings: int
    threat: dict[str, ThreatSignal]
    environmental: dict[str, EnvironmentalScore]
    reachability: dict[str, Any] | None
    orphaned_findings: int
    toxic: list[Any]
    asset: dict[str, Any] | None
    exposure: dict[str, Any]
    controls: dict[str, Any]
    scored: tuple[str, ...] = ()
    notes: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        kev = sorted(c for c, s in self.threat.items() if s.in_kev)
        epss = {c: s.epss for c, s in sorted(self.threat.items()) if s.epss is not None}
        moved = {
            fid: row
            for fid, row in sorted(self.environmental.items())
            if row.effective_severity
            and (row.scanner_severity or "").lower() != row.effective_severity.lower()
        }
        categories: dict[str, dict[str, Any]] = {
            "threat_intel": {
                "available": bool(self.threat),
                "cves": len(self.threat),
                "kev": kev[:LISTED],
                "kev_count": len(kev),
                "epss": dict(list(epss.items())[:LISTED]),
            },
            "environmental": {
                "available": bool(self.environmental),
                "scored_findings": len(self.environmental),
                "moved": len(moved),
                "items": [
                    {
                        "finding_id": fid,
                        "scanner_severity": row.scanner_severity,
                        "effective_severity": row.effective_severity,
                        "context_id": row.context_id,
                    }
                    for fid, row in list(moved.items())[:LISTED]
                ],
            },
            "reachability": {
                "available": self.reachability is not None,
                "orphaned_findings": self.orphaned_findings,
                **(
                    {
                        "language": self.reachability["language"],
                        "commit_sha": self.reachability["commit_sha"],
                        "files_analysed": self.reachability["files_analysed"],
                    }
                    if self.reachability
                    else {}
                ),
            },
            "toxic_combinations": {
                "available": True,
                "count": len(self.toxic),
                "items": [
                    {
                        "combination_id": c.combination_id,
                        "name": c.name,
                        "severity": c.severity,
                        "kev_cves": list(c.kev_cves),
                        "finding_ids": [m["finding_id"] for m in c.members],
                        "qualifies": {
                            m["finding_id"]: m.get("qualifies", "") for m in c.members
                        },
                    }
                    for c in self.toxic[:LISTED]
                ],
            },
            "asset_sensitivity": {
                "available": self.asset is not None,
                **(self.asset or {}),
            },
            "exposure": {"available": bool(self.exposure.get("surfaces")), **self.exposure},
            "verified_controls": {
                "available": bool(self.controls.get("declared")),
                **self.controls,
            },
        }
        for name, block in categories.items():
            block["scored"] = name in self.scored
            if name in self.notes:
                block["note"] = self.notes[name]
        return {
            "model": "risk_evidence/1",
            "repo": self.repo,
            "as_of": self.as_of.isoformat(),
            "findings": self.findings,
            "categories": categories,
        }


def gather(
    session: Session,
    catalog: Any,
    *,
    repo: str,
    findings: Iterable[dict[str, Any]],
    as_of: datetime,
    fresh_days: int = FRESH_DAYS,
    escalate_steps: int = 1,
    scored: tuple[str, ...] = (),
    notes: dict[str, str] | None = None,
    combinations: list[Any] | None = None,
) -> RiskEvidence:
    """The evidence about `findings` (dicts with `finding_id`, `rule_id`, and
    optionally `title` and `location`/`file_path`), read through this module.

    `combinations` passes the repository's `toxic_combinations` when the
    caller has just read them, so a decision shows the combinations it
    scored rather than a second read of them.
    """
    items = list(findings)
    ids = {str(f["finding_id"]) for f in items}
    cves = {
        cve
        for f in items
        if (cve := extract_cve(str(f.get("rule_id") or ""), str(f.get("title") or "")))
    }
    report = reachability_report(session, repo)
    orphaned = set(report["orphaned_paths"]) if report else set()
    in_dead = sum(
        1 for f in items if str(f.get("file_path") or f.get("location") or "") in orphaned
    )
    if combinations is None:
        combinations = toxic_combinations(catalog, session, repo, escalate_steps=escalate_steps)
    combos = [c for c in combinations if ids & {str(m["finding_id"]) for m in c.members}]
    return RiskEvidence(
        repo=repo,
        as_of=as_of,
        findings=len(ids),
        threat=threat_signals(session, cves),
        environmental=environmental_scores(session, finding_ids=ids),
        reachability=report,
        orphaned_findings=in_dead,
        toxic=combos,
        asset=asset_context(session, repo),
        exposure=exposure(session, repo),
        controls=verified_controls(session, repo, now=as_of, fresh_days=fresh_days),
        scored=scored,
        notes=dict(notes or {}),
    )
