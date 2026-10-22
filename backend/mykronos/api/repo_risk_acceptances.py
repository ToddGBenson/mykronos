"""One repository's risk acceptances, for the repo page's Risk management tab.

`/api/risk-acceptances` is the decision's own API: propose, approve, renew,
revoke, and a flat list of serialized records. What it does not do is answer
the reviewer's question - *what did we accept here, on what grounds, and do
those grounds still hold?* - in one read. That needs, per acceptance, the
findings it covers with their severity as scanned and as re-read for this
environment, each premise with the monitor's verdict today and how old the
evidence behind that verdict is, and the expiry in days rather than as a
date to subtract. This module composes those from the pieces that already
compute them (`premise_monitor.check_record`, `EnvironmentalScore`, the lake's
findings, the audit log) and changes nothing: both routes are GETs.

**Repository scoping is the property that matters most.** Both routes take
the onboarding id, resolve it to a full name, and read only records whose
`repo_full_name` is that name; the detail route answers 404 for a record that
belongs to another repository rather than serving it under this one's URL.
Covered findings are read with the same repository predicate, so a finding id
that somehow named another repository's row would read as missing, not leak.

**State is derived, not stored.** The record's `status` is what the sweep last
wrote; the sweep runs daily, so a record can be `active` with an expiry
already behind it. `derive_state` reads the dates too, and `expiring` is a
live record with 30 days or fewer left - the same horizon the summary strip
counts.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from datetime import date, datetime
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy import select

from mykronos import premise_monitor
from mykronos import risk_acceptance as ra
from mykronos.adminauth import PrincipalDep
from mykronos.api.risk_acceptances import environmental_scores
from mykronos.db.models import AuditLogEntry, EnvironmentalScore, RiskAcceptance
from mykronos.schemas import utcnow

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

#: A live acceptance with this many days or fewer left reads `expiring`.
EXPIRING_WITHIN_DAYS = 30

#: Every state `derive_state` returns, in the order a reviewer reads them:
#: the ones that need a decision first.
STATES = (
    "premise_failed",
    "needs_review",
    "expired",
    "expiring",
    "active",
    "pending_approval",
    "revoked",
    "closed",
)

#: Severity words, least to worst. `info` is a scanner word acceptances do not
#: use for themselves, but a covered finding can carry it.
SEVERITY_RANK = ("info", "low", "medium", "high", "critical")

#: How many covered findings a list row carries; the detail carries more. The
#: total is always given - a ZAP acceptance can cover thousands of findings,
#: and that is one decision, not thousands of rows.
ROW_FINDINGS = 10
DETAIL_FINDINGS = 200

#: The lake takes the ids as bound parameters; this keeps one statement's
#: parameter list bounded however many findings a repository has accepted.
_CHUNK = 500


def derive_state(record_status: str, expires_at: date | None, today: date) -> str:
    """The state the tab shows and filters by, from the stored status and the dates."""
    if record_status == "premise_failed":
        return "premise_failed"
    if record_status == "revoked":
        return "revoked"
    if record_status == "expired":
        return "expired"
    if record_status == "pending_approval":
        return "pending_approval"
    if record_status == "needs_review" and not (
        expires_at is not None and expires_at < today
    ):
        # Its interim review lapsed (TheHub #60817): a decision is owed.
        return "needs_review"
    if record_status in ra.LIVE:
        if expires_at is not None:
            left = (expires_at - today).days
            if left < 0:
                # The daily sweep has not reached it yet; the date has.
                return "expired"
            if left <= EXPIRING_WITHIN_DAYS:
                return "expiring"
        return "active"
    # closed (renewed or every finding resolved), rejected, not approved.
    return "closed"


def worst(severities: Iterable[str]) -> str:
    """The worst of these severity words, or "" when none is a known word."""
    ranked = [s for s in (str(x).lower() for x in severities) if s in SEVERITY_RANK]
    return max(ranked, key=SEVERITY_RANK.index) if ranked else ""


def evidence_at(evidence: list[dict[str, Any]]) -> datetime | None:
    """The newest timestamp among a premise check's evidence: an observation's
    `collected_at` or an EPSS row's `fetched_at`."""
    stamps: list[datetime] = []
    for item in evidence:
        raw = item.get("collected_at") or item.get("fetched_at")
        if not raw:
            continue
        try:
            stamps.append(datetime.fromisoformat(str(raw)))
        except ValueError:
            continue
    return max(stamps) if stamps else None


# ---------------------------------------------------------------------------
# Shapes
# ---------------------------------------------------------------------------


class PremiseVerdictOut(BaseModel):
    index: int
    type: str
    #: holds | failed | unverified - as the monitor reads it at request time.
    status: str
    reason: str
    #: The premise as recorded: its type and whatever keys the monitor reads.
    premise: dict[str, Any]
    #: Each observation (or EPSS row) the verdict rests on: vantage, collector,
    #: tool, state and when it was collected.
    evidence: list[dict[str, Any]]
    #: The newest evidence timestamp, and its age in days. Null when the
    #: verdict rests on nothing - which is what `unverified` usually means.
    evidence_at: datetime | None
    evidence_age_days: float | None


class CoveredFindingOut(BaseModel):
    finding_id: str
    title: str
    rule_id: str
    capability: str
    package_name: str
    #: The scanner's word.
    severity: str
    #: Re-read for this environment (`EnvironmentalScore`), else the scanner's.
    effective_severity: str
    #: environmental | scanner - where `effective_severity` came from.
    effective_source: str
    #: The finding's status in the lake now. A covered finding the lake no
    #: longer holds reads `missing`.
    status: str
    fixed_version: str
    #: Accepted for want of a vendor fix, and a fix now exists.
    now_fixable: bool


class ActionOut(BaseModel):
    """An operation the acceptance API offers on this record now.

    Described, not performed: no page calls these routes yet, so the tab
    names them for an operator (or the agent playbook, which offers the same
    ones) instead of inventing buttons.
    """

    label: str
    method: str
    path: str
    effect: str
    #: `admin`/`agent` principal, or a person only (revoke).
    who: str


class RiskAcceptanceRowOut(BaseModel):
    id: str
    repo_full_name: str
    #: Derived (`derive_state`); `status` is what the record stores.
    state: str
    status: str
    response: str
    deviation_type: str
    #: The row-level reason code the findings carry (`reason_code_for`).
    reason_code: str
    #: The covered findings' worst scanner severity, and worst effective one.
    severity: str
    effective_severity: str
    #: The acceptance's own residual rating (likelihood x impact).
    residual_severity: str
    residual_likelihood: str
    residual_impact: str
    justification: str
    risk_owner: str
    requested_by: str
    approved_by: str | None
    approval_request_id: str | None
    legacy: bool
    renews_id: str | None
    renewal_count: int
    tracking_ref: str | None
    created_at: datetime
    effective_at: datetime | None
    review_by: date | None
    expires_at: date | None
    #: Negative once past. Null for a record with no expiry yet (pending).
    days_left: int | None
    #: Live, and past its review date - the one before expiry, or the
    #: interim review an acceptance nothing watches owes (TheHub #60817).
    review_due: bool
    #: The interim review (TheHub #60817): none | scheduled | due | lapsed |
    #: done, and the day it is owed. `none` when the reason is watched.
    interim_review: str
    interim_review_by: date | None
    interim_reviewed_at: datetime | None
    interim_reviewed_by: str | None
    #: Needs a reviewer's eye now: expired, past its date, or a premise that
    #: fails (stored as `premise_failed`, or failing on today's evidence).
    alarm: bool
    closed_at: datetime | None
    closed_reason: str | None
    compensating_controls: list[dict[str, Any]]
    milestones: list[dict[str, Any]]
    premises: list[PremiseVerdictOut]
    premise_fresh_days: int
    findings_total: int
    #: Covered findings with a fix available now, among all covered.
    now_fixable: int
    drift: int
    findings: list[CoveredFindingOut]


class RiskAcceptanceCountsOut(BaseModel):
    #: Every state in `STATES`, zero included.
    by_state: dict[str, int]
    #: By the covered findings' worst scanner / effective severity.
    by_severity: dict[str, int]
    by_effective_severity: dict[str, int]


class RepoRiskAcceptancesOut(BaseModel):
    repo_id: str
    repo_full_name: str
    today: date
    expiring_within_days: int
    premise_fresh_days: int
    #: Every acceptance in this repository, whatever the filters.
    total: int
    #: Counts over `total`, so the strip reads the same whichever filter is on.
    counts: RiskAcceptanceCountsOut
    #: The filters this response applied, echoed back.
    state: str | None
    severity: str | None
    effective_severity: str | None
    acceptances: list[RiskAcceptanceRowOut]


class EnvironmentalScoreOut(BaseModel):
    finding_id: str
    vector: str
    vector_version: str
    vector_source: str
    base: float
    environmental: float
    base_band: str
    env_band: str
    scanner_severity: str
    effective_severity: str
    facts: list[dict[str, Any]]
    context_id: str
    computed_at: str | None


class EnvironmentalScoresOut(BaseModel):
    available: bool
    reason: str
    total: int
    shown: int
    scored: int
    items: list[EnvironmentalScoreOut]


class AuditEventOut(BaseModel):
    at: datetime
    #: e.g. risk_acceptance.requested / premise_failed / revoked / expired.
    action: str
    actor: str
    actor_kind: str
    detail: dict[str, Any]


class RiskAcceptanceDetailOut(RiskAcceptanceRowOut):
    repo_id: str
    scope: dict[str, Any]
    scores: EnvironmentalScoresOut
    history: list[AuditEventOut]
    #: Records that renewed this one (`renews_id` pointing here).
    renewed_by: list[str]
    actions: list[ActionOut]


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------


def _covered_rows(catalog: Any, repo: str, finding_ids: list[str]) -> dict[str, tuple[Any, ...]]:
    """finding_id -> (title, rule_id, capability, package, severity, status,
    fixed_version), for this repository's rows only."""
    if not finding_ids or catalog is None or not catalog.all_files("findings"):
        return {}
    out: dict[str, tuple[Any, ...]] = {}
    ids = sorted(set(finding_ids))
    for start in range(0, len(ids), _CHUNK):
        chunk = ids[start : start + _CHUNK]
        placeholders = ", ".join("?" for _ in chunk)
        rows = catalog.query(
            "SELECT finding_id, coalesce(title, ''), coalesce(rule_id, ''), "
            "       coalesce(capability, ''), coalesce(package_name, ''), "
            "       lower(coalesce(severity, '')), coalesce(status, ''), "
            "       coalesce(json_extract_string(raw_finding_json, '$.fixed_version'), '') "
            f"FROM findings WHERE repo_full_name = ? AND finding_id IN ({placeholders})",
            [repo, *chunk],
        )
        for row in rows:
            out[str(row[0])] = tuple(row[1:])
    return out


def _effective(session: Any, finding_ids: list[str]) -> dict[str, str]:
    ids = sorted(set(finding_ids))
    out: dict[str, str] = {}
    for start in range(0, len(ids), _CHUNK):
        chunk = ids[start : start + _CHUNK]
        for fid, eff in session.execute(
            select(EnvironmentalScore.finding_id, EnvironmentalScore.effective_severity).where(
                EnvironmentalScore.finding_id.in_(chunk)
            )
        ).all():
            if eff:
                out[str(fid)] = str(eff).lower()
    return out


def _premises(
    session: Any, record: RiskAcceptance, catalog: Any, *, now: datetime, fresh_days: int
) -> list[PremiseVerdictOut]:
    checks = premise_monitor.check_record(session, record, catalog, now=now, fresh_days=fresh_days)
    recorded = [p if isinstance(p, dict) else {} for p in record.premises or []]
    out = []
    for check in checks:
        at = evidence_at(check.evidence)
        out.append(
            PremiseVerdictOut(
                index=check.index,
                type=check.type,
                status=check.status,
                reason=check.reason,
                premise=recorded[check.index] if check.index < len(recorded) else {},
                evidence=list(check.evidence),
                evidence_at=at,
                evidence_age_days=(
                    round((now - at).total_seconds() / 86400, 1) if at is not None else None
                ),
            )
        )
    return out


def _row(
    record: RiskAcceptance,
    *,
    lake: dict[str, tuple[Any, ...]],
    effective: dict[str, str],
    premises: list[PremiseVerdictOut],
    today: date,
    fresh_days: int,
    findings_shown: int,
) -> RiskAcceptanceRowOut:
    code = ra.reason_code_for(record.deviation_type, list(record.compensating_controls or []))
    covered = list(record.covered_finding_ids or [])
    findings: list[CoveredFindingOut] = []
    for fid in covered:
        row = lake.get(fid)
        if row is None:
            findings.append(
                CoveredFindingOut(
                    finding_id=fid,
                    title="",
                    rule_id="",
                    capability="",
                    package_name="",
                    severity="",
                    effective_severity=effective.get(fid, ""),
                    effective_source="environmental" if fid in effective else "scanner",
                    status="missing",
                    fixed_version="",
                    now_fixable=False,
                )
            )
            continue
        title, rule, capability, package, severity, fstatus, fixed = (str(v) for v in row)
        findings.append(
            CoveredFindingOut(
                finding_id=fid,
                title=title,
                rule_id=rule,
                capability=capability,
                package_name=package,
                severity=severity,
                effective_severity=effective.get(fid, severity),
                effective_source="environmental" if fid in effective else "scanner",
                status=fstatus,
                fixed_version=fixed,
                now_fixable=bool(fixed.strip()) and code == "no_vendor_fix",
            )
        )
    # Worst first, so the rows a list shows are the ones that matter.
    findings.sort(
        key=lambda f: (
            -SEVERITY_RANK.index(f.effective_severity)
            if f.effective_severity in SEVERITY_RANK
            else 1,
            f.finding_id,
        )
    )
    state = derive_state(record.status, record.expires_at, today)
    days_left = (record.expires_at - today).days if record.expires_at is not None else None
    failing = any(p.status == "failed" for p in premises)
    live = record.status in ra.LIVE
    interim = ra.interim_state(record, today, ra.interim_rule()) if live else "none"
    return RiskAcceptanceRowOut(
        id=record.id,
        repo_full_name=record.repo_full_name,
        state=state,
        status=record.status,
        response=record.response,
        deviation_type=record.deviation_type,
        reason_code=code,
        severity=worst(f.severity for f in findings),
        effective_severity=worst(f.effective_severity for f in findings),
        residual_severity=record.residual_severity,
        residual_likelihood=record.residual_likelihood,
        residual_impact=record.residual_impact,
        justification=record.justification,
        risk_owner=record.risk_owner,
        requested_by=record.requested_by,
        approved_by=record.approved_by,
        approval_request_id=record.approval_request_id,
        legacy=bool(record.legacy),
        renews_id=record.renews_id,
        renewal_count=int(record.renewal_count or 0),
        tracking_ref=record.tracking_ref,
        created_at=record.created_at,
        effective_at=record.effective_at,
        review_by=record.review_by,
        expires_at=record.expires_at,
        days_left=days_left,
        review_due=live
        and (
            record.status in ("review_due", "needs_review")
            or (record.review_by is not None and record.review_by < today)
            or interim in ("due", "lapsed")
        ),
        interim_review=interim,
        interim_review_by=record.interim_review_by,
        interim_reviewed_at=record.interim_reviewed_at,
        interim_reviewed_by=record.interim_reviewed_by,
        alarm=state in ("premise_failed", "expired", "needs_review")
        or (live and (failing or (days_left is not None and days_left < 0))),
        closed_at=record.closed_at,
        closed_reason=record.closed_reason,
        compensating_controls=list(record.compensating_controls or []),
        milestones=list(record.milestones or []),
        premises=premises,
        premise_fresh_days=fresh_days,
        findings_total=len(covered),
        now_fixable=sum(1 for f in findings if f.now_fixable),
        drift=len(record.drift_finding_ids or []),
        findings=findings[:findings_shown],
    )


def _fresh_days(request: Request) -> int:
    return int(
        getattr(request.app.state.settings, "premise_fresh_days", premise_monitor.FRESH_DAYS)
    )


def _count(values: Iterable[str], keys: Iterable[str]) -> dict[str, int]:
    tally = Counter(values)
    out = {key: tally.pop(key, 0) for key in keys}
    # Anything unforeseen is counted under its own word rather than dropped.
    out.update(dict(tally))
    return out


def actions_for(
    record_id: str, record_status: str, interim_review: str = "none"
) -> list[ActionOut]:
    """What the acceptance API will do with this record in its current status -
    the same rules the routes enforce, so a named action is one that would
    not be refused for the record's status."""
    base = f"/api/risk-acceptances/{record_id}"
    out: list[ActionOut] = []
    if record_status in ra.LIVE and interim_review in ("scheduled", "due", "lapsed"):
        out.append(
            ActionOut(
                label="Record the interim review",
                method="POST",
                path=f"{base}/interim-review",
                effect=(
                    "Says, with a note, that you looked again and the acceptance still "
                    "stands. Nothing watches its reason, so a person must (TheHub #60817)."
                ),
                who="a person",
            )
        )
    if record_status in ra.LIVE:
        out.append(
            ActionOut(
                label="Renew",
                method="POST",
                path=f"{base}/renew",
                effect=(
                    "Opens a new approval request with a new date and justification. "
                    "This record stays as it is until that request is decided."
                ),
                who="admin or agent",
            )
        )
    if record_status in (*ra.LIVE, "pending_approval"):
        out.append(
            ActionOut(
                label="Revoke",
                method="POST",
                path=f"{base}/revoke",
                effect="Ends it now, with a reason; every finding it held reopens.",
                who="a person",
            )
        )
    if record_status == "premise_failed":
        out.append(
            ActionOut(
                label="Propose a corrected acceptance",
                method="POST",
                path="/api/risk-acceptances",
                effect=(
                    "This record cannot be renewed: a premise failed. Fix the findings, "
                    "or propose a new acceptance whose premises hold today."
                ),
                who="admin or agent",
            )
        )
    return out


@router.get("/repos/{repo_id}/risk-acceptances", response_model=RepoRiskAcceptancesOut)
async def repo_risk_acceptances(
    request: Request,
    repo_id: str,
    principal: PrincipalDep,
    state: Annotated[str | None, Query(description="One of the derived states.")] = None,
    severity: Annotated[str | None, Query()] = None,
    effective_severity: Annotated[str | None, Query()] = None,
) -> RepoRiskAcceptancesOut:
    """Every risk acceptance in this repository, each with what it rests on."""
    from mykronos.api.dashboard import _resolve_repo

    repo_full_name = _resolve_repo(request, repo_id)
    catalog = request.app.state.catalog
    fresh_days = _fresh_days(request)
    now = utcnow()
    today = now.date()
    with request.app.state.db.session() as session:
        records = list(
            session.scalars(
                select(RiskAcceptance)
                .where(RiskAcceptance.repo_full_name == repo_full_name)
                .order_by(RiskAcceptance.created_at.desc())
            ).all()
        )
        covered = [fid for r in records for fid in (r.covered_finding_ids or [])]
        lake = _covered_rows(catalog, repo_full_name, covered)
        effective = _effective(session, covered)
        rows = [
            _row(
                record,
                lake=lake,
                effective=effective,
                premises=_premises(session, record, catalog, now=now, fresh_days=fresh_days),
                today=today,
                fresh_days=fresh_days,
                findings_shown=ROW_FINDINGS,
            )
            for record in records
        ]

    counts = RiskAcceptanceCountsOut(
        by_state=_count((r.state for r in rows), STATES),
        by_severity=_count((r.severity for r in rows if r.severity), reversed(SEVERITY_RANK)),
        by_effective_severity=_count(
            (r.effective_severity for r in rows if r.effective_severity),
            reversed(SEVERITY_RANK),
        ),
    )
    shown = [
        r
        for r in rows
        if (not state or r.state == state)
        and (not severity or r.severity == severity.lower())
        and (not effective_severity or r.effective_severity == effective_severity.lower())
    ]
    shown.sort(
        key=lambda r: (
            STATES.index(r.state) if r.state in STATES else len(STATES),
            r.days_left if r.days_left is not None else 10**6,
        )
    )
    return RepoRiskAcceptancesOut(
        repo_id=repo_id,
        repo_full_name=repo_full_name,
        today=today,
        expiring_within_days=EXPIRING_WITHIN_DAYS,
        premise_fresh_days=fresh_days,
        total=len(rows),
        counts=counts,
        state=state,
        severity=severity,
        effective_severity=effective_severity,
        acceptances=shown,
    )


@router.get(
    "/repos/{repo_id}/risk-acceptances/{acceptance_id}",
    response_model=RiskAcceptanceDetailOut,
)
async def repo_risk_acceptance(
    request: Request, repo_id: str, acceptance_id: str, principal: PrincipalDep
) -> RiskAcceptanceDetailOut:
    """One acceptance in full: justification, premises with their evidence,
    environmental scores, audit history and the actions the API offers."""
    from mykronos.api.dashboard import _resolve_repo

    repo_full_name = _resolve_repo(request, repo_id)
    catalog = request.app.state.catalog
    fresh_days = _fresh_days(request)
    now = utcnow()
    with request.app.state.db.session() as session:
        record = session.get(RiskAcceptance, acceptance_id)
        if record is None or record.repo_full_name != repo_full_name:
            # Another repository's record is not served under this one's URL.
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No risk acceptance {acceptance_id} in {repo_full_name}.",
            )
        covered = list(record.covered_finding_ids or [])
        row = _row(
            record,
            lake=_covered_rows(catalog, repo_full_name, covered),
            effective=_effective(session, covered),
            premises=_premises(session, record, catalog, now=now, fresh_days=fresh_days),
            today=now.date(),
            fresh_days=fresh_days,
            findings_shown=DETAIL_FINDINGS,
        )
        history = [
            AuditEventOut(
                at=entry.created_at,
                action=entry.action,
                actor=entry.actor,
                actor_kind=entry.actor_kind or "",
                detail=dict(entry.detail or {}),
            )
            for entry in session.scalars(
                select(AuditLogEntry)
                .where(
                    AuditLogEntry.entity_type == "risk_acceptance",
                    AuditLogEntry.entity_id == record.id,
                )
                .order_by(AuditLogEntry.created_at)
            ).all()
        ]
        renewed_by = [
            str(rid)
            for rid in session.scalars(
                select(RiskAcceptance.id)
                .where(
                    RiskAcceptance.renews_id == record.id,
                    RiskAcceptance.repo_full_name == repo_full_name,
                )
                .order_by(RiskAcceptance.created_at)
            ).all()
        ]
        scores = EnvironmentalScoresOut.model_validate(environmental_scores(session, covered))
        return RiskAcceptanceDetailOut(
            **row.model_dump(),
            repo_id=repo_id,
            scope=dict(record.scope or {}),
            scores=scores,
            history=history,
            renewed_by=renewed_by,
            actions=actions_for(record.id, record.status, row.interim_review),
        )
