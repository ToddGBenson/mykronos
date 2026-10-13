"""An agent's track record, from records that already exist (spec 36 §6).

Spec 34 §5 lets the operator delegate approval authority to an agent, and
§5.2 says trust is measured, not assumed. What was missing is the record a
delegation should rest on: how often a person overturned this family's
sampled approvals, how often its own requests were refused, how many of its
dispositions somebody had to reopen, how many claims it walked away from.

**No new events, no new tables.** Every number here is a read over rows the
platform already writes: `approval_requests` and `approval_decisions` (the
engine), `audit_log` with the actor kind and provenance spec 34 §1 added,
`triage_state` (the worklist) and finding status in the lake. A metric the
existing records cannot support is reported as `unavailable` with the reason,
never as zero: "could not compute" must not read as "nothing happened".

**Three states, not two.** `computed` has a numerator and a non-zero
denominator. `no_data` means the source was read and the denominator is zero:
an agent that never had a sample reviewed has no agreement rate, and showing
100% or 0% would each be a lie. `unavailable` means the source could not be
read, or no record exists from which the number could be derived.

**Grouped as the records say, not as the credential says now.** Approvals,
requests and audit entries each snapshot the agent's family and instance at
the moment it acted, so a revoked or expired credential cannot change what its
record says. Only claims are joined to `agent_credentials`, because a claim
stores a handle and nothing else.

Gathering (`gather`) is separate from computing (`compute`), the split
`agent_work` and `briefing` use: `compute` is pure and tested on rows.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any

from sqlalchemy import select

from mykronos.approvals.policy import ApprovalPolicy
from mykronos.db.models import (
    AgentCredential,
    ApprovalDecision,
    ApprovalRequest,
    AuditLogEntry,
    TriageState,
)

#: Metric states. See the module docstring.
COMPUTED = "computed"
NO_DATA = "no_data"
UNAVAILABLE = "unavailable"

#: A family or instance a record names no value for. Shown rather than
#: dropped: an agent action with no recorded family is still an agent action.
UNRECORDED = "(unrecorded)"

#: The dispositions `POST /findings/{id}/reopen` can undo (api/dashboard.py
#: `REOPENABLE`). Only these can be observed reopening, so only these are the
#: denominator of `dispositions.reopened`.
REOPENABLE = ("false_positive", "suppressed")

#: Request states as the engine stores them (`ApprovalRequest.state`).
REQUEST_STATES = ("approved", "rejected", "expired", "pending", "withdrawn")

SOURCE_DECISIONS = "approval_decisions (approver_kind = agent)"
SOURCE_REQUESTS = "approval_requests (requester_kind = agent) + approval_decisions"
SOURCE_DISPOSITIONS = "audit_log finding.status (actor_kind = agent) + finding.reopened"
SOURCE_CLAIMS = "triage_state.claimed_by = agent actor + findings.status (lake)"

#: Spec 36 §6 lists these. The records do not support them; the reason is the
#: output, so nobody reads their absence as a clean record.
NOT_DERIVABLE: dict[str, tuple[str, str]] = {
    "findings.reported_fixed_reopened": (
        "lake findings.status, compaction",
        "No principal reports a finding fixed: `fixed` is an observation the reconciler "
        "records after two successful scans miss a finding, and the status route refuses "
        "it from anyone (spec 10 §2.2). When a fixed finding comes back, compaction flips "
        "it to open and only logs a count (`CompactionResult.reopened`); nothing stores "
        "which finding reopened or which change claimed to fix it. Dispositions an agent "
        "made that were later reopened are measured instead: `dispositions.reopened`.",
    ),
    "pull_requests.closed_unmerged": (
        "none",
        "The platform records an approval request per head commit, not what happened to "
        "the pull request on GitHub: nothing stores a pull request closed without "
        "merging. Every GitHub action also reads as one shared account (spec 34 §1.2), so "
        "a close could not be attributed to an agent if it were stored. Rejected "
        "`pull_request_merge` requests are measured: see `requests_by_duty`.",
    ),
}


@dataclass(frozen=True)
class Metric:
    """One number, with what it was divided by and where it came from."""

    name: str
    status: str
    source: str
    #: The numerator. Null only when `unavailable`.
    value: int | None = None
    #: What `value` is out of, and what that is.
    denominator: int | None = None
    denominator_label: str = ""
    #: value / denominator, or null when the denominator is zero or unknown.
    rate: float | None = None
    breakdown: dict[str, int] = field(default_factory=dict)
    #: Why `unavailable` or `no_data`, or a limit a reader must know.
    note: str = ""


@dataclass(frozen=True)
class AgentRef:
    family: str
    instance: str
    actor: str = ""
    purpose: str = ""
    active: bool | None = None


@dataclass(frozen=True)
class DecisionRow:
    """One agent's verdict as an approver (`ApprovalDecision`)."""

    family: str
    instance: str
    verdict: str
    delegation_id: str | None
    sampled: bool
    sample_verdict: str | None
    sample_reviewed_at: datetime | None


@dataclass(frozen=True)
class RequestRow:
    """One request an agent made (`ApprovalRequest`), with its answers."""

    family: str
    instance: str
    duty: str
    state: str
    expires_at: datetime
    verdicts: tuple[str, ...]


@dataclass(frozen=True)
class StatusEvent:
    """`finding.status` or `finding.reopened` from the audit log."""

    finding_id: str
    action: str  # "finding.status" | "finding.reopened"
    created_at: datetime
    actor: str
    actor_kind: str
    family: str = ""
    instance: str = ""
    new_status: str = ""
    previous_status: str = ""
    applied: bool = True


@dataclass(frozen=True)
class ClaimRow:
    finding_id: str
    claimed_by: str
    claim_expires_at: datetime | None


@dataclass(frozen=True)
class Gathered:
    """Everything `compute` reads. A `None` source could not be read."""

    agents: list[AgentRef] | None
    decisions: list[DecisionRow] | None
    requests: list[RequestRow] | None
    status_events: list[StatusEvent] | None
    claims: list[ClaimRow] | None
    #: finding_id -> lake status, for claimed findings. None: lake unreadable.
    finding_status: dict[str, str] | None
    #: delegation_id -> `sampling.delegation_stats` output.
    delegation_stats: dict[str, dict[str, Any]]
    #: Disposition entries no agent can be read from: written before the
    #: actor kind existed, or by a CLI or script (`unattributed`).
    unattributed_dispositions: int | None
    unknown: list[tuple[str, str]] = field(default_factory=list)


@dataclass(frozen=True)
class DutyRecord:
    duty: str
    requests: int
    by_state: dict[str, int]
    rejected: Metric
    needs_info: Metric


@dataclass(frozen=True)
class DelegationRecord:
    """The figure that actually suspends a delegation (spec 34 §5.2)."""

    delegation_id: str
    duty: str
    agreed: int
    reviewed: int
    window: int
    threshold: float
    below_threshold: bool | None
    suspended_at: datetime | None
    suspended_reason: str | None


@dataclass(frozen=True)
class GroupRecord:
    family: str
    #: Null on a family's aggregate.
    instance: str | None
    actor: str
    instances: list[str]
    metrics: list[Metric]
    requests_by_duty: list[DutyRecord]
    delegations: list[DelegationRecord]


@dataclass(frozen=True)
class Scorecard:
    generated_at: datetime
    agreement_window: int
    suspend_below_agreement: float
    policy_version: str
    families: list[GroupRecord]
    instances: list[GroupRecord]
    unattributed_dispositions: int | None
    unknown: list[dict[str, str]]


# -- Metric helpers ------------------------------------------------------------


def _ratio(
    name: str,
    source: str,
    value: int,
    denominator: int,
    label: str,
    *,
    empty_note: str,
    breakdown: dict[str, int] | None = None,
    note: str = "",
) -> Metric:
    if denominator == 0:
        return Metric(
            name=name,
            status=NO_DATA,
            source=source,
            value=value,
            denominator=0,
            denominator_label=label,
            breakdown=breakdown or {},
            note=empty_note + (" " + note if note else ""),
        )
    return Metric(
        name=name,
        status=COMPUTED,
        source=source,
        value=value,
        denominator=denominator,
        denominator_label=label,
        rate=round(value / denominator, 4),
        breakdown=breakdown or {},
        note=note,
    )


def _unavailable(name: str, source: str, reason: str) -> Metric:
    return Metric(name=name, status=UNAVAILABLE, source=source, note=reason)


# -- As an approver --------------------------------------------------------------


def _approver_metrics(
    rows: list[DecisionRow] | None, window: int, threshold: float
) -> list[Metric]:
    names = (
        "approver.verdicts",
        "approver.sampled",
        "approver.sample_reviewed",
        "approver.overturned",
        "approver.agreement",
        "approver.agreement_window",
    )
    if rows is None:
        return [
            _unavailable(n, SOURCE_DECISIONS, "approval_decisions could not be read.")
            for n in names
        ]
    verdicts: dict[str, int] = defaultdict(int)
    for r in rows:
        verdicts[r.verdict] += 1
    delegated = [r for r in rows if r.delegation_id]
    sampled = [r for r in delegated if r.sampled]
    reviewed = [r for r in sampled if r.sample_verdict is not None]
    agreed = sum(1 for r in reviewed if r.sample_verdict == "agree")
    disagreed = sum(1 for r in reviewed if r.sample_verdict == "disagree")
    # The same order and window `sampling._agreement` applies per delegation:
    # the newest `agreement_window` reviewed samples, by when they were reviewed.
    recent = sorted(
        reviewed, key=lambda r: r.sample_reviewed_at or datetime.min, reverse=True
    )[:window]
    recent_agreed = sum(1 for r in recent if r.sample_verdict == "agree")
    windowed = _ratio(
        "approver.agreement_window",
        SOURCE_DECISIONS,
        recent_agreed,
        len(recent),
        f"newest {window} reviewed samples (agreement_window)",
        empty_note="No sampled decision has been reviewed by a person yet.",
    )
    if windowed.rate is not None:
        windowed = replace(
            windowed,
            note=(
                f"{'Below' if windowed.rate < threshold else 'At or above'} the policy's "
                f"suspend_below_agreement of {threshold:.0%}. Suspension acts per "
                "delegation, across every family it trusts: see `delegations`."
            ),
        )
    return [
        _ratio(
            "approver.verdicts",
            SOURCE_DECISIONS,
            verdicts.get("reject", 0),
            len(rows),
            "decisions as an approver; value counts rejections",
            empty_note="This agent has not decided any approval request.",
            breakdown=dict(verdicts),
        ),
        _ratio(
            "approver.sampled",
            SOURCE_DECISIONS,
            len(sampled),
            len(delegated),
            "decisions made under a delegation",
            empty_note="No decision was made under a delegation, so none could be sampled.",
        ),
        _ratio(
            "approver.sample_reviewed",
            SOURCE_DECISIONS,
            len(reviewed),
            len(sampled),
            "sampled decisions",
            empty_note="No decision was sampled.",
            breakdown={"awaiting_review": len(sampled) - len(reviewed)},
        ),
        _ratio(
            "approver.overturned",
            SOURCE_DECISIONS,
            disagreed,
            len(reviewed),
            "sampled decisions a person reviewed",
            empty_note="No sampled decision has been reviewed by a person yet.",
            note=(
                "A person's disagreement does not undo the decision (approvals/sampling.py); "
                "it is what the approver is measured on."
            ),
        ),
        _ratio(
            "approver.agreement",
            SOURCE_DECISIONS,
            agreed,
            len(reviewed),
            "sampled decisions a person reviewed, all time",
            empty_note="No sampled decision has been reviewed by a person yet.",
        ),
        windowed,
    ]


# -- As a requester --------------------------------------------------------------


def _effective_state(row: RequestRow, now: datetime) -> str:
    """The engine expires a pending request lazily, on the next decision or
    the stamp job; one past its TTL is expired whether or not that ran."""
    if row.state == "pending" and row.expires_at <= now:
        return "expired"
    return row.state


def _requester_metrics(
    rows: list[RequestRow], now: datetime
) -> tuple[list[Metric], list[DutyRecord]]:
    def summarise(subset: list[RequestRow]) -> tuple[dict[str, int], Metric, Metric]:
        by_state: dict[str, int] = defaultdict(int)
        for r in subset:
            by_state[_effective_state(r, now)] += 1
        decided = by_state.get("approved", 0) + by_state.get("rejected", 0)
        asked = sum(1 for r in subset if "needs_info" in r.verdicts)
        rejected = _ratio(
            "requester.rejected",
            SOURCE_REQUESTS,
            by_state.get("rejected", 0),
            decided,
            "requests decided (approved + rejected)",
            empty_note="No request this agent made has been decided.",
            breakdown=dict(by_state),
            note=(
                "A pending request past its expiry is counted expired; the engine marks "
                "it so lazily."
            ),
        )
        needs_info = _ratio(
            "requester.needs_info",
            SOURCE_REQUESTS,
            asked,
            len(subset),
            "requests made",
            empty_note="This agent has made no approval request.",
        )
        return dict(by_state), rejected, needs_info

    _, rejected, needs_info = summarise(rows)
    duties: dict[str, list[RequestRow]] = defaultdict(list)
    for r in rows:
        duties[r.duty].append(r)
    by_duty = []
    for duty in sorted(duties):
        states, d_rejected, d_needs = summarise(duties[duty])
        by_duty.append(
            DutyRecord(
                duty=duty,
                requests=len(duties[duty]),
                by_state=states,
                rejected=d_rejected,
                needs_info=d_needs,
            )
        )
    return [rejected, needs_info], by_duty


# -- Dispositions ----------------------------------------------------------------


def _reopener(event: StatusEvent, disposer: StatusEvent) -> str:
    if event.actor_kind == "human":
        return "human"
    if event.actor_kind == "agent":
        return "self" if event.instance == disposer.instance else "another_agent"
    return event.actor_kind or "unattributed"


def _disposition_outcomes(events: list[StatusEvent]) -> dict[int, str]:
    """For each agent disposition (keyed by `id()` of the event), what happened next.

    A disposition is *reopened* only when the next status event on its finding
    is a reopen. If somebody dispositioned it again first, the reopen undid
    their decision, not this one: that is `superseded`.
    """
    by_finding: dict[str, list[StatusEvent]] = defaultdict(list)
    for e in events:
        if e.action == "finding.reopened" or e.applied:
            by_finding[e.finding_id].append(e)
    outcome: dict[int, str] = {}
    for seq in by_finding.values():
        seq.sort(key=lambda ev: ev.created_at)
        for pos, e in enumerate(seq):
            if e.action != "finding.status" or e.actor_kind != "agent":
                continue
            if pos + 1 == len(seq):
                outcome[id(e)] = "standing"
                continue
            nxt = seq[pos + 1]
            outcome[id(e)] = (
                "reopened_by_" + _reopener(nxt, e)
                if nxt.action == "finding.reopened"
                else "superseded"
            )
    return outcome


def _disposition_metric(own: list[StatusEvent], outcomes: dict[int, str]) -> Metric:
    reopenable = [e for e in own if e.applied and e.new_status in REOPENABLE]
    breakdown: dict[str, int] = defaultdict(int)
    for e in reopenable:
        breakdown[outcomes.get(id(e), "standing")] += 1
    reopened = sum(v for k, v in breakdown.items() if k.startswith("reopened_by_"))
    other = sum(1 for e in own if e.applied and e.new_status not in REOPENABLE)
    if other:
        breakdown["not_measurable"] = other
    return _ratio(
        "dispositions.reopened",
        SOURCE_DISPOSITIONS,
        reopened,
        len(reopenable),
        "false_positive and suppressed dispositions this agent applied",
        empty_note="This agent has applied no false_positive or suppressed disposition.",
        breakdown=dict(breakdown),
        note=(
            "`not_measurable` counts accepted_risk dispositions: an acceptance ends through "
            "the acceptance sweep, which writes no audit entry, so its reopening cannot be "
            "observed. A DAST finding gets a new id each scan (#274), so a disposition of "
            "one can stand here while the same alert comes back under another id."
        ),
    )


# -- Claims ----------------------------------------------------------------------


def _claim_metric(
    claims: list[ClaimRow] | None,
    finding_status: dict[str, str] | None,
    actors: set[str],
    now: datetime,
) -> Metric:
    name = "claims.lapsed_open"
    if claims is None:
        return _unavailable(name, SOURCE_CLAIMS, "triage_state could not be read.")
    own = [c for c in claims if c.claimed_by in actors]
    lapsed = [c for c in own if c.claim_expires_at is not None and c.claim_expires_at <= now]
    if lapsed and finding_status is None:
        return _unavailable(
            name,
            SOURCE_CLAIMS,
            "The lake could not be read, so whether a lapsed claim's finding is still "
            "open is unknown.",
        )
    statuses = finding_status or {}
    breakdown = {"live": len(own) - len(lapsed)}
    for c in lapsed:
        status = statuses.get(c.finding_id)
        key = (
            "lapsed_open"
            if status == "open"
            else "lapsed_finding_not_in_lake"
            if status is None
            else "lapsed_closed"
        )
        breakdown[key] = breakdown.get(key, 0) + 1
    return _ratio(
        name,
        SOURCE_CLAIMS,
        breakdown.get("lapsed_open", 0),
        len(own),
        "claims currently recorded under this agent's actor",
        empty_note="No claim is recorded under this agent's actor.",
        breakdown=breakdown,
        note=(
            "A lower bound. `triage_state` keeps one claim per finding: a released or "
            "re-claimed claim leaves no trace, and claims are not audited. A claim's "
            "`by` is the handle the caller typed; it is matched to the agent's actor "
            "name, which is the handle the work queue treats as the agent's own."
        ),
    )


# -- Grouping --------------------------------------------------------------------


def _key(family: str, instance: str) -> tuple[str, str]:
    return (family or UNRECORDED, instance or UNRECORDED)


def compute(
    gathered: Gathered,
    policy: ApprovalPolicy,
    *,
    now: datetime,
    family: str | None = None,
    instance: str | None = None,
) -> Scorecard:
    """The track record per family and per instance. Pure."""
    window = policy.delegations.agreement_window
    threshold = policy.delegations.suspend_below_agreement

    refs: dict[str, AgentRef] = {}
    actors_by_instance: dict[str, set[str]] = defaultdict(set)
    for a in gathered.agents or []:
        refs[a.instance] = a
        if a.actor:
            actors_by_instance[a.instance].add(a.actor)

    # Which (family, instance) pairs have a record of any kind.
    seen: set[tuple[str, str]] = set()
    decisions: dict[tuple[str, str], list[DecisionRow]] = defaultdict(list)
    for d in gathered.decisions or []:
        decisions[_key(d.family, d.instance)].append(d)
    requests: dict[tuple[str, str], list[RequestRow]] = defaultdict(list)
    for r in gathered.requests or []:
        requests[_key(r.family, r.instance)].append(r)
    events = gathered.status_events or []
    outcomes = _disposition_outcomes(events)
    dispositions: dict[tuple[str, str], list[StatusEvent]] = defaultdict(list)
    for e in events:
        if e.action == "finding.status" and e.actor_kind == "agent":
            dispositions[_key(e.family, e.instance)].append(e)
    claim_holders: set[str] = {c.claimed_by for c in gathered.claims or []}
    seen.update(decisions, requests, dispositions)
    for inst, actor_names in actors_by_instance.items():
        if actor_names & claim_holders:
            ref = refs[inst]
            seen.add(_key(ref.family, inst))

    def record(fam: str, keys: list[tuple[str, str]], inst: str | None) -> GroupRecord:
        d_rows = None if gathered.decisions is None else [x for k in keys for x in decisions[k]]
        r_rows = [x for k in keys for x in requests[k]]
        s_rows = [x for k in keys for x in dispositions[k]]
        actors = {a for _, i in keys for a in actors_by_instance.get(i, set())}
        metrics = _approver_metrics(d_rows, window, threshold)
        if gathered.requests is None:
            metrics += [
                _unavailable(n, SOURCE_REQUESTS, "approval_requests could not be read.")
                for n in ("requester.rejected", "requester.needs_info")
            ]
            by_duty: list[DutyRecord] = []
        else:
            req_metrics, by_duty = _requester_metrics(r_rows, now)
            metrics += req_metrics
        if gathered.status_events is None:
            metrics.append(
                _unavailable(
                    "dispositions.reopened", SOURCE_DISPOSITIONS, "audit_log could not be read."
                )
            )
        else:
            metrics.append(_disposition_metric(s_rows, outcomes))
        if gathered.agents is None:
            metrics.append(
                _unavailable(
                    "claims.lapsed_open",
                    SOURCE_CLAIMS,
                    "agent_credentials could not be read, so no claim's handle can be "
                    "matched to an agent.",
                )
            )
        else:
            metrics.append(
                _claim_metric(gathered.claims, gathered.finding_status, actors, now)
            )
        metrics += [
            _unavailable(name, source, reason)
            for name, (source, reason) in NOT_DERIVABLE.items()
        ]
        delegation_ids = sorted({x.delegation_id for x in d_rows or [] if x.delegation_id})
        delegations = []
        for did in delegation_ids:
            stats = gathered.delegation_stats.get(did)
            if stats is None:
                continue
            agreement = stats.get("agreement") or {}
            reviewed = int(agreement.get("reviewed", 0))
            agreed = int(agreement.get("agreed", 0))
            delegations.append(
                DelegationRecord(
                    delegation_id=did,
                    duty=str(stats.get("duty") or ""),
                    agreed=agreed,
                    reviewed=reviewed,
                    window=int(agreement.get("window", window)),
                    threshold=float(agreement.get("threshold", threshold)),
                    below_threshold=(agreed / reviewed < threshold) if reviewed else None,
                    suspended_at=stats.get("suspended_at"),
                    suspended_reason=stats.get("suspended_reason"),
                )
            )
        ref = refs.get(inst or "")
        return GroupRecord(
            family=fam,
            instance=inst,
            actor=ref.actor if ref else "",
            instances=sorted(i for _, i in keys),
            metrics=metrics,
            requests_by_duty=by_duty,
            delegations=delegations,
        )

    selected = sorted(
        k
        for k in seen
        if (family is None or k[0] == family) and (instance is None or k[1] == instance)
    )
    families_wanted = sorted({k[0] for k in selected})
    family_records = [
        record(fam, sorted(k for k in seen if k[0] == fam), None) for fam in families_wanted
    ]
    instance_records = [record(fam, [(fam, inst)], inst) for fam, inst in selected]

    unknown = [{"source": s, "detail": d} for s, d in gathered.unknown]
    return Scorecard(
        generated_at=now,
        agreement_window=window,
        suspend_below_agreement=threshold,
        policy_version=policy.version,
        families=family_records,
        instances=instance_records,
        unattributed_dispositions=gathered.unattributed_dispositions,
        unknown=unknown,
    )


# -- Gathering -------------------------------------------------------------------


def _prov(provenance: dict[str, Any] | None) -> tuple[str, str]:
    p = provenance or {}
    return str(p.get("family") or ""), str(p.get("instance") or "")


def _read(label: str, unknown: list[tuple[str, str]], fn: Any) -> Any:
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 - reported as unknown, not as none
        unknown.append((label, f"{type(exc).__name__}: {exc}"[:300]))
        return None


def _finding_status(catalog: Any, ids: Iterable[str]) -> dict[str, str]:
    wanted = sorted(set(ids))
    if not wanted or not catalog.all_files("findings"):
        return {}
    out: dict[str, str] = {}
    for start in range(0, len(wanted), 500):
        chunk = wanted[start : start + 500]
        marks = ", ".join("?" for _ in chunk)
        for finding_id, status in catalog.query(
            f"SELECT finding_id, status FROM findings WHERE finding_id IN ({marks})", chunk
        ):
            out[str(finding_id)] = str(status)
    return out


def gather(db: Any, catalog: Any, policy: ApprovalPolicy, *, now: datetime) -> Gathered:
    """Read the rows `compute` needs. A source that fails is `None` and named
    in `unknown`; the others are still read."""
    from mykronos.approvals import sampling

    unknown: list[tuple[str, str]] = []

    def agents() -> list[AgentRef]:
        with db.session() as session:
            return [
                AgentRef(
                    family=r.family,
                    instance=r.instance,
                    actor=r.actor,
                    purpose=r.purpose,
                    active=r.revoked_at is None and r.expires_at > now,
                )
                for r in session.execute(select(AgentCredential)).scalars()
            ]

    def decisions() -> list[DecisionRow]:
        with db.session() as session:
            rows = session.execute(
                select(ApprovalDecision).where(ApprovalDecision.approver_kind == "agent")
            ).scalars()
            out = []
            for d in rows:
                fam, inst = _prov(d.approver_provenance)
                out.append(
                    DecisionRow(
                        family=fam,
                        instance=inst,
                        verdict=d.verdict,
                        delegation_id=d.delegation_id,
                        sampled=bool(d.sampled),
                        sample_verdict=d.sample_verdict,
                        sample_reviewed_at=d.sample_reviewed_at,
                    )
                )
            return out

    def requests() -> list[RequestRow]:
        with db.session() as session:
            reqs = list(
                session.execute(
                    select(ApprovalRequest).where(ApprovalRequest.requester_kind == "agent")
                ).scalars()
            )
            verdicts: dict[str, list[str]] = defaultdict(list)
            if reqs:
                for request_id, verdict in session.execute(
                    select(ApprovalDecision.request_id, ApprovalDecision.verdict).where(
                        ApprovalDecision.request_id.in_([r.id for r in reqs])
                    )
                ).all():
                    verdicts[str(request_id)].append(str(verdict))
            out = []
            for r in reqs:
                fam, inst = _prov(r.requester_provenance)
                out.append(
                    RequestRow(
                        family=fam,
                        instance=inst,
                        duty=r.duty,
                        state=r.state,
                        expires_at=r.expires_at,
                        verdicts=tuple(verdicts.get(r.id, ())),
                    )
                )
            return out

    def status_events() -> tuple[list[StatusEvent], int]:
        with db.session() as session:
            rows = session.execute(
                select(AuditLogEntry).where(
                    AuditLogEntry.action.in_(("finding.status", "finding.reopened"))
                )
            ).scalars()
            out = []
            unattributed = 0
            for e in rows:
                detail = e.detail or {}
                if e.action == "finding.status" and e.actor_kind in ("", "unattributed"):
                    unattributed += 1
                fam, inst = _prov(e.actor_provenance) if e.actor_kind == "agent" else ("", "")
                out.append(
                    StatusEvent(
                        finding_id=e.entity_id,
                        action=e.action,
                        created_at=e.created_at,
                        actor=e.actor,
                        actor_kind=e.actor_kind or "",
                        family=fam,
                        instance=inst,
                        new_status=str(detail.get("new_status") or ""),
                        previous_status=str(detail.get("previous_status") or ""),
                        # A governed disposition approved after its finding
                        # closed is recorded with `applied: false`.
                        applied=bool(detail.get("applied", True)),
                    )
                )
            return out, unattributed

    def claims() -> list[ClaimRow]:
        with db.session() as session:
            return [
                ClaimRow(
                    finding_id=r.finding_id,
                    claimed_by=r.claimed_by or "",
                    claim_expires_at=r.claim_expires_at,
                )
                for r in session.execute(
                    select(TriageState).where(TriageState.claimed_by.is_not(None))
                ).scalars()
            ]

    agent_rows = _read("agent_credentials", unknown, agents)
    decision_rows = _read("approval_decisions", unknown, decisions)
    request_rows = _read("approval_requests", unknown, requests)
    events = _read("audit_log", unknown, status_events)
    claim_rows = _read("triage_state", unknown, claims)

    agent_actors = {a.actor for a in agent_rows or []}
    claimed = [c.finding_id for c in claim_rows or [] if c.claimed_by in agent_actors]
    finding_status = (
        _read("lake findings", unknown, lambda: _finding_status(catalog, claimed))
        if claimed
        else {}
    )

    stats: dict[str, dict[str, Any]] = {}
    for did in sorted({d.delegation_id for d in decision_rows or [] if d.delegation_id}):
        found = _read(
            f"delegation {did}", unknown, lambda did=did: sampling.delegation_stats(db, policy, did)
        )
        if found is not None:
            stats[did] = found

    return Gathered(
        agents=agent_rows,
        decisions=decision_rows,
        requests=request_rows,
        status_events=events[0] if events is not None else None,
        claims=claim_rows,
        finding_status=finding_status,
        delegation_stats=stats,
        unattributed_dispositions=events[1] if events is not None else None,
        unknown=unknown,
    )
