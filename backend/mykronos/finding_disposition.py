"""Governed dispositions of critical and high findings (mykronos #713).

`PATCH /api/dashboard/findings/{id}/status` closes a finding as completely as
an approved risk acceptance does, and until this module anyone with write
access could call it - an agent credential included. Spec 33/34 made the
honest route (risk acceptance) a governed duty and left the easy one open: an
agent that wanted a finding gone did not need an acceptance, it could call the
finding a false positive. On 2026-09-27 one did, for a high ZAP 40012 XSS. The
evidence was good and the verdict was right, but nobody else signed it.

This is the `finding_disposition` duty. For an **agent** and a **critical or
high** finding:

- `false_positive` and `suppressed` go through here: the agent's evidence is
  frozen with the finding row and its raw scanner record, the finding stays
  open, and the disposition is applied only when an approver the policy admits
  says yes;
- `accepted_risk` is refused outright on the direct route - it already has a
  governed home, `/api/risk-acceptances`.

A person's direct disposition keeps working (one operator runs this estate,
and `single_operator` already flags that), and so does an agent's on medium
and below. Those are the next step if the governed tiers prove their worth;
the dangerous case is the one closed here.

**A member of a serious toxic combination is governed at the combination's
severity** (review of #1018). Since TheHub #60965 a member dispositioned
`false_positive` or `accepted_risk` stops counting, so the low ZAP-10037 half
of a critical vulnerable-image-and-live-service pair closes a critical - and
lifts the Oracle's `no_go` - the moment it is dispositioned. Read by its own
severity, that member was an agent's to close alone. `governing_severity`
raises a finding to the worst open combination it belongs to, detected the
way the risk decision detects it (`toxic.detect`, KEV and the policy's
escalation included), and every enforcement point reads that instead.
Detection that cannot run fails closed for an agent.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from mykronos.adminauth import ActorKind, Principal
from mykronos.approvals.engine import (
    ApprovalError,
    Subject,
    rationale_problem,
    register_adapter,
    register_dedicated_route,
    register_on_approved,
)
from mykronos.db.models import ApprovalDecision, ApprovalRequest, AuditLogEntry
from mykronos.lake.catalog import Catalog
from mykronos.lake.mutate import locate_findings, update_findings
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

DUTY = "finding_disposition"
ROUTE = "/api/dashboard/findings/{finding_id}/disposition-requests"
#: Severities an agent may not close on its own word.
GOVERNED_SEVERITIES = ("critical", "high")
#: What this duty can apply. `accepted_risk` is a risk acceptance, not this.
DISPOSITIONS = ("false_positive", "suppressed")

_CATALOG: Catalog | None = None
#: For KEV, which can make any combination critical. Optional: without it
#: KEV is not consulted and the escalation alone decides.
_DB: Any = None
#: Where the Oracle policy's `toxic_combinations.escalate_steps` is read.
_ORACLE_POLICY_PATH: Any = None


def bind(catalog: Catalog, *, db: Any = None, oracle_policy_path: Any = None) -> None:
    global _CATALOG, _DB, _ORACLE_POLICY_PATH
    _CATALOG = catalog
    _DB = db
    _ORACLE_POLICY_PATH = oracle_policy_path


def _catalog() -> Catalog:
    if _CATALOG is None:
        raise RuntimeError("finding_disposition.bind(catalog) was never called.")
    return _CATALOG


def governed(principal: Principal, severity: str | None) -> bool:
    """Whether this principal's direct disposition of this finding is refused."""
    return principal.kind is ActorKind.AGENT and str(severity or "").lower() in (
        GOVERNED_SEVERITIES
    )


def _rank(severity: str | None) -> int:
    from mykronos.toxic import SEVERITIES

    value = str(severity or "").lower()
    return SEVERITIES.index(value) if value in SEVERITIES else -1


def worse(a: str | None, b: str | None) -> str:
    """The worse of two severities, lower-cased."""
    return str((a if _rank(a) >= _rank(b) else b) or "").lower()


def _escalate_steps() -> int:
    if _ORACLE_POLICY_PATH is None:
        return 1
    from mykronos.oracle.policy import load_policy

    try:
        return int(load_policy(_ORACLE_POLICY_PATH).toxic_combinations.escalate_steps)
    except Exception:  # noqa: BLE001 - the same fallback the estate listing uses
        return 1


def _repo_combinations(repo: str) -> list[dict[str, Any]]:
    """Every open toxic combination in `repo`, as the risk decision sees it.
    Raises when detection cannot run."""
    from mykronos import toxic

    catalog = _catalog()
    steps = _escalate_steps()
    if _DB is not None:
        with _DB.session() as session:
            combos = toxic.detect(catalog, repo=repo, session=session, escalate_steps=steps)
    else:
        combos = toxic.detect(catalog, repo=repo, escalate_steps=steps)
    return [
        {
            "combination_id": c.combination_id,
            "rule_id": c.rule_id,
            "name": c.name,
            "severity": c.severity,
            "member_ids": {str(m.get("finding_id")) for m in c.members},
        }
        for c in combos
    ]


def governing_severities(
    rows: list[dict[str, Any]],
) -> dict[str, tuple[str, list[dict[str, str]]]]:
    """finding id -> (governing severity, the combinations that raised it).

    The governing severity is the finding's own, raised to the worst open
    combination it is a member of; detection runs once per repository.
    Detection that cannot run answers `critical`, so an agent is sent to the
    governed route rather than let through on a guess."""
    out: dict[str, tuple[str, list[dict[str, str]]]] = {}
    by_repo: dict[str, list[dict[str, Any]] | None] = {}
    for row in rows:
        finding_id = str(row.get("finding_id") or "")
        own = str(row.get("severity") or "").lower()
        repo = str(row.get("repo_full_name") or "")
        if repo and repo not in by_repo:
            try:
                by_repo[repo] = _repo_combinations(repo)
            except Exception:  # noqa: BLE001 - fail closed; logged for the operator
                logger.exception("Toxic detection failed for %s; governing as critical.", repo)
                by_repo[repo] = None
        combos = by_repo.get(repo, []) if repo else []
        if combos is None:
            out[finding_id] = ("critical", [])
            continue
        mine = [
            {k: c[k] for k in ("combination_id", "rule_id", "name", "severity")}
            for c in combos
            if finding_id in c["member_ids"]
        ]
        severity = own
        for combo in mine:
            severity = worse(severity, combo["severity"])
        out[finding_id] = (severity, mine)
    return out


def governing_severity(row: dict[str, Any]) -> tuple[str, list[dict[str, str]]]:
    """`governing_severities` for one finding."""
    return governing_severities([row])[str(row.get("finding_id") or "")]


def governed_findings(principal: Principal, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The rows whose direct disposition by `principal` is refused, each at its
    governing severity. Detection runs only for an agent, and only when some
    row is below the governed tiers on its own."""
    if principal.kind is not ActorKind.AGENT:
        return []
    lesser = [r for r in rows if not governed(principal, r.get("severity"))]
    raised = governing_severities(lesser) if lesser else {}
    return [
        r
        for r in rows
        if governed(principal, r.get("severity"))
        or governed(principal, raised[str(r.get("finding_id") or "")][0])
    ]


def governed_finding(principal: Principal, row: dict[str, Any]) -> bool:
    """`governed`, at the finding's governing severity."""
    return bool(governed_findings(principal, [row]))


_FINDING_FIELDS = (
    "finding_id", "repo_full_name", "capability", "rule_id", "severity",
    "title", "description", "file_path", "line_start", "package_name",
    "package_version", "first_seen_at", "last_seen_at",
)


def _adapter(subject_ref: str, context: dict[str, Any]) -> Subject:
    """Tier from the finding's own severity, evidence from the lake - never
    from what the requester says about either."""
    from mykronos.dashboard import DashboardQueries

    if context.get("finding_ids"):
        return _cluster_adapter(subject_ref, context)

    status = str(context.get("status") or "")
    if status not in DISPOSITIONS:
        raise ApprovalError(
            f"A finding disposition is one of {', '.join(DISPOSITIONS)}. Accepting the "
            "risk is a risk acceptance: POST /api/risk-acceptances."
        )
    reason = str(context.get("reason") or "").strip()
    problem = rationale_problem(reason)
    if problem:
        raise ApprovalError(problem)
    row = DashboardQueries(_catalog()).finding(subject_ref, include_raw=True)
    if row is None:
        raise ApprovalError(f"No finding {subject_ref}.")
    if row.get("status") != "open":
        raise ApprovalError(f"Finding {subject_ref} is {row.get('status')}, not open.")
    row = {**row, "finding_id": row.get("finding_id") or subject_ref}
    severity, combinations = governing_severity(row)
    if severity not in GOVERNED_SEVERITIES:
        raise ApprovalError(
            f"Finding {subject_ref} is {severity} and in no high or critical toxic "
            "combination; only critical and high dispositions are governed. "
            "Disposition it directly."
        )
    finding = {key: row.get(key) for key in _FINDING_FIELDS}
    # Round-tripped through JSON once, so the bundle stored in the request is
    # byte-for-byte the bundle its digest was computed over: the lake hands
    # back datetimes, which a JSON column will not take as they are.
    evidence = json.loads(
        json.dumps(
            {
                "finding": finding,
                "raw_finding_json": row.get("raw_finding_json"),
                # What closing it would dissolve: why a lesser finding is
                # approved at this tier.
                "combinations": combinations,
                "proposed_status": status,
                "reason": reason,
            },
            default=str,
        )
    )
    return Subject(tier=severity, evidence=evidence)


def _cluster_adapter(subject_ref: str, context: dict[str, Any]) -> Subject:
    """One request for a whole cluster (TheHub #60887).

    A cluster's disposition is one decision, so when any member would need an
    approval the cluster raises one request rather than one per member. The
    tier is the worst governed severity among the members - a cluster holding a
    critical is approved at the critical tier - and the evidence holds every
    member's row and raw record, so the approver sees all of what they are
    closing. Every member must still be open: the approval is for the set in
    the evidence and nothing else.
    """
    from mykronos.dashboard import DashboardQueries

    status = str(context.get("status") or "")
    if status not in DISPOSITIONS:
        raise ApprovalError(
            f"A finding disposition is one of {', '.join(DISPOSITIONS)}. Accepting the "
            "risk is a risk acceptance: POST /api/risk-acceptances."
        )
    reason = str(context.get("reason") or "").strip()
    problem = rationale_problem(reason)
    if problem:
        raise ApprovalError(problem)
    queries = DashboardQueries(_catalog())
    findings: list[dict[str, Any]] = []
    raw: dict[str, Any] = {}
    for finding_id in [str(f) for f in context.get("finding_ids") or []]:
        row = queries.finding(finding_id, include_raw=True)
        if row is None:
            raise ApprovalError(f"No finding {finding_id}.")
        if row.get("status") != "open":
            raise ApprovalError(f"Finding {finding_id} is {row.get('status')}, not open.")
        findings.append({key: row.get(key) for key in _FINDING_FIELDS})
        raw[finding_id] = row.get("raw_finding_json")
    severities: set[str] = set()
    combinations: dict[str, dict[str, str]] = {}
    for severity, combos in governing_severities(findings).values():
        severities.add(severity)
        combinations.update({c["combination_id"]: c for c in combos})
    tier = next((s for s in GOVERNED_SEVERITIES if s in severities), None)
    if tier is None:
        raise ApprovalError(
            f"Cluster {subject_ref} holds no critical or high finding and no member of a "
            "high or critical toxic combination; dispositions of "
            "medium and below are not governed. Disposition it directly."
        )
    evidence = json.loads(
        json.dumps(
            {
                "cluster_id": subject_ref,
                "cluster_reason": str(context.get("cluster_reason") or ""),
                "findings": findings,
                "raw_finding_json": raw,
                "combinations": list(combinations.values()),
                "proposed_status": status,
                "reason": reason,
            },
            default=str,
        )
    )
    return Subject(tier=tier, evidence=evidence)


def on_approved(session: Session, request: ApprovalRequest) -> None:
    """Apply the disposition the approver saw, and only to a finding still open.

    A finding that closed or was dispositioned while the request waited is
    left as it is: the approval was for the state in the evidence."""
    evidence = dict(request.evidence or {})
    status = str(evidence.get("proposed_status") or "")
    if status not in DISPOSITIONS:
        raise ApprovalError(f"Request {request.id} carries no disposition to apply.")
    if evidence.get("findings"):
        _apply_cluster(session, request, evidence, status)
        return
    catalog = _catalog()
    outcome = update_findings(
        catalog,
        locate_findings(catalog, [request.subject_ref]),
        "status = ?, resolved_at = ?, accepted_until = NULL, accepted_reason_code = NULL",
        [status, utcnow()],
        only_if_status="open",
    )
    approver = session.execute(
        select(ApprovalDecision.approver)
        .where(ApprovalDecision.request_id == request.id, ApprovalDecision.verdict == "approve")
        .order_by(ApprovalDecision.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()
    finding = dict(evidence.get("finding") or {})
    # The same action the direct route writes, so every disposition of a
    # finding reads the same way in its history - with the approval beside it.
    session.add(
        AuditLogEntry(
            actor=request.requested_by,
            action="finding.status",
            entity_type="finding",
            entity_id=request.subject_ref,
            detail={
                "repo": finding.get("repo_full_name"),
                "capability": finding.get("capability"),
                "new_status": status,
                "reason": evidence.get("reason"),
                "approval_request_id": request.id,
                "approved_by": approver,
                "applied": bool(outcome.count),
            },
            actor_kind=request.requester_kind,
            actor_provenance=dict(request.requester_provenance or {}),
        )
    )
    if not outcome.count:
        logger.warning(
            "Disposition %s approved but not applied: finding %s is no longer open.",
            request.id,
            request.subject_ref,
        )


def _apply_cluster(
    session: Session, request: ApprovalRequest, evidence: dict[str, Any], status: str
) -> None:
    """Every member the approver saw, each with its own audit entry naming
    the cluster and the approval - the same `finding.status` action the
    single-finding path writes, so a member's history reads the same way."""
    catalog = _catalog()
    approver = session.execute(
        select(ApprovalDecision.approver)
        .where(ApprovalDecision.request_id == request.id, ApprovalDecision.verdict == "approve")
        .order_by(ApprovalDecision.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()
    for finding in evidence.get("findings") or []:
        finding_id = str(finding.get("finding_id") or "")
        outcome = update_findings(
            catalog,
            locate_findings(catalog, [finding_id]),
            "status = ?, resolved_at = ?, accepted_until = NULL, accepted_reason_code = NULL",
            [status, utcnow()],
            only_if_status="open",
        )
        session.add(
            AuditLogEntry(
                actor=request.requested_by,
                action="finding.status",
                entity_type="finding",
                entity_id=finding_id,
                detail={
                    "repo": finding.get("repo_full_name"),
                    "capability": finding.get("capability"),
                    "new_status": status,
                    "reason": evidence.get("reason"),
                    "cluster_id": evidence.get("cluster_id"),
                    "approval_request_id": request.id,
                    "approved_by": approver,
                    "applied": bool(outcome.count),
                },
                actor_kind=request.requester_kind,
                actor_provenance=dict(request.requester_provenance or {}),
            )
        )
        if not outcome.count:
            logger.warning(
                "Cluster disposition %s approved but not applied to %s: no longer open.",
                request.id,
                finding_id,
            )


register_adapter(DUTY, _adapter)
register_on_approved(DUTY, on_approved)
register_dedicated_route(DUTY, ROUTE)
