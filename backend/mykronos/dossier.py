"""The investigation dossier for one finding (TheHub #60893, Triage T6).

What somebody reads before deciding: where it is, who owns it, what has
happened to it, how the same rule was decided elsewhere, the cluster it
belongs to, and what a model proposed in shadow with how that model has
graded so far. Assembled from records that already exist; nothing here is a
new judgement, and nothing here changes a finding.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from mykronos import shadow_proposals
from mykronos.db.models import (
    AuditLogEntry,
    AutoTriageAction,
    ModelTriageProposal,
    RepoOnboarding,
)
from mykronos.schemas import asset_label
from mykronos.threat_intel import extract_cve

#: Human dispositions a precedent can carry.
DISPOSED = ("false_positive", "accepted_risk", "suppressed")
SIMILAR_LISTED = 10
HISTORY_LISTED = 50


def location(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "repo_full_name": str(row.get("repo_full_name") or ""),
        "capability": str(row.get("capability") or ""),
        "file_path": row.get("file_path") or None,
        "line_start": row.get("line_start"),
        "line_end": row.get("line_end"),
        "symbol": row.get("symbol") or None,
        "package_name": row.get("package_name") or None,
        "package_version": row.get("package_version") or None,
        "asset": asset_label(row.get("address"), row.get("port")),
    }


def history(session: Session, row: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Oldest first: the lake's own dates, then every audit entry and
    auto-triage action that names this finding."""
    finding_id = str(row.get("finding_id") or "")
    events: list[dict[str, Any]] = []
    for key, label in (("first_seen_at", "first seen"), ("last_seen_at", "last seen")):
        when = row.get(key)
        if isinstance(when, datetime):
            events.append({"at": when, "event": label, "actor": "scanner", "detail": ""})
    if isinstance(row.get("resolved_at"), datetime):
        events.append(
            {
                "at": row["resolved_at"],
                "event": f"status {row.get('status')}",
                "actor": "",
                "detail": "the finding's current status",
            }
        )
    # The newest entries when there are more than are listed: the latest
    # decision is the one an investigator needs. Sorted oldest first below.
    for entry in session.scalars(
        select(AuditLogEntry)
        .where(AuditLogEntry.entity_id == finding_id)
        .order_by(AuditLogEntry.created_at.desc())
        .limit(HISTORY_LISTED)
    ):
        detail = entry.detail or {}
        words = [
            f"{k}={detail[k]}"
            for k in ("new_status", "reason", "cluster_id")
            if detail.get(k)
        ]
        events.append(
            {
                "at": entry.created_at,
                "event": entry.action,
                "actor": f"{entry.actor} ({entry.actor_kind or 'unattributed'})",
                "detail": "; ".join(words),
            }
        )
    for action in session.scalars(
        select(AutoTriageAction).where(AutoTriageAction.finding_id == finding_id)
    ):
        events.append(
            {
                "at": action.applied_at,
                "event": f"auto-triage {action.rule}",
                "actor": "automation",
                "detail": action.summary
                + (f" (undone by {action.undone_by})" if action.undone_at else ""),
            }
        )
    events.sort(key=lambda e: e["at"])
    return events


def similar(
    catalog: Any, session: Session, row: Mapping[str, Any]
) -> list[dict[str, Any]]:
    """How the same rule or advisory was decided on other findings, newest
    first, with the reason a person gave where one was recorded."""
    finding_id = str(row.get("finding_id") or "")
    rule_id = str(row.get("rule_id") or "")
    cve = extract_cve(rule_id, str(row.get("title") or ""))
    if not rule_id and not cve:
        return []
    statuses = ", ".join(f"'{s}'" for s in DISPOSED)
    # An empty rule id would match every disposed finding that has none.
    clauses: list[str] = ["rule_id = ?"] if rule_id else []
    params: list[Any] = [rule_id] if rule_id else []
    if cve:
        clauses.append("upper(title) LIKE ?")
        params.append(f"%{cve}%")
    rows = catalog.query(
        "SELECT finding_id, repo_full_name, capability, status, resolved_at, "
        "accepted_reason_code, file_path, package_name "
        f"FROM findings WHERE status IN ({statuses}) AND finding_id <> ? "
        f"AND ({' OR '.join(clauses)}) "
        "ORDER BY resolved_at DESC NULLS LAST LIMIT ?",
        [finding_id, *params, SIMILAR_LISTED],
    )
    ids = [str(r[0]) for r in rows]
    reasons: dict[str, tuple[str, str]] = {}
    if ids:
        for entry in session.scalars(
            select(AuditLogEntry)
            .where(AuditLogEntry.action == "finding.status", AuditLogEntry.entity_id.in_(ids))
            .order_by(AuditLogEntry.created_at)
        ):
            reasons[entry.entity_id] = (
                str((entry.detail or {}).get("reason") or ""),
                f"{entry.actor} ({entry.actor_kind or 'unattributed'})",
            )
    # The record page's route takes a repository's onboarding id, and a
    # precedent is often in another repository than the page it is shown on.
    names = {str(r[1]) for r in rows if r[1]}
    repo_ids = (
        {
            str(name): str(repo_id)
            for name, repo_id in session.execute(
                select(RepoOnboarding.github_repo_full_name, RepoOnboarding.id).where(
                    RepoOnboarding.github_repo_full_name.in_(names)
                )
            )
        }
        if names
        else {}
    )
    out = []
    for fid, repo, capability, status, resolved_at, code, path, package in rows:
        reason, actor = reasons.get(str(fid), ("", ""))
        out.append(
            {
                "finding_id": str(fid),
                "repo_full_name": str(repo or ""),
                "repo_id": repo_ids.get(str(repo or "")),
                "capability": str(capability or ""),
                "status": str(status),
                "resolved_at": resolved_at if isinstance(resolved_at, datetime) else None,
                "accepted_reason_code": code or None,
                "where": path or package or None,
                "reason": reason or None,
                "decided_by": actor or None,
            }
        )
    return out


def proposals(session: Session, catalog: Any, finding_id: str) -> list[dict[str, Any]]:
    """Every shadow proposal on this finding, newest first, each graded."""
    rows = list(
        session.scalars(
            select(ModelTriageProposal)
            .where(ModelTriageProposal.finding_id == finding_id)
            .order_by(ModelTriageProposal.created_at.desc())
        )
    )
    verdicts = shadow_proposals.human_verdicts(session, [finding_id]).get(finding_id, [])
    fixed = shadow_proposals.fixed_times(catalog, [finding_id]).get(finding_id)
    out = []
    for p in rows:
        out.append(
            {
                "id": p.id,
                "model": p.model,
                "proposed_status": p.proposed_status,
                "confidence": p.confidence,
                "rationale": p.rationale,
                "evidence": p.evidence or {},
                "proposed_by": p.proposed_by,
                "created_at": p.created_at,
                "applied": False,
                **shadow_proposals.grade_one(p, verdicts, fixed),
            }
        )
    return out
