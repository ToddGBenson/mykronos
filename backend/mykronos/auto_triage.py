"""Deterministic auto-triage: closing what the evidence already closed
(TheHub #60888, D-169).

Todd's decision of 2026-10-22: a verdict that follows from recorded evidence
by a fixed rule may be applied by the platform, with an audit row and a
one-click undo; a model's verdict never is. The classifier in
`patchwork/triage.py` keeps suggesting and never acts, and nothing here reads
it.

**Four lanes, each a rule over evidence the platform already holds.** None of
them infers; each names the record it rests on, and stores a reference to it
on the action.

- `fix_verified` - a Patchwork fix merged, and the scan of its merge commit
  for the finding's capability succeeded without reporting it
  (`remediation_events.verification_outcome = verified_fixed`, spec 25 §1).
  The finding becomes `fixed` without waiting for the second absent scan the
  reconciler needs - unless it has been seen again since, which is a
  regression and is left open.
- `vex_not_affected` - an operator recorded a vendor or VEX `not_affected`
  statement for this advisory and package (`VexStatement`, with its source).
  The finding becomes `suppressed`.
- `exact_duplicate` - somebody (a person, or an agent within #713's limits)
  already dispositioned a finding that is the same decision: the same
  cluster key (`clusters.key_for`, D-168) and, for a package, the same
  version. The finding takes that verdict -
  `false_positive` or `suppressed` only; an acceptance is a governed record
  with a review date (spec 33) and is never copied.
- `unreachable` - the repository's import-graph report
  (`ReachabilityReport`, spec 19 §2.1) lists the finding's Python file as
  orphaned, and every file parsed. The finding becomes `suppressed`. This is
  the only reachability evidence the platform records; nothing else is read
  as reachability.

**Never a serious finding on weak evidence.** A critical or high finding is
closed only by `fix_verified` or `vex_not_affected`: a scan of the fixing
commit, or a vendor's statement. A duplicate verdict or an orphaned file can
quietly close a medium; on a high it waits for a person.

**Undo restores exactly what was there.** Each action stores the finding's
prior status, `resolved_at`, `accepted_until` and `accepted_reason_code`;
`undo` writes them back, guarded on the finding still holding the status the
action set, and audits it. A rule is never re-applied to a finding it was
undone on - otherwise the next sweep would undo the undo - and a finding a
person reopened is left alone.

**Each lane has a kill switch**: `auto_triage.<rule>.enabled` in
`oracle-policy-v1.yaml`. A disabled lane proposes nothing.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from mykronos import clusters
from mykronos.db.models import (
    AuditLogEntry,
    AutoTriageAction,
    ReachabilityReport,
    RepoOnboarding,
    VexStatement,
)
from mykronos.lake.catalog import Catalog
from mykronos.lake.mutate import locate_findings, update_findings
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

FIX_VERIFIED = "fix_verified"
VEX_NOT_AFFECTED = "vex_not_affected"
EXACT_DUPLICATE = "exact_duplicate"
UNREACHABLE = "unreachable"

#: Strongest evidence first: when two lanes match one finding, the action
#: records the one a reader would trust most.
RULES: tuple[str, ...] = (FIX_VERIFIED, VEX_NOT_AFFECTED, EXACT_DUPLICATE, UNREACHABLE)

#: Severities closed only on a verified fix or a vendor statement.
SERIOUS: tuple[str, ...] = ("critical", "high")
#: The evidence that may close a serious finding.
SERIOUS_EVIDENCE: frozenset[str] = frozenset({FIX_VERIFIED, VEX_NOT_AFFECTED})

#: The verdicts `exact_duplicate` copies. Not `accepted_risk`.
COPYABLE: tuple[str, ...] = ("false_positive", "suppressed")

#: Who the audit log says acted.
ACTOR = "auto-triage"

_OPEN_COLUMNS = (
    "finding_id",
    "repo_full_name",
    "capability",
    "rule_id",
    "title",
    "severity",
    "file_path",
    "line_start",
    "symbol",
    "cwe_ids_json",
    "package_name",
    "package_version",
    "image",
    "status",
    "resolved_at",
    "accepted_until",
    "accepted_reason_code",
    "last_seen_scan_run_id",
    "last_seen_at",
)
_SELECT = {"image": "json_extract_string(raw_finding_json, '$.image') AS image"}


@dataclass(frozen=True)
class Proposal:
    """One action a sweep would take, with what it rests on."""

    finding_id: str
    repo_full_name: str
    capability: str
    severity: str
    rule: str
    new_status: str
    evidence: dict[str, Any]
    summary: str
    prior: dict[str, Any]


@dataclass
class SweepResult:
    proposals: list[Proposal] = field(default_factory=list)
    applied: list[str] = field(default_factory=list)
    #: Rule -> how many findings it matched while switched off.
    disabled: dict[str, int] = field(default_factory=dict)
    #: Serious findings a weak-evidence lane matched and left for a person.
    held_serious: int = 0
    dry_run: bool = False

    def summary(self) -> str:
        return (
            f"{len(self.applied)} applied of {len(self.proposals)} proposed, "
            f"{self.held_serious} serious left for a person, disabled: {self.disabled or 'none'}"
        )


class AutoTriageError(ValueError):
    """An undo the state refuses. The message says why."""


def _rows(catalog: Catalog, where: str, params: list[Any]) -> list[dict[str, Any]]:
    if not catalog.all_files("findings"):
        return []
    projection = ", ".join(_SELECT.get(c, c) for c in _OPEN_COLUMNS)
    found = catalog.query(f"SELECT {projection} FROM findings WHERE {where}", params)
    return [dict(zip(_OPEN_COLUMNS, row, strict=True)) for row in found]


def _active_repos(session: Session) -> dict[str, str]:
    """repo_full_name -> onboarding id, for active repositories."""
    return {
        str(row.github_repo_full_name): str(row.id)
        for row in session.execute(
            select(RepoOnboarding).where(RepoOnboarding.status == "active")
        ).scalars()
    }


def _prior(row: Mapping[str, Any]) -> dict[str, Any]:
    """The state an undo writes back, JSON-safe."""
    state: dict[str, Any] = json.loads(
        json.dumps(
            {
                "status": row.get("status"),
                "resolved_at": row.get("resolved_at"),
                "accepted_until": row.get("accepted_until"),
                "accepted_reason_code": row.get("accepted_reason_code"),
            },
            default=lambda v: v.isoformat(),
        )
    )
    return state


# --------------------------------------------------------------------------
# Evidence, one reader per lane
# --------------------------------------------------------------------------


def _verified_fixes(catalog: Catalog) -> dict[str, dict[str, Any]]:
    """finding_id -> the newest merged fix whose verifying scan did not see it."""
    if not catalog.all_files("remediation_events"):
        return {}
    names = (
        "event_id", "finding_id", "fix_pr_number", "fix_pr_url",
        "verification_commit_sha", "verification_scan_run_id", "verified_at",
    )
    rows = catalog.query(
        f"SELECT {', '.join(names)} FROM remediation_events "
        "WHERE verification_outcome = 'verified_fixed' AND pr_status = 'merged' "
        "AND finding_id IS NOT NULL",
    )
    found: dict[str, dict[str, Any]] = {}
    for row in rows:
        event = dict(zip(names, row, strict=True))
        finding_id = str(event["finding_id"])
        current = found.get(finding_id)
        if current is None or (event["verified_at"] or datetime.min) > (
            current["verified_at"] or datetime.min
        ):
            found[finding_id] = event
    return found


def _vex_statements(session: Session) -> list[VexStatement]:
    return list(
        session.execute(
            select(VexStatement).where(
                VexStatement.status == "not_affected", VexStatement.revoked_at.is_(None)
            )
        ).scalars()
    )


def _vex_match(row: Mapping[str, Any], statements: Iterable[VexStatement]) -> VexStatement | None:
    package = str(row.get("package_name") or "").strip().lower()
    if not package:
        return None
    advisory = clusters.advisory_of(row)
    for statement in statements:
        if statement.vulnerability_id.strip().upper() != advisory:
            continue
        if statement.package_name.strip().lower() != package:
            continue
        if statement.package_version and statement.package_version != str(
            row.get("package_version") or ""
        ):
            continue
        if statement.repo_full_name and statement.repo_full_name != row.get("repo_full_name"):
            continue
        return statement
    return None


def _duplicate_key(row: Mapping[str, Any]) -> tuple[str, ...] | None:
    """What "exactly the same decision" means: the cluster key, plus the
    version for a package. `single` findings have no duplicates."""
    key = clusters.key_for(row)
    if key.kind == clusters.SINGLE:
        return None
    if key.kind == clusters.ADVISORY:
        version = str(row.get("package_version") or "")
        if not version:
            return None
        return (key.kind, *key.parts, version)
    return (key.kind, *key.parts)


def _precedents(catalog: Catalog, auto_closed: set[str]) -> dict[tuple[str, ...], dict[str, Any]]:
    """Duplicate key -> the newest verdict with that key that this module did
    not make.

    A verdict this module set is not a precedent: a chain of copies would
    let one human decision spread further with every sweep, each step one
    more remove from anybody having looked.
    """
    statuses = ", ".join("?" for _ in COPYABLE)
    rows = _rows(catalog, f"status IN ({statuses})", list(COPYABLE))
    best: dict[tuple[str, ...], dict[str, Any]] = {}
    for row in rows:
        if str(row["finding_id"]) in auto_closed:
            continue
        key = _duplicate_key(row)
        if key is None:
            continue
        current = best.get(key)
        if current is None or (row.get("resolved_at") or datetime.min) > (
            current.get("resolved_at") or datetime.min
        ):
            best[key] = row
    return best


def _orphaned(
    session: Session, repos: Mapping[str, str]
) -> dict[str, tuple[ReachabilityReport, set[str]]]:
    """repo_full_name -> its report and orphaned paths, where every file parsed."""
    by_id = {onboarding_id: repo for repo, onboarding_id in repos.items()}
    found: dict[str, tuple[ReachabilityReport, set[str]]] = {}
    for report in session.execute(select(ReachabilityReport)).scalars():
        repo = by_id.get(str(report.repo_onboarding_id))
        if repo is None or report.files_unparseable:
            continue
        paths = {clusters.normalise_path(p) for p in report.orphaned_paths or []}
        if paths:
            found[repo] = (report, paths)
    return found


# --------------------------------------------------------------------------
# Proposing
# --------------------------------------------------------------------------


def propose(
    catalog: Catalog, session: Session, enabled: Mapping[str, bool]
) -> SweepResult:
    """Every action the evidence supports now. Writes nothing."""
    result = SweepResult()
    repos = _active_repos(session)
    if not repos:
        return result
    placeholders = ", ".join("?" for _ in repos)
    open_rows = _rows(
        catalog, f"status = 'open' AND repo_full_name IN ({placeholders})", list(repos)
    )
    if not open_rows:
        return result

    history = session.execute(select(AutoTriageAction)).scalars().all()
    tried = {(a.finding_id, a.rule) for a in history}
    auto_closed = {a.finding_id for a in history if a.undone_at is None}
    reopened = set(
        session.execute(
            select(AuditLogEntry.entity_id).where(AuditLogEntry.action == "finding.reopened")
        ).scalars()
    )

    fixes = _verified_fixes(catalog)
    statements = _vex_statements(session)
    precedents = _precedents(catalog, auto_closed)
    orphaned = _orphaned(session, repos)

    for row in open_rows:
        finding_id = str(row["finding_id"])
        if finding_id in reopened:
            continue
        severity = str(row.get("severity") or "").lower()
        held = False
        for rule in RULES:
            if (finding_id, rule) in tried:
                continue
            match = _match(rule, row, fixes, statements, precedents, orphaned)
            if match is None:
                continue
            if severity in SERIOUS and rule not in SERIOUS_EVIDENCE:
                held = True
                continue
            if not enabled.get(rule, False):
                result.disabled[rule] = result.disabled.get(rule, 0) + 1
                continue
            new_status, evidence, summary = match
            result.proposals.append(
                Proposal(
                    finding_id=finding_id,
                    repo_full_name=str(row.get("repo_full_name") or ""),
                    capability=str(row.get("capability") or ""),
                    severity=severity,
                    rule=rule,
                    new_status=new_status,
                    evidence=json.loads(json.dumps(evidence, default=str)),
                    summary=summary,
                    prior=_prior(row),
                )
            )
            held = False
            break
        if held:
            result.held_serious += 1
    return result


def _match(
    rule: str,
    row: Mapping[str, Any],
    fixes: Mapping[str, dict[str, Any]],
    statements: list[VexStatement],
    precedents: Mapping[tuple[str, ...], dict[str, Any]],
    orphaned: Mapping[str, tuple[ReachabilityReport, set[str]]],
) -> tuple[str, dict[str, Any], str] | None:
    finding_id = str(row["finding_id"])
    if rule == FIX_VERIFIED:
        event = fixes.get(finding_id)
        if event is None:
            return None
        if str(row.get("last_seen_scan_run_id") or "") == str(
            event.get("verification_scan_run_id") or ""
        ):
            return None
        verified_at = event.get("verified_at")
        last_seen = row.get("last_seen_at")
        if verified_at is not None and last_seen is not None and last_seen > verified_at:
            # Reported again after the verifying scan: a regression, not a fix.
            return None
        commit = str(event.get("verification_commit_sha") or "")
        return (
            "fixed",
            {
                "type": "remediation_event",
                "ref": event["event_id"],
                "fix_pr_number": event.get("fix_pr_number"),
                "fix_pr_url": event.get("fix_pr_url"),
                "commit_sha": commit,
                "scan_run_id": event.get("verification_scan_run_id"),
                "verified_at": verified_at,
            },
            f"Fix PR #{event.get('fix_pr_number')} merged; the scan of {commit[:12]} "
            "no longer reports it.",
        )
    if rule == VEX_NOT_AFFECTED:
        statement = _vex_match(row, statements)
        if statement is None:
            return None
        return (
            "suppressed",
            {
                "type": "vex_statement",
                "ref": statement.id,
                "vulnerability_id": statement.vulnerability_id,
                "package_name": statement.package_name,
                "package_version": statement.package_version,
                "justification": statement.justification,
                "source": statement.source,
            },
            f"{statement.source_kind.capitalize()} statement: {statement.vulnerability_id} "
            f"not_affected in {statement.package_name} ({statement.justification}); "
            f"source {statement.source}.",
        )
    if rule == EXACT_DUPLICATE:
        key = _duplicate_key(row)
        precedent = precedents.get(key) if key else None
        if precedent is None or str(precedent["finding_id"]) == finding_id:
            return None
        cluster_id = clusters.key_for(row).cluster_id
        return (
            str(precedent["status"]),
            {
                "type": "precedent_finding",
                "ref": precedent["finding_id"],
                "precedent_status": precedent["status"],
                "precedent_repo": precedent.get("repo_full_name"),
                "decided_at": precedent.get("resolved_at"),
                "cluster_id": cluster_id,
            },
            f"Exact duplicate of {precedent['finding_id']} in "
            f"{precedent.get('repo_full_name')}, already {precedent['status']} by a decision "
            f"auto-triage did not make (cluster {cluster_id}).",
        )
    if rule == UNREACHABLE:
        if row.get("package_name"):
            return None
        path = clusters.normalise_path(row.get("file_path"))
        if not path.endswith(".py"):
            return None
        entry = orphaned.get(str(row.get("repo_full_name") or ""))
        if entry is None or path not in entry[1]:
            return None
        report = entry[0]
        return (
            "suppressed",
            {
                "type": "reachability_report",
                "ref": report.id,
                "language": report.language,
                "commit_sha": report.commit_sha,
                "files_analysed": report.files_analysed,
                "path": path,
            },
            f"{path} is imported by nothing in the repository and is not an entry point "
            f"(import graph at {str(report.commit_sha)[:12] or 'unknown commit'}, "
            f"{report.files_analysed} files, all parsed).",
        )
    return None


# --------------------------------------------------------------------------
# Applying and undoing
# --------------------------------------------------------------------------


def _statuses(catalog: Catalog, finding_ids: list[str]) -> dict[str, str]:
    """Each finding's status now."""
    if not finding_ids:
        return {}
    placeholders = ", ".join("?" for _ in finding_ids)
    rows = catalog.query(
        f"SELECT finding_id, status FROM findings WHERE finding_id IN ({placeholders})",
        list(finding_ids),
    )
    return {str(r[0]): str(r[1]) for r in rows}


def apply(db: Any, catalog: Catalog, result: SweepResult, now: datetime | None = None) -> None:
    """Write every proposal: the lake first, guarded on `open`, then one
    action row and one audit entry per finding actually changed."""
    moment = now or utcnow()
    by_status: dict[str, list[Proposal]] = {}
    for proposal in result.proposals:
        by_status.setdefault(proposal.new_status, []).append(proposal)
    for new_status, proposals in by_status.items():
        before = _statuses(catalog, [p.finding_id for p in proposals])
        ids = [p.finding_id for p in proposals if before.get(p.finding_id) == "open"]
        if not ids:
            continue
        # `updated` names only the rows the `open` guard let through (TheHub
        # #60926), so a finding closed between the read and the write gets no
        # action row and no audit entry claiming a change that did not happen.
        changed = set(
            update_findings(
                catalog,
                locate_findings(catalog, ids),
                "status = ?, resolved_at = ?, accepted_until = NULL, accepted_reason_code = NULL",
                [new_status, moment],
                only_if_status="open",
            ).updated
        )
        with db.session() as session:
            for proposal in proposals:
                if proposal.finding_id not in changed:
                    continue
                action = AutoTriageAction(
                    finding_id=proposal.finding_id,
                    repo_full_name=proposal.repo_full_name,
                    capability=proposal.capability,
                    severity=proposal.severity,
                    rule=proposal.rule,
                    new_status=proposal.new_status,
                    evidence=proposal.evidence,
                    summary=proposal.summary,
                    prior_state=proposal.prior,
                    applied_at=moment,
                )
                session.add(action)
                session.flush()
                session.add(
                    AuditLogEntry(
                        actor=ACTOR,
                        action="finding.auto_triage",
                        entity_type="finding",
                        entity_id=proposal.finding_id,
                        detail={
                            "repo": proposal.repo_full_name,
                            "capability": proposal.capability,
                            "new_status": proposal.new_status,
                            "rule": proposal.rule,
                            "evidence": proposal.evidence,
                            "reason": proposal.summary,
                            "prior_state": proposal.prior,
                            "auto_triage_action_id": action.id,
                        },
                        actor_kind="automation",
                        created_at=moment,
                    )
                )
                result.applied.append(action.id)


def sweep(
    db: Any,
    catalog: Catalog,
    enabled: Mapping[str, bool],
    *,
    dry_run: bool = False,
    now: datetime | None = None,
) -> SweepResult:
    with db.session() as session:
        result = propose(catalog, session, enabled)
    result.dry_run = dry_run
    if not dry_run and result.proposals:
        apply(db, catalog, result, now)
    if result.applied or result.held_serious:
        logger.info("Auto-triage: %s", result.summary())
    return result


def _parse_moment(value: Any) -> Any:
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return value
    return value


def undo(
    db: Any, catalog: Catalog, action_id: str, *, actor: str, reason: str
) -> AutoTriageAction:
    """Put the finding back exactly as the action found it, and say so."""
    with db.session() as session:
        action = session.get(AutoTriageAction, action_id)
        if action is None:
            raise LookupError(f"No auto-triage action {action_id}.")
        if action.undone_at is not None:
            raise AutoTriageError(
                f"Action {action_id} was already undone by {action.undone_by} at "
                f"{action.undone_at.isoformat()}."
            )
        prior = dict(action.prior_state or {})
        finding_id = action.finding_id
        new_status = action.new_status

    if _statuses(catalog, [finding_id]).get(finding_id) != new_status:
        raise AutoTriageError(
            f"Finding {finding_id} is no longer {new_status}, so this action has nothing "
            "to undo: someone or something changed it since."
        )
    restored = str(prior.get("status") or "open")
    accepted_until = _parse_moment(prior.get("accepted_until"))
    if isinstance(accepted_until, datetime):
        accepted_until = accepted_until.date()
    outcome = update_findings(
        catalog,
        locate_findings(catalog, [finding_id]),
        "status = ?, resolved_at = ?, accepted_until = ?, accepted_reason_code = ?",
        [
            restored,
            _parse_moment(prior.get("resolved_at")),
            accepted_until,
            prior.get("accepted_reason_code"),
        ],
        only_if_status=new_status,
    )
    if not outcome.count:
        raise AutoTriageError(
            f"Finding {finding_id} changed while it was being restored; nothing was undone."
        )
    moment = utcnow()
    with db.session() as session:
        undone: AutoTriageAction | None = session.get(AutoTriageAction, action_id)
        if undone is None:  # pragma: no cover - read a moment ago, never deleted
            raise LookupError(f"No auto-triage action {action_id}.")
        action = undone
        action.undone_at = moment
        action.undone_by = actor
        action.undo_reason = reason
        db.audit(
            session,
            actor=actor,
            action="finding.auto_triage_undone",
            entity_type="finding",
            entity_id=finding_id,
            repo=action.repo_full_name,
            capability=action.capability,
            rule=action.rule,
            auto_triage_action_id=action_id,
            restored_state=prior,
            reason=reason,
        )
        session.flush()
        session.expunge(action)
        return action


def recent(session: Session, since: datetime) -> list[AutoTriageAction]:
    return list(
        session.execute(
            select(AutoTriageAction)
            .where(AutoTriageAction.applied_at >= since)
            .order_by(AutoTriageAction.applied_at.desc())
        ).scalars()
    )


def digest(session: Session, *, hours: int = 24, now: datetime | None = None) -> dict[str, Any]:
    """What the platform closed by itself in the window, by lane."""
    moment = now or utcnow()
    since = moment - timedelta(hours=hours)
    actions = recent(session, since)
    by_rule: dict[str, int] = {}
    for action in actions:
        by_rule[action.rule] = by_rule.get(action.rule, 0) + 1
    return {
        "since": since,
        "hours": hours,
        "total": len(actions),
        "undone": sum(1 for a in actions if a.undone_at is not None),
        "by_rule": by_rule,
        "actions": actions,
    }
