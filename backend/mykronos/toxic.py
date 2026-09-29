"""Toxic combinations, as one answer every surface shares (spec 08 §5).

`patchwork.correlate` finds the combinations. This module decides what one
*means*, once, for the three places that report it: the Oracle's risk
decision, the briefing, and the estate-wide API. Before it, each caller
re-ran detection over its own slice of findings and described the result its
own way, and the risk decision did not look at all.

Three decisions are made here, and made here only:

**Accepted findings still count.** Detection runs over `open` and
`accepted_risk` findings (operator decision, 2026-09-28). An acceptance is a
decision about one finding judged alone; accepting half of a toxic pair must
not make the pair disappear. A combination with an accepted member is
reported `partly_accepted`, not dropped.

**A combination is worse than its worst member.** Its severity is the worst
member's raised by `escalate_steps` bands (default one), and `critical` when
any member names a KEV-listed CVE. Reporting the worst member's severity -
what the dashboard did - says two medium findings that together make an
unauthenticated database are "medium", which is the opposite of the point.

**Coverage is part of the answer.** A rule whose inputs never reach the lake
(network, cloud) cannot fire, and "no combinations" from it is not evidence
of safety. `coverage()` names those rules so every surface can say so.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from mykronos.lake import Catalog
from mykronos.patchwork import correlate
from mykronos.patchwork.pipeline import DEFAULT_CORRELATION_CAPABILITIES
from mykronos.threat_intel import extract_cve

SEVERITIES = ("info", "low", "medium", "high", "critical")

#: Statuses detection runs over. `accepted_risk` on purpose: see the module doc.
STATUSES = ("open", "accepted_risk")

_COLUMNS = (
    "finding_id",
    "repo_full_name",
    "capability",
    "rule_id",
    "title",
    "severity",
    "file_path",
    "status",
)


@dataclass(frozen=True)
class ToxicCombination:
    repo_full_name: str
    combination_id: str
    rule_id: str
    name: str
    severity: str
    member_severity: str  # the worst member's, before escalation
    kev_cves: tuple[str, ...]
    partly_accepted: bool
    rationale: str
    members: tuple[dict[str, Any], ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "repo_full_name": self.repo_full_name,
            "combination_id": self.combination_id,
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": self.severity,
            "member_severity": self.member_severity,
            "kev_cves": list(self.kev_cves),
            "partly_accepted": self.partly_accepted,
            "rationale": self.rationale,
            "members": [dict(m) for m in self.members],
        }


def escalate(severity: str, steps: int) -> str:
    """`severity` raised `steps` bands, never past critical."""
    try:
        index = SEVERITIES.index(severity)
    except ValueError:
        index = 0
    return SEVERITIES[min(index + max(steps, 0), len(SEVERITIES) - 1)]


def combination_severity(member_severities: list[str], *, kev: bool, escalate_steps: int) -> str:
    worst = "info"
    for s in member_severities:
        if s in SEVERITIES and SEVERITIES.index(s) > SEVERITIES.index(worst):
            worst = s
    return "critical" if kev else escalate(worst, escalate_steps)


def _pool(catalog: Catalog, repo: str | None) -> list[dict[str, Any]]:
    if not catalog.all_files("findings"):
        return []
    caps = sorted(DEFAULT_CORRELATION_CAPABILITIES)
    params: list[Any] = [*STATUSES, *caps]
    where = (
        f"status IN ({', '.join('?' for _ in STATUSES)}) "
        f"AND capability IN ({', '.join('?' for _ in caps)})"
    )
    if repo is not None:
        where += " AND repo_full_name = ?"
        params.append(repo)
    rows = catalog.query(
        "SELECT finding_id, repo_full_name, capability, rule_id, coalesce(title, ''), "
        "lower(severity), file_path, status "
        f"FROM findings WHERE {where}",
        params,
    )
    return [dict(zip(_COLUMNS, row, strict=True)) for row in rows]


def _kev_ids(session: Session | None, findings: list[dict[str, Any]]) -> set[str]:
    if session is None:
        return set()
    from mykronos.db.models import ThreatIntelMatch

    cves = {
        extract_cve(str(f.get("rule_id") or ""), str(f.get("title") or "")) for f in findings
    }
    cves.discard(None)
    if not cves:
        return set()
    return {
        str(c)
        for c in session.execute(
            select(ThreatIntelMatch.cve_id).where(
                ThreatIntelMatch.cve_id.in_(cves), ThreatIntelMatch.in_kev.is_(True)
            )
        ).scalars()
    }


def detect(
    catalog: Catalog,
    *,
    repo: str | None = None,
    session: Session | None = None,
    escalate_steps: int = 1,
) -> list[ToxicCombination]:
    """Every toxic combination, for one repository or the whole estate.

    Detection is per repository, as `correlate.detect` expects: a DAST finding
    in one service and a SAST finding in another are not a combination.
    """
    by_repo: dict[str, list[dict[str, Any]]] = {}
    for finding in _pool(catalog, repo):
        by_repo.setdefault(str(finding["repo_full_name"]), []).append(finding)

    rules = {r.rule_id: r for r in correlate.BUILT_IN_RULES}
    out: list[ToxicCombination] = []
    for repo_name, pool in sorted(by_repo.items()):
        by_id = {str(f["finding_id"]): f for f in pool}
        for combo in correlate.detect(pool):
            members = [by_id[fid] for fid in sorted(combo.finding_ids) if fid in by_id]
            kev = _kev_ids(session, members)
            member_kev = sorted(
                c
                for m in members
                if (c := extract_cve(str(m.get("rule_id") or ""), str(m.get("title") or "")))
                and c in kev
            )
            severities = [str(m["severity"]) for m in members]
            worst = combination_severity(severities, kev=False, escalate_steps=0)
            rule = rules.get(combo.rule_id)
            out.append(
                ToxicCombination(
                    repo_full_name=repo_name,
                    combination_id=combo.combination_id,
                    rule_id=combo.rule_id,
                    name=rule.name if rule else combo.rule_id,
                    severity=combination_severity(
                        severities, kev=bool(member_kev), escalate_steps=escalate_steps
                    ),
                    member_severity=worst,
                    kev_cves=tuple(member_kev),
                    partly_accepted=any(m["status"] == "accepted_risk" for m in members),
                    rationale=combo.rationale,
                    members=tuple(
                        {
                            "finding_id": str(m["finding_id"]),
                            "capability": str(m["capability"]),
                            "rule_id": str(m["rule_id"]),
                            "title": str(m["title"]),
                            "severity": str(m["severity"]),
                            "status": str(m["status"]),
                            "file_path": m.get("file_path"),
                        }
                        for m in members
                    ),
                )
            )
    return out


def coverage(catalog: Catalog) -> dict[str, Any]:
    """Which rules can fire on the data the lake actually holds.

    A rule needs, for each requirement, at least one finding of an allowed
    capability somewhere in the lake. One that cannot be met reports nothing,
    whatever is true of the estate - and must not be read as a clean result.
    """
    present: set[str] = set()
    if catalog.all_files("findings"):
        present = {str(r[0]) for r in catalog.query("SELECT DISTINCT capability FROM findings")}
    live: list[dict[str, Any]] = []
    dark: list[dict[str, Any]] = []
    for rule in correlate.BUILT_IN_RULES:
        missing = sorted(
            {
                cap
                for req in rule.requires
                if req.capabilities and not (set(req.capabilities) & present)
                for cap in req.capabilities
            }
        )
        entry = {"rule_id": rule.rule_id, "name": rule.name, "missing": missing}
        (dark if missing else live).append(entry)
    return {"rules": len(correlate.BUILT_IN_RULES), "can_fire": live, "cannot_fire": dark}
