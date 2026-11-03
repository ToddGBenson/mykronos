"""Toxic combinations, as one answer every surface shares (spec 08 §5).

`patchwork.correlate` finds the combinations. This module decides what one
*means*, once, for the three places that report it: the Oracle's risk
decision, the briefing, and the estate-wide API. Before it, each caller
re-ran detection over its own slice of findings and described the result its
own way, and the risk decision did not look at all.

Three decisions are made here, and made here only:

**A false positive stops counting; an acceptance dissolves only what it saw.**
A member dispositioned `false_positive` no longer satisfies its half (TheHub
#60965). An `accepted_risk` member suppresses a combination only when that
combination - by `combination_id`, its rule and exact members - is in the
evidence frozen into the approval of a live acceptance covering the member:
the approver saw the pair and accepted anyway (TheHub #61013). A combination
that formed after the acceptance is evidence against its premise (usually
"not reachable"), so it forms, names the acceptances that did not know of it
in `unanticipated_acceptances`, and the premise monitor moves those to
`premise_failed` for re-decision. Under #1018 alone, an acceptance made
before the combination existed dissolved it silently.

Fails closed: an acceptance with no readable frozen evidence (a direct
disposition with no record, a record proposed before the evidence block, no
database session) covers no combination. A combination is suppressed only
when every accepted member is covered. When one is, the open findings it
claimed are detected again on their own, so a suppressed pair never hides an
all-open one. `partly_accepted` says a formed combination has an accepted
member. `detect(suppress=False)` is the view an approver signs: every
combination, accepted members counting, nothing suppressed.

**A combination is worse than its worst member.** Its severity is the worst
member's raised by `escalate_steps` bands (default one), and `critical` when
any member names a KEV-listed CVE. Reporting the worst member's severity -
what the dashboard did - says two medium findings that together make an
unauthenticated database are "medium", which is the opposite of the point.

**Coverage is part of the answer.** A rule whose inputs never reach the lake
(network, cloud) cannot fire, and "no combinations" from it is not evidence
of safety. `coverage()` names those rules so every surface can say so.

**A chain is scoped by the threat model** (TheHub #60894, Triage T7). The
entry-point rules (`correlate.ENTRY_POINT_CHAIN_RULES`) group findings by the
declared internet-facing entry point `surface_match` places them in, rather
than by file or repository, and are checked first. A combination they form
carries `chain`: the entry point as declared (name, exposure, where it was
declared and its evidence reference), then each link - the finding, the
selector that placed it behind that entry point, and why it qualifies. The
entry point is declared, never observed, and the chain says so. With no
session there is no threat model to read, so only the built-in rules run;
`coverage()` then names the chain rules as unable to fire.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from mykronos import risk_evidence, surface_match
from mykronos.db.models import ApprovalRequest, RepoSurface, RiskAcceptance
from mykronos.lake import Catalog
from mykronos.patchwork import correlate
from mykronos.patchwork.pipeline import DEFAULT_CORRELATION_CAPABILITIES
from mykronos.threat_intel import extract_cve

SEVERITIES = ("info", "low", "medium", "high", "critical")

#: Statuses detection runs over: see the module doc (TheHub #60965, #61013).
#: `accepted_risk` members count, and their combinations are then suppressed
#: or not by the acceptance's frozen evidence.
STATUSES = ("open", "accepted_risk")

#: An accepted member's coverage: finding id -> (live acceptance id, the
#: combination ids its approver was shown) for each live acceptance covering it.
Coverage = dict[str, list[tuple[str, frozenset[str]]]]

_COLUMNS = (
    "finding_id",
    "repo_full_name",
    "capability",
    "rule_id",
    "title",
    "severity",
    "file_path",
    "status",
    "cwe_ids_json",
    "image",
    "uri",
)

#: Every rule detection runs, in the order it runs them: a chain claims its
#: members before a file- or repository-scoped pair can.
RULES: tuple[correlate.CombinationRule, ...] = (
    correlate.ENTRY_POINT_CHAIN_RULES + correlate.BUILT_IN_RULES
)

#: What a chain rule needs beyond findings, as `coverage()` names it.
NEEDS_ENTRY_POINT = "internet-facing entry point"

#: Set on a pool row by `_locate`: entry point id -> the selector that placed
#: the finding there. Private to this module; never leaves it.
_LOCATED_BY = "_entry_point_selectors"


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
    #: Live acceptances covering an accepted member whose frozen evidence does
    #: not name this combination: it formed after they were approved, which
    #: fails their premise (TheHub #61013, `premise_monitor`).
    unanticipated_acceptances: tuple[str, ...] = ()
    #: For an entry-point chain (TheHub #60894): the declared entry point and
    #: each link in order. None for every other combination.
    chain: dict[str, Any] | None = None

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
            "unanticipated_acceptances": list(self.unanticipated_acceptances),
            "chain": self.chain,
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
        "lower(severity), file_path, status, cwe_ids_json, "
        # What `surface_match` locates a container and a DAST finding by
        # (TheHub #60894). Two strings, never the raw record.
        "json_extract_string(raw_finding_json, '$.image'), "
        "json_extract_string(raw_finding_json, '$.instance.uri') "
        f"FROM findings WHERE {where}",
        params,
    )
    pool = [dict(zip(_COLUMNS, row, strict=True)) for row in rows]
    for finding in pool:
        finding["cwe_ids"] = _cwe_ids(finding.pop("cwe_ids_json", None))
    # A 90022 counts only on its evidence, which this pool does not select
    # (TheHub #61014).
    correlate.attach_disclosure_evidence(pool, catalog.query)
    return pool


def _cwe_ids(raw: Any) -> list[str]:
    """The CWE ids ingest stored as JSON text; [] for anything unreadable."""
    if not isinstance(raw, str) or not raw:
        return []
    try:
        value = json.loads(raw)
    except ValueError:
        return []
    return [str(c) for c in value] if isinstance(value, list) else []


def internet_entry_points(
    session: Session | None, repo: str | None = None
) -> dict[str, list[RepoSurface]]:
    """Declared internet-facing entry points with at least one selector, by
    repository. Only `internet`: `unknown` is an open question, and a chain
    that says "from the internet" must rest on somebody having said so. An
    entry point with no selectors locates nothing, so it is left out."""
    if session is None:
        return {}
    query = select(RepoSurface).where(
        RepoSurface.kind == "entry_point", RepoSurface.exposure == "internet"
    )
    if repo is not None:
        query = query.where(RepoSurface.repo_full_name == repo)
    out: dict[str, list[RepoSurface]] = {}
    for row in session.scalars(query.order_by(RepoSurface.name, RepoSurface.id)).all():
        selectors = row.selectors if isinstance(row.selectors, dict) else {}
        if any(selectors.get(key) for key in surface_match.SELECTOR_KEYS):
            out.setdefault(row.repo_full_name, []).append(row)
    return out


def _locate(pool: list[dict[str, Any]], entry_points: list[RepoSurface]) -> None:
    """Annotate each pool row with the entry points it is inside
    (`correlate.ENTRY_POINTS_KEY`) and the selector that placed it there."""
    if not entry_points:
        return
    for finding in pool:
        located = {
            "capability": finding.get("capability"),
            "file_path": finding.get("file_path"),
            "raw_finding_json": {
                k: v
                for k, v in (
                    ("image", finding.get("image")),
                    ("instance", {"uri": finding["uri"]} if finding.get("uri") else None),
                )
                if v
            },
        }
        hits = surface_match.matches(located, entry_points)
        if hits:
            finding[correlate.ENTRY_POINTS_KEY] = tuple(m.surface.id for m in hits)
            finding[_LOCATED_BY] = {
                m.surface.id: f"{m.selector_type} `{m.selector}`" for m in hits
            }


def _chain(
    combo: correlate.Combination,
    rule: correlate.CombinationRule | None,
    by_id: dict[str, dict[str, Any]],
    entry_points: dict[str, RepoSurface],
) -> dict[str, Any] | None:
    """The chain an entry-point combination is: the way in, then each link."""
    if combo.entry_point is None or rule is None:
        return None
    surface = entry_points.get(combo.entry_point)
    if surface is None:
        return None
    from mykronos.surfaces import declared_via

    door = {
        "id": surface.id,
        "name": surface.name,
        "exposure": surface.exposure,
        "declared_via": declared_via(surface),
        "evidence_ref": surface.evidence_ref or "",
    }
    links: list[dict[str, Any]] = [{"step": "entry_point", **door}]
    for requirement, (fid, why) in zip(rule.requires, combo.qualifications, strict=False):
        member = by_id.get(fid, {})
        links.append(
            {
                "step": requirement.step or requirement.describes,
                "finding_id": fid,
                "capability": str(member.get("capability") or ""),
                "rule_id": str(member.get("rule_id") or ""),
                "title": str(member.get("title") or ""),
                "severity": str(member.get("severity") or ""),
                "status": str(member.get("status") or ""),
                "file_path": member.get("file_path"),
                "located_by": (member.get(_LOCATED_BY) or {}).get(combo.entry_point, ""),
                "qualifies": why,
            }
        )
    return {
        "entry_point": door,
        "links": links,
        "note": (
            "The entry point and its internet exposure are declared in the "
            "threat model, not observed; each finding is placed behind it by "
            "the selector shown."
        ),
    }


def _kev_ids(session: Session | None, findings: list[dict[str, Any]]) -> set[str]:
    if session is None:
        return set()
    cves = {
        cve
        for f in findings
        if (cve := extract_cve(str(f.get("rule_id") or ""), str(f.get("title") or "")))
    }
    # The one KEV read every risk decision shares (TheHub #60901).
    return set(risk_evidence.kev_listed(session, cves))


def known_combinations(evidence: Any) -> frozenset[str]:
    """The combination ids an approver was shown, from an approval request's
    frozen evidence: the `risk_evidence` block's `toxic_combinations` items
    and the `combinations` the tier was floored at.

    Fails closed: anything missing or malformed names nothing, so it covers
    nothing. A block that listed only the first `risk_evidence.LISTED` of
    more names only those."""
    known: set[str] = set()
    if not isinstance(evidence, dict):
        return frozenset()
    block = evidence.get("risk_evidence")
    categories = block.get("categories") if isinstance(block, dict) else None
    toxic_block = categories.get("toxic_combinations") if isinstance(categories, dict) else None
    items = toxic_block.get("items") if isinstance(toxic_block, dict) else None
    floored = evidence.get("combinations")
    for listing in (items, floored):
        if not isinstance(listing, list):
            continue
        for item in listing:
            cid = item.get("combination_id") if isinstance(item, dict) else None
            if isinstance(cid, str) and cid:
                known.add(cid)
    return frozenset(known)


def acceptance_coverage(session: Session | None, finding_ids: Iterable[str]) -> Coverage:
    """For each of these findings, every live acceptance covering it and the
    combinations its approver was shown. One read of the live acceptances and
    one of their approval requests.

    No session reads nothing: every accepted member is then uncovered."""
    ids = {str(f) for f in finding_ids}
    if session is None or not ids:
        return {}
    from mykronos.risk_acceptance import LIVE

    records = [
        r
        for r in session.scalars(
            select(RiskAcceptance).where(RiskAcceptance.status.in_(LIVE))
        ).all()
        if ids & {str(f) for f in (r.covered_finding_ids or [])}
    ]
    request_ids = {r.approval_request_id for r in records if r.approval_request_id}
    evidence: dict[str, Any] = {}
    if request_ids:
        evidence = {
            str(rid): ev
            for rid, ev in session.execute(
                select(ApprovalRequest.id, ApprovalRequest.evidence).where(
                    ApprovalRequest.id.in_(request_ids)
                )
            ).all()
        }
    out: Coverage = {}
    for record in records:
        known = known_combinations(evidence.get(record.approval_request_id or ""))
        for fid in {str(f) for f in (record.covered_finding_ids or [])} & ids:
            out.setdefault(fid, []).append((record.id, known))
    return out


def _judge(
    combo: correlate.Combination, by_id: dict[str, dict[str, Any]], coverage: Coverage
) -> tuple[bool, tuple[str, ...]]:
    """(suppressed, the acceptances that did not know of it) for one combination.

    Suppressed only when every accepted member is covered by a live
    acceptance that was shown this combination."""
    accepted = [
        fid
        for fid in sorted(combo.finding_ids)
        if str(by_id.get(fid, {}).get("status")) == "accepted_risk"
    ]
    if not accepted:
        return False, ()
    unanticipated: set[str] = set()
    covered = True
    for fid in accepted:
        covers = coverage.get(fid, [])
        if any(combo.combination_id in known for _, known in covers):
            continue
        covered = False
        unanticipated.update(rid for rid, _ in covers)
    return covered, tuple(sorted(unanticipated))


def _combinations(
    pool: list[dict[str, Any]],
    session: Session | None,
    *,
    suppress: bool,
    labels: dict[str, str] | None = None,
) -> list[tuple[correlate.Combination, tuple[str, ...]]]:
    """One repository's combinations, each with its unanticipated acceptances."""
    by_id = {str(f["finding_id"]): f for f in pool}
    found = correlate.detect(
        pool, RULES, discounted=correlate.FALSE_POSITIVE_ONLY, entry_point_labels=labels
    )
    if not suppress:
        return [(c, ()) for c in found]
    accepted = {fid for fid, f in by_id.items() if f.get("status") == "accepted_risk"}
    coverage = acceptance_coverage(
        session, {fid for c in found for fid in c.finding_ids if fid in accepted}
    )
    kept: list[tuple[correlate.Combination, tuple[str, ...]]] = []
    suppressed = False
    for combo in found:
        hidden, unanticipated = _judge(combo, by_id, coverage)
        if hidden:
            suppressed = True
        else:
            kept.append((combo, unanticipated))
    if suppressed:
        # The open findings a suppressed combination claimed may make an
        # all-open one #1018 would have shown: detect those on their own.
        claimed = {fid for c, _ in kept for fid in c.finding_ids}
        rest = [
            f
            for fid, f in by_id.items()
            if f.get("status") == "open" and fid not in claimed
        ]
        kept.extend(
            (c, ()) for c in correlate.detect(rest, RULES, entry_point_labels=labels)
        )
    return kept


def detect(
    catalog: Catalog,
    *,
    repo: str | None = None,
    session: Session | None = None,
    escalate_steps: int = 1,
    suppress: bool = True,
) -> list[ToxicCombination]:
    """Every toxic combination, for one repository or the whole estate.

    Detection is per repository, as `correlate.detect` expects: a DAST finding
    in one service and a SAST finding in another are not a combination.

    `suppress=False` is the approver's view: accepted members count and no
    acceptance dissolves anything, so a proposal (and its frozen evidence)
    names every combination its findings are in - a renewal included.
    """
    by_repo: dict[str, list[dict[str, Any]]] = {}
    for finding in _pool(catalog, repo):
        by_repo.setdefault(str(finding["repo_full_name"]), []).append(finding)

    rules = {r.rule_id: r for r in RULES}
    doors = internet_entry_points(session, repo) if by_repo else {}
    out: list[ToxicCombination] = []
    for repo_name, pool in sorted(by_repo.items()):
        here = doors.get(repo_name, [])
        _locate(pool, here)
        by_door = {s.id: s for s in here}
        labels = {s.id: s.name for s in here}
        by_id = {str(f["finding_id"]): f for f in pool}
        for combo, unanticipated in _combinations(
            pool, session, suppress=suppress, labels=labels
        ):
            members = [by_id[fid] for fid in sorted(combo.finding_ids) if fid in by_id]
            why = dict(combo.qualifications)
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
                            "qualifies": why.get(str(m["finding_id"]), ""),
                        }
                        for m in members
                    ),
                    unanticipated_acceptances=unanticipated,
                    chain=_chain(combo, rule, by_id, by_door),
                )
            )
    return out


def coverage(catalog: Catalog, session: Session | None = None) -> dict[str, Any]:
    """Which rules can fire on the data the lake actually holds.

    A rule needs, for each requirement, at least one finding of an allowed
    capability somewhere in the lake. One that cannot be met reports nothing,
    whatever is true of the estate - and must not be read as a clean result.

    An entry-point chain also needs a declared internet-facing entry point
    with a selector, somewhere in the estate. Without a session the threat
    model is not read, so the chain rules are named as unable to fire.
    """
    present: set[str] = set()
    if catalog.all_files("findings"):
        present = {str(r[0]) for r in catalog.query("SELECT DISTINCT capability FROM findings")}
    has_door = bool(internet_entry_points(session))
    live: list[dict[str, Any]] = []
    dark: list[dict[str, Any]] = []
    for rule in RULES:
        missing = sorted(
            {
                cap
                for req in rule.requires
                if req.capabilities and not (set(req.capabilities) & present)
                for cap in req.capabilities
            }
        )
        if rule.scope == "entry_point" and not has_door:
            missing.append(NEEDS_ENTRY_POINT)
        entry = {"rule_id": rule.rule_id, "name": rule.name, "missing": missing}
        (dark if missing else live).append(entry)
    return {"rules": len(RULES), "can_fire": live, "cannot_fire": dark}
