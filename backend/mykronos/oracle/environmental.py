"""Environmental severity as an Oracle input, in shadow (TheHub #60830).

Oracle counts open findings by the scanner's severity word. TheHub #60827
stores, per finding, `EnvironmentalScore.effective_severity`: that word
shifted by as many CVSS bands as this repository's resolved facts move the
score. Epic #60822 decision D2 is that Oracle reads it in *shadow* first:
every decision records, beside the live score, the score and verdict it would
have reached counting by effective severity, so the go-live decision is made
on evidence - how often the two differ, which way, and what happened to the
pull requests where they did - rather than on the arithmetic's promise.

**Nothing here can move a live decision.** `shadow` takes the live decision's
settled tallies and terms as read-only inputs and returns a dict that the
engine writes into `inputs_snapshot.environmental`, after the score, the
verdict and every term are final. `tests/test_oracle_environmental.py` pins
that a decision is byte-identical, environmental block aside, with and
without environmental data and with the shadow on or off.

**What the shadow re-derives.** Only the terms that count findings by
severity: the finding bands, aging, the KEV boost, and toxic combinations.
Every other term (risk profile, accepted risk, posture credits, ...) is
carried over from live unchanged. The band arithmetic is the live function
(`engine.finding_band_terms`) run on tallies adjusted finding by finding, so
with nothing moved the shadow's terms *are* the live terms.

**Which environmental score counts.** A finding's stored row is used only if
it was computed for the finding's current scanner severity and rests on no
applied lowering fact that has expired by the decision's `as_of`
(`environment._lapsed`, the rule #60827's rescore uses). Otherwise the
finding falls back to the scanner's word, and the fallback is counted by
reason - a lapsed fact never lowers a shadow verdict between rescores.

**Two safety rules,** which will hold when this goes live as well:

- *KEV floor.* A KEV-listed finding is never counted below high, or below its
  own scanner word where that is lower. The environment cannot argue an
  actively exploited vulnerability down; the floor also never makes a
  finding harsher than the scanner said, so a KEV-listed `medium` stays
  `medium` (and is boosted to high as in live).
- *Toxic combinations use max(scanner, effective).* A member's severity for
  the combination is the worse of the two, so the environment can make a
  combination critical - and force no_go - but can never lift one.
"""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from mykronos import risk_evidence, toxic
from mykronos.db.models import EnvironmentalScore
from mykronos.environment import _lapsed
from mykronos.oracle.engine import (
    AGE_DAYS,
    NOT_ASSESSED,
    Term,
    age_terms,
    finding_band_terms,
    kev_boost,
)
from mykronos.oracle.policy import Policy
from mykronos.threat_intel import extract_cve

logger = logging.getLogger(__name__)

SEVERITIES = ("info", "low", "medium", "high", "critical")

#: Live terms the shadow recomputes. Everything else is carried over.
_RECOUNTED_PREFIXES = ("findings.", "age.", "exploitability.")
_RECOUNTED_KEYS = ("toxic_combinations", "toxic_combination_no_go")

#: How many moved findings and reasons a snapshot lists by name. The counts
#: are always complete; the lists are for a person reading one decision.
MOVED_LISTED = 25
WHY_LISTED = 12


def _rank(severity: str) -> int:
    return SEVERITIES.index(severity) if severity in SEVERITIES else -1


def _worse(a: str, b: str) -> str:
    return a if _rank(a) >= _rank(b) else b


def _milder(a: str, b: str) -> str:
    return a if _rank(a) <= _rank(b) else b


@dataclass
class LiveDecision:
    """The settled live decision, as the shadow reads it. Never written to."""

    repo_full_name: str
    as_of: datetime
    terms: list[Term]
    raw_score: float
    score: int
    recommendation: str
    counts: dict[str, int]
    aged: dict[str, int]
    dampened_counts: dict[str, int]
    covered_counts: dict[str, int]
    unfixable_counts: dict[str, int]
    dampened_rules: set[str]
    covered: set[str]
    toxic_snapshot: dict[str, Any]
    evidence_available: bool
    #: The SQL scope fragment the live counts used (`OracleEngine._excluded`).
    excluded_sql: str = ""
    statuses: tuple[str, ...] = ("open",)


@dataclass
class _Resolved:
    finding_id: str
    scanner: str
    effective: str
    counted: str
    context_id: str | None
    kev: bool = False
    kev_floor: bool = False


@dataclass
class _Tallies:
    counts: dict[str, int]
    aged: dict[str, int]
    dampened: dict[str, int]
    covered: dict[str, int]
    unfixable: dict[str, int]
    moved: list[_Resolved] = field(default_factory=list)


def off_snapshot(policy: Policy) -> dict[str, Any]:
    return {
        "mode": policy.environmental.mode,
        "available": False,
        "reason": (
            "Environmental severity is off in this policy "
            f"({policy.version}); no shadow was computed."
        ),
    }


def unavailable(policy: Policy, reason: str) -> dict[str, Any]:
    return {"mode": policy.environmental.mode, "available": False, "reason": reason}


def resolve_effective(
    row: EnvironmentalScore | None, scanner: str, as_of: datetime
) -> tuple[str, str | None, str | None]:
    """(severity to count, context id, fallback reason) for one finding.

    The stored score is used only if it was computed for this scanner word and
    rests on nothing that has lapsed by `as_of`; otherwise the scanner's word.
    """
    if row is None or not row.effective_severity:
        return scanner, None, "no_score"
    if (row.scanner_severity or "").strip().lower() != scanner.strip().lower():
        return scanner, None, "scanner_severity_changed"
    if _lapsed(row, as_of):
        return scanner, None, "lapsed"
    effective = row.effective_severity.strip().lower()
    if effective not in SEVERITIES:
        return scanner, None, "no_score"
    return effective, row.context_id or None, None


def shadow(
    catalog: Any, db: Any, policy: Policy, live: LiveDecision
) -> dict[str, Any]:
    """The `environmental` block of one decision's inputs_snapshot."""
    if not policy.environmental.shadow:
        return off_snapshot(policy)
    if db is None:
        return unavailable(
            policy,
            "No operational database is configured for this evaluation, so no "
            "environmental score could be read. The shadow is not computed "
            "rather than reported equal to live.",
        )

    statuses = ", ".join(f"'{s}'" for s in live.statuses)
    rows = catalog.query(
        f"""
        SELECT finding_id, severity, rule_id, title, first_seen_at,
               (package_name IS NOT NULL AND trim(package_name) <> ''
                AND coalesce(json_extract_string(raw_finding_json, '$.fixed_version'), '') = ''
               ) AS unfixable
        FROM findings
        WHERE asset_id = ?
          AND status IN ({statuses})
          {live.excluded_sql}
        ORDER BY finding_id
        """,
        [live.repo_full_name],
    )

    cves = {
        str(fid): cve
        for fid, _sev, rule_id, title, _first, _unfix in rows
        if (cve := extract_cve(str(rule_id), str(title))) is not None
    }
    # Read through the shared evidence model (TheHub #60901), the same reads
    # a risk acceptance makes.
    with db.session() as session:
        scores = risk_evidence.environmental_scores(session, repo=live.repo_full_name)
        kev_cves = set(risk_evidence.kev_listed(session, cves.values()))

    in_scope = set(policy.severities_in_scope())
    tallies = _Tallies(
        counts=dict(live.counts),
        aged=dict(live.aged),
        dampened=dict(live.dampened_counts),
        covered=dict(live.covered_counts),
        unfixable=dict(live.unfixable_counts),
    )
    by_effective: Counter[str] = Counter()
    fallback: Counter[str] = Counter({"no_score": 0, "lapsed": 0, "scanner_severity_changed": 0})
    contexts: set[str] = set()
    resolved: dict[str, _Resolved] = {}
    kev_floor: list[str] = []
    scored = 0

    for fid_raw, sev_raw, rule_id, _title, first_seen, unfix in rows:
        fid = str(fid_raw)
        scanner = str(sev_raw)
        effective, context_id, reason = resolve_effective(scores.get(fid), scanner, live.as_of)
        if reason is not None:
            fallback[reason] += 1
        else:
            scored += 1
            if context_id:
                contexts.add(context_id)
        counted = effective
        is_kev = fid in cves and cves[fid] in kev_cves
        entry = _Resolved(fid, scanner, effective, counted, context_id, kev=is_kev)
        if scanner in SEVERITIES:
            floor = _milder(scanner, "high")
            if is_kev and _rank(counted) < _rank(floor):
                entry.counted = floor
                entry.kev_floor = True
                kev_floor.append(fid)
        else:
            # A severity word Oracle does not know is not moved: there is no
            # band to move it out of.
            entry.counted = scanner
        resolved[fid] = entry
        if entry.counted in in_scope:
            by_effective[entry.counted] += 1
        if entry.counted == scanner:
            continue
        tallies.moved.append(entry)
        _move(
            tallies,
            scanner,
            entry.counted,
            in_scope=in_scope,
            quiet=str(rule_id) in live.dampened_rules,
            covered=fid in live.covered,
            unfixable=bool(unfix),
            first_seen=first_seen,
            as_of=live.as_of,
        )

    toxic_shadow = _toxic(policy, live.toxic_snapshot, resolved, scores, live.as_of)
    moved_any = bool(tallies.moved)
    toxic_changed = any(
        c["live_severity"] != c["shadow_severity"] for c in toxic_shadow["combinations"]
    )

    replaced = [t for t in live.terms if _recounted(t.key)]
    if not moved_any and not toxic_changed:
        # Exactly live, not live re-added: summing the same floats in a
        # different order can move a score sitting on .5.
        shadow_terms = list(replaced)
        shadow_raw = live.raw_score
    else:
        band, _effective = finding_band_terms(
            tallies.counts, tallies.dampened, tallies.covered, tallies.unfixable, policy
        )
        shadow_terms = [*band, *age_terms(tallies.aged, policy)]
        shadow_terms.extend(_kev_terms(resolved, in_scope, policy))
        if toxic_shadow["points"]:
            shadow_terms.append(
                Term(
                    key="toxic_combinations",
                    label="Toxic combinations",
                    contribution=toxic_shadow["points"],
                    detail="Re-rated with max(scanner, effective) per member.",
                )
            )
        carried = sum(t.contribution for t in live.terms if not _recounted(t.key))
        shadow_raw = carried + sum(t.contribution for t in shadow_terms)
        if toxic_shadow["forces_no_go"] and shadow_raw < policy.no_go:
            lift = policy.no_go - shadow_raw
            shadow_terms.append(
                Term(
                    key="toxic_combination_no_go",
                    label="Critical toxic combination",
                    contribution=lift,
                    detail="A critical toxic combination forces no_go.",
                )
            )
            shadow_raw += lift

    shadow_score = max(0, min(100, round(shadow_raw)))
    shadow_recommendation = policy.recommendation_for(shadow_score)
    if shadow_recommendation == "go" and not live.evidence_available:
        shadow_recommendation = NOT_ASSESSED

    would_differ = shadow_recommendation != live.recommendation
    why = _why(live, tallies.moved, toxic_shadow, shadow_score, shadow_recommendation)

    return {
        "mode": policy.environmental.mode,
        "available": True,
        "reason": (
            f"{scored} of {len(rows)} open finding(s) counted by a current "
            "environmental score; the rest by the scanner's severity."
        ),
        "counts_by_scanner_severity": {
            sev: live.counts.get(sev, 0) for sev in policy.severities_in_scope()
        },
        "counts_by_effective_severity": {
            sev: by_effective.get(sev, 0) for sev in policy.severities_in_scope()
        },
        "context_ids": sorted(contexts),
        "scored_findings": scored,
        "fallback": dict(fallback),
        "kev_floor_applied": kev_floor,
        "moved": [
            {
                "finding_id": m.finding_id,
                "scanner_severity": m.scanner,
                "effective_severity": m.effective,
                "counted_as": m.counted,
                "context_id": m.context_id,
                "kev_floor": m.kev_floor,
            }
            for m in tallies.moved[:MOVED_LISTED]
        ],
        "moved_not_listed": max(0, len(tallies.moved) - MOVED_LISTED),
        "toxic_combinations": {
            "forces_no_go": toxic_shadow["forces_no_go"],
            "contribution": round(toxic_shadow["points"], 2),
            "combinations": toxic_shadow["combinations"],
        },
        "shadow": {
            "raw_score": round(shadow_raw, 2),
            "overall_risk_score": shadow_score,
            "recommendation": shadow_recommendation,
            "terms": [
                {
                    "key": t.key,
                    "label": t.label,
                    "contribution": round(t.contribution, 2),
                    "detail": t.detail,
                }
                for t in shadow_terms
            ],
        },
        "live": {
            "raw_score": round(live.raw_score, 2),
            "overall_risk_score": live.score,
            "recommendation": live.recommendation,
        },
        "would_differ": would_differ,
        "why": why,
        "recounted": (
            "finding bands, aging, KEV boost and toxic combinations; every "
            "other term carried over from live"
        ),
    }


def _recounted(key: str) -> bool:
    return key.startswith(_RECOUNTED_PREFIXES) or key in _RECOUNTED_KEYS


def _aged_under(severity: str, first_seen: Any, as_of: datetime) -> bool:
    days = AGE_DAYS.get(severity)
    if days is None or not isinstance(first_seen, datetime):
        return False
    # Lake timestamps are naive UTC (schemas.utcnow); an aware one is brought
    # to the same footing rather than compared and raising.
    seen: datetime = first_seen
    if seen.tzinfo is not None:
        seen = seen.astimezone(UTC).replace(tzinfo=None)
    if as_of.tzinfo is not None:
        as_of = as_of.astimezone(UTC).replace(tzinfo=None)
    return seen <= as_of - timedelta(days=days)


def _move(
    tallies: _Tallies,
    scanner: str,
    counted: str,
    *,
    in_scope: set[str],
    quiet: bool,
    covered: bool,
    unfixable: bool,
    first_seen: Any,
    as_of: datetime,
) -> None:
    """Take one finding out of its scanner band and put it in its counted one,
    carrying its dampened / in-flight / unfixable attributes with it."""
    for band, step in ((scanner, -1), (counted, +1)):
        if band in in_scope:
            tallies.counts[band] = tallies.counts.get(band, 0) + step
            if quiet:
                tallies.dampened[band] = tallies.dampened.get(band, 0) + step
            if covered:
                tallies.covered[band] = tallies.covered.get(band, 0) + step
            if unfixable:
                tallies.unfixable[band] = tallies.unfixable.get(band, 0) + step
        if _aged_under(band, first_seen, as_of):
            tallies.aged[band] = tallies.aged.get(band, 0) + step


def _kev_terms(
    resolved: dict[str, _Resolved], in_scope: set[str], policy: Policy
) -> list[Term]:
    terms: list[Term] = []
    for entry in resolved.values():
        if not entry.kev or entry.counted not in in_scope:
            continue
        boosted_to, boost = kev_boost(entry.counted, policy.severity_weights)
        if boost <= 0:
            continue
        terms.append(
            Term(
                key=f"exploitability.{entry.finding_id}",
                label=f"KEV-listed finding counted {entry.counted}",
                contribution=boost,
                detail=f"{entry.counted} boosted to {boosted_to}",
            )
        )
    return terms


def _toxic(
    policy: Policy,
    snapshot: dict[str, Any],
    resolved: dict[str, _Resolved],
    scores: dict[str, EnvironmentalScore],
    as_of: datetime,
) -> dict[str, Any]:
    """Combinations re-rated with max(scanner, effective) per member.

    Members outside the scored scope are read from their stored score where
    one is current. (Dispositioned findings no longer count toward a
    combination at all since TheHub #60965, so this is now the rarer case.)"""
    pol = policy.toxic_combinations
    combinations: list[dict[str, Any]] = []
    for combo in snapshot.get("combinations") or []:
        worst = str(combo.get("member_severity") or "")
        for fid in combo.get("finding_ids") or []:
            entry = resolved.get(str(fid))
            if entry is not None:
                worst = _worse(worst, entry.effective)
                continue
            row = scores.get(str(fid))
            if row is not None and row.effective_severity and not _lapsed(row, as_of):
                worst = _worse(worst, row.effective_severity.strip().lower())
        rated = toxic.combination_severity(
            [worst], kev=bool(combo.get("kev_cves")), escalate_steps=pol.escalate_steps
        )
        # max(), applied to the combination as well as its members: whatever
        # the arithmetic, the shadow never rates a combination milder than live.
        rated = _worse(rated, str(combo.get("severity") or ""))
        combinations.append(
            {
                "name": combo.get("name"),
                "combination_id": combo.get("combination_id"),
                "live_severity": combo.get("severity"),
                "shadow_severity": rated,
            }
        )
    forces = pol.critical_forces_no_go and any(
        c["shadow_severity"] == "critical" for c in combinations
    )
    points = sum(
        pol.points.get(c["shadow_severity"], 0.0)
        for c in combinations
        if not (forces and c["shadow_severity"] == "critical")
    )
    return {
        "forces_no_go": forces,
        "points": min(points, pol.cap),
        "combinations": combinations,
    }


def _why(
    live: LiveDecision,
    moved: list[_Resolved],
    toxic_shadow: dict[str, Any],
    shadow_score: int,
    shadow_recommendation: str,
) -> list[str]:
    lines: list[str] = []
    if shadow_score != live.score or shadow_recommendation != live.recommendation:
        lines.append(
            f"Score {live.score} ({live.recommendation}) live, {shadow_score} "
            f"({shadow_recommendation}) counting by effective severity."
        )
    for m in moved[:WHY_LISTED]:
        if m.kev_floor:
            lines.append(
                f"Finding {m.finding_id[:12]} is KEV-listed: effective {m.effective} "
                f"floored to {m.counted} (scanner {m.scanner})."
            )
        else:
            lines.append(
                f"Finding {m.finding_id[:12]} counted {m.counted} instead of "
                f"{m.scanner} (context {(m.context_id or '-')[:12]})."
            )
    if len(moved) > WHY_LISTED:
        lines.append(f"...and {len(moved) - WHY_LISTED} more finding(s) moved band.")
    for combo in toxic_shadow["combinations"]:
        if combo["live_severity"] != combo["shadow_severity"]:
            lines.append(
                f"Toxic combination {combo['name']}: {combo['live_severity']} live, "
                f"{combo['shadow_severity']} with max(scanner, effective) per member"
                + ("; it forces no_go." if combo["shadow_severity"] == "critical"
                   and toxic_shadow["forces_no_go"] else ".")
            )
    return lines


# ---------------------------------------------------------------------------
# The report
# ---------------------------------------------------------------------------

#: How many differing decisions the report lists by name.
DIFFERENCES_LISTED = 100


def build_report(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Shadow against live, and both against `gate_outcome`, over decisions.

    `rows` are risk_decisions rows with `environmental` already parsed (None
    for a decision from before policy 1.13). A decision whose shadow was off
    or unavailable is counted as not shadowed, never as agreeing.
    """
    shadowed = 0
    agree = 0
    transitions: Counter[str] = Counter()
    deltas: list[int] = []
    differences: list[dict[str, Any]] = []
    by_live: dict[str, Counter[str]] = {}
    by_shadow: dict[str, Counter[str]] = {}
    with_outcome = 0
    differing_merged = 0
    shadow_no_go_merged = 0
    live_no_go_merged = 0

    for row in rows:
        env = row.get("environmental")
        if not isinstance(env, dict) or not env.get("available") or "shadow" not in env:
            continue
        shadowed += 1
        live = str(row.get("recommendation") or "")
        shadow_rec = str(env["shadow"].get("recommendation") or "")
        live_score = int(row.get("overall_risk_score") or 0)
        shadow_score = int(env["shadow"].get("overall_risk_score") or 0)
        deltas.append(shadow_score - live_score)
        outcome = row.get("gate_outcome")
        differs = shadow_rec != live
        if differs:
            transitions[f"{live} -> {shadow_rec}"] += 1
            differences.append(
                {
                    "decision_id": row.get("decision_id"),
                    "repo_full_name": row.get("repo_full_name"),
                    "decision_type": row.get("decision_type"),
                    "pr_number": row.get("pr_number"),
                    "commit_sha": row.get("commit_sha"),
                    "evaluated_at": _iso(row.get("evaluated_at")),
                    "live": live,
                    "shadow": shadow_rec,
                    "live_score": live_score,
                    "shadow_score": shadow_score,
                    "gate_outcome": outcome,
                    "why": list(env.get("why") or []),
                }
            )
        else:
            agree += 1
        if outcome:
            with_outcome += 1
            by_live.setdefault(live, Counter())[str(outcome)] += 1
            by_shadow.setdefault(shadow_rec, Counter())[str(outcome)] += 1
            if outcome == "merged":
                differing_merged += int(differs)
                shadow_no_go_merged += int(shadow_rec == "no_go")
                live_no_go_merged += int(live == "no_go")

    total = len(rows)
    return {
        "decisions": total,
        "shadowed": shadowed,
        "not_shadowed": total - shadowed,
        "agree": agree,
        "differ": shadowed - agree,
        "transitions": dict(sorted(transitions.items())),
        "score_delta": (
            {
                "mean": round(sum(deltas) / len(deltas), 2),
                "min": min(deltas),
                "max": max(deltas),
            }
            if deltas
            else None
        ),
        "differences": differences[:DIFFERENCES_LISTED],
        "differences_not_listed": max(0, len(differences) - DIFFERENCES_LISTED),
        "against_gate_outcome": {
            "decisions_with_a_known_outcome": with_outcome,
            "by_live": {k: dict(v) for k, v in sorted(by_live.items())},
            "by_shadow": {k: dict(v) for k, v in sorted(by_shadow.items())},
            "differing_and_merged": differing_merged,
            "shadow_no_go_merged": shadow_no_go_merged,
            "live_no_go_merged": live_no_go_merged,
        },
        "interpretation": (
            "Every difference is a verdict environmental severity would have "
            "changed. `why` names the findings that moved band and the context "
            "they were scored in. A shadow verdict harsher than live on a PR "
            "that merged is a merge it would have flagged; one milder than live "
            "is a review it would have spared - whether that was right needs "
            "the facts behind it, which the context ids lead to. This is the "
            "evidence the go-live conditions in oracle-policy-v1.yaml ask for, "
            "not the decision."
        ),
    }


def _iso(value: Any) -> Any:
    return value.isoformat() if isinstance(value, datetime) else value
