"""The risk decision engine (spec 09).

Oracle is a *consumer*. It never scans anything; it reads the lake and turns
what is already there into an explainable go / review / no-go.

Two properties the whole design serves:

**Determinism.** The same inputs and the same policy version always produce
the same score (spec 09 §9). No clocks inside the arithmetic, no iteration
over unordered sets, no floating-point accumulation order that depends on how
rows came back. `tests/test_oracle_golden.py` pins exact values.

**Explainability.** Every term that contributes is recorded in
`inputs_snapshot` with its own value, and the reasoning sentence is generated
*from that snapshot* rather than assembled alongside it. That is what makes
the claim "the reasoning has no hidden inputs" checkable rather than
aspirational — if a term is not in the snapshot, it cannot appear in the
sentence.
"""

from __future__ import annotations

import logging
import math
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select

from mykronos import blast_radius, governance, regression
from mykronos.db.models import ReachabilityReport, RepoOnboarding, RiskProfile, ThreatIntelMatch
from mykronos.db.session import Database
from mykronos.knowledge.dampening import dampened_rules
from mykronos.knowledge.store import KnowledgeStore
from mykronos.lake.catalog import Catalog
from mykronos.logsafe import scrub
from mykronos.oracle.policy import Policy
from mykronos.schemas import Severity, utcnow
from mykronos.threat_intel import extract_cve

logger = logging.getLogger(__name__)

DECISION_TYPES = ("pr_gate", "release_gate", "portfolio")

#: Every category present in `inputs_snapshot` whether or not it has anything
#: to say (spec 09 §9). Defined once so `render_reasoning` here and
#: `render_check_run_summary` (oracle/service.py) cannot list a different set
#: of "not yet consulted" categories from each other.
MODIFIER_CATEGORIES = (
    "insider_risk",
    "sscs_trust",
    "remediation_in_flight",
    "false_positive_dampening",
    "exploitability",
    "reachability",
    "risk_profile",
    "governance",
    "blast_radius",
    "overdue_findings",
    "posture_credits",
)

#: One band up (spec 17 §5.4). `critical` has nowhere further to go — a
#: finding already at the ceiling is not made worse by also being exploited;
#: the exploitation is already reflected in every band below it.
_NEXT_SEVERITY_BAND = {
    Severity.INFO.value: Severity.LOW.value,
    Severity.LOW.value: Severity.MEDIUM.value,
    Severity.MEDIUM.value: Severity.HIGH.value,
    Severity.HIGH.value: Severity.CRITICAL.value,
    Severity.CRITICAL.value: Severity.CRITICAL.value,
}


@dataclass
class Term:
    """One contributing term, as it appears in the snapshot and the reasoning.

    `detail` carries the arithmetic — "2 findings, 40 × log2(3)" — so a human
    can check the number rather than trust it.
    """

    key: str
    label: str
    contribution: float
    detail: str
    inputs: dict[str, Any] = field(default_factory=dict)


@dataclass
class Decision:
    decision_id: str
    repo_full_name: str
    decision_type: str
    commit_sha: str
    pr_number: int | None
    release_tag: str | None
    overall_risk_score: int
    recommendation: str
    reasoning: str
    inputs_snapshot: dict[str, Any]
    policy_version: str
    evaluated_at: datetime

    def summary(self) -> str:
        return f"{self.recommendation} ({self.overall_risk_score}/100)"


def _band_contribution(weight: float, count: float) -> float:
    """`weight × log2(1 + count)` — the saturation fix (D-018).

    Linear weighting pinned every vulnerable repo at the clamp: three open
    criticals reached 100, and so did three hundred, so the portfolio could
    not be ranked and the trend line flatlined. The curve keeps the score
    strictly increasing in findings while flattening, so the gap between "a
    few" and "some" matters more than between "many" and "very many" — which
    is how a person triages.

    `count` is a float rather than an int because false-positive dampening
    (spec 11 §6.1) makes a dismissed-often finding count for a fraction of one.
    """
    if count <= 0:
        return 0.0
    return weight * math.log2(1 + count)


def _dampening_snapshot(
    dampened: dict[str, Any] | None,
    *,
    store_configured: bool,
    factor: float,
    min_observations: int,
) -> dict[str, Any]:
    """The dampening category, with the evidence for every rule it quietened.

    A weight that quietly halved is exactly the kind of hidden input spec 09
    exists to prevent, so each dampened rule travels with its rate, its counts
    and the human reasons that earned it.

    Note this is *not* a contribution: dampening reduces other terms rather
    than adding one of its own, so the figure reported is the multiplier that
    was applied, and the reduction is visible in the finding bands themselves.
    """
    if not store_configured:
        return {
            "available": False,
            "dampened_rules": None,
            "contribution": 0.0,
            "reason": "No Knowledge Store is configured for this deployment.",
        }
    if not dampened:
        return {
            "available": True,
            "dampened_rules": [],
            "contribution": 0.0,
            "reason": (
                f"No rule has reached {min_observations} reasoned dismissals "
                "at or above the policy's false-positive threshold."
            ),
        }
    return {
        "available": True,
        "dampened_rules": [
            entry.as_snapshot(factor) for entry in sorted(
                dampened.values(), key=lambda d: d.rule_id
            )
        ],
        "weight_multiplier": round(1.0 - factor, 3),
        "contribution": 0.0,
    }


def _remediation_snapshot(
    covered: set[str] | None, *, discount: float
) -> dict[str, Any]:
    """Findings with a fix already in flight (spec 08 §9, spec 09 §5).

    Available even when nothing is covered, unlike the categories that depend
    on a capability being enabled: Patchwork writes no rows for a repository
    it is not running on, and "no open fixes" is the correct and complete
    answer for such a repository. There is nothing to be uncertain about.
    """
    count = len(covered or ())
    return {
        "available": True,
        "covered_findings": count,
        "discount": discount,
        # Not a contribution of its own: like dampening, it reduces other
        # terms, and the reduction is visible in the finding bands.
        "contribution": 0.0,
        "reason": (
            "No Patchwork pull request is open for any finding in scope."
            if not count
            else (
                f"{count} finding(s) have a draft fix awaiting review, counted "
                f"at {1.0 - discount:g}× because a fix in flight lowers "
                "urgency, not risk."
            )
        ),
    }


def _insider_snapshot(
    insider: dict[str, Any] | None, *, for_gate: bool, multiplier: float
) -> dict[str, Any]:
    """The insider-risk category, present whether or not it has anything to say.

    Three distinct absences, each named. Reporting all of them as `score: 0`
    would let a repo with Aegis switched off look identical to one where Aegis
    ran and found nothing — a difference of some importance to the person the
    score is about.
    """
    if not for_gate:
        return {
            "available": False,
            "score": None,
            "contribution": 0.0,
            "reason": (
                "Insider risk is about a specific pull request, so it is not "
                "consulted for a standing portfolio score (spec 06 §9)."
            ),
        }
    if insider is None:
        return {
            "available": False,
            "score": None,
            "contribution": 0.0,
            "reason": (
                "No Aegis assessment exists for this pull request — the "
                "capability is not enabled, or its workflow has not run yet."
            ),
        }
    return {
        "available": True,
        "score": insider["score"],
        "recommendation": insider["recommendation"],
        "assessed_commit": insider["commit_sha"],
        "multiplier": multiplier,
        "contribution": round(insider["score"] * multiplier, 2),
    }


def _sscs_snapshot(sscs: dict[str, Any] | None, *, cap: float) -> dict[str, Any]:
    if sscs is None:
        return {
            "available": False,
            "trust_score": None,
            "contribution": 0.0,
            "reason": (
                "No Atlas evidence exists for this repository — the capability "
                "is not enabled, or its workflow has not run yet."
            ),
        }
    shortfall = 100 - sscs["trust_score"]
    return {
        "available": True,
        "trust_score": sscs["trust_score"],
        "vulnerable_dependency_count": sscs["vulnerable_dependency_count"],
        "dependency_count": sscs["dependency_count"],
        "assessed_commit": sscs["commit_sha"],
        "penalty_cap": cap,
        "contribution": round(float(min(max(shortfall, 0), cap)), 2),
    }


def _reachability_snapshot(
    report: dict[str, Any] | None, orphaned_findings: int, policy: Policy
) -> tuple[dict[str, Any], list[Term]]:
    """Findings in code nothing imports (spec 19 §2.1).

    Much less than reachability, and the snapshot says so. Spec 17 §5.3
    declined to build a call-graph engine and left this category permanently
    unavailable; this is the floor underneath it — for Python only, does
    anything in the repository import this file.

    The direction of the term is worth stating: it is a *discount*, not a
    penalty. A finding in a file nothing imports is lower priority than the
    same finding on a request path, so this subtracts. That makes the failure
    mode of a wrong answer specific and worth guarding: a file wrongly called
    orphaned quietly deprioritises a real finding. Everything the analysis is
    unsure of — a file that would not parse, an entry point, a non-Python
    file, a repository it never ran for — stays out of the orphaned list, so
    the error can only be in the direction of discounting nothing.
    """
    if report is None:
        return (
            {
                "available": False,
                "contribution": 0.0,
                "reason": (
                    "No import analysis has run for this repository "
                    "(spec 19 §2.1). It runs alongside the sast capability, "
                    "and covers Python only."
                ),
            },
            [],
        )

    orphaned = list(report.get("orphaned_paths") or [])
    snapshot = {
        "available": True,
        "language": report.get("language") or "python",
        "analysed_commit": report.get("commit_sha") or None,
        "files_analysed": int(report.get("files_analysed") or 0),
        "files_unparseable": int(report.get("files_unparseable") or 0),
        "orphaned_files": len(orphaned),
        "findings_in_orphaned_files": orphaned_findings,
        "contribution": 0.0,
        "reason": (
            "Whether anything in the repository imports the file — not "
            "whether the code runs. A file not listed as orphaned is not "
            "proven reachable, only not proven dead."
        ),
    }

    points = policy.reachability.orphaned_discount_per_finding * orphaned_findings
    points = min(points, policy.reachability.discount_cap)
    if not points:
        return (snapshot, [])

    snapshot["contribution"] = round(-points, 2)
    return (
        snapshot,
        [
            Term(
                key="reachability.orphaned",
                label="Findings in files nothing imports",
                contribution=-points,
                detail=(
                    f"{orphaned_findings} finding(s) in {len(orphaned)} "
                    f"file(s) that nothing in the repository imports, "
                    f"discounted {points:g} points. Import reachability for "
                    "Python only — not whether the code is called."
                ),
                inputs={"orphaned_files": len(orphaned)},
            )
        ],
    )


def _overdue_snapshot(
    overdue: int, in_scope: int, policy: Policy
) -> tuple[dict[str, Any], list[Term]]:
    """Findings past a deadline this organisation set (spec 24 §2.4).

    Deliberately not a second age term. `finding_age` escalates continuously
    and describes drift; this fires once, on a date, and a repository whose
    findings are all inside their windows scores nothing here however old they
    are. That is the behaviour the age curve alone cannot express, and it is
    the whole reason targets exist as policy rather than as a dashboard label.

    Unavailable — never a zero — when no targets are configured. A deployment
    that has not adopted them has not achieved compliance, and reporting
    "0 overdue" would read as though it had.
    """
    if not policy.remediation_targets.configured:
        return (
            {
                "available": False,
                "contribution": 0.0,
                "reason": (
                    "No remediation targets are configured in the policy "
                    "(spec 24 §2.2), so no finding has a deadline to be past."
                ),
            },
            [],
        )

    snapshot = {
        "available": True,
        "overdue_findings": overdue,
        "findings_with_a_target": in_scope,
        "targets": dict(policy.remediation_targets.days),
        "contribution": 0.0,
        "reason": (
            f"{overdue} of {in_scope} in-scope finding(s) with a deadline are "
            "past it. A finding inside its window contributes nothing here, "
            "however old it is."
        ),
    }

    points = min(
        policy.overdue.per_finding * overdue,
        policy.overdue.cap,
    )
    if not points:
        return (snapshot, [])

    snapshot["contribution"] = round(points, 2)
    return (
        snapshot,
        [
            Term(
                key="overdue_findings",
                label="Findings past their remediation target",
                contribution=points,
                detail=(
                    f"{overdue} finding(s) past a deadline set by policy or by "
                    f"CISA KEV, adding {points:g} points. Distinct from age: a "
                    "finding inside its window adds nothing here."
                ),
                inputs={"overdue": overdue},
            )
        ],
    )


def _posture_snapshot(
    *,
    coverage: Any,
    verified: tuple[int, int],
    within_target: tuple[int, int],
    open_criticals: int,
    policy: Policy,
) -> tuple[dict[str, Any], list[Term]]:
    """What the team earned back (spec 26 §2).

    The only terms in the model that subtract for something somebody *did*
    rather than for a fact about the code. Each is `available: False` with a
    reason until its evidence exists, per spec 09 §9 — a credit that silently
    contributes zero is how a team concludes the model is rigged.
    """
    credits = policy.posture
    if not credits.configured:
        return (
            {
                "available": False,
                "contribution": 0.0,
                "reason": "No posture credits are configured in the policy.",
            },
            [],
        )

    parts: list[Term] = []
    detail: dict[str, Any] = {}

    # 1. Regression coverage (spec 31).
    if coverage is not None and coverage.available:
        points = min(
            credits.regression_per_covered * coverage.covered, credits.regression_cap
        )
        detail["regression_coverage"] = {
            "available": True,
            "covered": coverage.covered,
            "of_fixed": coverage.fixed_findings,
            "points": round(points, 2),
        }
        if points:
            parts.append(
                Term(
                    key="posture.regression_coverage",
                    label="Fixed findings with a regression test pinned",
                    contribution=-points,
                    detail=(
                        f"{coverage.covered} of {coverage.fixed_findings} fixed "
                        f"finding(s) would be caught coming back, worth "
                        f"{points:g} points."
                    ),
                    inputs={"covered": coverage.covered},
                )
            )
    else:
        detail["regression_coverage"] = {
            "available": False,
            "reason": "Nothing has been fixed here yet, so there is no coverage to earn.",
        }

    # 2. Verified fix rate (spec 25 §3).
    verified_count, merged_count = verified
    if merged_count >= credits.verified_minimum_sample:
        rate = verified_count / merged_count if merged_count else 0.0
        points = credits.verified_at_full_rate * rate
        detail["verified_fix_rate"] = {
            "available": True,
            "verified": verified_count,
            "merged": merged_count,
            "rate": round(rate, 3),
            "points": round(points, 2),
        }
        if points:
            parts.append(
                Term(
                    key="posture.verified_fix_rate",
                    label="Merged fixes verified as removing the finding",
                    contribution=-points,
                    detail=(
                        f"{verified_count} of {merged_count} merged fix(es) were "
                        f"verified gone by a re-scan, worth {points:g} points."
                    ),
                    inputs={"verified": verified_count, "merged": merged_count},
                )
            )
    else:
        detail["verified_fix_rate"] = {
            "available": False,
            "reason": (
                f"Only {merged_count} merged fix(es); below the minimum sample of "
                f"{credits.verified_minimum_sample} the rate is noise. A team that "
                "has fixed three things well has not earned a rate, and must not "
                "be scored as though it failed seven."
            ),
        }

    # 3. Findings inside their remediation window (spec 24 §2).
    on_track, with_target = within_target
    if with_target:
        rate = on_track / with_target
        points = credits.within_target_at_full * rate
        detail["within_target"] = {
            "available": True,
            "on_track": on_track,
            "with_target": with_target,
            "rate": round(rate, 3),
            "points": round(points, 2),
        }
        if points:
            parts.append(
                Term(
                    key="posture.within_target",
                    label="Findings fixed inside their remediation target",
                    contribution=-points,
                    detail=(
                        f"{on_track} of {with_target} finding(s) with a deadline were "
                        f"fixed inside it, worth {points:g} points."
                    ),
                    inputs={"on_track": on_track, "with_target": with_target},
                )
            )
    else:
        detail["within_target"] = {
            "available": False,
            "reason": (
                "Nothing with a remediation target has been fixed here in the "
                "last 90 days. Open findings that are merely not late yet earn "
                "nothing: that would credit the clock rather than the team."
            ),
        }

    earned = sum(-term.contribution for term in parts)
    capped = min(earned, credits.total_cap)
    floored = False
    if credits.floor_with_open_critical and open_criticals and capped:
        # A team may not test its way out of an exploited critical. Flagged
        # rather than applied here: the clamp needs the score the rest of the
        # model produced, so `evaluate` applies it and rewrites the terms.
        floored = True

    snapshot = {
        "available": True,
        "credits": detail,
        "earned": round(earned, 2),
        "applied": round(capped, 2),
        "capped_at": credits.total_cap if capped < earned else None,
        "floored_by_open_critical": floored,
        "contribution": round(-capped, 2),
        "reason": (
            "The only terms here that subtract for something somebody did. "
            "Every one requires evidence — a test pinned, a fix verified, a "
            "deadline met — and none can be earned by changing a setting."
        ),
    }

    if not capped:
        return (snapshot, [])

    # Rescale the individual terms so the published arithmetic sums to what
    # was actually applied. Terms that do not add up to the total are how a
    # breakdown stops being checkable.
    if capped < earned and earned:
        factor = capped / earned
        parts = [
            Term(
                key=term.key,
                label=term.label,
                contribution=term.contribution * factor,
                detail=f"{term.detail} Scaled to the {credits.total_cap:g}-point cap.",
                inputs=term.inputs,
            )
            for term in parts
        ]
    return (snapshot, parts)


#: How many actions a path may name before it stops being an instruction and
#: starts being the findings list again. The value of this is the *prefix*.
PATH_STEPS_MAX = 12


def _path_to_green(
    *,
    effective: dict[str, float],
    candidates: dict[str, list[dict[str, Any]]],
    raw_score: float,
    policy: Policy,
) -> dict[str, Any]:
    """The minimal set of closures that moves this repository down a band
    (spec 26 §1).

    The engine already holds every term, its weight and the exact distance to
    the threshold, and then reports a verdict and leaves the reader to solve
    the inverse by hand. This is that inverse, and it is arithmetic on values
    already computed rather than a second model.

    **Recomputed at every step, not summed.** The band curve is
    `weight × log2(1 + n)`, so removing the second finding from a band is
    worth less than removing the first. Independent deltas would publish
    arithmetic that does not match what happens when somebody actually does
    it.

    **The projection counts the band curve only.** Removing a finding also
    removes any KEV boost and any overdue points attached to it, so the real
    drop is *at least* the projected one. Under-promising is the safe
    direction for a number people plan against, and the response says so.

    **Actions, never outcomes.** Each step names a finding somebody can close.
    "Reduce criticals by two" is an instruction nobody can act on directly,
    and this platform does not publish those.
    """
    order = list(reversed(policy.severities_in_scope()))
    remaining = {severity: list(candidates.get(severity, [])) for severity in order}
    working = dict(effective)
    projected = raw_score
    steps: list[dict[str, Any]] = []

    def band_at(severity: str, count: float) -> float:
        return _band_contribution(policy.severity_weights.get(severity, 0.0), count)

    while len(steps) < PATH_STEPS_MAX and projected >= policy.review_recommended:
        best: tuple[float, str] | None = None
        for severity in order:
            if not remaining[severity]:
                continue
            current = working.get(severity, 0.0)
            if current <= 0:
                continue
            saving = band_at(severity, current) - band_at(severity, max(0.0, current - 1))
            if saving <= 0:
                continue
            if best is None or saving > best[0]:
                best = (saving, severity)

        if best is None:
            break

        saving, severity = best
        finding = remaining[severity].pop(0)
        working[severity] = max(0.0, working.get(severity, 0.0) - 1)
        projected -= saving
        steps.append(
            {
                "finding_id": finding["finding_id"],
                "rule_id": finding["rule_id"],
                "title": finding["title"],
                "severity": severity,
                "file_path": finding.get("file_path"),
                "points_removed": round(saving, 2),
                "score_after": max(0, min(100, round(projected))),
                "recommendation_after": policy.recommendation_for(
                    max(0.0, min(100.0, projected))
                ),
            }
        )

    left = sum(len(rows) for rows in remaining.values())
    reached = policy.recommendation_for(max(0.0, min(100.0, projected)))
    return {
        "available": True,
        "steps": steps,
        "findings_not_listed": left,
        "reaches": reached,
        "reachable": reached != "no_go" or not steps,
        "note": (
            "Each step is recomputed, not summed: the band curve means the "
            "second finding out of a band is worth less than the first. The "
            "projection counts the finding bands only, so closing these "
            "removes at least this much — any KEV boost or overdue points on "
            "the same findings come off as well."
        ),
    }


def _risk_profile_snapshot(
    profile: dict[str, Any] | None, policy: Policy
) -> tuple[dict[str, Any], list[Term]]:
    """What this application *is*, as an asset (spec 21 §1.4).

    The only input here not derived from a scan: nothing a scanner sees can
    say whether an application is internet-facing or handles regulated data.
    An admin records it, and a repository nobody has recorded one for is
    `available: false` — never defaulted to "internal, low criticality",
    which would be a guess presented as a fact.

    A profile that exists with every field null *is* available: somebody
    opened the form and recorded that they do not know yet, which is an
    auditable state and not the same as never having been asked. Each
    non-null field contributes its own `Term`, so the reasoning can say
    which fact moved the score rather than only that something did.
    """
    if profile is None:
        return (
            {
                "available": False,
                "contribution": 0.0,
                "reason": (
                    "No risk profile has been recorded for this repository "
                    "(spec 21 §1) — what the application is has never been "
                    "stated, which is not the same as it being low risk."
                ),
            },
            [],
        )

    weights = policy.risk_profile
    terms: list[Term] = []

    if profile.get("internet_facing") and weights.internet_facing_points:
        terms.append(
            Term(
                key="risk_profile.internet_facing",
                label="Internet-facing application",
                contribution=weights.internet_facing_points,
                detail=(
                    "Recorded as accepting traffic from the public internet, "
                    f"worth {weights.internet_facing_points:g} points."
                ),
            )
        )

    classification = profile.get("data_classification")
    if classification:
        points = weights.data_classification_points.get(str(classification), 0.0)
        if points:
            terms.append(
                Term(
                    key="risk_profile.data_classification",
                    label=f"Handles {classification} data",
                    contribution=points,
                    detail=f"data_classification={classification}, worth {points:g} points.",
                )
            )

    criticality = profile.get("business_criticality")
    if criticality:
        points = weights.business_criticality_points.get(str(criticality), 0.0)
        if points:
            terms.append(
                Term(
                    key="risk_profile.business_criticality",
                    label=f"Business criticality: {criticality}",
                    contribution=points,
                    detail=f"business_criticality={criticality}, worth {points:g} points.",
                )
            )

    scope = list(profile.get("compliance_scope") or [])
    if scope and weights.compliance_scope_points_per_entry:
        points = weights.compliance_scope_points_per_entry * len(scope)
        terms.append(
            Term(
                key="risk_profile.compliance_scope",
                label=f"In scope for {', '.join(sorted(scope))}",
                contribution=points,
                detail=(
                    f"{len(scope)} regime(s) × "
                    f"{weights.compliance_scope_points_per_entry:g} points."
                ),
            )
        )

    return (
        {
            "available": True,
            "internet_facing": profile.get("internet_facing"),
            "data_classification": classification,
            "business_criticality": criticality,
            "compliance_scope": scope,
            "recorded_by": profile.get("updated_by") or None,
            "contribution": round(sum(t.contribution for t in terms), 2),
        },
        terms,
    )


def _governance_snapshot(
    reading: dict[str, Any] | None, policy: Policy
) -> tuple[dict[str, Any], list[Term]]:
    """Weak change governance, as part of what this repository *is* (spec 30 §4).

    Sits with the risk profile rather than with the finding terms, and the
    distinction is spec 21's: the profile carries context about what a
    repository is — its exposure, its data classification, its criticality —
    and how hard it is to get a bad change into it is exactly that kind of
    fact. The finding score carries what was found. Weak review controls do
    not make a SQL injection worse; they make this repository a worse place
    for one to be.

    **Only ever a penalty.** Spec 30 §4 expected strong governance to earn the
    reward side of spec 26 §2 for free. It cannot: branch protection is a
    switch, and spec 26 §2.3 refuses credit for switch-flipping because the
    fastest route to a good score must never be a setting.

    **Stale is unavailable, not old.** A reading more than two weeks old is
    about a repository that may have been reconfigured twice since, and
    scoring it would be worse than scoring nothing.
    """
    weights = policy.governance
    if reading is None:
        return (
            {
                "available": False,
                "contribution": 0.0,
                "reason": (
                    "No current reading of this repository's change controls "
                    "(spec 30 §1). Either the Insider Threat tab has not been "
                    "opened for it, or the last reading has gone stale — "
                    "neither is a statement that its governance is weak."
                ),
            },
            [],
        )

    read_controls = int(reading.get("controls_read") or 0)
    if read_controls < weights.minimum_controls:
        return (
            {
                "available": False,
                "contribution": 0.0,
                "controls_read": read_controls,
                "reason": (
                    f"Only {read_controls} control(s) could be read; below "
                    f"{weights.minimum_controls} that is not a posture. A "
                    "score over two controls is not a weaker version of a "
                    "score over nine."
                ),
            },
            [],
        )

    value = int(reading.get("governance_score") or 0)
    snapshot: dict[str, Any] = {
        "available": True,
        "governance_score": value,
        "source": reading.get("source"),
        "controls_read": read_controls,
        "read_at": reading.get("read_at"),
        "good_enough": weights.good_enough,
        "contribution": 0.0,
    }

    if value >= weights.good_enough or not weights.points_at_zero:
        # At or above the bar, nothing is added — and a repository does not
        # have to be perfect to get there. A term that could only be silenced
        # by a flawless configuration is one teams learn to ignore.
        return (snapshot, [])

    shortfall = (weights.good_enough - value) / weights.good_enough
    points = weights.points_at_zero * shortfall
    snapshot["contribution"] = round(points, 2)
    return (
        snapshot,
        [
            Term(
                key="risk_profile.governance",
                label="Weak change-governance controls",
                contribution=points,
                detail=(
                    f"Governance scores {value}/100 against a bar of "
                    f"{weights.good_enough}, adding {points:g} points. Weak "
                    "controls do not make a finding worse; they make this a "
                    "worse repository for one to be in."
                ),
                inputs={"governance_score": value},
            )
        ],
    )


def _exploitability_snapshot(
    matched: list[dict[str, Any]], *, db_configured: bool
) -> dict[str, Any]:
    """Public exploitation data for this decision's in-scope findings
    (spec 17 §5.4), sourced from `ThreatIntelMatch` (spec 17 §4).

    `matched` carries every scope-matching open finding that names a CVE,
    whether or not that CVE turned out to be KEV-listed — so "we checked and
    it isn't exploited" and "we never checked" are distinguishable even when
    the finding count is identical.
    """
    if not db_configured:
        return {
            "available": False,
            "contribution": 0.0,
            "reason": "No operational database is configured for this evaluation.",
        }
    kev_listed = [m for m in matched if m["in_kev"]]
    return {
        "available": True,
        "cve_matched_findings": len(matched),
        "kev_listed_findings": [
            {
                "finding_id": m["finding_id"],
                "cve_id": m["cve_id"],
                "severity": m["severity"],
                "boosted_to": m["boosted_to"],
                "kev_added_at": m["kev_added_at"],
            }
            for m in kev_listed
        ],
        "contribution": round(sum(m["boost"] for m in kev_listed), 2),
        "reason": (
            f"{len(matched)} open finding(s) name a CVE; none is in CISA's "
            "Known Exploited Vulnerabilities catalog."
            if matched and not kev_listed
            else (
                "No open finding in scope names a CVE — most SAST/IaC "
                "findings describe a code pattern, not a published "
                "vulnerability, and have no exploitability data available."
                if not matched
                else (
                    f"{len(kev_listed)} of {len(matched)} CVE-naming open "
                    "finding(s) are in CISA's KEV catalog."
                )
            )
        ),
    }


class OracleEngine:
    def __init__(
        self,
        catalog: Catalog,
        policy: Policy,
        store: KnowledgeStore | None = None,
        *,
        db: Database | None = None,
    ) -> None:
        self.catalog = catalog
        self.policy = policy
        # Optional on purpose (spec 11 §6): dampening is an adjustment on top
        # of a correct score. A deployment with no Knowledge Store, or one
        # whose store is unreadable, gets undampened scores rather than no
        # scores.
        self.store = store
        # Optional on the same principle (spec 17 §5.4): exploitability reads
        # `ThreatIntelMatch`, which lives in the operational database, not the
        # lake `self.catalog` already holds. A caller that has not wired one
        # up gets `exploitability: unavailable` rather than a crash — the
        # same shape every other missing input already takes.
        self.db = db

    # -- inputs ---------------------------------------------------------

    def _finding_counts(
        self, repo_full_name: str, *, for_gate: bool, dampened: list[str] | None = None
    ) -> tuple[dict[str, int], dict[str, int], dict[str, int], dict[str, int]]:
        """Open findings by severity, and the aged subset.

        `for_gate` excludes capabilities spec 14 §7 keeps out of PR and
        release gates — a host with an open port did not arrive with this pull
        request and will not leave with it.
        """
        statuses = ", ".join(f"'{s}'" for s in self.policy.statuses_considered)
        severities = ", ".join(f"'{s}'" for s in self.policy.severities_in_scope())

        excluded = ""
        if for_gate and self.policy.capabilities_excluded_from_gates:
            names = ", ".join(
                f"'{c}'" for c in self.policy.capabilities_excluded_from_gates
            )
            excluded = f"AND capability NOT IN ({names})"

        # Parameters are bound in the order their placeholders appear in the
        # SQL *text*, and this one's are in the SELECT clause — before the
        # WHERE. Getting that backwards silently asks for
        # `rule_id IN (<repo name>)`, which matches nothing and returns no
        # findings at all rather than erroring.
        dampened_clause = ""
        dampened_params: list[Any] = []
        if dampened:
            placeholders = ", ".join("?" for _ in dampened)
            dampened_clause = (
                f", count(*) FILTER (WHERE rule_id IN ({placeholders})) AS dampened"
            )
            dampened_params = list(dampened)
        params: list[Any] = [*dampened_params, repo_full_name]

        # Findings the maintainer has shipped no fix for (D-077). Gated on
        # `package_name` deliberately: a SAST finding has no `fixed_version`
        # and never will, so an unguarded check would read "no such field" as
        # "nobody can fix this" and quieten every injection finding in the
        # repository. The column position is fixed rather than appended after
        # `dampened_clause`, which is conditional -- an index that moves with
        # configuration is how the wrong number gets read as the right one.
        unfixable_clause = """
            , count(*) FILTER (
                  WHERE package_name IS NOT NULL AND trim(package_name) <> ''
                    AND coalesce(
                          json_extract_string(raw_finding_json, '$.fixed_version'), ''
                        ) = ''
              ) AS unfixable
        """

        rows = self.catalog.query(
            f"""
            SELECT severity, count(*) AS total{unfixable_clause}{dampened_clause}
            FROM findings
            WHERE asset_id = ?
              AND status IN ({statuses})
              AND severity IN ({severities})
              {excluded}
            GROUP BY severity
            """,
            params,
        )
        counts = {str(row[0]): int(row[1]) for row in rows}
        unfixable_counts = {str(row[0]): int(row[2]) for row in rows}
        dampened_counts = (
            {str(row[0]): int(row[3]) for row in rows} if dampened else {}
        )

        # Age is measured against first_seen_at, which only survives because
        # finding identity is anchored to code rather than line numbers
        # (D-001). Without that, every refactor would reset the clock and
        # nothing would ever look old.
        aged_rows = self.catalog.query(
            f"""
            SELECT severity, count(*)
            FROM findings
            WHERE asset_id = ?
              AND status IN ({statuses})
              {excluded}
              AND (
                    (severity = 'critical' AND first_seen_at <= ?)
                 OR (severity = 'high'     AND first_seen_at <= ?)
              )
            GROUP BY severity
            """,
            [
                repo_full_name,
                self._as_of - timedelta(days=30),
                self._as_of - timedelta(days=90),
            ],
        )
        aged = {str(severity): int(count) for severity, count in aged_rows}
        return counts, aged, dampened_counts, unfixable_counts

    def _insider_risk(
        self, repo_full_name: str, pr_number: int | None
    ) -> dict[str, Any] | None:
        """The Aegis score for the pull request under discussion (spec 06 §8).

        Deliberately scoped to *this* pull request, and only for a PR gate.
        Aegis scores a change by a person, and reaching for "the worst recent
        insider-risk score in this repo" would carry one contributor's signal
        into an unrelated colleague's decision — which is exactly the
        cross-pull-request aggregation spec 06 §9 forbids.

        Returns None when there is nothing to read, which the snapshot renders
        as an explicit "not available" rather than as zero.
        """
        if pr_number is None:
            return None

        rows = self.catalog.query(
            """
            SELECT insider_risk_score, recommendation, commit_sha, evaluated_at
            FROM insider_risk_signals
            WHERE repo_full_name = ? AND pr_number = ?
            ORDER BY evaluated_at DESC
            LIMIT 1
            """,
            [repo_full_name, pr_number],
        )
        if not rows:
            return None
        score, recommendation, commit_sha, evaluated_at = rows[0]
        return {
            "score": int(score),
            "recommendation": str(recommendation),
            "commit_sha": str(commit_sha),
            "evaluated_at": evaluated_at,
        }

    def _remediation_in_flight(self, repo_full_name: str) -> set[str]:
        """Findings with a Patchwork draft pull request open (spec 08 §9).

        spec 09 §5's discount lowers *urgency*, not risk: a fix in flight means
        somebody is on it, and the vulnerability is still there. That is why
        the modifier is a partial discount rather than an exclusion — a repo
        with ten open auto-fixes is not a safe repo, it is a repo with ten
        unmerged fixes.

        `human_edited` counts. A person took the draft and started working on
        it, which is *more* evidence of remediation in flight than an
        untouched one, not less.
        """
        rows = self.catalog.query(
            """
            SELECT finding_id
            FROM remediation_events
            WHERE repo_full_name = ?
              AND pr_status IN ('draft_open', 'human_edited')
            """,
            [repo_full_name],
        )
        return {str(row[0]) for row in rows}

    def _covered_counts(
        self, repo_full_name: str, covered: set[str]
    ) -> dict[str, int]:
        """Open findings per severity that already have a fix in flight."""
        if not covered:
            return {}
        placeholders = ", ".join("?" for _ in covered)
        rows = self.catalog.query(
            f"SELECT severity, count(*) FROM findings "
            f"WHERE finding_id IN ({placeholders}) "
            "AND asset_id = ? AND status = 'open' "
            "GROUP BY severity",
            [*sorted(covered), repo_full_name],
        )
        return {str(severity): int(count) for severity, count in rows}

    def _sscs_trust(self, repo_full_name: str) -> dict[str, Any] | None:
        """The most recent Atlas evidence for this repo (spec 07 §9).

        Repo-scoped rather than commit-scoped: a dependency tree does not
        change per pull request unless a manifest was touched, and pinning the
        lookup to the gated commit would report "no evidence" for every PR
        that did not happen to trigger an Atlas run.
        """
        rows = self.catalog.query(
            """
            SELECT trust_score, vulnerable_dependency_count, dependency_count,
                   commit_sha, evaluated_at
            FROM sscs_evidence
            WHERE repo_full_name = ?
            ORDER BY evaluated_at DESC
            LIMIT 1
            """,
            [repo_full_name],
        )
        if not rows:
            return None
        trust, vulnerable, total, commit_sha, evaluated_at = rows[0]
        if trust is None:
            # The scan resolved no dependencies, so there is no trust to
            # consume (spec 07 §5a). Treated exactly like no evidence at all:
            # Oracle records supply chain as not assessed rather than crediting
            # a repository that pinned nothing with a perfect score.
            return None
        return {
            "trust_score": int(trust),
            "vulnerable_dependency_count": int(vulnerable),
            "dependency_count": int(total),
            "commit_sha": str(commit_sha),
            "evaluated_at": evaluated_at,
        }

    def _dampened_rules(self, repo_full_name: str) -> dict[str, Any]:
        """Rules this repo has dismissed often enough, with reasons, to quieten.

        Returns `{}` when there is no store — the ordinary case for a
        deployment that has not accumulated any learnings yet, and not an
        error.
        """
        if self.store is None:
            return {}
        return dampened_rules(
            self.catalog,
            self.store,
            repo_full_name,
            threshold=self.policy.dampening.threshold,
            min_observations=self.policy.dampening.min_observations,
            as_of=self._as_of,
        )

    def _path_candidates(
        self, repo_full_name: str, *, for_gate: bool, covered: set[str]
    ) -> dict[str, list[dict[str, Any]]]:
        """Findings a person could close, worst and oldest first.

        Three exclusions, and each is about the instruction being actionable
        rather than about the arithmetic:

        - a finding with a fix already in flight is not something to go and do;
        - a finding with no upstream fix cannot be closed by this team at all
          (D-077), and telling them to close it would be advice they cannot
          take;
        - a dampened finding contributes a fraction of a finding to the score,
          so closing one saves less than the projection assumes.

        All three also happen to be the findings whose removal saves less than
        a whole unit, so excluding them keeps the published number
        conservative — the safe direction.
        """
        statuses = ", ".join(f"'{s}'" for s in self.policy.statuses_considered)
        severities = ", ".join(f"'{s}'" for s in self.policy.severities_in_scope())
        excluded = ""
        if for_gate and self.policy.capabilities_excluded_from_gates:
            names = ", ".join(
                f"'{c}'" for c in self.policy.capabilities_excluded_from_gates
            )
            excluded = f"AND capability NOT IN ({names})"

        rows = self.catalog.query(
            f"""
            SELECT finding_id, rule_id, title, severity, file_path
            FROM findings
            WHERE repo_full_name = ?
              AND status IN ({statuses})
              AND severity IN ({severities})
              AND NOT (
                  package_name IS NOT NULL AND trim(package_name) <> ''
                  AND coalesce(
                        json_extract_string(raw_finding_json, '$.fixed_version'), ''
                      ) = ''
              )
              {excluded}
            ORDER BY first_seen_at
            """,
            [repo_full_name],
        )
        dampened = self._dampened_rules(repo_full_name)
        candidates: dict[str, list[dict[str, Any]]] = {}
        for finding_id, rule_id, title, severity, file_path in rows:
            if str(rule_id) in dampened or str(finding_id) in covered:
                continue
            candidates.setdefault(str(severity), []).append(
                {
                    "finding_id": str(finding_id),
                    "rule_id": str(rule_id),
                    "title": str(title or rule_id),
                    "file_path": str(file_path) if file_path else None,
                }
            )
        return candidates

    def _forecast(self, repo_full_name: str, score: float) -> dict[str, Any]:
        """When this repository crosses a threshold on ageing alone (spec 26 §4).

        The age term escalates on a date, so a repository with a static
        backlog crosses a band on a day that is already computable. Saying it
        in advance is the difference between a verdict that changes overnight
        and one somebody saw coming.

        Deliberately one sentence and deliberately not a chart. It is a
        projection of a known curve over known ages — not a model — and it
        must not acquire the visual authority of one.
        """
        if score >= self.policy.no_go:
            return {"available": False, "reason": "Already at no_go."}

        rows = self.catalog.query(
            """
            SELECT severity, first_seen_at FROM findings
            WHERE repo_full_name = ? AND status = 'open'
              AND severity IN ('critical', 'high')
            """,
            [repo_full_name],
        )
        if not rows:
            return {"available": False, "reason": "Nothing open that ages into a penalty."}

        thresholds = {
            "critical": (30, self.policy.age.over_30_days_critical),
            "high": (90, self.policy.age.over_90_days_high),
        }
        # (days until it ages, points it will add)
        upcoming: list[tuple[int, float, str]] = []
        for severity, first_seen in rows:
            days, points = thresholds[str(severity)]
            if not isinstance(first_seen, datetime) or not points:
                continue
            crosses_in = days - (self._as_of - first_seen).days
            if crosses_in > 0:
                upcoming.append((crosses_in, points, str(severity)))

        if not upcoming:
            return {
                "available": True,
                "crosses_in_days": None,
                "reason": "Everything that will age into a penalty already has.",
            }

        upcoming.sort()
        running = score
        for index, (days, points, _severity) in enumerate(upcoming):
            running += points
            if running >= self.policy.no_go:
                counted = index + 1
                return {
                    "available": True,
                    "crosses_in_days": days,
                    "findings_involved": counted,
                    "reaches": "no_go",
                    "reason": (
                        f"With no changes, this repository reaches no_go in "
                        f"{days} day(s) as {counted} finding(s) cross their age "
                        "threshold."
                    ),
                }
        return {
            "available": True,
            "crosses_in_days": None,
            "reason": (
                "Ageing alone does not reach no_go from here — everything open "
                "would have to age and it would still be below the threshold."
            ),
        }

    def _verified_fixes(self, repo_full_name: str) -> tuple[int, int]:
        """`(verified, merged)` for this repository (spec 25 §3)."""
        if not self.catalog.all_files("remediation_events"):
            return (0, 0)
        rows = self.catalog.query(
            """
            SELECT
                count(*) FILTER (WHERE verification_outcome = 'verified_fixed'),
                count(*) FILTER (WHERE pr_status = 'merged')
            FROM remediation_events WHERE repo_full_name = ?
            """,
            [repo_full_name],
        )
        if not rows:
            return (0, 0)
        return (int(rows[0][0] or 0), int(rows[0][1] or 0))

    def _within_target(self, repo_full_name: str) -> tuple[int, int]:
        """`(fixed inside its window, fixed with a window)` — spec 24 §2.

        Deliberately about findings that were **closed**, not open ones that
        are merely not late yet. The first draft credited the latter, and it
        was wrong in a way the golden scoring tests caught: a repository full
        of brand-new criticals is inside every window by construction and had
        done nothing to earn it. A credit that rewards the clock rather than
        the team is exactly what spec 26 §2's evidence-not-switches rule
        exists to prevent.

        Windowed to the last 90 days for `mean_time_to_fix`'s reason: an
        all-time rate is dominated by whatever happened when the platform was
        switched on and stops responding to the present.
        """
        since = self._as_of - timedelta(days=90)
        rows = self.catalog.query(
            """
            SELECT count(*) FILTER (WHERE resolved_at <= due_at), count(*)
            FROM findings
            WHERE repo_full_name = ? AND status = 'fixed'
              AND due_at IS NOT NULL AND resolved_at IS NOT NULL
              AND resolved_at >= ?
            """,
            [repo_full_name, since],
        )
        if not rows:
            return (0, 0)
        return (int(rows[0][0] or 0), int(rows[0][1] or 0))

    def _overdue(self, repo_full_name: str, for_gate: bool) -> tuple[int, int]:
        """`(overdue, with_a_target)` over this decision's in-scope findings.

        Counts findings, not groups: the score is built from finding counts
        everywhere else, and switching unit here would make the term
        incomparable with the band weights it is added to.

        `due_at` is compared against the engine's own `_as_of`, not against
        wall-clock time, so re-evaluating a past decision reproduces it
        (spec 09 §10).
        """
        statuses = ", ".join(f"'{s}'" for s in self.policy.statuses_considered)
        severities = ", ".join(f"'{s}'" for s in self.policy.severities_in_scope())
        excluded = ""
        if for_gate and self.policy.capabilities_excluded_from_gates:
            names = ", ".join(
                f"'{c}'" for c in self.policy.capabilities_excluded_from_gates
            )
            excluded = f"AND capability NOT IN ({names})"
        rows = self.catalog.query(
            f"""
            SELECT count(*) FILTER (WHERE due_at <= ?) AS overdue,
                   count(*) AS with_target
            FROM findings
            WHERE repo_full_name = ?
              AND status IN ({statuses})
              AND severity IN ({severities})
              AND due_at IS NOT NULL
              {excluded}
            """,
            [self._as_of, repo_full_name],
        )
        if not rows:
            return (0, 0)
        return (int(rows[0][0] or 0), int(rows[0][1] or 0))

    def _reachability(self, repo_full_name: str) -> tuple[dict[str, Any] | None, int]:
        """The stored import analysis, and how many findings sit in dead files.

        `None` when the operational DB is not wired in or no analysis has run
        — both are `available: false`, which is the honest answer either way.
        Deliberately not distinguished: there is nothing different to tell an
        admin about the two.
        """
        if self.db is None:
            return (None, 0)
        with self.db.session() as session:
            row = (
                session.execute(
                    select(ReachabilityReport)
                    .join(
                        RepoOnboarding,
                        RepoOnboarding.id == ReachabilityReport.repo_onboarding_id,
                    )
                    .where(RepoOnboarding.github_repo_full_name == repo_full_name)
                )
                .scalars()
                .first()
            )
        if row is None:
            return (None, 0)

        paths: list[str] = [str(p) for p in (row.orphaned_paths or [])]
        report: dict[str, Any] = {
            "language": row.language,
            "commit_sha": row.commit_sha,
            "orphaned_paths": paths,
            "files_analysed": row.files_analysed,
            "files_unparseable": row.files_unparseable,
        }
        if not paths:
            return (report, 0)

        # Counted against the same scope the score uses, not against every
        # finding ever recorded: discounting a resolved finding would move a
        # score for work already done.
        severities = ", ".join(f"'{s}'" for s in self.policy.severities_in_scope())
        placeholders = ", ".join("?" for _ in paths)
        rows = self.catalog.query(
            f"""
            SELECT count(*) FROM findings
            WHERE asset_id = ? AND status = 'open'
              AND severity IN ({severities})
              AND file_path IN ({placeholders})
            """,
            [repo_full_name, *paths],
        )
        return (report, int(rows[0][0]) if rows else 0)

    def _blast_radius(self, repo_full_name: str) -> tuple[list[str], dict[str, int] | None]:
        """This repo's finding packages, and the portfolio map (spec 19 §2.4).

        The map is built on every evaluation rather than cached. It is one
        grouped query over `findings`, and a cache would have to be
        invalidated by every ingestion — the staleness window that buys is
        worse than the query it saves, which is the same trade D-016 already
        made for the portfolio aggregate.

        `None` for the map only when the query itself cannot run. An empty
        map is *available* and contributes nothing: "no package in this
        portfolio is carried by five repositories" is a real answer.
        """
        rows = self.catalog.query(
            """
            SELECT DISTINCT lower(trim(package_name)) FROM findings
            WHERE asset_id = ? AND status = 'open'
              AND package_name IS NOT NULL AND trim(package_name) <> ''
            """,
            [repo_full_name],
        )
        return ([str(row[0]) for row in rows], blast_radius.build(self.catalog))

    def _governance(self, repo_full_name: str) -> dict[str, Any] | None:
        """The last reading of this repository's change controls (spec 30 §4).

        `None` when the database is not configured, when nothing has read
        them, or when the reading has gone stale — all three render as
        `available: false`, which is the honest answer in every case: the
        platform does not currently know how this repository is governed.
        """
        if self.db is None:
            return None
        with self.db.session() as session:
            return governance.stored(session, repo_full_name, now=self._as_of)

    def _risk_profile(self, repo_full_name: str) -> dict[str, Any] | None:
        """This repository's recorded asset context (spec 21 §1.4).

        `None` when `self.db` is not configured *or* when no profile row
        exists — both render as `available: false`, which is the honest
        answer either way: nobody has stated what this application is.
        Deliberately not distinguished further, unlike exploitability's
        db-configured check, because there is no useful third thing to say
        to an admin whose deployment has no operational DB wired into
        Oracle at all.
        """
        if self.db is None:
            return None
        with self.db.session() as session:
            row = (
                session.execute(
                    select(RiskProfile)
                    .join(
                        RepoOnboarding,
                        RepoOnboarding.id == RiskProfile.repo_onboarding_id,
                    )
                    .where(RepoOnboarding.github_repo_full_name == repo_full_name)
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

    def _exploitable_findings(
        self, repo_full_name: str, *, for_gate: bool
    ) -> list[dict[str, Any]]:
        """Scope-matching open findings that name a CVE, with KEV status
        (spec 17 §5.4). `[]` when `self.db` is not configured — the caller
        renders that as `exploitability: unavailable`, not as zero findings.

        Scope mirrors `_finding_counts`: the same statuses, severities and
        gate-excluded capabilities, so a finding this method boosts is always
        one the band contributions above already counted.
        """
        if self.db is None:
            return []

        statuses = ", ".join(f"'{s}'" for s in self.policy.statuses_considered)
        severities = ", ".join(f"'{s}'" for s in self.policy.severities_in_scope())
        excluded = ""
        if for_gate and self.policy.capabilities_excluded_from_gates:
            names = ", ".join(f"'{c}'" for c in self.policy.capabilities_excluded_from_gates)
            excluded = f"AND capability NOT IN ({names})"

        rows = self.catalog.query(
            f"""
            SELECT finding_id, rule_id, title, severity
            FROM findings
            WHERE asset_id = ?
              AND status IN ({statuses})
              AND severity IN ({severities})
              {excluded}
            """,
            [repo_full_name],
        )

        by_cve: dict[str, list[dict[str, Any]]] = {}
        for finding_id, rule_id, title, severity in rows:
            cve_id = extract_cve(str(rule_id), str(title))
            if cve_id is None:
                continue
            by_cve.setdefault(cve_id, []).append(
                {"finding_id": str(finding_id), "severity": str(severity)}
            )
        if not by_cve:
            return []

        with self.db.session() as session:
            matches = {
                row.cve_id: row
                for row in session.execute(
                    select(ThreatIntelMatch).where(ThreatIntelMatch.cve_id.in_(by_cve))
                ).scalars()
            }

        weights = self.policy.severity_weights
        matched: list[dict[str, Any]] = []
        for cve_id, findings in sorted(by_cve.items()):
            match = matches.get(cve_id)
            in_kev = bool(match and match.in_kev)
            for finding in findings:
                severity = finding["severity"]
                boosted_to = _NEXT_SEVERITY_BAND.get(severity, severity)
                boost = (
                    max(0.0, weights.get(boosted_to, 0.0) - weights.get(severity, 0.0))
                    if in_kev
                    else 0.0
                )
                matched.append(
                    {
                        "finding_id": finding["finding_id"],
                        "cve_id": cve_id,
                        "severity": severity,
                        "in_kev": in_kev,
                        "boosted_to": boosted_to if in_kev else None,
                        "boost": boost,
                        "kev_added_at": (
                            match.kev_added_at.isoformat()
                            if in_kev and match and match.kev_added_at
                            else None
                        ),
                    }
                )
        return matched

    # -- scoring --------------------------------------------------------

    def evaluate(
        self,
        repo_full_name: str,
        *,
        decision_type: str = "portfolio",
        commit_sha: str = "",
        pr_number: int | None = None,
        release_tag: str | None = None,
        as_of: datetime | None = None,
        decision_id: str | None = None,
    ) -> Decision:
        if decision_type not in DECISION_TYPES:
            raise ValueError(
                f"Unknown decision_type {decision_type!r}. "
                f"Expected one of: {', '.join(DECISION_TYPES)}."
            )

        self._as_of = as_of or utcnow()
        for_gate = decision_type in ("pr_gate", "release_gate")

        # Which rules this repo has earned the right to quieten (spec 11
        # §6.1). Looked up before the counts so the query can split each
        # severity band into dampened and undampened in one pass.
        dampened = self._dampened_rules(repo_full_name)
        counts, aged, dampened_counts, unfixable_counts = self._finding_counts(
            repo_full_name, for_gate=for_gate, dampened=sorted(dampened)
        )
        covered = self._remediation_in_flight(repo_full_name)
        covered_counts = self._covered_counts(repo_full_name, covered)
        terms: list[Term] = []

        # 1. Findings, worst band first so the reasoning reads in the order a
        #    person would care about.
        factor = self.policy.dampening.dampening_factor
        # Kept for the path-to-green projection (spec 26 §1): it has to start
        # from the same effective counts the score was built from, not from
        # the raw ones, or the arithmetic it publishes will not match.
        effective_by_severity: dict[str, float] = {}
        for severity in reversed(self.policy.severities_in_scope()):
            count = counts.get(severity, 0)
            weight = self.policy.severity_weights.get(severity, 0.0)
            if count == 0 or weight == 0:
                continue

            # A dismissed-often rule counts for less, not for nothing. Applied
            # to the *count* inside the curve rather than to the band's weight
            # outside it, because only some of a band's findings are dampened
            # and halving the whole band would quieten the real ones too.
            quiet = dampened_counts.get(severity, 0)
            # A fix already in flight lowers urgency, not risk (spec 09 §5).
            # Capped at the undampened remainder so a finding that is both
            # dampened and being fixed cannot be discounted twice.
            in_flight = max(0, min(covered_counts.get(severity, 0), count - quiet))
            discount = self.policy.remediation_discount
            # No fix exists upstream (D-077). Capped at what is left after the
            # first two for the same reason they cap each other: a finding
            # discounted twice would be quieter than the sum of its reasons.
            unfixable_factor = self.policy.unfixable.factor
            unfixable = max(
                0, min(unfixable_counts.get(severity, 0), count - quiet - in_flight)
            )
            effective = (
                (count - quiet - in_flight - unfixable)
                + quiet * (1.0 - factor)
                + in_flight * (1.0 - discount)
                + unfixable * (1.0 - unfixable_factor)
            )
            contribution = _band_contribution(weight, effective)
            effective_by_severity[severity] = effective

            plural = "s" if count != 1 else ""
            detail = f"{weight:g} × log2(1 + {count}) = {contribution:.1f}"
            label = f"{count} open {severity} finding{plural}"
            if quiet or in_flight or (unfixable and unfixable_factor):
                parts = []
                if quiet:
                    parts.append(f"{quiet} from dampened rules at {1.0 - factor:g}×")
                    label += f", {quiet} from a dampened rule"
                if in_flight:
                    parts.append(f"{in_flight} being fixed at {1.0 - discount:g}×")
                    label += f", {in_flight} with a fix in flight"
                if unfixable and unfixable_factor:
                    parts.append(
                        f"{unfixable} with no upstream fix at {1.0 - unfixable_factor:g}×"
                    )
                    label += f", {unfixable} with no upstream fix"
                detail = (
                    f"{weight:g} × log2(1 + {effective:g}) = {contribution:.1f} "
                    f"({'; '.join(parts)})"
                )

            terms.append(
                Term(
                    key=f"findings.{severity}",
                    label=label,
                    contribution=contribution,
                    detail=detail,
                    inputs={
                        "count": count,
                        "weight": weight,
                        "dampened": quiet,
                        "remediation_in_flight": in_flight,
                        "no_upstream_fix": unfixable,
                        "effective_count": round(effective, 2),
                    },
                )
            )

        # 2. Aging. An unresolved critical is worse at 90 days than at 9, and
        #    this is what stops "accepted for now" becoming permanent.
        for severity, days, points in (
            ("critical", 30, self.policy.age.over_30_days_critical),
            ("high", 90, self.policy.age.over_90_days_high),
        ):
            count = aged.get(severity, 0)
            if count == 0 or points == 0:
                continue
            terms.append(
                Term(
                    key=f"age.{severity}",
                    label=f"{count} {severity} finding{'s' if count != 1 else ''} "
                    f"open over {days} days",
                    contribution=points,
                    detail=f"+{points:g} (flat, once any {severity} passes {days} days)",
                    inputs={"count": count, "days": days},
                )
            )

        # 3. Insider risk (spec 06). Only for a pull-request gate, and only
        #    about that pull request — see _insider_risk.
        insider = self._insider_risk(repo_full_name, pr_number if for_gate else None)
        if insider and insider["score"] > 0:
            contribution = insider["score"] * self.policy.insider_risk_multiplier
            terms.append(
                Term(
                    key="insider_risk",
                    label=f"insider-risk score {insider['score']} on this pull request",
                    contribution=contribution,
                    detail=(
                        f"{insider['score']} × "
                        f"{self.policy.insider_risk_multiplier:g} = {contribution:.1f}"
                    ),
                    inputs={"score": insider["score"]},
                )
            )

        # 4. Supply-chain trust (spec 07). A penalty for the distance below
        #    perfect trust, capped so a bad dependency tree cannot dominate a
        #    decision about the code someone actually wrote.
        sscs = self._sscs_trust(repo_full_name)
        if sscs and sscs["trust_score"] < 100:
            shortfall = 100 - sscs["trust_score"]
            contribution = float(min(shortfall, self.policy.sscs_penalty_cap))
            terms.append(
                Term(
                    key="sscs_trust",
                    label=f"supply-chain trust {sscs['trust_score']}/100",
                    contribution=contribution,
                    detail=(
                        f"min(100 - {sscs['trust_score']}, "
                        f"{self.policy.sscs_penalty_cap:g}) = {contribution:.1f}"
                    ),
                    inputs={
                        "trust_score": sscs["trust_score"],
                        "vulnerable_dependency_count": sscs[
                            "vulnerable_dependency_count"
                        ],
                    },
                )
            )

        # 5. Exploitability (spec 17 §5.4). A KEV-listed finding is boosted
        #    one severity band's worth of points — an additive term, not a
        #    move between bands, so the tested band-curve arithmetic above is
        #    untouched by whether this category is even configured.
        exploitable = self._exploitable_findings(repo_full_name, for_gate=for_gate)
        for entry in exploitable:
            if not entry["in_kev"] or entry["boost"] <= 0:
                continue
            terms.append(
                Term(
                    key=f"exploitability.{entry['finding_id']}",
                    label=(
                        f"{entry['cve_id']} ({entry['severity']}) is CISA "
                        "KEV-listed"
                    ),
                    contribution=entry["boost"],
                    detail=(
                        f"{entry['severity']} boosted to {entry['boosted_to']}: "
                        f"weight({entry['boosted_to']}) - weight({entry['severity']}) "
                        f"= {entry['boost']:.1f}"
                    ),
                    inputs={
                        "cve_id": entry["cve_id"],
                        "severity": entry["severity"],
                        "boosted_to": entry["boosted_to"],
                        "kev_added_at": entry["kev_added_at"],
                    },
                )
            )

        # 6. Risk profile (spec 21 §1.4). What the application *is*, as
        #    opposed to what was found in it — recorded by an admin, and the
        #    only category here no scanner can produce. Additive per recorded
        #    fact, so the reasoning names which one moved the score.
        risk_profile = self._risk_profile(repo_full_name)
        terms.extend(_risk_profile_snapshot(risk_profile, self.policy)[1])

        # 7. Blast radius (spec 19 §2.4). The only input here derived from
        #    other repositories: a vulnerable package five other teams also
        #    carry is a different problem from the same package in one leaf
        #    service. Capped hard — the map behind it is package-name
        #    matching, not version resolution, and a deliberately approximate
        #    signal should not be able to swing a verdict.
        radius_packages, radius_map = self._blast_radius(repo_full_name)
        radius_snapshot, radius_points = blast_radius.snapshot(
            radius_packages,
            radius_map,
            min_dependents=self.policy.blast_radius.min_dependents,
            points_per_package=self.policy.blast_radius.points_per_package,
            source=blast_radius.resolution(self.catalog),
        )
        radius_points = min(radius_points, self.policy.blast_radius.cap)
        if radius_points:
            concentrated = radius_snapshot["concentrated_packages"]
            radius_snapshot["contribution"] = round(radius_points, 2)
            terms.append(
                Term(
                    key="blast_radius",
                    label="Packages many repositories share",
                    contribution=radius_points,
                    detail=(
                        f"{len(concentrated)} package(s) with open findings in "
                        f"{self.policy.blast_radius.min_dependents}+ repositories: "
                        + ", ".join(
                            f"{p['package_name']} ({p['dependent_repos']})"
                            for p in concentrated[:5]
                        )
                        + (" …" if len(concentrated) > 5 else "")
                    ),
                    inputs={"packages": concentrated},
                )
            )

        # 7b. Change governance (spec 30 §4). With the profile rather than
        #     with the findings: how hard it is to get a bad change in is a
        #     fact about what this repository *is*, which is what the profile
        #     carries. Never a credit — branch protection is a switch, and
        #     spec 26 §2.3 refuses to reward switch-flipping.
        governance_snapshot, governance_terms = _governance_snapshot(
            self._governance(repo_full_name), self.policy
        )
        terms.extend(governance_terms)

        # 8. Reachability (spec 19 §2.1). A discount, not a penalty: a
        #    finding in a file nothing imports is lower priority than the
        #    same finding on a request path. The only negative term in the
        #    model, and the reason the analysis behind it refuses to guess.
        reach_report, orphaned_findings = self._reachability(repo_full_name)
        reach_snapshot, reach_terms = _reachability_snapshot(
            reach_report, orphaned_findings, self.policy
        )
        terms.extend(reach_terms)

        # 9. Overdue (spec 24 §2.4). A date, not a curve: this fires once,
        #    when a deadline set by policy or by CISA has passed, and stays
        #    silent for a repository whose backlog is inside its windows.
        overdue_count, with_target = self._overdue(repo_full_name, for_gate)
        overdue_snapshot, overdue_terms = _overdue_snapshot(
            overdue_count, with_target, self.policy
        )
        terms.extend(overdue_terms)

        # 10. What the team earned back (spec 26 §2). The only terms that
        #     subtract for something somebody did, and the last ones applied
        #     so the cap and the critical floor act on a settled score.
        posture_snapshot, posture_terms = _posture_snapshot(
            coverage=regression.coverage(self.catalog, repo_full_name, now=self._as_of),
            verified=self._verified_fixes(repo_full_name),
            within_target=self._within_target(repo_full_name),
            open_criticals=counts.get("critical", 0),
            policy=self.policy,
        )
        # The floor is applied here rather than inside the snapshot because it
        # needs the score the rest of the model produced.
        if posture_terms and posture_snapshot.get("floored_by_open_critical"):
            before = sum(term.contribution for term in terms)
            allowed = max(0.0, before - self.policy.review_recommended)
            applied = sum(-term.contribution for term in posture_terms)
            if applied > allowed:
                factor = (allowed / applied) if applied else 0.0
                posture_terms = [
                    Term(
                        key=term.key,
                        label=term.label,
                        contribution=term.contribution * factor,
                        detail=(
                            f"{term.detail} Reduced: credits may not take a "
                            "repository below the review threshold while a "
                            "critical is open."
                        ),
                        inputs=term.inputs,
                    )
                    for term in posture_terms
                ]
                posture_snapshot["applied"] = round(allowed, 2)
                posture_snapshot["contribution"] = round(-allowed, 2)
        terms.extend(posture_terms)

        raw_score = sum(term.contribution for term in terms)
        score = max(0, min(100, round(raw_score)))

        # 10. What would make this go (spec 26 §1). Computed only when it has
        #     something to say: a repository already at `go` gets an empty
        #     path that says so, rather than a list of work with no purpose.
        if raw_score >= self.policy.review_recommended:
            path = _path_to_green(
                effective=effective_by_severity,
                candidates=self._path_candidates(
                    repo_full_name, for_gate=for_gate, covered=covered
                ),
                raw_score=raw_score,
                policy=self.policy,
            )
        else:
            path = {
                "available": True,
                "steps": [],
                "findings_not_listed": 0,
                "reaches": self.policy.recommendation_for(raw_score),
                "reachable": True,
                "note": "Already below the review threshold — nothing to clear.",
            }

        snapshot = self._build_snapshot(
            terms=terms,
            counts=counts,
            aged=aged,
            raw_score=raw_score,
            score=score,
            for_gate=for_gate,
            insider=insider,
            sscs=sscs,
            dampened=dampened,
            covered=covered,
            exploitable=exploitable,
            risk_profile=risk_profile,
            blast_radius_snapshot=radius_snapshot,
            governance_snapshot=governance_snapshot,
            reachability_snapshot=reach_snapshot,
            overdue_snapshot=overdue_snapshot,
            posture_snapshot=posture_snapshot,
            forecast=self._forecast(repo_full_name, raw_score),
            path_to_green=path,
        )

        decision = Decision(
            decision_id=decision_id or str(uuid.uuid4()),
            repo_full_name=repo_full_name,
            decision_type=decision_type,
            commit_sha=commit_sha,
            pr_number=pr_number,
            release_tag=release_tag,
            overall_risk_score=score,
            recommendation=self.policy.recommendation_for(score),
            reasoning=render_reasoning(snapshot),
            inputs_snapshot=snapshot,
            policy_version=self.policy.version,
            evaluated_at=self._as_of,
        )
        logger.info(
            "Oracle %s for %s: %s",
            scrub(decision_type),
            scrub(repo_full_name),
            scrub(decision.summary()),
        )
        return decision

    def _build_snapshot(
        self,
        *,
        terms: list[Term],
        counts: dict[str, int],
        aged: dict[str, int],
        raw_score: float,
        score: int,
        for_gate: bool,
        insider: dict[str, Any] | None = None,
        sscs: dict[str, Any] | None = None,
        dampened: dict[str, Any] | None = None,
        covered: set[str] | None = None,
        exploitable: list[dict[str, Any]] | None = None,
        risk_profile: dict[str, Any] | None = None,
        blast_radius_snapshot: dict[str, Any] | None = None,
        governance_snapshot: dict[str, Any] | None = None,
        reachability_snapshot: dict[str, Any] | None = None,
        overdue_snapshot: dict[str, Any] | None = None,
        posture_snapshot: dict[str, Any] | None = None,
        forecast: dict[str, Any] | None = None,
        path_to_green: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Every input considered, including the ones with nothing to say.

        spec 09 §9 requires that a category with no data appears with an
        explicit null rather than being omitted. "We looked and there was
        nothing" and "we never looked" produce identical scores and completely
        different levels of trust, and a snapshot that drops the category
        cannot tell you which one you are reading.
        """
        return {
            "policy_version": self.policy.version,
            "decision_scope": {
                "for_gate": for_gate,
                "statuses_considered": list(self.policy.statuses_considered),
                "minimum_severity": self.policy.minimum_severity,
                "capabilities_excluded": (
                    list(self.policy.capabilities_excluded_from_gates) if for_gate else []
                ),
            },
            "findings": {
                "counts_by_severity": {
                    severity: counts.get(severity, 0)
                    for severity in self.policy.severities_in_scope()
                },
                "aged": dict(sorted(aged.items())),
                "curve": self.policy.curve,
            },
            # Present whether or not there is anything to say, with an
            # explicit null and a reason when there is not — so a reader can
            # tell "no insider risk" from "insider risk was never consulted".
            "insider_risk": _insider_snapshot(
                insider, for_gate=for_gate, multiplier=self.policy.insider_risk_multiplier
            ),
            "sscs_trust": _sscs_snapshot(sscs, cap=self.policy.sscs_penalty_cap),
            "remediation_in_flight": _remediation_snapshot(
                covered, discount=self.policy.remediation_discount
            ),
            "false_positive_dampening": _dampening_snapshot(
                dampened,
                store_configured=self.store is not None,
                factor=self.policy.dampening.dampening_factor,
                min_observations=self.policy.dampening.min_observations,
            ),
            "exploitability": _exploitability_snapshot(
                exploitable or [], db_configured=self.db is not None
            ),
            "reachability": reachability_snapshot
            or _reachability_snapshot(None, 0, self.policy)[0],
            "overdue_findings": overdue_snapshot
            or _overdue_snapshot(0, 0, self.policy)[0],
            "posture_credits": posture_snapshot
            or {
                "available": False,
                "contribution": 0.0,
                "reason": "Not computed for this decision.",
            },
            # Neither of these contributes to the score. One says what would
            # make it fall, the other when it will rise on its own.
            "forecast": forecast or {"available": False, "reason": "Not computed."},
            # Not a modifier category — it contributes nothing to the score.
            # It is the inverse of the score, and it lives in the snapshot so
            # a decision carries its own answer to "what now" rather than
            # making a caller recompute one that could disagree.
            "path_to_green": path_to_green
            or {"available": False, "steps": [], "reason": "Not computed."},
            "risk_profile": _risk_profile_snapshot(risk_profile, self.policy)[0],
            "blast_radius": blast_radius_snapshot
            or blast_radius.snapshot([], None)[0],
            # spec 09 §9: a category with nothing to say still appears, so a
            # reader can tell "not weighed" from "weighed and found nothing".
            "governance": governance_snapshot
            or _governance_snapshot(None, self.policy)[0],
            "terms": [
                {
                    "key": term.key,
                    "label": term.label,
                    "contribution": round(term.contribution, 2),
                    "detail": term.detail,
                    "inputs": term.inputs,
                }
                for term in terms
            ],
            "totals": {
                # Unclamped, so the portfolio can still rank two repos that
                # both clamp to 100. Without it, everything past the ceiling
                # ties and sorting by risk stops working.
                "raw_score": round(raw_score, 2),
                "overall_risk_score": score,
                "clamped": raw_score > 100,
            },
            "thresholds": {
                "no_go": self.policy.no_go,
                "review_recommended": self.policy.review_recommended,
            },
        }


def render_reasoning(snapshot: dict[str, Any]) -> str:
    """Build the human-readable explanation from the snapshot alone.

    Deliberately a pure function of the snapshot, and deliberately not an LLM
    narrative (spec 09 §5). Because it can only read what the snapshot
    contains, "the reasoning has no hidden inputs" is enforced by construction
    rather than promised in a docstring.
    """
    totals = snapshot["totals"]
    score = totals["overall_risk_score"]
    thresholds = snapshot["thresholds"]
    terms = snapshot["terms"]

    if score >= thresholds["no_go"]:
        opening = f"No-go at {score}/100."
    elif score >= thresholds["review_recommended"]:
        opening = f"Review recommended at {score}/100."
    else:
        opening = f"Go at {score}/100."

    # Computed before the zero-terms branch, and used by both: a finding-free
    # decision can still have Atlas or Aegis data to report, and the old
    # unconditional "every other category is unavailable" was wrong exactly
    # in that case — restated to say what is actually known, not guessed.
    unavailable = [name for name in MODIFIER_CATEGORIES if not snapshot[name]["available"]]

    if not terms:
        sentence = (
            f"{opening} Nothing scored: there are no open findings in scope "
            "for this decision."
        )
        if unavailable:
            sentence += (
                " Not yet consulted: " + ", ".join(unavailable) + " — see "
                "inputs_snapshot for why."
            )
        else:
            sentence += " Every other input category was consulted and had nothing to add."
        return sentence

    parts = [f"{term['label']} (+{term['contribution']:.1f})" for term in terms]
    body = "; ".join(parts)

    sentence = f"{opening} {body}."
    if totals["clamped"]:
        sentence += (
            f" Raw score {totals['raw_score']:.1f} was clamped to 100; the "
            "unclamped value is kept for ranking."
        )
    if unavailable:
        sentence += (
            " Not yet consulted: " + ", ".join(unavailable) + " — these are "
            "recorded as unavailable rather than zero, so this score is a "
            "partial picture by construction."
        )
    return sentence
