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

from mykronos.lake.catalog import Catalog
from mykronos.oracle.policy import Policy
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

DECISION_TYPES = ("pr_gate", "release_gate", "portfolio")


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


def _band_contribution(weight: float, count: int) -> float:
    """`weight × log2(1 + count)` — the saturation fix (D-018).

    Linear weighting pinned every vulnerable repo at the clamp: three open
    criticals reached 100, and so did three hundred, so the portfolio could
    not be ranked and the trend line flatlined. The curve keeps the score
    strictly increasing in findings while flattening, so the gap between "a
    few" and "some" matters more than between "many" and "very many" — which
    is how a person triages.
    """
    if count <= 0:
        return 0.0
    return weight * math.log2(1 + count)


class OracleEngine:
    def __init__(self, catalog: Catalog, policy: Policy) -> None:
        self.catalog = catalog
        self.policy = policy

    # -- inputs ---------------------------------------------------------

    def _finding_counts(
        self, repo_full_name: str, *, for_gate: bool
    ) -> tuple[dict[str, int], dict[str, int]]:
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

        rows = self.catalog.query(
            f"""
            SELECT severity, count(*)
            FROM findings
            WHERE repo_full_name = ?
              AND status IN ({statuses})
              AND severity IN ({severities})
              {excluded}
            GROUP BY severity
            """,
            [repo_full_name],
        )
        counts = {str(severity): int(count) for severity, count in rows}

        # Age is measured against first_seen_at, which only survives because
        # finding identity is anchored to code rather than line numbers
        # (D-001). Without that, every refactor would reset the clock and
        # nothing would ever look old.
        aged_rows = self.catalog.query(
            f"""
            SELECT severity, count(*)
            FROM findings
            WHERE repo_full_name = ?
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
        return counts, aged

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

        counts, aged = self._finding_counts(repo_full_name, for_gate=for_gate)
        terms: list[Term] = []

        # 1. Findings, worst band first so the reasoning reads in the order a
        #    person would care about.
        for severity in reversed(self.policy.severities_in_scope()):
            count = counts.get(severity, 0)
            weight = self.policy.severity_weights.get(severity, 0.0)
            if count == 0 or weight == 0:
                continue
            contribution = _band_contribution(weight, count)
            terms.append(
                Term(
                    key=f"findings.{severity}",
                    label=f"{count} open {severity} finding{'s' if count != 1 else ''}",
                    contribution=contribution,
                    detail=f"{weight:g} × log2(1 + {count}) = {contribution:.1f}",
                    inputs={"count": count, "weight": weight},
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

        raw_score = sum(term.contribution for term in terms)
        score = max(0, min(100, round(raw_score)))

        snapshot = self._build_snapshot(
            terms=terms,
            counts=counts,
            aged=aged,
            raw_score=raw_score,
            score=score,
            for_gate=for_gate,
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
            "Oracle %s for %s: %s", decision_type, repo_full_name, decision.summary()
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
            # Not yet available. Present, explicitly null, with the phase that
            # will fill them in — so a reader can tell "no insider risk" from
            # "insider risk was never consulted".
            "insider_risk": {
                "available": False,
                "score": None,
                "contribution": 0.0,
                "reason": "Aegis is not implemented yet (spec 06, Phase 4).",
            },
            "sscs_trust": {
                "available": False,
                "trust_score": None,
                "contribution": 0.0,
                "reason": "Atlas is not implemented yet (spec 07, Phase 4).",
            },
            "remediation_in_flight": {
                "available": False,
                "covered_findings": None,
                "contribution": 0.0,
                "reason": "Patchwork is not implemented yet (spec 08, Phase 6).",
            },
            "false_positive_dampening": {
                "available": False,
                "dampened_rules": None,
                "contribution": 0.0,
                "reason": "The Knowledge Store is not implemented yet (spec 11, Phase 5).",
            },
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

    if not terms:
        return (
            f"{opening} Nothing scored: there are no open findings in scope for "
            "this decision. Every other input category is unavailable — see "
            "inputs_snapshot for which, and why."
        )

    parts = [f"{term['label']} (+{term['contribution']:.1f})" for term in terms]
    body = "; ".join(parts)

    unavailable = [
        name
        for name in (
            "insider_risk",
            "sscs_trust",
            "remediation_in_flight",
            "false_positive_dampening",
        )
        if not snapshot[name]["available"]
    ]

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
