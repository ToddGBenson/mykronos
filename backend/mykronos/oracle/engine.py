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

from mykronos.knowledge.dampening import dampened_rules
from mykronos.knowledge.store import KnowledgeStore
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


class OracleEngine:
    def __init__(
        self,
        catalog: Catalog,
        policy: Policy,
        store: KnowledgeStore | None = None,
    ) -> None:
        self.catalog = catalog
        self.policy = policy
        # Optional on purpose (spec 11 §6): dampening is an adjustment on top
        # of a correct score. A deployment with no Knowledge Store, or one
        # whose store is unreadable, gets undampened scores rather than no
        # scores.
        self.store = store

    # -- inputs ---------------------------------------------------------

    def _finding_counts(
        self, repo_full_name: str, *, for_gate: bool, dampened: list[str] | None = None
    ) -> tuple[dict[str, int], dict[str, int], dict[str, int]]:
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

        rows = self.catalog.query(
            f"""
            SELECT severity, count(*) AS total{dampened_clause}
            FROM findings
            WHERE repo_full_name = ?
              AND status IN ({statuses})
              AND severity IN ({severities})
              {excluded}
            GROUP BY severity
            """,
            params,
        )
        counts = {str(row[0]): int(row[1]) for row in rows}
        dampened_counts = (
            {str(row[0]): int(row[2]) for row in rows} if dampened else {}
        )

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
        return counts, aged, dampened_counts

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
            "AND repo_full_name = ? AND status = 'open' "
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
        counts, aged, dampened_counts = self._finding_counts(
            repo_full_name, for_gate=for_gate, dampened=sorted(dampened)
        )
        covered = self._remediation_in_flight(repo_full_name)
        covered_counts = self._covered_counts(repo_full_name, covered)
        terms: list[Term] = []

        # 1. Findings, worst band first so the reasoning reads in the order a
        #    person would care about.
        factor = self.policy.dampening.dampening_factor
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
            effective = (
                (count - quiet - in_flight)
                + quiet * (1.0 - factor)
                + in_flight * (1.0 - discount)
            )
            contribution = _band_contribution(weight, effective)

            plural = "s" if count != 1 else ""
            detail = f"{weight:g} × log2(1 + {count}) = {contribution:.1f}"
            label = f"{count} open {severity} finding{plural}"
            if quiet or in_flight:
                parts = []
                if quiet:
                    parts.append(f"{quiet} from dampened rules at {1.0 - factor:g}×")
                    label += f", {quiet} from a dampened rule"
                if in_flight:
                    parts.append(f"{in_flight} being fixed at {1.0 - discount:g}×")
                    label += f", {in_flight} with a fix in flight"
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

        raw_score = sum(term.contribution for term in terms)
        score = max(0, min(100, round(raw_score)))

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
        insider: dict[str, Any] | None = None,
        sscs: dict[str, Any] | None = None,
        dampened: dict[str, Any] | None = None,
        covered: set[str] | None = None,
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
