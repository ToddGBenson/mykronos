"""Loading and validating the Oracle scoring policy (spec 09 §5).

The policy is versioned configuration rather than code, so that an admin can
read exactly how a score was computed and reproduce it by hand. This module's
job is to make sure a malformed policy fails at load — loudly, at startup —
rather than silently producing wrong risk decisions for a week.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from mykronos.schemas import Severity

logger = logging.getLogger(__name__)

SUPPORTED_CURVES = {"log2"}


class PolicyError(ValueError):
    """The policy file is unusable. Always fatal — a wrong policy silently
    applied is worse than no policy at all."""


@dataclass(frozen=True)
class AgePolicy:
    over_30_days_critical: float
    over_90_days_high: float


@dataclass(frozen=True)
class DampeningPolicy:
    threshold: float
    dampening_factor: float
    #: Reasoned dismissals required before a rule is dampened at all
    #: (spec 11 §6.1). Without it, one dismissal of a rule seen once is a 100%
    #: false-positive rate and a single click quietens the rule.
    min_observations: int


@dataclass(frozen=True)
class RiskProfilePolicy:
    """Weights for the asset facts an admin records (spec 21 §1.4).

    Per-field rather than one scalar, because each is an independent fact
    worth naming separately in the reasoning — "internet-facing: +10" and
    "regulated data: +15" tell an admin which choice moved the score, where
    a single combined number would not.
    """

    internet_facing_points: float
    data_classification_points: dict[str, float]
    business_criticality_points: dict[str, float]
    #: Unbounded on purpose: an asset in four regimes really does carry four
    #: kinds of exposure, and a cap would hide the fourth.
    compliance_scope_points_per_entry: float


@dataclass(frozen=True)
class UnfixableDampening:
    """How much less an unremediable finding counts (spec 09 §5, D-077).

    A CVE the maintainer has not patched is real risk and must still score —
    this dampens, it does not exclude. What it stops is the score measuring
    somebody else's release schedule: sixteen unfixable criticals pinned
    TheHub at 100/100, so the gate said the same thing whether the team fixed
    everything they could or nothing at all, which is the state in which a
    gate stops carrying information.

    Applies only to findings that name a package. A SAST finding has no
    `fixed_version` and never will; absence there means "no such field",
    not "upstream has shipped nothing", and dampening every injection finding
    on that reading would be the worst bug this file could have.
    """

    factor: float


@dataclass(frozen=True)
class BlastRadiusPolicy:
    """Weights for portfolio-wide package concentration (spec 19 §2.4).

    Two numbers rather than one, because they answer different questions.
    `min_dependents` is where "used by several teams" becomes "concentrated",
    a judgement about this portfolio's size; `points_per_package` is what that
    concentration is worth, a judgement about how much it should move a score.
    Folding them together would make one un-tunable without the other.
    """

    min_dependents: int
    points_per_package: float
    #: Flat rather than unbounded. Ten concentrated packages in one repository
    #: is a supply-chain problem SSCS trust already scores at length; this
    #: category is about the fact of concentration, and letting it run away
    #: would let one dependency-heavy repo dominate the portfolio ranking on a
    #: signal that is deliberately approximate.
    cap: float


@dataclass(frozen=True)
class ReachabilityPolicy:
    """How much a finding in un-imported code is discounted (spec 19 §2.1).

    The only *negative* weight in the policy, and the only one where being
    wrong quietly lowers a score rather than raising it. Small and capped for
    that reason: the analysis is Python-only and answers "does anything
    import this file", not "does this code run", and a discount large enough
    to move a verdict would be trusting it further than it can see.
    """

    orphaned_discount_per_finding: float
    discount_cap: float


@dataclass(frozen=True)
class RemediationTargets:
    """How long a finding of each severity may stay open (spec 24 §2.2).

    A target is not the age curve. Age escalates continuously and describes
    drift; a target is a date this organisation set for itself, and a finding
    inside its window is not late however old it is. Keeping them separate is
    what lets a repository with a large but in-policy backlog score better
    than one with three findings nobody looked at.

    A null for a severity means "not work" rather than "due immediately" —
    `info` is the expected case, and defaulting it to zero days would make
    every repository permanently overdue on findings nobody intends to fix.
    """

    #: severity -> days from first_seen_at, or None for "no target".
    days: dict[str, int | None]

    @property
    def configured(self) -> bool:
        """Whether any target is set at all.

        Drives `available` in Oracle's snapshot: a deployment that has not
        adopted targets reports the category as unavailable rather than
        reporting every finding on track, which would read as compliance.
        """
        return any(value is not None for value in self.days.values())

    def due_at(self, severity: str, first_seen_at: datetime) -> datetime | None:
        target = self.days.get(severity)
        if target is None:
            return None
        return first_seen_at + timedelta(days=target)


@dataclass(frozen=True)
class Policy:
    version: str
    curve: str
    severity_weights: dict[str, float]

    insider_risk_multiplier: float
    sscs_penalty_cap: float
    remediation_discount: float
    age: AgePolicy
    dampening: DampeningPolicy
    risk_profile: RiskProfilePolicy
    blast_radius: BlastRadiusPolicy
    reachability: ReachabilityPolicy
    unfixable: UnfixableDampening
    remediation_targets: RemediationTargets

    no_go: float
    review_recommended: float

    minimum_severity: str
    statuses_considered: tuple[str, ...]
    capabilities_excluded_from_gates: tuple[str, ...]

    #: Verbatim source, echoed by GET /api/oracle/policy so an admin can see
    #: precisely what is running rather than a re-serialisation of it.
    raw: dict[str, Any]

    def recommendation_for(self, score: float) -> str:
        if score >= self.no_go:
            return "no_go"
        if score >= self.review_recommended:
            return "review_recommended"
        return "go"

    def severities_in_scope(self) -> list[str]:
        order = [s.value for s in Severity]
        floor = order.index(self.minimum_severity)
        return order[floor:]


def _require(mapping: dict[str, Any], key: str, where: str) -> Any:
    if key not in mapping:
        raise PolicyError(f"Policy is missing '{key}' under {where}.")
    return mapping[key]


def _number(value: Any, where: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise PolicyError(f"{where} must be a number, got {value!r}.")
    return float(value)


def parse_policy(document: dict[str, Any]) -> Policy:
    if not isinstance(document, dict):
        raise PolicyError("Policy must be a mapping at the top level.")

    version = str(_require(document, "version", "the policy root"))

    findings = _require(document, "findings", "the policy root")
    curve = str(_require(findings, "curve", "findings"))
    if curve not in SUPPORTED_CURVES:
        raise PolicyError(
            f"Unsupported findings curve {curve!r}. Supported: "
            f"{', '.join(sorted(SUPPORTED_CURVES))}. A curve this code does not "
            "implement would be silently ignored, which is worse than refusing."
        )

    raw_weights = _require(findings, "weights", "findings")
    known = {s.value for s in Severity}
    unknown = set(raw_weights) - known
    if unknown:
        raise PolicyError(
            f"Policy weights name unknown severities: {', '.join(sorted(unknown))}. "
            f"Known: {', '.join(sorted(known))}."
        )
    missing = known - set(raw_weights)
    if missing:
        # An absent weight would default to zero and silently stop scoring a
        # whole severity band.
        raise PolicyError(
            f"Policy is missing weights for: {', '.join(sorted(missing))}. Every "
            "severity needs an explicit weight, including 0 — an omitted band "
            "would silently stop counting."
        )
    weights = {name: _number(value, f"weights.{name}") for name, value in raw_weights.items()}

    modifiers = _require(document, "modifiers", "the policy root")
    age_raw = _require(modifiers, "finding_age", "modifiers")
    dampening_raw = _require(modifiers, "false_positive_dampening", "modifiers")
    # Optional, unlike the modifiers above: a deployment running the policy
    # file from before spec 21 keeps working, with every risk-profile weight
    # at zero — the category still appears in the snapshot and still reports
    # `available`, it simply contributes nothing until weights are set. A
    # hard `_require` here would have made this spec's policy change
    # mandatory before the code could load at all.
    profile_raw = modifiers.get("risk_profile") or {}
    # Optional for the same reason, one spec later: a policy file from
    # before spec 19 §2.4 loads, with the category available and worth
    # zero, rather than refusing to load at all.
    blast_raw = modifiers.get("blast_radius") or {}
    reach_raw = modifiers.get("reachability") or {}
    # Optional like the two above: a policy file from before this loads,
    # with the factor at zero, and every score stays exactly as it was.
    unfixable_raw = modifiers.get("unfixable_dampening") or {}

    # Optional, on the same principle as the modifier blocks above: a policy
    # file from before spec 24 loads, with no targets, and nothing is overdue
    # until somebody sets one.
    targets_raw = document.get("remediation_targets") or {}
    unknown_targets = set(targets_raw) - known
    if unknown_targets:
        raise PolicyError(
            f"remediation_targets names unknown severities: "
            f"{', '.join(sorted(unknown_targets))}. Known: {', '.join(sorted(known))}."
        )
    target_days: dict[str, int | None] = {}
    for name in known:
        value = targets_raw.get(name)
        if value is None:
            target_days[name] = None
            continue
        number = _number(value, f"remediation_targets.{name}")
        if number <= 0:
            raise PolicyError(
                f"remediation_targets.{name} must be a positive number of days, "
                f"got {number:g}. Use null for 'no target' — zero would make "
                "every finding of this severity overdue the moment it is found."
            )
        target_days[name] = int(number)

    thresholds = _require(document, "thresholds", "the policy root")
    no_go = _number(_require(thresholds, "no_go", "thresholds"), "thresholds.no_go")
    review = _number(
        _require(thresholds, "review_recommended", "thresholds"),
        "thresholds.review_recommended",
    )
    if review >= no_go:
        raise PolicyError(
            f"thresholds.review_recommended ({review}) must be below no_go "
            f"({no_go}); otherwise no score can ever land on 'review'."
        )

    scope = document.get("scope") or {}
    minimum_severity = str(scope.get("minimum_severity", "low"))
    if minimum_severity not in known:
        raise PolicyError(f"scope.minimum_severity {minimum_severity!r} is not a severity.")

    return Policy(
        version=version,
        curve=curve,
        severity_weights=weights,
        insider_risk_multiplier=_number(
            _require(modifiers["insider_risk"], "multiplier", "modifiers.insider_risk"),
            "modifiers.insider_risk.multiplier",
        ),
        sscs_penalty_cap=_number(
            _require(modifiers["sscs_trust"], "penalty_cap", "modifiers.sscs_trust"),
            "modifiers.sscs_trust.penalty_cap",
        ),
        remediation_discount=_number(
            _require(
                modifiers["remediation_in_flight"], "discount", "modifiers.remediation_in_flight"
            ),
            "modifiers.remediation_in_flight.discount",
        ),
        age=AgePolicy(
            over_30_days_critical=_number(
                age_raw.get("over_30_days_critical", 0), "finding_age.over_30_days_critical"
            ),
            over_90_days_high=_number(
                age_raw.get("over_90_days_high", 0), "finding_age.over_90_days_high"
            ),
        ),
        dampening=DampeningPolicy(
            threshold=_number(dampening_raw.get("threshold", 0.5), "dampening.threshold"),
            dampening_factor=_number(
                dampening_raw.get("dampening_factor", 0.5), "dampening.dampening_factor"
            ),
            min_observations=int(
                _number(
                    dampening_raw.get("min_observations", 3),
                    "dampening.min_observations",
                )
            ),
        ),
        risk_profile=RiskProfilePolicy(
            internet_facing_points=_number(
                profile_raw.get("internet_facing_points", 0),
                "risk_profile.internet_facing_points",
            ),
            data_classification_points={
                str(key): _number(value, f"risk_profile.data_classification_points.{key}")
                for key, value in (profile_raw.get("data_classification_points") or {}).items()
            },
            business_criticality_points={
                str(key): _number(value, f"risk_profile.business_criticality_points.{key}")
                for key, value in (profile_raw.get("business_criticality_points") or {}).items()
            },
            compliance_scope_points_per_entry=_number(
                profile_raw.get("compliance_scope_points_per_entry", 0),
                "risk_profile.compliance_scope_points_per_entry",
            ),
        ),
        blast_radius=BlastRadiusPolicy(
            min_dependents=int(
                _number(blast_raw.get("min_dependents", 5), "blast_radius.min_dependents")
            ),
            points_per_package=_number(
                blast_raw.get("points_per_package", 0),
                "blast_radius.points_per_package",
            ),
            cap=_number(blast_raw.get("cap", 0), "blast_radius.cap"),
        ),
        reachability=ReachabilityPolicy(
            orphaned_discount_per_finding=_number(
                reach_raw.get("orphaned_discount_per_finding", 0),
                "reachability.orphaned_discount_per_finding",
            ),
            discount_cap=_number(
                reach_raw.get("discount_cap", 0), "reachability.discount_cap"
            ),
        ),
        remediation_targets=RemediationTargets(days=target_days),
        unfixable=UnfixableDampening(
            factor=_number(
                unfixable_raw.get("factor", 0), "unfixable_dampening.factor"
            )
        ),
        no_go=no_go,
        review_recommended=review,
        minimum_severity=minimum_severity,
        statuses_considered=tuple(scope.get("statuses_considered", ["open"])),
        capabilities_excluded_from_gates=tuple(
            scope.get("capabilities_excluded_from_gates", [])
        ),
        raw=document,
    )


def load_policy(path: Path) -> Policy:
    if not path.is_file():
        raise PolicyError(
            f"No Oracle policy at {path}. Risk decisions cannot be made without "
            "one, and defaulting to a built-in policy would mean scoring against "
            "weights nobody reviewed."
        )
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PolicyError(f"Oracle policy at {path} is not valid YAML: {exc}") from exc

    policy = parse_policy(document)
    logger.info("Loaded Oracle policy version %s from %s", policy.version, path)
    return policy


@lru_cache(maxsize=8)
def cached_policy(path: Path) -> Policy:
    """Policies are immutable per version, so caching is safe.

    spec 09 §10: an evaluation in progress keeps whichever version it started
    with. Caching by path plus an explicit reload is how that holds — the file
    changing under a running evaluation must not change its result midway.
    """
    return load_policy(path)
