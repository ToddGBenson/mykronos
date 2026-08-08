"""Loading and validating the Oracle scoring policy (spec 09 §5).

The policy is versioned configuration rather than code, so that an admin can
read exactly how a score was computed and reproduce it by hand. This module's
job is to make sure a malformed policy fails at load — loudly, at startup —
rather than silently producing wrong risk decisions for a week.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
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
