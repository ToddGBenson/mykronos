"""The approval policy file, parsed (spec 34 §3).

Loaded the way the Oracle policy is: from a reviewed file, refused loudly when
missing or malformed, and never replaced by a built-in default - an approval
rule nobody reviewed is exactly what this policy exists to prevent.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


class PolicyError(ValueError):
    pass


class Independence(StrEnum):
    DISTINCT_PRINCIPAL = "distinct_principal"
    DISTINCT_INSTANCE = "distinct_instance"
    OUTSIDE_LINEAGE = "outside_lineage"
    FRESH_CONTEXT = "fresh_context"
    DIFFERENT_FAMILY = "different_family"
    HUMAN = "human"


@dataclass(frozen=True)
class ApproverClass:
    kind: str  # human | agent
    delegation_required: bool = False


@dataclass(frozen=True)
class Tier:
    name: str
    approvers: tuple[ApproverClass, ...]
    quorum: int
    independence: frozenset[Independence]
    cooling_off_hours: float = 0.0
    break_glass: bool = False

    def admits(self, kind: str) -> ApproverClass | None:
        return next((a for a in self.approvers if a.kind == kind), None)


@dataclass(frozen=True)
class Duty:
    name: str
    tier_by: str
    tiers: dict[str, Tier]
    requesters: frozenset[str] = frozenset({"human", "agent"})
    #: What a platform-started reviewer is told to check (spec 34 §4.3).
    reviewer_instructions: str = ""


@dataclass(frozen=True)
class DelegationDefaults:
    default_sampling: float = 0.2
    suspend_below_agreement: float = 0.9
    agreement_window: int = 20
    unreviewed_sample_deadline_days: int = 14
    max_days: int = 90


@dataclass(frozen=True)
class RiskAcceptanceLimits:
    """What may be accepted at all (spec 33 §2.1), apart from who approves it."""

    max_duration_days: dict[str, int] = field(
        default_factory=lambda: {"critical": 30, "high": 90, "medium": 180, "low": 365}
    )
    max_renewals: dict[str, int] = field(
        default_factory=lambda: {"critical": 1, "high": 2, "medium": 4, "low": 99}
    )
    review_lead_days: int = 14
    refuse_kev_listed: bool = True
    refuse_critical_operational_requirement: bool = True


@dataclass(frozen=True)
class ApprovalPolicy:
    version: str
    single_operator: bool
    request_ttl_hours: float
    duties: dict[str, Duty]
    delegations: DelegationDefaults = field(default_factory=DelegationDefaults)
    risk_acceptance: RiskAcceptanceLimits = field(default_factory=RiskAcceptanceLimits)

    def duty(self, name: str) -> Duty:
        try:
            return self.duties[name]
        except KeyError as exc:
            raise PolicyError(f"No duty '{name}' in approval policy {self.version}.") from exc


def _tier(name: str, raw: dict[str, Any], duty: str) -> Tier:
    approvers = tuple(
        ApproverClass(
            kind=str(a.get("kind")),
            delegation_required=str(a.get("delegation", "")) == "required",
        )
        for a in raw.get("approvers") or []
    )
    if not approvers:
        raise PolicyError(f"{duty}.{name}: a tier with no approvers can never be satisfied.")
    for a in approvers:
        if a.kind not in ("human", "agent"):
            raise PolicyError(
                f"{duty}.{name}: approver kind '{a.kind}'. Automation may execute an "
                "approved action but is never an approver (spec 34 §3.1)."
            )
        if a.kind == "agent" and not a.delegation_required:
            raise PolicyError(
                f"{duty}.{name}: an agent approver must require a delegation. The "
                "operator's trust in an agent is an explicit grant (spec 34 §5), "
                "never a standing rule in a file."
            )
    try:
        rules = frozenset(Independence(r) for r in raw.get("independence") or [])
    except ValueError as exc:
        raise PolicyError(f"{duty}.{name}: unknown independence rule: {exc}") from exc
    quorum = int(raw.get("quorum", 1))
    if quorum < 1:
        raise PolicyError(f"{duty}.{name}: quorum must be at least 1.")
    return Tier(
        name=name,
        approvers=approvers,
        quorum=quorum,
        # Implied everywhere and not removable (spec 34 §3.1).
        independence=rules | {Independence.DISTINCT_PRINCIPAL},
        cooling_off_hours=float(raw.get("cooling_off_hours", 0) or 0),
        break_glass=bool(raw.get("break_glass", False)),
    )


def parse_policy(document: Any) -> ApprovalPolicy:
    if not isinstance(document, dict):
        raise PolicyError("Approval policy must be a mapping.")
    version = str(document.get("version") or "").strip()
    if not version:
        raise PolicyError("Approval policy has no `version`.")
    duties: dict[str, Duty] = {}
    for name, raw in (document.get("duties") or {}).items():
        tiers = {t: _tier(t, traw or {}, name) for t, traw in (raw.get("tiers") or {}).items()}
        if not tiers:
            raise PolicyError(f"Duty '{name}' has no tiers.")
        duties[name] = Duty(
            name=name,
            tier_by=str(raw.get("tier_by", "fixed")),
            tiers=tiers,
            requesters=frozenset(raw.get("requesters") or ("human", "agent")),
            reviewer_instructions=str(raw.get("reviewer_instructions") or ""),
        )
    ra = document.get("risk_acceptance") or {}
    refuse = ra.get("refuse") or {}
    limits = RiskAcceptanceLimits()
    ra_limits = RiskAcceptanceLimits(
        max_duration_days={
            str(k): int(v)
            for k, v in (ra.get("max_duration_days") or limits.max_duration_days).items()
        },
        max_renewals={
            str(k): int(v) for k, v in (ra.get("max_renewals") or limits.max_renewals).items()
        },
        review_lead_days=int(ra.get("review_lead_days", limits.review_lead_days)),
        refuse_kev_listed=bool(refuse.get("kev_listed", True)),
        refuse_critical_operational_requirement=bool(
            refuse.get("critical_operational_requirement", True)
        ),
    )
    d = document.get("delegations") or {}
    return ApprovalPolicy(
        version=version,
        single_operator=str(document.get("separation_of_duties", "")) == "single_operator",
        request_ttl_hours=float(document.get("request_ttl_hours", 168)),
        duties=duties,
        delegations=DelegationDefaults(
            default_sampling=float(d.get("default_sampling", 0.2)),
            suspend_below_agreement=float(d.get("suspend_below_agreement", 0.9)),
            agreement_window=int(d.get("agreement_window", 20)),
            unreviewed_sample_deadline_days=int(d.get("unreviewed_sample_deadline_days", 14)),
            max_days=int(d.get("max_days", 90)),
        ),
        risk_acceptance=ra_limits,
    )


def load_policy(path: Path) -> ApprovalPolicy:
    if not path.is_file():
        raise PolicyError(
            f"No approval policy at {path}. Governed actions cannot be approved "
            "without one, and a built-in default would be rules nobody reviewed."
        )
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PolicyError(f"Approval policy at {path} is not valid YAML: {exc}") from exc
    policy = parse_policy(document)
    logger.info("Loaded approval policy %s from %s", policy.version, path)
    return policy


@lru_cache(maxsize=4)
def cached_policy(path: Path) -> ApprovalPolicy:
    return load_policy(path)
