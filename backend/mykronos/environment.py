"""Environmental CVSS: which facts about the system a score may rest on
(TheHub #60827, S5 of epic #60822).

`cvss.py` is arithmetic: give it a vector and an `Environment` and it returns
the standard's number. This module decides what goes into that `Environment`,
and the whole point of it is the things it refuses to put there.

**Facts, not settings.** Every input becomes a `Fact`: one metric, one value,
where it came from (`source_kind`, `source_id`), whether a machine saw it or a
person said it (`tier`), who, when, until when, and whether it was applied. A
fact that was not applied is returned anyway, with the reason, because "the
gate would lower this, but nobody has seen it answer 401 for sixteen days" is
the most useful sentence the record page can show.

**The core rule** (design, "Core rule (S5)"):

1. No fact -> `X`, which is the base value.
2. A raising fact always applies.
3. A lowering fact applies only when it is *observed* (machine-collected,
   fresh within `freshness.observation_days`) or, for a Security Requirement
   (CR/IR/AR) only, *declared and confirmed* within
   `freshness.declaration_confirmed_days`. Lowering MAV/MPR/MAC needs an
   observation. A contradicted fact never applies: a fresh observation
   `surfaces.CONTRADICTED_BY` names, a control whose checking capability has
   an open finding in its category, or an open secrets finding against a
   token gate.
4. Exploitability modifiers never raise above the base vector. `cvss.score`
   already enforces that (#60823); here it only changes the label, so the
   reader is told the fact was capped rather than seeing it silently ignored.
5. Every fact is returned, applied or not, with its reason.

The mappings themselves (sensitivity to CR, exposure to MAV, the gate to MPR,
the disabled CWE-class pairings to MAC, the windows) are judgements and live
in `environment-map-v1.yaml`, reviewed as governance policy.

**Two stages.** `build_context` resolves everything that does not depend on
the finding: one list of candidate facts per repository, with freshness and
contradiction already decided. Its hash is the `ScoringContext` id, and is
what lets a rescore that changed nothing write nothing. `resolve` then places
one finding: which surface it is in (`surface_match.surface_for`), whether
its own capability, path, CWE and base vector let each candidate apply, and
which fact wins where two speak to one metric (the most severe, so a raising
fact is never outvoted).

**Recompute** is `rescore(repo)`, driven by a debounced per-repository dirty
flag (`mark_dirty`) that ingest, vector refresh and every write to a surface,
control, risk profile, public endpoint or observation set, drained after each
compaction; and by the daily `environment` job, which is the only thing that
notices a fact *lapsing* and so the only thing that raises a score back.

**ControlObservation (S4, #918) may not be installed.** It is feature-detected
on the model. Without it, observed facts are simply absent, and every lowering
of an exploitability metric is reported as waiting on evidence.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from functools import lru_cache
from itertools import chain
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import event, select
from sqlalchemy.orm import Session

from mykronos import control_observations, cvss, cvss_vectors, surface_match
from mykronos.cvss_vectors import VectorChoice, VectorSource
from mykronos.db import models
from mykronos.db.models import (
    EnvironmentalScore,
    RepoControl,
    RepoOnboarding,
    RepoSurface,
    RiskProfile,
    ScoringContext,
    ThreatIntelMatch,
)
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

#: S4's observation register, when it is installed (#918). Feature-detected
#: rather than imported so this module works, and says so, without it.
ControlObservation: Any = getattr(models, "ControlObservation", None)

SECURITY_REQUIREMENTS = ("CR", "IR", "AR")
EXPLOITABILITY = ("MAV", "MAC", "MPR", "MUI")

#: The only observation states that establish anything (host_controls).
_EVIDENCE_STATES = ("pass", "fail")

#: Severity order of each metric's values, most severe first. "Most severe"
#: is how two facts about one metric are reconciled.
_ORDER: dict[str, tuple[str, ...]] = {
    "CR": ("H", "M", "L"),
    "IR": ("H", "M", "L"),
    "AR": ("H", "M", "L"),
    "MAV": ("N", "A", "L", "P"),
    "MAC": ("L", "H"),
    "MPR": ("N", "L", "H"),
    "MUI": ("N", "R"),
}
_BASE_KEY = {"MAV": "AV", "MAC": "AC", "MPR": "PR", "MUI": "UI"}

#: CVSS 3.1 qualitative bands, and the scanner's severity scale.
BANDS = ("none", "low", "medium", "high", "critical")
_SEVERITIES = ("info", "low", "medium", "high", "critical")

#: How long a repository must have been quiet before a dirty flag is drained,
#: so a burst of writes (a manifest sync touching twenty rows) is one rescore.
DEBOUNCE_SECONDS = 30.0


# ---------------------------------------------------------------------------
# Policy (environment-map-v1.yaml)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GatePolicy:
    control_kind: str = "perimeter_gate"
    from_value: str = "N"
    to_value: str = "L"
    evidence: str = "anonymous_401"
    evidence_vantages: tuple[str, ...] = ("internet",)
    not_for_capabilities: tuple[str, ...] = ("secrets",)
    exempt_paths: tuple[str, ...] = ()


@dataclass(frozen=True)
class MacPairing:
    name: str
    cwes: frozenset[str]
    value: str
    evidence: str | None
    evidence_vantages: tuple[str, ...] = ()


@dataclass(frozen=True)
class Policy:
    """The mapping judgements. An empty `Policy` maps nothing, so every score
    is its base: the safe direction for a missing or unreadable file."""

    version: str = ""
    observation_days: int = 14
    declaration_days: int = 90
    cr_by_sensitivity: Mapping[str, str] = field(default_factory=dict)
    cr_by_classification: Mapping[str, str] = field(default_factory=dict)
    ir_by_sensitivity: Mapping[str, str] = field(default_factory=dict)
    ir_compliance: str | None = None
    ar_by_criticality: Mapping[str, str] = field(default_factory=dict)
    never: Mapping[str, frozenset[str]] = field(default_factory=dict)
    mav_by_exposure: Mapping[str, str] = field(default_factory=dict)
    mav_profile_not_internet_facing: str | None = None
    mav_tool_image: str | None = None
    mav_evidence: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    gate: GatePolicy | None = None
    mac_pairings: tuple[MacPairing, ...] = ()


def parse_policy(document: Mapping[str, Any]) -> Policy:
    """Read the YAML document. Unknown values are dropped, never guessed."""
    fresh = document.get("freshness") or {}
    reqs = document.get("security_requirements") or {}
    mav = document.get("modified_attack_vector") or {}
    mpr = (document.get("modified_privileges_required") or {}).get("perimeter_gate") or {}
    mac = (document.get("modified_attack_complexity") or {}).get("pairings") or []

    def levels(raw: Any) -> dict[str, str]:
        if not isinstance(raw, Mapping):
            return {}
        return {
            str(k).lower(): str(v).upper()
            for k, v in raw.items()
            if str(v).upper() in ("H", "M", "L")
        }

    def av(raw: Any) -> str | None:
        value = str(raw).upper() if raw else ""
        return value if value in ("N", "A", "L", "P") else None

    never = {
        metric.upper(): frozenset(
            str(v).upper() for v in (reqs.get(metric) or {}).get("never") or []
        )
        for metric in ("cr", "ir", "ar")
    }
    gate = None
    if mpr and mpr.get("enabled", False):
        gate = GatePolicy(
            control_kind=str(mpr.get("control_kind") or "perimeter_gate"),
            from_value=str(mpr.get("from") or "N").upper(),
            to_value=str(mpr.get("to") or "L").upper(),
            evidence=str(mpr.get("evidence") or "anonymous_401"),
            evidence_vantages=tuple(str(v) for v in mpr.get("evidence_vantages") or ()),
            not_for_capabilities=tuple(str(v) for v in mpr.get("not_for_capabilities") or ()),
            exempt_paths=tuple(str(v) for v in mpr.get("exempt_paths") or ()),
        )
    pairings = tuple(
        MacPairing(
            name=str(p.get("name") or ""),
            cwes=frozenset(str(c).upper() for c in p.get("cwes") or ()),
            value=str(p.get("value") or "H").upper(),
            evidence=str(p["evidence"]) if p.get("evidence") else None,
            evidence_vantages=tuple(str(v) for v in p.get("evidence_vantages") or ()),
        )
        for p in mac
        if isinstance(p, Mapping) and p.get("enabled", False)
    )
    evidence = mav.get("evidence") or {}
    return Policy(
        version=str(document.get("version") or ""),
        observation_days=int(fresh.get("observation_days", 14)),
        declaration_days=int(fresh.get("declaration_confirmed_days", 90)),
        cr_by_sensitivity=levels((reqs.get("cr") or {}).get("by_sensitivity")),
        cr_by_classification=levels((reqs.get("cr") or {}).get("by_classification")),
        ir_by_sensitivity=levels((reqs.get("ir") or {}).get("by_sensitivity")),
        ir_compliance=(levels({"x": (reqs.get("ir") or {}).get("compliance_scope")}).get("x")),
        ar_by_criticality=levels((reqs.get("ar") or {}).get("by_criticality")),
        never=never,
        mav_by_exposure={
            str(k).lower(): v
            for k, raw in (mav.get("by_exposure") or {}).items()
            if (v := av(raw)) is not None
        },
        mav_profile_not_internet_facing=av(mav.get("profile_not_internet_facing")),
        mav_tool_image=av(mav.get("tool_image")),
        mav_evidence={
            str(k).upper(): tuple(str(a) for a in (v or ()))
            for k, v in (evidence.items() if isinstance(evidence, Mapping) else ())
        },
        gate=gate,
        mac_pairings=pairings,
    )


@lru_cache(maxsize=4)
def load_policy(path: Path | None = None) -> Policy:
    """The mapping file, or an empty policy that maps nothing.

    Absent or unreadable is logged and scored as base everywhere. Refusing to
    start would make a policy file a hard dependency of the record page, and
    guessing mappings would be lowering on nobody's judgement.
    """
    if path is None:
        from mykronos.config import get_settings

        path = get_settings().environment_map_path
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        logger.warning("Environment map unreadable at %s; every score stays at its base", path)
        return Policy()
    if not isinstance(document, Mapping):
        return Policy()
    return parse_policy(document)


# ---------------------------------------------------------------------------
# Facts
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Fact:
    """One statement about one metric, and what became of it."""

    metric: str
    value: str
    #: raise | lower | neutral, relative to the base (for exploitability) or
    #: to an undefined requirement (M) for CR/IR/AR.
    direction: str
    #: risk_profile | surface | control | observation | adapter_tag
    source_kind: str
    source_id: str
    #: observed | declared
    tier: str
    asserted_by: str
    verified_at: datetime | None
    expires_at: datetime | None
    applied: bool
    not_applied_reason: str | None
    #: What the fact says, in words somebody can check.
    because: str = ""
    #: The surface the fact belongs to; None for the whole repository.
    scope: str | None = None
    #: The observation that verified it, when one did.
    evidence_id: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "metric": self.metric,
            "value": self.value,
            "direction": self.direction,
            "source_kind": self.source_kind,
            "source_id": self.source_id,
            "tier": self.tier,
            "asserted_by": self.asserted_by,
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "applied": self.applied,
            "not_applied_reason": self.not_applied_reason,
            "because": self.because,
            "scope": self.scope,
            "evidence_id": self.evidence_id,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> Fact:
        def when(value: Any) -> datetime | None:
            return datetime.fromisoformat(value) if isinstance(value, str) and value else None

        return cls(
            metric=str(raw.get("metric") or ""),
            value=str(raw.get("value") or ""),
            direction=str(raw.get("direction") or "neutral"),
            source_kind=str(raw.get("source_kind") or ""),
            source_id=str(raw.get("source_id") or ""),
            tier=str(raw.get("tier") or "declared"),
            asserted_by=str(raw.get("asserted_by") or ""),
            verified_at=when(raw.get("verified_at")),
            expires_at=when(raw.get("expires_at")),
            applied=bool(raw.get("applied")),
            not_applied_reason=raw.get("not_applied_reason"),
            because=str(raw.get("because") or ""),
            scope=raw.get("scope"),
            evidence_id=raw.get("evidence_id"),
        )


@dataclass(frozen=True)
class Candidate:
    """A repository-level fact plus what a finding must satisfy for it."""

    fact: Fact
    #: (base metric, value) the vector must have, e.g. ("PR", "N").
    requires_base: tuple[str, str] | None = None
    not_for_capabilities: tuple[str, ...] = ()
    exempt_paths: tuple[str, ...] = ()
    cwes: frozenset[str] | None = None

    def hash_view(self) -> dict[str, Any]:
        """What the context hash covers. Timestamps and the observation id
        are left out on purpose: a gate re-observed every morning is the same
        fact, and rescoring every finding daily because a timestamp moved
        would defeat the skip rule. Freshness still reaches the hash, through
        `applied` and the reason, which is what makes a lapse a new context.
        """
        view = self.fact.as_dict()
        for key in ("verified_at", "expires_at", "evidence_id", "not_applied_reason"):
            view.pop(key, None)
        view["reason_kind"] = (self.fact.not_applied_reason or "").split(":", 1)[0]
        view["requires_base"] = list(self.requires_base) if self.requires_base else None
        view["not_for"] = sorted(self.not_for_capabilities)
        view["exempt"] = sorted(self.exempt_paths)
        view["cwes"] = sorted(self.cwes) if self.cwes is not None else None
        return view


@dataclass
class RepoInputs:
    """Everything `build_context` reads, gathered once per repository."""

    repo_full_name: str
    profile: Any = None
    surfaces: Sequence[Any] = ()
    controls: Sequence[Any] = ()
    #: ControlObservation rows (or doubles). Empty when S4 is not installed.
    observations: Sequence[Any] = ()
    observations_available: bool = False
    #: Open findings in the repository, for the contradictions.
    open_findings: Sequence[Mapping[str, Any]] = ()


@dataclass(frozen=True)
class Context:
    repo_full_name: str
    candidates: tuple[Candidate, ...]
    surfaces: tuple[Any, ...]
    policy: Policy
    now: datetime
    context_id: str

    def facts_json(self) -> list[dict[str, Any]]:
        return [c.fact.as_dict() for c in self.candidates]


def _age_days(when: datetime | None, now: datetime) -> int | None:
    return None if when is None else max(0, (now - when).days)


def _direction_requirement(value: str) -> str:
    return {"H": "raise", "M": "neutral", "L": "lower"}.get(value, "neutral")


def _more_severe(metric: str, a: str, b: str) -> bool:
    order = _ORDER.get(metric, ())
    if a not in order or b not in order:
        return False
    return order.index(a) < order.index(b)


def _field(row: Any, name: str, default: Any = None) -> Any:
    if isinstance(row, Mapping):
        return row.get(name, default)
    return getattr(row, name, default)


def _latest_observations(rows: Iterable[Any]) -> list[Any]:
    """Newest per (subject, assertion). A `fail` newer than a `pass` means
    the pass no longer holds, so only the newest row ever counts."""
    latest: dict[tuple[str, str], Any] = {}
    for row in rows:
        key = (str(_field(row, "subject", "")), str(_field(row, "assertion", "")))
        current = latest.get(key)
        if current is None or _field(row, "collected_at") >= _field(current, "collected_at"):
            latest[key] = row
    return list(latest.values())


def _observation_about_surface(row: Any, surface: Any) -> bool:
    """Whether an observation is about this surface: #918's rule, one place.

    Linked by `surface_id` (which `control_observations.record` now sets from
    the surface's selectors at ingest), else the subject against the
    surface's address/hostname selectors, else its text.
    """
    return bool(control_observations._matches(surface, row))


def _observer(row: Any) -> str:
    return str(_field(row, "collector") or _field(row, "tool") or "collector")


def _stride_categories(finding: Mapping[str, Any]) -> set[str]:
    from mykronos.dashboard import STRIDE_BY_CAPABILITY, stride_by_cwe

    cwe_map = stride_by_cwe()
    categories: set[str] = set()
    for cwe in _cwes(finding):
        categories.update(cwe_map.get(cwe, ()))
    if not categories:
        categories.update(STRIDE_BY_CAPABILITY.get(str(finding.get("capability") or ""), ()))
    return categories


def _cwes(finding: Mapping[str, Any]) -> set[str]:
    raw = finding.get("cwe_ids_json") if isinstance(finding, Mapping) else None
    if isinstance(raw, list):
        return {str(c).upper() for c in raw}
    if not raw:
        return set()
    try:
        return {str(c).upper() for c in json.loads(str(raw))}
    except (ValueError, TypeError):
        return set()


def contradicted_controls(
    controls: Sequence[Any], surfaces: Sequence[Any], open_findings: Sequence[Mapping[str, Any]]
) -> dict[str, str]:
    """Control id -> why it is contradicted.

    The Threat Model tab's rule (spec 28 §4: findings open beneath a declared
    control), narrowed to what can actually disagree with the control: an
    open finding *from the capability that checks it*
    (`RepoControl.verified_by_capability`), in the control's STRIDE category,
    and inside the surface it guards when it guards one.
    """
    out: dict[str, str] = {}
    for control in controls:
        capability = _field(control, "verified_by_capability") or ""
        if not capability:
            continue
        guarded = _field(control, "applies_to_surface_id")
        for finding in open_findings:
            if finding.get("capability") != capability:
                continue
            if _field(control, "stride") not in _stride_categories(finding):
                continue
            if guarded:
                surface = surface_match.surface_for(finding, surfaces)
                if surface is None or _field(surface, "id") != guarded:
                    continue
            out[str(_field(control, "id"))] = (
                f"contradicted: open {capability} finding {finding.get('finding_id')!s:.12} "
                f"({finding.get('rule_id')}) sits beneath this {_field(control, 'kind')} control"
            )
            break
    return out


def build_context(inputs: RepoInputs, *, policy: Policy, now: datetime | None = None) -> Context:
    """Every candidate fact for one repository, with freshness and
    contradiction decided. Finding-independent, so it hashes."""
    now = now or utcnow()
    fresh_cut = now - timedelta(days=policy.observation_days)
    confirm_cut = now - timedelta(days=policy.declaration_days)
    observations = _latest_observations(inputs.observations)
    candidates: list[Candidate] = []

    def declared(
        metric: str,
        value: str,
        *,
        source_kind: str,
        source_id: str,
        asserted_by: str,
        verified_at: datetime | None,
        because: str,
        scope: str | None,
    ) -> Fact:
        direction = (
            _direction_requirement(value) if metric in SECURITY_REQUIREMENTS else "lower"
        )
        applied, reason = True, None
        if value in policy.never.get(metric, frozenset()):
            applied, reason = False, (
                f"policy: {metric} is never {value} here (environment-map-v1.yaml)"
            )
        elif direction == "lower":
            if metric not in SECURITY_REQUIREMENTS:
                applied, reason = False, (
                    "unverified: exploitability is lowered only on a fresh observation, "
                    "and this is a declaration"
                )
            elif not asserted_by:
                applied, reason = False, (
                    "unverified: nobody is recorded as having stated it, so it cannot lower"
                )
            elif verified_at is None or verified_at < confirm_cut:
                age = _age_days(verified_at, now)
                applied, reason = False, (
                    f"stale: confirmed {age if age is not None else 'never'} days ago; a "
                    f"lowering declaration counts for {policy.declaration_days} days"
                )
        return Fact(
            metric=metric,
            value=value,
            direction=direction,
            source_kind=source_kind,
            source_id=source_id,
            tier="declared",
            asserted_by=asserted_by,
            verified_at=verified_at,
            expires_at=(
                verified_at + timedelta(days=policy.declaration_days) if verified_at else None
            ),
            applied=applied,
            not_applied_reason=reason,
            because=because,
            scope=scope,
        )

    def observed_evidence(
        assertions: Iterable[str], matches: Callable[[Any], bool], vantages: Sequence[str] = ()
    ) -> tuple[Any | None, Any | None]:
        """(fresh passing row, stale-or-failing newest row) for the assertions."""
        wanted = set(assertions)
        best_fresh, newest_other = None, None
        for row in observations:
            if _field(row, "assertion") not in wanted or not matches(row):
                continue
            if vantages and _field(row, "vantage") not in vantages:
                continue
            if _field(row, "state") == "pass" and _field(row, "collected_at") >= fresh_cut:
                if best_fresh is None or _field(row, "collected_at") > _field(
                    best_fresh, "collected_at"
                ):
                    best_fresh = row
            elif newest_other is None or _field(row, "collected_at") > _field(
                newest_other, "collected_at"
            ):
                newest_other = row
        return best_fresh, newest_other

    def observed_fact(
        base: Fact, evidence: Any | None, other: Any | None, wanted: Sequence[str]
    ) -> Fact:
        if evidence is not None:
            at = _field(evidence, "collected_at")
            return replace(
                base,
                tier="observed",
                asserted_by=_observer(evidence),
                verified_at=at,
                expires_at=at + timedelta(days=policy.observation_days),
                applied=True,
                not_applied_reason=None,
                evidence_id=str(_field(evidence, "id") or ""),
            )
        if other is not None and _field(other, "state") in _EVIDENCE_STATES:
            at = _field(other, "collected_at")
            if _field(other, "state") == "pass":
                return replace(
                    base,
                    tier="observed",
                    asserted_by=_observer(other),
                    verified_at=at,
                    expires_at=at + timedelta(days=policy.observation_days),
                    applied=False,
                    not_applied_reason=(
                        f"stale: last observed {_age_days(at, now)} days ago; an observation "
                        f"lowers for {policy.observation_days} days"
                    ),
                    evidence_id=str(_field(other, "id") or ""),
                )
            return replace(
                base,
                applied=False,
                not_applied_reason=(
                    f"unverified: the newest {_field(other, 'assertion')} observation "
                    f"({_age_days(at, now)} days ago) did not hold"
                ),
            )
        if not inputs.observations_available:
            reason = (
                "unverified: needs a fresh observation "
                f"({' or '.join(wanted) or 'none defined'}); the observation register "
                "is not installed"
            )
        else:
            reason = (
                "unverified: needs a fresh observation "
                f"({' or '.join(wanted) or 'none defined'}); none recorded"
            )
        return replace(base, applied=False, not_applied_reason=reason)

    # -- The risk profile: repository-wide, declared. -----------------------
    profile = inputs.profile
    if profile is not None:
        who = str(_field(profile, "updated_by") or "")
        at = _field(profile, "updated_at")
        pid = str(_field(profile, "id") or "")
        classification = str(_field(profile, "data_classification") or "").strip().lower()
        if classification in policy.cr_by_classification:
            candidates.append(Candidate(declared(
                "CR", policy.cr_by_classification[classification],
                source_kind="risk_profile", source_id=pid, asserted_by=who, verified_at=at,
                because=f"the risk profile classifies the data as {classification}", scope=None,
            )))
        if _field(profile, "compliance_scope") and policy.ir_compliance:
            regimes = ", ".join(str(r) for r in _field(profile, "compliance_scope"))
            candidates.append(Candidate(declared(
                "IR", policy.ir_compliance,
                source_kind="risk_profile", source_id=pid, asserted_by=who, verified_at=at,
                because=f"the repository is in compliance scope ({regimes})", scope=None,
            )))
        criticality = str(_field(profile, "business_criticality") or "").strip().lower()
        if criticality in policy.ar_by_criticality:
            candidates.append(Candidate(declared(
                "AR", policy.ar_by_criticality[criticality],
                source_kind="risk_profile", source_id=pid, asserted_by=who, verified_at=at,
                because=f"the risk profile says business criticality is {criticality}",
                scope=None,
            )))
        if _field(profile, "internet_facing") is False and policy.mav_profile_not_internet_facing:
            candidates.append(Candidate(declared(
                "MAV", policy.mav_profile_not_internet_facing,
                source_kind="risk_profile", source_id=pid, asserted_by=who, verified_at=at,
                because="the risk profile says the repository is not internet-facing",
                scope=None,
            )))

    # -- Surfaces: per surface, declared, exposure verified by observation. -
    contradicted_surfaces = control_observations.contradictions(
        list(inputs.surfaces), list(observations), now
    )
    for surface in inputs.surfaces:
        sid = str(_field(surface, "id"))
        name = str(_field(surface, "name") or sid)
        who = str(_field(surface, "declared_by") or "")
        at = _field(surface, "updated_at") or _field(surface, "declared_at")
        is_asset = _field(surface, "kind") == "asset"
        sensitivity = str(_field(surface, "sensitivity") or "unknown")
        if is_asset:
            for metric, by_sensitivity in (
                ("CR", policy.cr_by_sensitivity),
                ("IR", policy.ir_by_sensitivity),
                ("AR", {}),
            ):
                override = _field(surface, metric.lower())
                if override:
                    value, because = str(override).upper(), (
                        f"asset {name!r} declares {metric}:{str(override).upper()}"
                    )
                elif sensitivity in by_sensitivity:
                    value, because = by_sensitivity[sensitivity], (
                        f"asset {name!r} holds {sensitivity} data"
                    )
                else:
                    continue
                candidates.append(Candidate(declared(
                    metric, value, source_kind="surface", source_id=sid, asserted_by=who,
                    verified_at=at, because=because, scope=sid,
                )))

        exposure = str(_field(surface, "exposure") or "unknown")
        mav_value = policy.mav_by_exposure.get(exposure)
        if mav_value is None:
            continue
        base = declared(
            "MAV", mav_value, source_kind="surface", source_id=sid, asserted_by=who,
            verified_at=at, because=f"{name!r} is declared {exposure}", scope=sid,
        )
        wanted = policy.mav_evidence.get(mav_value, ())

        def about(row: Any, surface: Any = surface) -> bool:
            return _observation_about_surface(row, surface)

        evidence, other = observed_evidence(wanted, about)
        fact = observed_fact(base, evidence, other, wanted)
        # Contradiction outranks evidence: a port published to the internet
        # is not made internal by a firewall rule somebody also observed.
        # `control_observations.contradictions` is the one reader of
        # `surfaces.CONTRADICTED_BY` (#918).
        against = contradicted_surfaces.get(sid)
        if against:
            first = against[0]
            fact = replace(
                fact,
                applied=False,
                not_applied_reason=(
                    f"contradicted: {first.assertion} observed from {first.vantage} "
                    f"for {first.subject} {_age_days(first.collected_at, now)} days ago"
                ),
            )
        candidates.append(Candidate(fact))

    # -- The perimeter gate: a control, verified by an anonymous 401. -------
    gate = policy.gate
    if gate is not None:
        contradicted = contradicted_controls(
            [c for c in inputs.controls if _field(c, "kind") == gate.control_kind],
            inputs.surfaces,
            inputs.open_findings,
        )
        secrets_open = [f for f in inputs.open_findings if f.get("capability") == "secrets"]
        by_id = {str(_field(s, "id")): s for s in inputs.surfaces}
        for control in inputs.controls:
            if _field(control, "kind") != gate.control_kind:
                continue
            cid = str(_field(control, "id"))
            guarded = _field(control, "applies_to_surface_id")
            guarded_surface = by_id.get(str(guarded)) if guarded else None
            base = declared(
                "MPR", gate.to_value, source_kind="control", source_id=cid,
                asserted_by=str(_field(control, "declared_by") or ""),
                verified_at=_field(control, "last_verified_at"),
                because="a perimeter gate stands in front of " + (
                    repr(_field(guarded_surface, "name"))
                    if guarded_surface
                    else "the repository"
                ),
                scope=str(guarded) if guarded else None,
            )

            def gate_matches(
                row: Any, cid: str = cid, guarded: Any = guarded, surface: Any = guarded_surface
            ) -> bool:
                if _field(row, "control_id"):
                    return bool(_field(row, "control_id") == cid)
                if guarded:
                    return surface is not None and _observation_about_surface(row, surface)
                return True

            evidence, other = observed_evidence(
                (gate.evidence,), gate_matches, gate.evidence_vantages
            )
            fact = observed_fact(base, evidence, other, (gate.evidence,))
            if cid in contradicted:
                fact = replace(fact, applied=False, not_applied_reason=contradicted[cid])
            elif secrets_open:
                fact = replace(
                    fact,
                    applied=False,
                    not_applied_reason=(
                        f"contradicted: {len(secrets_open)} open secrets finding(s) in this "
                        "repository; a leaked credential may be the gate token"
                    ),
                )
            candidates.append(Candidate(
                fact,
                requires_base=("PR", gate.from_value),
                not_for_capabilities=gate.not_for_capabilities,
                exempt_paths=gate.exempt_paths,
            ))

    # -- MAC pairings: only the enabled ones, each needing an observation. --
    for pairing in policy.mac_pairings:
        base = Fact(
            metric="MAC", value=pairing.value, direction="lower",
            source_kind="observation", source_id=pairing.name, tier="declared",
            asserted_by="", verified_at=None, expires_at=None, applied=False,
            not_applied_reason=None,
            because=f"pairing {pairing.name}: {', '.join(sorted(pairing.cwes))} is harder here",
        )
        if pairing.evidence is None:
            fact = replace(base, not_applied_reason=(
                "unverified: nothing observes this control yet, and a declaration "
                "cannot lower exploitability"
            ))
        else:
            evidence, other = observed_evidence(
                (pairing.evidence,), lambda row: True, pairing.evidence_vantages
            )
            fact = observed_fact(base, evidence, other, (pairing.evidence,))
        candidates.append(Candidate(fact, cwes=pairing.cwes))

    candidates.sort(key=lambda c: json.dumps(c.hash_view(), sort_keys=True, default=str))
    return Context(
        repo_full_name=inputs.repo_full_name,
        candidates=tuple(candidates),
        surfaces=tuple(inputs.surfaces),
        policy=policy,
        now=now,
        context_id=context_hash(inputs.repo_full_name, candidates, policy),
    )


def context_hash(repo_full_name: str, candidates: Iterable[Candidate], policy: Policy) -> str:
    """Stable across runs, processes and candidate order."""
    views = sorted(
        json.dumps(c.hash_view(), sort_keys=True, default=str) for c in candidates
    )
    payload = json.dumps(
        {"repo": repo_full_name, "policy": policy.version, "facts": views}, sort_keys=True
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# One finding
# ---------------------------------------------------------------------------


def _raw(finding: Mapping[str, Any]) -> dict[str, Any]:
    raw = finding.get("raw_finding_json")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return {}
    return raw if isinstance(raw, dict) else {}


def _dast_path(finding: Mapping[str, Any]) -> str | None:
    instance = _raw(finding).get("instance")
    uri = instance.get("uri") if isinstance(instance, Mapping) else None
    if not isinstance(uri, str) or not uri:
        return None
    from urllib.parse import urlsplit

    try:
        return urlsplit(uri).path or "/"
    except ValueError:
        return None


def _as_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value.replace(tzinfo=None) if value.tzinfo else value
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed.replace(tzinfo=None) if parsed.tzinfo else parsed
    return None


def resolve(
    finding: Mapping[str, Any], context: Context, metrics: Mapping[str, str]
) -> list[Fact]:
    """This finding's facts, each applied or not and why.

    `metrics` is the parsed base vector. The finding is placed in at most one
    surface; facts scoped to other surfaces are not about it and are left
    out, while every repository-wide fact and every fact of its own surface
    is returned.
    """
    policy, now = context.policy, context.now
    surface = surface_match.surface_for(finding, context.surfaces)
    sid = str(_field(surface, "id")) if surface is not None else None
    capability = str(finding.get("capability") or "")
    out: list[Fact] = []

    for candidate in context.candidates:
        fact = candidate.fact
        if fact.scope is not None and fact.scope != sid:
            continue
        if fact.applied and fact.direction == "lower":
            reason = None
            required = candidate.requires_base
            if required and metrics.get(required[0]) != required[1]:
                reason = (
                    f"not applicable: the base vector's {required[0]} is "
                    f"{metrics.get(required[0])}, and this fact changes only {required[1]}"
                )
            elif capability in candidate.not_for_capabilities:
                reason = f"not applicable: never applied to a {capability} finding"
            elif candidate.exempt_paths and (path := _dast_path(finding)) is not None and any(
                surface_match.glob_match(p.lstrip("/"), path.lstrip("/"))
                for p in candidate.exempt_paths
            ):
                reason = f"not applicable: {path} is exempt from the gate"
            elif candidate.cwes is not None and not (_cwes(finding) & candidate.cwes):
                reason = "not applicable: the finding names none of this pairing's CWEs"
            elif sid is None and fact.tier == "declared":
                reason = (
                    "unverified: the finding is in no declared surface, and a "
                    "repository-wide declaration lowers nothing"
                )
            if reason:
                fact = replace(fact, applied=False, not_applied_reason=reason)
        out.append(fact)

    # The adapter's own tag: a container image it recognised as a tool.
    raw = _raw(finding)
    if capability == "containers" and raw.get("image_role") == "tool" and policy.mav_tool_image:
        seen = _as_datetime(finding.get("last_seen_at"))
        fresh = seen is not None and seen >= now - timedelta(days=policy.observation_days)
        out.append(Fact(
            metric="MAV",
            value=policy.mav_tool_image,
            direction="lower",
            source_kind="adapter_tag",
            source_id=f"finding:{finding.get('finding_id')}",
            tier="observed",
            asserted_by="adapter:containers_trivy",
            verified_at=seen,
            expires_at=seen + timedelta(days=policy.observation_days) if seen else None,
            applied=fresh,
            not_applied_reason=None if fresh else (
                f"stale: the image was last scanned {_age_days(seen, now)} days ago"
                if seen else "stale: the finding records no scan time"
            ),
            because=f"image {raw.get('image')!r} is a tool image, never deployed as a service",
        ))

    # Rule 4, as a label: cvss.score caps; this says so.
    labelled: list[Fact] = []
    for fact in out:
        base_key = _BASE_KEY.get(fact.metric)
        if base_key and fact.applied and base_key in metrics:
            base_value = metrics[base_key]
            if not _more_severe(fact.metric, base_value, fact.value):
                fact = replace(
                    fact,
                    direction="neutral",
                    applied=False,
                    not_applied_reason=(
                        f"capped: the base vector is already {base_key}:{base_value}, and "
                        "exploitability is never raised"
                    ),
                )
        labelled.append(fact)

    # One value per metric: the most severe applied fact wins, so a raising
    # fact is never outvoted by a lowering one.
    winners: dict[str, Fact] = {}
    for fact in labelled:
        if not fact.applied:
            continue
        current = winners.get(fact.metric)
        if current is None or _more_severe(fact.metric, fact.value, current.value):
            winners[fact.metric] = fact
    final: list[Fact] = []
    for fact in labelled:
        winner = winners.get(fact.metric)
        # Two facts agreeing on a value both stand; only a disagreeing one is
        # outweighed.
        if fact.applied and winner is not None and winner.value != fact.value:
            fact = replace(
                fact,
                applied=False,
                not_applied_reason=(
                    f"outweighed: {fact.metric}:{winner.value} from the "
                    f"{winner.source_kind.replace('_', ' ')} applies"
                ),
            )
        final.append(fact)
    return final


def environment_of(facts: Iterable[Fact]) -> cvss.Environment:
    """The `cvss.Environment` the applied facts describe.

    A requirement of `M` is left `X`: the standard weighs the two identically
    (1.0), and stating it would only switch the score onto the environmental
    formula, which under a changed scope is not the base formula and can move
    the number by 0.1 on a fact that changes nothing.
    """
    values = {
        f.metric.lower(): f.value
        for f in facts
        if f.applied and not (f.metric in SECURITY_REQUIREMENTS and f.value == "M")
    }
    known = {k: v for k, v in values.items() if k in cvss.Environment.__dataclass_fields__}
    return cvss.Environment(**known)


def score_vector(vector: str, facts: Sequence[Fact]) -> cvss.Scored:
    """`cvss.score` on the applied facts, held to the direction they point.

    Under a changed scope CVSS 3.1's environmental impact formula is not the
    base formula, so a fact can move the number the *wrong way*: IR:H on an
    `I:N` flaw scored 8.0 against a base of 8.1. A raising fact must never
    lower a score and a lowering fact must never raise one (rules 2 and 3),
    so when every applied fact points one way the result is held at the base
    on the other side, and `because` says so. Raises `cvss.VectorError`.
    """
    result = cvss.score(vector, environment_of(facts))
    applied = [f for f in facts if f.applied]
    lowers = any(f.direction == "lower" for f in applied)
    raises = any(f.direction == "raise" for f in applied)
    if not lowers and result.environmental < result.base:
        side = "raise"
    elif not raises and result.environmental > result.base:
        side = "lower"
    else:
        return result
    return replace(
        result,
        environmental=result.base,
        because=(
            *result.because,
            f"held at the base: every applied fact can only {side} it, and the changed-scope "
            "formula would have moved it the other way",
        ),
    )


def band(score: float) -> str:
    """CVSS 3.1 qualitative severity rating (§5)."""
    if score <= 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def effective_severity(scanner_severity: str, base_band: str, env_band: str) -> str:
    """The scanner's word shifted by as many bands as the environment moved
    the score, clamped to low..critical. Unmoved, the scanner's word stands
    exactly, `info` included."""
    word = (scanner_severity or "").strip().lower()
    shift = BANDS.index(env_band) - BANDS.index(base_band)
    if word not in _SEVERITIES:
        word = base_band if base_band in _SEVERITIES else "medium"
    if shift == 0:
        return word
    index = min(max(_SEVERITIES.index(word) + shift, 1), len(_SEVERITIES) - 1)
    return _SEVERITIES[index]


def ChosenVector(  # noqa: N802 - reads as the type it builds
    vector: str, version: str, source: VectorSource = "nvd"
) -> VectorChoice:
    """A rescorable 3.x choice, for callers (and tests) that already hold one."""
    return VectorChoice(vector=vector, version=version, source=source, rescored=True)


@dataclass(frozen=True)
class FindingScore:
    finding_id: str
    vector: VectorChoice
    scored: cvss.Scored
    facts: tuple[Fact, ...]
    base_band: str
    env_band: str
    scanner_severity: str
    effective_severity: str


def score_finding(
    finding: Mapping[str, Any], context: Context, chosen: VectorChoice
) -> FindingScore:
    """Resolve, then score. Raises `cvss.VectorError` for an unscoreable vector."""
    metrics = cvss.parse(chosen.vector)
    facts = resolve(finding, context, metrics)
    scored = score_vector(chosen.vector, facts)
    base_band, env_band = band(scored.base), band(scored.environmental)
    severity = str(finding.get("severity") or "")
    return FindingScore(
        finding_id=str(finding.get("finding_id") or ""),
        vector=chosen,
        scored=scored,
        facts=tuple(facts),
        base_band=base_band,
        env_band=env_band,
        scanner_severity=severity,
        effective_severity=effective_severity(severity, base_band, env_band),
    )


# ---------------------------------------------------------------------------
# Vector selection: the one place a vector is chosen
# ---------------------------------------------------------------------------


def choose_vectors(
    session: Session, findings: Iterable[Mapping[str, Any]]
) -> dict[str, VectorChoice]:
    """finding_id -> the vector its severity is read from.

    **The one place a vector is chosen**, for the stored scores and the record
    page alike, and it is #917's `cvss_vectors.choose_vector`: NVD 3.x >
    advisory 3.x (kept on the finding's raw record) > v4.0, shown and never
    rescored (D1). A choice with `rescored=False` is returned so the caller
    can show it; nothing environmental is computed or stored for it.
    """
    from mykronos.threat_intel import extract_cve

    rows = list(findings)
    cve_of: dict[str, str] = {}
    for finding in rows:
        cve = extract_cve(finding.get("rule_id"), finding.get("title"))
        if cve:
            cve_of[str(finding.get("finding_id"))] = cve
    matches = (
        {
            row.cve_id: row
            for row in session.scalars(
                select(ThreatIntelMatch).where(
                    ThreatIntelMatch.cve_id.in_(set(cve_of.values()))
                )
            )
        }
        if cve_of
        else {}
    )
    out: dict[str, VectorChoice] = {}
    for finding in rows:
        finding_id = str(finding.get("finding_id"))
        match = matches.get(cve_of.get(finding_id, ""))
        choice = cvss_vectors.choose_vector(
            nvd_v3=match.cvss_vector if match else None,
            nvd_v4=match.cvss_v4_vector if match else None,
            nvd_v4_base_score=match.cvss_v4_base_score if match else None,
            advisory=cvss_vectors.from_raw(finding.get("raw_finding_json")),
        )
        if choice is not None:
            out[finding_id] = choice
    return out


# ---------------------------------------------------------------------------
# Loading and storing
# ---------------------------------------------------------------------------

_FINDING_COLUMNS = (
    "finding_id",
    "capability",
    "rule_id",
    "title",
    "severity",
    "file_path",
    "address",
    "port",
    "cwe_ids_json",
    "raw_finding_json",
    "last_seen_at",
)


def open_findings(catalog: Any, repo_full_name: str) -> list[dict[str, Any]]:
    """The repository's open findings, with what placement and scoring read."""
    if catalog is None or not catalog.all_files("findings"):
        return []
    rows = catalog.query(
        f"SELECT {', '.join(_FINDING_COLUMNS)} FROM findings "
        "WHERE asset_id = ? AND status = 'open'",
        [repo_full_name],
    )
    return [dict(zip(_FINDING_COLUMNS, row, strict=True)) for row in rows]


def finding_by_id(catalog: Any, finding_id: str) -> dict[str, Any] | None:
    if catalog is None or not catalog.all_files("findings"):
        return None
    columns = (*_FINDING_COLUMNS, "asset_id")
    rows = catalog.query(
        f"SELECT {', '.join(columns)} FROM findings WHERE finding_id = ? LIMIT 1",
        [finding_id],
    )
    return dict(zip(columns, rows[0], strict=True)) if rows else None


def load_inputs(
    session: Session,
    repo_full_name: str,
    findings: Sequence[Mapping[str, Any]],
    *,
    policy: Policy,
    now: datetime,
) -> RepoInputs:
    onboarding = session.scalars(
        select(RepoOnboarding).where(RepoOnboarding.github_repo_full_name == repo_full_name)
    ).first()
    profile = (
        session.scalars(
            select(RiskProfile).where(RiskProfile.repo_onboarding_id == onboarding.id)
        ).first()
        if onboarding is not None
        else None
    )
    surfaces = list(
        session.scalars(
            select(RepoSurface)
            .where(RepoSurface.repo_full_name == repo_full_name)
            .order_by(RepoSurface.id)
        )
    )
    controls = list(
        session.scalars(
            select(RepoControl)
            .where(RepoControl.repo_full_name == repo_full_name)
            .order_by(RepoControl.id)
        )
    )
    observations: list[Any] = []
    if ControlObservation is not None:
        # Only a bounded window: beyond it a newest row lowers nothing either
        # way. Four freshness windows rather than one, so a lapsed observation
        # is still read and the reason can say "last observed 16 days ago"
        # rather than "none recorded".
        cut = now - timedelta(days=policy.observation_days * 4)
        observations = list(
            session.scalars(
                select(ControlObservation).where(
                    ControlObservation.repo_full_name == repo_full_name,
                    ControlObservation.collected_at >= cut,
                )
            )
        )
    return RepoInputs(
        repo_full_name=repo_full_name,
        profile=profile,
        surfaces=surfaces,
        controls=controls,
        observations=observations,
        observations_available=ControlObservation is not None,
        open_findings=list(findings),
    )


@dataclass
class RescoreResult:
    repo_full_name: str
    context_id: str = ""
    context_changed: bool = False
    scored: int = 0
    unchanged: int = 0
    removed: int = 0
    unscored: int = 0

    def summary(self) -> str:
        return (
            f"{self.repo_full_name}: context {self.context_id[:12]}"
            f"{' (new)' if self.context_changed else ''}, {self.scored} scored, "
            f"{self.unchanged} unchanged, {self.removed} removed, {self.unscored} without a vector"
        )


def _lapsed(row: EnvironmentalScore, now: datetime) -> bool:
    """Whether a stored score rests on an applied fact that has since expired.

    The context hash catches every lapse of a repository-level fact; this
    catches the finding-level ones (an adapter tag) the hash cannot see.
    """
    for raw in row.facts_json or []:
        if not raw.get("applied") or raw.get("direction") != "lower":
            continue
        expires = raw.get("expires_at")
        if isinstance(expires, str) and expires and datetime.fromisoformat(expires) <= now:
            return True
    return False


#: One rescore at a time. The post-compaction drain and the daily job run in
#: separate threads, and two of them inserting the same finding's row would
#: collide on its primary key.
_rescore_lock = threading.Lock()


def rescore(
    db: Any,
    catalog: Any,
    repo_full_name: str,
    *,
    now: datetime | None = None,
    policy: Policy | None = None,
) -> RescoreResult:
    """Recompute and store every open finding's environmental score.

    Skips a finding whose stored row was computed in the same context, on the
    same vector and scanner severity, and rests on nothing that has expired.
    A context whose hash is unchanged appends no `ScoringContext`.
    """
    now = now or utcnow()
    policy = policy or load_policy()
    findings = open_findings(catalog, repo_full_name)
    result = RescoreResult(repo_full_name=repo_full_name)
    with _rescore_lock, db.session() as session:
        inputs = load_inputs(session, repo_full_name, findings, policy=policy, now=now)
        context = build_context(inputs, policy=policy, now=now)
        result.context_id = context.context_id
        latest = session.scalars(
            select(ScoringContext)
            .where(ScoringContext.repo_full_name == repo_full_name)
            .order_by(ScoringContext.seq.desc())
            .limit(1)
        ).first()
        result.context_changed = latest is None or latest.context_id != context.context_id
        if result.context_changed:
            session.add(
                ScoringContext(
                    context_id=context.context_id,
                    repo_full_name=repo_full_name,
                    facts_json=context.facts_json(),
                    created_at=now,
                )
            )

        existing = {
            row.finding_id: row
            for row in session.scalars(
                select(EnvironmentalScore).where(
                    EnvironmentalScore.repo_full_name == repo_full_name
                )
            )
        }
        vectors = choose_vectors(session, findings)
        kept: set[str] = set()
        for finding in findings:
            finding_id = str(finding.get("finding_id"))
            chosen = vectors.get(finding_id)
            if chosen is None or not chosen.rescored:
                result.unscored += 1
                continue
            row = existing.get(finding_id)
            severity = str(finding.get("severity") or "")
            if (
                row is not None
                and row.context_id == context.context_id
                and row.vector == chosen.vector
                and row.scanner_severity == severity
                and not _lapsed(row, now)
            ):
                kept.add(finding_id)
                result.unchanged += 1
                continue
            try:
                scored = score_finding(finding, context, chosen)
            except cvss.VectorError:
                logger.warning("Unscoreable vector for finding %s", finding_id[:12])
                result.unscored += 1
                continue
            kept.add(finding_id)
            if row is None:
                row = EnvironmentalScore(finding_id=finding_id)
                session.add(row)
            row.repo_full_name = repo_full_name
            row.vector = chosen.vector
            row.vector_version = chosen.version
            row.vector_source = chosen.source
            row.base = scored.scored.base
            row.environmental = scored.scored.environmental
            row.base_band = scored.base_band
            row.env_band = scored.env_band
            row.scanner_severity = severity
            row.effective_severity = scored.effective_severity
            row.facts_json = [f.as_dict() for f in scored.facts]
            row.context_id = context.context_id
            row.computed_at = now
            result.scored += 1
        for finding_id, row in existing.items():
            if finding_id not in kept:
                session.delete(row)
                result.removed += 1
    return result


def known_repos(db: Any) -> list[str]:
    """Every onboarded repository, and any that still hold stored scores."""
    with db.session() as session:
        names = set(session.scalars(select(RepoOnboarding.github_repo_full_name)))
        names.update(session.scalars(select(EnvironmentalScore.repo_full_name).distinct()))
    return sorted(n for n in names if n)


class RescoreError(RuntimeError):
    """At least one repository could not be rescored; the job reports it."""


def rescore_all(
    db: Any, catalog: Any, *, now: datetime | None = None
) -> list[RescoreResult]:
    """The daily `environment` job. Every repository, from scratch.

    Raises after trying them all if any failed, so `job_runs` says so rather
    than the job reading as clean while one repository's scores went stale.
    """
    results: list[RescoreResult] = []
    failed: list[str] = []
    for repo in known_repos(db):
        try:
            results.append(rescore(db, catalog, repo, now=now))
        except Exception:
            logger.exception("Environmental rescore failed for %s", repo)
            failed.append(repo)
    if failed:
        raise RescoreError(f"environmental rescore failed for {', '.join(failed)}")
    return results


def score_on_read(
    db: Any, catalog: Any, finding: Mapping[str, Any], *, now: datetime | None = None
) -> FindingScore | None:
    """One finding scored now, without storing it: `_severity_here`'s
    fallback when no rescore has reached the finding yet."""
    now = now or utcnow()
    policy = load_policy()
    repo = str(finding.get("asset_id") or finding.get("repo_full_name") or "")
    findings = open_findings(catalog, repo)
    with db.session() as session:
        chosen = choose_vectors(session, [finding]).get(str(finding.get("finding_id")))
        if chosen is None or not chosen.rescored:
            return None
        inputs = load_inputs(session, repo, findings, policy=policy, now=now)
    context = build_context(inputs, policy=policy, now=now)
    try:
        return score_finding(finding, context, chosen)
    except cvss.VectorError:
        return None


# ---------------------------------------------------------------------------
# Triggers: a debounced per-repository dirty flag
# ---------------------------------------------------------------------------

_lock = threading.Lock()
#: key -> monotonic time of its latest mark. A key is a repository name,
#: `onboarding:<id>` (a risk profile names its repository by onboarding), or
#: `*` for every repository (a vector refresh).
_dirty: dict[str, float] = {}
ALL = "*"


def mark_dirty(
    repo_full_name: str, reason: str = "", *, clock: Callable[[], float] = time.monotonic
) -> None:
    """Ask for this repository to be rescored after the next quiet moment."""
    if not repo_full_name:
        return
    with _lock:
        _dirty[repo_full_name] = clock()
    logger.debug("Environment dirty: %s (%s)", repo_full_name, reason)


def mark_all_dirty(reason: str = "", *, clock: Callable[[], float] = time.monotonic) -> None:
    mark_dirty(ALL, reason, clock=clock)


def pending() -> dict[str, float]:
    with _lock:
        return dict(_dirty)


def clear() -> None:
    with _lock:
        _dirty.clear()


def drain(
    db: Any,
    catalog: Any,
    *,
    debounce_seconds: float = DEBOUNCE_SECONDS,
    clock: Callable[[], float] = time.monotonic,
    rescore_fn: Callable[..., RescoreResult] | None = None,
) -> list[RescoreResult]:
    """Rescore every repository marked dirty and then left alone for
    `debounce_seconds`. Run after each compaction, so a finding ingest is
    scored once its rows are in the lake.

    A repository whose rescore fails is logged and not re-marked: the daily
    job retries it, and re-marking would turn one bad row into a hot loop.
    """
    run = rescore_fn or rescore
    cutoff = clock() - debounce_seconds
    with _lock:
        ready = [key for key, at in _dirty.items() if at <= cutoff]
        for key in ready:
            del _dirty[key]
    if not ready:
        return []

    repos: set[str] = set()
    onboarding_ids = [k.split(":", 1)[1] for k in ready if k.startswith("onboarding:")]
    if ALL in ready:
        repos.update(known_repos(db))
    if onboarding_ids:
        with db.session() as session:
            repos.update(
                session.scalars(
                    select(RepoOnboarding.github_repo_full_name).where(
                        RepoOnboarding.id.in_(onboarding_ids)
                    )
                )
            )
    repos.update(k for k in ready if k != ALL and not k.startswith("onboarding:"))

    results: list[RescoreResult] = []
    for repo in sorted(r for r in repos if r):
        try:
            results.append(run(db, catalog, repo))
        except Exception:
            logger.exception("Environmental rescore failed for %s; the daily job retries", repo)
    return results


#: The models whose writes change what a score may rest on, keyed by
#: repository name. A risk profile is keyed by onboarding and handled apart.
_REPO_KEYED = frozenset({"RepoSurface", "RepoControl", "PublicEndpoint", "ControlObservation"})


def _after_flush(session: Session, _flush_context: Any) -> None:
    """Mark the repository of every surface, control, profile, endpoint or
    observation a flush wrote. One listener rather than a call in every
    endpoint, the manifest sync and the MCP tools: a write path that forgot
    to mark would leave scores resting on facts that changed."""
    for obj in chain(session.new, session.dirty, session.deleted):
        name = type(obj).__name__
        if name in _REPO_KEYED:
            mark_dirty(str(getattr(obj, "repo_full_name", "") or ""), f"{name} written")
        elif isinstance(obj, RiskProfile) and obj.repo_onboarding_id:
            mark_dirty(f"onboarding:{obj.repo_onboarding_id}", "risk profile written")


if not event.contains(Session, "after_flush", _after_flush):
    event.listen(Session, "after_flush", _after_flush)
