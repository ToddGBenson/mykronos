"""CVSS v3.1 environmental scoring — the base score, re-read for this system.

A base score is a statement about a vulnerability in the abstract. It is the
same number whether the affected service is on the public internet holding card
data or on a laptop that has been off for a year, which is why a queue sorted
by base score sorts by nobody's priorities in particular.

The environmental score is the standard's own answer to that, and this
implements it rather than inventing a substitute. Two things it changes:

**Security Requirements (CR / IR / AR).** How much confidentiality, integrity
and availability are worth *here*. Driven by what the repository's risk profile
says about data classification and business criticality.

**Modified base metrics.** Chiefly Modified Attack Vector: a network-exploitable
flaw on a service nothing can reach from outside is not network-exploitable
here.

**Undefined means the base value, and that is the "assume the worst" rule.**
Every modifier defaults to `X` — not defined — and the standard says an
undefined modifier takes the base metric's value. So a repository with no
confirmed risk profile scores *exactly its base score*, never lower. Nothing is
discounted on a guess. That property is the whole reason this is worth
computing: the number can only move once somebody states a fact, and every
statement is attributable.

**It is arithmetic, not judgement.** This module implements the published
formula and nothing else. Where the platform wants to weigh exploitation in the
wild, a missing owner or a fix nobody has shipped, that is Oracle's job and a
different number with different terms. Bending CVSS to carry them would produce
a figure that looks like a standard and is not one.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

#: CVSS 3.1, table 15-19. Attack Vector, Attack Complexity, User Interaction
#: and the impact metrics have one value each; Privileges Required depends on
#: Scope, which is why it is a pair.
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

#: Requirement modifiers. `X` is 1.0 — the same as Medium — because an
#: undefined requirement must not move the score in either direction.
_REQ = {"H": 1.5, "M": 1.0, "L": 0.5, "X": 1.0}

#: Temporal metrics. Every `X` is 1.0 for the same reason: unstated is not the
#: same as favourable, and a score that quietly fell because nobody filled in
#: a form would be the worst possible failure mode here.
_E = {"X": 1.0, "H": 1.0, "F": 0.97, "P": 0.94, "U": 0.91}
_RL = {"X": 1.0, "U": 1.0, "W": 0.97, "T": 0.96, "O": 0.95}
_RC = {"X": 1.0, "C": 1.0, "R": 0.96, "U": 0.92}

_BASE_KEYS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
_VECTOR = re.compile(r"^CVSS:3\.[01]/(?P<body>[A-Z]+:[A-Z]+(?:/[A-Z]+:[A-Z]+)*)$")


class VectorError(ValueError):
    """A vector that cannot be scored, rather than one scored as zero."""


@dataclass(frozen=True)
class Environment:
    """What is known about the system, in the standard's own terms.

    Every field defaults to `X`, and `X` means the base value. A caller that
    knows nothing produces the base score, which is the only honest answer and
    is never a discount.
    """

    #: Confidentiality / Integrity / Availability requirement: H, M, L or X.
    cr: str = "X"
    ir: str = "X"
    ar: str = "X"
    #: Modified base metrics. `X` for each takes the base vector's own value.
    mav: str = "X"
    mac: str = "X"
    mpr: str = "X"
    mui: str = "X"
    ms: str = "X"
    mc: str = "X"
    mi: str = "X"
    ma: str = "X"

    @property
    def stated(self) -> bool:
        """Whether anything at all is known. A `False` here is why a score
        equals its base, and the caller should say so rather than showing an
        environmental figure that is silently the same number."""
        return any(
            value != "X"
            for value in (
                self.cr, self.ir, self.ar, self.mav, self.mac,
                self.mpr, self.mui, self.ms, self.mc, self.ma, self.mi,
            )
        )


@dataclass(frozen=True)
class Scored:
    base: float
    environmental: float
    #: The metrics that actually moved the number, for the reader who has to
    #: defend it. A score with no explanation is a score nobody can argue with,
    #: which is not the same as one nobody disagrees with.
    because: tuple[str, ...] = ()

    @property
    def moved(self) -> bool:
        return round(self.environmental, 1) != round(self.base, 1)


def parse(vector: str) -> dict[str, str]:
    """Split a CVSS 3.x vector string, or raise.

    Raises rather than returning a partial reading. A vector missing `AV`
    cannot be scored, and defaulting the missing metric would invent the
    attacker's position — the single most consequential thing in the formula.
    """
    match = _VECTOR.match((vector or "").strip())
    if not match:
        raise VectorError(f"Not a CVSS 3.x vector: {vector!r}")

    metrics = dict(
        part.split(":", 1) for part in match.group("body").split("/") if ":" in part
    )
    missing = [key for key in _BASE_KEYS if key not in metrics]
    if missing:
        raise VectorError(f"Vector is missing {', '.join(missing)}: {vector!r}")

    for key, table in (
        ("AV", _AV), ("AC", _AC), ("UI", _UI), ("C", _CIA), ("I", _CIA), ("A", _CIA)
    ):
        if metrics[key] not in table:
            raise VectorError(f"Unknown {key} value {metrics[key]!r}")
    if metrics["S"] not in ("U", "C"):
        raise VectorError(f"Unknown S value {metrics['S']!r}")
    if metrics["PR"] not in _PR_UNCHANGED:
        raise VectorError(f"Unknown PR value {metrics['PR']!r}")

    return metrics


def _roundup(value: float) -> float:
    """CVSS 3.1's own rounding (§7.4), not `round()`.

    The specification defines this as integer arithmetic precisely because
    floating-point `round` gives a different answer for some scores, and two
    tools disagreeing in the first decimal place on a published standard is the
    kind of difference that costs an afternoon.
    """
    integer = int(round(value * 100_000))
    if integer % 10_000 == 0:
        return integer / 100_000.0
    return (math.floor(integer / 10_000) + 1) / 10.0


def _impact(iss: float, scope_changed: bool) -> float:
    if scope_changed:
        return 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    return 6.42 * iss


def base_score(metrics: dict[str, str]) -> float:
    """The published base score for a parsed vector."""
    scope_changed = metrics["S"] == "C"
    iss = 1 - (
        (1 - _CIA[metrics["C"]]) * (1 - _CIA[metrics["I"]]) * (1 - _CIA[metrics["A"]])
    )
    impact = _impact(iss, scope_changed)
    if impact <= 0:
        return 0.0

    pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[metrics["PR"]]
    exploitability = 8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]] * pr * _UI[metrics["UI"]]

    combined = impact + exploitability
    if scope_changed:
        combined *= 1.08
    return _roundup(min(combined, 10.0))


def score(vector: str, environment: Environment | None = None) -> Scored:
    """Base and environmental scores for one vulnerability on one system.

    With no environment — or one that states nothing — the two are equal, by
    construction rather than by coincidence. Every modifier is `X`, every `X`
    takes the base value, and the arithmetic reduces to the base formula. A
    repository that has told the platform nothing about itself gets the full
    base score and no quiet discount.
    """
    metrics = parse(vector)
    env = environment or Environment()
    base = base_score(metrics)

    def modified(key: str, fallback: str) -> str:
        value = getattr(env, key)
        return metrics[fallback] if value == "X" else value

    m_scope = modified("ms", "S")
    scope_changed = m_scope == "C"

    m_c, m_i, m_a = modified("mc", "C"), modified("mi", "I"), modified("ma", "A")
    miss = min(
        1
        - (
            (1 - _CIA[m_c] * _REQ[env.cr])
            * (1 - _CIA[m_i] * _REQ[env.ir])
            * (1 - _CIA[m_a] * _REQ[env.ar])
        ),
        0.915,
    )

    if scope_changed:
        m_impact = 7.52 * (miss - 0.029) - 3.25 * (miss * 0.9731 - 0.02) ** 13
    else:
        m_impact = 6.42 * miss

    if m_impact <= 0:
        return Scored(base=base, environmental=0.0, because=_because(env, metrics))

    m_pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[modified("mpr", "PR")]
    m_exploitability = (
        8.22
        * _AV[modified("mav", "AV")]
        * _AC[modified("mac", "AC")]
        * m_pr
        * _UI[modified("mui", "UI")]
    )

    combined = m_impact + m_exploitability
    if scope_changed:
        combined *= 1.08

    temporal = (
        _E[metrics.get("E", "X")]
        * _RL[metrics.get("RL", "X")]
        * _RC[metrics.get("RC", "X")]
    )
    environmental = _roundup(_roundup(min(combined, 10.0)) * temporal)

    return Scored(base=base, environmental=environmental, because=_because(env, metrics))


_LABELS = {
    "cr": "confidentiality matters {}",
    "ir": "integrity matters {}",
    "ar": "availability matters {}",
    "mav": "attack vector is {} here",
    "mac": "attack complexity is {} here",
    "mpr": "privileges required are {} here",
    "mui": "user interaction is {} here",
    "ms": "scope is {} here",
    "mc": "confidentiality impact is {} here",
    "mi": "integrity impact is {} here",
    "ma": "availability impact is {} here",
}
_WORDS = {
    "H": "high", "M": "medium", "L": "low", "N": "none",
    "A": "adjacent", "P": "physical", "R": "required", "U": "unchanged", "C": "changed",
}


def _because(env: Environment, metrics: dict[str, str]) -> tuple[str, ...]:
    """Which stated facts moved the score, in words somebody can check."""
    reasons = [
        template.format(_WORDS.get(getattr(env, field), getattr(env, field)))
        for field, template in _LABELS.items()
        if getattr(env, field) != "X"
    ]
    return tuple(reasons)


#: Data classification to the Confidentiality Requirement. The mapping is a
#: judgement and is stated here rather than buried in a call site so somebody
#: can disagree with it in one place.
#:
#: `public` is deliberately *not* `L`. Public data still has integrity and
#: availability worth protecting, and a repository that honestly declares its
#: data public should not find every confidentiality finding quietly demoted —
#: the declaration is about the data, not about how much the team cares.
_CONFIDENTIALITY = {
    "regulated": "H",
    "confidential": "H",
    "internal": "M",
    "public": "M",
}

#: Business criticality to the Availability Requirement. Availability is the
#: metric criticality actually speaks to: a critical service being down is the
#: definition of the problem, where a critical service leaking data is a
#: confidentiality question the classification already answered.
_AVAILABILITY = {"critical": "H", "high": "H", "medium": "M", "low": "L"}


def environment_for(
    *,
    internet_facing: bool | None = None,
    data_classification: str | None = None,
    business_criticality: str | None = None,
    compliance_scope: list[str] | None = None,
) -> Environment:
    """Turn a repository's risk profile into environmental metrics.

    **Only fields somebody actually stated.** Every argument is optional and
    `None` leaves its metric `X`, which the standard reads as the base value.
    A half-filled profile therefore moves the score halfway and never further,
    and a profile nobody has filled in moves it not at all.

    **`internet_facing=False` is the one that pays for the whole feature.** A
    network-exploitable flaw on a service nothing outside can reach is not
    network-exploitable here, and that is `MAV:L` — a real reduction, on a
    stated fact, attributable to whoever stated it.

    **`internet_facing=True` sets nothing.** The base vector already says
    `AV:N` where the flaw is network-exploitable, and re-asserting it would be
    a modifier that cannot change anything while looking like it might.

    **Compliance scope raises integrity, never lowers anything.** A regime in
    scope is a reason the number should be higher; its absence is not a reason
    for it to be lower, because most systems are in no regime and are not
    thereby safer.
    """
    fields: dict[str, str] = {}

    if internet_facing is False:
        fields["mav"] = "L"

    if data_classification:
        requirement = _CONFIDENTIALITY.get(data_classification.strip().lower())
        if requirement:
            fields["cr"] = requirement

    if business_criticality:
        requirement = _AVAILABILITY.get(business_criticality.strip().lower())
        if requirement:
            fields["ar"] = requirement

    if compliance_scope:
        # A regime in scope means somebody outside this team cares whether the
        # data is right. That is integrity.
        fields["ir"] = "H"

    return Environment(**fields)
