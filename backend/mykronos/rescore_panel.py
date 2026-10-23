"""The rescore panel: base, environmental, effective, and the facts behind
each step (TheHub #60889, Triage T2 of epic #60879).

The finding record already showed three numbers and a list of facts. What it
did not show was the *working*: which fact moved which metric from what to
what, how old each fact is and when it stops counting, and how the scanner's
word became the effective severity. A reader had to know the CVSS formula and
`environment.effective_severity` to check the result. This module lays the
same computation out as three ordered steps, each with the facts it rested on.

It computes nothing new. `environment.score_vector` produced the scores and
`environment.effective_severity` the word; this only explains them, so the
panel and the stored score can never disagree.

**Freshness is a property of the fact, read against now.** `fresh`,
`expiring` (lapses within `EXPIRING_DAYS`), `lapsed`, or `undated` for a
fact nothing dated. A lapsed lowering fact is the case the stored score gets
wrong between rescores, which is why `stale_reason` exists: the record page
recomputes on read whenever the stored row no longer describes the evidence,
instead of showing yesterday's answer with today's date on the page.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from typing import Any

from mykronos import cvss
from mykronos.environment import (
    _BASE_KEY,
    ALL,
    BANDS,
    Fact,
    _lapsed,
    band,
)

#: A fact that lapses within this many days is shown as `expiring`: the
#: score it supports is about to move, and somebody can still renew it.
EXPIRING_DAYS = 7

FRESH = "fresh"
EXPIRING = "expiring"
LAPSED = "lapsed"
UNDATED = "undated"

#: Why a stored score was not used, in words the panel shows.
STALE_REASONS: dict[str, str] = {
    "not_yet_scored": "no rescore has reached this finding yet",
    "vector_changed": "the vector changed since the stored score was computed",
    "scanner_severity_changed": (
        "the scanner's severity changed since the stored score was computed"
    ),
    "fact_lapsed": (
        "a lowering fact the stored score rested on has lapsed; the next rescore "
        "would raise it"
    ),
    "evidence_changed": (
        "evidence for this repository changed and its rescore is still pending"
    ),
}


def _naive(value: datetime) -> datetime:
    return value.replace(tzinfo=None) if value.tzinfo is not None else value


def freshness(fact: Fact, now: datetime) -> dict[str, Any]:
    """`state`, `age_days` and `expires_in_days` for one fact, against now."""
    now = _naive(now)
    verified = _naive(fact.verified_at) if fact.verified_at else None
    expires = _naive(fact.expires_at) if fact.expires_at else None
    age = max(0, (now - verified).days) if verified else None
    remaining = (expires - now).days if expires else None
    if expires is not None and expires <= now:
        state = LAPSED
    elif expires is not None and expires - now <= timedelta(days=EXPIRING_DAYS):
        state = EXPIRING
    elif verified is not None or expires is not None:
        state = FRESH
    else:
        state = UNDATED
    return {"freshness": state, "age_days": age, "expires_in_days": remaining}


def _from_value(fact: Fact, metrics: Mapping[str, str]) -> str:
    """What the metric was before this fact: the base metric's value for an
    exploitability modifier, `X` (not defined) for a security requirement."""
    base_key = _BASE_KEY.get(fact.metric)
    if base_key is not None:
        return str(metrics.get(base_key) or "X")
    return "X"


def _fact_line(fact: Fact, metrics: Mapping[str, str], now: datetime) -> dict[str, Any]:
    fresh = freshness(fact, now)
    before = _from_value(fact, metrics)
    return {
        "metric": fact.metric,
        "from_value": before,
        "to_value": fact.value,
        "applied": fact.applied,
        "direction": fact.direction,
        "because": fact.because,
        "not_applied_reason": fact.not_applied_reason,
        "source_kind": fact.source_kind,
        "source_id": fact.source_id,
        "tier": fact.tier,
        **fresh,
    }


def steps(
    *,
    vector: str,
    vector_source: str,
    vector_version: str,
    base: float,
    environmental: float,
    scanner_severity: str,
    effective: str | None,
    facts: Sequence[Fact],
    now: datetime,
    in_kev: bool = False,
) -> list[dict[str, Any]]:
    """The three steps, in order, each with the facts it rested on.

    Every fact appears on the environmental step, applied or not: one that was
    not counted is the evidence somebody could go and get.
    """
    try:
        metrics = cvss.parse(vector)
    except cvss.VectorError:
        metrics = {}
    base_band = band(base)
    env_band = band(environmental)
    applied = [f for f in facts if f.applied]

    out: list[dict[str, Any]] = [
        {
            "key": "base",
            "label": "Base score",
            "score": base,
            "severity": base_band,
            "detail": (
                f"CVSS {vector_version} base vector from {vector_source}: the "
                "vulnerability in the abstract, the same number on every system."
            ),
            "facts": [],
        }
    ]

    if not facts:
        env_detail = (
            "Nothing about this system is stated, so every modifier takes the "
            "base value: the same score, as an upper bound and never a discount."
        )
    elif not applied:
        env_detail = (
            f"{len(facts)} fact(s) stated, none applied, so the score stands at "
            "the base value. Each says why it was not counted."
        )
    else:
        moved = "unchanged" if env_band == base_band else f"{base_band} to {env_band}"
        env_detail = (
            f"{len(applied)} of {len(facts)} fact(s) applied; band {moved}."
        )
    out.append(
        {
            "key": "environmental",
            "label": "Environmental score",
            "score": environmental,
            "severity": env_band,
            "detail": env_detail,
            "facts": [_fact_line(f, metrics, now) for f in facts],
        }
    )

    word = (scanner_severity or "").strip().lower()
    shift = BANDS.index(env_band) - BANDS.index(base_band)
    if effective is None:
        eff_detail = "Not computed."
    elif shift == 0:
        eff_detail = (
            f"The environment kept the score in the {base_band} band, so the "
            f"scanner's {word or 'severity'} stands."
        )
    else:
        direction = "down" if shift < 0 else "up"
        eff_detail = (
            f"The scanner said {word}; the environment moved the score "
            f"{abs(shift)} band(s) {direction} ({base_band} to {env_band}), so "
            f"{word} moves the same distance, clamped to low..critical: {effective}."
        )
    notes: list[str] = []
    if in_kev and effective:
        order = ("info", "low", "medium", "high", "critical")
        floor = word if word in order and order.index(word) < order.index("high") else "high"
        if effective in order and order.index(effective) < order.index(floor):
            notes.append(
                f"KEV-listed: Oracle counts this finding no lower than {floor}, "
                "whatever the environment says. An actively exploited "
                "vulnerability is not argued down."
            )
    out.append(
        {
            "key": "effective",
            "label": "Effective severity",
            "score": None,
            "severity": effective,
            "detail": eff_detail,
            "facts": [],
            "notes": notes,
        }
    )
    return out


def stale_reason(
    stored: Any,
    *,
    vector: str,
    scanner_severity: str,
    repo_full_name: str,
    onboarding_id: str | None,
    pending: Mapping[str, float],
    now: datetime,
) -> str | None:
    """Why the stored score cannot be shown as current, or None when it can.

    The rescore keeps the store right eventually; this is what keeps the page
    right now. Order matters only for the sentence shown.
    """
    if stored is None:
        return "not_yet_scored"
    if stored.vector != vector:
        return "vector_changed"
    if (stored.scanner_severity or "").strip().lower() != (
        scanner_severity or ""
    ).strip().lower():
        return "scanner_severity_changed"
    if _lapsed(stored, _naive(now)):
        return "fact_lapsed"
    keys = {ALL, repo_full_name}
    if onboarding_id:
        keys.add(f"onboarding:{onboarding_id}")
    if keys.intersection(pending):
        return "evidence_changed"
    return None
