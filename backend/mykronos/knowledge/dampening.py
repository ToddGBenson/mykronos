"""False-positive dampening (spec 11 §6.1, spec 09 §4).

The one place a learning changes a score. Everything else the Knowledge Store
does is advisory — retrieval context, retro reports, promotion proposals — so
this is where the care goes.

Two sources, deliberately:

- **The lake** supplies the denominator. Findings are ground truth for how
  often a rule actually fired; the Knowledge Store has no idea, because nobody
  clicks anything about the ones that were real.
- **The store** supplies the licence. A rule is only dampened if humans wrote
  down *why*, at least `min_observations` times. Without that gate, dampening
  would be driven by click counts, and the loudest, most-dismissed rule would
  be quietened fastest whether or not anyone could say what was wrong with it.

The gate is the whole design. An earlier draft of spec 11 had neither a
denominator nor a minimum, which meant one dismissal of a rule seen once was a
100% false-positive rate.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from mykronos.knowledge.store import KnowledgeStore
from mykronos.lake.catalog import Catalog

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Dampened:
    """One rule quietened in one repo, with the evidence for it."""

    rule_id: str
    dismissed: int
    total: int
    rate: float
    observations: int
    confidence: float
    reasons: list[str]

    def as_snapshot(self, factor: float) -> dict[str, Any]:
        """The record that appears in `inputs_snapshot` (spec 11 §6.1).

        A weight that quietly halved is exactly the kind of hidden input
        spec 09 exists to prevent, so the rate, the counts and the human
        reasons all travel with the decision.
        """
        return {
            "rule_id": self.rule_id,
            "false_positive_rate": round(self.rate, 3),
            "dismissed": self.dismissed,
            "of_total": self.total,
            "reasoned_observations": self.observations,
            "confidence": round(self.confidence, 3),
            "weight_multiplier": round(1.0 - factor, 3),
            "reasons": self.reasons[:3],
        }


def dampened_rules(
    catalog: Catalog,
    store: KnowledgeStore,
    repo_full_name: str,
    *,
    threshold: float,
    min_observations: int,
    min_confidence: float = 0.2,
    as_of: datetime | None = None,
) -> dict[str, Dampened]:
    """Rules whose weight should be reduced for this repo, keyed by rule_id.

    Returns `{}` on any failure. Dampening is an optimisation on top of a
    correct score; losing it must never cost the decision, and spec 11 §6
    makes graceful degradation a requirement rather than a courtesy.
    """
    try:
        eligible = {
            entry.subject: (entry, confidence)
            for entry, confidence in store.active_entries(
                min_confidence=min_confidence, as_of=as_of
            )
            if entry.source_type == "finding_dismissal"
            and entry.repo_full_name in (None, repo_full_name)
            # No reason, no dampening. spec 11 §4: reasons are what make a
            # learning actionable rather than a statistic.
            and entry.has_reason
            and entry.observations >= min_observations
        }
        if not eligible:
            return {}

        placeholders = ", ".join("?" for _ in eligible)
        rows = catalog.query(
            f"""
            SELECT rule_id,
                   count(*) AS total,
                   count(*) FILTER (WHERE status = 'false_positive') AS dismissed
            FROM findings
            WHERE repo_full_name = ? AND rule_id IN ({placeholders})
            GROUP BY rule_id
            """,
            [repo_full_name, *eligible],
        )
    except Exception as exc:  # noqa: BLE001 — see docstring
        logger.warning("Could not compute false-positive dampening: %s", exc)
        return {}

    dampened: dict[str, Dampened] = {}
    for rule_id, total, dismissed in rows:
        total, dismissed = int(total), int(dismissed)
        if total == 0:
            continue
        rate = dismissed / total
        if rate < threshold:
            continue
        entry, confidence = eligible[str(rule_id)]
        dampened[str(rule_id)] = Dampened(
            rule_id=str(rule_id),
            dismissed=dismissed,
            total=total,
            rate=rate,
            observations=entry.observations,
            confidence=confidence,
            reasons=list(entry.reasons),
        )

    if dampened:
        logger.info(
            "Dampening %s rule(s) for %s: %s",
            len(dampened),
            repo_full_name,
            ", ".join(sorted(dampened)),
        )
    return dampened


def open_finding_counts_excluding_dampened(
    catalog: Catalog,
    repo_full_name: str,
    dampened: dict[str, Dampened],
) -> dict[str, dict[str, int]]:
    """Open findings per severity, split into dampened and undampened.

    Returned split rather than pre-weighted so the caller can show both counts.
    "Four criticals, one of them from a rule you have dismissed six times" is a
    more useful sentence than a single adjusted number, and it is the sentence
    a developer needs to decide whether the dampening is still right.
    """
    if not dampened:
        return {}

    placeholders = ", ".join("?" for _ in dampened)
    rows = catalog.query(
        f"""
        SELECT severity, count(*)
        FROM findings
        WHERE repo_full_name = ? AND status = 'open' AND rule_id IN ({placeholders})
        GROUP BY severity
        """,
        [repo_full_name, *dampened],
    )
    return {str(severity): {"dampened": int(count)} for severity, count in rows}
