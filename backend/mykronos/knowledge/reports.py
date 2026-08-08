"""Retro and trend reports (spec 11 §7).

A retro report says what changed in one period. A trend report says what has
been true across several, and refuses to be generated from too few — spec 11
§10 makes that an acceptance criterion rather than a nicety, because the whole
failure mode of a trend line is that three points look like a direction.

Both are computed from the store rather than accumulated as they go, so any
past report can be re-derived. That is the same property `decayed_confidence`
has and for the same reason: a number nobody can reproduce is a number nobody
can argue with.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from mykronos.knowledge.promotion import PromotionCandidate, find_cross_project_candidates
from mykronos.knowledge.store import KnowledgeStore
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

#: spec 11 §7. Fewer than this and a "trend" is just noise with a line through
#: it.
MIN_TREND_PERIODS = 4


class NotEnoughHistoryError(ValueError):
    """Raised rather than producing a misleading report (spec 11 §10)."""


@dataclass
class RetroReport:
    period_start: datetime
    period_end: datetime
    new_entries: list[dict[str, Any]] = field(default_factory=list)
    reconfirmed: list[dict[str, Any]] = field(default_factory=list)
    decaying: list[dict[str, Any]] = field(default_factory=list)
    promotion_candidates: list[PromotionCandidate] = field(default_factory=list)
    unreasoned: int = 0

    @property
    def is_quiet(self) -> bool:
        return not (self.new_entries or self.reconfirmed or self.promotion_candidates)


def _describe(entry: Any, confidence: float) -> dict[str, Any]:
    return {
        "entry_id": entry.entry_id,
        "subject": entry.subject,
        "source_type": entry.source_type,
        "repo_full_name": entry.repo_full_name,
        "text": entry.text,
        "observations": entry.observations,
        "confidence": round(confidence, 3),
        "last_confirmed_at": entry.last_confirmed_at,
        "reasons": entry.reasons[:3],
    }


def build_retro(
    store: KnowledgeStore,
    *,
    period_days: int = 14,
    as_of: datetime | None = None,
    decay_warning_at: float = 0.3,
) -> RetroReport:
    """What the platform learned, and forgot, in one period (spec 11 §7).

    "Decaying" is the section people should read first and the one a naive
    implementation leaves out. An entry sliding toward irrelevance is either
    a problem that genuinely went away — worth noticing — or a rule everybody
    stopped bothering to dismiss because they gave up on the tool. Those look
    identical in the data and completely different in a retro conversation,
    which is exactly why a human is reading this.
    """
    stamp = as_of or utcnow()
    start = stamp - timedelta(days=period_days)

    report = RetroReport(period_start=start, period_end=stamp)

    for entry in store.list_entries():
        confidence = store.decayed_confidence(entry, stamp)
        described = _describe(entry, confidence)

        if entry.created_at >= start:
            report.new_entries.append(described)
        elif entry.last_confirmed_at >= start:
            report.reconfirmed.append(described)
        elif confidence < decay_warning_at:
            report.decaying.append(described)

        if not entry.has_reason:
            report.unreasoned += 1

    report.promotion_candidates = find_cross_project_candidates(store, as_of=stamp)

    for bucket in (report.new_entries, report.reconfirmed, report.decaying):
        bucket.sort(key=lambda row: (-row["confidence"], row["subject"]))
    return report


@dataclass
class TrendReport:
    periods: int
    period_days: int
    points: list[dict[str, Any]] = field(default_factory=list)

    @property
    def direction(self) -> str:
        """Whether the learning rate is rising, falling, or flat.

        Deliberately three words rather than a slope. A slope on four points
        invites more precision than four points can carry.
        """
        if len(self.points) < 2:
            return "unknown"
        first, last = self.points[0]["new_entries"], self.points[-1]["new_entries"]
        if last > first:
            return "rising"
        if last < first:
            return "falling"
        return "flat"


def build_trend(
    store: KnowledgeStore,
    *,
    periods: int = MIN_TREND_PERIODS,
    period_days: int = 14,
    as_of: datetime | None = None,
) -> TrendReport:
    """Learning volume across several periods (spec 11 §7).

    Raises `NotEnoughHistoryError` rather than producing a report from too little
    data. spec 11 §10 requires the clear error, and the reason is worth
    stating: a trend report that quietly renders two points is more dangerous
    than no report, because somebody will present it.
    """
    if periods < MIN_TREND_PERIODS:
        raise NotEnoughHistoryError(
            f"A trend report needs at least {MIN_TREND_PERIODS} periods; "
            f"{periods} was requested. Fewer points than that is noise with a "
            "line drawn through it, and it will be presented as a direction."
        )

    stamp = as_of or utcnow()
    entries = store.list_entries()
    if not entries:
        raise NotEnoughHistoryError(
            "The Knowledge Store is empty, so there is no trend to report."
        )

    oldest = min(entry.created_at for entry in entries)
    covered = (stamp - oldest).days
    required = MIN_TREND_PERIODS * period_days
    if covered < required:
        raise NotEnoughHistoryError(
            f"The Knowledge Store holds {covered} days of history; a trend "
            f"report over {periods} periods of {period_days} days needs "
            f"{required}. Come back later rather than reading a shape into "
            "this."
        )

    report = TrendReport(periods=periods, period_days=period_days)
    for index in range(periods, 0, -1):
        end = stamp - timedelta(days=period_days * (index - 1))
        start = end - timedelta(days=period_days)
        created = [e for e in entries if start <= e.created_at < end]
        confirmed = [
            e
            for e in entries
            if start <= e.last_confirmed_at < end and e.created_at < start
        ]
        report.points.append(
            {
                "period_start": start,
                "period_end": end,
                "new_entries": len(created),
                "reconfirmations": len(confirmed),
                "with_reasons": sum(1 for e in created if e.has_reason),
                "overrides": sum(
                    1 for e in created if e.source_type == "decision_override"
                ),
                "dismissals": sum(
                    1 for e in created if e.source_type == "finding_dismissal"
                ),
            }
        )
    return report


def render_retro_markdown(report: RetroReport) -> str:
    """The report as a committable markdown file (spec 11 §7)."""
    lines = [
        f"# Security retro — {report.period_start:%Y-%m-%d} to "
        f"{report.period_end:%Y-%m-%d}",
        "",
    ]

    if report.is_quiet:
        lines += [
            "Nothing was learned this period: no findings dismissed, no "
            "decisions overridden, no notes written.",
            "",
            "That is worth a moment rather than a shrug. It means either the "
            "tools produced nothing worth arguing with, or nobody had time to "
            "argue with them.",
            "",
        ]

    if report.new_entries:
        lines += [f"## New learnings ({len(report.new_entries)})", ""]
        for row in report.new_entries:
            lines.append(f"- **{row['subject']}** — {row['text']}")
        lines.append("")

    if report.reconfirmed:
        lines += [f"## Reconfirmed ({len(report.reconfirmed)})", ""]
        for row in report.reconfirmed:
            lines.append(
                f"- **{row['subject']}** — seen again "
                f"({row['observations']} observations, confidence "
                f"{row['confidence']:.2f})"
            )
        lines.append("")

    if report.decaying:
        lines += [
            f"## Fading ({len(report.decaying)})",
            "",
            "Not reconfirmed for long enough that they no longer influence "
            "anything. Either the problem went away, or people stopped "
            "reporting it — worth asking which.",
            "",
        ]
        for row in report.decaying:
            lines.append(
                f"- **{row['subject']}** — confidence {row['confidence']:.2f}, "
                f"last confirmed {row['last_confirmed_at']:%Y-%m-%d}"
            )
        lines.append("")

    if report.promotion_candidates:
        lines += [
            f"## Ready to generalise ({len(report.promotion_candidates)})",
            "",
            "Confirmed independently across repositories. Promotion is a "
            "human decision and nothing below has been applied (spec 11 §2).",
            "",
        ]
        for candidate in report.promotion_candidates:
            lines.append(f"- {candidate.summary()}")
        lines.append("")

    if report.unreasoned:
        lines += [
            "## Dismissals with no reason",
            "",
            f"{report.unreasoned} entr{'y' if report.unreasoned == 1 else 'ies'} "
            "were recorded without a written reason. They are kept, but they "
            "cannot raise confidence, cannot be promoted, and cannot dampen a "
            "rule — so the effort of dismissing was spent without teaching the "
            "platform anything.",
            "",
        ]

    lines.append(
        "<sub>Generated from the Knowledge Store. Every figure is "
        "reproducible from the stored entries and this period's dates.</sub>"
    )
    return "\n".join(lines)
