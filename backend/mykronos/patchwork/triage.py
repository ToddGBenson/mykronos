"""Triage classification (spec 08 §2, stage 2).

Lifted out of the pipeline because two callers now have to agree about it.
Patchwork triages a finding to decide whether to write a patch; the dashboard's
open-findings view triages the same finding to decide what to tell a person
about it. If those two used separate rules, the platform would say "likely
false positive" on one page and generate a fix for it on another, and the
Knowledge Store's whole purpose — not repeating a judgement somebody already
made — would hold in only one of the two places.

The store is the interesting input. A rule this repository keeps dismissing,
*with a written reason*, is quietened here; a rule dismissed without one is
not, on the same gate `knowledge/dampening.py` documents at length. Click
counts are not evidence.

The other input is a distribution's own decision (TheHub #60744). Debian's
security tracker records no-dsa, not-affected and will-not-fix per release; an
OS-package finding with one of those for its image's release is labelled
`likely_false_positive` with the tracker URL and state cited. A label is all it
is: nothing here closes or dismisses a finding, and a stale tracker copy, or a
finding whose fixed-version data disagrees with the tracker, changes nothing
(`debian_tracker.py`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from mykronos.debian_tracker import TrackerSnapshot, evidence_for
from mykronos.knowledge.store import KnowledgeEntry, KnowledgeStore

#: The whole vocabulary. A finding lands in exactly one of these.
CLASSIFICATIONS = ("true_positive", "likely_false_positive", "needs_human_judgment")


#: Severity ordered worst-first, so "at or above the floor" is an index
#: comparison rather than a set that has to be kept in step with the floor.
_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def _at_or_above(severity: str, floor: str) -> bool:
    try:
        return _SEVERITY_ORDER.index(severity) <= _SEVERITY_ORDER.index(floor)
    except ValueError:
        # An unrecognised severity is not silently promoted to fixable.
        return False


@dataclass(frozen=True)
class Verdict:
    """A classification, the sentence explaining it, and what it cites."""

    classification: str
    rationale: str
    evidence: list[dict[str, Any]] = field(default_factory=list)


def classify(
    finding: dict[str, Any],
    repo_full_name: str,
    store: KnowledgeStore | None = None,
    *,
    entries: list[tuple[KnowledgeEntry, float]] | None = None,
    min_severity: str = "high",
    tracker: TrackerSnapshot | None = None,
    now: datetime | None = None,
) -> tuple[str, str]:
    """Classify one finding, consulting the Knowledge Store.

    Returns the classification and the sentence explaining it. The rationale
    is not decoration: spec 01 §6 makes an unexplained verdict a bug, and a
    dashboard that labels a critical "needs human judgment" without saying why
    is one.

    `entries` is for callers classifying a batch. `active_entries()` reads and
    parses the whole knowledge file, so a caller doing this once per row would
    read that file once per row; passing the list in reads it once.

    `tracker` is a Debian security-tracker snapshot; see `classify_verdict`
    for what it can change, and the cited evidence a caller can read there.
    """
    verdict = classify_verdict(
        finding,
        repo_full_name,
        store,
        entries=entries,
        min_severity=min_severity,
        tracker=tracker,
        now=now,
    )
    return verdict.classification, verdict.rationale


def classify_verdict(
    finding: dict[str, Any],
    repo_full_name: str,
    store: KnowledgeStore | None = None,
    *,
    entries: list[tuple[KnowledgeEntry, float]] | None = None,
    min_severity: str = "high",
    tracker: TrackerSnapshot | None = None,
    now: datetime | None = None,
) -> Verdict:
    """`classify`, with the evidence the verdict cites.

    Order: a reasoned prior dismissal, then a Debian tracker decision for the
    finding's release, then severity. The tracker step only ever labels; it
    reads the finding and writes nothing back to it.
    """
    rule_id = str(finding.get("rule_id") or "")

    if entries is None:
        entries = [] if store is None else store.active_entries()

    for entry, confidence in entries:
        if (
            entry.source_type == "finding_dismissal"
            and entry.subject == rule_id
            and entry.repo_full_name in (None, repo_full_name)
            and entry.has_reason
        ):
            return Verdict(
                "likely_false_positive",
                f"This repository has dismissed {rule_id} "
                f"{entry.observations} time(s) with a written reason "
                f"(confidence {confidence:.2f}): \"{entry.reasons[0]}\". "
                "Patchwork does not generate fixes for findings the "
                "team has already judged.",
            )

    if tracker is not None:
        state = evidence_for(finding, tracker, now or datetime.now(UTC))
        if state is not None:
            return Verdict(
                "likely_false_positive",
                f"Debian's security tracker marks {state.cve} in "
                f"{state.source_package} as {state.state} for {state.release} "
                f"({state.url}). A label, not a verdict: this never closes or "
                "dismisses the finding, and a person can still act on it.",
                [state.as_evidence()],
            )

    severity = str(finding.get("severity") or "")
    if _at_or_above(severity, min_severity):
        return Verdict(
            "true_positive",
            f"A {severity} {finding.get('capability')} finding with no "
            "prior dismissal recorded for this rule.",
        )
    return Verdict(
        "needs_human_judgment",
        f"A {severity} finding. Patchwork generates fixes unprompted only at "
        f"{min_severity} and above for this repository — a draft pull request "
        "for a low finding costs more review attention than the finding is "
        "worth.",
    )
