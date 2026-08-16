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
"""

from __future__ import annotations

from typing import Any

from mykronos.knowledge.store import KnowledgeEntry, KnowledgeStore

#: The whole vocabulary. A finding lands in exactly one of these.
CLASSIFICATIONS = ("true_positive", "likely_false_positive", "needs_human_judgment")


def classify(
    finding: dict[str, Any],
    repo_full_name: str,
    store: KnowledgeStore | None = None,
    *,
    entries: list[tuple[KnowledgeEntry, float]] | None = None,
) -> tuple[str, str]:
    """Classify one finding, consulting the Knowledge Store.

    Returns the classification and the sentence explaining it. The rationale
    is not decoration: spec 01 §6 makes an unexplained verdict a bug, and a
    dashboard that labels a critical "needs human judgment" without saying why
    is one.

    `entries` is for callers classifying a batch. `active_entries()` reads and
    parses the whole knowledge file, so a caller doing this once per row would
    read that file once per row; passing the list in reads it once.
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
            return (
                "likely_false_positive",
                f"This repository has dismissed {rule_id} "
                f"{entry.observations} time(s) with a written reason "
                f"(confidence {confidence:.2f}): \"{entry.reasons[0]}\". "
                "Patchwork does not generate fixes for findings the "
                "team has already judged.",
            )

    severity = str(finding.get("severity") or "")
    if severity in ("critical", "high"):
        return (
            "true_positive",
            f"A {severity} {finding.get('capability')} finding with no "
            "prior dismissal recorded for this rule.",
        )
    return (
        "needs_human_judgment",
        f"A {severity} finding. Patchwork only generates fixes for high "
        "and critical findings unprompted — a draft pull request for a low "
        "finding costs more review attention than the finding is worth.",
    )
