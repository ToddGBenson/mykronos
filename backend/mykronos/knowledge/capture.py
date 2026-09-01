"""Turning human actions into learnings (spec 11 §4).

Two call sites today: a finding dismissed from the dashboard, and an Oracle
recommendation overridden. Both already existed and both already demanded a
reason; this is what finally does something with it.

The functions here are deliberately not exceptions-free wrappers around the
store — they are the place the *text* of a learning is composed, because that
text is what gets retrieved later and a badly-worded one is worse than none.
Each reads as a sentence somebody could have written.
"""

from __future__ import annotations

import logging
from typing import Any

from mykronos.knowledge.store import AddResult, KnowledgeStore

logger = logging.getLogger(__name__)

#: Dispositions that mean "this finding is not a real problem here". Only these
#: teach anything about the *rule*. `accepted_risk` deliberately does not: it
#: says the finding is real and we are living with it, which is a statement
#: about appetite, not about detection quality, and dampening a rule because
#: somebody accepted its risk would be exactly wrong.
TEACHES_ABOUT_THE_RULE = {"false_positive"}


def capture_dismissal(
    store: KnowledgeStore,
    *,
    repo_full_name: str,
    rule_id: str,
    finding_id: str,
    status: str,
    reason: str,
    capability: str = "",
    actor: str = "",
) -> AddResult | None:
    """Record that a human dismissed a finding (spec 11 §4).

    Returns None for dispositions that say nothing about the rule — see
    `TEACHES_ABOUT_THE_RULE`. A `suppressed` finding is hidden, not disproved.
    """
    if status not in TEACHES_ABOUT_THE_RULE:
        return None

    cleaned = reason.strip()
    detail = f" — {cleaned}" if cleaned else " with no reason given"
    text = (
        f"{rule_id} in {repo_full_name} was dismissed as a false positive"
        f"{detail}"
    )
    if capability:
        text += f" (reported by {capability})"

    result = store.add_entry(
        source_type="finding_dismissal",
        # The rule is what recurs. A second finding of the same rule in the
        # same repo is the same learning, seen again — which is what makes the
        # confidence model mean anything.
        subject=rule_id,
        source_ref=finding_id,
        text=text,
        repo_full_name=repo_full_name,
        reason=cleaned,
    )
    logger.info(
        "Knowledge: %s %s for %s in %s (observations=%s, confidence=%.2f)",
        "recorded" if result.created else "reconfirmed",
        "dismissal",
        rule_id,
        repo_full_name,
        result.entry.observations,
        result.entry.confidence,
    )
    return result


def capture_classification_rejected(
    store: KnowledgeStore,
    *,
    repo_full_name: str,
    rule_id: str,
    finding_id: str,
    classification: str,
    reason: str,
    actor: str = "",
) -> AddResult | None:
    """Record that a person disagreed with the classifier (B-020).

    The counterweight to `capture_dismissal`. Agreement already leaves a trace
    -- the finding changes status and the rule earns a dismissal observation --
    while disagreement left none at all, so a classifier calling real findings
    `likely_false_positive` would look exactly like a classifier nobody had
    got round to. A verdict nothing ever contradicts is a verdict nobody is
    checking.

    Deliberately does **not** dampen anything, and is not in
    `TEACHES_ABOUT_THE_RULE`. It teaches about the *classifier*, not about the
    rule: the finding is real and stays open, and quietening the rule on the
    strength of somebody saying it was real would invert the meaning of the
    whole loop.
    """
    cleaned = reason.strip()
    detail = f" — {cleaned}" if cleaned else " with no reason given"
    text = (
        f"{rule_id} in {repo_full_name} was classified {classification} and a "
        f"person disagreed{detail}"
    )

    result = store.add_entry(
        source_type="classification_rejected",
        subject=rule_id,
        source_ref=finding_id,
        text=text,
        repo_full_name=repo_full_name,
        reason=cleaned,
    )
    logger.info(
        "Knowledge: %s classifier rejection for %s in %s (observations=%s)",
        "recorded" if result.created else "reconfirmed",
        rule_id,
        repo_full_name,
        result.entry.observations,
    )
    return result


def capture_override(
    store: KnowledgeStore,
    *,
    repo_full_name: str,
    decision_id: str,
    original_recommendation: str,
    accepted_recommendation: str,
    reason: str,
    score: int | None = None,
) -> AddResult:
    """Record that a human overrode an Oracle recommendation (spec 11 §4).

    spec 09 §6 calls overrides "exactly the data that should most influence
    policy tuning over time", and this is the mechanism by which that becomes
    true rather than aspirational.

    The subject is the recommendation that was overturned, not the decision id:
    what recurs — and what a policy change would address — is "we keep
    overriding no_go on this repo", never "we overrode decision 4f2a once".
    """
    cleaned = reason.strip()
    scored = f" scoring {score}/100" if score is not None else ""
    text = (
        f"An Oracle {original_recommendation.replace('_', ' ')} decision"
        f"{scored} on {repo_full_name} was overridden to "
        f"{accepted_recommendation.replace('_', ' ')} — {cleaned}"
    )

    result = store.add_entry(
        source_type="decision_override",
        subject=original_recommendation,
        source_ref=decision_id,
        text=text,
        repo_full_name=repo_full_name,
        reason=cleaned,
    )
    logger.info(
        "Knowledge: %s override of %s on %s (observations=%s)",
        "recorded" if result.created else "reconfirmed",
        original_recommendation,
        repo_full_name,
        result.entry.observations,
    )
    return result


def capture_retro_note(
    store: KnowledgeStore,
    *,
    subject: str,
    text: str,
    author: str,
    repo_full_name: str | None = None,
) -> AddResult:
    """A human writing down something they noticed (spec 11 §4).

    The only entry type with no machine-generated component, and the only one
    where the free text *is* the learning rather than an annotation on one.
    """
    return store.add_entry(
        source_type="retro_note",
        subject=subject,
        source_ref=f"retro:{author}",
        text=text.strip(),
        repo_full_name=repo_full_name,
        reason=text.strip(),
    )


def safe_capture(fn: Any, *args: Any, **kwargs: Any) -> Any:
    """Run a capture, never letting it break the action that triggered it.

    A dismissal is a user action that has already succeeded by the time we get
    here — the finding is marked, the lake is written. Failing the request
    because a JSONL file could not be opened would undo a real thing to protect
    a derived one.
    """
    try:
        return fn(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 — see docstring
        logger.warning("Could not record a knowledge entry: %s", exc)
        return None
