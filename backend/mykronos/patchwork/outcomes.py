"""Keeping a draft fix's fate in sync, and learning from it (spec 08 §4, §9).

Two things happen when somebody closes a Patchwork pull request, and the
second is the more valuable.

The obvious one is bookkeeping: `pr_status` moves off `draft_open`, which
stops Oracle discounting the finding for a fix that is no longer in flight.
Without this the discount never expires and an abandoned auto-fix quietly
lowers a repository's score forever.

The other is that a merged auto-fix and an abandoned one are the clearest
verdicts a human ever gives this platform. spec 11 §9 calls remediation
outcomes "the single richest source of retro learning signal in the whole
system", and it is right: everywhere else the platform infers what people
think from what they dismiss. Here they either took the fix or they did not.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from mykronos.knowledge.capture import safe_capture
from mykronos.knowledge.store import KnowledgeStore
from mykronos.lake.buffer import WriteAheadBuffer
from mykronos.lake.catalog import Catalog
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)


def record_pr_outcome(
    catalog: Catalog,
    buffer: WriteAheadBuffer,
    repo_full_name: str,
    pr_number: int,
    *,
    merged: bool,
    store: KnowledgeStore | None = None,
) -> str | None:
    """Update the event for a closed Patchwork pull request.

    Returns the event id, or None if this pull request was not one of ours —
    which is the common case, since the webhook fires for every pull request
    in the repository.
    """
    rows = catalog.query(
        """
        SELECT event_id, finding_id, rationale
        FROM remediation_events
        WHERE repo_full_name = ? AND fix_pr_number = ?
        LIMIT 1
        """,
        [repo_full_name, pr_number],
    )
    if not rows:
        return None

    event_id, finding_id, rationale = (str(v) for v in rows[0])
    status = "merged" if merged else "closed_unmerged"

    buffer.append(
        "remediation_events",
        [
            {
                "event_id": event_id,
                "repo_full_name": repo_full_name,
                "finding_id": finding_id,
                "toxic_combination_id": None,
                "contributing_finding_ids": json.dumps([]),
                "pipeline_stage_reached": "pr_opened",
                "triage_classification": "true_positive",
                "fix_pr_number": pr_number,
                "fix_pr_url": None,
                "pr_status": status,
                "rationale": rationale,
                "created_at": utcnow(),
                "updated_at": utcnow(),
            }
        ],
    )

    if store is not None:
        safe_capture(
            _capture_outcome,
            store,
            repo_full_name=repo_full_name,
            finding_id=finding_id,
            pr_number=pr_number,
            merged=merged,
        )

    logger.info(
        "Patchwork PR %s#%s %s (finding %s)",
        repo_full_name,
        pr_number,
        status,
        finding_id,
    )
    return event_id


def _capture_outcome(
    store: KnowledgeStore,
    *,
    repo_full_name: str,
    finding_id: str,
    pr_number: int,
    merged: bool,
) -> Any:
    """Record the verdict as a learning (spec 11 §4, §9).

    The subject is the *outcome*, not the finding: what recurs, and what would
    change how Patchwork behaves, is "auto-fixes get merged here" or
    "auto-fixes get closed here". One merged pull request is an anecdote; a
    repository where nine of them were closed unmerged is telling you the
    fixes are not wanted, and that is a fact about the repository rather than
    about any one finding.

    A closed-unmerged fix carries no written reason, so it starts low and
    cannot dampen anything — consistent with every other unreasoned signal
    (spec 11 §4). It still resets decay, which is the honest amount of
    information a closed pull request contains.
    """
    verdict = "merged" if merged else "closed_unmerged"
    text = (
        f"A Patchwork fix for {finding_id} in {repo_full_name} was "
        + ("merged as-is." if merged else "closed without merging.")
        + (
            " Auto-fixes of this kind are being accepted here."
            if merged
            else " Worth asking whether the fix was wrong or simply unwanted; "
            "the pull request itself has the diff."
        )
    )
    return store.add_entry(
        source_type="remediation_outcome",
        subject=verdict,
        source_ref=f"pr:{pr_number}",
        text=text,
        repo_full_name=repo_full_name,
        # No human typed anything, so no reason. Deliberate: this is evidence
        # a pattern recurs and no evidence at all about why.
        reason="",
    )
