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

from mykronos import regression
from mykronos.knowledge.capture import safe_capture
from mykronos.knowledge.store import KnowledgeStore
from mykronos.lake.buffer import WriteAheadBuffer
from mykronos.lake.catalog import Catalog
from mykronos.patchwork.regression_prompt import (
    UNSTATED as REGRESSION_UNSTATED,
)
from mykronos.patchwork.regression_prompt import (
    parse_regression_test,
)
from mykronos.patchwork.rejection import UNSTATED, capture_reason, parse_rejection
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
    merge_commit_sha: str | None = None,
    pr_body: str = "",
) -> str | None:
    """Update the event for a closed Patchwork pull request.

    Returns the event id, or None if this pull request was not one of ours —
    which is the common case, since the webhook fires for every pull request
    in the repository.
    """
    rows = catalog.query(
        """
        SELECT event_id, finding_id, rationale, fixer_name
        FROM remediation_events
        WHERE repo_full_name = ? AND fix_pr_number = ?
        LIMIT 1
        """,
        [repo_full_name, pr_number],
    )
    if not rows:
        return None

    event_id, finding_id, rationale = (str(v) for v in rows[0][:3])
    fixer_name = str(rows[0][3]) if rows[0][3] else None
    status = "merged" if merged else "closed_unmerged"

    # Only a close asks a question; a merge answers it by itself.
    code, reason_text = parse_rejection(pr_body) if not merged else (None, "")

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
                # A merged fix earns a verification (spec 25 §1). `pending` is
                # a stored state rather than a null so "waiting for evidence"
                # and "nobody ever asked" stay distinguishable — an abandoned
                # fix is never verified and must not look like one that is
                # still being checked.
                "verification_commit_sha": merge_commit_sha if merged else None,
                "verification_outcome": "pending" if merged else None,
                "fixer_name": fixer_name,
                "rejection_reason_code": code,
                "rejection_reason": reason_text or None,
                "created_at": utcnow(),
                "updated_at": utcnow(),
            }
        ],
    )

    if store is not None and code and code != UNSTATED:
        rule_rows = catalog.query(
            "SELECT rule_id FROM findings WHERE finding_id = ? LIMIT 1", [finding_id]
        )
        safe_capture(
            capture_reason,
            store,
            repo_full_name=repo_full_name,
            rule_id=str(rule_rows[0][0]) if rule_rows else "",
            fixer_name=fixer_name,
            code=code,
            reason=reason_text,
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

    # The regression link, from the line Patchwork put in the body (spec 31
    # §2, B-011). Only on a merge: a test named on a fix nobody took is a
    # claim about code that is not in the repository.
    #
    # Failure here must not cost the outcome row. The webhook has already
    # recorded the merge by this point, and losing that to a link nobody
    # asked for would be the wrong trade -- the same posture the rejection
    # capture above takes.
    if merged:
        _link_regression_test(
            buffer,
            repo_full_name=repo_full_name,
            finding_id=finding_id,
            pr_body=pr_body,
            pr_number=pr_number,
        )

    logger.info(
        "Patchwork PR %s#%s %s (finding %s)",
        repo_full_name,
        pr_number,
        status,
        finding_id,
    )
    return event_id


def _link_regression_test(
    buffer: WriteAheadBuffer,
    *,
    repo_full_name: str,
    finding_id: str,
    pr_body: str,
    pr_number: int,
) -> str | None:
    """Pin the test the merger named, if they named one.

    `asserted`, never `demonstrated`, and that is the honest grade rather than
    a shortfall: the test arrives *in* this pull request, so it does not exist
    on the parent commit and no ordinary lane run there can have exercised it.
    Spec 31 §2 defines `demonstrated` as having watched the test fail against
    the vulnerable code and pass against the fixed code, which needs a lane
    invocation that takes a ref. `regression_prompt.py` sets out why that is
    not reachable from here.

    Idempotent by construction: `regression.record` keys the row on
    (repo, finding, test), so a redelivered webhook updates one link instead
    of inflating the count.
    """
    identifier, lane = parse_regression_test(pr_body)
    if identifier == REGRESSION_UNSTATED:
        return None

    try:
        link = regression.record(
            buffer,
            repo_full_name=repo_full_name,
            finding_id=finding_id,
            test_identifier=identifier,
            capability=lane,
            evidence=regression.ASSERTED,
            linked_by=f"patchwork-pr-{pr_number}",
        )
    except regression.RegressionError as exc:
        # A lane this platform does not run, or an empty identifier that got
        # past the parser. Logged and dropped: the merge is recorded either
        # way, and a webhook that fails often enough is a webhook GitHub
        # disables.
        logger.warning(
            "Could not link regression test %r from %s#%s: %s",
            identifier,
            repo_full_name,
            pr_number,
            exc,
        )
        return None

    logger.info(
        "Pinned regression test %r to finding %s from %s#%s (asserted)",
        identifier,
        finding_id,
        repo_full_name,
        pr_number,
    )
    return link


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
