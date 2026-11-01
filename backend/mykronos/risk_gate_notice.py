"""The risk gate posts when a repository's decision changes (TheHub #61197).

`POST /api/oracle/evaluate` used to post "A risk decision refused a commit"
for every `no_go`. A repository refused for its standing backlog is refused on
every commit, so the same score was posted up to 33 times a day (130 posts in
14 days, about 5% of `#alerts`), and none of the repeats said anything the
first had not. This applies the `red_main` rule to the gate instead:

* **clear -> refused** (or refused the first time a scope is seen): one post.
* **refused -> refused**: nothing, at any score. The exception is a commit
  that itself introduced a critical or high finding (`introduced_blocking`):
  that is a new blocking finding, not the old backlog, and it posts.
* **refused -> clear**: one "passes again" post, naming the commit the
  refusal began at and how many refusals were held back.
* **clear -> clear**: nothing, as before. The gate passing is not news.

"Refused" is `recommendation == "no_go"`; everything else is clear. The key
is the repository and the decision's scope (`subject_of`): a pull request is
its own subject, so a clean PR does not reset main's refusal and a refused PR
does not speak for main. Every decision is still recorded and shown on the
dashboard; only the Slack post is de-duplicated.

The state is stored in `risk_gate_notice_states`, so a restart does not post
the same refusal again. If that store cannot be read or written, the gate
falls back to posting every refusal: a duplicate is better than silence.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from mykronos.db.models import RiskGateNoticeState
from mykronos.db.session import Database
from mykronos.logsafe import scrub
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

REFUSED = "refused"
CLEAR = "clear"

#: What `decide` returns when a post is due.
POST_REFUSED = "refused"
POST_NEW_BLOCKING = "new_blocking"
POST_CLEARED = "cleared"


def state_of(recommendation: str) -> str:
    return REFUSED if recommendation == "no_go" else CLEAR


def subject_of(decision_type: str, pr_number: int | None) -> str:
    """The scope a decision belongs to: one per pull request, else its type."""
    if decision_type == "pr_gate" and pr_number is not None:
        return f"pr_gate#{pr_number}"
    return decision_type


def decide(previous: str | None, recommendation: str, introduced_blocking: bool) -> str | None:
    """Which post, if any, this decision earns given the recorded state."""
    current = state_of(recommendation)
    if current == REFUSED:
        if previous != REFUSED:
            return POST_REFUSED
        return POST_NEW_BLOCKING if introduced_blocking else None
    return POST_CLEARED if previous == REFUSED else None


@dataclass(frozen=True)
class Outcome:
    """What `record` decided, and what the clear post needs to say."""

    post: str | None
    #: The commit the previous state began at (for a `cleared` post).
    previous_since_sha: str = ""
    #: Refusals that were not posted while it was refused.
    previous_held: int = 0


def record(
    db: Database,
    repo_full_name: str,
    subject: str,
    *,
    recommendation: str,
    introduced_blocking: bool,
    commit_sha: str,
    score: int,
) -> Outcome:
    """Compare with the recorded state, store the new one, and say what to post.

    Raises if the store fails; the caller falls back to posting.
    """
    current = state_of(recommendation)
    now = utcnow()
    with db.session() as session:
        row = session.get(RiskGateNoticeState, (repo_full_name, subject))
        previous = row.state if row is not None else None
        post = decide(previous, recommendation, introduced_blocking)
        outcome = Outcome(
            post=post,
            previous_since_sha=row.since_sha if row is not None else "",
            previous_held=row.held if row is not None else 0,
        )
        if row is None:
            row = RiskGateNoticeState(repo_full_name=repo_full_name, subject=subject)
            session.add(row)
        if previous != current:
            row.state = current
            row.since_sha = commit_sha
            row.since = now
            row.held = 0
        elif post is None:
            row.held = (row.held or 0) + 1
        row.last_score = score
        row.updated_at = now
    if post is None and current == REFUSED:
        logger.info(
            "Risk gate still refusing %s (%s) at commit %s: not posted again.",
            scrub(repo_full_name),
            scrub(subject),
            scrub(commit_sha),
        )
    return outcome
