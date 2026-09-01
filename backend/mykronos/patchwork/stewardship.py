"""Looking after draft pull requests after they are opened (spec 08 §3, §8).

Opening a fix is the easy half. The two things that decide whether a team
keeps this capability switched on both happen afterwards:

**Never overwrite somebody's edit.** A human who takes a draft and improves it
must not find their work replaced by the next pipeline run. Spec 08 §3 makes
the transition to `human_edited` permanent, with no path back, deliberately —
a bot that silently reverted a colleague's commit would end the experiment
that afternoon.

**Never leave a stale draft open.** A fix for a finding somebody has already
dealt with is noise, and a queue of noise is how the real ones get ignored
(spec 08 §8). Those close themselves, with a comment explaining why rather
than vanishing.

The identity question runs through both, and it fails safe. If Patchwork
cannot confidently establish that a commit is its own, it treats the branch as
human-edited and stops touching it. The two mistakes are not symmetric:
wrongly leaving a branch alone costs one unrefreshed fix, and wrongly
overwriting costs somebody's work and the team's trust.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

from mykronos.github.client import GitHubError
from mykronos.lake.buffer import WriteAheadBuffer
from mykronos.lake.catalog import Catalog
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

#: Defined here rather than in the pipeline, though the pipeline is what
#: creates these branches. This module owns the question "is that branch
#: ours", and the pipeline conforms to the answer — the other arrangement is a
#: circular import, and this one puts the constant next to the code that
#: reasons about it.
BRANCH_PREFIX = "mykronos/fix-"


def is_patchwork_branch(ref: str) -> bool:
    """Whether a git ref names a branch Patchwork owns."""
    return ref.removeprefix("refs/heads/").startswith(BRANCH_PREFIX)


def commit_is_ours(commit: dict[str, Any], bot_logins: set[str]) -> bool:
    """Whether Patchwork authored this commit.

    Fails closed. An empty `bot_logins` — no App configured, or nobody set the
    login — means *nothing* is recognised as ours, so every branch looks
    human-edited and Patchwork stops refreshing them. That is the correct
    direction to be wrong in: the cost is a stale draft, where the opposite
    mistake is overwriting a colleague's commit.
    """
    if not bot_logins:
        return False

    candidates = {
        str((commit.get("author") or {}).get("username") or ""),
        str((commit.get("author") or {}).get("name") or ""),
        str((commit.get("committer") or {}).get("username") or ""),
        str((commit.get("committer") or {}).get("name") or ""),
    }
    return bool(candidates & bot_logins) and not (candidates - bot_logins - {""})


@dataclass
class EditResult:
    event_id: str | None = None
    marked: bool = False
    reason: str = ""


def record_human_edit(
    catalog: Catalog,
    buffer: WriteAheadBuffer,
    repo_full_name: str,
    branch: str,
    commits: list[dict[str, Any]],
    *,
    bot_logins: set[str],
) -> EditResult:
    """Mark a Patchwork branch as human-edited (spec 08 §3).

    Keyed on the branch rather than the pull request, because a push arrives
    before anybody has necessarily looked at the PR, and the branch name is
    the one thing both events share.
    """
    if not is_patchwork_branch(branch):
        return EditResult(reason="not an auto-remediation branch")

    if all(commit_is_ours(commit, bot_logins) for commit in commits):
        return EditResult(reason="every commit is auto-remediation's own")

    short = branch.removeprefix("refs/heads/").removeprefix(BRANCH_PREFIX)
    rows = catalog.query(
        """
        SELECT event_id, finding_id, rationale, fix_pr_number, fix_pr_url,
               pr_status
        FROM remediation_events
        WHERE repo_full_name = ? AND finding_id LIKE ?
        LIMIT 1
        """,
        [repo_full_name, f"{short}%"],
    )
    if not rows:
        return EditResult(reason="no remediation event matches this branch")

    event_id, finding_id, rationale, pr_number, pr_url, status = rows[0]
    if status == "human_edited":
        return EditResult(event_id=str(event_id), reason="already marked")

    buffer.append(
        "remediation_events",
        [
            {
                "event_id": str(event_id),
                "repo_full_name": repo_full_name,
                "finding_id": str(finding_id),
                "toxic_combination_id": None,
                "contributing_finding_ids": json.dumps([]),
                "pipeline_stage_reached": "pr_opened",
                "triage_classification": "true_positive",
                "fix_pr_number": int(pr_number) if pr_number is not None else None,
                "fix_pr_url": pr_url,
                "pr_status": "human_edited",
                "rationale": (
                    f"{rationale} A person has since committed to this branch, "
                    "so Patchwork will not touch it again — permanently, and "
                    "whether or not the finding changes."
                ),
                "created_at": utcnow(),
                "updated_at": utcnow(),
            }
        ],
    )
    logger.info(
        "Patchwork branch %s on %s was edited by a person; standing down",
        branch,
        repo_full_name,
    )
    return EditResult(event_id=str(event_id), marked=True, reason="human commit found")


def branches_off_limits(catalog: Catalog, repo_full_name: str) -> set[str]:
    """Findings whose fix branch a person has taken over.

    The pipeline consults this before regenerating anything. Returned as
    finding ids rather than branch names because that is what the pipeline
    holds at the point it has to decide.
    """
    rows = catalog.query(
        "SELECT finding_id FROM remediation_events "
        "WHERE repo_full_name = ? AND pr_status = 'human_edited'",
        [repo_full_name],
    )
    return {str(row[0]) for row in rows}


# --------------------------------------------------------------------------
# Stale drafts (spec 08 §8)
# --------------------------------------------------------------------------


@dataclass
class ReconcileResult:
    checked: int = 0
    closed: list[tuple[str, int]] = field(default_factory=list)
    failed: list[tuple[str, str]] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"checked {self.checked}, closed {len(self.closed)}, "
            f"failed {len(self.failed)}"
        )


CLOSE_COMMENT = """This fix is no longer needed.

The finding it addressed is no longer open — somebody fixed it, or judged it
not to be a problem — so merging this would change code for a reason that no
longer applies.

Closing rather than leaving it: a queue of draft pull requests nobody needs is
how the ones that matter stop getting read.

If this was closed in error, the finding reappearing on the next scan will
bring a fresh fix with it.
"""


async def close_superseded_drafts(
    catalog: Catalog,
    buffer: WriteAheadBuffer,
    repo_full_name: str,
    github: Any,
) -> ReconcileResult:
    """Close drafts whose finding is no longer open (spec 08 §8).

    `human_edited` branches are excluded. Somebody is working on that one, and
    the finding's status is not Patchwork's business once a person has taken
    the change over — they may be fixing three things at once, or may have
    dismissed the finding precisely because they are mid-fix.
    """
    result = ReconcileResult()

    rows = catalog.query(
        """
        SELECT e.event_id, e.finding_id, e.fix_pr_number, e.rationale, f.status
        FROM remediation_events e
        LEFT JOIN findings f ON f.finding_id = e.finding_id
        WHERE e.repo_full_name = ?
          AND e.pr_status = 'draft_open'
          AND e.fix_pr_number IS NOT NULL
        """,
        [repo_full_name],
    )

    for event_id, finding_id, pr_number, rationale, status in rows:
        result.checked += 1
        # NULL means the finding is gone from the lake entirely, which is also
        # a reason the fix is pointless.
        if status == "open":
            continue

        try:
            await github.close_pull_request(
                repo_full_name, int(pr_number), comment=CLOSE_COMMENT
            )
        except GitHubError as exc:
            logger.warning(
                "Could not close superseded draft %s#%s: %s",
                repo_full_name,
                pr_number,
                exc,
            )
            result.failed.append((str(finding_id), str(exc)))
            continue

        buffer.append(
            "remediation_events",
            [
                {
                    "event_id": str(event_id),
                    "repo_full_name": repo_full_name,
                    "finding_id": str(finding_id),
                    "toxic_combination_id": None,
                    "contributing_finding_ids": json.dumps([]),
                    "pipeline_stage_reached": "superseded",
                    "triage_classification": "true_positive",
                    "fix_pr_number": int(pr_number),
                    "fix_pr_url": None,
                    "pr_status": "closed_unmerged",
                    "rationale": (
                        f"{rationale} Closed automatically: the finding is now "
                        f"'{status or 'absent'}', so the fix addressed a "
                        "problem that no longer exists."
                    ),
                    "created_at": utcnow(),
                    "updated_at": utcnow(),
                }
            ],
        )
        result.closed.append((str(finding_id), int(pr_number)))

    if result.closed:
        logger.info(
            "Closed %s superseded draft(s) on %s", len(result.closed), repo_full_name
        )
    return result
