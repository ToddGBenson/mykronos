"""Opening (or updating) the GitHub issue for a groomed story.

Extracted from `api/triage.py` so the scheduled auto-routing pass (spec 19
§4.3) and the per-finding "groom as story" button run the *same* code. An
auto-filed story and a hand-filed one are indistinguishable once filed
because they are produced identically — not because two implementations were
kept in step by hand.

Idempotent by construction rather than by a guard: `story_id()` is derived
from repo + subject (spec 17 §7.2), so re-grooming the same subject finds the
row it wrote last time and updates that issue. A scheduled sweep running
nightly over findings it already groomed is a no-op update, not a growing
pile of duplicates.

Raises `GitHubError` rather than an HTTP exception — the API layer turns that
into a 502, and the job logs it and moves to the next repo. A module that
knew about `HTTPException` could not be called from a scheduled job without
pretending to be inside a request.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from mykronos.db import Database
from mykronos.db.models import GroomedStory
from mykronos.triage_story import TriageStory

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class GroomOutcome:
    story_id: str
    github_issue_number: int
    github_issue_url: str
    #: True if this opened a new issue; false if it updated one an earlier
    #: groom of the same subject already opened.
    created: bool


async def open_or_update_story(
    db: Database, github: Any, actor: str, story: TriageStory
) -> GroomOutcome:
    """Open the issue for this story, or update the one already open for it."""
    with db.session() as session:
        existing = session.get(GroomedStory, story.id)

        if existing is None:
            ref = await github.create_issue(
                story.repo_full_name,
                story.title,
                story.render_issue_body(),
                labels=story.labels,
            )
            created = True
        else:
            await github.update_issue(
                story.repo_full_name,
                existing.github_issue_number,
                title=story.title,
                body=story.render_issue_body(),
                labels=story.labels,
            )
            ref = None
            created = False

        if created and ref is not None:
            session.add(
                GroomedStory(
                    id=story.id,
                    repo_full_name=story.repo_full_name,
                    subject_type=story.subject_type,
                    subject_id=story.subject_id,
                    github_issue_number=ref.number,
                    github_issue_url=ref.url,
                    dev_ready=story.dev_ready,
                )
            )
            issue_number, issue_url = ref.number, ref.url
        else:
            assert existing is not None  # narrows for mypy; `created` implies otherwise
            existing.dev_ready = story.dev_ready
            issue_number, issue_url = existing.github_issue_number, existing.github_issue_url

        db.audit(
            session,
            actor=actor,
            action="triage.groom",
            entity_type=story.subject_type,
            entity_id=story.subject_id,
            repo=story.repo_full_name,
            dev_ready=story.dev_ready,
            created=created,
        )

    return GroomOutcome(
        story_id=story.id,
        github_issue_number=issue_number,
        github_issue_url=issue_url,
        created=created,
    )
