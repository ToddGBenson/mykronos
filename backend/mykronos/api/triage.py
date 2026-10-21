"""i2i grooming API (spec 17 §7.2) — retired by D-161.

These routes turned a triaged finding, or a detected toxic combination, into
a GitHub issue. TheHub's `dev_stories` is now the system of record for work
items (D-133), so MyKronos writes no issues and the GitHub App holds
`issues: read` only. The routes answer 410 Gone with that reason rather
than disappearing: a caller built before D-161 may still name these paths,
and "this moved, here is where" is a better answer to it than a bare 404.
Nothing in this repository offers them any more: the agent work queue and
its playbooks stopped in #60756, and `tests/test_playbooks.py` refuses a
playbook that names a route answering 410.

`GroomResult` stays in the schema so the generated frontend types do not
change under a caller that has not been updated yet.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from mykronos.adminauth import WriterDep

router = APIRouter(prefix="/api/triage", tags=["triage"])

#: What a caller is told. Names the decision and where work items live now.
RETIRED_DETAIL = (
    "Grooming a finding into a GitHub issue is retired (D-161). TheHub's "
    "dev_stories is the system of record for work items (D-133); file the "
    "story there. The MyKronos GitHub App no longer holds issues: write."
)


class GroomResult(BaseModel):
    story_id: str
    dev_ready: bool
    missing_fields: list[str] = Field(
        description="Empty when dev_ready. Named, not just implied by the boolean, "
        "so a caller knows what to fill in rather than only that something's missing."
    )
    github_issue_number: int
    github_issue_url: str
    created: bool = Field(
        description="True if this groom opened a new issue; false if it updated one "
        "already opened by an earlier groom of the same finding/combination."
    )


def _retired() -> HTTPException:
    return HTTPException(status_code=status.HTTP_410_GONE, detail=RETIRED_DETAIL)


@router.post(
    "/{finding_id}/groom",
    response_model=GroomResult,
    responses={410: {"description": "Retired (D-161). File the story in TheHub."}},
)
async def groom_finding(finding_id: str, actor: WriterDep) -> GroomResult:
    """Retired (D-161): always 410. Kept so callers learn where work went."""
    raise _retired()


@router.post(
    "/repos/{repo_id}/combinations/{combination_id}/groom",
    response_model=GroomResult,
    responses={410: {"description": "Retired (D-161). File the story in TheHub."}},
)
async def groom_combination(repo_id: str, combination_id: str, actor: WriterDep) -> GroomResult:
    """Retired (D-161): always 410. Kept so callers learn where work went."""
    raise _retired()
