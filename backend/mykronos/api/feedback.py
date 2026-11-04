"""Dashboard feedback, filed as a TheHub story (TheHub #61132).

- `GET /api/feedback` says whether feedback can be filed, and why not.
- `POST /api/feedback` files one backlog story on TheHub, tagged
  `repo:mykronos` and `source:dashboard-feedback`.

The dashboard's Feedback button used to open a pre-filled issue on the
platform's own GitHub repository. That repository is public, so a report one
click from submission could publish an internal path, a hostname or a repo
name the operator typed. TheHub is the private system of record for this
platform's work. The story is filed with this process's own Hub credential
(`hub_api_token`), which the browser never sees, and the answer carries the
story number only, not where TheHub lives.

**No fallback.** With no Hub configured the answer is "feedback is
unavailable". It is never a GitHub issue, because the public repository is
exactly the leak this route exists to close.

Filing is the operator's action (`HumanDep`). A viewer is refused, and so is
an agent: agents file to TheHub with their own credential, not through the
operator's button.
"""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from mykronos import product_owner as po
from mykronos.adminauth import HumanDep, PrincipalDep

router = APIRouter(prefix="/api/feedback", tags=["feedback"])

#: The tags every feedback story carries, so TheHub's board can find them.
FEEDBACK_TAGS = ("repo:mykronos", "source:dashboard-feedback")
SOURCE_KIND = "dashboard-feedback"

UNAVAILABLE = (
    "Feedback is unavailable: TheHub is not connected to this MyKronos "
    "(MYKRONOS_HUB_API_URL and MYKRONOS_HUB_API_TOKEN), so there is nowhere "
    "private to file it."
)


class FeedbackIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    #: `bug` is something wrong; `feature` is something wanted.
    kind: Literal["bug", "feature"]
    #: The story's title.
    summary: str = Field(min_length=3, max_length=200)
    detail: str = Field(default="", max_length=4_000)
    #: The dashboard page the report was made from: a path on this site, never a URL.
    page: str = Field(default="/", max_length=300, pattern=r"^/[^\s]*$")
    release: str = Field(default="", max_length=64)


class FeedbackOut(BaseModel):
    #: TheHub's id for the new story, when it returned one.
    story_id: int | None


class FeedbackStatusOut(BaseModel):
    available: bool
    #: Why feedback cannot be filed, when it cannot.
    reason: str | None


def _hub(request: Request) -> po.HubClient | None:
    return getattr(request.app.state, "hub", None)


def story_payload(body: FeedbackIn, actor: str) -> dict[str, Any]:
    """A backlog story. The caller chooses none of the tags, nor the bucket."""
    lines = [body.detail.strip() or "(no detail given)", "", "---", ""]
    lines.append(f"Filed from the MyKronos dashboard by `{actor}`.")
    lines.append(f"Page: `{body.page}`")
    if body.release:
        lines.append(f"Release: `{body.release}`")
    return {
        "title": body.summary.strip(),
        "detail": "\n".join(lines),
        "bucket": "backlog",
        "tags": [*FEEDBACK_TAGS, body.kind],
        "source_kind": SOURCE_KIND,
        "acceptance_criteria": [],
    }


@router.get("", response_model=FeedbackStatusOut)
def feedback_status(request: Request, principal: PrincipalDep) -> FeedbackStatusOut:
    """Whether the dashboard can file feedback, so the dialog can say so before
    anything is typed."""
    if _hub(request) is None:
        return FeedbackStatusOut(available=False, reason=UNAVAILABLE)
    return FeedbackStatusOut(available=True, reason=None)


@router.post("", response_model=FeedbackOut, status_code=status.HTTP_201_CREATED)
async def file_feedback(request: Request, body: FeedbackIn, principal: HumanDep) -> FeedbackOut:
    """File one TheHub backlog story from the dashboard's Feedback dialog.

    503 when no Hub is configured, and 502 when TheHub refused or could not be
    reached. Every attempt is audit-logged.
    """
    database = request.app.state.db

    def audit(outcome: str, **detail: Any) -> None:
        with database.session() as session:
            database.audit(
                session,
                actor=principal.actor,
                action="feedback.filed",
                entity_type="feedback",
                entity_id=body.kind,
                kind=body.kind,
                page=body.page,
                outcome=outcome,
                **detail,
            )

    hub = _hub(request)
    if hub is None:
        audit("unavailable")
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail=UNAVAILABLE)

    try:
        result = await hub.create_story(story_payload(body, principal.actor))
    except po.HubUnavailableError as exc:
        audit("unreachable")
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
    if not result.ok:
        audit("refused", hub_status=result.status)
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            detail=f"TheHub did not file the story: {result.detail}",
        )

    story_id = result.body.get("id") if isinstance(result.body, dict) else None
    story_id = story_id if isinstance(story_id, int) else None
    audit("filed", story_id=story_id)
    return FeedbackOut(story_id=story_id)
