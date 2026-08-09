"""Patchwork API (spec 08 §6).

The pipeline runs server-side rather than in the runner — spec 08 §6 asks for
that so the multi-agent work is observable and its cost is tracked in one
place. The workflow's job is to *ask*, which is why this endpoint takes the
repo from an ingestion token like every other capability entry point.

There is no endpoint here that merges anything, and there is no client method
it could call if there were (spec 08 §3).
"""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from mykronos.adminauth import PrincipalDep
from mykronos.api.ingest import TokenDep, _installation_client, _require_capability
from mykronos.db.models import RepoOnboarding, capability_config_for
from mykronos.patchwork import PatchworkPipeline
from mykronos.patchwork.pipeline import DEFAULT_SOURCE_CAPABILITIES
from mykronos.schemas import Capability

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/patchwork", tags=["patchwork"])


class RunRequest(BaseModel):
    """What the workflow sends. No repo field — it comes from the token."""

    model_config = ConfigDict(extra="forbid")

    commit_sha: str = Field(default="", max_length=64)
    pr_number: int | None = None


class RunResult(BaseModel):
    findings_considered: int
    by_stage: dict[str, int]
    draft_prs_opened: int
    queued: int
    errors: list[str] = Field(
        default_factory=list,
        description=(
            "Failures that did not stop the run. Reported rather than raised: "
            "spec 08 §8 requires every finding to record where it got to even "
            "when the pipeline breaks partway."
        ),
    )
    note: str = (
        "Every pull request Patchwork opens is a draft, and it has no ability "
        "to merge one — the GitHub client it uses exposes no merge operation "
        "(spec 08 §3)."
    )


class RemediationEventOut(BaseModel):
    event_id: str
    finding_id: str
    toxic_combination_id: str | None = None
    contributing_finding_ids: list[str] = Field(default_factory=list)
    pipeline_stage_reached: str
    triage_classification: str
    fix_pr_number: int | None = None
    fix_pr_url: str | None = None
    pr_status: str | None = None
    rationale: str
    created_at: Any = None
    updated_at: Any = None


class RemediationPage(BaseModel):
    repo_full_name: str
    events: list[RemediationEventOut]
    open_draft_prs: int
    note: str = (
        "Patchwork never merges. A draft pull request here is waiting for a "
        "person, and will wait indefinitely."
    )


def _pipeline(request: Request, repo_full_name: str) -> tuple[PatchworkPipeline, str]:
    with request.app.state.db.session() as session:
        config = capability_config_for(session, repo_full_name, "patchwork")
        onboarding = session.execute(
            select(RepoOnboarding).where(
                RepoOnboarding.github_repo_full_name == repo_full_name
            )
        ).scalars().first()
        default_branch = onboarding.default_branch if onboarding else "main"

    sources = config.get("source_capabilities") or DEFAULT_SOURCE_CAPABILITIES
    pipeline = PatchworkPipeline(
        request.app.state.catalog,
        request.app.state.buffer,
        request.app.state.knowledge,
        min_confidence=float(config.get("min_confidence_to_generate_fix", 0.7)),
        max_open_draft_prs=int(config.get("max_open_draft_prs_per_repo", 10)),
        source_capabilities=tuple(sources),
        fix_generator_url=config.get("fix_generator_url"),
    )
    return pipeline, default_branch


def _open_draft_count(request: Request, repo_full_name: str) -> int:
    """How many Patchwork pull requests are still waiting for a person.

    Counted from the event table rather than from GitHub, deliberately: this
    runs on every pipeline invocation, and a list-pull-requests call per run
    would spend the repository's API budget on a number we already hold.
    """
    rows = request.app.state.catalog.query(
        "SELECT count(*) FROM remediation_events "
        "WHERE repo_full_name = ? AND pr_status IN ('draft_open', 'human_edited')",
        [repo_full_name],
    )
    return int(rows[0][0]) if rows else 0


@router.post("/run", response_model=RunResult)
async def run(request: Request, body: RunRequest, token: TokenDep) -> RunResult:
    """Run the pipeline for this repository (spec 08 §2, §6)."""
    _require_capability(token, Capability.PATCHWORK.value)

    pipeline, default_branch = _pipeline(request, token.repo_full_name)
    result = await pipeline.run(
        token.repo_full_name,
        github=_installation_client(request, token.repo_full_name),
        default_branch=default_branch,
        open_prs=_open_draft_count(request, token.repo_full_name),
    )

    return RunResult(
        findings_considered=len(result.outcomes),
        by_stage=result.by_stage(),
        draft_prs_opened=result.prs_opened,
        queued=result.queued,
        errors=result.errors,
    )


@router.get("/repos/{repo_id}", response_model=RemediationPage)
async def repo_events(
    request: Request,
    repo_id: str,
    principal: PrincipalDep,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> RemediationPage:
    """What Patchwork did, and did not do, for one repository (spec 08 §7)."""
    from mykronos.api.dashboard import _resolve_repo

    repo_full_name = _resolve_repo(request, repo_id)
    columns = [
        "event_id",
        "finding_id",
        "toxic_combination_id",
        "contributing_finding_ids",
        "pipeline_stage_reached",
        "triage_classification",
        "fix_pr_number",
        "fix_pr_url",
        "pr_status",
        "rationale",
        "created_at",
        "updated_at",
    ]
    rows = request.app.state.catalog.query(
        f"SELECT {', '.join(columns)} FROM remediation_events "
        "WHERE repo_full_name = ? ORDER BY updated_at DESC LIMIT ?",
        [repo_full_name, limit],
    )

    import json

    events = []
    for row in rows:
        record = dict(zip(columns, row, strict=True))
        raw = record.get("contributing_finding_ids")
        try:
            record["contributing_finding_ids"] = json.loads(raw) if raw else []
        except (TypeError, json.JSONDecodeError):
            record["contributing_finding_ids"] = []
        events.append(RemediationEventOut(**record))

    return RemediationPage(
        repo_full_name=repo_full_name,
        events=events,
        open_draft_prs=_open_draft_count(request, repo_full_name),
    )
