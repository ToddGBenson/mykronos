"""Onboarding API (spec 02 §7).

Where an admin turns an installed App into a scanned repo. Every mutating
endpoint writes an audit entry in the same transaction as the change
(spec 12 §7).
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from mykronos.adminauth import AdminDep
from mykronos.auth import TokenRegistry
from mykronos.db.models import CapabilityConfig, Organization, RepoOnboarding
from mykronos.github.client import GitHubError
from mykronos.installer import (
    InstallerError,
    PathCollisionError,
    WorkflowInstaller,
    capability_configs,
)
from mykronos.schemas import Capability

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/repos", tags=["onboarding"])


# ---------------------------------------------------------------------------
# Wire models
# ---------------------------------------------------------------------------


class OnboardRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    github_repo_full_name: str = Field(pattern=r"^[^/\s]+/[^/\s]+$")
    github_installation_id: int
    default_branch: str = "main"
    org_login: str = ""


class CapabilityUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    capabilities: list[Capability]
    config: dict[str, dict[str, Any]] = Field(default_factory=dict)


class RepoSummary(BaseModel):
    id: str
    github_repo_full_name: str
    status: str
    enabled_capabilities: list[str]
    pending_capabilities: list[str] | None
    pending_pr_number: int | None
    default_branch: str
    onboarded_at: datetime
    last_synced_at: datetime | None


class RepoDetail(RepoSummary):
    github_installation_id: int
    onboarded_by: str
    auto_merge_workflow_prs: bool
    granted_capabilities: list[str]
    capability_config: dict[str, dict[str, Any]]


class CapabilityUpdateResult(BaseModel):
    repo: RepoSummary
    added: list[str]
    removed: list[str]
    pull_request_url: str | None = None
    pull_request_number: int | None = None
    secret_provisioned: bool = False
    detail: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _summary(row: RepoOnboarding) -> RepoSummary:
    return RepoSummary(
        id=row.id,
        github_repo_full_name=row.github_repo_full_name,
        status=row.status,
        enabled_capabilities=list(row.enabled_capabilities or []),
        pending_capabilities=(
            list(row.pending_capabilities) if row.pending_capabilities else None
        ),
        pending_pr_number=row.pending_pr_number,
        default_branch=row.default_branch,
        onboarded_at=row.onboarded_at,
        last_synced_at=row.last_synced_at,
    )


def _get(session: Session, repo_id: str) -> RepoOnboarding:
    row = session.get(RepoOnboarding, repo_id)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"No onboarding {repo_id}."
        )
    return row


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("", response_model=RepoSummary, status_code=status.HTTP_201_CREATED)
async def onboard_repo(
    request: Request, body: OnboardRequest, actor: AdminDep
) -> RepoSummary:
    """Idempotently register a repo (spec 02 §7).

    Usually the `installation` webhook gets here first; this exists for the
    manual path and for re-registering after an offboard. Either way it
    upserts, so the two paths cannot produce duplicate rows.
    """
    owner = body.org_login or body.github_repo_full_name.split("/")[0]
    db = request.app.state.db

    with db.session() as session:
        org = session.execute(
            select(Organization).where(Organization.github_org_login == owner)
        ).scalars().first()
        if org is None:
            org = Organization(github_org_login=owner)
            session.add(org)
            session.flush()

        row = session.execute(
            select(RepoOnboarding)
            .where(RepoOnboarding.org_id == org.id)
            .where(RepoOnboarding.github_repo_full_name == body.github_repo_full_name)
        ).scalars().first()

        created = row is None
        if row is None:
            row = RepoOnboarding(
                org_id=org.id,
                github_repo_full_name=body.github_repo_full_name,
                github_installation_id=body.github_installation_id,
                status="pending_install",
                enabled_capabilities=[],
                default_branch=body.default_branch,
                onboarded_by=actor,
            )
            session.add(row)
            session.flush()
        else:
            row.github_installation_id = body.github_installation_id
            row.default_branch = body.default_branch
            if row.status == "removed":
                row.status = "pending_install"

        db.audit(
            session,
            actor=actor,
            action="repo.onboard" if created else "repo.reonboard",
            entity_type="repo_onboarding",
            entity_id=row.id,
            repo=row.github_repo_full_name,
        )
        return _summary(row)


@router.get("", response_model=list[RepoSummary])
async def list_repos(
    request: Request,
    actor: AdminDep,
    include_removed: bool = Query(
        default=False,
        description=(
            "Offboarded repos are hidden by default but remain queryable for "
            "audit (spec 10 §7)."
        ),
    ),
) -> list[RepoSummary]:
    with request.app.state.db.session() as session:
        statement = select(RepoOnboarding).order_by(RepoOnboarding.github_repo_full_name)
        if not include_removed:
            statement = statement.where(RepoOnboarding.status != "removed")
        return [_summary(row) for row in session.execute(statement).scalars()]


@router.get("/{repo_id}", response_model=RepoDetail)
async def get_repo(request: Request, repo_id: str, actor: AdminDep) -> RepoDetail:
    with request.app.state.db.session() as session:
        row = _get(session, repo_id)
        registry = TokenRegistry(session)
        return RepoDetail(
            **_summary(row).model_dump(),
            github_installation_id=row.github_installation_id,
            onboarded_by=row.onboarded_by,
            auto_merge_workflow_prs=row.auto_merge_workflow_prs,
            granted_capabilities=sorted(
                registry.granted_capabilities(row.github_repo_full_name)
            ),
            capability_config=capability_configs(session, row),
        )


@router.patch("/{repo_id}/capabilities", response_model=CapabilityUpdateResult)
async def update_capabilities(
    request: Request, repo_id: str, body: CapabilityUpdate, actor: AdminDep
) -> CapabilityUpdateResult:
    """Set the enabled capability set and open the workflow-install PR.

    Capability *validation* happens here rather than at workflow run time
    (spec 04 §7): a bad tool name should fail the save, not surface three
    hours later as a red pipeline nobody connects to this action.
    """
    settings = request.app.state.settings
    db = request.app.state.db
    requested = {c.value for c in body.capabilities}

    with db.session() as session:
        row = _get(session, repo_id)

        if row.status == "removed":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"{row.github_repo_full_name} is offboarded. Re-onboard it "
                    "before changing capabilities."
                ),
            )

        for capability, config in body.config.items():
            if capability not in requested:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail=f"Config supplied for '{capability}', which is not enabled.",
                )
            existing = session.execute(
                select(CapabilityConfig)
                .where(CapabilityConfig.repo_onboarding_id == row.id)
                .where(CapabilityConfig.capability == capability)
            ).scalars().first()
            if existing is None:
                session.add(
                    CapabilityConfig(
                        repo_onboarding_id=row.id,
                        capability=capability,
                        config_json=config,
                    )
                )
            else:
                existing.config_json = config
        session.flush()

        installer = WorkflowInstaller(
            request.app.state.github_factory.for_installation(row.github_installation_id),
            request.app.state.templates,
            ingestion_api_url=settings.ingestion_api_url,
            upload_action_ref=settings.upload_action_ref,
            token_overlap_hours=settings.token_overlap_hours,
        )
        registry = TokenRegistry(session, overlap_hours=settings.token_overlap_hours)

        try:
            plan = await installer.plan(
                row, requested, configs=capability_configs(session, row)
            )
            result = await installer.apply(
                session, row, plan, actor=actor, registry=registry
            )
        except PathCollisionError as exc:
            # spec 03 §8 — a human wrote a file where we would generate one.
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail=str(exc)
            ) from exc
        except InstallerError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
            ) from exc
        except GitHubError as exc:
            # 502: we failed talking to GitHub, which is not the caller's fault
            # and is usually a permission or availability problem.
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"GitHub rejected the change: {exc}",
            ) from exc

        db.audit(
            session,
            actor=actor,
            action="repo.capabilities",
            entity_type="repo_onboarding",
            entity_id=row.id,
            repo=row.github_repo_full_name,
            requested=sorted(requested),
            added=plan.added,
            removed=plan.removed,
            pr_number=result.pull_request.number if result.pull_request else None,
        )

        if plan.already_pending:
            detail = (
                f"No change; this is already requested and pull request "
                f"#{plan.pending_pr_number} is open. Merge it to activate."
            )
        elif plan.is_noop:
            detail = "No change; the requested set already matches what is enabled."
        else:
            detail = (
                f"Opened/updated a pull request to {plan.describe()}. Capabilities "
                "become active when it merges; ingestion grants are already live."
            )

        return CapabilityUpdateResult(
            repo=_summary(row),
            # Report nothing changed when nothing did, even though the diff
            # against the merged set is non-empty for an already-pending
            # request — the caller asked what *this call* did.
            added=[] if plan.is_noop else plan.added,
            removed=[] if plan.is_noop else plan.removed,
            pull_request_url=result.pull_request.url if result.pull_request else None,
            pull_request_number=(
                result.pull_request.number
                if result.pull_request
                else plan.pending_pr_number
            ),
            secret_provisioned=result.secret_provisioned,
            detail=detail,
        )


@router.delete("/{repo_id}", response_model=RepoSummary)
async def offboard_repo(request: Request, repo_id: str, actor: AdminDep) -> RepoSummary:
    """Offboard a repo (spec 02 §6).

    Stops all scheduled activity and revokes every ingestion token and grant,
    but **does not delete historical data lake rows** — those are the audit
    trail. Deleting them is a separate, explicitly-confirmed action.
    """
    db = request.app.state.db
    with db.session() as session:
        row = _get(session, repo_id)
        registry = TokenRegistry(session)
        revoked = registry.revoke_repo(row.github_repo_full_name)
        row.status = "removed"

        db.audit(
            session,
            actor=actor,
            action="repo.offboard",
            entity_type="repo_onboarding",
            entity_id=row.id,
            repo=row.github_repo_full_name,
            tokens_revoked=revoked,
            note="historical findings retained for audit (spec 02 §6)",
        )
        return _summary(row)
