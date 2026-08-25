"""Onboarding API (spec 02 §7).

Where an admin turns an installed App into a scanned repo. Every mutating
endpoint writes an audit entry in the same transaction as the change
(spec 12 §7).
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import PurePosixPath
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from mykronos import controls, worklist
from mykronos.adminauth import AdminDep, PrincipalDep
from mykronos.auth import TokenRegistry
from mykronos.capabilities import (
    CapabilityConfigError,
    config_schema,
    configurable_capabilities,
    validate_config,
)
from mykronos.ci import ConcourseClient, jobs_for_capability, pipeline_name_for
from mykronos.db.models import (
    CapabilityConfig,
    CapabilityGrant,
    ReachabilityReport,
    RepoOnboarding,
    RiskProfile,
    get_or_create_organization,
)
from mykronos.github.client import GitHubError
from mykronos.installer import (
    InstallerError,
    PathCollisionError,
    TemplateError,
    WorkflowInstaller,
    capability_configs,
)
from mykronos.schemas import Capability

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/repos", tags=["onboarding"])

#: Which capabilities "scan now" (spec 17 §2.5) can actually dispatch — the
#: ones with a workflow template (spec 04) or a Concourse job, as opposed to
#: `aegis`/`oracle`/`patchwork`, which are event-driven (`ci.py`
#: NON_SCANNING) and have nothing for a dispatch to trigger.
#:
#: `unit`/`functional`/`qa` (spec 18, Test Harness tab) dispatch through the
#: exact same two paths as everything else here, and need no special case in
#: either. Both paths are now reachable: spec 31 §5 added the three workflow
#: templates, so an Actions-scanned repository can enable a test lane and
#: `scan_now` can dispatch it. This comment said the opposite until then, and
#: the reason it was true is worth keeping: an Actions repo's install PR is
#: generated *from* the templates of the capabilities being enabled, so with
#: no template the capabilities endpoint refused the enable with a 422 long
#: before a dispatch was attempted. A Concourse-scanned repo's attempt
#: resolves instead through `_JOBS_BY_CAPABILITY`, which reuses the
#: `unit`/`qa`/`qa-spec-links`/`functional` job names `ci.py`'s
#: `CAPABILITY_BY_JOB` already maps for stage-coverage cross-checking — the
#: same mapping, rather than a second one built for this.
DISPATCHABLE_CAPABILITIES = frozenset(
    {"sast", "dast", "secrets", "containers", "iac", "cloud", "atlas", "unit", "functional", "qa"}
)

# ---------------------------------------------------------------------------
# Wire models
# ---------------------------------------------------------------------------


class OnboardRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    github_repo_full_name: str = Field(pattern=r"^[^/\s]+/[^/\s]+$")
    github_installation_id: int
    default_branch: str = "main"
    org_login: str = ""
    scanned_by: Literal["concourse", "github_actions", "none"] = Field(
        default="concourse",
        description=(
            "Which CI is supposed to scan this repository (spec 03 §3a). "
            "`concourse` and `none` install no workflows: enabling a "
            "capability grants ingestion and nothing else. Only "
            "`github_actions` opens an install pull request."
        ),
    )


class CapabilityUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    capabilities: list[Capability]
    config: dict[str, dict[str, Any]] = Field(default_factory=dict)
    install_workflows: bool = Field(
        default=True,
        description=(
            "Whether to open a pull request installing this repo's GitHub "
            "Actions workflows. Leave true for a repository Mykronos onboards "
            "in the normal way.\n\n"
            "Set false for a repository scanned by a pipeline Mykronos does "
            "not install — TheHub's Concourse pipeline is the case this exists "
            "for (spec 16 §4). Until this flag existed, `enabled_capabilities` "
            "could only move when an install PR merged, so a Concourse-scanned "
            "repo reporting six capabilities showed however many its last "
            "Actions PR enabled, and the coverage column understated it "
            "permanently. The alternative was opening a PR that adds the very "
            "workflows spec 16 removes.\n\n"
            "It changes where the workflows come from, not what is enforced: "
            "ingestion grants, capability config validation and the audit "
            "entry are identical either way."
        ),
    )


class RepoSummary(BaseModel):
    id: str
    github_repo_full_name: str
    status: str
    #: Which CI scans this repo (spec 03 3a). The UI needs it to know what
    #: "enabled" means: the installer's ledger for Actions, the grants for
    #: everything else.
    scanned_by: str = "concourse"
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


#: The vocabularies Oracle's policy has weights for (spec 21 §1.4). Typed as
#: literals rather than free strings because a profile field Oracle scores has
#: to be one Oracle can look up — a typo'd "confidental" would silently
#: contribute zero and look like an honest "we said public".
DataClassification = Literal["public", "internal", "confidential", "regulated"]
BusinessCriticality = Literal["low", "medium", "high", "critical"]


class RiskProfileOut(BaseModel):
    """What this application is, as an asset (spec 21 §1).

    Every field independently nullable: a partially-filled profile is still
    useful. `exists` distinguishes the two states that matter to Oracle — a
    profile recorded but not yet filled in is an auditable fact, no profile
    at all is `available: false`.
    """

    exists: bool
    internet_facing: bool | None = None
    data_classification: DataClassification | None = None
    business_criticality: BusinessCriticality | None = None
    compliance_scope: list[str] = Field(default_factory=list)
    owner: str | None = None
    notes: str | None = None
    updated_by: str = ""
    updated_at: datetime | None = None


class ReachabilityOut(BaseModel):
    """Which files nothing in the repository imports (spec 19 §2.1).

    `analysed` is the field that carries the weight. False means the analysis
    has never run for this repository, which is not the same as it having run
    and found nothing — the second is a result, the first is a gap, and
    Oracle reports them differently (`available: false` versus a real zero).
    """

    analysed: bool
    language: str = "python"
    commit_sha: str = ""
    files_analysed: int = 0
    files_unparseable: int = 0
    orphaned_paths: list[str] = Field(default_factory=list)
    updated_at: datetime | None = None
    note: str = Field(
        default=(
            "Import reachability only, and Python only: whether anything in "
            "this repository imports the file — never whether the code runs. "
            "A file not listed here is not proven reachable, only not proven "
            "orphaned. A finding in an orphaned file is discounted, never "
            "dismissed (spec 19 §2.1)."
        ),
        description="Served with the data so a consumer cannot over-read it.",
    )


class RiskProfileUpdate(BaseModel):
    """A full replace, not a patch (spec 21 §1.3).

    A risk profile is a small, complete statement of fact about an asset;
    a field-by-field patch endpoint invites one that drifts a field at a
    time with nobody ever reading the whole thing.
    """

    model_config = ConfigDict(extra="forbid")

    internet_facing: bool | None = None
    data_classification: DataClassification | None = None
    business_criticality: BusinessCriticality | None = None
    compliance_scope: list[str] = Field(default_factory=list, max_length=20)
    owner: str | None = Field(default=None, max_length=255)
    notes: str | None = Field(default=None, max_length=4000)


class ScanResult(BaseModel):
    """spec 17 §2.5. Fire-and-forget on both dispatch paths — GitHub's and
    Concourse's own APIs return no synchronous run id — so this reports what
    was *attempted*, not a result to poll. The new runs surface on the
    Harness tab like any other, once they complete."""

    dispatched: list[str]
    failed: list[str]
    detail: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _summary(row: RepoOnboarding) -> RepoSummary:
    return RepoSummary(
        id=row.id,
        github_repo_full_name=row.github_repo_full_name,
        status=row.status,
        scanned_by=row.scanned_by,
        enabled_capabilities=list(row.enabled_capabilities or []),
        pending_capabilities=(list(row.pending_capabilities) if row.pending_capabilities else None),
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


@router.get("/-/capabilities", tags=["onboarding"])
async def list_capability_schemas(actor: AdminDep) -> dict[str, Any]:
    """Config schema per capability, for the UI to render a form from.

    Under `/-/` so it cannot be mistaken for a repo id. The valid tool list in
    each schema comes from the adapter registry rather than being restated
    here, so the form can never offer a tool the platform cannot parse.
    """
    return {capability: config_schema(capability) for capability in configurable_capabilities()}


@router.post("", response_model=RepoSummary, status_code=status.HTTP_201_CREATED)
async def onboard_repo(request: Request, body: OnboardRequest, actor: AdminDep) -> RepoSummary:
    """Idempotently register a repo (spec 02 §7).

    Usually the `installation` webhook gets here first; this exists for the
    manual path and for re-registering after an offboard. Either way it
    upserts, so the two paths cannot produce duplicate rows.
    """
    owner = body.org_login or body.github_repo_full_name.split("/")[0]
    db = request.app.state.db

    with db.session() as session:
        org = get_or_create_organization(session, owner)

        row = (
            session.execute(
                select(RepoOnboarding)
                .where(RepoOnboarding.org_id == org.id)
                .where(RepoOnboarding.github_repo_full_name == body.github_repo_full_name)
            )
            .scalars()
            .first()
        )

        created = row is None
        if row is None:
            row = RepoOnboarding(
                org_id=org.id,
                github_repo_full_name=body.github_repo_full_name,
                github_installation_id=body.github_installation_id,
                status="pending_install",
                enabled_capabilities=[],
                default_branch=body.default_branch,
                scanned_by=body.scanned_by,
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
            "Offboarded repos are hidden by default but remain queryable for audit (spec 10 §7)."
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
            granted_capabilities=sorted(registry.granted_capabilities(row.github_repo_full_name)),
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

        for capability, raw_config in body.config.items():
            if capability not in requested:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail=f"Config supplied for '{capability}', which is not enabled.",
                )
            # spec 04 §7: a bad tool name or malformed setting fails the save,
            # while the admin is looking at it — not three hours later as a red
            # pipeline nobody connects to this change.
            try:
                config = validate_config(capability, raw_config)
            except CapabilityConfigError as exc:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
                ) from exc
            existing = (
                session.execute(
                    select(CapabilityConfig)
                    .where(CapabilityConfig.repo_onboarding_id == row.id)
                    .where(CapabilityConfig.capability == capability)
                )
                .scalars()
                .first()
            )
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

        # No workflows to install, so no pull request to wait on: the enabled
        # set moves now. Grants are synced through the same TokenRegistry call
        # the installer makes, so what a capability may write is decided in one
        # place regardless of which path got here (spec 16 §15).
        # Spec 03 §3a: only an Actions-scanned repository has workflows to
        # install. For Concourse the pipeline decides what runs, so enabling
        # a capability grants ingestion and installs nothing - and asking for
        # an install here would open a pull request nobody wants against a
        # repository whose Actions were deliberately removed.
        installs_workflows = body.install_workflows and row.scanned_by == "github_actions"
        if not installs_workflows:
            registry = TokenRegistry(session, overlap_hours=settings.token_overlap_hours)
            previous = set(row.enabled_capabilities or [])
            grants_added, grants_removed = registry.sync_grants(
                row.github_repo_full_name, requested
            )
            row.enabled_capabilities = sorted(requested)
            # Any PR left open by an earlier install is now describing a set
            # nobody is waiting for. Clearing the pointer is not the same as
            # closing the PR, which is a GitHub action a person should take.
            row.pending_capabilities = None
            row.pending_pr_number = None
            if row.status == "pending_install":
                row.status = "active"

            db.audit(
                session,
                actor=actor,
                action="repo.capabilities",
                entity_type="repo_onboarding",
                entity_id=row.id,
                repo=row.github_repo_full_name,
                requested=sorted(requested),
                added=sorted(requested - previous),
                removed=sorted(previous - requested),
                install_workflows=False,
            )
            session.commit()

            return CapabilityUpdateResult(
                repo=_summary(row),
                added=sorted(requested - previous),
                removed=sorted(previous - requested),
                secret_provisioned=False,
                detail=(
                    "Enabled without installing workflows. Grants are live and "
                    f"{len(grants_added)} added / {len(grants_removed)} removed. "
                    "Nothing will scan this repository unless a pipeline "
                    "Mykronos does not manage is already doing so."
                ),
            )

        installer = WorkflowInstaller(
            request.app.state.github_factory.for_installation(row.github_installation_id),
            request.app.state.templates,
            ingestion_api_url=settings.ingestion_api_url,
            upload_action_ref=settings.upload_action_ref,
            package_spec=settings.mykronos_package_spec,
            token_overlap_hours=settings.token_overlap_hours,
        )
        registry = TokenRegistry(session, overlap_hours=settings.token_overlap_hours)

        try:
            plan = await installer.plan(row, requested, configs=capability_configs(session, row))
            result = await installer.apply(session, row, plan, actor=actor, registry=registry)
        except PathCollisionError as exc:
            # spec 03 §8 — a human wrote a file where we would generate one.
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
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
                result.pull_request.number if result.pull_request else plan.pending_pr_number
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

    Two operational tables *are* purged, and the distinction is the one the
    lake/operational split rests on. A triage claim is a fact about who is
    working on something this week (spec 27 §3); a declared control is a claim
    about the present (spec 28 §3). Neither is evidence of anything once the
    repository is offboarded, and both would otherwise sit in the queue and on
    the tab of a repository nobody scans any more. The counts go in the audit
    entry, so the deletion is recorded even though the rows are not.
    """
    db = request.app.state.db
    with db.session() as session:
        row = _get(session, repo_id)
        registry = TokenRegistry(session)
        revoked = registry.revoke_repo(row.github_repo_full_name)
        row.status = "removed"
        claims_purged = worklist.purge_for_repo(session, row.github_repo_full_name)
        controls_purged = controls.purge_for_repo(session, row.github_repo_full_name)

        db.audit(
            session,
            actor=actor,
            action="repo.offboard",
            entity_type="repo_onboarding",
            entity_id=row.id,
            repo=row.github_repo_full_name,
            tokens_revoked=revoked,
            triage_rows_purged=claims_purged,
            controls_purged=controls_purged,
            note="historical findings retained for audit (spec 02 §6)",
        )
        return _summary(row)


@router.post("/{repo_id}/scan", response_model=ScanResult)
async def scan_now(
    request: Request,
    repo_id: str,
    actor: AdminDep,
    capabilities: Annotated[
        list[str] | None,
        Query(
            description="Scope the dispatch to these capabilities only "
            "(repeat the param). Omitted — the default — dispatches every "
            "enabled scanning capability, as before; the Test Harness tab "
            "passes unit/functional/qa specifically so its 'run tests' "
            "button does not also kick off a security scan."
        ),
    ] = None,
) -> ScanResult:
    """Dispatch enabled scanning capabilities now (spec 17 §2.5), rather
    than waiting for the next scheduled or push-triggered run.

    Dispatch mechanism follows `scanned_by`, same as everywhere else it
    matters (spec 15 §4a's coverage cross-check, this row's own read path):
    a real GitHub Actions `workflow_dispatch` for an Actions-scanned repo, a
    Concourse build trigger for a Concourse-scanned one. Neither call is
    synchronous — both report only what was *attempted*.
    """
    db = request.app.state.db
    with db.session() as session:
        row = _get(session, repo_id)
        if row.status == "removed":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"{row.github_repo_full_name} is offboarded. Nothing to scan.",
            )

        enabled = set(row.enabled_capabilities or [])
        if row.scanned_by != "github_actions":
            # Same union the portfolio/CI views apply (spec 15 §4a): the
            # installer's ledger never moves for a Concourse-scanned repo, so
            # the grants are the truth for what may write, and therefore
            # what's worth dispatching.
            enabled |= {
                str(grant.capability)
                for grant in session.execute(
                    select(CapabilityGrant).where(
                        CapabilityGrant.repo_full_name == row.github_repo_full_name
                    )
                ).scalars()
            }
        dispatchable = DISPATCHABLE_CAPABILITIES
        if capabilities is not None:
            dispatchable = DISPATCHABLE_CAPABILITIES & set(capabilities)
        scanning = sorted(enabled & dispatchable)
        # `enabled_capabilities` and `pending_capabilities` are disjoint by
        # construction — a capability is one or the other, never both — so
        # this can never overlap `scanning`. It answers a different, more
        # useful question when `scanning` turns out empty: "nothing to
        # dispatch" and "nothing to dispatch *yet*, an install PR is still
        # open" are different facts, and only one of them is worth a 409.
        pending = sorted((set(row.pending_capabilities or [])) & dispatchable)

        repo_full_name = row.github_repo_full_name
        scanned_by = row.scanned_by
        default_branch = row.default_branch
        installation_id = row.github_installation_id

    if not scanning:
        if pending:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"Still awaiting an install pull request: {', '.join(pending)}. "
                    "Merge it, then dispatch a scan for them."
                ),
            )
        return ScanResult(
            dispatched=[],
            failed=[],
            detail=f"No scanning capability is enabled for {repo_full_name}.",
        )

    dispatched: list[str] = []
    failed: list[str] = []

    if scanned_by == "github_actions":
        github = request.app.state.github_factory.for_installation(installation_id)
        templates = request.app.state.templates
        for capability in scanning:
            try:
                workflow_file = PurePosixPath(templates.target_path(capability)).name
            except TemplateError:
                failed.append(capability)
                continue
            try:
                await github.dispatch_workflow(repo_full_name, workflow_file, default_branch)
                dispatched.append(capability)
            except GitHubError as exc:
                logger.warning(
                    "Scan dispatch for %s/%s failed: %s", repo_full_name, capability, exc
                )
                failed.append(capability)
        detail = (
            f"Dispatched {len(dispatched)} of {len(scanning)} workflow(s) via GitHub Actions."
        )

    elif scanned_by == "concourse":
        settings = request.app.state.settings
        client = ConcourseClient(
            settings.concourse_url,
            team=settings.concourse_team,
            external_url=settings.concourse_external_url,
        )
        if not client.configured or not settings.concourse_api_token:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=(
                    "No Concourse API token is configured for this deployment "
                    "(spec 17 §2.5) — the pipeline-status panel still reads "
                    "anonymously, but triggering a build is a write and needs one."
                ),
            )
        pipeline = pipeline_name_for(repo_full_name)
        for capability in scanning:
            candidates = sorted(jobs_for_capability(capability))
            if any(
                client.trigger_job(pipeline, job, token=settings.concourse_api_token)
                for job in candidates
            ):
                dispatched.append(capability)
            else:
                failed.append(capability)
        detail = f"Dispatched {len(dispatched)} of {len(scanning)} job(s) on pipeline {pipeline!r}."

    else:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"{repo_full_name} has no configured scanner (scanned_by=none) — "
                "nothing dispatches its findings today, so there is nothing to trigger."
            ),
        )

    return ScanResult(dispatched=dispatched, failed=failed, detail=detail)


def _profile_out(row: RiskProfile | None) -> RiskProfileOut:
    """A missing profile and an empty one are different answers (spec 21 §1).

    No row is `exists: False` — Oracle reports `available: false` for it and
    contributes nothing. A row whose every field is null is `exists: True`:
    somebody opened the form and recorded that they do not know yet, which is
    an auditable fact and not the same as never having been asked.
    """
    if row is None:
        return RiskProfileOut(exists=False)
    return RiskProfileOut(
        exists=True,
        internet_facing=row.internet_facing,
        data_classification=row.data_classification,  # type: ignore[arg-type]
        business_criticality=row.business_criticality,  # type: ignore[arg-type]
        compliance_scope=list(row.compliance_scope or []),
        owner=row.owner,
        notes=row.notes,
        updated_by=row.updated_by,
        updated_at=row.updated_at,
    )


@router.get("/{repo_id}/reachability", response_model=ReachabilityOut)
async def get_reachability(
    request: Request, repo_id: str, principal: PrincipalDep
) -> ReachabilityOut:
    """The stored import analysis for one repository (spec 19 §2.1).

    Readable by any authenticated principal, like the risk profile beside it
    and for the same reason: somebody reading a risk decision should be able
    to see the inputs that moved it, and this one *lowers* scores — a
    discount nobody can inspect is worse than one nobody applies.

    The absent case is a 200 with `analysed: false`, not a 404. No analysis
    having run is a real answer about the repository, and a 404 would make a
    caller guess between "this repo does not exist" and "nothing has looked".
    """
    with request.app.state.db.session() as session:
        row = _get(session, repo_id)
        report = (
            session.execute(
                select(ReachabilityReport).where(
                    ReachabilityReport.repo_onboarding_id == row.id
                )
            )
            .scalars()
            .first()
        )
        if report is None:
            return ReachabilityOut(analysed=False)
        return ReachabilityOut(
            analysed=True,
            language=report.language,
            commit_sha=report.commit_sha,
            files_analysed=report.files_analysed,
            files_unparseable=report.files_unparseable,
            orphaned_paths=list(report.orphaned_paths or []),
            updated_at=report.updated_at,
        )


@router.get("/{repo_id}/risk-profile", response_model=RiskProfileOut)
async def get_risk_profile(
    request: Request, repo_id: str, principal: PrincipalDep
) -> RiskProfileOut:
    """What this application is, as an asset (spec 21 §1.3).

    Readable by any authenticated principal — nothing here is more sensitive
    than a capability config, and a viewer reading a risk decision should be
    able to see the asset facts that drove it.
    """
    with request.app.state.db.session() as session:
        row = _get(session, repo_id)
        profile = (
            session.execute(
                select(RiskProfile).where(RiskProfile.repo_onboarding_id == row.id)
            )
            .scalars()
            .first()
        )
        return _profile_out(profile)


@router.put("/{repo_id}/risk-profile", response_model=RiskProfileOut)
async def put_risk_profile(
    request: Request, repo_id: str, body: RiskProfileUpdate, actor: AdminDep
) -> RiskProfileOut:
    """Record or replace this repository's risk profile (spec 21 §1.3).

    Admin-only and audit-logged: this changes what Oracle will decide, so it
    is a write in the same sense a finding disposition is (spec 10 §2.2), not
    a preference. `updated_by` is stamped from the caller rather than accepted
    from the body — "who said this repository is internet-facing" is exactly
    the field nobody should be able to fill in on somebody else's behalf.
    """
    db = request.app.state.db
    with db.session() as session:
        row = _get(session, repo_id)
        profile = (
            session.execute(
                select(RiskProfile).where(RiskProfile.repo_onboarding_id == row.id)
            )
            .scalars()
            .first()
        )
        if profile is None:
            profile = RiskProfile(repo_onboarding_id=row.id)
            session.add(profile)

        profile.internet_facing = body.internet_facing
        profile.data_classification = body.data_classification
        profile.business_criticality = body.business_criticality
        profile.compliance_scope = list(body.compliance_scope)
        profile.owner = body.owner
        profile.notes = body.notes
        profile.updated_by = actor

        db.audit(
            session,
            actor=actor,
            action="repo.risk_profile.set",
            entity_type="risk_profile",
            entity_id=row.id,
            repo=row.github_repo_full_name,
            internet_facing=body.internet_facing,
            data_classification=body.data_classification,
            business_criticality=body.business_criticality,
            compliance_scope=list(body.compliance_scope),
        )
        session.flush()
        return _profile_out(profile)
