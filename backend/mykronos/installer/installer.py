"""The Workflow Installer (spec 03).

Turns a repo's requested capability set into a pull request containing the
GitHub Actions YAML, so a human always reviews and merges the change that
turns scanning on.

Two invariants are worth stating up front, because both are easy to lose and
expensive to lose:

**A capability is not enabled until its PR merges.** `enabled_capabilities` is
the merged set; `pending_capabilities` is what has been requested. Keeping
them apart is what makes repeated saves idempotent, and it stops the dashboard
claiming coverage that does not exist yet.

**Grants are not the PR.** Ingestion grants are applied immediately on enable
and revoked immediately on disable (spec 03 §5), independent of whether the
workflow PR has merged. An unmerged removal PR must not leave a capability
able to keep writing for days; and a workflow whose grant is gone fails loudly
with 403, which is the correct signal that the PR is still outstanding.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy.orm import Session

from mykronos.auth import TokenRegistry
from mykronos.db.models import CapabilityConfig, RepoOnboarding, WorkflowInstallEvent
from mykronos.github.client import FileChange, GitHubClient, PullRequest
from mykronos.github.secrets import seal_secret
from mykronos.installer.templates import (
    RenderedWorkflow,
    TemplateLibrary,
    is_mykronos_generated,
)
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

BRANCH_PREFIX = "mykronos/enable-workflows-"
DEFAULT_SECRET_NAME = "MYKRONOS_INGESTION_TOKEN"


class InstallerError(RuntimeError):
    """The install cannot proceed and a human needs to know why."""


class PathCollisionError(InstallerError):
    """A hand-written file already occupies a path we would generate.

    spec 03 §8: abort with a clear error rather than silently overwriting
    someone's workflow.
    """


@dataclass
class InstallPlan:
    """What an install would do, computed before anything is written."""

    repo_full_name: str
    requested: set[str]
    active: set[str]
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    changes: list[FileChange] = field(default_factory=list)
    rendered: list[RenderedWorkflow] = field(default_factory=list)

    #: Nothing to do. Either the request matches what is already merged, or it
    #: matches a request already in flight (see `already_pending`).
    is_noop: bool = False

    #: The request is identical to the open PR's. spec 03 §4 only rules out a
    #: *second* PR; without this we would force-push a byte-identical diff onto
    #: the open one every time an admin re-saves, which shows up as churn on
    #: their PR for no reason.
    already_pending: bool = False

    #: The open PR this request matched, when `already_pending`.
    pending_pr_number: int | None = None

    def describe(self) -> str:
        parts = []
        if self.added:
            parts.append(f"enable {', '.join(sorted(self.added))}")
        if self.removed:
            parts.append(f"disable {', '.join(sorted(self.removed))}")
        return "; ".join(parts) or "no change"


@dataclass
class InstallResult:
    plan: InstallPlan
    pull_request: PullRequest | None
    branch: str | None
    secret_provisioned: bool
    grants_added: set[str] = field(default_factory=set)
    grants_removed: set[str] = field(default_factory=set)


class WorkflowInstaller:
    def __init__(
        self,
        github: GitHubClient,
        templates: TemplateLibrary,
        *,
        ingestion_api_url: str,
        upload_action_ref: str,
        secret_name: str = DEFAULT_SECRET_NAME,
        token_overlap_hours: int = 24,
    ) -> None:
        self.github = github
        self.templates = templates
        self.ingestion_api_url = ingestion_api_url
        self.upload_action_ref = upload_action_ref
        self.secret_name = secret_name
        self.token_overlap_hours = token_overlap_hours

    # -- planning -------------------------------------------------------

    async def plan(
        self,
        onboarding: RepoOnboarding,
        requested: set[str],
        configs: dict[str, dict[str, object]] | None = None,
    ) -> InstallPlan:
        """Compute the diff and stage file changes. Writes nothing."""
        unknown = requested - self.templates.available
        if unknown:
            raise InstallerError(
                f"No workflow template for: {', '.join(sorted(unknown))}. "
                f"Available: {', '.join(sorted(self.templates.available))}. "
                "Capability validation belongs at the API boundary "
                "(spec 04 §7) — reaching the installer with an unknown "
                "capability means that check was skipped."
            )

        active = set(onboarding.enabled_capabilities or [])
        plan = InstallPlan(
            repo_full_name=onboarding.github_repo_full_name,
            requested=requested,
            active=active,
            # Always relative to the *merged* set: this is what the PR does,
            # and it is what its body describes.
            added=sorted(requested - active),
            removed=sorted(active - requested),
        )

        if not plan.added and not plan.removed:
            # spec 03 §4: the request matches what is already enabled.
            plan.is_noop = True
            return plan

        pending = set(onboarding.pending_capabilities or [])
        if pending and pending == requested and onboarding.pending_pr_number:
            # Same request, already in flight. Re-rendering would push an
            # identical diff onto the open PR.
            plan.is_noop = True
            plan.already_pending = True
            plan.pending_pr_number = onboarding.pending_pr_number
            return plan

        configs = configs or {}
        for capability in plan.added:
            rendered = self.templates.render(
                capability,
                repo_full_name=onboarding.github_repo_full_name,
                default_branch=onboarding.default_branch,
                ingestion_api_url=self.ingestion_api_url,
                token_secret_name=self.secret_name,
                upload_action_ref=self.upload_action_ref,
                config=configs.get(capability, {}),
            )
            await self._assert_no_collision(onboarding, rendered.path)
            plan.rendered.append(rendered)
            plan.changes.append(FileChange(path=rendered.path, content=rendered.content))

        for capability in plan.removed:
            # Default is to delete the file so the repo's Actions tab stays
            # clean (spec 03 §3.3).
            plan.changes.append(
                FileChange(path=self.templates.target_path(capability), content=None)
            )

        return plan

    async def _assert_no_collision(self, onboarding: RepoOnboarding, path: str) -> None:
        existing = await self.github.get_file(
            onboarding.github_repo_full_name, path, onboarding.default_branch
        )
        if existing is None or is_mykronos_generated(existing):
            return
        raise PathCollisionError(
            f"{onboarding.github_repo_full_name} already has a file at {path} that "
            "Mykronos did not generate. Refusing to overwrite it. Rename or remove "
            "the existing workflow, then retry. (spec 03 §8)"
        )

    # -- applying -------------------------------------------------------

    async def apply(
        self,
        session: Session,
        onboarding: RepoOnboarding,
        plan: InstallPlan,
        *,
        actor: str,
        registry: TokenRegistry,
        now: datetime | None = None,
    ) -> InstallResult:
        """Provision the secret, open or update the PR, and record the event."""
        moment = now or utcnow()
        repo = onboarding.github_repo_full_name

        # 1. Ensure the repo has an ingestion token + secret. Once per repo,
        #    not per capability (D-009). Skipped when nothing is requested, so
        #    disabling everything does not mint a credential for a repo that
        #    has no capabilities left.
        secret_provisioned = (
            await self._ensure_secret(session, repo, registry) if plan.requested else False
        )

        # 2. Grants track *intent* and change immediately, decoupled from the
        #    PR (spec 03 §5). This happens even on a no-op: an admin who
        #    disables a capability before its PR merged has still disabled it,
        #    and must not be left with a live grant.
        grants_added, grants_removed = registry.sync_grants(repo, plan.requested)

        existing_pr = await self.github.find_open_pull_request(repo, BRANCH_PREFIX)

        if plan.already_pending:
            # Same request, already in flight. Touching the PR would push an
            # identical diff.
            return InstallResult(
                plan=plan,
                pull_request=existing_pr,
                branch=existing_pr.head_branch if existing_pr else None,
                secret_provisioned=secret_provisioned,
                grants_added=grants_added,
                grants_removed=grants_removed,
            )

        if plan.is_noop:
            # The request matches what is already merged. If a PR is open it
            # was for a request since withdrawn, and has nothing left to do —
            # leaving it would let a later merge re-enable what was cancelled.
            if existing_pr is not None:
                await self.github.close_pull_request(
                    repo,
                    existing_pr.number,
                    comment=(
                        "Superseded: the requested capability set now matches what "
                        "is already enabled on this repository, so there is nothing "
                        "for this pull request to change. Closing it rather than "
                        "leaving a merge that would re-enable a withdrawn request."
                    ),
                )
                onboarding.pending_capabilities = None
                onboarding.pending_pr_number = None
                session.add(
                    WorkflowInstallEvent(
                        repo_onboarding_id=onboarding.id,
                        pr_number=existing_pr.number,
                        pr_url=existing_pr.url,
                        branch=existing_pr.head_branch,
                        status="closed_unmerged",
                        detail="request withdrawn before merge",
                    )
                )
            return InstallResult(
                plan=plan,
                pull_request=None,
                branch=None,
                secret_provisioned=secret_provisioned,
                grants_added=grants_added,
                grants_removed=grants_removed,
            )

        # 3. Reuse an open PR rather than opening a second (spec 03 §4).
        if existing_pr is not None:
            branch = existing_pr.head_branch
        else:
            branch = f"{BRANCH_PREFIX}{moment.strftime('%Y%m%dT%H%M%S')}"
            await self.github.create_branch(repo, branch, onboarding.default_branch)

        await self.github.commit_files(
            repo, branch, f"Mykronos: {plan.describe()}", plan.changes
        )

        title = "Mykronos: update security workflows"
        body = self._pr_body(plan)
        if existing_pr is not None:
            pull_request = await self.github.update_pull_request(
                repo, existing_pr.number, title=title, body=body
            )
        else:
            pull_request = await self.github.create_pull_request(
                repo, head=branch, base=onboarding.default_branch, title=title, body=body
            )

        # 4. Requested-but-not-merged. `enabled_capabilities` moves only when
        #    the PR merges (spec 03 §3.6).
        onboarding.pending_capabilities = sorted(plan.requested)
        onboarding.pending_pr_number = pull_request.number

        session.add(
            WorkflowInstallEvent(
                repo_onboarding_id=onboarding.id,
                pr_number=pull_request.number,
                pr_url=pull_request.url,
                branch=branch,
                capabilities_added=plan.added,
                capabilities_removed=plan.removed,
                status="updated" if existing_pr is not None else "opened",
                detail=plan.describe(),
            )
        )
        return InstallResult(
            plan=plan,
            pull_request=pull_request,
            branch=branch,
            secret_provisioned=secret_provisioned,
            grants_added=grants_added,
            grants_removed=grants_removed,
        )

    async def _ensure_secret(
        self, session: Session, repo_full_name: str, registry: TokenRegistry
    ) -> bool:
        """Create the repo's ingestion secret if it has no active token yet.

        Deliberately not called on every capability change: the repo has one
        token spanning capabilities (D-009), so re-issuing here would rotate a
        working credential for no reason every time an admin ticks a box.
        """
        if registry._active_token(repo_full_name) is not None:  # noqa: SLF001
            return False

        plaintext = registry.issue(repo_full_name, label="workflow-installer")
        key = await self.github.get_actions_public_key(repo_full_name)
        await self.github.put_actions_secret(
            repo_full_name,
            self.secret_name,
            seal_secret(key.key_base64, plaintext),
            key.key_id,
        )
        return True

    def _pr_body(self, plan: InstallPlan) -> str:
        lines = [
            "This pull request was opened by **Mykronos** to update the security",
            "scanning workflows on this repository.",
            "",
            "### What changes",
            "",
        ]
        for capability in plan.added:
            spec = self.templates.spec(capability)
            lines.append(
                f"- **Enable `{capability}`** — {spec.summary or capability} "
                f"(`{spec.target}`, template v{spec.version})"
            )
        for capability in plan.removed:
            lines.append(
                f"- **Disable `{capability}`** — removes `"
                f"{self.templates.target_path(capability)}`"
            )
        lines += [
            "",
            "### What happens when you merge",
            "",
            "The workflows start running on their configured triggers and upload",
            "results to Mykronos. Nothing is auto-merged or auto-fixed anywhere;",
            "every finding stays advisory unless this repo has explicitly opted",
            "into blocking checks.",
            "",
            "### Notes",
            "",
            "- Ingestion for the capabilities above is already live, so a workflow",
            "  merged from this PR can post results immediately.",
            "- If branch protection requires a status check that these workflows",
            "  themselves provide, the first run has nothing to satisfy it with.",
            "  That is standard GitHub behaviour on a new required check and is",
            "  yours to resolve, not something Mykronos can work around.",
            "- These files are generated. Edit the capability config in Mykronos",
            "  rather than the YAML, or a future template resync will overwrite",
            "  your changes.",
        ]
        return "\n".join(lines)

    # -- merge -----------------------------------------------------------

    @staticmethod
    def on_install_pr_merged(
        session: Session, onboarding: RepoOnboarding, pr_number: int
    ) -> bool:
        """Promote pending capabilities to active (spec 03 §3.6).

        Driven by the `pull_request.closed` webhook with `merged=true`. Only
        here does `enabled_capabilities` change, which is what keeps the
        dashboard from claiming coverage that has not shipped.
        """
        if onboarding.pending_pr_number != pr_number:
            return False

        onboarding.enabled_capabilities = list(onboarding.pending_capabilities or [])
        onboarding.pending_capabilities = None
        onboarding.pending_pr_number = None
        if onboarding.status == "pending_install":
            onboarding.status = "active"

        event = (
            session.query(WorkflowInstallEvent)
            .filter(WorkflowInstallEvent.repo_onboarding_id == onboarding.id)
            .filter(WorkflowInstallEvent.pr_number == pr_number)
            .order_by(WorkflowInstallEvent.created_at.desc())
            .first()
        )
        if event is not None:
            event.status = "merged"
            event.merged_at = utcnow()
        return True


def capability_configs(
    session: Session, onboarding: RepoOnboarding
) -> dict[str, dict[str, object]]:
    """Per-capability config blocks for rendering (spec 02 §3)."""
    rows = (
        session.query(CapabilityConfig)
        .filter(CapabilityConfig.repo_onboarding_id == onboarding.id)
        .all()
    )
    return {row.capability: dict(row.config_json or {}) for row in rows}
