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
from mykronos.regression import TEST_CAPABILITIES as TEST_LANES
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

BRANCH_PREFIX = "mykronos/enable-workflows-"

#: Capabilities that are triggered by other workflows rather than by a push.
#: Ordered: each waits for everything before it, so Oracle sees Patchwork's
#: draft pull requests when it scores (spec 08 §9) instead of racing the
#: pipeline whose output it consumes.
_GATE_ORDER = ("patchwork", "oracle")


def _gate_depends_on(capability: str, enabled: list[str]) -> list[str]:
    """Workflow names a `workflow_run`-triggered capability must wait for.

    Derived from what this repo will actually have enabled, not from the full
    capability list: a `workflow_run` trigger naming a workflow that does not
    exist never fires, so an over-broad list silently stops the gate firing at
    all.

    Two rules beyond that, both of which were wrong in the first version:

    - **A gate never waits for itself.** Listing `Mykronos patchwork` in
      patchwork's own trigger is a workflow triggering on its own completion.
    - **A later gate waits for the earlier ones.** Oracle reads Patchwork's
      output; if they both trigger on the scanners they race, and Oracle
      scores before the draft pull requests exist. The discount would then be
      missing from exactly the decision a reviewer is reading.
    """
    if capability not in _GATE_ORDER:
        return []

    position = _GATE_ORDER.index(capability)
    waits_for = [c for c in enabled if c not in _GATE_ORDER] + [
        c for c in _GATE_ORDER[:position] if c in enabled
    ]
    return [f"Mykronos {c}" for c in waits_for]

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

    #: Capabilities already requested whose rendered workflow no longer matches
    #: what is in the repo — a config change rather than an enable or disable.
    #: Without this the installer was blind to config: it decided there was
    #: nothing to do by comparing capability *sets*, so narrowing a CodeQL
    #: language matrix, setting a DAST target or changing a cron was stored in
    #: the database and never reached the repository. The two then disagreed
    #: silently until some later resync rewrote the file for no visible reason.
    updated: list[str] = field(default_factory=list)

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
        if self.updated:
            parts.append(f"update {', '.join(sorted(self.updated))}")
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
        package_spec: str = "",
        secret_name: str = DEFAULT_SECRET_NAME,
        token_overlap_hours: int = 24,
    ) -> None:
        self.github = github
        self.templates = templates
        self.ingestion_api_url = ingestion_api_url
        self.upload_action_ref = upload_action_ref
        self.package_spec = package_spec
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

        configs = configs or {}

        # A test lane with no command would render a workflow that checks out
        # the code, runs nothing, and uploads an empty results directory —
        # green on every run and meaningless. The command has no default
        # because a repository's test runner is decided by its language and
        # its own conventions (D-046, spec 31 §5), so the honest failure is a
        # 422 naming the field rather than a workflow that tests nothing.
        commandless = sorted(
            capability
            for capability in requested
            if capability in TEST_LANES
            and not str(configs.get(capability, {}).get("command", "")).strip()
        )
        if commandless:
            raise InstallerError(
                f"No test command configured for: {', '.join(commandless)}. "
                "A test lane runs this repository's own suite, and this "
                "platform will not guess it — set `command` on each "
                "capability's config to something that writes JUnit XML into "
                "$MYKRONOS_RESULTS."
            )

        enabled_after = sorted(
            c for c in requested if c in self.templates.available
        )

        # What a further change would land on top of. An open install PR is
        # that branch — comparing against the default branch instead would
        # re-push every file the PR already carries.
        repo = onboarding.github_repo_full_name
        existing_pr = await self.github.find_open_pull_request(repo, BRANCH_PREFIX)
        baseline = existing_pr.head_branch if existing_pr else onboarding.default_branch

        # Render everything requested, not only what is newly added. A
        # capability that is already on can still have a workflow that no
        # longer matches its config, and that is precisely the case the old
        # set-comparison could not see.
        for capability in sorted(requested):
            if capability not in self.templates.available:
                continue
            rendered = self.templates.render(
                capability,
                repo_full_name=repo,
                default_branch=onboarding.default_branch,
                ingestion_api_url=self.ingestion_api_url,
                token_secret_name=self.secret_name,
                upload_action_ref=self.upload_action_ref,
                mykronos_package_spec=self.package_spec,
                config=configs.get(capability, {}),
                gate_depends_on=_gate_depends_on(capability, enabled_after),
            )
            plan.rendered.append(rendered)

            current = await self._existing_file(onboarding, rendered.path, baseline)
            if current == rendered.content:
                # Byte-identical. Skipping it is what keeps a re-save from
                # showing up as churn on somebody's open pull request.
                continue
            if capability not in plan.added:
                plan.updated.append(capability)
            plan.changes.append(FileChange(path=rendered.path, content=rendered.content))

        for capability in plan.removed:
            # Default is to delete the file so the repo's Actions tab stays
            # clean (spec 03 §3.3).
            path = self.templates.target_path(capability)
            if await self._existing_file(onboarding, path, baseline) is None:
                continue  # Already absent on the branch we would push to.
            plan.changes.append(FileChange(path=path, content=None))

        if not plan.changes:
            # Judged on content, not on capability sets. The two differ exactly
            # when config changed, which is the bug this replaced.
            plan.is_noop = True
            if existing_pr is not None and set(
                onboarding.pending_capabilities or []
            ) == requested:
                plan.already_pending = True
                plan.pending_pr_number = existing_pr.number

        return plan

    async def _existing_file(
        self, onboarding: RepoOnboarding, path: str, ref: str
    ) -> str | None:
        """This repo's current content at `path`, refusing to touch a file a
        person wrote (spec 03 §8).

        The collision check lives here rather than in a separate pass so that
        every path the plan touches is checked exactly once, and always
        against the same read that decides whether it changed.
        """
        existing = await self.github.get_file(onboarding.github_repo_full_name, path, ref)
        if existing is not None and not is_mykronos_generated(existing):
            raise PathCollisionError(
                f"{onboarding.github_repo_full_name} already has a file at {path} that "
                "Mykronos did not generate. Refusing to overwrite it. Rename or remove "
                "the existing workflow, then retry. (spec 03 §8)"
            )
        return existing

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
        # Only after the write lands. If it raised, the token stays unsynced
        # and the rotation job picks it up rather than leaving a repo holding
        # a credential the platform has never heard of.
        registry.mark_secret_synced(repo_full_name)
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
        for capability in plan.updated:
            spec = self.templates.spec(capability)
            lines.append(
                f"- **Update `{capability}`** — already enabled; its workflow no "
                f"longer matches the configuration held in Mykronos "
                f"(`{spec.target}`, template v{spec.version})"
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
