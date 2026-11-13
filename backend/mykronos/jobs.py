"""Scheduled maintenance jobs.

Six things that have to happen on a timer rather than in response to a
request: rotating ingestion tokens, noticing that a repo uninstalled the App
behind our back, closing findings that stopped being reported, scoring the
portfolio, deleting insider-risk rows past their retention period, and
dropping learnings about repositories that no longer exist.

That last one is not housekeeping. Spec 06 §9 makes it normative, on the
grounds that an unenforced retention policy is just a sentence.

Every job here is safe to run twice and safe to interrupt. They run
unattended, so "crashed halfway and left something inconsistent" is not an
acceptable failure mode — each one either completes a repo's work or leaves
that repo exactly as it was for the next run to retry.
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, date, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

import httpx2
from sqlalchemy import select

from mykronos import (
    ci_stall,
    dependabot_merge,
    dormant_lanes,
    gate_liveness,
    red_main,
    timeout_audit,
)
from mykronos.adminauth import ActorKind, Principal, Role
from mykronos.approvals import pull_requests as approval_pull_requests
from mykronos.approvals.engine import ApprovalError
from mykronos.auth import TokenRegistry
from mykronos.ci import ConcourseClient, jobs_for_capability, pipeline_name_for
from mykronos.db import Database
from mykronos.db.models import (
    ApprovalRequest,
    GatingLaneState,
    JobRun,
    RepoOnboarding,
    capability_config_for,
)
from mykronos.github.client import GitHubClient, GitHubError
from mykronos.github.factory import GitHubClientFactory
from mykronos.github.secrets import (
    permission_not_held_reason,
    seal_secret,
    sync_dependabot_secret,
    write_failed_under_grant,
)
from mykronos.installer import DEFAULT_SECRET_NAME
from mykronos.knowledge import KnowledgeStore
from mykronos.knowledge import PurgeResult as KnowledgePurgeResult
from mykronos.lake.buffer import WriteAheadBuffer
from mykronos.lake.catalog import Catalog
from mykronos.lake.mutate import locate_findings, purge_rows, update_findings
from mykronos.logsafe import scrub
from mykronos.notify import Delivery, Notification, Notifier
from mykronos.oracle.service import OracleService
from mykronos.patchwork.branch_rescan import BranchRescanResult, rescan_open_fixes
from mykronos.patchwork.stewardship import close_superseded_drafts
from mykronos.patchwork.verification import (
    VerificationResult,
    dispatch_pending,
    resolve_pending,
)
from mykronos.schemas import utcnow

if TYPE_CHECKING:  # pragma: no cover - import-cycle guard
    from mykronos.briefing import TokenDelivery

logger = logging.getLogger(__name__)


@dataclass
class ReachabilityResult:
    """Whether the outside world can actually reach this platform.

    The one check that cannot be delegated to a container healthcheck, because
    a container healthcheck runs *inside* the thing it is checking. On
    2026-08-29 `mykronos-backend` reported `healthy` for 22 hours while its
    host port was unpublished: the process was fine, the dashboard was fine —
    the frontend reaches it over the Docker network — and every scan upload
    from every pipeline was failing with a 502 from the tunnel. Nothing said
    so, because nothing was looking from outside.

    That is precisely the disagreement spec 15 §4a.1 exists to surface, one
    layer lower down: green and unreachable, at the same time.
    """

    url: str = ""
    reachable: bool = False
    status_code: int | None = None
    detail: str = ""
    #: Whether this deployment has the dependency at all (B-014).
    #:
    #: A dependency nobody configured is not a dependency that failed, and
    #: rendering the two the same way is how a check stops being read. Vault
    #: sat `FAILED` on every run of this command because `vault_url` was
    #: blank, which is the permanent red this platform refuses everywhere
    #: else — `available: false` versus a real zero, "not enabled" versus
    #: "enabled and silent".
    configured: bool = True


@dataclass
class RotationResult:
    rotated: list[str] = field(default_factory=list)
    resynced: list[str] = field(default_factory=list)
    failed: list[tuple[str, str]] = field(default_factory=list)
    purged: int = 0
    #: Due, and deliberately left alone: this platform has no way to deliver a
    #: rotated token to a Concourse-scanned repository (D-086). Named rather
    #: than counted, because the operator has to act on each one.
    deferred: list[str] = field(default_factory=list)
    #: Not due, and not rotated: flagged never-confirmed-delivered on a
    #: repository this job cannot write a secret to (#263).
    #:
    #: Its own list because the requested action is the opposite one. A
    #: `deferred` repo needs a hand rotation; an `unverified` repo needs
    #: somebody to check that ingestion is arriving, and rotating it by hand
    #: is how its pipeline goes dark. Counting the two together under
    #: "deferred" is what let TheHub be reported as due for rotation with 88
    #: days left on its clock.
    unverified: list[str] = field(default_factory=list)
    #: Repositories whose Actions secret is delivered and whose *Dependabot*
    #: copy could not be written, with the reason (TheHub #60855). Usually the
    #: App lacks `dependabot_secrets: write`; the reason says so and names the
    #: grant. Not `failed`: the rotation itself succeeded, or was correctly
    #: not attempted, and the operator's action is a permission, not a retry.
    dependabot_blocked: list[tuple[str, str]] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"rotated {len(self.rotated)}, resynced {len(self.resynced)}, "
            f"deferred {len(self.deferred)}, unverified {len(self.unverified)}, "
            f"dependabot blocked {len(self.dependabot_blocked)}, "
            f"failed {len(self.failed)}, purged {self.purged}"
        )


def unsynced_deferral_warning(repo: str, blocker: str) -> str:
    """What to say about a repo deferred for being unsynced rather than due.

    `rotate_ingestion_tokens` walks `due | unsynced`, and until now every
    deferral said "is due for token rotation" -- true of the first set and
    false of the second. The difference is not cosmetic, because the two want
    opposite actions from whoever reads the line.

    `secret_synced` used to be set in exactly two places, both immediately
    after a GitHub Actions secret write landed. So a repository this job
    cannot write to could never shed the flag: it joined `unsynced_repos()` on
    the day it was onboarded and stayed there permanently, warning on every
    scheduled run about a token that was being delivered perfectly well by
    another path. ToddGBenson/TheHub was that repository -- flagged unsynced,
    three months from its rotation date, and uploading successfully from
    Concourse the whole time.

    `TokenRegistry.confirm_delivery` closed that hole (#263): an upload
    authenticated with the *active* token now records delivery, so the flag
    has a path back to true for a repository this job cannot write to. What
    remains, and what this line reports, is a repository that has genuinely
    never presented its active token -- which is a real thing to look into and
    still not a reason to rotate.

    Telling that operator to "rotate it by hand" is telling them to break a
    working pipeline: the token changes, Vault keeps serving the old value,
    and the repository goes dark when the overlap expires. That is the
    2026-08-31 outage (D-097) reached from the other direction -- by following
    the advice instead of by ignoring it.
    """
    return (
        f"{repo} has never presented its active ingestion token and {blocker}; "
        "its token is NOT due for rotation. Delivery is recorded when an "
        "upload authenticates with the active token, so this says no scan has "
        "used it yet -- not that rotation is overdue. Confirm ingestion is "
        "actually failing (mykronos briefing) before rotating: rotating a "
        "token whose Vault copy works is what breaks it."
    )


def hand_rotation_instruction(repo: str) -> str:
    """How to rotate a token this job had to defer, as one runnable line.

    It used to say "re-run set-pipeline (or Import-EnvSecretsToVault.ps1
    -Apply)", and neither replaces a value Vault already holds:
    `set-pipeline.ps1` falls back to the vars file only when Vault has *no*
    value, and `Import-EnvSecretsToVault.ps1` reports a key it finds there as
    PRESENT and leaves it (#60753). Every repository this line is about reads
    its token from Vault, so following the advice rotated nothing - or, done by
    hand in the order it implied, rotated the registry and left Vault serving
    the old value, which is D-097.

    `repair-ingestion-token.ps1` is the one path that rotates once and writes
    every reader, Vault included, then re-applies the pipeline.
    """
    return (
        f"deploy/concourse/repair-ingestion-token.ps1 -Repo {repo} -WhatIf, "
        "then again without -WhatIf"
    )


async def _dependabot_grant(github: GitHubClient, installation_id: int) -> str | None:
    """What the installation holds for `dependabot_secrets`: `write`, `read`
    or None (not granted, or the installation could not be read).

    Read from the installation rather than inferred from a successful key
    read, because `read` can fetch the key and still cannot write the secret
    (independent review of #1142). An unreadable installation is None: "could
    not check" must not rotate, for the same reason it must not elsewhere.
    """
    try:
        installation = await github.get_installation(installation_id)
    except (GitHubError, OSError) as exc:
        logger.warning("Could not read installation %s: %s", installation_id, exc)
        return None
    permissions = installation.get("permissions") or {}
    held = permissions.get("dependabot_secrets")
    return str(held) if held else None


def deliveries_awaiting_operator(db: Database) -> list[TokenDelivery]:
    """The tokens the rotation sweep will hand to a person, for the briefing.

    Read separately from running the sweep, because the briefing must not
    rotate anything to find out what needs rotating. Everything here comes
    from the operational database; nothing is called.

    **What this deliberately cannot see.** The sweep also defers a repository
    that *declares* `github_actions` but has a Concourse pipeline reading the
    same token (D-097), and that check is a network call to Concourse. Asking
    it from a briefing would make the page fail when CI is unreachable, so
    this reports the deferrals that are decidable from the record alone. It is
    therefore a floor on what is waiting, which is the safe direction and is
    said out loud rather than left to be discovered.
    """
    from mykronos.briefing import TokenDelivery

    with db.session() as session:
        registry = TokenRegistry(session)
        due = set(registry.due_for_rotation())
        unsynced = set(registry.unsynced_repos())
        scanners = {
            row.github_repo_full_name: row.scanned_by
            for row in session.execute(
                select(RepoOnboarding).where(
                    RepoOnboarding.status.in_(("active", "pending_install"))
                )
            ).scalars()
        }

        waiting: list[TokenDelivery] = []
        for repo in sorted(due | unsynced):
            scanned_by = scanners.get(repo)
            if scanned_by is None or scanned_by == "github_actions":
                # Offboarded, or the sweep can deliver to it unaided: not
                # something to put in front of a person.
                continue
            token = registry.active_token_for(repo)
            if token is None:
                continue
            waiting.append(
                TokenDelivery(
                    repo_full_name=repo,
                    # `due` wins when a repo is both, because the two actions
                    # are not equally urgent and only one of them is safe to
                    # skip: an expired token stops working on a date.
                    state="due" if repo in due else "unverified",
                    issued_at=token.issued_at,
                    rotate_after=token.rotate_after,
                    scanned_by=scanned_by,
                )
            )

        # A Dependabot copy the sweep tried to write and could not (TheHub
        # #60855). Only a *recorded* refusal is a person's work: a token
        # nothing has tried to deliver yet is the sweep's next run, and a
        # repository the sweep does not drive never records one. Any scanner,
        # because the remedy is a permission on the App, not a hand rotation.
        for repo in sorted(registry.dependabot_unsynced_repos()):
            if repo not in scanners:
                continue
            token = registry.active_token_for(repo)
            if token is None or not token.dependabot_sync_blocker:
                continue
            waiting.append(
                TokenDelivery(
                    repo_full_name=repo,
                    state="dependabot_unsynced",
                    issued_at=token.issued_at,
                    rotate_after=token.rotate_after,
                    scanned_by=scanners[repo],
                    reason=token.dependabot_sync_blocker,
                    recorded_at=token.dependabot_sync_blocker_at,
                )
            )
        return waiting


async def rotate_ingestion_tokens(
    db: Database,
    github_factory: GitHubClientFactory,
    *,
    secret_name: str = DEFAULT_SECRET_NAME,
    overlap_hours: int = 24,
    concourse: ConcourseClient | None = None,
) -> RotationResult:
    """Rotate tokens past their 90-day mark, and repair any that never synced.

    Ordering matters and is the whole design (spec 05 §4): the new token is
    created and the old marked superseded **before** the secret is written. If
    the write then fails, the old token is still accepted for the rest of its
    overlap window, so nothing in flight breaks and the next run retries.

    The retry is why `secret_synced` exists. A rotation that succeeded locally
    but failed to write the secret is invisible to a due-date check — the new
    token has a fresh 90-day clock — and the repo would break silently when
    the overlap expired.
    """
    result = RotationResult()

    with db.session() as session:
        registry = TokenRegistry(session, overlap_hours=overlap_hours)
        due = set(registry.due_for_rotation())
        unsynced = set(registry.unsynced_repos())
        # The Dependabot store is the third reason to visit a repository
        # (TheHub #60855). Walked with the other two, but a repository that is
        # *only* here is handled differently below: its Actions token works,
        # so it is probed before anything is rotated.
        dependabot_pending = set(registry.dependabot_unsynced_repos())

        onboardings = {
            row.github_repo_full_name: row
            for row in session.execute(
                select(RepoOnboarding).where(
                    RepoOnboarding.status.in_(("active", "pending_install"))
                )
            ).scalars()
        }

    def _record_dependabot_gap(repo: str, reason: str) -> None:
        with db.session() as session:
            TokenRegistry(session, overlap_hours=overlap_hours).mark_dependabot_unsynced(
                repo, reason
            )
        result.dependabot_blocked.append((repo, reason))

    for repo in sorted(due | unsynced | dependabot_pending):
        onboarding = onboardings.get(repo)
        if onboarding is None:
            # Offboarded or suspended. Its token is revoked or dormant; there
            # is no repo to write a secret to.
            continue

        # Actions delivery is confirmed and only the Dependabot copy is
        # missing. Nothing below is a reason to call such a token due or
        # unverified; it is a reason to write one more secret, if the job
        # can.
        only_dependabot = repo not in due and repo not in unsynced

        # A rotated token is only useful where the scanner can read it, and
        # the only delivery path this job has is a GitHub Actions secret
        # (D-086). For a Concourse-scanned repository that write *succeeds* --
        # GitHub accepts a secret for a repo whose Actions lanes were retired
        # (D-080) -- and the pipeline goes on reading the old value from Vault
        # until a human runs set-pipeline. The job then marked the repo synced
        # and reported green.
        #
        # So the rotation is deferred rather than performed: an un-rotated
        # token keeps working, while a rotated-and-undelivered one breaks the
        # repository as soon as its overlap expires. Doing nothing loudly beats
        # doing the wrong thing quietly.
        if onboarding.scanned_by != "github_actions":
            if only_dependabot:
                # Its Actions token is confirmed delivered, and D-086 says
                # this job writes nothing to a repository it does not drive.
                # A Dependabot copy serves Actions lanes, which this
                # repository declares it has retired, so there is nothing
                # to deliver and nobody to tell.
                continue
            if repo in due:
                # Matches on the word 'token'. Logs a repo name and a command, never a token.
                # nosemgrep: python-logger-credential-disclosure
                logger.warning(
                    "%s is due for token rotation and is scanned by %s, which this "
                    "job cannot deliver to. Rotate it by hand: %s.",
                    repo,
                    onboarding.scanned_by,
                    hand_rotation_instruction(repo),
                )
                result.deferred.append(repo)
            else:
                logger.warning(
                    "%s",
                    unsynced_deferral_warning(
                        repo,
                        f"is scanned by {onboarding.scanned_by}, which this job "
                        "cannot deliver to",
                    ),
                )
                result.unverified.append(repo)
            continue

        # `scanned_by` records intent and holds one value, so it cannot
        # describe a repository scanned by both systems - and this repository
        # is exactly that during the spec 32 migration: 14 Actions workflows
        # active and a Concourse pipeline reading the same token from Vault.
        # It declared `github_actions`, passed the check above, and every
        # rotation desynchronised Vault anyway. That is D-086's failure in the
        # one shape D-086 did not cover, and it broke four lanes on
        # 2026-08-31 (D-097).
        #
        # So the question is not what the repository declares but who reads
        # the token. A Concourse pipeline is a second reader this job cannot
        # write to, and `None` - Concourse unreachable or not configured - is
        # deferred too: "could not check" is not "nobody else reads it", and
        # only one of those is safe to rotate on.
        if concourse is not None:
            has_pipeline = concourse.has_pipeline_for(repo)
            if has_pipeline is not False:
                blocker = (
                    "also has a Concourse pipeline reading its token"
                    if has_pipeline
                    else "Concourse could not be reached to rule one out"
                )
                if only_dependabot:
                    # Delivering the Dependabot copy takes a rotation (the
                    # plaintext is not stored), and a rotation here is what
                    # D-097 forbids. Recorded, not skipped: the work queue
                    # says the copy is missing and why.
                    _record_dependabot_gap(
                        repo,
                        f"The Dependabot secret is not written: {repo} {blocker}, so "
                        "this job will not rotate to deliver it. Rotate by hand: "
                        f"{hand_rotation_instruction(repo)}.",
                    )
                    continue
                if repo in due:
                    # Matches on the word 'token'. Logs a repo name and a reason, never a token.
                    # nosemgrep: python-logger-credential-disclosure
                    logger.warning(
                        "%s is due for token rotation and %s. This job can only "
                        "write a GitHub Actions secret, so rotating would leave "
                        "Vault serving the old value until a human runs "
                        "set-pipeline. Rotate it by hand instead.",
                        repo,
                        blocker,
                    )
                    result.deferred.append(repo)
                else:
                    logger.warning("%s", unsynced_deferral_warning(repo, blocker))
                    result.unverified.append(repo)
                continue

        github = github_factory.for_installation(onboarding.github_installation_id)

        try:
            if only_dependabot:
                # The only way to deliver a Dependabot copy is a rotation,
                # because the plaintext is not stored, and a rotation that
                # then fails the write churns a working credential for
                # nothing. So the token is rotated only on evidence the
                # write will land (TheHub #60855, independent review of
                # #1142): the installation's grant says `write` -- reading
                # the public key proves nothing, a Read-only grant can do
                # that -- and no earlier write failed under that grant.
                held = await _dependabot_grant(github, onboarding.github_installation_id)
                if held != "write":
                    _record_dependabot_gap(repo, permission_not_held_reason(held))
                    continue
                with db.session() as session:
                    token = TokenRegistry(session, overlap_hours=overlap_hours).active_token_for(
                        repo
                    )
                    blocker = token.dependabot_sync_blocker if token is not None else ""
                if write_failed_under_grant(blocker):
                    # Recorded last time; still shown, not retried. The next
                    # due rotation attempts the copy again.
                    result.dependabot_blocked.append((repo, blocker))
                    continue

            with db.session() as session:
                registry = TokenRegistry(session, overlap_hours=overlap_hours)
                if repo in due:
                    plaintext = registry.rotate(repo, label="rotation-job")
                    action = "rotated"
                elif only_dependabot:
                    # Delivered to Actions; the Dependabot copy is missing
                    # and the permission is now held.
                    plaintext = registry.rotate(repo, label="dependabot-resync")
                    action = "resynced"
                else:
                    # Already rotated; only the secret write failed last time.
                    plaintext = registry.rotate(repo, label="rotation-resync")
                    action = "resynced"

            key = await github.get_actions_public_key(repo)
            await github.put_actions_secret(
                repo, secret_name, seal_secret(key.key_base64, plaintext), key.key_id
            )

            with db.session() as session:
                TokenRegistry(session, overlap_hours=overlap_hours).mark_secret_synced(repo)
                db.audit(
                    session,
                    actor="rotation-job",
                    action=f"ingestion_token.{action}",
                    entity_type="repo",
                    entity_id=repo,
                    overlap_hours=overlap_hours,
                )

            (result.rotated if action == "rotated" else result.resynced).append(repo)

            # The same plaintext into the Dependabot store (TheHub #60855).
            # After the Actions write is recorded, so a refusal here cannot
            # undo it, and never raising, so it cannot land in `failed`. A
            # refusal after the grant was read as `write` is recorded as
            # such, which is what stops the next sweep rotating to retry it.
            outcome = await sync_dependabot_secret(
                github, repo, secret_name, plaintext, grant_verified=only_dependabot
            )
            if outcome.synced:
                with db.session() as session:
                    TokenRegistry(session, overlap_hours=overlap_hours).mark_dependabot_synced(
                        repo
                    )
            else:
                _record_dependabot_gap(repo, outcome.reason)

        except (GitHubError, OSError) as exc:
            # Deliberately not fatal to the job: one unreachable repo must not
            # stop every other repo from rotating.
            # Matches on the word 'token'. Logs GitHub's error text, which never echoes the secret.
            # nosemgrep: python-logger-credential-disclosure
            logger.warning("Rotation for %s could not write the secret: %s", repo, exc)
            result.failed.append((repo, str(exc)))

    with db.session() as session:
        result.purged = TokenRegistry(
            session, overlap_hours=overlap_hours
        ).purge_expired()

    # Matches on the word 'token'. Logs counts only (TokenRotationResult.summary).
    # nosemgrep: python-logger-credential-disclosure
    logger.info("Token rotation: %s", result.summary())
    return result


@dataclass
class InstallationSyncResult:
    checked: int = 0
    removed: list[str] = field(default_factory=list)
    suspended: list[str] = field(default_factory=list)
    unreachable: list[str] = field(default_factory=list)


async def reconcile_installations(
    db: Database, github_factory: GitHubClientFactory
) -> InstallationSyncResult:
    """Daily check that each installation still exists (spec 02 §5.6).

    A webhook can be missed — delivery fails, the platform is down, someone
    disables the webhook — so uninstalls are also detected by asking. spec 02
    §8 allows up to 24 hours for this, which is what makes a daily job
    sufficient rather than a gap.
    """
    result = InstallationSyncResult()

    with db.session() as session:
        targets = [
            (row.id, row.github_repo_full_name, row.github_installation_id)
            for row in session.execute(
                select(RepoOnboarding).where(RepoOnboarding.status != "removed")
            ).scalars()
        ]

    for repo_id, repo, installation_id in targets:
        result.checked += 1
        github = github_factory.for_installation(installation_id)
        try:
            installation = await github.get_installation(installation_id)
        except GitHubError as exc:
            if exc.status == 404:
                with db.session() as session:
                    row = session.get(RepoOnboarding, repo_id)
                    if row is not None and row.status != "removed":
                        row.status = "removed"
                        row.last_synced_at = utcnow()
                        db.audit(
                            session,
                            actor="installation-reconciler",
                            action="repo.removed",
                            entity_type="repo_onboarding",
                            entity_id=repo_id,
                            repo=repo,
                            reason="installation no longer exists on GitHub",
                        )
                result.removed.append(repo)
            else:
                # Transient: leave the row alone and try again tomorrow.
                # Marking a repo removed because GitHub had a bad minute would
                # stop its scans for no reason.
                logger.warning("Could not check installation for %s: %s", repo, exc)
                result.unreachable.append(repo)
            continue

        suspended = bool(installation.get("suspended_at"))
        with db.session() as session:
            row = session.get(RepoOnboarding, repo_id)
            if row is None:
                continue
            row.last_synced_at = utcnow()
            if suspended and row.status != "suspended":
                row.status = "suspended"
                result.suspended.append(repo)
            elif not suspended and row.status == "suspended":
                # Unsuspended behind our back; let it be onboarded again.
                row.status = "pending_install" if not row.enabled_capabilities else "active"

    logger.info(
        "Installation reconciliation: checked %s, removed %s, suspended %s, unreachable %s",
        result.checked,
        len(result.removed),
        len(result.suspended),
        len(result.unreachable),
    )
    return result


@dataclass
class PurgeResult:
    rows_deleted: int = 0
    partitions_rewritten: int = 0
    #: Per-repo retention, so the log shows what was applied rather than
    #: implying one global number.
    applied: dict[str, int] = field(default_factory=dict)


def purge_expired_insider_risk(
    db: Database, catalog: Catalog, *, default_retention_days: int = 90
) -> PurgeResult:
    """Delete insider-risk rows past their retention period (spec 06 §9).

    This job is the difference between a retention policy and a sentence about
    one. Every other table in the lake is kept indefinitely — findings, scan
    runs, decisions are all evidence about code. These rows are about people,
    and their usefulness expires with the pull request they describe. After
    that they are only a record of somebody having been suspected.

    Retention is per-repo, from that repo's Aegis config, because a repo can
    reasonably want a shorter window than the default and none should be able
    to opt out of having one. A repo with no config gets the default rather
    than being skipped — the absence of a setting is not consent to keep the
    data forever.

    Rows for repos that have been offboarded entirely are purged at the
    default too: nobody is left to configure a window, and leaving them would
    make deletion depend on an onboarding record that no longer exists.
    """
    result = PurgeResult()
    if not catalog.all_files("insider_risk_signals"):
        return result

    with db.session() as session:
        configured: dict[str, int] = {}
        for row in session.execute(select(RepoOnboarding)).scalars():
            config = capability_config_for(
                session, row.github_repo_full_name, "aegis"
            )
            configured[row.github_repo_full_name] = int(
                config.get("retention_days", default_retention_days)
            )

    known = {
        str(repo)
        for (repo,) in catalog.query(
            "SELECT DISTINCT repo_full_name FROM insider_risk_signals"
        )
    }

    # Grouped by window so a hundred repos sharing the default cost one
    # rewrite pass rather than a hundred.
    by_window: dict[int, list[str]] = {}
    for repo in sorted(known):
        window = configured.get(repo, default_retention_days)
        by_window.setdefault(window, []).append(repo)
        result.applied[repo] = window

    now = utcnow()
    for window, repos in sorted(by_window.items()):
        cutoff = now - timedelta(days=window)
        placeholders = ", ".join("?" for _ in repos)
        deleted, rewritten = purge_rows(
            catalog,
            "insider_risk_signals",
            f"repo_full_name IN ({placeholders}) AND evaluated_at < ?",
            [*repos, cutoff],
        )
        result.rows_deleted += deleted
        result.partitions_rewritten += rewritten

    if result.rows_deleted:
        logger.info(
            "Insider-risk retention: deleted %s row(s) across %s partition(s)",
            result.rows_deleted,
            result.partitions_rewritten,
        )
    return result


def purge_orphaned_learnings(
    db: Database, store: KnowledgeStore
) -> KnowledgePurgeResult:
    """Drop learnings about repos Mykronos no longer holds data for (spec 11 §5).

    Not a confidence purge — decay never deletes. An entry about an offboarded
    repository cannot be reconfirmed, cannot be audited against anything, and
    would otherwise outlive the deletion request that removed everything else
    (spec 02 §6).

    "No longer holds data for" means `removed`, not merely absent from the
    active list: a suspended repo is expected back, and forgetting what its
    team concluded while it was paused would be a real loss.
    """
    with db.session() as session:
        known = {
            row.github_repo_full_name
            for row in session.execute(
                select(RepoOnboarding).where(RepoOnboarding.status != "removed")
            ).scalars()
        }
    return store.purge_expired(known_repos=known)


async def close_superseded_fixes(
    db: Database,
    catalog: Catalog,
    buffer: WriteAheadBuffer,
    github_factory: GitHubClientFactory,
) -> dict[str, int]:
    """Close draft fixes whose finding somebody already dealt with (spec 08 §8).

    A queue of draft pull requests nobody needs is how the ones that matter
    stop being read, so a fix for a resolved finding closes itself with an
    explanation rather than sitting there.
    """
    with db.session() as session:
        targets = [
            (row.github_repo_full_name, row.github_installation_id)
            for row in session.execute(
                select(RepoOnboarding).where(RepoOnboarding.status == "active")
            ).scalars()
        ]

    totals = {"checked": 0, "closed": 0, "failed": 0}
    for repo, installation_id in sorted(targets):
        github = github_factory.for_installation(installation_id)
        try:
            outcome = await close_superseded_drafts(catalog, buffer, repo, github)
        except Exception as exc:  # noqa: BLE001
            # One repo failing must not stop the sweep; the next run retries.
            logger.warning("Could not reconcile drafts for %s: %s", repo, exc)
            totals["failed"] += 1
            continue
        totals["checked"] += outcome.checked
        totals["closed"] += len(outcome.closed)
        totals["failed"] += len(outcome.failed)

    if totals["closed"]:
        logger.info("Superseded-draft sweep: %s", totals)
    return totals


@dataclass
class PortfolioRunResult:
    scored: list[tuple[str, int, str]] = field(default_factory=list)
    failed: list[tuple[str, str]] = field(default_factory=list)

    @property
    def worst(self) -> tuple[str, int, str] | None:
        return max(self.scored, key=lambda row: row[1]) if self.scored else None


async def score_portfolio(db: Database, service: OracleService) -> PortfolioRunResult:
    """Give every Oracle-enabled repo a fresh standing risk decision (spec 09 §5).

    The gate answers "is this change safe to merge". This answers "how risky is
    this repo right now", which is a different question and cannot be derived
    from the gate: a repo nobody has opened a pull request against for three
    months still accumulates risk as its findings age and as new advisories
    land against dependencies that have not changed.

    Only repos with `oracle` enabled are scored. A repo that has opted into
    scanning but not into being judged gets its findings shown on the dashboard
    without a verdict attached — consent to the one is not consent to the
    other, and quietly scoring everybody is how a platform loses the goodwill
    it needs to be adopted at all.

    No Check Run is posted. There is no commit under discussion, so there is
    nowhere for it to appear, and annotating an arbitrary head SHA with a score
    that is not about that commit would be actively misleading.
    """
    result = PortfolioRunResult()

    with db.session() as session:
        targets = sorted(
            row.github_repo_full_name
            for row in session.execute(
                select(RepoOnboarding).where(RepoOnboarding.status == "active")
            ).scalars()
            if "oracle" in (row.enabled_capabilities or [])
        )

    for repo in targets:
        try:
            published = await service.evaluate_and_publish(repo, decision_type="portfolio")
        except Exception as exc:  # noqa: BLE001 — see below
            # One repo with an unreadable partition must not cost every other
            # repo its daily decision. The failure is logged and surfaced in
            # the result rather than swallowed; the next run retries.
            logger.warning("Portfolio decision for %s failed: %s", repo, exc)
            result.failed.append((repo, str(exc)))
            continue

        decision = published.decision
        result.scored.append(
            (repo, decision.overall_risk_score, decision.recommendation)
        )

    worst = result.worst
    logger.info(
        "Portfolio scoring: %s scored, %s failed%s",
        len(result.scored),
        len(result.failed),
        f", worst {worst[0]} at {worst[1]}/100" if worst else "",
    )
    return result


@dataclass(frozen=True)
class OverCapAcceptance:
    """An acceptance whose window the current policy would refuse — reported,
    and left exactly as the operator wrote it (#419).

    `window_days` is the window as it was *granted*: `accepted_until` minus the
    day the acceptance was recorded, which is the same span
    `_check_acceptance_is_earned` measures on the PATCH that creates one. Not
    the days remaining, which shrink as the window runs down and would quietly
    stop reporting an over-long acceptance about halfway through it.
    """

    finding_id: str
    repo_full_name: str
    severity: str
    reason_code: str
    accepted_until: date
    window_days: int
    limit_days: int

    def line(self) -> str:
        return (
            f"{self.repo_full_name} {self.finding_id} {self.severity}/"
            f"{self.reason_code}: {self.window_days} days to "
            f"{self.accepted_until.isoformat()}, cap {self.limit_days}"
        )


@dataclass
class AcceptanceSweepResult:
    """What one pass over the accepted-risk backlog changed."""

    expired: int = 0
    reopened_by_fix: int = 0
    still_accepted: int = 0
    #: Reported only. Nothing in the sweep writes to these findings.
    over_cap: list[OverCapAcceptance] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"{self.expired} expired, {self.reopened_by_fix} re-opened because a "
            f"fix shipped, {self.still_accepted} still accepted, "
            f"{len(self.over_cap)} over the window cap (reported, not changed)"
        )


def _over_cap(
    *,
    finding_id: str,
    repo_full_name: str,
    severity: str,
    reason_code: str,
    accepted_until: date | None,
    accepted_on: date | None,
    limits: dict[str, int],
) -> OverCapAcceptance | None:
    """The one acceptance, if today's policy would refuse the window it got.

    `accepted_on` is `resolved_at`, the moment the disposition was written. A
    row without one cannot have its granted window reconstructed, so it is
    skipped rather than measured from some other date — reporting an acceptance
    as over-long on a window nobody granted would be worse than missing it.
    """
    if accepted_until is None or accepted_on is None:
        return None
    limit = limits.get(severity)
    if limit is None:
        return None
    window = (accepted_until - accepted_on).days
    if window <= limit:
        return None
    return OverCapAcceptance(
        finding_id=finding_id,
        repo_full_name=repo_full_name,
        severity=severity,
        reason_code=reason_code,
        accepted_until=accepted_until,
        window_days=window,
        limit_days=limit,
    )


def sweep_acceptances(catalog: Catalog, *, today: date | None = None) -> AcceptanceSweepResult:
    """Return acceptances to `open` when their premise runs out (spec 24 §3).

    Two triggers, and they are deliberately different in kind.

    **A date passed.** `accepted_until` is a review date somebody set, and the
    sweep enforces it. Nothing is judged here — the finding goes back on the
    queue so a person can accept it again with fresh eyes, which is the whole
    point of asking for a date instead of a permanent dismissal.

    **A fix shipped.** Only for `no_vendor_fix`, and only that code. It is the
    one premise a scan can contradict: the acceptance said no patch exists,
    and `raw_finding_json.fixed_version` now names one. Every other code rests
    on something no scanner can see — a compensating control that may have
    been removed, a cost judgement that may have changed — and re-opening
    those on machine evidence would be inventing a verdict.

    `first_seen_at` is preserved in both cases. An acceptance that ran out is
    not a new discovery, and letting it reset the clock would hand every
    ageing finding a way to look young — which is exactly what the age term,
    the due date, and mean-time-to-fix would then be measuring.

    **And one thing it reports without touching** (#419). `MAX_ACCEPTANCE_DAYS`
    is enforced by `_check_acceptance_is_earned`, which runs on the PATCH that
    *creates* an acceptance and so has never seen the population that predates
    it: 42 of 669 acceptances carry a window the policy would refuse today, all
    `high`, at 166–176 days against a 90-day cap. This walk already visits every
    one of them, so it names them — in `over_cap` and in the log.

    Named, not corrected. Re-dating, shortening or revoking one here would be
    the platform overruling the operator's judgement about their own estate,
    silently and in bulk; a machine that can quietly re-date an acceptance can
    quietly re-date a real risk. The 42 are theirs to re-date, re-justify, or
    leave with a note saying why six months was right.
    """
    from mykronos.api.dashboard import MAX_ACCEPTANCE_DAYS

    result = AcceptanceSweepResult()
    if not catalog.all_files("findings"):
        return result

    now = today or utcnow().date()

    rows = catalog.query(
        """
        SELECT finding_id,
               accepted_until,
               accepted_reason_code,
               coalesce(json_extract_string(raw_finding_json, '$.fixed_version'), ''),
               repo_full_name,
               severity,
               resolved_at
        FROM findings
        WHERE status = 'accepted_risk'
        """
    )
    if not rows:
        return result

    expired: list[str] = []
    fixed: list[str] = []
    for (
        finding_id,
        accepted_until,
        reason_code,
        fixed_version,
        repo_full_name,
        severity,
        resolved_at,
    ) in rows:
        if accepted_until is not None and accepted_until <= now:
            expired.append(str(finding_id))
        elif reason_code == "no_vendor_fix" and str(fixed_version).strip():
            fixed.append(str(finding_id))
        else:
            result.still_accepted += 1
            # Only the ones staying accepted. An acceptance this sweep is about
            # to re-open has no window left to report on.
            reported = _over_cap(
                finding_id=str(finding_id),
                repo_full_name=str(repo_full_name or ""),
                severity=str(severity or "").strip().lower(),
                reason_code=str(reason_code or ""),
                accepted_until=accepted_until,
                accepted_on=resolved_at.date() if resolved_at is not None else None,
                limits=MAX_ACCEPTANCE_DAYS,
            )
            if reported is not None:
                result.over_cap.append(reported)

    for finding_ids, bucket in ((expired, "expired"), (fixed, "fixed")):
        if not finding_ids:
            continue
        outcome = update_findings(
            catalog,
            locate_findings(catalog, finding_ids),
            # `resolved_at` back to null and the acceptance fields cleared: a
            # finding that is open again must not carry the paperwork of the
            # decision that has just lapsed, or the next sweep would expire it
            # a second time and the UI would show a review date on an open row.
            "status = 'open', resolved_at = NULL, accepted_until = NULL, "
            "accepted_reason_code = NULL",
            [],
            only_if_status="accepted_risk",
        )
        if bucket == "expired":
            result.expired += outcome.count
        else:
            result.reopened_by_fix += outcome.count

    if result.over_cap:
        # One line per acceptance, because a count is not a work list: the
        # person who has to re-date these needs to know which they are.
        logger.warning(
            "Acceptance sweep: %s acceptance(s) carry a window the current "
            "policy would refuse; none was changed:\n%s",
            len(result.over_cap),
            "\n".join(sorted(entry.line() for entry in result.over_cap)),
        )

    if result.expired or result.reopened_by_fix:
        logger.info("Acceptance sweep: %s", result.summary())
    return result


async def verify_merged_fixes(
    db: Database,
    catalog: Catalog,
    buffer: WriteAheadBuffer,
    factory: GitHubClientFactory,
    templates: Any,
    settings: Any,
) -> VerificationResult:
    """Scan the merge commit of every landed fix, then read the verdict
    (spec 25 §1, §2).

    Dispatch follows `scanned_by`, the same split `scan_now` uses and for the
    same reason: a repository is scanned by Actions or by Concourse, and the
    verification of a fix has to run wherever the scan that found it runs.

    Nothing here raises. A fix whose verification cannot be dispatched stays
    `pending` and is retried on the next pass — the deadline in
    `verification.py` is what eventually calls it `not_scanned`, so a broken
    dispatcher degrades into "we never checked" rather than into a wrong
    verdict.
    """
    onboardings: dict[str, Any] = {}
    with db.session() as session:
        for row in session.execute(select(RepoOnboarding)).scalars():
            onboardings[row.github_repo_full_name] = {
                "scanned_by": row.scanned_by,
                "installation_id": row.github_installation_id,
                "default_branch": row.default_branch,
            }

    concourse = ConcourseClient(
        settings.concourse_url,
        team=settings.concourse_team,
        external_url=settings.concourse_external_url,
    )

    async def dispatch(repo_full_name: str, capability: str) -> bool:
        onboarding = onboardings.get(repo_full_name)
        if onboarding is None:
            return False
        if onboarding["scanned_by"] == "github_actions":
            try:
                workflow_file = PurePosixPath(templates.target_path(capability)).name
            except Exception:  # noqa: BLE001 — no template is "cannot dispatch"
                return False
            try:
                github = factory.for_installation(onboarding["installation_id"])
                await github.dispatch_workflow(
                    repo_full_name, workflow_file, onboarding["default_branch"]
                )
                return True
            except Exception:  # noqa: BLE001 — see the docstring
                logger.warning(
                    "Verification dispatch failed for %s/%s",
                    repo_full_name,
                    capability,
                    exc_info=True,
                )
                return False
        if not concourse.configured or not settings.concourse_api_token:
            return False
        pipeline = pipeline_name_for(repo_full_name)
        return any(
            concourse.trigger_job(pipeline, job, token=settings.concourse_api_token)
            for job in jobs_for_capability(pipeline, capability)
        )

    result = await dispatch_pending(catalog, buffer, dispatch=dispatch)
    return resolve_pending(catalog, buffer, result=result)


async def rescan_fix_branches(
    db: Database, catalog: Catalog, factory: GitHubClientFactory
) -> BranchRescanResult:
    """Record on each open fix pull request whether its branch's scan cleared
    the finding (TheHub #60746).

    The draft's own `pull_request` scan is the rescan; this reads it and
    writes the verdict onto the pull request. Nothing here raises: a
    repository whose installation cannot be built is skipped and retried on
    the next pass, and a pull request with no scan yet waits.
    """
    clients: dict[str, Any] = {}
    with db.session() as session:
        for row in session.execute(select(RepoOnboarding)).scalars():
            try:
                clients[row.github_repo_full_name] = factory.for_installation(
                    row.github_installation_id
                )
            except Exception:  # noqa: BLE001 - see the docstring
                logger.warning(
                    "No installation client for %s; its fix branches wait",
                    row.github_repo_full_name,
                    exc_info=True,
                )
    return await rescan_open_fixes(catalog, clients)


#: How recently a GitHub Actions upload must have landed for it to count as
#: evidence that the public URL works. Six hours rather than one: the Actions
#: lanes are push- and schedule-driven, so a quiet afternoon is normal and must
#: not be read as an outage.
ACTIONS_UPLOAD_GRACE_HOURS = 6.0


def hours_since_an_actions_upload(datalake_dir: Any) -> float | None:
    """Hours since a scan run arrived that could only have come from GitHub.

    A run carrying `github_workflow_run_id` was uploaded by a GitHub-hosted
    runner, and a GitHub runner cannot reach this LAN. So such a run is
    positive evidence that the public ingestion URL was working when it
    landed, which is exactly the claim a probe from inside the network
    cannot make (hairpin NAT).

    None when the lake cannot be read or has no such run. Callers treat that
    as "no evidence either way" and keep the stronger wording: an unreadable
    lake is not permission to reassure anybody. Used by `self-check` and by
    MyKronos Health (TheHub #60905).
    """
    try:
        from mykronos.lake.catalog import Catalog

        rows = Catalog(datalake_dir).query(
            """
            SELECT max(started_at) FROM scan_runs
            WHERE github_workflow_run_id IS NOT NULL
              AND github_workflow_run_id <> ''
            """
        )
    except Exception:  # noqa: BLE001 - a health read must not fail on its own diagnostics
        return None
    if not rows or rows[0][0] is None:
        return None
    from mykronos.schemas import utcnow

    # `utcnow()` here is naive, and the lake hands back naive UTC too --
    # but not always, so drop any tzinfo rather than adding one. Adding
    # it raises "can't subtract offset-naive and offset-aware".
    latest = rows[0][0].replace(tzinfo=None)
    return float((utcnow() - latest).total_seconds()) / 3600


def reachability_alert(detail: str, hours_since_actions_upload: float | None) -> str:
    """The body of the critical notification, with the claim it can support.

    The unqualified version said "findings are being lost now" -- the most
    alarming sentence this platform sends, at `level="critical"`, asserted from
    the one vantage point that cannot establish it.

    A host inside this network reaches its own public hostname through hairpin
    NAT, which does not work here. Measured 2026-09-12:
    `mykronos.toddbenson.net/healthz` was unreachable from the backend container
    AND from the host, while GitHub Actions runs 34683969779 and 34683887120 had
    uploaded at 08:43 and 08:41 the same morning. Both carry a workflow run id,
    so both came from a GitHub-hosted runner, which cannot reach 192.168.0.14 --
    they went through the public URL.

    A `critical` alert that is wrong is how a real outage stops being believed,
    and this one fires on a schedule.

    `None` is deliberately not reassuring: nothing corroborates either way, so
    the stronger wording stands.
    """
    if (
        hours_since_actions_upload is not None
        and hours_since_actions_upload <= ACTIONS_UPLOAD_GRACE_HOURS
    ):
        return (
            detail + "\n"
            "This was checked from inside the network, where a public hostname "
            "resolves through hairpin NAT. Uploads are still arriving: a GitHub "
            f"Actions scan run landed {hours_since_actions_upload:.1f}h ago, and "
            "a GitHub runner cannot reach this LAN, so it went through this URL. "
            "Check from outside before treating this as an outage."
        )
    body = (
        detail + "\n"
        "Scan uploads from GitHub Actions and from Concourse both go through "
        "this URL, so findings are being lost now. The dashboard may still look "
        "healthy: the frontend reaches the backend over the Docker network, and "
        "the container's own healthcheck runs inside it."
    )
    if hours_since_actions_upload is not None:
        body += (
            f"\nNo GitHub Actions upload for {hours_since_actions_upload:.1f}h, "
            "which is consistent with that."
        )
    return body


async def check_public_reachability(
    ingestion_api_url: str,
    *,
    notifier: Notifier | None = None,
    timeout: float = 20.0,
    hours_since_actions_upload: float | None = None,
) -> ReachabilityResult:
    """Ask the internet whether this platform is answering (spec 32 §8).

    **It must use the public URL, and that is the entire point.** A check
    against `localhost` would have passed for every one of the 22 hours the
    ingestion API was unreachable, because the process was healthy the whole
    time — what was broken was the path to it. This request leaves the host,
    crosses the tunnel and comes back, so it exercises what a GitHub-hosted
    runner exercises.

    `/healthz` rather than `/api/ingest/health`: it is exempt from the
    perimeter gate (`gate.py`) and needs no credential, so the check works
    from anywhere and cannot fail for a reason of its own.

    **Quiet when healthy.** A channel that reports every successful minute is
    one nobody reads by the time it matters — the same rule the netassess
    judgement follows.
    """
    url = ingestion_api_url.rstrip("/") + "/healthz"
    result = ReachabilityResult(url=url)

    try:
        async with httpx2.AsyncClient(timeout=timeout) as http:
            response = await http.get(url)
        result.status_code = response.status_code
        result.reachable = response.status_code == 200
        if not result.reachable:
            result.detail = f"{url} answered HTTP {response.status_code}."
    except Exception as exc:  # noqa: BLE001 - any failure to reach is the finding
        result.detail = f"{url} could not be reached: {scrub(str(exc))}"

    if result.reachable:
        logger.info("Public reachability OK: %s", scrub(url))
        return result

    logger.error("Public reachability FAILED: %s", scrub(result.detail))
    if notifier is not None:
        # Critical, and it earns it WHEN nothing contradicts it: while this is
        # genuinely false, every scan upload from every pipeline is failing and
        # nothing else will say so. The dashboard keeps serving, which is what
        # makes it dangerous. What it must not do is say that while uploads are
        # visibly landing.
        await notifier.send(
            Notification(
                title="Mykronos is not reachable from the internet",
                detail=reachability_alert(result.detail, hours_since_actions_upload),
                repo_full_name="",
                level="critical",
            )
        )
    return result


async def check_vault(vault_url: str, *, timeout: float = 10.0) -> ReachabilityResult:
    """Is Vault up, and is it unsealed (spec 32 §8.1)?

    **Sealed is the interesting state, and it is not an outage.** Vault uses
    the file storage backend rather than dev mode, so its data survives a
    restart and it comes back *sealed* every time. Nothing can read a secret
    until somebody unseals it, and `vault-unseal.ps1` says what that costs:
    "Concourse pipelines fail to resolve ((vars)) after every reboot of this
    host until you run this."

    So a reachable-but-sealed Vault answers HTTP 503 and is a failure here,
    while a container that is merely running is not a pass. The distinction is
    the whole reason this check is not a port probe.
    """
    url = vault_url.rstrip("/") + "/v1/sys/health"
    result = ReachabilityResult(url=url)
    if not vault_url:
        result.configured = False
        result.detail = (
            "No Vault is configured for this deployment (MYKRONOS_VAULT_URL). "
            "Nothing is wrong; nothing is being checked either — a sealed "
            "Vault would not be noticed here."
        )
        return result

    try:
        async with httpx2.AsyncClient(timeout=timeout) as http:
            response = await http.get(url)
        result.status_code = response.status_code
        # 200 = initialised, unsealed, active. 503 = sealed or standby, which
        # Vault reports as unhealthy on purpose.
        body = response.json() if response.content else {}
        sealed = bool(body.get("sealed"))
        result.reachable = response.status_code == 200 and not sealed
        if sealed:
            result.detail = (
                f"{url} answered, and Vault is SEALED. Concourse cannot resolve "
                "((vars)) until it is unsealed: deploy/concourse/vault-unseal.ps1"
            )
        elif not result.reachable:
            result.detail = f"{url} answered HTTP {response.status_code}."
    except Exception as exc:  # noqa: BLE001 - any failure to reach is the finding
        result.detail = f"{url} could not be reached: {scrub(str(exc))}"
    return result


async def check_concourse(concourse_url: str, *, timeout: float = 10.0) -> ReachabilityResult:
    """Is Concourse answering (spec 32 §8.1)?

    `/api/v1/info` rather than the pipeline list: it needs no team, no
    authentication and no pipeline to exist, so it separates "Concourse is
    down" from "Concourse is up and covers nothing" — which are the two facts
    `ci.py` spends a docstring insisting are different.
    """
    url = concourse_url.rstrip("/") + "/api/v1/info"
    result = ReachabilityResult(url=url)
    if not concourse_url:
        # Not configured is not unreachable (B-014): `check_vault` already
        # says so, and MyKronos Health counts only configured dependencies.
        result.configured = False
        result.detail = "No Concourse is configured for this deployment."
        return result

    try:
        async with httpx2.AsyncClient(timeout=timeout) as http:
            response = await http.get(url)
        result.status_code = response.status_code
        result.reachable = response.status_code == 200
        if not result.reachable:
            result.detail = f"{url} answered HTTP {response.status_code}."
    except Exception as exc:  # noqa: BLE001 - any failure to reach is the finding
        result.detail = f"{url} could not be reached: {scrub(str(exc))}"
    return result


async def self_check(
    settings: Any, *, notifier: Notifier | None = None
) -> list[tuple[str, ReachabilityResult]]:
    """Everything a reboot can quietly take away (spec 32 §8.1).

    A host restart on 2026-08-28 broke three things and nothing noticed any of
    them for a day: the ingestion API lost its published port, Vault came back
    sealed, and Concourse never came back at all. Each was invisible in a
    different way — a container reporting healthy from inside itself, a
    dashboard served over the Docker network, and a CI server nothing was
    watching.

    One command, one line per dependency, so what did not come back is named
    rather than inferred.

    **Only ingestion alerts.** It is the one whose failure silently loses
    data: scans keep running and their results go nowhere. A sealed Vault and
    a stopped Concourse fail loudly at the next build, so paging for them
    would train somebody to ignore the channel that matters.
    """
    checks = [
        ("ingestion", await check_public_reachability(
            settings.ingestion_api_url, notifier=notifier
        )),
        ("vault", await check_vault(getattr(settings, "vault_url", ""))),
        ("concourse", await check_concourse(getattr(settings, "concourse_url", ""))),
    ]
    for name, result in checks:
        logger.info(
            "self-check %s: %s", name, "ok" if result.reachable else scrub(result.detail)
        )
    return checks


@dataclass
class GovernanceSweepResult:
    """What one pass over every repository's change controls found."""

    read: int = 0
    unreadable: int = 0
    drifted: int = 0
    #: The transitions themselves, worst kind first, for the caller to log.
    changes: list[str] = field(default_factory=list)
    #: Controls inside a readable repository that could not be resolved this
    #: pass, or could not be resolved last pass. Counted separately from
    #: `drifted` and never logged at `warning` (#264): a failed read is not a
    #: control coming off. Counted at all, rather than dropped, so a read that
    #: fails every six hours forever is visible somewhere.
    unreadable_controls: int = 0
    #: `repo control_key`, for the caller to name in the log.
    unreadable_reads: list[str] = field(default_factory=list)

    def summary(self) -> str:
        parts = [f"{self.read} read", f"{self.unreadable} unreadable"]
        if self.drifted:
            parts.append(
                f"{self.drifted} control(s) changed: {'; '.join(self.changes)}"
            )
        else:
            parts.append("nothing changed")
        if self.unreadable_controls:
            parts.append(
                f"could not read {self.unreadable_controls} control(s): "
                f"{'; '.join(self.unreadable_reads)}"
            )
        return ", ".join(parts)


async def sweep_governance(
    db: Database, factory: GitHubClientFactory
) -> GovernanceSweepResult:
    """Re-read every repository's change controls and record what moved.

    **Monitoring is the thing that happens when nobody is looking.** Governance
    has always been read live, so the console has never shown a stale control —
    but the read only happened when somebody opened the panel, and nothing
    compared one reading to the next. A repository could drop its review
    requirement and the only trace would be a score nobody was watching.

    This is the sweep that makes it a control rather than a dashboard. It runs
    on a timer, reads every onboarded repository, and files one row per
    transition.

    Two things it is careful not to say. A control that becomes `unknown` is a
    read that failed, not a control that was removed — a revoked permission and
    a security regression must never look the same. And a repository's first
    reading produces no drift at all: with nothing to compare against, treating
    every control as having moved from `unknown` would file nine regressions
    for a repository that has done nothing.

    Safe to run twice: a re-read that sees no change writes nothing.
    """
    from mykronos import governance as governance_module

    result = GovernanceSweepResult()

    with db.session() as session:
        repos = list(
            session.execute(
                select(RepoOnboarding).where(RepoOnboarding.status == "active")
            ).scalars()
        )

    for repo in repos:
        try:
            posture = await governance_module.read(
                factory.for_installation(repo.github_installation_id),
                repo.github_repo_full_name,
                repo.default_branch,
            )
        except (GitHubError, httpx2.HTTPError) as exc:
            # One repository failing must not end the sweep: the next one may
            # be the one that drifted.
            result.unreadable += 1
            logger.warning(
                "Governance sweep could not read %s: %s",
                scrub(repo.github_repo_full_name),
                scrub(str(exc)),
            )
            continue

        if not posture.readable:
            result.unreadable += 1
            continue

        result.read += 1
        with db.session() as session:
            report = governance_module.remember(session, posture)
            for change in report.drift:
                result.drifted += 1
                result.changes.append(
                    f"{change.repo_full_name} {change.control_key} "
                    f"{change.from_state}->{change.to_state}"
                )
            # A control the read could not resolve is counted here and nowhere
            # near `drifted`, so it can never reach the `warning` branch in
            # `main.py` (#264). `posture.readable` is about the repository; a
            # repository can be readable and one control inside it not be, and
            # that gap is what filed both of this estate's governance alerts.
            for key in report.unreadable:
                result.unreadable_controls += 1
                result.unreadable_reads.append(f"{repo.github_repo_full_name} {key}")
            session.commit()

    return result


class TimeoutAuditIncompleteError(RuntimeError):
    """The timeout audit could not read Concourse, so it has no verdict.

    Raised rather than returned so `_every` records the run as FAILED in
    `job_runs` and platform health shows `could not audit` beside the job. A
    return would record a success, and a success is what a clean estate looks
    like.
    """


def _concourse_fetch(concourse_url: str, *, timeout: float = 20.0) -> timeout_audit.Fetch:
    base = concourse_url.rstrip("/")

    def fetch(path: str) -> Any:
        response = httpx2.get(f"{base}{path}", timeout=timeout)
        response.raise_for_status()
        return response.json()

    return fetch


async def audit_pipeline_timeouts(
    concourse_url: str,
    pipeline_dir: Path,
    *,
    team: str = "main",
    notifier: Notifier | None = None,
    fetch: timeout_audit.Fetch | None = None,
) -> timeout_audit.TimeoutAuditReport:
    """Grade every committed task cap against live Concourse history (TheHub #60729).

    `test_timeout_audit.py` used to be the only automatic run of this audit,
    and it graded LIVE history from the unit tier -- so `main` went red the
    day one job had a slow run. That test is hermetic now, and this is where
    the live verdict went: a daily job, off every build lane, that cannot turn
    an unrelated lane red.

    Three outcomes, and they stay three:

    * **Caps to raise.** One notification naming each `pipeline/job`, its
      current cap and the suggested one, at `warning`. The job itself
      succeeds: the audit ran and answered.
    * **Could not audit.** Concourse, a pipeline, or a job's builds could not
      be read. `TimeoutAuditIncompleteError` is raised, after any findings from the
      readable part have been sent, so the run is recorded as failed with
      `could not audit` as its error. Not paged, for `self_check`'s reason: a
      stopped Concourse fails loudly at its next build.
    * **Clean.** Logged at info. Quiet when healthy.
    """
    report = await asyncio.to_thread(
        timeout_audit.audit,
        pipeline_dir,
        fetch or _concourse_fetch(concourse_url),
        team=team,
    )

    if report.unwaived:
        lines = [problem.line() for problem in report.unwaived]
        logger.warning("Timeout audit: caps to raise: %s", "; ".join(lines))
        if notifier is not None:
            await notifier.send(
                Notification(
                    title="Pipeline timeout caps to raise",
                    detail=(
                        "A task cap sits below, or within 30% of, what its job "
                        "has actually taken. A cap that fires kills a working "
                        "build and reads as the job's own failure (PS-7).\n"
                        + "\n".join(lines)
                        + "\nFull table: python scripts/audit_pipeline_timeouts.py"
                    ),
                    repo_full_name="",
                    level="warning",
                )
            )

    if not report.complete:
        raise TimeoutAuditIncompleteError(
            "could not audit: " + "; ".join(scrub(entry) for entry in report.unreadable)
        )

    if not report.unwaived:
        logger.info(
            "Timeout audit: clean, %s capped job(s) across %s pipeline(s)",
            report.capped_jobs,
            len(report.pipelines),
        )
    return report


class GateLivenessIncompleteError(RuntimeError):
    """The gate-liveness check could not read what it needs, so it has no verdict.

    Raised for `TimeoutAuditIncompleteError`'s reason: `_every` records the run
    as FAILED and platform health shows `could not check`. A return would
    record a success, and a success is what a live gate looks like.
    """


async def check_gate_liveness(
    concourse_url: str,
    lookup: gate_liveness.Lookup,
    *,
    threshold_hours: float,
    team: str = "main",
    notifier: Notifier | None = None,
    fetch: gate_liveness.Fetch | None = None,
    now: datetime | None = None,
    already_sent: str | None = None,
) -> gate_liveness.GateLivenessReport:
    """Say when main's commits stop reaching a gate decision (TheHub #60731).

    Three outcomes:

    * **Stale.** The oldest commit after the last decided one has waited more
      than `threshold_hours`. One `warning` notification names it, the newest
      judged commit, and every job upstream of `oracle-gate` whose latest build
      failed, errored or is paused, or says that none is. The job succeeds,
      because it ran and answered. It does not re-post a signature equal to
      `already_sent`. Hourly repeats of the same news are how a channel stops
      being read.
    * **Could not check.** Concourse or the decision store could not be read.
      `GateLivenessIncompleteError` is raised, after any stale notification has
      been sent, so the run is recorded as failed. It is never reported as live.
    * **Live.** Logged at info.
    """
    report = await asyncio.to_thread(
        gate_liveness.check,
        fetch or _concourse_fetch(concourse_url),
        lookup,
        threshold_hours=threshold_hours,
        now=now or datetime.now(UTC),
        team=team,
    )

    if report.stale:
        lines = report.lines()
        logger.warning("Gate liveness: stale: %s", " ".join(lines))
        if notifier is not None and report.signature != already_sent:
            await notifier.send(
                Notification(
                    title="MyKronos commits are not reaching the risk gate",
                    detail="\n".join(lines),
                    repo_full_name="",
                    level="warning",
                )
            )

    if not report.complete:
        raise GateLivenessIncompleteError(
            "could not check: " + "; ".join(scrub(entry) for entry in report.unreadable)
        )

    if not report.stale:
        logger.info(
            "Gate liveness: live, newest judged %s, %s commit(s) waiting",
            (report.last_judged or "none")[:12],
            len(report.unjudged),
        )
    return report


#: The scheduled job's name, and the `job_runs` row its once-a-day rule reads.
DORMANT_LANES_JOB = "dormant-lanes"


class DormantLanesIncompleteError(RuntimeError):
    """The dormant-lanes read could not finish, and nothing was posted.

    Raised for `TimeoutAuditIncompleteError`'s reason: `_every` records the
    run as FAILED, platform health shows `could not check`, and because
    `last_succeeded_at` did not move, the next hourly run tries again the
    same day.
    """


def _succeeded_today(db: Database | None, name: str, now: datetime) -> bool:
    if db is None:
        return False
    with db.session() as session:
        row = session.get(JobRun, name)
        last = row.last_succeeded_at if row is not None else None
    if last is None:
        return False
    # Stored naive UTC by `_record_run` (`utcnow()`).
    last_utc = last.replace(tzinfo=UTC) if last.tzinfo is None else last.astimezone(UTC)
    return last_utc.date() == now.astimezone(UTC).date()


async def notify_dormant_lanes(
    source: dormant_lanes.LaneSource,
    *,
    db: Database | None,
    notifier: Notifier | None,
    threshold_hours: float,
    now: datetime | None = None,
    job_name: str = DORMANT_LANES_JOB,
) -> dormant_lanes.DormantLanesReport | None:
    """Post, once per UTC day, every Concourse job off or red for days.

    **Once a day, not once a run.** The job is scheduled hourly, and every
    restart runs it again within ninety seconds (`_every`). So the day is
    decided by this job's own `job_runs` row. If it already succeeded today,
    the run returns None and posts nothing. A success means the read finished
    and the notice, if there was one, was delivered. A day therefore produces
    one post, and a restart does not produce a second.

    Outcomes:

    * **Something dormant.** One `warning` notification, one line per lane,
      oldest first, with any unreadable pipeline named at the end. If it was
      not delivered, the run raises, so the day stays open and the next hour
      tries again. A notifier with no transport is a supported state
      (`digest.send_all`): logged, and the run succeeds.
    * **Nothing dormant, everything read.** Logged at info, and nothing is
      posted. Quiet when healthy.
    * **Nothing dormant, something unreadable.** `DormantLanesIncompleteError`,
      so the run reads `could not check` and is retried. A partial read that
      did find something is posted with the gap named, rather than retried
      into an hourly repeat.
    """
    moment = now or datetime.now(UTC)
    if _succeeded_today(db, job_name, moment):
        logger.info("Dormant lanes: today's notice has already gone out; skipping")
        return None

    report = await asyncio.to_thread(
        dormant_lanes.find, source, now=moment, threshold_hours=threshold_hours
    )

    if report.lanes:
        lines = report.lines(moment)
        logger.warning("Dormant lanes: %s", " | ".join(lines))
        if notifier is not None and notifier.enabled:
            delivered = await notifier.send(
                Notification(
                    title=(
                        f"{len(report.lanes)} Concourse lane(s) paused or red "
                        f"for more than {threshold_hours:g}h"
                    ),
                    detail=(
                        "A paused or broken lane says nothing by itself. Each of "
                        "these has been off or red for days:\n"
                        + "\n".join(lines)
                        + "\nOnce a day. `mykronos briefing` has the detail."
                    ),
                    repo_full_name="",
                    level="warning",
                )
            )
            if not delivered:
                raise DormantLanesIncompleteError(
                    f"{len(report.lanes)} dormant lane(s) found and the notice was not delivered"
                )
        return report

    if not report.complete:
        raise DormantLanesIncompleteError(
            "could not check: " + "; ".join(scrub(entry) for entry in report.unreadable)
        )

    logger.info(
        "Dormant lanes: none across %s pipeline(s)", len(report.pipelines_read)
    )
    return report


#: The scheduled job's name (TheHub #60973).
RED_MAIN_JOB = "red-main"


class RedMainIncompleteError(RuntimeError):
    """A configured pipeline or lane could not be read, so this poll has no
    verdict for it. Raised for `TimeoutAuditIncompleteError`'s reason, after
    every readable lane has been handled, so `job_runs` reads `could not
    check` and not clean."""


def load_lane_states(db: Database) -> dict[tuple[str, str], red_main.LaneState]:
    """Every recorded gating-lane state, keyed on `(repo_full_name, job)`."""
    with db.session() as session:
        rows = session.execute(select(GatingLaneState)).scalars().all()
        return {
            (row.repo_full_name, row.job): red_main.LaneState(
                repo_full_name=row.repo_full_name,
                pipeline=row.pipeline,
                job=row.job,
                state=row.state,
                status=row.status,
                build=row.build,
                red_since=row.red_since.replace(tzinfo=UTC) if row.red_since else None,
                first_bad_build=row.first_bad_build,
                first_bad_sha=row.first_bad_sha,
                last_green_sha=row.last_green_sha,
                slack_channel=row.slack_channel,
                slack_ts=row.slack_ts,
            )
            for row in rows
        }


def save_lane_state(db: Database, state: red_main.LaneState) -> None:
    with db.session() as session:
        row = session.get(GatingLaneState, (state.repo_full_name, state.job))
        if row is None:
            row = GatingLaneState(repo_full_name=state.repo_full_name, job=state.job)
            session.add(row)
        row.pipeline = state.pipeline
        row.state = state.state
        row.status = state.status
        row.build = state.build
        row.red_since = (
            state.red_since.astimezone(UTC).replace(tzinfo=None) if state.red_since else None
        )
        row.first_bad_build = state.first_bad_build
        row.first_bad_sha = state.first_bad_sha
        row.last_green_sha = state.last_green_sha
        row.slack_channel = state.slack_channel
        row.slack_ts = state.slack_ts
        row.updated_at = utcnow()


def junit_totals_lookup(catalog: Catalog | None) -> red_main.TestLookup:
    """The newest JUnit run one lane uploaded for one commit, as suite totals.

    Matched on the run's recorded `job`, so another lane's report for the
    same commit is never attributed to this one; a run uploaded with no job
    name is not matched. Reads the compacted lake only: a report still in the
    write-ahead buffer reads as not uploaded until the next compaction.
    """

    def lookup(repo_full_name: str, commit_sha: str, lane: str) -> red_main.TestTotals | None:
        if catalog is None or not commit_sha or not catalog.all_files("scan_runs"):
            return None
        rows = catalog.query(
            """
            SELECT scan_status, detail FROM scan_runs
            WHERE repo_full_name = ? AND tool_name = 'junit' AND job = ?
              AND commit_sha IS NOT NULL AND commit_sha <> ''
              AND (starts_with(commit_sha, ?) OR starts_with(?, commit_sha))
            ORDER BY coalesce(completed_at, started_at) DESC
            LIMIT 1
            """,
            [repo_full_name, lane, commit_sha, commit_sha],
        )
        if not rows:
            return None
        status, detail = rows[0]
        return red_main.totals_from_run(
            str(status) if status is not None else None,
            str(detail) if detail is not None else None,
        )

    return lookup


async def announce_red_main(
    concourse_url: str,
    *,
    db: Database,
    gating: dict[str, list[str]],
    tests: red_main.TestLookup,
    team: str = "main",
    link_base: str = "",
    notifier: Notifier | None = None,
    fetch: red_main.Fetch | None = None,
    now: datetime | None = None,
    branches: dict[str, str] | None = None,
) -> red_main.RedMainReport:
    """Announce a gating lane that went red on main, or recovered, once (TheHub #60973).

    Since TheHub #61194 this is the one sender for every lane of every
    configured pipeline (`red_main.ALL_LANES`), and the pipelines' own hooks
    no longer post. A red message's Slack thread is recorded with the red
    state, and its recovery replies in that thread, through the notifier's
    `post_message` when it has one; a notifier with only `send` posts top-level.

    The recorded state in `gating_lane_states` is the de-duplication key. A
    lane's new state is saved only after its message is delivered, so a
    message Slack refused is retried on the next poll rather than lost. With
    no Slack transport configured the state is saved anyway: there is nothing
    to retry, and the CI page still needs `red_since`.

    An unreadable pipeline or a configured lane Concourse does not have raises
    `RedMainIncompleteError` after everything readable has been handled.
    """
    prior = await asyncio.to_thread(load_lane_states, db)
    report = await asyncio.to_thread(
        red_main.evaluate,
        fetch or _concourse_fetch(concourse_url),
        gating=gating,
        prior=prior,
        tests=tests,
        now=now or datetime.now(UTC),
        team=team,
        link_base=link_base,
        branches=branches,
    )
    pending = {(m.repo_full_name, m.job): m for m in report.messages}
    for state in report.states:
        message = pending.get((state.repo_full_name, state.job))
        if message is not None:
            logger.warning("Red main: %s", " ".join(message.lines))
            if notifier is not None and notifier.enabled:
                note = Notification(
                    title=message.title,
                    detail="",
                    repo_full_name="",
                    level="warning" if message.kind == "red" else "info",
                    lines=message.lines,
                )
                post = getattr(notifier, "post_message", None)
                if post is not None:
                    delivery: Delivery = await post(note, thread_ts=message.thread_ts)
                else:
                    delivery = Delivery(await notifier.send(note))
                delivered = delivery.delivered
                if delivered and message.kind == "red":
                    # The thread every later message about this red replies in.
                    state = replace(
                        state,
                        slack_channel=delivery.channel or None,
                        slack_ts=delivery.ts or None,
                    )
                if not delivered:
                    # Not saved: the next poll sees the same transition.
                    report.unreadable.append(
                        f"{state.repo_full_name} {state.job}: the {message.kind} "
                        "message was not delivered"
                    )
                    continue
        if prior.get((state.repo_full_name, state.job)) != state:
            await asyncio.to_thread(save_lane_state, db, state)

    if not report.complete:
        raise RedMainIncompleteError(
            "could not check: " + "; ".join(scrub(entry) for entry in report.unreadable)
        )
    return report


class JobNotDue(Exception):  # noqa: N818 - an outcome, not an error
    """Raised by a job that ticks often and acts rarely: nothing is owed yet.

    `main._every` records nothing for it. A tick that only asked "is it time?"
    is not a run, and recording it as a success would make the row's
    `last_succeeded_at` a heartbeat - fresh every five minutes whether or not
    the thing the job exists to do has happened (TheHub #60864).
    """


class JobSkipped(Exception):  # noqa: N818 - an outcome, not an error
    """Raised by a job that was due and could not act, with the reason.

    `main._every` records it as `skipped` with that reason: not a failure,
    since nothing broke, and never a success, since nothing was done. The
    briefing DM raises it when Slack is not configured for it.
    """


#: The scheduled job's name and its `job_runs` row (TheHub #60975).
CI_STALL_JOB = "ci-stall"


class CiStallIncompleteError(RuntimeError):
    """The stall check could not finish, or found a stall and could not
    deliver the notice. `_every` records the run as failed, and because the
    episode is not marked notified, the next tick tries again."""


async def notify_ci_stall(
    client: ConcourseClient,
    *,
    db: Database,
    notifier: Notifier | None,
    now: datetime | None = None,
) -> ci_stall.CiStall:
    """Say "Concourse is stalled" once per stall (TheHub #60975).

    Reads the anonymous job summaries, assesses them (`ci_stall.assess`),
    and records the evaluation as part of an episode. A red evaluation whose
    episode has not been announced sends one notice; every later red of the
    same episode sends nothing, and a green closes the episode.

    Fails closed (TheHub #59331). The episode is marked notified only when
    the notifier reports delivery. No Slack transport raises `JobSkipped`
    with the reason; a refused post raises `CiStallIncompleteError`. Neither
    looks like a delivered alert, and both are retried next tick.
    """
    moment = now or datetime.now(UTC)
    payload = await asyncio.to_thread(client.all_jobs)
    if payload is None:
        raise CiStallIncompleteError("could not check: the Concourse job list is unreadable")

    stall = ci_stall.assess(payload, link=client.build_url)
    episode = ci_stall.observe(db, stall, now=moment)
    if not stall.red or episode is None:
        logger.info("CI stall: %s", stall.detail)
        return stall

    logger.warning("CI stall: %s", stall.detail)
    if episode.notified_at is not None:
        return stall
    if notifier is None or not notifier.enabled:
        raise JobSkipped(
            "Concourse is stalled and no Slack transport is configured, so "
            "nobody has been told; MyKronos Health shows it"
        )
    delivered = await notifier.send(
        Notification(
            title="Concourse is stalled",
            detail=stall.detail,
            repo_full_name="",
            level="critical",
            lines=tuple(ci_stall.notice_lines(stall)),
        )
    )
    if not delivered:
        raise CiStallIncompleteError("Concourse is stalled and the notice was not delivered")
    ci_stall.mark_notified(db, episode.id, now=moment)
    return stall


#: The briefing DM's job name (`mykronos.briefing_dm`), here so the table
#: below needs no import of that module.
BRIEFING_DM_JOB = "briefing-dm"

#: The same-day flash DM (`mykronos.briefing_flash`, TheHub #60865).
BRIEFING_FLASH_JOB = "briefing-flash"

#: Next-sprint candidates filed to TheHub's backlog (`mykronos.sprint_signal`,
#: TheHub #60862). Ticks hourly, acts once a UTC day.
SIGNAL_FILING_JOB = "briefing-signal-filing"

#: An incident a day before a credential lapses unrenewed
#: (`mykronos.credential_expiry_incidents`, TheHub #61104). Ticks hourly.
CREDENTIAL_EXPIRY_INCIDENTS_JOB = "credential-expiry-incidents"

#: The interval `job_runs` records for a job whose scheduler tick is shorter
#: than its real cadence. The briefing DM ticks every five minutes and is owed
#: once a day; platform health judges `late` against what is recorded here,
#: so recording the tick would call every evening "late".
RECORDED_INTERVAL_SECONDS: dict[str, int] = {
    BRIEFING_DM_JOB: 86_400,
    SIGNAL_FILING_JOB: 86_400,
}


# -- The Dependabot autopilot (TheHub #61615) -----------------------------------
#
# Dependency bumps waited for the same human train as features. Operator
# decision 2026-11-13: an open Dependabot pull request in a minor/patch group,
# green on its current head, is requested for approval without anyone asking,
# and once the platform reviewer approves it the App merges exactly that head.
# The safety rules are unchanged: green on the current head, approval by
# someone other than the author (the tier's own independence rules decide who),
# and batches. `dependabot_autopilot_mode` starts at `dry-run`, which lists
# what the job would do on the work queue and asks for nothing.

DEPENDABOT_AUTOPILOT_JOB = "dependabot-autopilot"

AUTOPILOT_MODES = ("off", "dry-run", "live")

AUTOPILOT_REQUESTER = Principal(
    actor=f"job:{DEPENDABOT_AUTOPILOT_JOB}", role=Role.VIEWER, kind=ActorKind.AUTOMATION
)

#: The allowlist's own check (`mykronos.library_check.CHECK_NAME`). Required
#: green on top of the branch's required checks: `neutral`, which it reports
#: for a library it only reports on, is not green here.
LIBRARY_ALLOWLIST_CHECK = "library-allowlist"

#: The estate's batch limit (operator decision 2026-11-03): at most this many
#: merges per run, and the rest wait one interval.
AUTOPILOT_MAX_MERGES = 5


@dataclass(frozen=True)
class AutopilotGroup:
    """A `.github/dependabot.yml` group the autopilot works, and the files a
    pull request from it may change. Anything else is a change outside the
    group and is skipped."""

    name: str
    directory: str
    #: Full-match patterns for a file's name inside `directory`.
    files: tuple[str, ...]

    def owns(self, path: str) -> bool:
        directory, _, name = path.rpartition("/")
        return directory == self.directory and any(re.fullmatch(p, name) for p in self.files)


#: The minor/patch groups in `.github/dependabot.yml`. `actions-minor-patch`
#: is deliberately absent: an action bump is a 40-character SHA a reviewer
#: cannot judge, and its files are workflow files (governance tier).
AUTOPILOT_GROUPS: tuple[AutopilotGroup, ...] = (
    AutopilotGroup(
        "pip-minor-patch",
        "backend",
        (r"pyproject\.toml", r"requirements(-[A-Za-z0-9_-]+)?\.txt", r"uv\.lock"),
    ),
    AutopilotGroup("npm-minor-patch", "frontend", (r"package\.json", r"package-lock\.json")),
)

#: Outcomes, in the words the work queue shows.
WOULD_REQUEST = "would_request"
REQUESTED = "requested"
ALREADY_REQUESTED = "already_requested"
AWAITING_APPROVAL = "awaiting_approval"
WOULD_MERGE = "would_merge"
MERGED = "merged"
MERGE_FAILED = "merge_failed"
SKIPPED = "skipped"


@dataclass
class AutopilotItem:
    repo_full_name: str
    number: int
    head_sha: str
    title: str
    outcome: str
    reason: str
    group: str = ""
    request_id: str = ""


@dataclass
class AutopilotRun:
    mode: str
    ran_at: datetime
    items: list[AutopilotItem] = field(default_factory=list)
    #: (repo, why) for a repository whose pull requests could not be read.
    unreadable: list[tuple[str, str]] = field(default_factory=list)

    def summary(self) -> str:
        counts: dict[str, int] = {}
        for item in self.items:
            counts[item.outcome] = counts.get(item.outcome, 0) + 1
        shown = ", ".join(f"{k} {v}" for k, v in sorted(counts.items())) or "nothing open"
        return f"{self.mode}: {shown}; unreadable {len(self.unreadable)}"


#: The last run, for the work queue. In memory on purpose, like
#: `pull_requests._first_seen`: the job runs within ninety seconds of a start,
#: and until then the queue says it has not run rather than showing nothing.
LAST_AUTOPILOT_RUN: AutopilotRun | None = None


def autopilot_group(title: str, branch: str) -> AutopilotGroup | None:
    """The group a Dependabot pull request belongs to, from its title
    ("Bump the pip-minor-patch group in /backend ...") or its branch
    (`dependabot/pip/backend/pip-minor-patch-<hash>`)."""
    lowered = title.lower()
    for group in AUTOPILOT_GROUPS:
        if f"the {group.name} group" in lowered or f"/{group.name}-" in branch:
            return group
    return None


_TABLE_ROW = re.compile(
    r"^\|\s*\[?([^\]|]+?)\]?(?:\([^)]*\))?\s*\|\s*`([^`]+)`\s*\|\s*`([^`]+)`\s*\|"
)
_UPDATES = re.compile(
    r"(?:Updates|Bumps) \[?`?([^`\]\s]+)`?\]?(?:\([^)]*\))? from (\S+) to (\S+?)\.?(?:\s|$)"
)


def version_changes(body: str) -> list[tuple[str, str, str]]:
    """(package, from, to) for every bump the description lists."""
    seen: dict[str, tuple[str, str, str]] = {}
    for line in body.splitlines():
        line = line.strip()
        match = _TABLE_ROW.match(line) or _UPDATES.search(line)
        if match:
            name, old, new = (g.strip() for g in match.groups())
            if name.lower() in {"package", "---"} or old.startswith("-"):
                continue
            seen.setdefault(name, (name, old, new))
    return list(seen.values())


def _numbers(version: str) -> list[int] | None:
    parts = re.findall(r"\d+", version.lstrip("^~=v<>"))
    return [int(p) for p in parts[:2]] if parts else None


def is_major(old: str, new: str) -> bool:
    """A major bump, counting a `0.x` minor as one: under semver a 0.y bump
    may break (fastapi's 0.156 -> 0.162 carried "Breaking Changes"). A version
    that cannot be read is treated as major."""
    a, b = _numbers(old), _numbers(new)
    if not a or not b:
        return True
    if a[0] != b[0]:
        return True
    return a[0] == 0 and (a[1:2] or [0]) != (b[1:2] or [0])


#: An advisory's own identifier. Matched anywhere, URLs included: in
#: Dependabot's quoted release notes the GHSA ids are only in the links
#: (`.../security/advisories/GHSA-mfr8-8qww-v76h`), and no badge or docs URL
#: carries one.
_ADVISORY_ID = re.compile(r"\bGHSA(?:-[0-9a-z]{4}){3}\b|\bCVE-\d{4}-\d{4,}\b", re.I)
#: Words that say "advisory", matched only with every URL removed: the
#: compatibility badge in every Dependabot body links to
#: `.../managing-security-vulnerabilities/...`, which is not an advisory.
_ADVISORY_WORDS = re.compile(
    r"\bsecurity (?:fix(?:es)?|advisor(?:y|ies)|update|release)\b", re.I
)
_SEVERITIES = "critical|high|moderate|medium|low"
#: How a severity is written. Dependabot quotes the upstream release notes, and
#: next.js's put each severity in its own heading above its advisories:
#: `<p>This release contains security fixes ...</p><h2>Moderate</h2><ul>...`.
_SEVERITY = re.compile(
    rf"<h[1-6]>\s*({_SEVERITIES})\s*</h[1-6]>"
    rf"|^\s*#{{1,6}}\s*({_SEVERITIES})\s*$"
    rf"|\b({_SEVERITIES})[ -]severity\b"
    rf"|\bseverity\W{{0,3}}({_SEVERITIES})\b",
    re.I | re.M,
)
_URL = re.compile(r"""href=(["'])[^"']*\1|\]\([^)]*\)|https?://[^\s)"'<>]+""", re.I)


def advisory_reason(title: str, body: str, labels: tuple[str, ...]) -> str | None:
    """Why a security-advisory bump is skipped, or None when it may go.

    Above moderate is skipped; so is an advisory whose severity the
    description does not state, which is not assumed to be low. Words are
    read with the URLs taken out, so a link's path never makes a bump an
    advisory; advisory ids count wherever they are."""
    raw = f"{title}\n{body}"
    text = _URL.sub(" ", raw)
    if not (
        _ADVISORY_ID.search(raw)
        or _ADVISORY_WORDS.search(text)
        or any("security" in label.lower() for label in labels)
    ):
        return None
    severities = {next(g for g in m if g).lower() for m in _SEVERITY.findall(text)}
    above = severities & {"critical", "high"}
    if above:
        return (
            f"a security advisory above moderate ({', '.join(sorted(above))}); "
            "a person decides it"
        )
    if not severities:
        return (
            "a security advisory whose severity the description does not state; "
            "not assumed moderate"
        )
    return None


def autopilot_required_checks(protection: dict[str, Any]) -> set[str]:
    """The branch's required checks, without `independent-review` (the
    approval this job asks for), plus `library-allowlist`."""
    checks = protection.get("required_status_checks") or {}
    names = {str(c.get("context")) for c in checks.get("checks") or [] if c.get("context")}
    names |= {str(c) for c in checks.get("contexts") or []}
    names.discard(approval_pull_requests.CHECK_NAME)
    names.add(LIBRARY_ALLOWLIST_CHECK)
    return names


def checks_reason(by_name: dict[str, str], required: set[str]) -> str | None:
    """Why the head is not green, or None when every required check is."""
    def green(name: str) -> set[str]:
        # GitHub's protection passes neutral and skipped; the allowlist does not.
        return {"success"} if name == LIBRARY_ALLOWLIST_CHECK else {"success", "neutral", "skipped"}

    pending = sorted(n for n in required if by_name.get(n, "pending") == "pending")
    red = sorted(
        n
        for n in required
        if by_name.get(n, "pending") != "pending" and by_name[n] not in green(n)
    )
    if red:
        return "red on the current head: " + ", ".join(f"{n} ({by_name[n]})" for n in red)
    if pending:
        return "pending or not reported on the current head: " + ", ".join(pending)
    return None


def _requests_by_pull_request(db: Database) -> dict[tuple[str, int], list[tuple[str, str, str]]]:
    """(repo, number) -> [(head sha, state, request id)] for every live request."""
    out: dict[tuple[str, int], list[tuple[str, str, str]]] = {}
    with db.session() as session:
        for row in session.execute(
            select(ApprovalRequest).where(
                ApprovalRequest.duty == approval_pull_requests.DUTY,
                ApprovalRequest.state.in_(("pending", "approved", "rejected")),
            )
        ).scalars():
            ref = str(row.subject_ref)
            head, _, sha = ref.partition("@")
            repo, _, number = head.rpartition("#")
            if repo and number.isdigit() and sha:
                out.setdefault((repo, int(number)), []).append((sha, str(row.state), str(row.id)))
    return out


async def dependabot_autopilot(
    db: Database,
    policy: Any,
    github_factory: GitHubClientFactory,
    *,
    mode: str,
    merger_for: Callable[[GitHubClient], dependabot_merge.Merger] = dependabot_merge.merger_for,
    now: datetime | None = None,
) -> AutopilotRun:
    """Walk open Dependabot pull requests; list, request and merge (TheHub #61615).

    For each open pull request by `dependabot[bot]` on an onboarded repository:
    it must be in a minor/patch group, change only that group's manifests and
    lockfiles, carry no major bump and no advisory above moderate, and have
    every required check plus `library-allowlist` green on its current head.
    Then, in `live` mode only, its head is requested for `pull_request_merge`
    approval through `approvals.pull_requests.propose` (the code path of
    POST /api/approvals/pull-requests; an existing request is "already
    requested"), and an approved head is squash-merged by the App at exactly
    that sha. `dry-run` lists what it would do and changes nothing; `off`
    returns an empty run. Every pull request it looks at is in the run with
    its outcome and reason, which the work queue shows.
    """
    global LAST_AUTOPILOT_RUN
    if mode not in AUTOPILOT_MODES:
        raise ValueError(
            f"dependabot_autopilot_mode must be one of {AUTOPILOT_MODES}, not {mode!r}"
        )
    run = AutopilotRun(mode=mode, ran_at=now or utcnow())
    if mode == "off":
        LAST_AUTOPILOT_RUN = run
        return run
    with db.session() as session:
        repos = [
            (r.github_repo_full_name, r.github_installation_id)
            for r in session.execute(
                select(RepoOnboarding).where(RepoOnboarding.status != "removed")
            ).scalars()
        ]
    requests = _requests_by_pull_request(db)
    merges = 0
    for repo, installation in repos:
        if not installation:
            continue
        github = github_factory.for_installation(installation)
        try:
            branch = str((await github.get_repo(repo)).get("default_branch") or "main")
            protection = await github.get_branch_protection(repo, branch)
            pulls = await github.list_open_pull_requests(repo)
        except Exception as exc:  # noqa: BLE001 - one repository never stops the rest
            run.unreadable.append((repo, scrub(str(exc), max_length=300) or type(exc).__name__))
            continue
        for pr in pulls:
            if pr.author != dependabot_merge.DEPENDABOT_LOGIN or not pr.head_sha:
                continue
            item = AutopilotItem(repo, pr.number, pr.head_sha, pr.title, SKIPPED, "")
            run.items.append(item)
            try:
                merges += await _autopilot_one(
                    db, policy, github, item, pr, branch, protection,
                    requests.get((repo, pr.number), []),
                    mode=mode, merger_for=merger_for, merges_left=AUTOPILOT_MAX_MERGES - merges,
                )
            except Exception as exc:  # noqa: BLE001 - one pull request never stops the rest
                item.outcome, item.reason = SKIPPED, (
                    f"could not be read: {scrub(str(exc), max_length=300) or type(exc).__name__}"
                )
    LAST_AUTOPILOT_RUN = run
    return run


async def _autopilot_one(
    db: Database,
    policy: Any,
    github: GitHubClient,
    item: AutopilotItem,
    pr: Any,
    default_branch: str,
    protection: dict[str, Any] | None,
    requests: list[tuple[str, str, str]],
    *,
    mode: str,
    merger_for: Callable[[GitHubClient], dependabot_merge.Merger],
    merges_left: int,
) -> int:
    """Decide one pull request into `item`. Returns 1 when it merged it."""
    here = [r for r in requests if r[0] == pr.head_sha]
    older = [r for r in requests if r[0] != pr.head_sha and r[1] in ("pending", "approved")]
    # An approval is of one commit. A request on an earlier head is never
    # merged and never carried over: the new head is judged from scratch, and
    # every reason says the head moved so nobody reads the old approval as live.
    moved = (
        f"head moved since request {older[-1][2]} ({older[-1][1]}) on {older[-1][0][:12]}; "
        if older
        else ""
    )

    def skip(reason: str) -> int:
        item.outcome, item.reason = SKIPPED, moved + reason
        return 0

    if pr.draft:
        return skip("a draft")
    if (pr.base_branch or default_branch) != default_branch:
        return skip(f"targets {pr.base_branch}, not {default_branch}")
    group = autopilot_group(pr.title, pr.head_branch)
    if group is None:
        return skip(
            "a lockfile or single-dependency change outside the minor/patch groups "
            f"({', '.join(g.name for g in AUTOPILOT_GROUPS)}); a person decides it"
        )
    item.group = group.name
    advisory = advisory_reason(pr.title, pr.body, pr.labels)
    if advisory:
        return skip(advisory)
    changes = version_changes(pr.body)
    if not changes:
        return skip("no version change could be read from the description")
    majors = [f"{n} {a} -> {b}" for n, a, b in changes if is_major(a, b)]
    if majors:
        return skip("a major (0.x minor counts as major): " + ", ".join(majors[:5]))
    comparison = await github.compare(item.repo_full_name, default_branch, pr.head_sha)
    if comparison.truncated:
        return skip("the change lists too many files to read")
    outside = sorted(f.filename for f in comparison.files if not group.owns(f.filename))
    if outside or not comparison.files:
        return skip(
            f"changes files outside the {group.name} group: " + ", ".join(outside[:5])
            if outside
            else "GitHub listed no changed files"
        )
    if protection is None:
        return skip(f"{default_branch} is unprotected, so no required checks gate a merge")
    summary = await github.get_checks_summary(item.repo_full_name, pr.head_sha)
    not_green = checks_reason(summary.by_name, autopilot_required_checks(protection))
    if not_green:
        return skip(not_green)

    rejected =[r for r in here if r[1] == "rejected"]
    approved = [r for r in here if r[1] == "approved"]
    pending = [r for r in here if r[1] == "pending"]
    if approved:
        request_id = approved[-1][2]
        item.request_id = request_id
        review = summary.by_name.get(approval_pull_requests.CHECK_NAME, "pending")
        if review != "success":
            item.outcome, item.reason = AWAITING_APPROVAL, (
                f"approved as {request_id}; {approval_pull_requests.CHECK_NAME} is {review} "
                "on the head, waiting for the stamp"
            )
            return 0
        if mode != "live":
            item.outcome, item.reason = WOULD_MERGE, (
                f"approved as {request_id}; would squash-merge at {pr.head_sha[:12]}"
            )
            return 0
        if merges_left <= 0:
            item.outcome, item.reason = WOULD_MERGE, (
                f"approved as {request_id}; the batch of {AUTOPILOT_MAX_MERGES} is full, next run"
            )
            return 0
        message = (
            f"Merged by the Dependabot autopilot (TheHub #61615) at {pr.head_sha}.\n\n"
            f"Approval-Request: {request_id}"
        )
        try:
            merger = merger_for(github)
            result = await merger.squash_at_head(
                item.repo_full_name, item.number, head_sha=pr.head_sha, message=message
            )
        except (dependabot_merge.MergeRefusedError, GitHubError) as exc:
            item.outcome, item.reason = MERGE_FAILED, scrub(str(exc), max_length=400)
            _audit_autopilot(db, "dependabot_autopilot.merge_failed", item)
            return 0
        item.outcome, item.reason = MERGED, (
            f"squash-merged at {pr.head_sha[:12]} as {result.merge_commit_sha[:12]} "
            f"under approval {request_id}"
        )
        _audit_autopilot(
            db, "dependabot_autopilot.merged", item, merge_commit=result.merge_commit_sha
        )
        return 1
    if pending:
        item.request_id = pending[-1][2]
        item.outcome, item.reason = AWAITING_APPROVAL, f"requested as {item.request_id}"
        return 0
    if rejected:
        item.request_id = rejected[-1][2]
        return skip(f"rejected as {item.request_id}; a new head needs a new request")
    if mode != "live":
        item.outcome, item.reason = WOULD_REQUEST, (
            moved + f"green; would request {approval_pull_requests.DUTY} approval"
        )
        return 0
    try:
        request = await approval_pull_requests.propose(
            db,
            policy,
            github,
            requested_by=AUTOPILOT_REQUESTER,
            repo=item.repo_full_name,
            number=item.number,
            statement=(
                f"Opened by the Dependabot autopilot (TheHub #61615): a {group.name} bump by "
                f"{dependabot_merge.DEPENDABOT_LOGIN}, no major and no advisory above "
                "moderate, every required check and library-allowlist green on this head."
            ),
        )
    except ApprovalError as exc:
        if "already has approval request" in str(exc):
            item.outcome, item.reason = ALREADY_REQUESTED, str(exc)
            return 0
        return skip(f"the request was refused: {exc}")
    item.request_id = str(request.id)
    item.outcome, item.reason = REQUESTED, moved + f"requested as {request.id}"
    _audit_autopilot(db, "dependabot_autopilot.requested", item)
    return 0


def _audit_autopilot(db: Database, action: str, item: AutopilotItem, **detail: Any) -> None:
    with db.session() as session:
        db.audit(
            session,
            actor=AUTOPILOT_REQUESTER.actor,
            action=action,
            entity_type="approval_request",
            entity_id=item.request_id,
            target=approval_pull_requests.subject_ref(
                item.repo_full_name, item.number, item.head_sha
            ),
            reason=item.reason,
            **detail,
        )
