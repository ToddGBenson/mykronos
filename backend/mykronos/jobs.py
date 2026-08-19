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

import logging
from dataclasses import dataclass, field
from datetime import timedelta

from sqlalchemy import select

from mykronos.auth import TokenRegistry
from mykronos.db import Database
from mykronos.db.models import RepoOnboarding, capability_config_for
from mykronos.github.client import GitHubError
from mykronos.github.factory import GitHubClientFactory
from mykronos.github.secrets import seal_secret
from mykronos.installer import DEFAULT_SECRET_NAME
from mykronos.knowledge import KnowledgeStore
from mykronos.knowledge import PurgeResult as KnowledgePurgeResult
from mykronos.lake.buffer import WriteAheadBuffer
from mykronos.lake.catalog import Catalog
from mykronos.lake.mutate import purge_rows
from mykronos.oracle.service import OracleService
from mykronos.patchwork.stewardship import close_superseded_drafts
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)


@dataclass
class RotationResult:
    rotated: list[str] = field(default_factory=list)
    resynced: list[str] = field(default_factory=list)
    failed: list[tuple[str, str]] = field(default_factory=list)
    purged: int = 0

    def summary(self) -> str:
        return (
            f"rotated {len(self.rotated)}, resynced {len(self.resynced)}, "
            f"failed {len(self.failed)}, purged {self.purged}"
        )


async def rotate_ingestion_tokens(
    db: Database,
    github_factory: GitHubClientFactory,
    *,
    secret_name: str = DEFAULT_SECRET_NAME,
    overlap_hours: int = 24,
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

        onboardings = {
            row.github_repo_full_name: row
            for row in session.execute(
                select(RepoOnboarding).where(
                    RepoOnboarding.status.in_(("active", "pending_install"))
                )
            ).scalars()
        }

    for repo in sorted(due | unsynced):
        onboarding = onboardings.get(repo)
        if onboarding is None:
            # Offboarded or suspended. Its token is revoked or dormant; there
            # is no repo to write a secret to.
            continue

        github = github_factory.for_installation(onboarding.github_installation_id)

        try:
            with db.session() as session:
                registry = TokenRegistry(session, overlap_hours=overlap_hours)
                if repo in due:
                    plaintext = registry.rotate(repo, label="rotation-job")
                    action = "rotated"
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

        except (GitHubError, OSError) as exc:
            # Deliberately not fatal to the job: one unreachable repo must not
            # stop every other repo from rotating.
            logger.warning("Rotation for %s could not write the secret: %s", repo, exc)
            result.failed.append((repo, str(exc)))

    with db.session() as session:
        result.purged = TokenRegistry(
            session, overlap_hours=overlap_hours
        ).purge_expired()

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


#: Patchwork stages that mean it looked and could not help (spec 08 §7). A
#: finding sitting at one of these is exactly the finding a person has to
#: pick up, which is what makes it a story.
_PATCHWORK_GAVE_UP = frozenset(
    {"triaged", "no_fix_available", "skipped_low_confidence", "correlated"}
)

#: Stages that mean Patchwork owns it — a story would give a reviewer two
#: places to act on one finding.
_PATCHWORK_OWNS = frozenset({"pr_opened", "fix_generated", "queued"})


@dataclass
class RoutingResult:
    """What the auto-routing pass did (spec 19 §4)."""

    stories_opened: int = 0
    stories_updated: int = 0
    left_to_patchwork: int = 0
    #: Findings Patchwork has not looked at yet, in a repo where it will.
    #: Skipped this cycle rather than raced — the next sweep sees whatever
    #: Patchwork decided.
    awaiting_patchwork: int = 0
    failed: list[tuple[str, str]] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"{self.stories_opened} opened, {self.stories_updated} updated, "
            f"{self.left_to_patchwork} left to Patchwork, "
            f"{self.awaiting_patchwork} awaiting Patchwork, "
            f"{len(self.failed)} failed"
        )


def _patchwork_stages(catalog: Catalog, repo_full_name: str) -> dict[str, str]:
    """finding_id -> the stage Patchwork last reached for it (spec 08 §7)."""
    rows = catalog.query(
        """
        SELECT finding_id, pipeline_stage_reached FROM (
            SELECT finding_id, pipeline_stage_reached,
                   row_number() OVER (
                       PARTITION BY finding_id ORDER BY updated_at DESC
                   ) AS rn
            FROM remediation_events
            WHERE repo_full_name = ?
        ) WHERE rn = 1
        """,
        [repo_full_name],
    )
    return {str(finding_id): str(stage) for finding_id, stage in rows}


async def route_open_findings(
    db: Database,
    catalog: Catalog,
    store: KnowledgeStore | None,
    github_factory: GitHubClientFactory,
) -> RoutingResult:
    """File a story for every open finding Patchwork will not fix (spec 19 §4).

    The gap this closes: classification decides what a finding *is*, and two
    manual actions exist to act on it — Patchwork's fix and i2i grooming —
    with nothing connecting the three. A finding the platform already knew
    enough to act on sat inert until somebody opened it and clicked.

    **Routed on observed outcome, not on a prediction.** The obvious design —
    guess whether a fixer would match, and file a story only if not — is
    wrong in a way that fails silently: a finding guessed fixable that
    Patchwork then declines would never get a story on any later pass either,
    because the guess does not change. So this reads `remediation_events`,
    which records what Patchwork actually did:

    - It opened (or queued) a PR → Patchwork owns it, no story.
    - It looked and gave up (`no_fix_available`, `skipped_low_confidence`,
      `triaged`) → exactly the finding a person has to pick up. Story.
    - No event yet, and `patchwork` is enabled → it has not looked. Skipped
      this cycle; the next sweep sees whatever it decided.
    - No event yet, and `patchwork` is *not* enabled → nothing will ever look.
      Story, immediately — waiting on a capability the repo declined would
      mean these findings are never routed at all.

    Self-correcting by construction, and idempotent: `story_id()` is derived,
    so re-routing a subject updates its issue instead of opening a second one.
    """
    from mykronos.dashboard import DashboardQueries
    from mykronos.groom import open_or_update_story
    from mykronos.triage_story import gather_finding_story

    queries = DashboardQueries(catalog)
    result = RoutingResult()

    with db.session() as session:
        targets = [
            (
                row.github_repo_full_name,
                row.github_installation_id,
                "patchwork" in (row.enabled_capabilities or []),
            )
            for row in session.execute(
                select(RepoOnboarding).where(RepoOnboarding.status == "active")
            ).scalars()
        ]

    for repo_full_name, installation_id, patchwork_enabled in sorted(targets):
        # Always a client — the factory returns one per installation id and
        # never None (`github/factory.py`), the same assumption
        # `close_superseded_fixes` above already makes.
        github = github_factory.for_installation(installation_id)

        try:
            stages = _patchwork_stages(catalog, repo_full_name)
            with db.session() as session:
                page = queries.open_findings(repo_full_name, store=store, session=session)
        except Exception as exc:  # noqa: BLE001
            # One repo failing must not stop the sweep; the next run retries.
            logger.warning("Could not read findings for %s: %s", repo_full_name, exc)
            result.failed.append((repo_full_name, str(exc)))
            continue

        for group in page["groups"]:
            if group["triage"] == "likely_false_positive":
                # Dampened on purpose (spec 11) — routing it anywhere would
                # undo a judgement somebody already recorded, with a reason.
                continue

            finding_id = str(group["locations"][0]["finding_id"])
            stage = stages.get(finding_id)

            if stage in _PATCHWORK_OWNS:
                result.left_to_patchwork += 1
                continue
            if stage is None and patchwork_enabled:
                result.awaiting_patchwork += 1
                continue

            try:
                with db.session() as session:
                    finding = queries.finding(finding_id)
                    if finding is None:
                        continue
                    story = gather_finding_story(catalog, session, store, finding)
                outcome = await open_or_update_story(
                    db, github, "mykronos:auto-routing", story
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Could not route %s in %s: %s", group["rule_id"], repo_full_name, exc
                )
                result.failed.append((repo_full_name, str(exc)))
                continue

            if outcome.created:
                result.stories_opened += 1
            else:
                result.stories_updated += 1

    if result.stories_opened or result.failed:
        logger.info("Auto-routing sweep: %s", result.summary())
    return result
