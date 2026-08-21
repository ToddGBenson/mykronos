"""GitHub App webhook receiver (spec 02 §4, §5, §7).

This endpoint is unauthenticated in the ordinary sense — GitHub cannot present
a bearer token — so the HMAC signature is the *only* thing standing between
the open internet and an API that creates onboardings and flips repos to
active. It is checked before the body is parsed, and a deployment with no
webhook secret configured rejects everything rather than trusting whatever
arrives.

Handlers are idempotent because GitHub redelivers. Unrecognised events return
200: a non-2xx is a delivery failure to GitHub, and enough of them get the
webhook disabled entirely, so "I do not care about this event" must not look
like "I am broken".
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from mykronos.db.models import RepoOnboarding, get_or_create_organization
from mykronos.installer import BRANCH_PREFIX, WorkflowInstaller
from mykronos.logsafe import scrub
from mykronos.patchwork.stewardship import is_patchwork_branch, record_human_edit
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/webhooks", tags=["webhooks"])

WEBHOOK_ACTOR = "github-webhook"


def verify_signature(secret: str, body: bytes, header: str | None) -> bool:
    """Constant-time HMAC-SHA256 check of `X-Hub-Signature-256`."""
    if not header or not header.startswith("sha256="):
        return False
    expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header.removeprefix("sha256="))


def _upsert_onboarding(
    session: Session,
    *,
    org_login: str,
    repo_full_name: str,
    installation_id: int,
    default_branch: str,
) -> tuple[RepoOnboarding, bool]:
    """Create or refresh a RepoOnboarding. Returns (row, created)."""
    org = get_or_create_organization(session, org_login)
    existing = session.execute(
        select(RepoOnboarding)
        .where(RepoOnboarding.org_id == org.id)
        .where(RepoOnboarding.github_repo_full_name == repo_full_name)
    ).scalars().first()

    if existing is not None:
        # A reinstall after an uninstall must revive the row rather than
        # stranding it as `removed` with a stale installation id.
        existing.github_installation_id = installation_id
        existing.last_synced_at = utcnow()
        if existing.status == "removed":
            existing.status = "pending_install"
        return existing, False

    row = RepoOnboarding(
        org_id=org.id,
        github_repo_full_name=repo_full_name,
        github_installation_id=installation_id,
        status="pending_install",
        enabled_capabilities=[],
        default_branch=default_branch,
        onboarded_by=WEBHOOK_ACTOR,
        last_synced_at=utcnow(),
    )
    session.add(row)
    session.flush()
    return row, True


def _set_status(session: Session, installation_id: int, new_status: str) -> int:
    rows = session.execute(
        select(RepoOnboarding).where(
            RepoOnboarding.github_installation_id == installation_id
        )
    ).scalars().all()
    for row in rows:
        row.status = new_status
        row.last_synced_at = utcnow()
    return len(rows)


# ---------------------------------------------------------------------------
# Event handlers
# ---------------------------------------------------------------------------


def handle_installation(
    session: Session, payload: dict[str, Any], state: Any
) -> dict[str, Any]:
    """`installation` — the App was installed, removed, or suspended."""
    action = payload.get("action", "")
    installation = payload.get("installation") or {}
    installation_id = int(installation.get("id") or 0)
    account = (installation.get("account") or {}).get("login", "")

    if action in {"created", "new_permissions_accepted", "unsuspend"}:
        created = 0
        for repo in payload.get("repositories") or []:
            full_name = repo.get("full_name") or ""
            if not full_name:
                continue
            _, was_new = _upsert_onboarding(
                session,
                org_login=account or full_name.split("/")[0],
                repo_full_name=full_name,
                installation_id=installation_id,
                # The install payload does not carry the default branch; the
                # onboarding API refreshes it before the installer needs it.
                default_branch="main",
            )
            created += int(was_new)
        if action == "unsuspend":
            _set_status(session, installation_id, "pending_install")
        state.db.audit(
            session,
            actor=WEBHOOK_ACTOR,
            action=f"installation.{action}",
            entity_type="installation",
            entity_id=str(installation_id),
            repos_created=created,
        )
        return {"handled": action, "repos_created": created}

    if action in {"deleted", "suspend"}:
        # spec 02 §9: suspended is treated as removed for scheduling but kept
        # distinct, so the dashboard can say "paused" rather than "gone".
        new_status = "removed" if action == "deleted" else "suspended"
        affected = _set_status(session, installation_id, new_status)
        state.db.audit(
            session,
            actor=WEBHOOK_ACTOR,
            action=f"installation.{action}",
            entity_type="installation",
            entity_id=str(installation_id),
            repos_affected=affected,
        )
        return {"handled": action, "repos_affected": affected}

    return {"ignored": f"installation.{action}"}


def handle_installation_repositories(
    session: Session, payload: dict[str, Any], state: Any
) -> dict[str, Any]:
    """`installation_repositories` — repos added to or removed from an install."""
    installation = payload.get("installation") or {}
    installation_id = int(installation.get("id") or 0)
    account = (installation.get("account") or {}).get("login", "")

    added = 0
    for repo in payload.get("repositories_added") or []:
        full_name = repo.get("full_name") or ""
        if full_name:
            _upsert_onboarding(
                session,
                org_login=account or full_name.split("/")[0],
                repo_full_name=full_name,
                installation_id=installation_id,
                default_branch="main",
            )
            added += 1

    removed = 0
    for repo in payload.get("repositories_removed") or []:
        full_name = repo.get("full_name") or ""
        row = session.execute(
            select(RepoOnboarding).where(
                RepoOnboarding.github_repo_full_name == full_name
            )
        ).scalars().first()
        if row is not None:
            # Historical data lake rows are retained (spec 02 §6); only the
            # onboarding stops.
            row.status = "removed"
            row.last_synced_at = utcnow()
            removed += 1

    state.db.audit(
        session,
        actor=WEBHOOK_ACTOR,
        action="installation_repositories",
        entity_type="installation",
        entity_id=str(installation_id),
        added=added,
        removed=removed,
    )
    return {"handled": "installation_repositories", "added": added, "removed": removed}


def handle_pull_request(
    session: Session, payload: dict[str, Any], state: Any
) -> dict[str, Any]:
    """`pull_request` — two unrelated things happen when a PR closes.

    One is our own install PR merging, which promotes pending capabilities
    (spec 03 §3.6). The other is that any PR Oracle judged now has a known
    outcome, which is the evidence blocking mode will eventually be argued
    from (spec 09 §6). Both hang off the same event; neither is allowed to
    stop the other from running.
    """
    if payload.get("action") != "closed":
        return {"ignored": f"pull_request.{payload.get('action')}"}

    pull_request = payload.get("pull_request") or {}
    merged = bool(pull_request.get("merged"))
    repo_full_name = (payload.get("repository") or {}).get("full_name") or ""
    number = int(pull_request.get("number") or 0)

    result: dict[str, Any] = {"handled": "pull_request.closed"}

    if repo_full_name and number:
        decision_id = _record_gate_outcome(
            state, repo_full_name, number, "merged" if merged else "closed_unmerged"
        )
        if decision_id:
            result["gate_outcome_recorded_for"] = decision_id

        # A Patchwork draft closing is the clearest verdict a human ever gives
        # this platform (spec 11 §9), and it is also what stops Oracle
        # discounting a finding for a fix that is no longer in flight.
        event_id = _record_remediation_outcome(
            state,
            repo_full_name,
            number,
            merged,
            merge_commit_sha=str(pull_request.get("merge_commit_sha") or ""),
            pr_body=str(pull_request.get("body") or ""),
        )
        if event_id:
            result["remediation_outcome_recorded_for"] = event_id

    if not merged:
        return {**result, "promoted": []}

    head_ref = ((pull_request.get("head") or {}).get("ref")) or ""
    if not head_ref.startswith(BRANCH_PREFIX):
        return {**result, "promoted": []}

    row = session.execute(
        select(RepoOnboarding).where(
            RepoOnboarding.github_repo_full_name == repo_full_name
        )
    ).scalars().first()
    if row is None:
        logger.warning("Install PR merged for unknown repo %s", repo_full_name)
        return {**result, "ignored": "unknown repo"}

    promoted = WorkflowInstaller.on_install_pr_merged(session, row, number)
    if promoted:
        state.db.audit(
            session,
            actor=WEBHOOK_ACTOR,
            action="workflow_install_pr.merged",
            entity_type="repo_onboarding",
            entity_id=row.id,
            pr_number=number,
            enabled_capabilities=row.enabled_capabilities,
        )
    return {**result, "promoted": promoted}


def _record_remediation_outcome(
    state: Any,
    repo_full_name: str,
    pr_number: int,
    merged: bool,
    *,
    merge_commit_sha: str = "",
    pr_body: str = "",
) -> str | None:
    """Same failure posture as the gate outcome: never break the webhook.

    GitHub disables a webhook that fails often enough, and losing install-PR
    promotion to save a bookkeeping update would be a bad trade.
    """
    from mykronos.patchwork.outcomes import record_pr_outcome

    try:
        return record_pr_outcome(
            state.catalog,
            state.buffer,
            repo_full_name,
            pr_number,
            merged=merged,
            store=state.knowledge,
            # Recorded here, dispatched later by the verification job
            # (spec 25 §1): the webhook must stay fast and must not fail, and
            # a GitHub or Concourse call in this path is one that can do both.
            merge_commit_sha=merge_commit_sha,
            # The body as GitHub reports it at close. Whatever the closer
            # wrote on the line Patchwork put there is the only reason this
            # platform will ever get (spec 25 §3.3).
            pr_body=pr_body,
        )
    except Exception as exc:  # noqa: BLE001 — see docstring
        logger.warning(
            "Could not record the remediation outcome for %s#%s: %s",
            repo_full_name,
            pr_number,
            exc,
        )
        return None


def _record_gate_outcome(
    state: Any, repo_full_name: str, pr_number: int, outcome: str
) -> str | None:
    """Mark what happened to a judged PR, without letting it break the webhook.

    A lake read failing here must not turn into a non-2xx: GitHub disables a
    webhook that fails often enough, and losing install-PR promotion to save a
    metric would be a bad trade.
    """
    from mykronos.oracle.service import OracleService

    try:
        return OracleService(
            state.catalog, state.buffer, state.oracle_policy, state.knowledge, db=state.db
        ).record_gate_outcome(repo_full_name, pr_number, outcome)
    except Exception as exc:  # noqa: BLE001 — see docstring
        logger.warning(
            "Could not record the gate outcome for %s#%s: %s",
            repo_full_name,
            pr_number,
            exc,
        )
        return None


def handle_push(
    session: Session, payload: dict[str, Any], state: Any
) -> dict[str, Any]:
    """`push` — watch for a person committing to a Patchwork fix branch.

    This is the only way to learn that somebody has taken a draft over. The
    pull-request events do not fire for a plain push to an existing branch,
    so without this Patchwork would keep regenerating over the top of
    somebody's work — the single behaviour spec 08 §3 says it must never
    have.
    """
    ref = str(payload.get("ref") or "")
    repo_full_name = (payload.get("repository") or {}).get("full_name") or ""
    commits = list(payload.get("commits") or [])

    if not repo_full_name or not is_patchwork_branch(ref):
        return {"ignored": "not a Patchwork branch"}

    try:
        outcome = record_human_edit(
            state.catalog,
            state.buffer,
            repo_full_name,
            ref,
            commits,
            bot_logins=set(state.settings.github_bot_logins),
        )
    except Exception as exc:  # noqa: BLE001
        # Same posture as the other two side-effects on this endpoint: GitHub
        # disables a webhook that fails often enough, and losing install-PR
        # promotion to save a bookkeeping update would be a bad trade.
        #
        # The failure mode here is worth naming, though: if this never
        # records, Patchwork keeps regenerating over the branch. That is the
        # one thing spec 08 §3 forbids — so the log line says so, loudly.
        logger.warning(
            "Could not record a human edit on %s (%s): %s. Patchwork may "
            "overwrite this branch on its next run.",
            repo_full_name,
            ref,
            exc,
        )
        return {"handled": "push", "marked_human_edited": False, "reason": str(exc)}

    if outcome.marked:
        state.db.audit(
            session,
            actor=WEBHOOK_ACTOR,
            action="patchwork.human_edited",
            entity_type="remediation_event",
            entity_id=outcome.event_id or ref,
            repo=repo_full_name,
            branch=ref,
        )

    return {"handled": "push", "marked_human_edited": outcome.marked,
            "reason": outcome.reason}


HANDLERS = {
    "installation": handle_installation,
    "installation_repositories": handle_installation_repositories,
    "pull_request": handle_pull_request,
    "push": handle_push,
}


@router.post("/github")
async def github_webhook(
    request: Request,
    x_github_event: str | None = Header(default=None),
    x_hub_signature_256: str | None = Header(default=None),
    x_github_delivery: str | None = Header(default=None),
) -> dict[str, Any]:
    settings = request.app.state.settings
    body = await request.body()

    if not settings.github_webhook_secret:
        # Fail closed. Without a secret there is no way to distinguish GitHub
        # from anyone who found the URL, and this endpoint can flip repos to
        # active and create onboardings.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "No webhook secret configured, so webhooks are rejected. Set "
                "MYKRONOS_GITHUB_WEBHOOK_SECRET to the value given to the App."
            ),
        )

    if not verify_signature(settings.github_webhook_secret, body, x_hub_signature_256):
        # Unauthenticated at this point, by definition: the signature just
        # failed. The delivery id is an attacker-supplied header, and this is
        # the one log-injection site on the platform reachable without any
        # credential at all.
        logger.warning(
            "Rejected webhook delivery %s: bad signature", scrub(x_github_delivery)
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Signature verification failed.",
        )

    handler = HANDLERS.get(x_github_event or "")
    if handler is None:
        # 200, deliberately. A non-2xx is a delivery failure to GitHub, and
        # enough of them disable the webhook — "not interested" must not look
        # like "broken". Events we will want later (workflow_run, check_run)
        # land here until their phase.
        return {"ignored": x_github_event or "unknown"}

    import json

    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Body is not valid JSON."
        ) from None

    state = request.app.state
    with state.db.session() as session:
        result = handler(session, payload, state)

    logger.info(
        "webhook %s delivery=%s -> %s",
        scrub(x_github_event),
        scrub(x_github_delivery),
        scrub(result),
    )
    return result
