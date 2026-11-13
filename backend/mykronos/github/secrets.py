"""Actions and Dependabot secret sealing (spec 03 §4a, spec 12 §4.4).

GitHub requires repository secrets to be encrypted client-side with a
libsodium sealed box against the repo's own public key. A plaintext secret
value never crosses the wire — not to GitHub, and not into any log or request
trace along the way.

This is also the reason `secrets: write` is safe to hold (spec 12 §6): the
API takes ciphertext we produced and never hands any secret value back.

A repository has **two** such stores (TheHub #60855). Actions secrets are
what a push- or schedule-triggered run reads; a Dependabot-triggered run
reads Dependabot secrets, a separate store with its own public key behind
its own App permission. A token sealed into the first alone fails every
Dependabot pull request's lanes closed. `sync_dependabot_secret` is the
second half, written wherever the first is.
"""

from __future__ import annotations

import base64
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from nacl import encoding, public

if TYPE_CHECKING:
    from mykronos.github.client import GitHubClient

logger = logging.getLogger(__name__)

#: The repository permission the operator grants on the App, named as
#: GitHub's permissions page names it, so a reason that quotes it can be
#: followed without a lookup.
DEPENDABOT_PERMISSION = "Dependabot secrets: Read and write"

#: What GitHub answers on the Dependabot endpoints when the installation does
#: not hold the permission: 403 ("Resource not accessible by integration"), or
#: 404 for an installation that cannot see the endpoint at all.
PERMISSION_GAP_STATUSES = frozenset({403, 404})


@dataclass(frozen=True)
class RepoPublicKey:
    """A repo's secrets public key, from `GET /repos/{o}/{r}/actions/secrets/public-key`
    or `GET /repos/{o}/{r}/dependabot/secrets/public-key`."""

    key_id: str
    key_base64: str


@dataclass(frozen=True)
class DependabotSyncOutcome:
    """Whether the Dependabot copy landed, and if not, why, in a sentence a
    person can act on (TheHub #60855)."""

    synced: bool
    reason: str = ""


def seal_secret(public_key_base64: str, plaintext: str) -> str:
    """Return the base64 sealed-box ciphertext GitHub's Secrets API expects.

    Sealed boxes are anonymous and one-way: we can encrypt to the repo's
    public key but cannot decrypt what we produced, and neither can anyone
    who intercepts it without the repo's private key, which only GitHub holds.
    """
    key = public.PublicKey(public_key_base64.encode("utf-8"), encoding.Base64Encoder)
    sealed = public.SealedBox(key).encrypt(plaintext.encode("utf-8"))
    return base64.b64encode(sealed).decode("utf-8")


#: Prefix of the reason recorded when the write failed *although* the
#: installation was read and holds `dependabot_secrets: write`. The sweep
#: never rotates again on such a blocker: a second rotation would meet the
#: same refusal, and one credential churned per sweep for nothing is the
#: defect the independent review of #1142 measured. The copy is retried at
#: the repository's next due rotation, when a rotation happens anyway.
WRITE_FAILED_UNDER_GRANT = (
    "The Dependabot secret write failed although the installation holds "
    "'dependabot_secrets: write'"
)


def write_failed_under_grant(reason: str) -> bool:
    """Whether `reason` records a refusal the grant does not explain."""
    return reason.startswith(WRITE_FAILED_UNDER_GRANT)


def permission_not_held_reason(held: str | None) -> str:
    """The reason recorded when the installation's grant is read and is not
    `write`: nothing was attempted, and nothing will be until it is."""
    holding = f"holds 'dependabot_secrets: {held}'" if held else "holds no 'dependabot_secrets'"
    return (
        f"The App's installation {holding}; writing the Dependabot secret needs the "
        f"repository permission '{DEPENDABOT_PERMISSION}'. Grant it on the App and "
        "accept the permission update on the installation; the next rotation sweep "
        "then writes the secret."
    )


def dependabot_gap_reason(status: int | None, detail: str) -> str:
    """The sentence recorded on the token when the Dependabot write failed.

    A permission gap names the grant, because that is the usual remedy and
    the status code alone does not say so — and still quotes what GitHub
    said, because a secondary rate limit or an SSO enforcement answers 403
    too. The error text describes a request that only ever held ciphertext.
    """
    if status in PERMISSION_GAP_STATUSES:
        return (
            f"GitHub answered {status} on the Dependabot secrets endpoint, which is "
            f"what an App lacking the repository permission '{DEPENDABOT_PERMISSION}' "
            "gets. Grant it on the App and accept the permission update on the "
            f"installation; the next rotation sweep then writes the secret. GitHub "
            f"said: {detail}"
        )
    return f"The Dependabot secret write failed: {detail}"


async def sync_dependabot_secret(
    github: GitHubClient,
    repo_full_name: str,
    name: str,
    plaintext: str,
    *,
    grant_verified: bool = False,
) -> DependabotSyncOutcome:
    """Seal `plaintext` into the repo's Dependabot secrets under their own key.

    Never raises for a GitHub refusal or an unreachable API: the caller has
    just written the Actions secret, and that write must stand on its own.
    The outcome says what happened so the caller records it on the token,
    where the work queue reads it — a refusal is written down, never skipped.

    `grant_verified` is the caller saying it read the installation and found
    `dependabot_secrets: write` before this attempt. A failure then is one
    the grant does not explain, and is recorded under
    `WRITE_FAILED_UNDER_GRANT` so the sweep does not rotate to retry it.
    """
    from mykronos.github.client import GitHubError

    try:
        key = await github.get_dependabot_public_key(repo_full_name)
        await github.put_dependabot_secret(
            repo_full_name, name, seal_secret(key.key_base64, plaintext), key.key_id
        )
    except GitHubError as exc:
        reason = _failure_reason(exc.status, str(exc), grant_verified=grant_verified)
        # Matches on the word 'secret'. Logs a repo name and GitHub's error text,
        # which describes a request that carried ciphertext only.
        # nosemgrep: python-logger-credential-disclosure
        logger.warning("%s: Dependabot secret not written. %s", repo_full_name, reason)
        return DependabotSyncOutcome(synced=False, reason=reason)
    except OSError as exc:
        reason = _failure_reason(None, str(exc), grant_verified=grant_verified)
        logger.warning("%s: Dependabot secret not written. %s", repo_full_name, reason)
        return DependabotSyncOutcome(synced=False, reason=reason)
    return DependabotSyncOutcome(synced=True)


def _failure_reason(status: int | None, detail: str, *, grant_verified: bool) -> str:
    if grant_verified:
        return (
            f"{WRITE_FAILED_UNDER_GRANT}: GitHub answered {status or 'no status'}: "
            f"{detail}. Not retried by rotation; the copy is attempted again at the "
            "repository's next due rotation."
        )
    return dependabot_gap_reason(status, detail)
