"""Ingestion token auth (spec 05 §4, spec 12 §2, D-009).

One token per repo, carrying capability grants held separately. The repo is
the isolation boundary because it is the only boundary GitHub enforces:
Actions repository secrets are readable by every workflow in the repo, so a
per-capability token would be a boundary a compromised runner walks straight
through.

Only a token's SHA-256 is ever persisted. Issuance returns the plaintext once;
after that the platform genuinely cannot recover it.

Three states:

- ``active``     — the current token for a repo.
- ``superseded`` — replaced by rotation, still accepted until ``expires_at``.
  This is what stops a rotation from 401-ing a workflow that read the old
  secret before the swap and posts its findings ten minutes later.
- ``revoked``    — offboarded. Rejected immediately.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, cast

from sqlalchemy import CursorResult, delete, select
from sqlalchemy.orm import Session

from mykronos.db.models import CapabilityGrant, IngestionToken
from mykronos.schemas import utcnow

TOKEN_BYTES = 32
ROTATION_DAYS = 90  # spec 05 §4
DEFAULT_OVERLAP_HOURS = 24  # spec 05 §4 dual-validity window


def hash_token(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Resolution:
    """What a presented token turned out to be."""

    repo_full_name: str
    granted_capabilities: frozenset[str]
    token_sha256: str
    #: True when the caller is still using a rotated-away token inside its
    #: overlap window. Surfaced as a response header so a repo that never
    #: picked up the new secret is diagnosable before it starts failing.
    superseded: bool

    def permits(self, capability: str) -> bool:
        return capability in self.granted_capabilities


class TokenRegistry:
    """Issues, rotates, resolves and revokes ingestion tokens."""

    def __init__(self, session: Session, overlap_hours: int = DEFAULT_OVERLAP_HOURS) -> None:
        self.session = session
        self.overlap = timedelta(hours=overlap_hours)

    # -- issuance -------------------------------------------------------

    def issue(self, repo_full_name: str, label: str = "") -> str:
        """Mint the repo's first token. Returns the plaintext, once.

        If the repo already has an active token this supersedes it, so calling
        `issue` twice is a rotation rather than two live credentials.
        """
        if self._active_token(repo_full_name) is not None:
            return self.rotate(repo_full_name, label=label)

        plaintext = secrets.token_urlsafe(TOKEN_BYTES)
        now = utcnow()
        self.session.add(
            IngestionToken(
                token_sha256=hash_token(plaintext),
                repo_full_name=repo_full_name,
                status="active",
                issued_at=now,
                rotate_after=now + timedelta(days=ROTATION_DAYS),
                label=label,
            )
        )
        return plaintext

    def rotate(self, repo_full_name: str, label: str = "") -> str:
        """Issue a replacement, keeping the old token valid for the overlap.

        Order matters: the new token is created and the old one marked
        superseded *before* the caller writes the new value to the repo
        secret. If that write then fails, the old token is still accepted and
        nothing is stranded — the rotation is simply retried.
        """
        now = utcnow()
        for token in self._tokens_for(repo_full_name):
            if token.status == "active":
                token.status = "superseded"
                token.superseded_at = now
                token.expires_at = now + self.overlap

        plaintext = secrets.token_urlsafe(TOKEN_BYTES)
        self.session.add(
            IngestionToken(
                token_sha256=hash_token(plaintext),
                repo_full_name=repo_full_name,
                status="active",
                issued_at=now,
                rotate_after=now + timedelta(days=ROTATION_DAYS),
                label=label,
            )
        )
        return plaintext

    def due_for_rotation(self, as_of: datetime | None = None) -> list[str]:
        """Repos whose active token has passed `rotate_after`."""
        moment = as_of or utcnow()
        rows = self.session.execute(
            select(IngestionToken.repo_full_name)
            .where(IngestionToken.status == "active")
            .where(IngestionToken.rotate_after <= moment)
        ).scalars()
        return list(rows)

    # -- resolution -----------------------------------------------------

    def resolve(self, plaintext: str, as_of: datetime | None = None) -> Resolution | None:
        """Return the scope for a presented token, or None if it is not usable.

        None covers unknown, revoked, and superseded-past-expiry alike. The
        caller must not distinguish them in its response: a caller learns only
        that this token does not work now, not whether it ever did.
        """
        moment = as_of or utcnow()
        digest = hash_token(plaintext)
        token = self.session.get(IngestionToken, digest)

        if token is None or token.status == "revoked":
            return None
        if token.status == "superseded" and (
            token.expires_at is None or token.expires_at <= moment
        ):
            return None

        grants = self.session.execute(
            select(CapabilityGrant.capability).where(
                CapabilityGrant.repo_full_name == token.repo_full_name
            )
        ).scalars()

        return Resolution(
            repo_full_name=token.repo_full_name,
            granted_capabilities=frozenset(grants),
            token_sha256=digest,
            superseded=token.status == "superseded",
        )

    # -- grants ---------------------------------------------------------

    def grant(self, repo_full_name: str, capability: str) -> bool:
        """Allow a capability to write. Idempotent; True if it changed anything."""
        if self.is_granted(repo_full_name, capability):
            return False
        self.session.add(
            CapabilityGrant(repo_full_name=repo_full_name, capability=capability)
        )
        self.session.flush()
        return True

    def revoke_grant(self, repo_full_name: str, capability: str) -> bool:
        """Stop a capability writing, effective on the very next request.

        No GitHub API call is involved, so unlike deleting a repo secret this
        cannot half-succeed and leave a live credential behind. The repo's
        other capabilities keep working on the same token.
        """
        result = cast(
            "CursorResult[Any]",
            self.session.execute(
                delete(CapabilityGrant)
                .where(CapabilityGrant.repo_full_name == repo_full_name)
                .where(CapabilityGrant.capability == capability)
            ),
        )
        return bool(result.rowcount)

    def is_granted(self, repo_full_name: str, capability: str) -> bool:
        return (
            self.session.execute(
                select(CapabilityGrant.id)
                .where(CapabilityGrant.repo_full_name == repo_full_name)
                .where(CapabilityGrant.capability == capability)
            ).first()
            is not None
        )

    def granted_capabilities(self, repo_full_name: str) -> set[str]:
        return set(
            self.session.execute(
                select(CapabilityGrant.capability).where(
                    CapabilityGrant.repo_full_name == repo_full_name
                )
            ).scalars()
        )

    def sync_grants(
        self, repo_full_name: str, capabilities: set[str]
    ) -> tuple[set[str], set[str]]:
        """Make the grant set exactly `capabilities`. Returns (added, removed)."""
        current = self.granted_capabilities(repo_full_name)
        added = capabilities - current
        removed = current - capabilities
        for capability in added:
            self.grant(repo_full_name, capability)
        for capability in removed:
            self.revoke_grant(repo_full_name, capability)
        return added, removed

    # -- revocation -----------------------------------------------------

    def revoke_repo(self, repo_full_name: str) -> int:
        """Offboarding: kill every token for the repo, and all its grants."""
        count = 0
        for token in self._tokens_for(repo_full_name):
            if token.status != "revoked":
                token.status = "revoked"
                token.expires_at = utcnow()
                count += 1
        self.session.execute(
            delete(CapabilityGrant).where(CapabilityGrant.repo_full_name == repo_full_name)
        )
        return count

    def purge_expired(self, as_of: datetime | None = None) -> int:
        """Drop superseded tokens whose overlap has passed.

        Retaining them would quietly extend the rotation window forever, which
        is not a rotation.
        """
        moment = as_of or utcnow()
        result = cast(
            "CursorResult[Any]",
            self.session.execute(
                delete(IngestionToken)
                .where(IngestionToken.status == "superseded")
                .where(IngestionToken.expires_at.is_not(None))
                .where(IngestionToken.expires_at <= moment)
            ),
        )
        return int(result.rowcount)

    # -- introspection --------------------------------------------------

    def list_tokens(self) -> list[IngestionToken]:
        return list(self.session.execute(select(IngestionToken)).scalars())

    def _tokens_for(self, repo_full_name: str) -> list[IngestionToken]:
        return list(
            self.session.execute(
                select(IngestionToken).where(IngestionToken.repo_full_name == repo_full_name)
            ).scalars()
        )

    def _active_token(self, repo_full_name: str) -> IngestionToken | None:
        return (
            self.session.execute(
                select(IngestionToken)
                .where(IngestionToken.repo_full_name == repo_full_name)
                .where(IngestionToken.status == "active")
            )
            .scalars()
            .first()
        )
