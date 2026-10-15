"""Repo read tokens: a read-only credential scoped to one repository.

A service that wants a number about its own repository - TheHub's
self-assessment asks "how many open dependency and container findings do I
have?" - needs a credential that can read that and nothing more. The two it
could already hold are both too broad: the repository's ingestion token
*writes* findings, and the viewer token reads the whole estate.

A repo read token is accepted by one route, `GET /api/repo-read/posture-summary`,
which returns open-finding *counts* for the repository the token was minted
for. It never resolves to a `Principal`, so no other route accepts it, and the
route has no repository parameter for a caller to change.

Minting and revoking are a person's acts (spec 34 §5): an agent may not hand
out a long-lived credential, any more than it may grant authority.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select

from mykronos.adminauth import Principal
from mykronos.auth import hash_token
from mykronos.db.models import RepoReadToken
from mykronos.schemas import utcnow

#: The plaintext prefix, so a leaked one is recognisable for what it is and is
#: never mistaken for an agent credential (`mka_`) or an ingestion token.
TOKEN_PREFIX = "mkr_"
TOKEN_BYTES = 32

#: The same clock as ingestion-token rotation (spec 05 §4).
DEFAULT_TTL_DAYS = 90
MAX_TTL_DAYS = 365


class RepoReadTokenError(ValueError):
    """A mint or revoke the rules refuse. The message says which rule."""


@dataclass(frozen=True)
class MintedReadToken:
    token: str  # the plaintext - shown once
    token_id: str
    repo_full_name: str
    expires_at: datetime


def _require_person(principal: Principal, act: str) -> None:
    if not (principal.is_human and principal.may_write):
        raise RepoReadTokenError(
            f"Only a person with the 'admin' role may {act} a repo read token; "
            f"the caller is {principal.kind.value} '{principal.actor}'."
        )


def mint_read_token(
    db: Any,
    *,
    minted_by: Principal,
    repo_full_name: str,
    label: str = "",
    ttl_days: float = DEFAULT_TTL_DAYS,
) -> MintedReadToken:
    """Issue a read token for one repository. Returns the plaintext, once."""
    _require_person(minted_by, "mint")
    repo = (repo_full_name or "").strip()
    if repo.count("/") != 1 or not all(repo.split("/")):
        raise RepoReadTokenError("`repo_full_name` must be `owner/repo`.")
    if not 0 < ttl_days <= MAX_TTL_DAYS:
        raise RepoReadTokenError(f"`ttl_days` must be between 0 and {MAX_TTL_DAYS}.")

    token = TOKEN_PREFIX + secrets.token_urlsafe(TOKEN_BYTES)
    now = utcnow()
    row = RepoReadToken(
        token_sha256=hash_token(token),
        repo_full_name=repo,
        label=label.strip(),
        minted_by=minted_by.actor,
        minted_at=now,
        expires_at=now + timedelta(days=ttl_days),
    )
    with db.session() as session:
        session.add(row)
        session.flush()
        token_id = row.token_id
        expires_at = row.expires_at
        db.audit(
            session,
            actor=minted_by.actor,
            action="repo_read_token.minted",
            entity_type="repo_read_token",
            entity_id=token_id,
            repo_full_name=repo,
            label=row.label,
            expires_at=row.expires_at.isoformat(),
        )
    return MintedReadToken(
        token=token, token_id=token_id, repo_full_name=repo, expires_at=expires_at
    )


def resolve_read_token(db: Any, presented: str) -> str | None:
    """The repository a presented token may read, or `None`.

    Unknown, revoked and expired are indistinguishable to the caller, as they
    are for every other credential here.
    """
    if not presented.startswith(TOKEN_PREFIX):
        return None
    with db.session() as session:
        row = session.get(RepoReadToken, hash_token(presented))
        if row is None or row.revoked_at is not None or row.expires_at <= utcnow():
            return None
        return str(row.repo_full_name)


def revoke_read_token(db: Any, *, token_id: str, revoked_by: Principal) -> bool:
    """Revoke one token, effective on the next request. True if it changed anything."""
    _require_person(revoked_by, "revoke")
    with db.session() as session:
        row = (
            session.execute(select(RepoReadToken).where(RepoReadToken.token_id == token_id))
            .scalars()
            .first()
        )
        if row is None or row.revoked_at is not None:
            return False
        row.revoked_at = utcnow()
        row.revoked_by = revoked_by.actor
        db.audit(
            session,
            actor=revoked_by.actor,
            action="repo_read_token.revoked",
            entity_type="repo_read_token",
            entity_id=token_id,
            repo_full_name=row.repo_full_name,
        )
        return True


def list_read_tokens(db: Any) -> list[dict[str, Any]]:
    """Every token's metadata - never the hash, never the plaintext."""
    now = utcnow()
    with db.session() as session:
        rows = session.execute(
            select(RepoReadToken).order_by(RepoReadToken.minted_at.desc())
        ).scalars()
        return [
            {
                "token_id": r.token_id,
                "repo_full_name": r.repo_full_name,
                "label": r.label,
                "minted_by": r.minted_by,
                "minted_at": r.minted_at,
                "expires_at": r.expires_at,
                "revoked_at": r.revoked_at,
                "active": r.revoked_at is None and r.expires_at > now,
            }
            for r in rows
        ]
