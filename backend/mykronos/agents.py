"""Agent identities: minting, resolving and revoking agent credentials (spec 34 §1).

An agent that does work here - writes code, dispositions findings, opens pull
requests - used to do it with the operator's admin token, and the audit log
recorded both under one name. This module gives each agent *instance* its own
credential, so the platform can tell an agent from the person it acts for, one
agent from another, and a sub-agent from the agent that started it.

**What an agent may mint.** A human may mint a credential for any agent. An
agent may mint one only for a sub-agent: the child inherits the parent's
`on_behalf_of`, can outlive neither the parent nor the maximum lifetime, and
records the parent in its lineage. That is what makes spec 34's
`outside_lineage` rule enforceable - a sub-agent approving its parent's work is
visibly the parent's own lineage, not a second party.

**Recorded, not attested.** `family` is what the credential was issued for. The
platform cannot prove which model answers when the credential is used (spec 34
§1.3), and nothing here pretends otherwise.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select

from mykronos.adminauth import ActorKind, Principal, Role
from mykronos.auth import hash_token
from mykronos.db.models import AgentCredential, new_id
from mykronos.schemas import utcnow

#: The plaintext prefix. Lets a leaked agent credential be recognised by a
#: secret scanner as what it is, and never confused with an ingestion token.
TOKEN_PREFIX = "mka_"
TOKEN_BYTES = 32

#: Short by default: an agent run is a session, not an employee.
DEFAULT_TTL_HOURS = 12
MAX_TTL_HOURS = 24 * 7


class AgentCredentialError(ValueError):
    """A mint or revoke that the rules refuse. The message says which rule."""


@dataclass(frozen=True)
class MintedCredential:
    token: str  # the plaintext - shown once
    actor: str
    instance: str
    lineage: list[str]
    expires_at: datetime


def _actor_name(family: str, instance: str) -> str:
    return f"agent:{family}:{instance[:8]}"


def provenance_of(row: AgentCredential) -> dict[str, Any]:
    return {
        "family": row.family,
        "instance": row.instance,
        "lineage": list(row.lineage or []),
        "on_behalf_of": row.on_behalf_of,
        "purpose": row.purpose,
        "platform_started": bool(row.platform_started),
    }


def mint_agent_credential(
    db: Any,
    *,
    minted_by: Principal,
    family: str,
    on_behalf_of: str | None = None,
    purpose: str = "",
    ttl_hours: float = DEFAULT_TTL_HOURS,
) -> MintedCredential:
    """Issue a credential for a new agent instance.

    A human mints a root agent: `on_behalf_of` defaults to that human. An agent
    mints a child: `on_behalf_of` is always the parent's, the lineage extends
    with the parent's instance, and the child expires no later than the parent.
    Automation and viewers may not mint at all.
    """
    family = (family or "").strip()
    if not family:
        raise AgentCredentialError("`family` is required: which model the agent runs as.")
    if not 0 < ttl_hours <= MAX_TTL_HOURS:
        raise AgentCredentialError(
            f"`ttl_hours` must be between 0 and {MAX_TTL_HOURS}; an agent credential "
            "is for a run, and a long-lived one is an unattributed admin token by "
            "another name."
        )

    now = utcnow()
    expires_at = now + timedelta(hours=ttl_hours)
    instance = new_id()

    if minted_by.is_human and minted_by.may_write:
        lineage: list[str] = []
        principal_for = (on_behalf_of or minted_by.actor).strip()
    elif minted_by.is_agent:
        if on_behalf_of and on_behalf_of != minted_by.provenance.get("on_behalf_of"):
            raise AgentCredentialError(
                "An agent may mint only for its own principal: a sub-agent acts for "
                "the same human its parent does."
            )
        parent_expiry = minted_by.provenance.get("expires_at")
        if isinstance(parent_expiry, datetime) and expires_at > parent_expiry:
            expires_at = parent_expiry
        lineage = [*minted_by.lineage, str(minted_by.instance)]
        principal_for = str(minted_by.provenance.get("on_behalf_of") or "")
    else:
        raise AgentCredentialError(
            f"A {minted_by.kind.value} principal may not mint agent credentials."
        )

    token = TOKEN_PREFIX + secrets.token_urlsafe(TOKEN_BYTES)
    actor = _actor_name(family, instance)
    with db.session() as session:
        session.add(
            AgentCredential(
                token_sha256=hash_token(token),
                actor=actor,
                family=family,
                instance=instance,
                lineage=lineage,
                on_behalf_of=principal_for,
                purpose=purpose.strip(),
                minted_by=minted_by.actor,
                minted_at=now,
                expires_at=expires_at,
            )
        )
        db.audit(
            session,
            actor=minted_by.actor,
            action="agent.credential_minted",
            entity_type="agent_credential",
            entity_id=instance,
            agent=actor,
            family=family,
            lineage=lineage,
            on_behalf_of=principal_for,
            purpose=purpose.strip(),
            expires_at=expires_at.isoformat(),
        )
    return MintedCredential(
        token=token, actor=actor, instance=instance, lineage=lineage, expires_at=expires_at
    )


def resolve_agent_credential(db: Any, presented: str) -> Principal | None:
    """The agent principal a presented token belongs to, or `None`.

    Unknown, revoked and expired are indistinguishable to the caller, as they
    are for ingestion tokens.
    """
    if not presented.startswith(TOKEN_PREFIX):
        return None
    digest = hash_token(presented)
    with db.session() as session:
        row = session.get(AgentCredential, digest)
        if row is None or row.revoked_at is not None or row.expires_at <= utcnow():
            return None
        provenance = provenance_of(row)
        provenance["expires_at"] = row.expires_at
        return Principal(
            actor=row.actor, role=Role.AGENT, kind=ActorKind.AGENT, provenance=provenance
        )


def revoke_agent_credential(db: Any, *, instance: str, revoked_by: Principal) -> int:
    """Revoke an instance and every instance descended from it.

    Descendants go too: a sub-agent's authority came from its parent, and a
    revoked parent whose children keep working has not been revoked.
    """
    if not (revoked_by.is_human and revoked_by.may_write):
        raise AgentCredentialError("Only a person may revoke agent credentials.")
    now = utcnow()
    with db.session() as session:
        rows = list(session.execute(select(AgentCredential)).scalars())
        targets = [
            r
            for r in rows
            if r.revoked_at is None and (r.instance == instance or instance in (r.lineage or []))
        ]
        for row in targets:
            row.revoked_at = now
            row.revoked_by = revoked_by.actor
        if targets:
            db.audit(
                session,
                actor=revoked_by.actor,
                action="agent.credential_revoked",
                entity_type="agent_credential",
                entity_id=instance,
                revoked=[r.instance for r in targets],
            )
        return len(targets)


def list_agent_credentials(db: Any, *, include_inactive: bool = False) -> list[dict[str, Any]]:
    now = utcnow()
    with db.session() as session:
        rows = session.execute(
            select(AgentCredential).order_by(AgentCredential.minted_at.desc())
        ).scalars()
        out = []
        for r in rows:
            active = r.revoked_at is None and r.expires_at > now
            if not include_inactive and not active:
                continue
            out.append(
                {
                    "actor": r.actor,
                    **provenance_of(r),
                    "minted_by": r.minted_by,
                    "minted_at": r.minted_at,
                    "expires_at": r.expires_at,
                    "revoked_at": r.revoked_at,
                    "active": active,
                }
            )
        return out
