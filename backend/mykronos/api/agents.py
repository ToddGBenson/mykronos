"""Agent identity API (spec 34 §1).

`POST /api/agents/credentials` mints a credential for a new agent instance. A
person may mint one for any agent; an agent may mint one only for a sub-agent,
whose lineage then records it. Revocation is a person's act, and takes every
descendant with it.

`GET /api/agents/whoami` answers the question an agent should ask before it
acts: "what does the platform think I am?" - so an agent that believes it is
using its own credential can prove it is not still on the operator's.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from mykronos.adminauth import HumanDep, PrincipalDep
from mykronos.agents import (
    DEFAULT_TTL_HOURS,
    MAX_TTL_HOURS,
    AgentCredentialError,
    list_agent_credentials,
    mint_agent_credential,
    revoke_agent_credential,
)

router = APIRouter(prefix="/api/agents", tags=["agents"])


class MintRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    family: str = Field(description="The model family the agent runs as, e.g. `claude-opus-5.5`.")
    purpose: str = Field(
        default="", max_length=128, description="`author`, `independent-reviewer`, …"
    )
    on_behalf_of: str | None = Field(
        default=None,
        description="The human the agent acts for. A person may name another person; "
        "an agent may not change it.",
    )
    ttl_hours: float = Field(default=DEFAULT_TTL_HOURS, gt=0, le=MAX_TTL_HOURS)


class MintedOut(BaseModel):
    token: str = Field(description="Shown once. Only its hash is stored.")
    actor: str
    instance: str
    lineage: list[str]
    expires_at: datetime


class WhoAmI(BaseModel):
    actor: str
    kind: str
    role: str
    provenance: dict[str, Any]


class AgentOut(BaseModel):
    actor: str
    family: str
    instance: str
    lineage: list[str]
    on_behalf_of: str
    purpose: str
    minted_by: str
    minted_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    active: bool


@router.post("/credentials", response_model=MintedOut, status_code=status.HTTP_201_CREATED)
async def mint(request: Request, body: MintRequest, principal: PrincipalDep) -> MintedOut:
    try:
        minted = mint_agent_credential(
            request.app.state.db,
            minted_by=principal,
            family=body.family,
            on_behalf_of=body.on_behalf_of,
            purpose=body.purpose,
            ttl_hours=body.ttl_hours,
        )
    except AgentCredentialError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    return MintedOut(
        token=minted.token,
        actor=minted.actor,
        instance=minted.instance,
        lineage=minted.lineage,
        expires_at=minted.expires_at,
    )


@router.get("/whoami", response_model=WhoAmI)
async def whoami(principal: PrincipalDep) -> WhoAmI:
    provenance = {
        k: (v.isoformat() if isinstance(v, datetime) else v)
        for k, v in principal.provenance.items()
    }
    return WhoAmI(
        actor=principal.actor,
        kind=principal.kind.value,
        role=principal.role.value,
        provenance=provenance,
    )


@router.get("/credentials", response_model=list[AgentOut])
async def credentials(
    request: Request, principal: PrincipalDep, include_inactive: bool = False
) -> list[AgentOut]:
    if not principal.may_write:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Listing agent credentials requires the 'admin' or 'agent' role.",
        )
    return [
        AgentOut(**row)
        for row in list_agent_credentials(request.app.state.db, include_inactive=include_inactive)
    ]


@router.post("/credentials/{instance}/revoke")
async def revoke(request: Request, instance: str, principal: HumanDep) -> dict[str, int]:
    try:
        count = revoke_agent_credential(
            request.app.state.db, instance=instance, revoked_by=principal
        )
    except AgentCredentialError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    if count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No active agent instance {instance}.",
        )
    return {"revoked": count}
