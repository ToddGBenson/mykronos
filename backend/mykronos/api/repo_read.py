"""Repo read tokens, and the one route they open.

`GET /api/repo-read/posture-summary` answers "how does my repository stand?"
with counts: open findings per capability and severity, and when each
capability last scanned successfully. It takes no repository parameter - the
repository is the one the presented token was minted for - and it returns no
finding detail, so a leaked token discloses a handful of integers about one
repository and cannot write anything.

Minting, listing and revoking are the operator's: a person with the admin role
(spec 34 §5). The summary route authenticates itself with the read token, so
it is exempt from the perimeter gate in the same way the ingestion routes are
(`mykronos/gate.py`).
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field

from mykronos.adminauth import HumanDep
from mykronos.dashboard import SEVERITIES, DashboardQueries
from mykronos.repo_read import (
    DEFAULT_TTL_DAYS,
    MAX_TTL_DAYS,
    RepoReadTokenError,
    list_read_tokens,
    mint_read_token,
    resolve_read_token,
    revoke_read_token,
)
from mykronos.schemas import Capability, utcnow

router = APIRouter(prefix="/api/repo-read", tags=["repo-read"])

#: Stages that report a ScanRun and never a finding (D-046), so a count of
#: their open findings would be a zero that measured nothing.
_QUALITY_STAGES = {Capability.UNIT, Capability.FUNCTIONAL, Capability.QA}
FINDING_CAPABILITIES = [c.value for c in Capability if c not in _QUALITY_STAGES]

_read_bearer = HTTPBearer(auto_error=False, description="Repo read token (`mkr_…`).")


async def require_read_token(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_read_bearer)],
) -> str:
    """The repository the presented read token may read."""
    presented = credentials.credentials if credentials else ""
    repo = resolve_read_token(request.app.state.db, presented) if presented else None
    if repo is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A valid repo read token is required: 'Authorization: Bearer mkr_…'.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return repo


ReadRepoDep = Annotated[str, Depends(require_read_token)]


class CapabilityPosture(BaseModel):
    open_by_severity: dict[str, int] = Field(
        description="Open findings at each severity, every severity present."
    )
    open_total: int
    last_successful_scan_at: datetime | None = Field(
        description="Newest successful scan run for this capability. Null when it has "
        "never scanned successfully, in which case its zero counts measured nothing."
    )


class PostureSummaryOut(BaseModel):
    repo_full_name: str
    generated_at: datetime
    capabilities: dict[str, CapabilityPosture]


@router.get("/posture-summary", response_model=PostureSummaryOut)
async def posture_summary(request: Request, repo_full_name: ReadRepoDep) -> PostureSummaryOut:
    """Open-finding counts for the token's repository, per capability.

    Counts are rows with status `open`, keyed on `asset_id` - the same count
    the portfolio shows.
    """
    queries = DashboardQueries(request.app.state.catalog)
    counts: dict[str, dict[str, int]] = {
        c: dict.fromkeys(SEVERITIES, 0) for c in FINDING_CAPABILITIES
    }
    for capability, severity, count in queries.catalog.query(
        "SELECT capability, severity, count(*) FROM findings "
        "WHERE asset_id = ? AND status = 'open' GROUP BY 1, 2",
        [repo_full_name],
    ):
        if str(capability) in counts and str(severity) in counts[str(capability)]:
            counts[str(capability)][str(severity)] = int(count)
    scanned = queries.last_successful_scan_at(repo_full_name)
    return PostureSummaryOut(
        repo_full_name=repo_full_name,
        generated_at=utcnow(),
        capabilities={
            c: CapabilityPosture(
                open_by_severity=by_severity,
                open_total=sum(by_severity.values()),
                last_successful_scan_at=scanned.get(c),
            )
            for c, by_severity in counts.items()
        },
    )


class MintReadTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repo_full_name: str = Field(description="`owner/repo` the token may read.")
    label: str = Field(default="", max_length=255, description="Who holds it, and why.")
    ttl_days: float = Field(default=DEFAULT_TTL_DAYS, gt=0, le=MAX_TTL_DAYS)


class MintedReadTokenOut(BaseModel):
    token: str = Field(description="Shown once. Only its hash is stored.")
    token_id: str
    repo_full_name: str
    expires_at: datetime


class ReadTokenOut(BaseModel):
    token_id: str
    repo_full_name: str
    label: str
    minted_by: str
    minted_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    active: bool


@router.post("/tokens", response_model=MintedReadTokenOut, status_code=status.HTTP_201_CREATED)
async def mint(
    request: Request, body: MintReadTokenRequest, principal: HumanDep
) -> MintedReadTokenOut:
    try:
        minted = mint_read_token(
            request.app.state.db,
            minted_by=principal,
            repo_full_name=body.repo_full_name,
            label=body.label,
            ttl_days=body.ttl_days,
        )
    except RepoReadTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc
    return MintedReadTokenOut(
        token=minted.token,
        token_id=minted.token_id,
        repo_full_name=minted.repo_full_name,
        expires_at=minted.expires_at,
    )


@router.get("/tokens", response_model=list[ReadTokenOut])
async def tokens(request: Request, principal: HumanDep) -> list[ReadTokenOut]:
    return [ReadTokenOut(**row) for row in list_read_tokens(request.app.state.db)]


@router.post("/tokens/{token_id}/revoke")
async def revoke(request: Request, token_id: str, principal: HumanDep) -> dict[str, bool]:
    if not revoke_read_token(request.app.state.db, token_id=token_id, revoked_by=principal):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No active repo read token {token_id}.",
        )
    return {"revoked": True}
