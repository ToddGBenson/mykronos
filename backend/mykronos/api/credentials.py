"""`GET /api/credentials/expiring`: what lapses soon, and how to renew it
(TheHub #61104).

The reasoning lives in `mykronos.credential_expiry`. This route reads the
database, merges the declared file, and shapes the answer. It returns names,
kinds, owners, dates and renewal steps - never a token, a hash or a key.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from mykronos import credential_expiry
from mykronos.adminauth import PrincipalDep
from mykronos.schemas import utcnow

router = APIRouter(prefix="/api/credentials", tags=["credentials"])


class ExpiringCredentialOut(BaseModel):
    name: str
    kind: str
    owner: str
    expires_at: datetime
    #: Negative once the credential has lapsed.
    hours_left: float
    expired: bool
    renewal_step: str
    #: observed: read from MyKronos's own records. declared: a person wrote
    #: the date in credential-expiry-v1.yaml and MyKronos cannot check it.
    source: Literal["observed", "declared"]


class ExpiringOut(BaseModel):
    as_of: datetime
    within_hours: float
    credentials: list[ExpiringCredentialOut]
    #: Declared credentials with no date. Not a lapse, but not known safe.
    undated: list[str] = Field(default_factory=list)


def _now(request: Request) -> datetime:
    """The clock. Tests put a callable on `app.state.clock`."""
    clock = getattr(request.app.state, "clock", None)
    return clock() if clock else utcnow()


@router.get("/expiring", response_model=ExpiringOut)
async def expiring(
    request: Request,
    principal: PrincipalDep,
    within_hours: Annotated[float, Query(ge=0, le=24 * 365)] = 48,
) -> ExpiringOut:
    """Credentials expired or expiring within `within_hours`, soonest first."""
    if not principal.may_write:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Listing credential expiry requires the 'admin' or 'agent' role.",
        )
    state = request.app.state
    now = _now(request)
    try:
        declared = credential_expiry.load_declared(state.settings.credential_expiry_path)
    except credential_expiry.CredentialFileError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    with state.db.session() as session:
        everything = credential_expiry.collect(session, declared, now)
    return ExpiringOut(
        as_of=now,
        within_hours=within_hours,
        credentials=[
            ExpiringCredentialOut(**row)
            for row in credential_expiry.expiring(everything, now, within_hours)
        ],
        undated=credential_expiry.undated(everything),
    )
