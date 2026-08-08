"""Human-user authentication for the admin API.

**This is a Phase 1 stub and is labelled as one everywhere it appears.**
Spec 12 §3 requires the organisation's SSO (SAML/OIDC) with roles mapped from
identity groups, and explicitly rules out Mykronos implementing its own
username/password system. That arrives in Phase 7.

What exists here is a single configured bearer token carrying a single role,
enough to keep the admin API from being open while the rest of Phase 1 is
built. Two properties make the stub safe to have in the tree:

- **It fails closed.** With no token configured the admin API returns 503,
  not 200. A deployment that forgets to configure it is unusable rather than
  unauthenticated.
- **It cannot be mistaken for the real thing.** The role model is one token,
  one role; there is no user, no session, no group mapping. Anyone reading it
  can see it is not an identity system.
"""

from __future__ import annotations

import secrets
from enum import StrEnum
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer


class Role(StrEnum):
    """spec 10 §5. `repo_scoped` is defined but not yet enforced per-repo."""

    ADMIN = "admin"
    VIEWER = "viewer"
    REPO_SCOPED = "repo_scoped"


_bearer = HTTPBearer(auto_error=False, description="Admin API token (Phase 1 stub).")


async def require_admin(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> str:
    """Authenticate an admin caller. Returns the actor identity for the audit log."""
    configured: str = request.app.state.settings.admin_token

    if not configured:
        # Fail closed. An unconfigured deployment must not expose repo
        # onboarding, capability changes or offboarding to anyone who asks.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "The admin API has no token configured, so it is disabled. Set "
                "MYKRONOS_ADMIN_TOKEN to enable it. This is a Phase 1 stub — "
                "spec 12 §3 replaces it with SSO."
            ),
        )

    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing admin token. Send 'Authorization: Bearer <token>'.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Constant-time: a timing oracle on an admin token is worth avoiding even
    # in a stub, because stubs outlive their intended lifespan.
    if not secrets.compare_digest(credentials.credentials, configured):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Admin token is not valid.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return str(request.app.state.settings.admin_identity or "admin")


AdminDep = Annotated[str, Depends(require_admin)]
