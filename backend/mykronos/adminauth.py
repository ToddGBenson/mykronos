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
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer


class Role(StrEnum):
    """spec 10 §5. `repo_scoped` is defined but not yet enforced per-repo."""

    ADMIN = "admin"
    VIEWER = "viewer"
    REPO_SCOPED = "repo_scoped"


@dataclass(frozen=True)
class Principal:
    """Who is calling, and what they may see."""

    actor: str
    role: Role

    @property
    def may_see_raw_output(self) -> bool:
        """spec 12 §5: raw tool output is admin-only.

        A Secrets finding's raw record necessarily quotes context around the
        secret, and the archived output is worse. Withheld from viewers at the
        query layer rather than hidden in the UI, because "not rendered" is
        not "not sent".
        """
        return self.role is Role.ADMIN

    @property
    def may_see_insider_risk(self) -> bool:
        """spec 06 §9: insider-risk detail is admin-only.

        A separate property from `may_see_raw_output` even though both are
        currently "admin", because they protect different things for different
        reasons and will diverge. Raw output is withheld because it may quote a
        secret; this is withheld because it is a risk assessment of a named
        colleague. Collapsing them into one check would make the next role
        change silently alter both.

        Viewers can still see *that* Aegis ran on a pull request and what it
        recommended — the same thing anyone with repo access sees on the Check
        Run. What they cannot see is the breakdown, the author's baseline
        comparison, or the history across pull requests.
        """
        return self.role is Role.ADMIN

    @property
    def may_write(self) -> bool:
        return self.role is Role.ADMIN


_bearer = HTTPBearer(auto_error=False, description="Admin API token (Phase 1 stub).")


async def require_principal(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> Principal:
    """Authenticate a caller and resolve their role."""
    settings = request.app.state.settings
    configured: str = settings.admin_token
    viewer_token: str = settings.viewer_token

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
    presented = credentials.credentials

    if secrets.compare_digest(presented, configured):
        return Principal(actor=str(settings.admin_identity or "admin"), role=Role.ADMIN)

    if viewer_token and secrets.compare_digest(presented, viewer_token):
        return Principal(actor=str(settings.viewer_identity or "viewer"), role=Role.VIEWER)

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token is not valid.",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def require_admin(
    principal: Annotated[Principal, Depends(require_principal)],
) -> str:
    """Admin-only endpoints. Returns the actor identity for the audit log."""
    if not principal.may_write:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"This action requires the 'admin' role; you have "
                f"'{principal.role.value}'."
            ),
        )
    return principal.actor


AdminDep = Annotated[str, Depends(require_admin)]
PrincipalDep = Annotated[Principal, Depends(require_principal)]
