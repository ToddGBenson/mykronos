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

**Agents are a second kind of caller (spec 34 §1).** The operator's admin token
identifies the operator. An agent presents its own credential, minted per
instance (`AgentCredential`), and is resolved to a principal of kind `agent`
carrying its provenance - so the audit log can say an agent acted, which one,
and for whom. The resolved principal is also published on a context variable
so `Database.audit` can attribute every entry without each call site having to
pass the principal through.
"""

from __future__ import annotations

import secrets
from contextvars import ContextVar
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer


class Role(StrEnum):
    """spec 10 §5. `repo_scoped` is defined but not yet enforced per-repo."""

    ADMIN = "admin"
    VIEWER = "viewer"
    REPO_SCOPED = "repo_scoped"
    #: An agent with its own credential (spec 34 §1). May write, like the
    #: operator it acts for, but is never `human`: the duties that must be
    #: decided by a person check `is_human`, not the role.
    AGENT = "agent"


class ActorKind(StrEnum):
    """spec 34 §1: the three kinds of actor, plus the honest fourth."""

    HUMAN = "human"
    AGENT = "agent"
    AUTOMATION = "automation"
    #: Something acted and nothing established who: a CLI run, a script.
    #: Recorded as such rather than defaulted to `human`, because the whole
    #: point of this field is to stop the log claiming more than it knows.
    UNATTRIBUTED = "unattributed"


@dataclass(frozen=True)
class Principal:
    """Who is calling, and what they may see."""

    actor: str
    role: Role
    kind: ActorKind = ActorKind.HUMAN
    #: For agents: family, instance, lineage, on_behalf_of, purpose.
    provenance: dict[str, Any] = field(default_factory=dict)

    @property
    def is_human(self) -> bool:
        return self.kind is ActorKind.HUMAN

    @property
    def is_agent(self) -> bool:
        return self.kind is ActorKind.AGENT

    @property
    def instance(self) -> str | None:
        return self.provenance.get("instance") if self.is_agent else None

    @property
    def lineage(self) -> list[str]:
        return list(self.provenance.get("lineage") or []) if self.is_agent else []

    @property
    def may_see_raw_output(self) -> bool:
        """spec 12 §5: raw tool output is admin-only.

        A Secrets finding's raw record necessarily quotes context around the
        secret, and the archived output is worse. Withheld from viewers at the
        query layer rather than hidden in the UI, because "not rendered" is
        not "not sent".
        """
        return self.role in (Role.ADMIN, Role.AGENT)

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
        return self.role in (Role.ADMIN, Role.AGENT)


#: The principal the current request authenticated as. Read by
#: `Database.audit`; `None` outside a request (jobs, the CLI).
current_principal: ContextVar[Principal | None] = ContextVar("current_principal", default=None)


class PrincipalContextReset:
    """Pure ASGI middleware: every request starts with no principal.

    Not `BaseHTTPMiddleware`, which runs the app in a separate task and would
    make the reset's relationship to the handler's context an accident of its
    implementation. Here the reset and the handler share one context, and the
    token restores whatever was there before once the request is done.
    """

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope.get("type") not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        token = current_principal.set(None)
        try:
            await self.app(scope, receive, send)
        finally:
            current_principal.reset(token)


def _agent_principal(request: Request, presented: str) -> Principal | None:
    """Resolve an agent credential, or `None` if the token is not one."""
    # Imported here: adminauth is imported by the db layer's callers, and the
    # model import would otherwise run at module import time.
    from mykronos.agents import resolve_agent_credential

    db = getattr(request.app.state, "db", None)
    if db is None:
        return None
    return resolve_agent_credential(db, presented)


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

    principal: Principal | None = None
    if secrets.compare_digest(presented, configured):
        principal = Principal(actor=str(settings.admin_identity or "admin"), role=Role.ADMIN)
    elif viewer_token and secrets.compare_digest(presented, viewer_token):
        principal = Principal(actor=str(settings.viewer_identity or "viewer"), role=Role.VIEWER)
    else:
        principal = _agent_principal(request, presented)

    if principal is not None:
        current_principal.set(principal)
        request.state.principal = principal
        return principal

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


async def require_human(
    principal: Annotated[Principal, Depends(require_principal)],
) -> Principal:
    """Actions only a person may take (spec 34 §5: granting authority, changing
    the policy that governs approvals). An agent's credential is refused here
    whatever it may otherwise write."""
    if not (principal.is_human and principal.may_write):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"This action must be taken by a person with the 'admin' role; "
                f"the caller is {principal.kind.value} '{principal.actor}'."
            ),
        )
    return principal


AdminDep = Annotated[str, Depends(require_admin)]
PrincipalDep = Annotated[Principal, Depends(require_principal)]
HumanDep = Annotated[Principal, Depends(require_human)]
