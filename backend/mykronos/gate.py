"""Perimeter gate — the Hub's scheme, with Mykronos's own secret.

The Hub (a sibling service on this host) fronts itself with a static token
presented as `X-Hub-Token`, a `hub_token` cookie, or a `?_token=` query
parameter. This mirrors that scheme exactly - same carriers, same names - so
browser sessions behave the same way on each.

**The secret is not shared.** This compares against `MYKRONOS_GATE_TOKEN`,
which is a different value from the Hub's `HUB_API_TOKEN` (checked
2026-10-08). An earlier version of this docstring said "the same secret, so
one credential reaches both"; it was not true when checked, and it sent the
operator to the dashboard with the Hub's token. Keeping them separate is the
better property anyway: a leaked Hub token does not open Mykronos.

**This is a perimeter, not an authorisation model.** It answers "may you talk
to this host at all". Who you are once inside — admin or viewer — is still
`mykronos.adminauth`, and collapsing the two would make everyone who can
reach the host an admin.

**What it deliberately does not cover.** Three kinds of caller cannot present
this token and must not be asked to:

- **GitHub Actions runners** authenticate with a per-repo ingestion token in
  `Authorization: Bearer`. Requiring the gate as well would mean a second
  secret in every repository, rotating on a different clock, protecting
  endpoints that are already scoped to one repo and one capability grant. The
  ingestion tokens are the *tighter* control — a leaked gate token opens
  everything, a leaked ingestion token writes findings for one repo.
- **GitHub's webhook sender** cannot be given a custom header at all. That
  endpoint is authenticated by HMAC over the body, which is stronger than a
  shared bearer anyway.
- **Liveness probes**, which must work before anything is configured. The
  exemption covers the status code only: `/healthz` checks the token itself
  and shows the build SHA only to a caller that presents it (D-157).

That is the same reasoning the Hub's own gate uses for its OAuth callbacks and
webhooks: exempt the paths that carry their own proof, and only those.

**One kind of agent may read without it (TheHub #61954).** The security
champion and Delivery hold an agent credential and not this token, so every
check they needed - pending approvals, risk acceptances, findings - became an
operator script. A credential a *person* minted for one of
`AGENT_READ_PURPOSES` now passes on its own for the GETs in `AGENT_READ`, and
nothing else: any other method or path is a 403, every use is in the audit
log under the credential's actor and purpose, and the handler serves the
request as a viewer (`adminauth.READ_ONLY_AGENT`), so raw output stays
withheld and no write check can pass. A request that came through a proxy is
not offered this at all: there the token is still wanted.
"""

from __future__ import annotations

import hmac
import logging
import re
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response

from mykronos.adminauth import READ_ONLY_AGENT, Principal, current_principal
from mykronos.agents import TOKEN_PREFIX, resolve_agent_credential

logger = logging.getLogger(__name__)

#: Header, cookie and query-parameter names. Identical to the Hub's so a token
#: that works there works here without the operator learning a second scheme.
TOKEN_HEADER = "X-Hub-Token"
TOKEN_COOKIE = "hub_token"
TOKEN_QUERY = "_token"

#: Paths that authenticate themselves. Kept as a compiled pattern rather than
#: a prefix list so the boundaries are exact: `/api/ingest` must not also
#: exempt `/api/ingestion-admin` if somebody adds one later.
#:
#: [#60495] ADDING A SELF-AUTHENTICATING ROUTE MEANS ADDING IT HERE, IN THE
#: SAME EDIT. This middleware runs BEFORE routing and reads its token from
#: `X-Hub-Token` / the `hub_token` cookie / `?_token=` — never from
#: `Authorization: Bearer`. So a route that gates itself on a principal or a
#: per-repo token is still 401'd here, before its handler sees the credential
#: the caller is carrying, and the caller cannot tell that apart from being
#: refused on the merits.
#:
#: #60487 shipped `/api/oracle/decisions/by-commit/{sha}` without this line.
#: The deploy host asked, got `Not authorised for this host.`, and printed its
#: red COULD NOT ASK banner — correctly, and on every deploy, forever, because
#: nothing could ever clear it. Measured against f735cc2 on 2026-09-24.
#:
#: The same hazard exists in TheHub as `middleware/api_gate.py`'s
#: `EXEMPT_EXACT`, where it has now caught six endpoints across the two repos.
EXEMPT = re.compile(
    r"""^(
        /healthz                      # liveness, must work unconfigured
      | /api/ingest(/.*)?             # per-repo ingestion token
      | /api/oracle/evaluate          # per-repo ingestion token + oracle grant
      | /api/oracle/decisions/by-commit/[0-9a-fA-F]{7,40}
                                      # [#60495] principal auth (PrincipalDep)
      | /api/oracle/deploy-gate       # D-183, principal auth (PrincipalDep)
      | /api/patchwork/run            # per-repo ingestion token + patchwork grant
      | /api/repo-read/posture-summary
                                      # per-repo read token (api/repo_read.py)
      | /webhooks/github              # HMAC over the body
    )$""",
    re.VERBOSE,
)

#: [TheHub #61954] The purposes whose credential passes this gate on its own,
#: for `AGENT_READ` only. In code, not configuration, so widening it is a
#: reviewed change. The purpose counts only on a credential a person minted
#: (no lineage, not platform-started): an agent may mint a child with any
#: purpose it likes, and the approvals engine trusts one on the same terms.
AGENT_READ_PURPOSES = frozenset({"security-champion", "delivery"})

#: [TheHub #61954] The GETs such a credential may make without the token.
#: Reads of approvals, risk acceptances, findings, lane health and the
#: briefing, and `whoami`. Not the credential listing, the OpenAPI map, a raw
#: record or scan output, or anything under an admin path. Anchored, like
#: `EXEMPT`, so an entry never opens a neighbour.
AGENT_READ = re.compile(
    r"""^(
        /api/agents/whoami
      | /api/approvals
      | /api/approvals/(delegations|samples|shadow-reviews)
      | /api/approvals/delegations/[^/]+/stats
      | /api/approvals/[^/]+(/(evidence|chain))?
      | /api/risk-acceptances(/[^/]+)?
      | /api/dashboard/briefing
      | /api/briefing/(daily|weekly)
      | /api/dashboard/triage
      | /api/dashboard/findings/[^/]+
      | /api/dashboard/repos/[^/]+/(findings|open-findings|scan-health)
      | /api/dashboard/repos/[^/]+/risk-acceptances(/[^/]+)?
    )$""",
    re.VERBOSE,
)

#: Headers a proxy in front of this host adds. Cloudflare sets
#: `Cf-Connecting-Ip` at its edge and a client cannot strip it, so a request
#: carrying any of these came through the tunnel, and the one-secret path is
#: not offered there: from the internet, the token is still wanted.
PROXY_HEADERS = ("cf-connecting-ip", "cf-ray", "x-forwarded-for", "forwarded")


def presented_token(request: Request) -> str:
    """The token this request carries, from whichever carrier has one."""
    return (
        request.headers.get(TOKEN_HEADER, "")
        or request.cookies.get(TOKEN_COOKIE, "")
        or request.query_params.get(TOKEN_QUERY, "")
    )


def presents_token(request: Request, token: str) -> bool:
    """Whether this request carries `token`. Always False when no token is
    configured: an unset gate has no credential to present, which is not the
    same as every caller presenting it."""
    presented = presented_token(request)
    return bool(token) and bool(presented) and hmac.compare_digest(presented, token)


def is_exempt(path: str) -> bool:
    """Whether this path authenticates itself.

    A path containing `..` is never exempt, and the check comes first.
    `/api/ingest/../dashboard/portfolio` matches the ingestion pattern
    perfectly well — `(/.*)?` is happy to swallow `/../dashboard/portfolio` —
    which would have exempted the dashboard from the gate.

    It is not exploitable as things stand, because the router would not match
    the un-normalised path either and the request 404s. But "the layer behind
    it happens to reject this" is not a property of the auth check, it is a
    property of something else that could change. A traversal sequence in a
    URL has no legitimate use here, so it is refused outright rather than
    normalised and reasoned about.
    """
    if ".." in path:
        return False
    return EXEMPT.match(path) is not None


def is_agent_readable(method: str, path: str) -> bool:
    """Whether a scoped agent credential may make this request on its own.
    GET only (not HEAD), and never a path containing `..`, as for `is_exempt`."""
    if ".." in path:
        return False
    return method == "GET" and AGENT_READ.match(path) is not None


def scoped_agent(request: Request) -> Principal | None:
    """The agent this request may be let through for on its own credential.

    `None` unless the request came straight to this host (no proxy header),
    carries an `mka_` bearer that resolves to a live credential, and that
    credential was minted by a person for one of `AGENT_READ_PURPOSES`.
    """
    if any(name in request.headers for name in PROXY_HEADERS):
        return None
    scheme, _, credential = request.headers.get("Authorization", "").partition(" ")
    credential = credential.strip()
    if scheme.lower() != "bearer" or not credential.startswith(TOKEN_PREFIX):
        return None
    db = getattr(request.app.state, "db", None)
    principal = resolve_agent_credential(db, credential) if db is not None else None
    if principal is None:
        return None
    provenance = principal.provenance
    if (
        provenance.get("purpose") not in AGENT_READ_PURPOSES
        or provenance.get("lineage")
        or provenance.get("platform_started")
    ):
        return None
    return principal


def _audit_agent(request: Request, agent: Principal, action: str) -> None:
    """One audit entry per use, attributed to the agent (spec 34 §1). Written
    before the handler runs, so a use is recorded whatever the handler does."""
    db = request.app.state.db
    path = request.url.path[:512]
    token = current_principal.set(agent)
    try:
        with db.session() as session:
            db.audit(
                session,
                actor=agent.actor,
                action=action,
                entity_type="agent_credential",
                entity_id=str(agent.instance),
                method=request.method,
                path=path,
                purpose=agent.provenance.get("purpose"),
                instance=agent.instance,
            )
    finally:
        current_principal.reset(token)


class PerimeterGate(BaseHTTPMiddleware):
    """Reject anything that cannot present the shared token.

    Disabled when no token is configured, which is how it behaves in tests and
    on a laptop. That is safe here in a way it would not be for a bare
    application: the admin API underneath already refuses to serve without
    `MYKRONOS_ADMIN_TOKEN` (503, not 200), so an unconfigured deployment is
    unusable rather than open. This layer exists because the service is about
    to be reachable from the internet, not because it is the only lock.
    """

    def __init__(self, app: object, token: str = "") -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self.token = token

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if not self.token:
            return await call_next(request)

        path = request.url.path
        if is_exempt(path) or request.method == "OPTIONS":
            return await call_next(request)

        presented = presented_token(request)

        # [TheHub #61954] Only when no token was presented at all: a wrong
        # one is a 401 whatever else the request carries.
        agent = None if presented else scoped_agent(request)
        if agent is not None:
            if not is_agent_readable(request.method, path):
                _audit_agent(request, agent, "perimeter.agent_refused")
                logger.warning(
                    "Perimeter gate refused %s %s to %s: reads only",
                    request.method,
                    path,
                    agent.actor,
                )
                return JSONResponse(
                    {
                        "detail": "This agent credential may only read here without the "
                        "perimeter token (GET on mykronos.gate.AGENT_READ)."
                    },
                    status_code=403,
                )
            _audit_agent(request, agent, "perimeter.agent_read")
            setattr(request.state, READ_ONLY_AGENT, agent.actor)
            return await call_next(request)

        if not presents_token(request, self.token):
            # Deliberately terse, and identical whether the token was absent,
            # wrong, or malformed. A gate that explains itself to an
            # unauthenticated caller is a gate that helps them.
            logger.warning(
                "Perimeter gate rejected %s %s from %s",
                request.method,
                path,
                request.client.host if request.client else "unknown",
            )
            return JSONResponse(
                {"detail": "Not authorised for this host."},
                status_code=401,
                headers={"WWW-Authenticate": f'{TOKEN_HEADER} realm="mykronos"'},
            )

        # Arriving with `?_token=` means somebody followed a link. Set the
        # cookie and redirect to a clean URL so the token stops appearing in
        # the address bar, in browser history, and in any Referer this page
        # goes on to send.
        if request.query_params.get(TOKEN_QUERY):
            clean = request.url.remove_query_params(TOKEN_QUERY)
            response: Response = RedirectResponse(url=str(clean), status_code=302)
            over_https = (
                request.headers.get("X-Forwarded-Proto", request.url.scheme).lower()
                == "https"
            )
            response.set_cookie(
                TOKEN_COOKIE,
                presented,
                path="/",
                samesite="lax",
                max_age=86_400,
                # Secure behind the tunnel, where it is always HTTPS; not on
                # plain http://localhost, which would otherwise redirect-loop.
                secure=over_https,
                # The Hub's cookie is readable by its own JavaScript, which is
                # why it is not HttpOnly there. Nothing in this dashboard reads
                # it — every backend call is made server-side by Next — so it
                # can be HttpOnly here, and an XSS in the dashboard cannot
                # walk off with the credential that opens this host.
                httponly=True,
            )
            return response

        return await call_next(request)
