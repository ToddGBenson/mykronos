"""Perimeter gate — the same credential that opens the Hub opens Mykronos.

The Hub (a sibling service on this host) fronts itself with a static token
presented as `X-Hub-Token`, a `hub_token` cookie, or a `?_token=` query
parameter. This mirrors that exactly, against the same secret, so one
credential reaches both and browser sessions behave the same way on each.

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
- **Liveness probes**, which must work before anything is configured.

That is the same reasoning the Hub's own gate uses for its OAuth callbacks and
webhooks: exempt the paths that carry their own proof, and only those.
"""

from __future__ import annotations

import hmac
import logging
import re
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response

logger = logging.getLogger(__name__)

#: Header, cookie and query-parameter names. Identical to the Hub's so a token
#: that works there works here without the operator learning a second scheme.
TOKEN_HEADER = "X-Hub-Token"
TOKEN_COOKIE = "hub_token"
TOKEN_QUERY = "_token"

#: Paths that authenticate themselves. Kept as a compiled pattern rather than
#: a prefix list so the boundaries are exact: `/api/ingest` must not also
#: exempt `/api/ingestion-admin` if somebody adds one later.
EXEMPT = re.compile(
    r"""^(
        /healthz                      # liveness, must work unconfigured
      | /api/ingest(/.*)?             # per-repo ingestion token
      | /api/oracle/evaluate          # per-repo ingestion token + oracle grant
      | /api/patchwork/run            # per-repo ingestion token + patchwork grant
      | /webhooks/github              # HMAC over the body
    )$""",
    re.VERBOSE,
)


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

        presented = (
            request.headers.get(TOKEN_HEADER, "")
            or request.cookies.get(TOKEN_COOKIE, "")
            or request.query_params.get(TOKEN_QUERY, "")
        )

        if not presented or not hmac.compare_digest(presented, self.token):
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
                # walk off with the credential that opens the Hub as well.
                httponly=True,
            )
            return response

        return await call_next(request)
