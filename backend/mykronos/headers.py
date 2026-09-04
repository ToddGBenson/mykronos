"""Security response headers for the API (B-025).

The frontend has had these since `next.config.ts` grew a `headers()` block.
The backend never did, and nobody noticed for a simple reason: the DAST lane
had been failing for two days, so no scan had reported the API in a fortnight.
The first successful run after the lane was repaired returned 69 findings, and
the ones that reproduce are all at backend paths — `/healthz`,
`/api/dashboard/trends` — not frontend ones.

**An API's headers are not a page's headers, and copying the frontend's would
be wrong.** This service returns JSON to programs. It has no markup to
sandbox, no styles to allow and no fonts to fetch, so its CSP is the empty
one: `default-src 'none'`. A policy that permits `'self'` scripts on an
endpoint that never serves a script is a policy that would let one run.

`Strict-Transport-Security` is deliberately absent. TLS terminates at the
reverse proxy in front of this service, so the header belongs there — setting
it here would either be stripped or, worse, be served over plain HTTP on the
LAN and pin a browser to a scheme this port does not speak.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

#: Applied to every response. Static, because a header that varies per route
#: is a header somebody has to reason about per route.
SECURITY_HEADERS: dict[str, str] = {
    # Nothing here is meant to be framed. The API returns JSON.
    "X-Frame-Options": "DENY",
    # The one that matters most for an API: a JSON body a browser is allowed
    # to sniff can be coaxed into being interpreted as something executable.
    "X-Content-Type-Options": "nosniff",
    # An API has no markup, so it needs no source permitted at all. This is
    # stricter than the frontend's on purpose — see the module docstring.
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    # A finding id in a path is not something to hand to another origin.
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
    # ZAP reports the presence of a version-bearing `Server` header, and
    # Uvicorn sends `uvicorn`. This value is only half the fix and cannot be
    # the whole of it: uvicorn appends its own copy *after* the application
    # returns, so setting one here leaves the response carrying two `Server`
    # headers, one of them still naming the server. The Dockerfile passes
    # `--no-server-header` for that reason; this line then supplies the single
    # uninformative value that remains.
    #
    # It was visible only on a live container. Starlette's TestClient never
    # adds uvicorn's copy, so the test for this passed while production sent
    # both — which is why `test_the_server_header_is_disabled_at_the_server`
    # asserts on the Dockerfile rather than on a response.
    "Server": "mykronos",
}


#: The two documentation UIs FastAPI serves. They are the one part of this
#: service that is a page rather than an API, and `default-src 'none'` blanks
#: them: Swagger and ReDoc both load a script and a stylesheet from a CDN.
#: Exempting them beats the two alternatives — shipping a policy that breaks
#: the docs, or weakening the policy everywhere to accommodate two paths.
DOC_PATHS = frozenset({"/docs", "/redoc", "/docs/oauth2-redirect"})

#: What those two pages actually need: FastAPI's bundled UIs pull from
#: jsdelivr, and Swagger's inline initialiser needs `unsafe-inline`. Narrow to
#: the sources in use rather than reaching for `*`.
DOC_CSP = (
    "default-src 'none'; "
    "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
    "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
    "img-src 'self' https://fastapi.tiangolo.com data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'"
)


class SecurityHeaders(BaseHTTPMiddleware):
    """Set the headers above on every response, including error responses.

    Errors especially. A 401 from the perimeter gate is still a response a
    browser renders, and the scan that reported this counted 404s and 405s
    among the offending paths — so this has to sit outside the gate rather
    than behind it.

    Nothing here overwrites a header a handler set deliberately, with the one
    exception of `Server` — which is set by the ASGI server rather than by any
    handler, and is the thing being corrected.
    """

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        for header, value in SECURITY_HEADERS.items():
            if header == "Server" or header not in response.headers:
                response.headers[header] = value

        if request.url.path in DOC_PATHS:
            response.headers["Content-Security-Policy"] = DOC_CSP
        return response
