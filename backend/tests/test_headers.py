"""Security response headers on the API (B-025).

The frontend has had these for a while. The backend never did, and it took a
repaired DAST lane to say so: the first successful scan in a fortnight
returned 69 findings, and the ones that reproduced were all at backend paths —
`/healthz`, `/api/dashboard/trends` — rather than frontend ones.
"""

from __future__ import annotations

import pytest

from mykronos.headers import DOC_PATHS, SECURITY_HEADERS


class TestEveryResponseCarriesThem:
    def test_a_plain_200(self, client) -> None:
        response = client.get("/healthz")

        assert response.status_code == 200
        for header, value in SECURITY_HEADERS.items():
            assert response.headers.get(header) == value, f"{header} missing on 200"

    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("/no-such-path", 404),
            ("/healthz", 405),  # via POST below — the scan counted these too
        ],
    )
    def test_error_responses_too(self, client, path: str, expected: int) -> None:
        """A 404 is still a response a browser renders.

        ZAP reported `/healthz` and unrouted paths among the offending ones,
        so headers applied only on the success path would have closed none of
        them.
        """
        response = client.post(path) if expected == 405 else client.get(path)

        assert response.status_code == expected
        assert response.headers.get("X-Content-Type-Options") == "nosniff"
        assert response.headers.get("X-Frame-Options") == "DENY"

    def test_the_server_header_no_longer_names_the_server(self, client) -> None:
        response = client.get("/healthz")

        assert response.headers.get("Server") == "mykronos"
        assert "uvicorn" not in response.headers.get("Server", "").lower()

    def test_the_server_header_is_disabled_at_the_server(self) -> None:
        """The half of this the application cannot do, asserted where it lives.

        Uvicorn appends `server: uvicorn` *after* the app returns, so the
        middleware above does not replace it — the response carries two
        `Server` headers and one still names the server. The test above passed
        anyway, because Starlette's TestClient never adds uvicorn's copy: it
        was visible only on a live container.

        So this asserts on the Dockerfile. A test that can only pass in an
        environment the suite does not run in is worth less than one that pins
        the flag which makes it true.
        """
        from pathlib import Path

        dockerfile = Path(__file__).resolve().parents[1] / "Dockerfile"
        assert "--no-server-header" in dockerfile.read_text(encoding="utf-8"), (
            "uvicorn will append its own Server header and the app cannot stop it"
        )


class TestThePolicyFitsAnApi:
    def test_the_csp_permits_nothing(self) -> None:
        """An API returns JSON to programs. It has no markup to sandbox and no
        scripts to allow, so permitting `'self'` scripts on an endpoint that
        never serves one is permitting a script to run."""
        assert SECURITY_HEADERS["Content-Security-Policy"] == (
            "default-src 'none'; frame-ancestors 'none'"
        )

    def test_hsts_is_not_set_here(self) -> None:
        """TLS terminates at the proxy in front of this service, so the header
        belongs there. Served from here over plain HTTP on the LAN it would
        pin a browser to a scheme this port does not speak."""
        assert not any(h.lower() == "strict-transport-security" for h in SECURITY_HEADERS)

    def test_the_docs_ui_still_works(self, client) -> None:
        """`default-src 'none'` blanks Swagger and ReDoc — both load a script
        and a stylesheet from a CDN. Exempting two paths beats shipping a
        policy that breaks the docs, and beats weakening the policy
        everywhere to accommodate them."""
        for path in ("/docs", "/redoc"):
            csp = client.get(path).headers.get("Content-Security-Policy", "")
            assert "cdn.jsdelivr.net" in csp, f"{path} would render blank"
            assert "frame-ancestors 'none'" in csp, f"{path} lost its framing guard"

    def test_the_exemption_is_only_those_paths(self, client) -> None:
        """A doc-shaped policy leaking onto the API would undo the point."""
        assert "/api/dashboard/portfolio" not in DOC_PATHS
        csp = client.get("/healthz").headers.get("Content-Security-Policy")
        assert csp == SECURITY_HEADERS["Content-Security-Policy"]
        assert "jsdelivr" not in (csp or "")
