"""Every route, every kind of caller: who may reach what (spec 12).

Authorisation in this app is spread across three layers and several styles.
The route signature carries the coarse scheme (`PrincipalDep`, `AdminDep`,
`HumanDep`, the ingestion `require_token`, the webhook's HMAC); a principal
route that writes then checks `may_write` inside the handler, in whichever
style its module settled on (`_require_writer`, `require_admin(principal,
...)`, an inline `if not principal.may_write`). Each of those is tested where
it lives, one route at a time. Nothing tested them all at once, so a new
route that forgot its check could only be caught by the reviewer remembering
to look.

This file walks `create_app().routes` and holds every one of them to the
same three rules:

1. With no credential, or a wrong bearer token, the answer is 401 - unless the
   route is in `PUBLIC`, with its reason.
2. A **viewer** cannot write: every POST/PUT/PATCH/DELETE answers 401 or 403,
   never a 2xx and never a 5xx - unless the route is in `VIEWER_MAY_CALL`.
   A repo's **ingestion token**, even one granted every capability, reaches
   nothing but the routes in `INGESTION_TOKEN_MAY_CALL`. An **agent** is
   refused every route that only a person may take.
3. Every route is declared in `ROUTES` with the scheme its signature carries,
   and the declaration is checked against the dependency graph. A route that
   is not declared fails the meta-test, so a new route is classified on
   purpose, in review, rather than by default.

Requests carry syntactically valid dummy values - path parameters, required
query parameters and a JSON body built from the route's own OpenAPI schema -
so a handler's in-body `may_write` check is actually reached rather than the
request being turned away at validation with a 422 that proves nothing. The
dummies name nothing that exists, which is the point: a write check that
runs only after the resource is found answers a viewer 404 here, and that
fails rule 2 just as a 200 would, because with a real id it would be a 200.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from mykronos.capabilities import CONFIG_MODELS
from mykronos.config import Settings
from mykronos.main import create_app
from tests.conftest import ADMIN_TOKEN, REPO, VIEWER_TOKEN, WEBHOOK_SECRET, issue_token

MUTATING = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# --------------------------------------------------------------------------
# The classification. Every route the app serves appears in ROUTES exactly
# once; the exceptions below carry a one-line reason each.
# --------------------------------------------------------------------------

#: No credential at all (FastAPI's own docs, and the liveness probe).
PUBLIC_SCHEME = "public"
#: `PrincipalDep`: admin, viewer or agent. Writes check `may_write` in the handler.
PRINCIPAL = "principal"
#: `AdminDep`: a principal that `may_write` (admin or agent).
ADMIN = "admin"
#: `HumanDep`: a person with the admin role; never an agent.
HUMAN = "human"
#: `require_token`: one repository's ingestion token (D-009).
INGEST = "ingest-token"
#: HMAC over the body with the webhook secret.
HMAC = "hmac"
#: `require_read_token`: one repository's read token (`mkr_`), counts only.
READ_TOKEN = "repo-read-token"

ROUTES: dict[str, str] = {
    # -- ingestion (per-repo token) ----------------------------------------
    "GET /api/ingest/health": INGEST,
    "POST /api/ingest/netassess": INGEST,
    "POST /api/ingest/lane-failure": INGEST,
    "POST /api/ingest/scan-run": INGEST,
    "POST /api/ingest/findings": INGEST,
    "POST /api/ingest/raw": INGEST,
    "POST /api/ingest/aegis": INGEST,
    "POST /api/ingest/atlas": INGEST,
    "POST /api/ingest/reachability": INGEST,
    "POST /api/ingest/check-runs": INGEST,
    "POST /api/ingest/{capability}": INGEST,
    "POST /api/oracle/evaluate": INGEST,
    "POST /api/patchwork/run": INGEST,
    # -- dashboard ---------------------------------------------------------
    "GET /api/dashboard/portfolio": PRINCIPAL,
    "GET /api/dashboard/pull-requests": PRINCIPAL,
    "GET /api/dashboard/toxic-combinations": PRINCIPAL,
    "GET /api/dashboard/triage": PRINCIPAL,
    "GET /api/dashboard/trends": PRINCIPAL,
    "GET /api/dashboard/maturity": PRINCIPAL,
    "GET /api/dashboard/triage/throughput": PRINCIPAL,
    "POST /api/dashboard/triage/{finding_id}/claim": PRINCIPAL,
    "DELETE /api/dashboard/triage/{finding_id}/claim": PRINCIPAL,
    "POST /api/dashboard/triage/{finding_id}/snooze": PRINCIPAL,
    "DELETE /api/dashboard/triage/{finding_id}/snooze": PRINCIPAL,
    "POST /api/dashboard/triage/batch": PRINCIPAL,
    "GET /api/dashboard/repos/{repo_id}/insider-risk": PRINCIPAL,
    "GET /api/dashboard/vulnerability-management": PRINCIPAL,
    "GET /api/dashboard/repos/{repo_id}/ci": PRINCIPAL,
    "GET /api/dashboard/repos/{repo_id}/sscs": PRINCIPAL,
    "GET /api/dashboard/repos/{repo_id}/sscs/sbom": PRINCIPAL,
    "POST /api/dashboard/findings/{finding_id}/regression-test": PRINCIPAL,
    "GET /api/dashboard/repos/{repo_id}/regression-coverage": PRINCIPAL,
    "GET /api/dashboard/repos/{repo_id}/governance": PRINCIPAL,
    "GET /api/dashboard/incident": PRINCIPAL,
    "GET /api/dashboard/briefing": PRINCIPAL,
    "GET /api/dashboard/repos/{repo_id}/sscs/packages": PRINCIPAL,
    "GET /api/dashboard/repos/{repo_id}/threat-model": PRINCIPAL,
    "GET /api/dashboard/repos/{repo_id}/guidance": PRINCIPAL,
    "GET /api/dashboard/repos/{repo_id}/surfaces": PRINCIPAL,
    "POST /api/dashboard/repos/{repo_id}/surfaces": PRINCIPAL,
    "DELETE /api/dashboard/repos/{repo_id}/surfaces/{surface_id}": PRINCIPAL,
    "GET /api/dashboard/repos/{repo_id}/controls": PRINCIPAL,
    "POST /api/dashboard/repos/{repo_id}/controls": PRINCIPAL,
    "POST /api/dashboard/repos/{repo_id}/threat-model/sync": PRINCIPAL,
    "POST /api/dashboard/repos/{repo_id}/controls/{control_id}/confirm": PRINCIPAL,
    "DELETE /api/dashboard/repos/{repo_id}/controls/{control_id}": PRINCIPAL,
    "GET /api/dashboard/repos/{repo_id}/findings": PRINCIPAL,
    "GET /api/dashboard/repos/{repo_id}/open-findings": PRINCIPAL,
    "GET /api/dashboard/repos/{repo_id}/findings/export": PRINCIPAL,
    "GET /api/dashboard/repos/{repo_id}/scan-health": PRINCIPAL,
    "GET /api/dashboard/repos/{repo_id}/scan-runs/trend": PRINCIPAL,
    "GET /api/dashboard/repos/{repo_id}/scan-runs": PRINCIPAL,
    "GET /api/dashboard/scan-runs/{scan_run_id}": PRINCIPAL,
    "GET /api/dashboard/scan-runs/{scan_run_id}/raw/{filename}": PRINCIPAL,
    "GET /api/dashboard/findings/{finding_id}": PRINCIPAL,
    "POST /api/dashboard/findings/{finding_id}/classification-review": PRINCIPAL,
    "POST /api/dashboard/findings/{finding_id}/disposition-requests": PRINCIPAL,
    "POST /api/dashboard/findings/{finding_id}/reopen": PRINCIPAL,
    "PATCH /api/dashboard/findings/{finding_id}/status": PRINCIPAL,
    "PATCH /api/dashboard/findings/{finding_id}/owner": PRINCIPAL,
    "GET /api/dashboard/threat-intel": PRINCIPAL,
    "POST /api/dashboard/repos/{repo_id}/reown": PRINCIPAL,
    "GET /api/dashboard/findings/{finding_id}/record": PRINCIPAL,
    "POST /api/dashboard/inventory/reindex": PRINCIPAL,
    "GET /api/dashboard/libraries": PRINCIPAL,
    "GET /api/dashboard/repos/{repo_id}/risk-profile/proposal": PRINCIPAL,
    "GET /api/dashboard/repos/{repo_id}/ssdf": PRINCIPAL,
    "GET /api/dashboard/repos/{repo_id}/tests": PRINCIPAL,
    "GET /api/dashboard/repos/{repo_id}/consult": PRINCIPAL,
    "GET /api/dashboard/platform-health": PRINCIPAL,
    "GET /api/dashboard/deployments": PRINCIPAL,
    # -- product owner -----------------------------------------------------
    "GET /api/dashboard/repos/{repo_id}/product-owner": PRINCIPAL,
    "POST /api/dashboard/repos/{repo_id}/product-owner/stories/{story_id}/pull": PRINCIPAL,
    "POST /api/dashboard/repos/{repo_id}/product-owner/stories/{story_id}/return": PRINCIPAL,
    "POST /api/dashboard/repos/{repo_id}/product-owner/rank": PRINCIPAL,
    "POST /api/dashboard/repos/{repo_id}/product-owner/template": PRINCIPAL,
    "GET /api/dashboard/repos/{repo_id}/product-owner/delivery": PRINCIPAL,
    "GET /api/dashboard/repos/{repo_id}/product-owner/approvals": PRINCIPAL,
    "POST /api/dashboard/repos/{repo_id}/product-owner/approvals/{request_id}/decision": PRINCIPAL,
    "GET /api/dashboard/repos/{repo_id}/product-owner/roles": PRINCIPAL,
    "GET /api/dashboard/repos/{repo_id}/product-owner/retro": PRINCIPAL,
    "GET /api/dashboard/repos/{repo_id}/product-owner/trace": PRINCIPAL,
    "GET /api/dashboard/repos/{repo_id}/product-owner/fleet": PRINCIPAL,
    "GET /api/dashboard/product-owner/estate": PRINCIPAL,
    "GET /api/dashboard/product-owner/review-queue": PRINCIPAL,
    "GET /api/dashboard/product-owner/review-queue/{request_id}": PRINCIPAL,
    # -- exposure ----------------------------------------------------------
    "GET /api/exposure": PRINCIPAL,
    "POST /api/exposure/endpoints": PRINCIPAL,
    "DELETE /api/exposure/endpoints/{endpoint_id}": PRINCIPAL,
    "POST /api/exposure/probe": PRINCIPAL,
    # -- knowledge ---------------------------------------------------------
    "GET /api/knowledge/entries": PRINCIPAL,
    "POST /api/knowledge/notes": ADMIN,
    "GET /api/knowledge/retro": PRINCIPAL,
    "GET /api/knowledge/trend": PRINCIPAL,
    "GET /api/knowledge/promotion-candidates": PRINCIPAL,
    "POST /api/knowledge/promotion-candidates/{subject}/approve": ADMIN,
    # -- oracle ------------------------------------------------------------
    "GET /api/oracle/policy": PRINCIPAL,
    "GET /api/oracle/policy/history": PRINCIPAL,
    "GET /api/oracle/shadow-mode": PRINCIPAL,
    "GET /api/oracle/environmental-shadow": PRINCIPAL,
    "GET /api/oracle/term-analytics": PRINCIPAL,
    "GET /api/oracle/decisions/by-commit/{commit_sha}": PRINCIPAL,
    "GET /api/oracle/decisions/{repo_id}": PRINCIPAL,
    "POST /api/oracle/decisions/{decision_id}/override": HUMAN,
    # -- patchwork ---------------------------------------------------------
    "POST /api/patchwork/findings/{finding_id}/preview": PRINCIPAL,
    "POST /api/patchwork/findings/{finding_id}/fix": PRINCIPAL,
    "GET /api/patchwork/digest": PRINCIPAL,
    "GET /api/patchwork/efficacy": PRINCIPAL,
    "GET /api/patchwork/repos/{repo_id}": PRINCIPAL,
    # -- onboarding --------------------------------------------------------
    "GET /api/repos/-/capabilities": ADMIN,
    "POST /api/repos": ADMIN,
    "GET /api/repos": ADMIN,
    "GET /api/repos/{repo_id}": ADMIN,
    "PATCH /api/repos/{repo_id}": ADMIN,
    "PUT /api/repos/{repo_id}/deployment-probe": ADMIN,
    "PATCH /api/repos/{repo_id}/capabilities": ADMIN,
    "DELETE /api/repos/{repo_id}": ADMIN,
    "POST /api/repos/{repo_id}/scan": ADMIN,
    "GET /api/repos/{repo_id}/workflows": ADMIN,
    "PUT /api/repos/{repo_id}/workflows/{capability}/enable": ADMIN,
    "PUT /api/repos/{repo_id}/workflows/{capability}/disable": ADMIN,
    "GET /api/repos/{repo_id}/reachability": PRINCIPAL,
    "GET /api/repos/{repo_id}/risk-profile": PRINCIPAL,
    "PUT /api/repos/{repo_id}/risk-profile": ADMIN,
    # -- triage ------------------------------------------------------------
    "POST /api/triage/{finding_id}/groom": ADMIN,
    "POST /api/triage/repos/{repo_id}/combinations/{combination_id}/groom": ADMIN,
    # -- webhooks ----------------------------------------------------------
    "POST /webhooks/github": HMAC,
    # -- agents ------------------------------------------------------------
    "POST /api/agents/credentials": PRINCIPAL,
    "GET /api/agents/whoami": PRINCIPAL,
    "GET /api/agents/credentials": PRINCIPAL,
    "POST /api/agents/credentials/{instance}/revoke": HUMAN,
    # -- repo read tokens --------------------------------------------------
    "GET /api/repo-read/posture-summary": READ_TOKEN,
    "POST /api/repo-read/tokens": HUMAN,
    "GET /api/repo-read/tokens": HUMAN,
    "POST /api/repo-read/tokens/{token_id}/revoke": HUMAN,
    "GET /api/agent/work": PRINCIPAL,
    "GET /api/agent/scorecard": PRINCIPAL,
    "GET /api/agent/playbooks": PRINCIPAL,
    "GET /api/agent/playbooks/{kind}": PRINCIPAL,
    # -- approvals ---------------------------------------------------------
    "POST /api/approvals": PRINCIPAL,
    "GET /api/approvals": PRINCIPAL,
    "GET /api/approvals/delegations": PRINCIPAL,
    "POST /api/approvals/delegations": HUMAN,
    "POST /api/approvals/delegations/{delegation_id}/revoke": HUMAN,
    "POST /api/approvals/pull-requests": PRINCIPAL,
    "GET /api/approvals/samples": PRINCIPAL,
    "POST /api/approvals/samples/{decision_id}": HUMAN,
    "GET /api/approvals/delegations/{delegation_id}/stats": PRINCIPAL,
    "GET /api/approvals/shadow-reviews": PRINCIPAL,
    "POST /api/approvals/{request_id}/independent-review": PRINCIPAL,
    "GET /api/approvals/{request_id}": PRINCIPAL,
    "GET /api/approvals/{request_id}/evidence": PRINCIPAL,
    "POST /api/approvals/{request_id}/decisions": PRINCIPAL,
    "GET /api/approvals/{request_id}/chain": PRINCIPAL,
    # -- risk acceptances --------------------------------------------------
    "POST /api/risk-acceptances": PRINCIPAL,
    "GET /api/risk-acceptances": PRINCIPAL,
    "POST /api/risk-acceptances/migrate-legacy": PRINCIPAL,
    "GET /api/risk-acceptances/{record_id}": PRINCIPAL,
    "POST /api/risk-acceptances/{record_id}/renew": PRINCIPAL,
    "POST /api/risk-acceptances/{record_id}/revoke": HUMAN,
    # -- public ------------------------------------------------------------
    "GET /healthz": PUBLIC_SCHEME,
    "GET /openapi.json": PUBLIC_SCHEME,
    "GET /docs": PUBLIC_SCHEME,
    "GET /docs/oauth2-redirect": PUBLIC_SCHEME,
    "GET /redoc": PUBLIC_SCHEME,
}

#: Rule 1's exceptions: routes that answer a caller with no credential.
PUBLIC: dict[str, str] = {
    "GET /healthz": "liveness probe; works unconfigured, SHA only for a gate holder (D-157)",
    "GET /openapi.json": "API schema of a public repo; the perimeter gate covers it if configured",
    "GET /docs": "Swagger UI over /openapi.json; no data, gated by the perimeter where configured",
    "GET /docs/oauth2-redirect": "Swagger UI's static OAuth helper page; no data",
    "GET /redoc": "ReDoc over /openapi.json; no data, gated by the perimeter where configured",
}

#: Rule 2's viewer exceptions: writes-by-verb a viewer may call.
VIEWER_MAY_CALL: dict[str, str] = {
    "POST /api/patchwork/findings/{finding_id}/preview": (
        "read-ish POST: preview_only writes nothing to GitHub or to the platform (spec 18 §7.2)"
    ),
}

#: Rule 2's ingestion-token exceptions: the routes a repo token authenticates.
INGESTION_TOKEN_MAY_CALL: dict[str, str] = {
    "GET /api/ingest/health": "a workflow's first call; reports lake writability for its own repo",
    "POST /api/ingest/netassess": "netassess capability upload, grant-checked",
    "POST /api/ingest/lane-failure": "a lane reporting its own failure for its own repo",
    "POST /api/ingest/scan-run": "scan-run envelope upload, grant-checked against the capability",
    "POST /api/ingest/findings": "findings upload, grant-checked against the capability",
    "POST /api/ingest/raw": "raw tool output archive for the token's own scan run",
    "POST /api/ingest/aegis": "aegis capability upload, grant-checked",
    "POST /api/ingest/atlas": "atlas capability upload, grant-checked",
    "POST /api/ingest/reachability": "reachability upload for the token's own repo",
    "POST /api/ingest/check-runs": "CI check-run upload for the token's own repo",
    "POST /api/ingest/{capability}": "generic capability upload, grant-checked (or 501)",
    "POST /api/oracle/evaluate": "the risk gate a pipeline asks; needs the oracle grant",
    "POST /api/patchwork/run": "auto-remediation a pipeline starts; needs the patchwork grant",
}

#: Rule 2's agent exceptions would go here; an agent may write wherever an
#: admin may (Role.AGENT may_write), so the agent rule is the inverse: every
#: HUMAN route refuses it. Agent-allowed writes such as disposition-requests
#: and risk-acceptance propose are ordinary PRINCIPAL writes.


# --------------------------------------------------------------------------
# The app, and the three callers held to the rules.
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def matrix(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, Any]]:
    """One app for the whole matrix: ~600 requests against one start-up."""
    root: Path = tmp_path_factory.mktemp("authz-matrix")
    settings = Settings(
        datalake_dir=root / "datalake",
        database_url=f"sqlite:///{(root / 'mykronos.db').as_posix()}",
        run_compaction_in_background=False,
        run_jobs_in_background=False,
        admin_token=ADMIN_TOKEN,
        viewer_token=VIEWER_TOKEN,
        github_webhook_secret=WEBHOOK_SECRET,
        # Pinned off: this matrix tests the routes, not the perimeter in front
        # of them (test_gate.py). With the gate on, every non-exempt route is
        # 401 before its own auth runs, and the matrix would prove nothing.
        gate_token="",
        github_app_id="",
        github_app_private_key_path=None,
        # The token below is called once per route; the limiter is not the
        # control under test.
        rate_limit_requests_per_minute=100_000,
    )
    app = create_app(settings)
    with TestClient(app) as client:
        # The strongest ingestion token there is: every capability granted.
        token = issue_token(client, REPO, *sorted(CONFIG_MODELS))
        minted = client.post(
            "/api/agents/credentials",
            json={"family": "claude-opus-5.5", "purpose": "authz-matrix"},
            headers=_bearer(ADMIN_TOKEN),
        )
        assert minted.status_code == 201, minted.text
        read = client.post(
            "/api/repo-read/tokens",
            json={"repo_full_name": REPO, "label": "authz-matrix"},
            headers=_bearer(ADMIN_TOKEN),
        )
        assert read.status_code == 201, read.text
        yield {
            "app": app,
            "client": client,
            "spec": app.openapi(),
            "viewer": _bearer(VIEWER_TOKEN),
            "token": _bearer(token),
            "agent": _bearer(minted.json()["token"]),
            "read": _bearer(read.json()["token"]),
        }


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _served_routes(app: FastAPI) -> dict[str, Any]:
    """Every `METHOD path` the app serves, mapped to its route.

    Recent FastAPI keeps an included router as one entry in `app.routes` and
    flattens it through `iter_route_contexts` (see test_playbooks.py); older
    versions list every route directly. HEAD is left out: Starlette adds it
    beside GET on the docs routes, and it answers whatever GET answers.
    """
    import fastapi.routing

    walk = getattr(fastapi.routing, "iter_route_contexts", None)
    routes = list(walk(app.routes)) if walk is not None else list(app.routes)
    served: dict[str, Any] = {}
    for route in routes:
        path = getattr(route, "path", None)
        for method in getattr(route, "methods", None) or ():
            if path and method != "HEAD":
                served[f"{method} {path}"] = route
    return served


def _derived_scheme(route: Any) -> str:
    """The scheme a route's dependency graph actually carries."""
    original = getattr(route, "original_route", route)
    if not isinstance(original, APIRoute):
        return PUBLIC_SCHEME
    names: set[str] = set()
    stack = list(original.dependant.dependencies)
    while stack:
        dep = stack.pop()
        names.add(getattr(dep.call, "__name__", ""))
        stack.extend(dep.dependencies)
    if "require_human" in names:
        return HUMAN
    if "require_admin" in names:
        return ADMIN
    if "require_principal" in names:
        return PRINCIPAL
    if "require_token" in names:
        return INGEST
    if "require_read_token" in names:
        return READ_TOKEN
    # No auth dependency. The webhook authenticates its body itself; anything
    # else with no dependency is public, and must be declared so.
    return HMAC if original.path.startswith("/webhooks/") else PUBLIC_SCHEME


# --------------------------------------------------------------------------
# Dummy requests: valid enough to reach the handler, naming nothing real.
# --------------------------------------------------------------------------

DUMMY_ID = str(uuid.UUID(int=1))

#: Strings tried, in order, against a `pattern` the schema imposes.
_PATTERN_CANDIDATES = (
    DUMMY_ID,
    "x",
    REPO,
    "a" * 40,
    "sast",
    "approve",
    "https://example.test",
)


def _string_for(schema: dict[str, Any]) -> str:
    fmt = schema.get("format")
    if fmt == "uuid":
        return DUMMY_ID
    if fmt == "date-time":
        return "2030-01-01T00:00:00"
    if fmt == "date":
        return "2030-01-01"
    pattern = schema.get("pattern")
    if pattern:
        # `^(approve|reject)$` and friends: the first alternative is a value.
        alternatives = re.fullmatch(r"\^\(([\w|-]+)\)\$", pattern)
        candidates = ((alternatives.group(1).split("|")[0],) if alternatives else ()) + (
            _PATTERN_CANDIDATES
        )
        for candidate in candidates:
            if re.search(pattern, candidate):
                return candidate
    return "x" * max(1, int(schema.get("minLength", 1)))


def _example(schema: dict[str, Any], defs: dict[str, Any], depth: int = 0) -> Any:
    """A minimal instance of a JSON schema: required fields only."""
    if depth > 10:
        return None
    if "$ref" in schema:
        return _example(defs[schema["$ref"].rsplit("/", 1)[-1]], defs, depth + 1)
    if "const" in schema:
        return schema["const"]
    if "enum" in schema:
        return schema["enum"][0]
    if schema.get("default") is not None:
        return schema["default"]
    for key in ("anyOf", "oneOf", "allOf"):
        if key in schema:
            options = [o for o in schema[key] if o.get("type") != "null"]
            return _example(options[0], defs, depth + 1) if options else None
    kind = schema.get("type")
    if kind == "object" or "properties" in schema:
        properties = schema.get("properties", {})
        return {
            name: _example(properties.get(name, {}), defs, depth + 1)
            for name in schema.get("required", [])
        }
    if kind == "array":
        return [
            _example(schema.get("items", {}), defs, depth + 1)
            for _ in range(int(schema.get("minItems", 0)))
        ]
    if kind == "string":
        return _string_for(schema)
    if kind == "integer":
        return max(1, int(schema.get("minimum", 1)))
    if kind == "number":
        return 1.0
    if kind == "boolean":
        return False
    return None


def _request(matrix: dict[str, Any], key: str, headers: dict[str, str]) -> Any:
    """Send `METHOD path` with dummy parameters and body."""
    method, path = key.split(" ", 1)
    spec = matrix["spec"]
    defs = spec.get("components", {}).get("schemas", {})
    operation = spec.get("paths", {}).get(path, {}).get(method.lower(), {})

    url = path
    query: dict[str, Any] = {}
    for param in operation.get("parameters", []):
        value = _example(param.get("schema", {}), defs)
        if param.get("in") == "path":
            url = url.replace("{" + param["name"] + "}", str(value))
        elif param.get("in") == "query" and param.get("required"):
            query[param["name"]] = value
    # Any path parameter the schema did not describe still needs filling.
    url = re.sub(r"\{[^}]+\}", DUMMY_ID, url)

    body = None
    content = (operation.get("requestBody") or {}).get("content", {})
    if "application/json" in content:
        body = _example(content["application/json"].get("schema", {}), defs)

    client: TestClient = matrix["client"]
    return client.request(method, url, headers=headers, params=query, json=body)


ALL = sorted(ROUTES)
NOT_PUBLIC = [k for k in ALL if k not in PUBLIC]
MUTATING_ROUTES = [k for k in ALL if k.split(" ", 1)[0] in MUTATING]
VIEWER_DENIED = [k for k in MUTATING_ROUTES if k not in VIEWER_MAY_CALL]
TOKEN_DENIED = [k for k in ALL if k not in INGESTION_TOKEN_MAY_CALL and k not in PUBLIC]
TOKEN_ALLOWED = sorted(INGESTION_TOKEN_MAY_CALL)
HUMAN_ONLY = [k for k in ALL if ROUTES[k] == HUMAN]
READ_ALLOWED = [k for k in ALL if ROUTES[k] == READ_TOKEN]
READ_DENIED = [k for k in ALL if ROUTES[k] != READ_TOKEN and k not in PUBLIC]


def _say(response: Any) -> str:
    return f"{response.status_code}: {response.text[:300]}"


# --------------------------------------------------------------------------
# Rule 3: the classification is complete and true.
# --------------------------------------------------------------------------


class TestTheClassification:
    def test_every_served_route_is_classified(self, matrix: dict[str, Any]) -> None:
        """A new route fails here until it is added to ROUTES on purpose."""
        served = set(_served_routes(matrix["app"]))
        unclassified = sorted(served - set(ROUTES))
        assert not unclassified, (
            "Routes with no entry in ROUTES - classify each one, and add it to "
            "PUBLIC / VIEWER_MAY_CALL / INGESTION_TOKEN_MAY_CALL only with a reason: "
            f"{unclassified}"
        )

    def test_every_classified_route_is_served(self, matrix: dict[str, Any]) -> None:
        """A removed or renamed route leaves a stale entry; drop it."""
        stale = sorted(set(ROUTES) - set(_served_routes(matrix["app"])))
        assert not stale, f"ROUTES names routes the app no longer serves: {stale}"

    def test_the_declared_scheme_is_the_one_the_route_carries(
        self, matrix: dict[str, Any]
    ) -> None:
        """A route quietly moved from AdminDep to PrincipalDep fails here."""
        served = _served_routes(matrix["app"])
        wrong = {
            key: f"declared {ROUTES[key]}, carries {_derived_scheme(route)}"
            for key, route in served.items()
            if key in ROUTES and _derived_scheme(route) != ROUTES[key]
        }
        assert not wrong, wrong

    def test_the_exceptions_name_classified_routes(self) -> None:
        for name, exceptions in (
            ("PUBLIC", PUBLIC),
            ("VIEWER_MAY_CALL", VIEWER_MAY_CALL),
            ("INGESTION_TOKEN_MAY_CALL", INGESTION_TOKEN_MAY_CALL),
        ):
            assert set(exceptions) <= set(ROUTES), (name, sorted(set(exceptions) - set(ROUTES)))
            assert all(reason.strip() for reason in exceptions.values()), name

    def test_public_is_exactly_the_routes_with_no_auth(self) -> None:
        assert set(PUBLIC) == {k for k, v in ROUTES.items() if v == PUBLIC_SCHEME}

    def test_the_token_reaches_exactly_the_token_routes(self) -> None:
        assert set(INGESTION_TOKEN_MAY_CALL) == {k for k, v in ROUTES.items() if v == INGEST}

    def test_a_viewer_exception_is_a_principal_route(self) -> None:
        """An AdminDep/HumanDep route a viewer may call is a contradiction."""
        assert all(ROUTES[k] == PRINCIPAL for k in VIEWER_MAY_CALL)

    def test_the_matrix_is_not_empty(self) -> None:
        """Guards against a parametrisation that silently collects nothing."""
        assert len(ALL) > 100
        assert len(VIEWER_DENIED) > 50
        assert HUMAN_ONLY


# --------------------------------------------------------------------------
# Rule 1: no credential, no entry.
# --------------------------------------------------------------------------


class TestUnauthenticated:
    @pytest.mark.parametrize("key", NOT_PUBLIC, ids=NOT_PUBLIC)
    def test_no_credential_is_401(self, matrix: dict[str, Any], key: str) -> None:
        response = _request(matrix, key, {})
        assert response.status_code == 401, _say(response)

    @pytest.mark.parametrize("key", NOT_PUBLIC, ids=NOT_PUBLIC)
    def test_a_wrong_bearer_is_401(self, matrix: dict[str, Any], key: str) -> None:
        response = _request(matrix, key, _bearer("not-a-token-anyone-issued"))
        assert response.status_code == 401, _say(response)


# --------------------------------------------------------------------------
# Rule 2: a viewer cannot write; a repo token reaches only ingestion; an agent
# cannot take a person's decision.
# --------------------------------------------------------------------------


class TestAViewerCannotWrite:
    @pytest.mark.parametrize("key", VIEWER_DENIED, ids=VIEWER_DENIED)
    def test_refused(self, matrix: dict[str, Any], key: str) -> None:
        response = _request(matrix, key, matrix["viewer"])
        assert response.status_code in (401, 403), _say(response)

    @pytest.mark.parametrize("key", sorted(VIEWER_MAY_CALL), ids=sorted(VIEWER_MAY_CALL))
    def test_an_allowed_call_does_not_crash(self, matrix: dict[str, Any], key: str) -> None:
        response = _request(matrix, key, matrix["viewer"])
        assert response.status_code < 500, _say(response)


class TestAnIngestionTokenReachesOnlyIngestion:
    @pytest.mark.parametrize("key", TOKEN_DENIED, ids=TOKEN_DENIED)
    def test_refused(self, matrix: dict[str, Any], key: str) -> None:
        response = _request(matrix, key, matrix["token"])
        assert response.status_code in (401, 403), _say(response)

    @pytest.mark.parametrize("key", TOKEN_ALLOWED, ids=TOKEN_ALLOWED)
    def test_an_allowed_call_does_not_crash(self, matrix: dict[str, Any], key: str) -> None:
        """501 is a deliberate answer (a capability with no ingestion yet);
        500 is a crash."""
        response = _request(matrix, key, matrix["token"])
        assert response.status_code != 500, _say(response)
        assert response.status_code not in (401, 403), _say(response)


class TestARepoReadTokenReachesOnlyItsSummary:
    """Read-only and one repository: it opens nothing else, write or read."""

    @pytest.mark.parametrize("key", READ_DENIED, ids=READ_DENIED)
    def test_refused(self, matrix: dict[str, Any], key: str) -> None:
        response = _request(matrix, key, matrix["read"])
        assert response.status_code in (401, 403), _say(response)

    @pytest.mark.parametrize("key", READ_ALLOWED, ids=READ_ALLOWED)
    def test_its_own_route_answers(self, matrix: dict[str, Any], key: str) -> None:
        response = _request(matrix, key, matrix["read"])
        assert response.status_code == 200, _say(response)


class TestAnAgentCannotTakeAPersonsDecision:
    @pytest.mark.parametrize("key", HUMAN_ONLY, ids=HUMAN_ONLY)
    def test_refused(self, matrix: dict[str, Any], key: str) -> None:
        response = _request(matrix, key, matrix["agent"])
        assert response.status_code == 403, _say(response)
