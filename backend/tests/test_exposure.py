"""What a public endpoint shows anyone who asks (mykronos.exposure).

On 2026-10-01 the demo's full API schema and a Concourse server were both on
the internet through a tunnel, and both were declared `internal`. These pin
the observation that would have said otherwise, and its limits.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import select

from mykronos import briefing as briefing_report
from mykronos import exposure
from mykronos.db.models import AuditLogEntry, PublicEndpoint
from mykronos.exposure import Answer, classify

SCHEMA = {
    "openapi": "3.1.0",
    "paths": {
        "/api/items": {"get": {}, "post": {}},
        "/api/admin/env/{key}": {"put": {}, "delete": {}},
        "/health": {"get": {}},
    },
}


def _ok(body: Any, content_type: str = "application/json") -> Answer:
    text = body if isinstance(body, str) else json.dumps(body)
    return Answer(status=200, content_type=content_type, body=text)


class TestClassify:
    def test_a_public_schema_with_writes_is_high_and_names_admin_writes(self) -> None:
        (obs,) = classify({"/openapi.json": _ok(SCHEMA)})

        assert obs.kind == "api_schema_public"
        assert obs.severity == "high"
        assert obs.evidence["operations"] == 5 and obs.evidence["writes"] == 3
        assert obs.evidence["admin_writes"] == ["/api/admin/env/{key}"]

    def test_a_read_only_schema_is_medium(self) -> None:
        (obs,) = classify({"/openapi.json": _ok({"paths": {"/health": {"get": {}}}})})

        assert obs.severity == "medium"

    def test_a_gated_endpoint_shows_nothing(self) -> None:
        """Production answers 401 to the same requests: nothing to report."""
        refused = Answer(status=401, body='{"detail":"Not authorised"}')
        answers = {path: refused for path in exposure.PATHS}

        assert classify(answers) == []

    def test_an_html_catch_all_is_not_a_schema(self) -> None:
        """A SPA that answers every path with its index page has not published
        an API description; stretching the rule to it would cry wolf."""
        page = _ok("<!doctype html><html><body>app</body></html>", "text/html")

        assert classify({"/openapi.json": page, "/docs": page}) == []

    def test_swagger_docs_are_medium(self) -> None:
        docs = _ok("<html><script src='swagger-ui-bundle.js'></script></html>", "text/html")

        (obs,) = classify({"/docs": docs})

        assert obs.kind == "api_docs_public" and obs.severity == "medium"

    def test_a_public_concourse_names_its_public_pipelines(self) -> None:
        answers = {
            "/api/v1/info": _ok({"version": "8.3.1", "worker_version": "3.0"}),
            "/api/v1/teams/main/pipelines": _ok(
                [{"name": "thehub", "public": True}, {"name": "secret", "public": False}]
            ),
        }

        (obs,) = classify(answers)

        assert obs.kind == "ci_public" and obs.severity == "high"
        assert obs.evidence["public_pipelines"] == ["thehub"]


class FakeResponse:
    def __init__(self, status: int, body: Any = "") -> None:
        self.status_code = status
        self.text = body if isinstance(body, str) else json.dumps(body)
        self.headers = {"content-type": "application/json"}


class FakeClient:
    def __init__(self, routes: dict[str, FakeResponse] | None, error: Exception | None) -> None:
        self.routes = routes or {}
        self.error = error
        self.asked: list[str] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc) -> bool:
        return False

    async def get(self, url: str):
        self.asked.append(url)
        if self.error is not None:
            raise self.error
        for suffix, response in self.routes.items():
            if url.endswith(suffix):
                return response
        return FakeResponse(404, "")


@pytest.fixture
def fake_http(monkeypatch):
    holder: dict[str, FakeClient] = {}

    def install(routes=None, error=None) -> FakeClient:
        client = FakeClient(routes, error)
        holder["c"] = client
        monkeypatch.setattr("mykronos.exposure.httpx2.AsyncClient", lambda **kw: client)
        return client

    return install


class TestProbe:
    def test_it_asks_only_the_fixed_paths_anonymously(self, fake_http) -> None:
        client = fake_http({"/openapi.json": FakeResponse(200, SCHEMA)})

        status, answers, _ = asyncio.run(exposure.probe_endpoint("https://demo.example.com/"))

        assert status == exposure.PROBED
        assert client.asked == [f"https://demo.example.com{p}" for p in exposure.PATHS]
        assert classify(answers)[0].kind == "api_schema_public"

    def test_nothing_answering_is_unreachable_not_clean(self, fake_http) -> None:
        fake_http(error=OSError("connection refused"))

        status, _, detail = asyncio.run(exposure.probe_endpoint("https://gone.example.com"))

        assert status == exposure.UNREACHABLE
        assert "could not be reached" in detail


class TestTheApi:
    def test_register_list_and_probe(self, client, admin_auth, fake_http) -> None:
        created = client.post(
            "/api/exposure/endpoints",
            json={"url": "https://demo.example.com/", "repo_full_name": "o/hub", "label": "demo"},
            headers=admin_auth,
        )
        assert created.status_code == 201, created.text
        assert created.json()["url"] == "https://demo.example.com"

        fake_http({"/openapi.json": FakeResponse(200, SCHEMA)})
        probed = client.post("/api/exposure/probe", headers=admin_auth)
        assert probed.status_code == 200, probed.text

        listed = client.get("/api/exposure", headers=admin_auth).json()
        assert listed["exposed"] == 1
        (row,) = listed["endpoints"]
        assert row["last_status"] == "probed"
        assert row["observations"][0]["kind"] == "api_schema_public"
        with client.app.state.db.session() as session:
            assert session.execute(
                select(AuditLogEntry).where(AuditLogEntry.action == "exposure.changed")
            ).scalar_one()

    def test_an_unreachable_probe_keeps_what_was_last_seen(
        self, client, admin_auth, fake_http
    ) -> None:
        """Down for a minute is not evidence the exposure went away."""
        client.post(
            "/api/exposure/endpoints", json={"url": "https://demo.example.com"}, headers=admin_auth
        )
        fake_http({"/openapi.json": FakeResponse(200, SCHEMA)})
        client.post("/api/exposure/probe", headers=admin_auth)
        fake_http(error=OSError("timeout"))
        client.post("/api/exposure/probe", headers=admin_auth)

        (row,) = client.get("/api/exposure", headers=admin_auth).json()["endpoints"]
        assert row["last_status"] == "unreachable"
        assert row["observations"], "the last observation must survive an unreachable probe"

    def test_duplicates_and_bad_urls_are_refused(self, client, admin_auth) -> None:
        url = {"url": "https://demo.example.com"}

        def register(body):
            return client.post("/api/exposure/endpoints", json=body, headers=admin_auth)

        assert register(url).status_code == 201
        assert register(url).status_code == 409
        for bad in ("demo.example.com", "ftp://x.example.com", "https://x.example.com/?a=1"):
            response = client.post(
                "/api/exposure/endpoints", json={"url": bad}, headers=admin_auth
            )
            assert response.status_code == 422, bad

    def test_a_viewer_cannot_register_or_probe(self, client, viewer_auth) -> None:
        assert client.post(
            "/api/exposure/endpoints", json={"url": "https://x.example.com"}, headers=viewer_auth
        ).status_code == 403
        assert client.post("/api/exposure/probe", headers=viewer_auth).status_code == 403


class TestTheBriefing:
    def _briefing(self, exposure_rows):
        return briefing_report.Briefing(
            generated_at=datetime(2026, 10, 1, tzinfo=UTC),
            total_open=0,
            exposure=exposure_rows or [],
            exposure_unknown=exposure_rows is None,
        )

    def test_an_exposure_is_on_the_page(self) -> None:
        text = "\n".join(
            briefing_report._render_exposure(
                self._briefing(
                    [
                        {
                            "url": "https://demo.example.com",
                            "last_status": "probed",
                            "last_probed_at": "2026-10-01T20:00:00",
                            "observations": [{"severity": "high", "title": "API schema served"}],
                        }
                    ]
                )
            )
        )
        assert "PUBLIC ENDPOINTS" in text
        assert "[high] API schema served" in text

    def test_nothing_registered_says_nothing(self) -> None:
        assert briefing_report._render_exposure(self._briefing([])) == []

    def test_unreadable_is_not_none(self) -> None:
        text = "\n".join(briefing_report._render_exposure(self._briefing(None)))
        assert "Could not be read" in text


def test_the_model_is_a_table(client) -> None:
    with client.app.state.db.session() as session:
        assert session.execute(select(PublicEndpoint)).all() == []
