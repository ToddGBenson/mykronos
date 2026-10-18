"""The exposure sweep's answers as ControlObservations (TheHub #60826).

The sweep already makes four anonymous GETs per registered URL. Those same
responses say whether the hostname answers anonymous requests with 401 and
whether it sends CSP and HSTS - so the sweep records that, from what it
already fetched, and asks nothing new.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select

from mykronos import exposure
from mykronos.db.models import ControlObservation, PublicEndpoint
from mykronos.exposure import Answer

DATA = Path(__file__).parent / "data" / "control_observations"


def _answers(name: str) -> tuple[str, dict[str, Answer]]:
    fixture = json.loads((DATA / "exposure_responses.json").read_text(encoding="utf-8"))[name]
    answers = {
        path: Answer(
            status=a["status"],
            content_type=a["headers"].get("content-type", ""),
            body=a["body"],
            error=a.get("error", ""),
            headers=a["headers"],
        )
        for path, a in fixture["answers"].items()
    }
    return fixture["url"], answers


def _by(observed: list[Any]) -> dict[str, Any]:
    return {o.assertion: o for o in observed}


class TestFromAnswers:
    def test_a_gated_endpoint(self) -> None:
        url, answers = _answers("gated")
        by = _by(exposure.control_observations(url, exposure.PROBED, answers))

        assert by["anonymous_401"].state == "pass"
        assert by["anonymous_401"].subject == "mykronos-app.example.net"
        assert by["header_csp"].state == "pass"
        assert by["header_hsts"].state == "pass"
        assert by["port_published"].state == "pass"
        assert by["port_published"].subject == "mykronos-app.example.net:443"
        assert {o.vantage for o in by.values()} == {"internet"}

    def test_an_open_endpoint(self) -> None:
        url, answers = _answers("open_demo")
        by = _by(exposure.control_observations(url, exposure.PROBED, answers))

        assert by["anonymous_401"].state == "fail"
        # Report-only is not a policy that is enforced.
        assert by["header_csp"].state == "fail"
        assert by["header_hsts"].state == "fail"

    def test_redirects_and_mixed_answers_are_unknown_for_the_gate(self) -> None:
        url, answers = _answers("mixed_redirects")
        by = _by(exposure.control_observations(url, exposure.PROBED, answers))

        assert by["anonymous_401"].state == "unknown"
        # Plain http: HSTS cannot apply, so its absence is a fact, not a gap.
        assert by["header_hsts"].state == "fail"
        assert by["port_published"].subject == "blog.example.net:80"

    @pytest.mark.parametrize("status", [exposure.UNREACHABLE, exposure.RESOLVES_LOCALLY])
    def test_a_probe_that_reached_nothing_is_unknown_never_pass(self, status: str) -> None:
        observed = exposure.control_observations("https://gone.example.net", status, {})
        assert observed
        assert {o.state for o in observed} == {"unknown"}


class FakeResponse:
    def __init__(self, status: int, headers: dict[str, str]) -> None:
        self.status_code = status
        self.text = ""
        self.headers = headers


class FakeClient:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.asked: list[str] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc) -> bool:
        return False

    async def get(self, url: str):
        self.asked.append(url)
        return self.response


@pytest.fixture(autouse=True)
def public_dns(monkeypatch):
    monkeypatch.setattr(
        "mykronos.exposure.socket.getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("93.184.215.14", 0))],
    )


class TestTheSweep:
    def test_the_probe_keeps_headers_and_asks_nothing_new(self, monkeypatch) -> None:
        client = FakeClient(FakeResponse(401, {"Content-Security-Policy": "default-src 'none'"}))
        monkeypatch.setattr("mykronos.exposure.httpx2.AsyncClient", lambda **kw: client)

        status, answers, _ = asyncio.run(exposure.probe_endpoint("https://a.example.net"))

        assert status == exposure.PROBED
        assert len(client.asked) == len(exposure.PATHS)
        assert answers["/docs"].headers["content-security-policy"] == "default-src 'none'"

    def test_the_sweep_records_rows_for_the_endpoints_repository(
        self, client, monkeypatch
    ) -> None:
        db = client.app.state.db
        with db.session() as session:
            session.add(PublicEndpoint(url="https://a.example.net", repo_full_name="o/hub"))
            session.add(PublicEndpoint(url="https://b.example.net", repo_full_name=""))
            session.commit()
        fake = FakeClient(
            FakeResponse(
                401,
                {
                    "content-security-policy": "default-src 'none'",
                    "strict-transport-security": "max-age=1",
                },
            )
        )
        monkeypatch.setattr("mykronos.exposure.httpx2.AsyncClient", lambda **kw: fake)

        asyncio.run(exposure.run_sweep(db))

        with db.session() as session:
            rows = session.scalars(select(ControlObservation)).all()
        # The unowned endpoint has no repository to file evidence under.
        assert {r.repo_full_name for r in rows} == {"o/hub"}
        assert {r.assertion for r in rows} == {
            "anonymous_401",
            "header_csp",
            "header_hsts",
            "port_published",
        }
        assert {r.collector for r in rows} == {"job:exposure"}
        assert all(r.state == "pass" for r in rows)
