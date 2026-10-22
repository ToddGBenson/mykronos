"""No Concourse link the reader cannot open (TheHub #60924).

Every Concourse link the briefing and the CI views printed was
`http://localhost:8080/...`: compose defaulted MYKRONOS_CONCOURSE_EXTERNAL_URL
to loopback, and Concourse itself is published on 127.0.0.1 only. A
localhost link works on exactly one machine, and the 07:00 DM is read on a
phone. When nothing better is configured, the honest link is no link.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from mykronos.ci import ConcourseClient, browser_url

COMPOSE = Path(__file__).resolve().parents[2] / "deploy" / "mykronos" / "docker-compose.yml"


class TestTheBrowserUrl:
    @pytest.mark.parametrize(
        "external",
        [
            "http://localhost:8080",
            "http://127.0.0.1:8080/",
            "http://[::1]:8080",
            "http://0.0.0.0:8080",
            "http://LOCALHOST:8080",
        ],
    )
    def test_a_loopback_external_url_is_no_link(self, external: str) -> None:
        assert browser_url(external, "http://concourse:8080") == ""

    def test_a_lan_or_public_external_url_is_used(self) -> None:
        assert browser_url("http://192.168.0.14:8080/", "http://concourse:8080") == (
            "http://192.168.0.14:8080"
        )
        assert browser_url("https://ci.example.net", "") == "https://ci.example.net"

    def test_the_docker_service_name_is_not_a_browser_url(self) -> None:
        """Falling back to `concourse_url` gave `http://concourse:8080`, which
        resolves only on the compose network."""
        assert browser_url("", "http://concourse:8080") == ""

    def test_a_dotted_api_url_is_a_fallback(self) -> None:
        assert browser_url("", "https://ci.example.net/") == "https://ci.example.net"

    def test_nothing_configured_is_nothing(self) -> None:
        assert browser_url("", "") == ""


class FakeResponse:
    def __init__(self, payload: object) -> None:
        self.status_code = 200
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> object:
        return json.loads(json.dumps(self._payload))


@pytest.fixture
def routes(monkeypatch) -> dict[str, object]:
    table: dict[str, object] = {
        "/api/v1/pipelines": [{"name": "mykronos"}],
        "/api/v1/teams/main/pipelines/mykronos/jobs": [
            {"name": "unit", "finished_build": {"name": "8", "status": "failed"}}
        ],
    }

    def fake_get(url: str, timeout: float = 0) -> FakeResponse:
        for suffix in sorted(table, key=len, reverse=True):
            if url.endswith(suffix):
                return FakeResponse(table[suffix])
        raise AssertionError(url)

    monkeypatch.setattr("mykronos.ci.httpx2.get", fake_get)
    return table


class TestTheClientPrintsNoLocalhost:
    def test_a_loopback_external_url_gives_no_build_url(self, routes) -> None:
        client = ConcourseClient("http://concourse:8080", external_url="http://localhost:8080")

        [(_pipeline, job)] = client.failing_jobs() or []
        status = client.status_for("ToddGBenson/mykronos")

        assert job.build_url is None
        assert status.url is None
        assert client.pipeline_url("mykronos") == ""

    def test_a_configured_lan_url_is_used(self, routes) -> None:
        client = ConcourseClient(
            "http://concourse:8080", external_url="http://192.168.0.14:8080"
        )

        [(_pipeline, job)] = client.failing_jobs() or []

        assert job.build_url == (
            "http://192.168.0.14:8080/teams/main/pipelines/mykronos/jobs/unit/builds/8"
        )

    def test_the_api_is_still_read_through_the_internal_url(self, routes) -> None:
        """Only links change: an empty browser URL must not disable the read."""
        client = ConcourseClient("http://concourse:8080", external_url="")

        assert client.configured
        assert client.failing_jobs()


def test_compose_no_longer_defaults_links_to_loopback() -> None:
    env = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))["services"]["backend"][
        "environment"
    ]

    value = str(env["MYKRONOS_CONCOURSE_EXTERNAL_URL"])
    assert value.startswith("${MYKRONOS_CONCOURSE_EXTERNAL_URL")
    assert "localhost" not in value and "127.0.0.1" not in value
