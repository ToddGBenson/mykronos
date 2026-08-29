"""Asking the internet whether this platform is answering — spec 32 §8.

Written after an incident rather than before one. On 2026-08-29
`mykronos-backend` reported `healthy` for 22 hours while its host port was
unpublished: the process was fine, the frontend was fine — it reaches the
backend over the Docker network — and every scan upload from every pipeline
was failing with a 502 from the tunnel. Nothing said so, because nothing was
looking from outside.

**A container healthcheck cannot catch this**, by construction: it runs inside
the thing it is checking. Neither can a probe against `localhost`, which is
why the URL under test has to be the public one. That is the single property
these tests exist to pin.
"""

from __future__ import annotations

from typing import Any

import pytest

from mykronos import jobs
from mykronos.notify import Notification


class Recorder:
    def __init__(self) -> None:
        self.sent: list[Notification] = []

    async def send(self, note: Notification) -> bool:
        self.sent.append(note)
        return True


class FakeResponse:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


class FakeClient:
    """Stands in for httpx2.AsyncClient, recording what was asked for."""

    requested: list[str] = []

    def __init__(self, *, behaviour: Any = 200, **_: Any) -> None:
        self._behaviour = behaviour

    async def __aenter__(self) -> FakeClient:
        return self

    async def __aexit__(self, *_: Any) -> None:
        return None

    async def get(self, url: str) -> FakeResponse:
        type(self).requested.append(url)
        if isinstance(self._behaviour, Exception):
            raise self._behaviour
        return FakeResponse(self._behaviour)


@pytest.fixture
def client_factory(monkeypatch):
    def install(behaviour: Any) -> None:
        FakeClient.requested = []
        monkeypatch.setattr(
            jobs.httpx2,
            "AsyncClient",
            lambda **kwargs: FakeClient(behaviour=behaviour, **kwargs),
        )

    return install


class TestReachable:
    @pytest.mark.asyncio
    async def test_a_200_is_reachable(self, client_factory) -> None:
        client_factory(200)
        notifier = Recorder()

        result = await jobs.check_public_reachability(
            "https://mykronos.example", notifier=notifier
        )

        assert result.reachable
        assert result.status_code == 200

    @pytest.mark.asyncio
    async def test_it_says_nothing_when_healthy(self, client_factory) -> None:
        """A channel that reports every successful minute is one nobody reads
        by the time it matters — the rule the netassess judgement follows."""
        client_factory(200)
        notifier = Recorder()

        await jobs.check_public_reachability("https://mykronos.example", notifier=notifier)

        assert notifier.sent == []


class TestTheUrlUnderTest:
    @pytest.mark.asyncio
    async def test_it_probes_the_public_url(self, client_factory) -> None:
        """The entire point. A localhost probe would have passed for every one
        of the 22 hours the ingestion API was unreachable, because the process
        was healthy the whole time — what was broken was the path to it."""
        client_factory(200)

        await jobs.check_public_reachability("https://mykronos.example")

        assert FakeClient.requested == ["https://mykronos.example/healthz"]

    @pytest.mark.asyncio
    async def test_a_trailing_slash_does_not_double_up(self, client_factory) -> None:
        client_factory(200)

        await jobs.check_public_reachability("https://mykronos.example/")

        assert FakeClient.requested == ["https://mykronos.example/healthz"]

    @pytest.mark.asyncio
    async def test_it_uses_healthz_not_the_ingestion_probe(
        self, client_factory
    ) -> None:
        """`/healthz` is exempt from the perimeter gate, so the check needs no
        credential and cannot fail for a reason of its own."""
        client_factory(200)

        await jobs.check_public_reachability("https://mykronos.example")

        assert FakeClient.requested[0].endswith("/healthz")


class TestUnreachable:
    @pytest.mark.asyncio
    async def test_a_502_is_not_reachable(self, client_factory) -> None:
        """The exact shape of the real incident: Cloudflare answering, the
        origin behind it not."""
        client_factory(502)
        notifier = Recorder()

        result = await jobs.check_public_reachability(
            "https://mykronos.example", notifier=notifier
        )

        assert not result.reachable
        assert result.status_code == 502
        assert "502" in result.detail

    @pytest.mark.asyncio
    async def test_a_connection_failure_is_not_reachable(
        self, client_factory
    ) -> None:
        client_factory(OSError("connection refused"))

        result = await jobs.check_public_reachability("https://mykronos.example")

        assert not result.reachable
        assert result.status_code is None
        assert "could not be reached" in result.detail

    @pytest.mark.asyncio
    async def test_it_is_critical(self, client_factory) -> None:
        """While this is false, every scan upload from every pipeline is
        failing and nothing else will say so. The dashboard keeps serving,
        which is what makes it dangerous rather than obvious."""
        client_factory(502)
        notifier = Recorder()

        await jobs.check_public_reachability("https://mykronos.example", notifier=notifier)

        assert len(notifier.sent) == 1
        assert notifier.sent[0].level == "critical"
        assert "not reachable" in notifier.sent[0].title

    @pytest.mark.asyncio
    async def test_it_warns_that_the_dashboard_will_look_fine(
        self, client_factory
    ) -> None:
        """The detail that turns a confusing alert into an actionable one:
        somebody checking the dashboard will see a working system."""
        client_factory(502)
        notifier = Recorder()

        await jobs.check_public_reachability("https://mykronos.example", notifier=notifier)

        assert "Docker network" in notifier.sent[0].detail

    @pytest.mark.asyncio
    async def test_no_notifier_is_not_a_crash(self, client_factory) -> None:
        """It runs unattended. A deployment with no Slack webhook must still
        get the result, and the CLI still exits non-zero on it."""
        client_factory(502)

        result = await jobs.check_public_reachability("https://mykronos.example")

        assert not result.reachable
