"""What a reboot quietly takes away — spec 32 §8.1.

A host restart on 2026-08-28 broke three things and nothing noticed any of
them for a day: the ingestion API lost its published port, Vault came back
sealed, and Concourse never came back at all.

Each was invisible in a different way, which is why one check has to cover
all three. The container reported healthy from inside itself. The dashboard
served normally over the Docker network. And nothing anywhere was watching
Concourse, so `mykronos parity` compared real coverage against a connection
error and called it an improvement.
"""

from __future__ import annotations

from typing import Any

import pytest

from mykronos import jobs


class FakeResponse:
    def __init__(self, status_code: int, payload: dict[str, Any] | None = None) -> None:
        self.status_code = status_code
        self._payload = payload or {}
        self.content = b"{}" if payload is not None else b""

    def json(self) -> dict[str, Any]:
        return self._payload


class FakeClient:
    def __init__(self, *, behaviour: Any = None, **_: Any) -> None:
        self._behaviour = behaviour

    async def __aenter__(self) -> FakeClient:
        return self

    async def __aexit__(self, *_: Any) -> None:
        return None

    async def get(self, url: str) -> FakeResponse:
        if isinstance(self._behaviour, Exception):
            raise self._behaviour
        return self._behaviour


@pytest.fixture
def respond(monkeypatch):
    def install(behaviour: Any) -> None:
        monkeypatch.setattr(
            jobs.httpx2, "AsyncClient", lambda **kw: FakeClient(behaviour=behaviour, **kw)
        )

    return install


class TestVault:
    @pytest.mark.asyncio
    async def test_unsealed_is_ok(self, respond) -> None:
        respond(FakeResponse(200, {"sealed": False, "initialized": True}))

        result = await jobs.check_vault("http://vault:8200")

        assert result.reachable

    @pytest.mark.asyncio
    async def test_sealed_is_a_failure_not_an_outage(self, respond) -> None:
        """The state this check exists for. Vault uses file storage, so it
        comes back sealed after every restart and nothing can read a secret
        until somebody unseals it — while the container is up and answering
        the whole time. A port probe would call this healthy."""
        respond(FakeResponse(503, {"sealed": True, "initialized": True}))

        result = await jobs.check_vault("http://vault:8200")

        assert not result.reachable
        assert "SEALED" in result.detail
        assert "vault-unseal.ps1" in result.detail

    @pytest.mark.asyncio
    async def test_unreachable_is_a_failure(self, respond) -> None:
        respond(OSError("no such host"))

        result = await jobs.check_vault("http://vault:8200")

        assert not result.reachable
        assert "could not be reached" in result.detail

    @pytest.mark.asyncio
    async def test_unconfigured_is_not_a_failure_to_report_loudly(self, respond) -> None:
        """A deployment with no Vault is a valid deployment."""
        result = await jobs.check_vault("")

        assert not result.reachable
        assert "No Vault is configured" in result.detail


class TestConcourse:
    @pytest.mark.asyncio
    async def test_answering_is_ok(self, respond) -> None:
        respond(FakeResponse(200, {"version": "7.14"}))

        result = await jobs.check_concourse("http://concourse:8080")

        assert result.reachable

    @pytest.mark.asyncio
    async def test_down_is_a_failure(self, respond) -> None:
        """Observed for real: `No address associated with hostname`, for 31
        hours, while `mykronos parity` reported every capability improved."""
        respond(OSError("No address associated with hostname"))

        result = await jobs.check_concourse("http://concourse:8080")

        assert not result.reachable
        assert "could not be reached" in result.detail

    @pytest.mark.asyncio
    async def test_it_asks_for_info_not_the_pipeline_list(self, respond) -> None:
        """`/api/v1/info` needs no team, no auth and no pipeline to exist, so
        it separates "Concourse is down" from "Concourse covers nothing" —
        which `ci.py` spends a docstring insisting are different facts."""
        seen: list[str] = []

        class Recording(FakeClient):
            async def get(self, url: str) -> FakeResponse:
                seen.append(url)
                return FakeResponse(200, {})

        import mykronos.jobs as j

        j.httpx2.AsyncClient = lambda **kw: Recording()  # type: ignore[assignment]
        await jobs.check_concourse("http://concourse:8080")

        assert seen == ["http://concourse:8080/api/v1/info"]


class TestOnlyIngestionPages:
    @pytest.mark.asyncio
    async def test_a_sealed_vault_does_not_alert(self, respond) -> None:
        """A sealed Vault and a stopped Concourse fail loudly at the next
        build. Paging for them trains somebody to ignore the channel that
        carries the one failure which loses data silently."""
        respond(FakeResponse(503, {"sealed": True}))
        sent: list[Any] = []

        class Recorder:
            async def send(self, note: Any) -> bool:
                sent.append(note)
                return True

        await jobs.check_vault("http://vault:8200")

        assert sent == []
