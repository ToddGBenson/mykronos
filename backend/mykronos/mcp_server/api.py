"""The MCP server's one connection to MyKronos: configuration and an HTTP client.

Three of #319's failures were transport, not judgement, and each one looked
like something else:

- `localhost` resolves to `::1` on this host and the IPv6 port proxy resets
  the connection mid-batch. Four of eight acceptances failed with HTTP 000,
  which reads exactly like an expired token. The default is `127.0.0.1`, and
  a configured `localhost` is refused rather than quietly tried.
- A token read with `printenv` carries a trailing newline, which is also an
  HTTP 000. Both tokens are stripped.
- A retried 4xx repeats a refusal and can double a write. Nothing here
  retries: the API's own `detail` goes back to the agent, once.

The credential must be an agent's (spec 34 §1). The operator's admin token is
refused twice: by its prefix before it is ever sent, and by `whoami` saying
the caller is not an agent.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx2

from mykronos.adminauth import ActorKind, Principal, Role
from mykronos.agents import TOKEN_PREFIX
from mykronos.gate import TOKEN_HEADER

DEFAULT_URL = "http://127.0.0.1:8100"
URL_ENV = "MYKRONOS_URL"
AGENT_TOKEN_ENV = "MYKRONOS_AGENT_TOKEN"
GATE_TOKEN_ENV = "MYKRONOS_GATE_TOKEN"

#: Generous for the briefing and the work queue, which read the lake and CI.
TIMEOUT_SECONDS = 60.0


class ConfigError(RuntimeError):
    """The server cannot start. The message says what to set and why."""


class ApiError(RuntimeError):
    """A non-2xx answer from MyKronos, carrying the API's own `detail`."""

    def __init__(self, method: str, path: str, status_code: int, detail: str) -> None:
        self.method = method
        self.path = path
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"{method} {path} -> HTTP {status_code}: {detail}")


@dataclass(frozen=True)
class Settings:
    url: str
    agent_token: str
    gate_token: str

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        env = os.environ if env is None else env
        url = (env.get(URL_ENV) or DEFAULT_URL).strip().rstrip("/")
        agent_token = (env.get(AGENT_TOKEN_ENV) or "").strip()
        gate_token = (env.get(GATE_TOKEN_ENV) or "").strip()
        if not agent_token:
            raise ConfigError(
                f"{AGENT_TOKEN_ENV} is not set. This server acts only as an agent, under "
                f"its own `{TOKEN_PREFIX}` credential: mint one with "
                "POST /api/agents/credentials (see docs/agent-mcp.md)."
            )
        if not agent_token.startswith(TOKEN_PREFIX):
            raise ConfigError(
                f"{AGENT_TOKEN_ENV} is not an agent credential (it does not start with "
                f"`{TOKEN_PREFIX}`). The operator's admin token must never be used "
                "through this server; mint an agent credential instead."
            )
        host = urlsplit(url).hostname or ""
        if host.lower() == "localhost":
            raise ConfigError(
                f"{URL_ENV} names `localhost`, which resolves to ::1 here, and the IPv6 "
                "port proxy resets the connection: a failure that looks like an expired "
                "token (#319). Use 127.0.0.1."
            )
        return cls(url=url, agent_token=agent_token, gate_token=gate_token)


def _detail(response: httpx2.Response) -> str:
    """The API's own words. FastAPI puts them in `detail`, sometimes as a list
    of validation errors; anything else is passed through as text."""
    try:
        payload = response.json()
    except ValueError:
        return response.text.strip() or response.reason_phrase
    if isinstance(payload, dict) and "detail" in payload:
        detail = payload["detail"]
        if isinstance(detail, str):
            return detail
        if isinstance(detail, list):
            parts = []
            for err in detail:
                if isinstance(err, dict):
                    loc = ".".join(str(p) for p in err.get("loc", []))
                    parts.append(f"{loc}: {err.get('msg', '')}".strip(": "))
                else:
                    parts.append(str(err))
            return "; ".join(parts)
        return str(detail)
    return response.text.strip() or response.reason_phrase


class MykronosApi:
    """A thin, non-retrying JSON client for the MyKronos API."""

    def __init__(
        self, settings: Settings, *, transport: httpx2.AsyncBaseTransport | None = None
    ) -> None:
        headers = {"Authorization": f"Bearer {settings.agent_token}"}
        if settings.gate_token:
            headers[TOKEN_HEADER] = settings.gate_token
        self.settings = settings
        self._http = httpx2.AsyncClient(
            base_url=settings.url,
            headers=headers,
            timeout=TIMEOUT_SECONDS,
            transport=transport,
        )

    async def request_json(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        body: Any = None,
    ) -> Any:
        """One request, no retry. Raises `ApiError` with the API's `detail`."""
        query = {k: v for k, v in (params or {}).items() if v is not None}
        try:
            response = await self._http.request(
                method, path, params=query or None, json=body
            )
        except httpx2.HTTPError as exc:
            raise ApiError(
                method,
                path,
                0,
                f"MyKronos could not be reached at {self.settings.url} ({exc!r}). "
                "This is a transport failure, not a refusal.",
            ) from exc
        if response.status_code >= 400:
            raise ApiError(method, path, response.status_code, _detail(response))
        if not response.content:
            return None
        return response.json()

    async def aclose(self) -> None:
        await self._http.aclose()


async def verify_agent(api: MykronosApi) -> Principal:
    """Ask the platform who this credential is, and refuse anything but an agent.

    The prefix check in `Settings` stops an admin token being configured by
    mistake; this one stops anything the platform itself does not call an
    agent, which is the definition that matters.
    """
    try:
        who = await api.request_json("GET", "/api/agents/whoami")
    except ApiError as exc:
        raise ConfigError(f"GET /api/agents/whoami failed: {exc.detail}") from exc
    if not isinstance(who, dict) or who.get("kind") != ActorKind.AGENT.value:
        kind = who.get("kind") if isinstance(who, dict) else None
        raise ConfigError(
            f"This credential belongs to a {kind or 'non-agent'} principal, not an "
            "agent. The MCP server only runs under an agent's own credential (spec 34 §1)."
        )
    return Principal(
        actor=str(who.get("actor") or ""),
        role=Role(str(who.get("role") or Role.AGENT.value)),
        kind=ActorKind.AGENT,
        provenance=dict(who.get("provenance") or {}),
    )
