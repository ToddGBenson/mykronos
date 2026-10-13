"""`mykronos-mcp`: run the agent's MCP server over stdio (spec 36 §4).

Refuses to start, with a sentence saying why, rather than start in a state
that would fail on the first call: no credential, a credential that is not an
agent's, or a platform that cannot say who the credential belongs to. Every
message goes to stderr, because stdout is the protocol.
"""

from __future__ import annotations

import logging
import sys

import anyio

from mykronos.mcp_server.api import ConfigError, MykronosApi, Settings, verify_agent

logger = logging.getLogger("mykronos.mcp_server")


async def _serve(settings: Settings) -> None:
    from mykronos.mcp_server.tools import build_server

    api = MykronosApi(settings)
    try:
        principal = await verify_agent(api)
        logger.info("Serving MyKronos at %s as %s", settings.url, principal.actor)
        await build_server(api, principal).run_stdio_async()
    finally:
        await api.aclose()


def main() -> int:
    logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(message)s")
    try:
        import mcp  # noqa: F401 - only to fail with an instruction rather than a trace
    except ImportError:
        print(
            "mykronos-mcp needs the `mcp` extra: pip install 'mykronos[mcp]'. The backend "
            "image deliberately does not carry it.",
            file=sys.stderr,
        )
        return 2
    try:
        settings = Settings.from_env()
        anyio.run(_serve, settings)
    except ConfigError as exc:
        print(f"mykronos-mcp refused to start: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
