"""An MCP server for the agent that operates MyKronos (spec 36 §4, closes #319).

Everything an agent did here before went through SQL against the lake and
curl against the API, and #319 lists what that cost in one session: four
failed queries to a reserved word, a DAST target inferred wrongly for three
cycles while it sat in `raw_finding_json`, and half a batch of acceptances
lost to `localhost` resolving to `::1`. None of those were hard problems.
They were the cost of having no typed surface between an agent and the
platform.

This package is that surface, and nothing more. It wraps the HTTP API under
the agent's own `mka_` credential (spec 34 §1), so every call is attributed
to the agent and meets the same rules a direct call would. It holds no
authority of its own: a refusal from a governed route comes back word for
word, because the route is the authority and this is a client of it.

`mcp` is an optional extra (`pip install mykronos[mcp]`). The backend image
does not carry it and nothing in the API imports this package.
"""
