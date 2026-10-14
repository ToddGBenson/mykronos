# The agent's MCP server

`mykronos-mcp` is a stdio [MCP](https://modelcontextprotocol.io) server that lets an AI agent
operate MyKronos through typed tools instead of SQL against the lake and curl against the API
(spec 36 §4, #319). It wraps the HTTP API under the agent's **own** `mka_` credential, so every call
is attributed to the agent and meets the same rules a direct call would. It holds no authority of
its own: when a route refuses, the refusal comes back word for word.

The code is `backend/mykronos/mcp_server/`. The tool set is pinned by
`backend/tests/test_mcp_server.py`; changing it means changing that test in a pull request.

## Install

The server is an optional extra. The backend image does not carry it.

```
pip install -e "backend[mcp]"      # from the repository root, into the venv the agent uses
```

This puts `mykronos-mcp` on that venv's path (`.venv/Scripts/mykronos-mcp.exe` on Windows).
`python -m mykronos.mcp_server` does the same thing.

## Mint a credential

The server refuses the operator's admin token. A person mints a credential for the agent:

```
curl -s -X POST http://127.0.0.1:8100/api/agents/credentials \
  -H "X-Hub-Token: $GATE_TOKEN" -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"family": "claude-opus-5.5", "purpose": "author", "ttl_hours": 12}'
```

The response holds `token` (shown once), `actor`, `instance` and `expires_at`. The default lifetime
is 12 hours and the most is 7 days (`ttl_hours` up to 168). An agent run is a session, not an
employee. An expired credential shows up as the server refusing to start, with the API's reason.

## Configure

| Variable | Default | What it is |
|---|---|---|
| `MYKRONOS_URL` | `http://127.0.0.1:8100` | The backend. Use `127.0.0.1`: `localhost` resolves to `::1`, the IPv6 port proxy resets the connection, and the result looks like an expired token. The server refuses `localhost`. |
| `MYKRONOS_AGENT_TOKEN` | (required) | The `mka_` credential, sent as `Authorization: Bearer`. |
| `MYKRONOS_GATE_TOKEN` | (none) | The perimeter token, sent as `X-Hub-Token`. |

Both tokens are stripped of whitespace, because a trailing newline from `printenv` is another
failure that looks like an expired token.

The server refuses to start, with a message on stderr, when:

- `MYKRONOS_AGENT_TOKEN` is unset;
- the token does not start with `mka_`, so an admin token is never sent;
- `GET /api/agents/whoami` fails, or says the caller's `kind` is not `agent`.

## Register it with Claude Code

```
claude mcp add mykronos \
  -e MYKRONOS_URL=http://127.0.0.1:8100 \
  -e MYKRONOS_AGENT_TOKEN=mka_... \
  -e MYKRONOS_GATE_TOKEN=... \
  -- /path/to/backend/.venv/Scripts/mykronos-mcp.exe
```

`claude mcp list` should then show `mykronos` as connected. The tokens are stored in Claude Code's
configuration in plain text, so register under the scope you mean (`--scope local` is the default),
and re-register when the credential expires.

## The tools

Repository-scoped tools take the **onboarding id**, not `owner/repo`, because the routes are
id-only (TheHub #60739). `repos()` maps one to the other. `accept` and `request_pr_review` take
`owner/repo`, because their routes do.

| Tool | Route | Notes |
|---|---|---|
| `whoami()` | `GET /api/agents/whoami` | |
| `repos(include_removed)` | `GET /api/repos` | Names to ids. |
| `work(repo_id?, findings?)` | `GET /api/agent/work` | Start here (spec 36 §2). |
| `briefing(repo_id?)` | `GET /api/dashboard/briefing` | |
| `findings(...)` | `GET /api/dashboard/repos/{id}/findings`, or `GET /api/dashboard/triage` without `repo_id` | Typed filters: capability, severity, status, rule_id, triage. Without a repository, the ranked queue of open findings. |
| `finding(finding_id)` | `GET /api/dashboard/findings/{id}/record` | For DAST, `uri`, `method`, `param` and `evidence` from `raw_finding_json.instance` are at the top level. |
| `lane_health(repo_id)` | `GET /api/dashboard/repos/{id}/scan-health` + `/ci` | A CI half that cannot be read is listed in `unknown`. |
| `scan_run(scan_run_id)` | `GET /api/dashboard/scan-runs/{id}` | One run and what it changed against the previous run on its lane. A `lane_stalled` work item cites its latest run. `new` is exact; the rest are lower bounds unless `exact`. Raw files are listed, not served: downloading them is admin-only. |
| `claim(finding_id)` | `POST /api/dashboard/triage/{id}/claim` | Claimed in the agent's actor name. |
| `disposition(finding_id, status, reason)` | `PATCH /api/dashboard/findings/{id}/status`, or `POST …/disposition-requests` | Reads severity first. Critical or high goes to the governed route (`finding_disposition`, #713). `status` is `false_positive` or `suppressed`. |
| `accept(...)` | `POST /api/risk-acceptances` | The route's own rules: a deviation type (the reason code), a review date (`requested_until`, required, since this route has no indefinite option), a named person as risk owner, and a milestone that ends the weakness. |
| `request_pr_review(repo, number, statement)` | `POST /api/approvals/pull-requests` | |

Every write tool takes `dry_run`. A dry run returns the method, path, body and `governed_by` the real
call would meet, and sends no write. `disposition` still reads the finding, because its route
depends on the severity. `governed_by: null` is a direct write. Anything else names the duty in
`approval-policy-v1.yaml` that someone independent will weigh before it takes effect.

Errors are the API's own `detail`, with the method, path and status. Nothing is retried. A 403 from
a governed route says what to do instead, so read it.

## What it deliberately cannot do

No tool starts or stops a scan, revokes a token or an acceptance, removes data, grants a capability
or a delegation, decides an approval request, or mints a credential. #319 set the rule: an agent
that can close findings is already a risk, and one that can also stop the scans or revoke tokens
is a worse one. Anything that removes coverage or authority stays behind a person. The test file
fails if a tool's name, description or schema mentions any of those verbs.

The tools #319 also proposed, `pipeline(repo)` and `coverage(repo)`, are not here because no route
serves them yet (#318). Playbooks (spec 36 §5) and the agent's track record (§6) come later.
