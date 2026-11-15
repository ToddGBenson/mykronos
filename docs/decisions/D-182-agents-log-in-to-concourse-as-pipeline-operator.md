## D-182 — Agents log in to Concourse as a second local user holding `pipeline-operator` on main

**2026-11-14.** **Status:** Decided, implemented; live once the operator adds
two `.env` values and recreates the web node (OPERATOR-TASKS.md item 11)
**Refs:** D-181 (the compose this changes)

**The problem.** Concourse had one local user, the operator, who owned the
main team through `CONCOURSE_MAIN_TEAM_LOCAL_USER`. A fly token lasts 24 hours
(`--auth-duration`'s default), so every agent's fly target lapsed daily and
only the operator could log it back in. An agent that could log in as that
user would be owner: able to set pipelines, hijack containers and change the
team, which is far more than re-running a red build needs.

**The decision.**

1. **A second local user for agents.** `CONCOURSE_AGENT_USER` and
   `CONCOURSE_AGENT_PASSWORD` in `.env`, required (`:?`) exactly as the
   operator's pair is, appended to `CONCOURSE_ADD_LOCAL_USER` as a second
   comma-separated `USER:PASSWORD` pair. Concourse splits that variable on
   commas (twentythousandtonnesofcrudeoil gives map and slice flags `,` as the
   env delimiter), so neither password may contain one; `setup.ps1`'s URL-safe
   base64 never does.
2. **Roles come from a team config, not from `CONCOURSE_MAIN_TEAM_LOCAL_USER`.**
   `CONCOURSE_MAIN_TEAM_CONFIG` names a file in `fly set-team -c` format:
   `owner` holds `CONCOURSE_LOCAL_USER`, `pipeline-operator` holds
   `CONCOURSE_AGENT_USER`. Read from the 8.3.3 source: `skycmd.AuthTeamFlags.Format`
   reads the file when one is given and ignores `--main-team-local-user`
   entirely, so the old variable is removed rather than left as a grant that
   no longer exists. `TeamAuth.Validate` does not require an owner, and
   `configureAuthForDefaultTeam` rewrites the main team's auth from this file
   on every web start, so a config without the operator under `owner` would
   lock the operator out at the next recreate; a test pins that the owner role
   names `CONCOURSE_LOCAL_USER`.
3. **The file is inline in compose.** A top-level `configs:` entry with
   `content:`, which compose interpolates like the rest of the file and mounts
   read-only at `/concourse-config/main-team.yml`. The user names come from
   `.env`, which this public repository never holds, so a committed YAML
   would either carry them or need a generator step and a gitignored file;
   inline keeps one source.
4. **`pipeline-operator`, not `member` or `viewer`.** Per
   `atc/api/accessor/roles.go` (8.3.3) it allows trigger, rerun, abort,
   check, pin and pause/unpause; it does not allow `set-pipeline`, delete,
   archive, expose, hijack, `fly execute` or `set-team`. Viewer cannot
   rerun, and member can rewrite any pipeline. Pause is allowed by the role and
   forbidden to agents by standing rule; the role cannot express that split.
5. **Agents renew their own token.** `Connect-AgentFly.ps1` logs fly target
   `mykronos-agent` in from `.env` without printing the password, leaves a
   valid token alone, and after a login reads `fly userinfo` and logs out
   again unless Concourse granted exactly `pipeline-operator` on main. Run
   from a worktree it finds the main checkout's `.env` and `bin\fly.exe`
   through git's common directory. `-Provision` is the operator's one-time
   step that appends the two values.

**Why not a longer `--auth-duration`.** It applies to every user, the owner
included, and a long-lived owner token is the thing to avoid. The 24-hour
token stays; what changed is that renewing it no longer needs a person.

**Accepted.** The agents' password reaches fly as `--password`, as in
`set-pipeline.ps1`: fly 8 uses the password grant only when both `-u` and
`-p` are given, so the password is in `fly.exe`'s argv for the duration of
the login. The two required variables also mean every `docker compose`
command against this stack fails until `.env` has them, which is why the
operator steps add them before the checkout moves.
