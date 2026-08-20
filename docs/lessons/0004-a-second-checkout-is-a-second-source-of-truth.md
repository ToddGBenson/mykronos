# L0004: A second checkout is a second source of truth

**Date:** 2026-08-20 · **Class:** learned here, three times in one day
**Applies to:** anything applied from a working copy — pipelines, credentials, migrations
**Landed as:** D-081, `check_capability_grants.py` running the CLI inside the container,
and the applied-config drift check still open in D-081's own follow-up

## The lesson, in one line

**A copy that is close enough to be plausible is worse than one that is obviously
different, because nothing about using it feels wrong until the divergence has already
cost you something.**

## The day that taught it

Three instances, three guises, none of them recognisable as the same problem at the time.

### 1. The pipelines that run were not the pipelines in the repository

The Concourse stack's compose project lives in `PDSO2/`, a second clone of this
repository. `docker inspect mykronos-concourse` says so; nothing else did. It was
**eighteen commits behind** `main` and carried uncommitted edits to five files.

This was found by accident. `set-pipeline.ps1` needs `deploy/concourse/.env`,
`backend/.env` and `bin/fly.exe`, and none of the three existed in the checkout everything
else had been done in. Looking for a missing `.env` is what surfaced it.

Everything about that checkout looked right: same remote, same branch name, same file
tree. Applying a pipeline from it would have silently applied an eighteen-commit-old
definition and reported success.

### 2. Two live operator decisions existed only in a working tree

Inside that same checkout, uncommitted:

- **TheHub's Oracle gate was disabled** — `exit 1` on a `no_go` commented out on
  2026-08-18 with 21 open critical findings.
- **TheHub's pipeline watched `main`, not `develop`** — a deliberate change with a real
  rationale (SDLC-7 #49216), committed locally and never pushed.

Both were reasonable calls. Neither existed anywhere a reader could find. The repository
said the gate blocked while the applied pipeline let every `no_go` through, and nothing
reconciled the two. A **disabled security control** is the worst possible thing to hold
in unversioned state, and the only way to discover it was `git status` in a directory
nobody would think to open. → D-081

### 3. The CLI on the host reads a different database from the API

`mykronos list-tokens` run from `PDSO2/backend` reported five granted capabilities for
`ToddGBenson/mykronos`. The live API reported thirteen. Both were "the platform".

The backend container uses `sqlite:////data/mykronos.db` inside a Docker named volume;
the CLI defaults to `sqlite:///mykronos.db`, relative to the working directory. That
local file was a week old.

The near-miss: `mykronos rotate-token` is the obvious way to rotate a credential, and run
that way it would have rotated in the stale database — minting a token the live platform
had never heard of, then writing it into Vault and re-applying. Every scanning lane across
three pipelines would have started failing auth, caused by the command whose entire job is
to keep them working.

Caught only because the two answers were compared before acting.

## Why this class is hard to see

- **The copy passes every check you would think to run.** Right remote, right branch,
  right filenames, right command syntax. It fails only on content, and only later.
- **The tooling actively hides it.** A CLI with a relative-path default produces a working
  database rather than an error. `fly set-pipeline` succeeds against a stale file. Neither
  says "this is not the one you mean".
- **Discovery is incidental.** All three were found while looking for something else. None
  would have surfaced from the direction of the work itself.
- **It compounds with concurrency.** Two sessions editing one checkout produced a
  `reset --hard` that destroyed a session's work, a merge that silently dropped three
  decision entries, and an overwrite that made an apply report success while writing the
  opposite. Same day.

## What to do instead

- **Ask the running system where it runs from.** `docker inspect <container> --format
  '{{index .Config.Labels "com.docker.compose.project.working_dir"}}'` is one command and
  it is authoritative. Assume nothing about which clone is live.
- **Run platform commands inside the platform.** `docker exec <backend> python -m
  mykronos.cli …`, never the host copy. `check_capability_grants.py` does this and says
  why, so the next reader does not have to rediscover it.
- **Never hand-copy a file into the deployment checkout.** Commit, merge, pull, apply. A
  copy skips the one step that makes the change visible to everyone else, and a concurrent
  session will overwrite it — which happened, producing an apply that logged "Resolving
  from Vault" while writing literals.
- **Diff before every destructive step, and let the diff decide.** Every reset,
  force-push and branch deletion here was preceded by a comparison proving the target held
  nothing unique. One of those comparisons found a merge had dropped three decision
  entries that would otherwise have been lost silently.
- **Render the disagreement.** The pattern that caught all three was the same one L0003
  ends on: put the two sources side by side and show where they differ. The one still
  missing is a check comparing the *applied* pipeline config against the committed file —
  proposed in D-081, and now cheap.

## The connection to L0003

[L0003](0003-a-check-that-cannot-report-is-a-check-that-does-not-exist.md) is about a
check whose result cannot reach anyone. This is its sibling: a check whose result reaches
you correctly, *about the wrong thing*. Both present as green. Both are only visible when
two views of the same fact are placed next to each other and made to disagree out loud.
