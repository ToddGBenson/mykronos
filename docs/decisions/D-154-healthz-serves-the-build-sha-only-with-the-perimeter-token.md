## D-154 — `/healthz` serves the build SHA only with the perimeter token

**2026-10-11.** **Status:** Decided, implemented
**Story:** TheHub #60722 · reverses the public half of #361 · mirrors TheHub #60709

**The rule.** The public `/healthz` body is `{"status": "ok"}` and nothing
else. `version` and `build` (`sha`, `source`) go into the body only when the
request carries the perimeter token in `X-Hub-Token`, the `hub_token` cookie
or `?_token=`. That is the same check, with the same carriers, that
`PerimeterGate` applies to every other path (`gate.presents_token`). The
status code is 200 for every caller. `/healthz` stays exempt from the gate.

A host with no `MYKRONOS_GATE_TOKEN` serves status only as well. An unset
gate has no credential to present. That does not make every caller trusted.
TheHub's version keeps a dev-mode exception, because its internet-facing demo
was found reading "no token" as dev mode and publishing everything. MyKronos
has no environment flag that could tell the two apart, so it has no
exception.

**Why.** `/healthz` is exempt from the gate, so every key in it is published
to the internet. #361 made `build.sha` public on purpose: a SHA names a public
commit, and "is the fix running yet?" had to be answerable from outside. That
is exactly what makes it useful to an attacker. Diff the running SHA against
`main` and you have the list of fixes not yet deployed. Measured on
2026-10-11, nothing needed the SHA to be public:

| consumer | reads | after this |
|---|---|---|
| `deploy/mykronos/deploy.ps1` (post-deploy "running what you asked for") | `.build.sha` from `127.0.0.1:8100/healthz` | reads `MYKRONOS_BUILD_SHA` from `docker inspect mykronos-backend`, the image ENV the backend serves. No token is handled. Live check: the stamp and the old `/healthz` value were both `667ff081` |
| container healthchecks (backend Dockerfile, both composes) | status code | unchanged |
| Concourse `mykronos.yml` backend reachability `curl -f` | status code | unchanged |
| `scripts/install-tunnel-route.ps1` `-VerifyUrl` | status code | unchanged |
| `jobs.py` public-reachability check | status code | unchanged |
| frontend `/api/healthz` | its own `"ok"`, never calls the backend | unchanged |
| `deployments.py` revision probe | `build.sha`, no credential | now `unparsed` against `/healthz` (and against TheHub's `/health` since #60709). `repo_onboardings.deployment_probe_url` was empty for every repository in production, so nothing regresses. A probe that authenticates is follow-up work |

**Not chosen.** A separate authenticated route for the SHA. It would be a
new gated path to keep in step with `EXEMPT`, and the same route answering
both callers was TheHub's choice too.
