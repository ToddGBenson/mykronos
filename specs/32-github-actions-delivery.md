# Spec 32 — GitHub Actions Delivery

**Status:** Draft for review
**Depends on:** [03 — Workflow Installer](03-workflow-installer.md), [04 — Scanner Workflows](04-scanner-workflows.md), [05 — Data Lake](05-datalake.md), [12 — Security](12-security-and-secrets-management.md), [14 — Network Scanning](14-network-scanning.md), [15 — Concourse Pipeline](15-concourse-pipeline.md), [16 — TheHub Delivery](16-thehub-delivery-pipeline.md)

---

## 1. Purpose

Move CI and CD for `mykronos`, `keel` and `personal-soc` off Concourse and
onto GitHub Actions, with Mykronos as the control plane: it installs the
workflows, enables and disables them, dispatches them on demand, and reads
their state back. TheHub stays on Concourse.

The end state is one execution environment for these three repositories, no
runner inside the LAN, and a delivery pipeline whose on/off switch is an API
call rather than an operator remembering `fly pause`.

## 2. What moves, and what deliberately does not

| Repository | Today | After |
|---|---|---|
| `mykronos` | `deploy/concourse/pipelines/mykronos.yml`, 19 jobs | GitHub Actions, GitHub-hosted runners |
| `personal-soc` | `deploy/concourse/pipelines/personal-soc.yml`, 11 jobs | GitHub Actions, GitHub-hosted runners |
| `keel` | GitHub Actions (scanning only) | GitHub Actions, plus the delivery lanes §5 adds |
| `thehub` | `deploy/concourse/pipelines/thehub.yml` | **Unchanged.** Spec 16 stands in full |

**Concourse is not decommissioned and `scanned_by` keeps all three values.**
TheHub is the largest pipeline here, it deploys to two environments through
the MinIO pointer mechanism of spec 16 §7, and it has no reason to move. Every
Concourse-shaped thing in the backend — `ConcourseClient`, the `concourse_*`
settings, the `scanned_by == "concourse"` branches in `api/repos.py`,
`jobs.py` and `dashboard.py` — stays and stays exercised.

That is the single most important constraint on this work. **This spec adds a
second reader and a second dispatcher; it does not replace the first.** A
change that makes the Actions path work by deleting the Concourse path breaks
TheHub, and TheHub is the one pipeline here that deploys to production.

**The ingestion contract does not change.** Spec 15 §4's seam is what makes
this cheap: the lake, Oracle, the dashboard and the Knowledge Store cannot
tell which CI produced a finding. `python -m mykronos.upload` is called from
an Actions step exactly as it is called from a Concourse task. No adapter, no
lake schema and no scoring path is touched by this migration.

**`.github/README.md` is wrong after this and must be rewritten, not
deleted.** It currently explains why this repository has no workflows. The
reasoning it records — D-038, D-039, the fork-PR refusal — is the history that
makes §3 and §4 legible, and the replacement should say what changed rather
than pretending the removal never happened.

## 3. The three repositories become public

`mykronos`, `keel` and `personal-soc` go public. This is a prerequisite, not a
side effect, and it settles the second of spec 15 §2's three reasons for
Concourse existing: **public repositories have unlimited GitHub Actions
minutes**, so the failure that put fifteen checks red on TheHub for a billing
reason cannot happen to these three.

It also settles §4 in a direction that is not negotiable afterwards. **A public
repository must not have a self-hosted runner.** A pull request from a fork
executes the contributor's workflow, and a runner registered on `192.168.0.14`
sits beside the registry, MinIO, TheHub's Postgres and the Vault. GitHub's own
guidance is not to do this; spec 14 §4 and spec 15 §7 both refused it when the
question was Concourse's worker. Going public means §4 has to actually
dissolve the LAN dependencies rather than relocate them, which is why §4 is
the longest section here.

**Before the flip, per repository:**

1. `gitleaks detect` over **full history**, not the working tree. The
   `secrets` lanes scan commits as they land; nothing has scanned the whole
   history against the standard of "this is about to be world-readable".
2. Confirm the ignored-secret set was never committed. It was not, as of
   2026-08-28: `deploy/concourse/.env`, `deploy/concourse/vault/init.json`,
   `deploy/thehub/.env` and `*.db` have zero commits each and are all covered
   by `.gitignore`. Re-run the check at flip time rather than trusting this
   paragraph.
3. Review `.gitleaksignore`. An allowlisted finding that was acceptable in a
   private repository is a different decision in a public one.
4. Confirm the demo tokens stay obviously fake. `demo-gate-token-not-a-secret`
   and `demo-admin-token-not-a-secret` are named the way they are precisely so
   this review is a five-second one.
5. `deploy/concourse/pipelines/*.yml` become world-readable, including
   TheHub's. They contain `((var))` references and no values — that is the
   property CNC-2 exists to keep, and it is now load-bearing rather than
   tidy.

**What going public costs.** Fork pull requests get workflow runs, which means
the ingestion token must never be reachable from one. GitHub does not pass
secrets to workflows triggered by `pull_request` from a fork, so the fail-fast
probe and the upload step in `_base.yml.j2` will both fail there with an empty
token. That is the correct outcome and it must be made *legible* rather than
mysterious — see §5.4.

## 4. Every LAN dependency dissolves

Concourse's worker is inside the LAN. The pipelines therefore reach four
things a GitHub-hosted runner cannot: a plain-HTTP registry at
`192.168.0.14:5000`, MinIO at `192.168.0.14:9000`, a demo stack and ZAP daemon
at `192.168.0.14:3200/8201/8290`, and — historically — `192.168.0.0/16`
itself.

The last one is already gone, and noticing that is what makes this migration
possible at all.

| What | Endpoint today | Answer |
|---|---|---|
| Ingestion API | `mykronos.toddbenson.net` (Cloudflare tunnel) | Already public. Unchanged |
| Network scan | *not in CI* — a Windows Scheduled Task runs it | Unchanged. §4.5 |
| Container registry | `192.168.0.14:5000` | GHCR. §4.1 |
| Demo stack + ZAP | `192.168.0.14:3200/8201/8290` | Ephemeral stack inside the job. §4.2 |
| Build artifacts, SBOMs | MinIO `192.168.0.14:9000` | Actions artifacts + Releases. §4.3 |
| netassess run ingest | MinIO `192.168.0.14:9000` | A backend job, not a CI job. §4.4 |
| Deploy | human runs `deploy.ps1` on the host | Unchanged mechanism, new pull source. §4.6 |

### 4.1 The registry becomes GHCR

`build`, `publish-backend`, `publish-frontend`, `containers` and `promote` all
address `((registry))`, which resolves to `192.168.0.14:5000` — a registry with
no TLS and no authentication, reachable only from the LAN.

They move to `ghcr.io/toddgbenson/mykronos-backend` and
`.../mykronos-frontend`. Public repositories get unlimited free GHCR storage
and bandwidth, `GITHUB_TOKEN` authenticates the push with `packages: write`
and no secret to manage, and Trivy scans a GHCR reference exactly as it scans
a LAN one — `containers` already scans "the published images out of the
registry directly. No daemon", so it is a hostname change.

**`promote` stays a tag move and stays gated.** Spec 15 §3's rule that the
gate holds the tag rather than the artifact (D-047) is unaffected: images
publish as `:${SHA}`, `containers` scans that SHA, and `:latest` moves only
after an Oracle `go`. On GHCR the retag is `docker buildx imagetools create`
against the digest, which is *better* than the current `crane` step because a
digest cannot be raced by a second push to the same tag.

**What this gains beyond reachability**, worth stating so the migration is not
read as pure cost: authentication where there is none today, immutable
digests, and a retention policy that is configured rather than absent.

**What this gives up.** Pulls now cross the internet. `deploy.ps1` on the host
pulls a few hundred megabytes from GHCR rather than from a machine on the same
switch. Measure it once before assuming it is fine; if it is not, a
pull-through cache on the host is a smaller thing than keeping a self-hosted
runner.

### 4.2 The demo environment moves inside the job

`demo-and-dast` runs the functional suite through ZAP's proxy and then scans,
against a **long-lived demo stack on the host** that somebody else rebuilds
with `deploy/demo/Invoke-DemoRebuild.ps1`. The job's own comments record what
that arrangement costs:

- `serial: true`, because there is one ZAP daemon and one site tree, and
  "builds 8 and 9 started while [7] was still scanning" wiped it.
- A preflight that fails with *"No demo environment at $BACKEND. Rebuild it on
  the host"* — a CI job blocked on a manual step.
- A seeded-repository count check, because "a stale environment is worse than
  none: it answers, so the suite passes, and the DAST result describes an
  application nobody is shipping."

All three are consequences of one shared, persistent, hand-maintained
environment. A GitHub-hosted runner is ephemeral, so the job stands the stack
up itself with `docker compose up` from `deploy/demo/`, runs ZAP as a
container beside it, and tears it down. Concurrency stops mattering, the
preflight becomes unnecessary, and the environment cannot be stale because it
did not exist ninety seconds ago.

**This is the step most likely to be underestimated.** `Invoke-DemoRebuild.ps1`
is PowerShell that seeds the environment, and the seeding is what the
`REPOS < 1` check is guarding. Porting it to something a Linux runner can run
— or invoking `pwsh` on the runner, which is preinstalled — is real work, and
it is the task that decides whether this migration is a week or three.

**DAST's resource budget still applies.** D-053 paused DAST because ZAP's
active scan measured 548% CPU and 7 GiB on this host. A GitHub-hosted runner
is 4 vCPU / 16 GB, which does not make that measurement go away — it makes it
somebody else's hardware, and it makes the scan's *duration* the constraint
instead of the host's health. Keep the passive-scan-only posture D-053 left in
place and revisit it with a measurement, not an assumption.

### 4.3 Artifacts and SBOMs leave MinIO

Spec 15 §5 chose MinIO for build artifacts and SBOMs because "Concourse's `s3`
resource is first-class". Actions has its own first-class answer and no
retention story to invent:

| Class | Where | Retention |
|---|---|---|
| Build artifacts (wheel, frontend bundle) | `actions/upload-artifact` | 30 days, which is what spec 15 §5 already specified |
| SBOMs | Release assets, attached per tag | Indefinite, which is what spec 15 §5 already specified |
| Raw tool output | `/api/ingest/raw`, unchanged | Spec 05 §7 |

The retention requirements are met without a bucket, and `reprocess` is
unaffected because raw output never went to MinIO in the first place.

### 4.4 The netassess ingest becomes a backend job

`personal-soc`'s `netassess-ingest` and `netassess-freshness` are the only
lanes in these three repositories that genuinely need MinIO, and they need it
to *read* an artifact somebody else wrote.

They should not be CI jobs at all. `netassess-ingest` fetches two zips,
compares them, and decides whether the run is worth believing — it is triggered
by an artifact appearing rather than by a commit, and it consumes no source.
It runs in Concourse because Concourse was the only scheduler available.

**Move both into the backend as scheduled jobs** alongside the rotation sweep
in `jobs.py`. Mykronos is on the host, already has MinIO credentials, already
has the lake to write to and the Slack alerting to shout with, and already
runs periodic work. The verify-and-diff logic ports as-is; only its trigger
and its output path change.

This is the one place where this plan adds backend code rather than removing
it, and it is worth being explicit that the code is a port of an existing bash
task, not a new subsystem.

### 4.5 Network scanning is already outside CI, and stays there

Spec 14 §4 and spec 15 §8 both describe network scanning as the capability
that requires a second execution environment inside the LAN. **That stopped
being true and the specs were never updated.**

`personal-soc.yml`'s `netassess-ingest` says so directly: *"The scan does not
run here. It runs on Windows, under the 'personal-soc Weekly Network Scan'
Scheduled Task, and `publish-netassess-run.ps1` puts the result in MinIO."*
The measurement that forced it is recorded in the same comment — an nmap sweep
from a Concourse task reported all 256 addresses up, including `.0` and
`.255`, because Docker Desktop's NAT answers every probe, while the host's ARP
table had 38 entries. MAC-keyed inventory needs L2 adjacency a container does
not have.

So the scan already runs on the host, not in any CI system, and moving CI to
GitHub-hosted runners does not touch it. **Spec 14 §4 and spec 15 §8 should be
amended to say so** — they are the two documents an operator would read before
concluding this migration is impossible.

### 4.6 Deploy keeps its mechanism

For `mykronos`, D-038 already answered this: the pipeline publishes an image
and a human runs `deploy/mykronos/deploy.ps1` on the host. Nothing in CI
deploys, so nothing in CI needs the LAN. `deploy.ps1` changes one hostname to
pull `:latest` from GHCR instead of `192.168.0.14:5000`.

**The Actions-native gate is a GitHub Environment**, not a job that waits. A
`production` environment with required reviewers turns "a person clicks a
button in Concourse" (spec 16 §3) into the same act with an audit trail and an
identity attached. That is available now for the `promote` lane and should be
used for it.

**A backend-mediated deploy request is deliberately out of scope.** It would
be a `POST /api/deploy/request` that writes the `<env>.requested` pointer of
spec 16 §7, letting Actions ask for a deploy without reaching the LAN. It is
the right shape and it is not needed by any repository moving here — TheHub is
the only repository whose pipeline deploys itself, and TheHub stays on
Concourse. Building it now would be building for a user that does not exist.

## 5. The delivery lanes become templates

The template library holds fourteen capabilities and every one of them is a
*scanner*. Nothing renders a build, a publish, a promote or a deploy, because
until now the only Actions workflows Mykronos generated were the ones it
installs into other people's repositories, where build and deploy are none of
its business (spec 15 §2).

That reasoning does not extend to a repository Mykronos owns. Four new
templates:

| Template | Target | What it does |
|---|---|---|
| `build.yml.j2` | `.github/workflows/mykronos-build.yml` | Compile, package, upload artifacts |
| `publish.yml.j2` | `.github/workflows/mykronos-publish.yml` | Push `ghcr.io/...:${SHA}`, attach SBOM |
| `promote.yml.j2` | `.github/workflows/mykronos-promote.yml` | Retag `:SHA` → `:latest` behind the Oracle gate and an Environment approval |
| `deploy.yml.j2` | `.github/workflows/mykronos-deploy.yml` | Optional per repo; for `mykronos` it is a no-op today (§4.6) |

**These are opt-in and default off.** A repository onboarded to Mykronos gets
scanners; it gets delivery lanes only if somebody enables them. The installer
already keys everything off `enabled_capabilities`, so this is four manifest
entries and four templates, not a new mechanism.

**They must not inherit `_base.yml.j2` unchanged.** The base template's
skeleton — fail-fast ingestion probe, scan steps, upload step — describes a
scanner. A build lane has no findings to upload and no `results-path`. It
should report a **ScanRun and no findings**, exactly as the quality lanes do
under D-046, so that §7's cross-check can tell a build that ran from a build
that did not. `_test_lane.yml.j2` is the closer relative and the better parent.

### 5.1 Three Concourse jobs have no template at all

`lint-and-types`, `frontend` and `qa-spec-links` exist only in `mykronos.yml`.
Under `CAPABILITY_BY_JOB` they all report as `qa`, alongside `qa-spec-links`,
which is "a richer answer rather than a collision" because quality stages carry
no findings.

The `qa` template must grow to cover them or they are silently lost in the
move — and "silently lost" is precisely the failure §7's cross-check exists to
catch, so losing them would be an unusually ironic way to do this.

(`api-inventory` and `prompt-evals` appear in `CAPABILITY_BY_JOB` and are
TheHub's jobs, not this repository's. They stay in Concourse and need no
template. The mapping table covers all three pipelines, so it is not a list of
what moves.)

`pin-check` (D-051's uploader-provenance check) is a fourth job with no
template. It is not a capability; it is a guard that belongs as a step in every
lane that installs the package, which is what `_base.yml.j2` should do
centrally.

### 5.2 CodeQL is available again, and Semgrep may stay

Spec 16 §5 replaced CodeQL with Semgrep because CodeQL "is available to public
repositories and GHAS customers rather than a self-hosted worker", and TheHub
is neither. `mykronos`, `keel` and `personal-soc` become public, so CodeQL
becomes available to all three.

**This is not automatically a change worth making.** Two scanners producing
findings the ingestion upsert makes indistinguishable is the exact duplication
D-039 removed. Pick one per repository, deliberately, and record which.

### 5.3 `insider` has no pull-request event here either

`ci.py` documents why `insider` is absent from `CAPABILITY_BY_JOB`: Aegis
assesses a pull request, the pipelines trigger on pushes to main, and
cross-checking it "reported every green insider job as a silent failure".

On Actions this improves on its own. `aegis.yml.j2` already triggers on
`pull_request` and review events, so a repository whose work arrives through
pull requests gets real assessments. It stays `event_driven` in the coverage
model regardless (§7), because a webhook-fed capability has no job-versus-scan
comparison to make.

### 5.4 Fork pull requests must fail legibly

Per §3, a `pull_request` run from a fork gets no secrets, so
`secrets.MYKRONOS_INGESTION_TOKEN` is empty. Today the fail-fast probe would
`curl --fail` against the ingestion API with an empty bearer token and exit
non-zero with a 401 — technically correct, and it reads as "Mykronos is broken"
to a contributor who has no idea what Mykronos is.

`_base.yml.j2` gains an explicit guard: if the token is empty **and** the event
is a fork pull request, skip the upload and say why, in one line, in the job
summary. A scan that could not report is not the same as a scan that failed,
and spec 01 §6 forbids silently skipping — so it is skipped *loudly*.

## 6. Install is a pull request. Enable and disable are API calls.

Three states, and the mechanism differs by state on purpose:

| Action | Mechanism | Why |
|---|---|---|
| **Install** | Pull request, exactly as spec 03 §3 | Adding code that runs in a repository is a change a human reviews. Unchanged |
| **Enable** | `PUT /repos/{o}/{r}/actions/workflows/{id}/enable` | Instant, no PR |
| **Disable** | `PUT /repos/{o}/{r}/actions/workflows/{id}/disable` | Instant, no PR |
| **Uninstall** | Pull request that deletes the file | Removing code is still a code change |

**Why disable is not a pull request.** Spec 03 §3 offers `--soft-disable` as
"set it to `if: false` at the job level", which is a commit, which is a PR,
which is a review round-trip. The state an operator actually needs at 2am is
"stop this lane now" — the equivalent of the `fly pause` that spec 15 §4a.1's
caveat calls "state only an operator remembers". GitHub has a first-class API
for it, and using it means the off switch is one call and the file on disk
still says what the lane does when it comes back.

**The state is derived, not stored**, following the same rule §4a applied to
pipeline names. `GET /repos/{o}/{r}/actions/workflows` returns each workflow's
`state`: `active`, `disabled_manually`, `disabled_inactivity`, `disabled_fork`.
A `workflow_enabled` column in `RepoOnboarding` would be a second place for the
truth to live, and it would be wrong the moment somebody clicks Disable in the
GitHub UI. Re-deriving on every read cannot go stale.

`disabled_inactivity` is worth surfacing distinctly: GitHub disables scheduled
workflows in repositories with no activity for 60 days. A capability that
stopped running because nobody pushed for two months is a real coverage gap
and it looks identical to a deliberate pause unless the reason is rendered.

### 6.1 The App already holds `actions: write`

An earlier draft of this spec made re-registering the App the first step of the
migration, on the assumption that enabling and disabling workflows needed a
permission the App did not have. It does not: `actions: write` has been in
`REQUIRED_PERMISSIONS` (`github/client.py`) since the scan-now button needed it
to call `dispatch_workflow` (spec 17 §2.5), and it is the same permission
GitHub documents for `PUT .../actions/workflows/{id}/enable|disable` and for
reading workflows and runs in §7.

**So there is no re-consent step and no 403 window.** This is recorded rather
than quietly deleted because "the App needs a new permission" is the kind of
prerequisite that gets planned around for weeks, and the whole of §6 and §7 is
buildable today without touching the App registration.

The narrow consequence for §7 is worth keeping: the status read now spends a
permission the platform already relies on for dispatch, rotation and the
installer, which is exactly why §7.1's rate-limit budget matters.

### 6.2 The API surface

Additive to `api/repos.py`:

```
GET    /api/repos/{id}/workflows            -> installed, state, last run
PUT    /api/repos/{id}/workflows/{cap}/enable
PUT    /api/repos/{id}/workflows/{cap}/disable
```

`PATCH /api/repos/{id}/capabilities` keeps its current meaning exactly:
install and uninstall, through a pull request, with `install_workflows` gating
on `scanned_by == "github_actions"`. Enable and disable are a different verb on
a different noun and do not touch `enabled_capabilities` — a disabled workflow
is still an enabled capability whose lane is paused, and conflating the two
would make the grant registry lie about what may write.

The CLI gains `mykronos workflows <repo>`, `enable-workflow` and
`disable-workflow` to match, because §6's whole point is an off switch that
works when the dashboard is the thing that is down.

**Status: built, 2026-08-28.** The three endpoints, the three CLI commands and
a `WorkflowSwitches` panel on the repository Dashboard tab are in, with
`list_workflows` / `set_workflow_state` on the GitHub client protocol, its
fake and its real implementation. `tests/test_workflow_state.py` covers the
listing states, both switches, the audit entry and the invariant below.

The panel is deliberately **separate from `capability-manager.tsx`** rather
than a mode of it. That control asks whether a repository should be scanned
for something — answered by a pull request, because it adds or removes code
that runs in somebody's repository. This one asks whether the lane that
already exists is switched on. One button for both would have made the fast
path indistinguishable from the slow one and implied that pausing a lane
withdraws the capability.

The invariant worth a test of its own, and it has one: **disabling a workflow
leaves `enabled_capabilities` and the grants untouched.** If disabling
narrowed the grants, re-enabling would leave a lane that runs and cannot
write — findings 403 at upload and the lane looks green for a reason nobody
can see.

## 7. The return path: Mykronos reads Actions

`ci.py` is 465 lines that read Concourse and answer two questions — where is
this repository built, and is each capability actually reporting (spec 15
§4a.1). All of it must keep working for TheHub while an Actions equivalent
answers the same questions for the other three.

**Refactor into a protocol, not a rewrite.** `PipelineStatus`, `JobStatus`,
`Reporting`, `StageCoverage`, `coverage()` and `reconcile()` are already
CI-agnostic — they take job names, statuses and timestamps. Only
`ConcourseClient` knows about Concourse. So:

- Keep every dataclass and both pure functions exactly as they are.
- Extract the two methods the callers use into a small protocol, and add an
  `ActionsClient` implementing it against
  `GET /repos/{o}/{r}/actions/workflows` and `.../actions/runs`.
- Dispatch on `scanned_by`, the same split `scan_now` and fix-verification
  already use.

`reconcile()` and `coverage()` are the parts that took two attempts to get
right (§4a.1's "two rules the first implementation got wrong"). They are also
the parts with no CI-specific content. Not touching them is the point.

**Status: built, 2026-08-28.** `ActionsClient` sits beside `ConcourseClient`
in `ci.py`; `JobStatus`, `PipelineStatus`, `Reporting`, `StageCoverage`,
`reconcile()` and `coverage()` are byte-for-byte unchanged. `repo_ci` in
`api/dashboard.py` dispatches through a new `_ci_status` helper on
`scanned_by`, and `scanned_by="none"` now gets its own answer rather than a
Concourse lookup for a pipeline nobody claimed. `tests/test_ci_actions.py`
covers it, including the four cross-check states end-to-end through the
untouched functions.

**The vocabulary translation is the part that would have failed silently.**
GitHub reports `success`; every consumer here compares against `succeeded`.
A client passing the conclusion through unchanged would have left every green
lane reading `not_run`, `coverage()` reporting the whole repository as never
scanned, and nothing raising anywhere. `_STATUS_BY_CONCLUSION` does the
mapping in one place, and `skipped` and any conclusion GitHub adds later both
resolve to *not run* rather than to a success — the safe direction, because
"has not run" invites a look and a wrong "succeeded" ends the conversation.

Two behaviours worth recording because they are judgement calls, not
mechanics:

- **A disabled workflow reports no status, not its last one.** Its final run
  may well have succeeded; the lane is switched off now, so that result
  describes a commit nobody is checking. Showing the green tick would be the
  "green pipeline, stale data" disagreement §4a.1 exists to surface.
- **A workflow the installer did not write is skipped, not guessed at.** A
  repository's own `release.yml` is somebody else's lane, and crediting it to
  a capability would invent coverage this platform cannot vouch for.

**The job-to-capability mapping stops being a heuristic.** In Concourse,
`CAPABILITY_BY_JOB` is guesswork about names somebody else chose, and it is
documented as such. On Actions the installer *chose the filename* —
`mykronos-<capability>.yml` — so the mapping is exact for every installed lane,
and remains a heuristic only for a repository's own hand-written workflows.
That is a strict improvement and it should be implemented as a lookup on the
template target path, not by copying the Concourse table.

**Four properties of §4a must survive, and two of them get harder:**

- *Derived, not configured.* Kept, and stronger — the workflow file name comes
  from the template registry.
- *Never reads logs.* Kept. Run metadata only. Actions logs carry the same
  scanner output and the same risk.
- *Fails soft, always.* Kept, and now with more ways to fail: an expired
  installation token, a 403 from an installation that has not re-consented
  (§6.1), and rate limiting. Each resolves to "unavailable, and here is why",
  never an exception reaching a handler.
- *Reads anonymously.* **Lost.** Concourse was read with no credential because
  the pipelines are `public: true` on a loopback-bound server. GitHub needs an
  installation token, which the backend already mints. No new secret, but the
  "no credential to leak" property of §4a is gone and the spec should say so.

### 7.1 Rate limiting is a new constraint

`ConcourseClient._get` is a synchronous `httpx2.get` with a 3-second timeout
against a server on the same host. Reading GitHub is a network round-trip
against a 5000-requests-per-hour installation limit, from inside a dashboard
request handler.

Two consequences the current design does not have:

- **It must be cached.** A short TTL — 60 seconds is generous for a panel
  showing build states — turns a per-request cost into a per-minute one.
  Without it, the portfolio page fans out one or two calls per repository on
  every render.
- **It must be async.** The GitHub client is `async`; `ConcourseClient` is
  sync. `dashboard.py` and `api/repos.py` call it inline. Whichever way this
  resolves, it must not turn a fail-soft read into a blocking one — a rate
  limit is "unavailable", not a slow page.

**A budget, not just a cache.** Exhausting the installation's rate limit to
render a status panel would break token rotation, the installer and Patchwork,
which share it. The status read is the least important consumer and should be
the first to give up.

**Status: built, 2026-08-28.** `StatusCache` on `app.state`, TTL from
`ci_status_cache_seconds` (default 60s), bounded at 512 entries. **Successes
only are cached** — caching a failure would pin a transient outage in place
for the whole TTL, and "GitHub did not answer" is exactly the answer somebody
reloads the page to change. The async question resolved itself: `status_for`
had exactly one call site, in an already-`async` handler, so `ActionsClient`
is async and `ConcourseClient` stays synchronous and untouched. The
per-repository run read is one call for the whole repository rather than one
per workflow, for the same budget reason.

## 8. Secrets

Spec 15 §6 put pipeline credentials in Vault because "Concourse pipeline YAML
is committed. Nothing sensitive may appear in it." Actions has repository
secrets and environments, and for these three repositories Vault stops being in
the path.

| Secret | Today | After |
|---|---|---|
| Ingestion token | Vault, per pipeline | Actions secret `MYKRONOS_INGESTION_TOKEN` — already how every installed repo works |
| Registry credentials | Vault | None. `GITHUB_TOKEN` with `packages: write` |
| MinIO keys | Vault | None in CI. The backend keeps its own for §4.4 |
| Slack webhook | Vault | Actions secret, or drop it — see §11.5 |
| Deploy credentials | Vault, scoped per job | Environment secrets, scoped per environment |

**Vault stays, for TheHub.** Its pipeline still resolves `((var))` and
`deploy/concourse/VAULT.md` still describes the deployment. What shrinks is how
much depends on it.

**This fixes the deferred token rotation.** `jobs.py` currently refuses to
rotate a Concourse-scanned repository's token because "the only delivery path
this job has is a GitHub Actions secret (D-086)" — it logs a warning, defers,
and tells an operator to run `Import-EnvSecretsToVault.ps1` by hand. Three of
the four repositories stop needing that the day they flip to
`scanned_by=github_actions`, which is a real operational win and should be
verified explicitly rather than assumed.

**Environments carry the deploy credentials.** Spec 15 §6's rule — "a pipeline
where the test job can read production credentials has no meaningful
separation" — maps exactly onto GitHub Environments, which scope secrets to the
jobs that declare them and add the reviewer gate §4.6 wants.

## 9. Migration order

Each step is separately revertible, and no step makes the previous one
unrevertible. The Concourse pipeline stays applied and running until step 8.

1. **Enable/disable API, CLI and UI** (§6), against the repositories that are
   already `scanned_by=github_actions`. Deliverable on its own, useful
   immediately, independent of everything below, and needing no change to the
   App registration (§6.1).
2. **`ActionsClient` and the `ci.py` protocol split** (§7). Keel is the test
   case: Actions-scanned, no Concourse pipeline, and today its CI panel
   correctly says nothing covers it. It should start saying something true.
3. **Go public** (§3), one repository at a time, `keel` first because it has
   the least history and no pipeline to break.
4. **Port `mykronos`'s quality and security lanes** to Actions templates and
   run them *alongside* Concourse. Duplicate findings for a week is exactly
   what D-039 removed — accept it deliberately and briefly, because the
   ingestion upsert makes the two indistinguishable, which is what makes a
   parity check possible at all.
5. **Port the delivery lanes** (§5): build, publish to GHCR, promote,
   containers against GHCR. Point `deploy.ps1` at GHCR.
6. **Port `demo-and-dast`** (§4.2). Late, because it is the largest single
   piece of work and the one most likely to need a second attempt.
7. **Move the netassess jobs into the backend** (§4.4), then port
   `personal-soc`'s remaining lanes.
8. **Retire `mykronos.yml` and `personal-soc.yml`**: `fly destroy-pipeline`,
   delete the YAML and the `set-*-pipeline.ps1` scripts, rewrite
   `.github/README.md` (§2). `thehub.yml`, `docker-compose.yml`, Vault and
   `ConcourseClient` all stay.

**The parity check that decides step 8** is §7's own cross-check, run against
both systems: every capability that reads `reporting` under Concourse must read
`reporting` under Actions before the Concourse pipeline is destroyed. A lane
that reads `silent` or `never_reported` on the Actions side is a lane that has
not moved yet, whatever its badge says. This is what §4a.1 was built for — "its
first day of existence found a lane that had been green on every build and had
never reported once" — and this migration is the largest opportunity to create
that failure mode since it was written.

## 10. Acceptance criteria

1. A commit to the default branch of `mykronos` triggers its Actions pipeline
   within one minute.
2. Quality lanes run in parallel and a failure in any one stops the run before
   the security stage — spec 15 §9.2, unchanged in substance.
3. Findings appear in Mykronos with **repo-relative paths**, and dependency and
   container findings carry a package name and version. Verified against the
   dashboard, not the workflow logs. Spec 15 §9.3, unchanged.
4. Raw tool output is archived and `mykronos reprocess` can re-derive findings
   from it. Spec 15 §9.4, unchanged.
5. An Oracle `no_go` prevents `promote`, and the decision is visible in the
   dashboard with its reasoning.
6. Images are published to GHCR as `:${SHA}`; `:latest` moves only after a `go`
   and an Environment approval; `deploy.ps1` pulls the promoted image and the
   deployed SHA matches.
7. No credential appears in workflow YAML, in a run log, or in an image layer —
   and the repository is public, so this criterion is now checkable by anyone.
8. For each of the three repositories, every capability that read `reporting`
   under Concourse reads `reporting` under Actions, with no `silent` or
   `never_reported` rows introduced by the move.
9. Disabling a capability's workflow from Mykronos stops its next scheduled and
   push-triggered run, takes effect without a pull request, and is visible as
   `disabled_manually` rather than as an absence.
10. A fork pull request runs the scanners, cannot read the ingestion token, and
    reports that fact in the job summary rather than failing with a 401.
11. TheHub's pipeline, its Vault secrets and its CI panel are unaffected
    throughout, verified after each step rather than at the end.

## 11. Open questions

1. **Does `Invoke-DemoRebuild.ps1` port to a Linux runner, or does the demo
   stack need `pwsh` on the runner?** §4.2 assumes one of the two works. This
   is the largest unknown in the plan and the one that should be spiked first,
   before step 5 rather than at step 7.
2. **CodeQL or Semgrep, per repository?** §5.2. Running both is the duplication
   D-039 removed; the choice needs making rather than defaulting.
3. **Does the GHCR pull cost enough to matter for `deploy.ps1`?** §4.1. Measure
   once; a pull-through cache is the answer if it does.
4. **Does DAST's D-053 budget change on a GitHub-hosted runner?** §4.2. The
   answer is a measurement, and the passive-only posture holds until there is
   one.
5. **Should the Slack alerting move, or be dropped?** Every Concourse job
   carries `on_failure: *slack_alert`. Actions can do the same, and Mykronos
   already has a notification path (`notify.py`) that knows about findings.
   Routing failures through Mykronos rather than through the CI system is more
   consistent with "reports to Mykronos", and is a decision this spec does not
   make.
