# Spec 16 — TheHub Delivery Pipeline

**Status:** Draft for review
**Depends on:** [04 — Scanner Workflows](04-scanner-workflows.md), [06 — Aegis](06-aegis-integration.md), [09 — Oracle](09-oracle-risk-decision-engine.md), [12 — Security](12-security-and-secrets-management.md), [15 — Concourse Pipeline](15-concourse-pipeline.md)

> **Process note — this spec did not go through i2i, and should have.**
>
> "Run through i2i" was the instruction this work started from. It was read as
> a generic idea-to-implementation discipline — write the spec, implement
> against it, record the decisions — and that is what happened here.
>
> i2i is not generic. It is TheHub's own Idea-to-Implementation funnel, with
> four named phases whose canonical definition is
> `config/pipeline_phases.yaml` and whose surface is Mission Control →
> Delivery → I2I:
>
> | Phase | Idea to Inception |
> |---|---|
> | Scoping | Idea → problem definition (an oplan, `status=active`) |
> | Discovery | Problem → validated concept (epic ideation) |
> | Framing | Validated concept → epic (decomposition, requirements) |
> | Inception | Epic → ready stories. *Ready-for-Dev is the output, not a phase* |
>
> Against that, this spec is roughly a Framing artefact — it decomposes the
> problem and states requirements — reached without Scoping or Discovery, and
> Inception produced no stories because none were ever created. **There is no
> oplan and no epic in TheHub for any of this work**, so none of it appears in
> the funnel it was supposed to run through, and the delivery pipeline this
> spec describes reports stages against a lifecycle that has no record of why
> they exist.
>
> Recorded rather than quietly corrected, because the gap is the interesting
> part: a pipeline that reports into a lifecycle it never entered is exactly
> the drift §13 was written to prevent, arrived at from the other direction.

---

## 1. Purpose

Spec 15 built a pipeline that *scans* TheHub and stops there, because at the
time nothing in this platform had an answer to "who owns the deploy target".
D-038 answered that question for Mykronos and left TheHub where it was.

This spec takes TheHub the rest of the way: one pipeline that scans a commit,
asks Oracle whether it may ship, delivers it to a demo environment, probes that
running environment with DAST, and then waits — indefinitely, for a person —
before anything reaches production.

It also absorbs the eight capability lanes that used to be split across two CI
systems. Spec 15 §2 argued that a second CI system duplicating the first is a
liability; §10 asked whether both should run for one repository. §4 of this
spec settles it in the direction that removes the duplication rather than
managing it.

## 2. What "delivery" means here, precisely

Two Docker Compose stacks on the same host, distinguished by compose project
name and published port range:

| Environment | Project | Reached at | Gets a commit when |
|---|---|---|---|
| demo | `thehub-demo` | `((thehub-demo-url))` | The static security lanes and the image scan are green (§3) |
| prod | `thehub-prod` | `((thehub-prod-url))` | A person clicks a button in Concourse |

Both run the *same image*, identified by the commit SHA, pulled from the
registry the pipeline already publishes to (spec 15 §5). Promotion is
therefore a restart against a tag that already exists, never a rebuild — the
artifact production runs is byte-identical to the one DAST probed, which is the
only version of "we tested it" that survives contact with a rebuild.

**The manual gate is a job with no trigger, not a separate approval step.**
Concourse will not start a job whose inputs are not set to trigger it, so
`deploy-prod` waits until somebody clicks it. A distinct "promote" job that
re-tagged the image and a "deploy" job that followed it was considered and
dropped: it adds a registry write and a second failure mode to record a fact —
that a person approved this SHA — which Concourse's own build history already
records, against the person who authenticated.

**The demo environment is not a copy of production.** It has its own database
volume and its own configuration. Nothing in this pipeline copies production
data into it, and nothing should: a lower environment holding real data is a
production environment with weaker controls and a different name.

## 3. Topology

```
   git ──▶ unit ──▶ build ──▶ containers ─┐
   git ──▶ secrets ───────────────────────┤
   git ──▶ sast (semgrep) ────────────────┤
   git ──▶ dependencies (osv + SBOM) ─────┤
   git ──▶ prompt-evals ──────────────────┤
   git ──▶ iac (checkov) ─────────────────┘
                                          │
                                ┌─────────▼─────────┐
                                │   deploy demo     │
                                └─────────┬─────────┘
                                          │ healthy
                                ┌─────────▼─────────┐
                                │   dast (ZAP)      │  ◀── probes demo
                                └─────────┬─────────┘
                                          │
                                ┌─────────▼─────────┐
                                │   oracle gate     │  ◀── now sees DAST
                                └─────────┬─────────┘
                                          │ not no_go
                                ┌─────────▼─────────┐
                                │  insider (aegis)  │
                                └─────────┬─────────┘
                                          │
                                ┌─────────▼─────────┐
                                │   deploy prod     │  ◀── MANUAL
                                └───────────────────┘

   timer ─▶ cloud posture (prowler, Azure)   ── independent of any commit
```

`iac` scans this repository's Dockerfiles and workflow definitions with
checkov (D-046). Its first run found that both Dockerfiles lack a `USER`
directive — true, and false about the running container, which drops to
`appuser` through `gosu` in `entrypoint.sh`. Both are skipped with that
reason recorded in the Dockerfile itself, which is the outcome worth having:
the claim "we already handle that" is now written where a scanner will keep
re-asking it.

**Oracle runs after DAST, and insider after Oracle.** This is a change from the
first version of this spec, and it trades one thing for another rather than
being a straight improvement.

*What it buys.* Oracle previously scored before DAST had run, so no runtime
finding could ever influence a decision — the gate judged the code and never
the running service. It now sees them. That is a real gain, and it is the same
argument spec 15 §3 makes for putting Oracle after the static lanes, applied
consistently.

*What it costs, and this is the part to watch.* Oracle's score will now never
include insider risk, because the insider lane is downstream of it. The first
Oracle run on the Mykronos pipeline said so out loud — *"Not yet consulted:
insider_risk — these are recorded as unavailable rather than zero, so this score
is a partial picture by construction"* — and under this ordering that sentence
becomes permanent rather than a timing artefact. Insider risk is no longer an
input to the risk score; it is a separate gate in front of production.

*Why that is defensible.* The two answer different questions. Oracle asks "is
this build too risky to ship", which is about the artefact. Aegis asks "did a
person with access change something sensitive without review" (spec 06 §2),
which is about the change and is a judgement a human makes at the moment of
promotion. Putting it immediately before the manual prod job is where a
reviewer is actually looking.

*The demo deploy is no longer Oracle-gated.* It cannot be — DAST needs a
running environment, and Oracle now waits for DAST. Demo is gated on secrets,
SAST, dependencies and the image scan, which is the whole static picture. A
commit Oracle later refuses will have reached demo; nothing reaches production,
which is the boundary that matters.

**Build moved to before the gate, and that is a change from spec 15 §3.** Spec
15 put build after Oracle so that no image exists for a commit Oracle refused.
That ordering cannot survive container scanning: you cannot scan an image you
have not built, and a `containers` lane that reads Dockerfiles instead of
images — which is what TheHub's current lane does, and says so — is not
container scanning. It reports no base-image CVEs at all.

The concern spec 15 raised is real and is addressed differently: the image is
tagged with the commit SHA and nothing else, and **only the deploy jobs ever
name a tag**. An image built from a refused commit sits in the registry
unreferenced. The gate protects the deploy, which is the step that matters,
rather than the build, which produces a file.

**Every lane that feeds a finding into the lake still completes before the
gate** — secrets, SAST, dependencies, containers and now DAST. Spec 15 §3's
reasoning is why: Oracle scores the whole picture, and gating on a partial one
produces a decision the next finding invalidates. The one exception is insider
risk, which is downstream by design and is discussed above; it is a gate in its
own right rather than an input to the score.

## 4. One CI system, not two

D-038 split the two lanes by purpose: Actions kept pull-request feedback,
Concourse owned the full pipeline. That rule is withdrawn for repositories this
operator owns, and the reasoning that retires it is the same reasoning that
created it.

The split only pays for itself when both halves run. TheHub's Actions
allowance is exhausted, so its half never runs — spec 15 §2 is entirely about
that. Mykronos's own workflows do run, and they scan the identical commits
Concourse scans, producing identical findings that the ingestion upsert makes
indistinguishable. D-038 called that "worse than harmless" and then left it in
place, because nothing yet ran the full set in Concourse.

Now something does. The five workflows in `.github/workflows/` are removed and
their function moves into `deploy/concourse/pipelines/mykronos.yml`:

| Was | Becomes | Note |
|---|---|---|
| `ci.yml` backend job | `unit`, `lint-and-types` | Already existed |
| `ci.yml` frontend job | `frontend` | New. Includes the OpenAPI drift check |
| `ci.yml` secrets job | `secrets` | Already existed; gitleaks reads full history from the checkout |
| `ci.yml` specs job | `qa-spec-links` | Already existed |
| `mykronos-sast.yml` | `sast` | CodeQL → Semgrep. See §5 |
| `mykronos-secrets.yml` | `secrets` | Duplicate of the `ci.yml` job; one lane now |
| `mykronos-atlas.yml` | `dependencies` + `atlas-evidence` | The evidence POST and SBOM archival were missing from Concourse |
| `mykronos-aegis.yml` | `insider` | See §6 |

**What is deliberately not removed.** `workflow-templates/` and
`actions/upload-results` are *products*: they are installed into other people's
repositories by the Workflow Installer (spec 03), which is the platform's whole
purpose. Spec 15 §2 already states this and it is worth restating, because
"remove the GitHub Actions" and "remove the GitHub Actions integration" are one
word apart and opposite instructions.

**What this costs.** Pull requests to the Mykronos repository no longer get
checks from a system that runs on GitHub's infrastructure. Concourse polls the
configured branch; a pull request from a fork is not scanned by it and must not
be — spec 14 §4 and spec 15 §7 both reject running untrusted code on a worker
inside the LAN. For a single-operator repository that is an acceptable trade
and it is a real regression, not a neutral one. It becomes unacceptable the day
somebody else opens a pull request, and the answer then is to restore the
Actions lanes for pull requests only rather than to widen what Concourse trusts.

## 5. CodeQL is not available here, and Semgrep is what replaces it

The `sast` capability defaults to CodeQL (`adapters/registry.py`), and CodeQL
is the wrong tool for this execution environment for two independent reasons:
its CLI needs a multi-hundred-megabyte bundle per language on every run, and
its licence covers Actions on public repositories and GitHub Advanced Security
customers — not a self-hosted worker scanning a private repository.

Semgrep is already a registered `sast` tool (spec 04 §3 names it as the
secondary), emits SARIF, and installs from PyPI. The pipeline sets
`--tool semgrep` explicitly rather than relying on the capability default, so
the lake records which analyser produced each finding and the dashboard does
not imply CodeQL coverage that never existed.

**The finding sets are not equivalent and the difference should be expected.**
Semgrep's default rulesets are pattern-based; CodeQL's `security-extended`
includes dataflow queries Semgrep's free rules do not reproduce. Findings will
appear and disappear on the cutover, and that is a tool change, not a change in
the code's security.

## 6. Insider risk without a pull-request event

Aegis (spec 06) is built around a `pull_request` event: `aegis_signals`
requires a PR number, an author login, and a base ref, and the review-integrity
signals of §2a need the review list. Concourse sees a branch, not an event.

The pipeline recovers the missing context by asking GitHub which pull request
introduced the commit — `GET /repos/{owner}/{repo}/commits/{sha}/pulls` — and
then collects signals exactly as the workflow does. Where a pull request
exists, the assessment is the same assessment.

**Where no pull request exists, nothing is recorded, loudly.** A commit pushed
directly to the branch has no reviews to have integrity, no author baseline
gathered against a base ref, and no PR body to check for AI disclosure.
Submitting an assessment anyway would mean a `0/100` insider-risk score for
precisely the case Aegis exists to notice — the change nobody reviewed reading
as the safest change in the repository.

This is L0001's third state, and it is handled the way L0001 requires: the job
prints an unmissable notice, records no assessment, and exits green. It exits
green rather than red because TheHub is pushed to directly as a matter of
routine, and a lane that is permanently red is a lane that gets paused — which
is how the capability would actually be lost.

## 7. The deploy mechanism

Spec 15 §7 and D-038 both refuse a Docker socket in a pipeline task: a
Concourse worker inside the LAN that can drive the host's daemon can restart,
read or replace anything on the machine, and every task in every pipeline
inherits that. Mykronos's answer was a one-way handoff — the pipeline publishes
an image and a human runs `deploy.ps1`.

A pipeline that waits for a human at *both* environments is not a delivery
pipeline, so TheHub needs the pipeline to be able to act. It gets something
narrower than a socket, and narrower than a login.

**A pointer the host pulls, not a connection Concourse makes.** The deploy job
writes a commit SHA to `<env>.requested` in MinIO. A Scheduled Task on the host
polls that key, pulls the matching image by SHA from the registry, brings the
compose services up, and writes `<env>.deployed` back. Concourse then waits for
its own SHA to appear in `<env>.deployed` before reporting success — so
`passed: [deploy-demo]` continues to mean *demo is serving this commit*, not
merely that a request was filed for it.

This was not the first design. §7 originally specified a forced-command SSH key
per environment, which is sound and which this host cannot run: **OpenSSH
Server is not installed here**, only the (disabled) agent. Installing a
listener on a machine inside the LAN to accept deploy instructions is a larger
change than the thing it enables. The reworked mechanism needs no listener at
all. See D-042.

Three properties, and they are why this is not "a socket with extra steps":

- **Nothing Concourse does can run a command.** The pipeline's entire
  vocabulary is one 40-character hexadecimal string written to one object. A
  compromised pipeline task can ask for a different already-built image. It
  cannot ask for anything else, because there is no other field.
- **The host opens no port to be told to.** It polls outbound. There is no
  listener to authenticate, no host key to pin, and no service whose
  compromise reaches the deploy path.
- **Separation is by object, not by argument.** `demo.requested` and
  `prod.requested` are separate keys with separate MinIO credentials, so the
  demo job cannot request a production deploy any more than the demo SSH key
  could have.

**What this gives up, stated plainly.** Latency: a deploy takes as long as the
poll interval rather than being instant. And the host-side task is now a
component that can *itself* be down — the SSH model failed loudly at connect
time, whereas a stalled poller looks like a slow deploy. The deploy job
therefore fails on a timeout that names the Scheduled Task, so the message
points at the thing to restart rather than at the pipeline.

**Rollback.** The host script records the SHA each environment is on before it
starts. If the stack does not become healthy within the timeout it restores the
previous SHA and reports the failure through `<env>.deployed`, which fails the
waiting Concourse job. A deploy that half-lands and reports success is worse
than one that fails, because DAST then probes whatever happens to be up.

## 8. DAST probes demo, and only demo

The `dast` capability config already carries `target_url` (spec 04 §5), and
this pipeline points it at the demo environment. Production is never probed.

ZAP's baseline scan is a spider and a passive scan — it does not attack — but
the boundary is worth being explicit about because it is the boundary people
erode first. Attack traffic against production is a decision with an incident
report attached, not a pipeline setting.

**A failed probe is not a clean probe.** If ZAP cannot reach the target, the
job fails rather than uploading an empty report. The demo environment being
down is a deploy failure that the health check should already have caught, and
a green DAST lane over an unreachable host is the same false negative L0001 is
about.

## 9. Cloud posture

Azure holds TheHub's backups. Prowler runs against the subscription on a
schedule rather than on a commit, because the subscription's posture does not
change when the code does — and a commit-triggered cloud scan produces one
identical finding set per push, which is noise in the lake and a rate limit
against Azure Resource Manager.

**Authentication is a service principal, and Mykronos never holds it.** Spec 12
§4.3 says the platform does not hold cloud credentials; the client ID and
secret come from Concourse's credential store into the task environment and
appear in no file in this repository. The principal needs `Reader` and
`Security Reader` at subscription scope and nothing else — Prowler reads
configuration, and a posture scanner with write access to the thing it audits
is a finding of its own.

`CloudConfig` gains `azure_subscription_id` and `azure_tenant_id` alongside the
existing AWS fields, under the same validation discipline: both are rendered
into a workflow template and a shell command, so they are constrained on the
way in rather than escaped on the way out.

**Only failing checks are ingested**, which is the cloud adapter's existing
behaviour and worth restating here: Prowler emits passes too, and storing every
passing control for every resource on every daily scan grows without bound
while answering no question anyone asks.

## 10. Secrets

Everything spec 15 §6 requires, plus what this pipeline adds:

| Credential | Where it lives | Scope |
|---|---|---|
| TheHub ingestion token | Credential store | One repository, 90-day rotation (spec 12 §2) |
| GitHub App installation token | Minted at set-pipeline time | One hour. Also used by the insider lane to resolve the PR |
| Demo deploy key | Credential store | Forced command, demo only |
| Prod deploy key | Credential store | Forced command, prod only |
| Azure service principal | Credential store | `Reader` + `Security Reader`, one subscription |
| Registry credentials | None — the registry is on the host | Reachable only from the LAN |

No credential appears in pipeline YAML, in a build log, or in an image layer.
The vars file `set-thehub-pipeline.ps1` writes is created in the temp directory
and deleted in a `finally` block, which is the existing pattern and is kept.

## 11. Acceptance criteria

1. A commit to the configured branch triggers the pipeline within one minute.
2. All five security lanes — secrets, SAST, dependencies, containers, insider —
   complete before the Oracle gate runs, and each records a ScanRun in Mykronos
   whether it found anything or not.
3. The `containers` lane scans the **image built from this commit**, and its
   findings carry a package name and version.
4. An Oracle `no_go` stops the pipeline before the demo deploy, with its
   reasoning visible in the dashboard.
5. The demo environment serves the new commit and reports healthy before the
   DAST job starts; a stack that does not become healthy is rolled back and
   fails the job.
6. DAST findings appear in Mykronos with a URL path and HTTP method as their
   location, attributed to the demo target.
7. **Production does not change without a human action in Concourse.** Verified
   by pushing a commit and confirming prod still serves the previous SHA.
8. The image production runs is the image DAST probed, identified by the same
   SHA, with no rebuild between them.
9. A Prowler run against the Azure subscription records failing checks against
   TheHub, and passing checks are not stored.
10. A commit with no associated pull request produces an insider lane that is
    green, records nothing, and says so in its log.
11. No credential appears in pipeline YAML, in build logs, or in an image layer.

## 12. Alerting

Two senders, and they are not redundant — each covers what the other
structurally cannot see.

**Mykronos sends the alerts that matter.** It is the system of record and
cannot tell which CI produced a finding (spec 15 §4), so one notifier serves
the Actions workflows in onboarded repositories and both Concourse pipelines,
and a third CI would need no change. `mykronos.notify` posts on exactly three
events:

| Event | Why it is worth interrupting somebody | Level |
|---|---|---|
| Oracle returns `no_go` | The one decision that stops a deploy, and the pipeline that asked has already exited | critical |
| A ScanRun finalises as `failure` or `partial_failure` | A failed scan reports no findings, which is indistinguishable from a clean repository on every dashboard (spec 04 §6) | warning |
| A batch containing findings at or above `slack_notify_min_severity` | The findings themselves, once per batch | critical / warning |

**Concourse sends what never arrives.** `python -m mykronos.upload` is the last
line of every scan task, so a task that fails on the line above it is invisible
to the lake — the platform cannot alert on a scan it was never told about. Each
job carries `on_failure` and `on_error` hooks, which are different events:
`on_failure` is the task exiting non-zero, `on_error` is Concourse being unable
to run it at all. The second is the one that looks like nothing happening.

**Three rules that stop this making things worse.**

1. *A notification failure is never an ingestion failure.* Every send is
   wrapped and the worst case is a logged warning. A security platform that
   stops accepting findings because a chat service is unreachable has inverted
   its own priorities. Same rule on the pipeline side: the notify task exits 0
   unconditionally, because it only ever runs when something already failed.
2. *One message per batch, never per finding.* A scan uploading four hundred
   criticals is one event. Four hundred messages is a channel somebody mutes,
   which costs more than the alert was ever worth.
3. *Nothing untrusted reaches Slack unscrubbed.* Finding titles come from
   scanner output, which comes from repository content. `logsafe.scrub` applies
   on the way out for the same reason it applies on the way to a log.

**What is deliberately silent.** A successful scan. The opening half of a
ScanRun's two posts (D-002) — alerting there would fire on every scan that
merely started. `no_applicable_targets`, which is L0001's third state and a
normal result for a repository with no Dockerfiles: alerting on it trains
people to ignore the channel, which is how the entries above stop being read.

**Configuration.** `MYKRONOS_SLACK_WEBHOOK_URL` in `backend/.env` for the
platform half, `SLACK_WEBHOOK_URL` in `deploy/concourse/.env` for the pipeline
half. Both default to empty, and empty means nothing is posted anywhere. There
is deliberately no default endpoint: a deployment that changed no configuration
must not be sending its findings to a chat service, which is the rule spec 12
§5.2 applies to the AI classifier for the same reason.

## 13. Reporting back into TheHub's own processes

TheHub is not only a repository this pipeline scans. It runs a DevSecOps and
story-lifecycle subsystem of its own (`backend/services/devops/lifecycle.py`),
and that subsystem advances stories from *evidence* rather than from anyone
clicking a button:

| Story transition | Evidence it requires |
|---|---|
| `in_progress` → `tested` | a green `integration_tests` stage in `deploy_history` whose commit message or branch names the story |
| `tested` → `deployed` | a successful run in `deploy_runs`, or a `finish`/`smoke` stage in `deploy_history` |
| `deployed` → `verified` | 24h elapsed since that deploy with no failure referencing the story |

Those tables are written by TheHub's own `scripts/deploy.sh` and by its GitHub
Actions. **Moving delivery to Concourse does not break them, and that is the
problem.** `deploy.sh` still runs and still reports, so the lifecycle keeps
advancing stories on evidence from a pipeline that is no longer the one
shipping the software. Nothing errors. The two simply drift, and the first
symptom is a story marked deployed on the strength of a deploy that was not the
one that went out.

So every stage reports. The pipeline POSTs to `/api/ops/deploys` — the endpoint
`deploy.sh` already uses, with the same `X-Ops-Deploy-Token` shared secret read
from TheHub's own `.env`, so **nothing in TheHub changes to receive this.**

| Concourse job | Reports as | Env |
|---|---|---|
| `unit` | `integration_tests` | prod |
| `containers` | `trivy` | prod |
| `deploy-demo` | `deploy_staging` | staging |
| `dast` | `dast_headers` | prod |
| `oracle-gate` | `oracle_gate` | prod |
| `insider` | `insider_risk` | prod |
| `deploy-prod` | `finish` | prod |

Four details that are load-bearing rather than cosmetic:

**`deploy_id` is the commit SHA, not the build number.** TheHub keys a
`deploy_run` on it, and every job here works on the same commit — so all seven
stages land under one run. A build number would scatter one commit's stages
across seven unrelated runs, and the Pipeline view would show seven deploys
that each did one thing.

**The commit message is sent because the lifecycle regexes the story id out of
it.** A report without it is a row nothing can match, which advances nothing
while looking like it worked.

**The demo deploy reports `deploy_staging`, deliberately not `smoke` or
`finish`.** Those two are exactly what `_story_deployed_signal` treats as "this
shipped". A staging deploy claiming them would advance stories to `deployed` on
the strength of a demo environment — the precise failure this bridge exists to
prevent, introduced by the bridge itself.

**A reporting failure never fails the build.** A lifecycle that did not hear
about a deploy is a reporting problem; failing the deploy over it would turn it
into an outage. With no token configured the task says so and exits 0, and
`set-thehub-pipeline.ps1` prints a warning at apply time so the silent case is
announced once where somebody is looking.

## 14. Testing the AI, where there is AI to test

"Add AI testing to the pipelines" was scoped by asking which pipeline actually
has AI in it. The answer was one of them.

**Mykronos needs nothing new.** Its two AI surfaces — Aegis's
`ai_classifier_url` (spec 06 §5) and Patchwork's `fix_generator_url` (spec 08
§5) — are both null by default, and null means the feature is off and no
repository content leaves the runner (spec 12 §5.2). The property worth
testing is that contract rather than any model's output, and four test modules
already assert it. Adding an eval lane for a model nobody has configured would
be testing an absence.

**TheHub is the opposite case, and already had the answer.** Its prompts are
code: `backend/prompts/<feature>/main.<v>.md` drives the room coordinators, and
a wording change can regress behaviour that no unit test can see, because the
code is identical and only the output moves. So it has a full eval system —
`services/ai/eval_harness.py`, fixture sets per feature, and
`tests/eval_fixtures/eval_thresholds.yaml` holding a pass-rate, p95 latency and
cost baseline for each prompt — gated by `scripts/run_prompt_evals.py`.

`deploy.sh` has run that gate for 51 deploys. **Concourse never did**, which is
the §13 problem again with a nastier failure mode: nothing broke. The gate
simply stopped being consulted for anything this pipeline shipped, so a prompt
regression would have reached demo with every other lane green.

### What the lane does

Runs `scripts/run_prompt_evals.py`, the same entry point `deploy.sh` calls, so
there is one definition of the gate rather than two that drift.

**It costs nothing by default, and that is a design property rather than a
happy accident.** The runner's own guardrail: rubric fixtures need a Claude API
key, and without one they report as `skipped` while `schema_validator` and
`exact_match` graders run normally. So the deterministic half of the suite
gates every commit for free, and the half that needs a model is opt-in — the
same rule spec 12 §5.2 applies to every other outbound AI call in this
platform. Supplying `ANTHROPIC_API_KEY` turns the judged fixtures on without
editing the pipeline.

**Only changed prompts are evaluated.** The runner diffs against `--base-ref`
and evaluates the features whose prompt files moved. A commit touching no
prompt says so and exits clean, rather than re-running a suite whose inputs did
not change.

**The judge cache is a Concourse cache.** The harness already caches judge
calls on `(prompt_version, fixture_id, grader)`; pointing `HUB_EVAL_CACHE_DIR`
at a worker-local cache means a configured key pays for a fixture once rather
than once per build, and a prompt-version bump invalidates exactly the entries
it should.

### Two failure modes, kept distinct

`deploy.sh` separates them and the lane keeps the distinction, because
collapsing them is how an eval gate gets switched off:

| Exit | Meaning | Lane |
|---|---|---|
| 0 | Fixtures met the baseline | passes |
| 2 | The harness could not run — broken fixture, unreachable judge | **warns**, does not fail |
| other | Measured regression against `eval_thresholds.yaml` | fails |

A harness that cannot run is not evidence of a prompt regression, and
reporting it as one trains people to ignore the red. A regression is measured
against a committed baseline and is the thing the gate exists for.

### What this deliberately does not run

`tests/classifier_validation/` — `pytest.ini` marks it *"Operator-driven
multimodal classifier accuracy validation. NOT auto-run; costs real Claude
budget."* That judgement was already made by whoever wrote the marker, and a
pipeline is the wrong place to overturn it. It stays a command a person runs
deliberately.

## 15. Before the first run

Four things must be true, and three of them fail in ways that look like
something else.

**1. The ingestion token must be granted every capability the pipeline
reports.** `POST /api/ingest/*` checks the grant on the token, not the repo's
enabled set, and refuses with a 403 naming what *is* granted. TheHub's token
was minted for `secrets`, `atlas` and `containers`; this pipeline adds three
more:

```
mykronos grant ToddGBenson/TheHub sast
mykronos grant ToddGBenson/TheHub dast
mykronos grant ToddGBenson/TheHub cloud
mykronos grant ToddGBenson/TheHub aegis
```

A missing grant fails the upload step at the very end of a lane that otherwise
ran perfectly — the scan works, the findings exist, and nothing records them.

**2. The repo's enabled capability set drives the dashboard, and is separate.**
A capability that reports findings without being enabled on the repo produces
data the portfolio's coverage column does not show. Enable `sast`, `dast`,
`cloud` and `aegis` for TheHub through `PATCH /api/repos/{id}/capabilities`.

**3. The deploy keys must be installed before the pipeline is applied.**
`Install-DeployKey.ps1` generates them and prints the `authorized_keys` lines;
`set-thehub-pipeline.ps1` refuses to apply a pipeline whose keys are absent,
because the alternative is three jobs that cannot ever pass.

**4. TheHub's compose files must read `${THEHUB_IMAGE}`.** This is the one
change the deploy model asks of TheHub itself, and it is what makes "deploy"
mean "run exactly this commit" rather than "rebuild and hope".

## 16. Open questions

0. **"Enabled capability" and "installed Actions workflow" are the same field,
   and for a Concourse-scanned repo they should not be.** TheHub's token is now
   granted `dast`, `cloud` and `oracle` and the pipeline reports all three — but
   the portfolio's coverage column still shows five capabilities, because that
   column reads the repo's *enabled* set, and the only way to change it is
   `PATCH /api/repos/{id}/capabilities`, which opens a workflow-install pull
   request against the repository (spec 03). For TheHub that would commit the
   GitHub Actions workflows this whole spec removes.

   So the dashboard currently understates TheHub's coverage, and the fix is not
   a configuration change: onboarding needs to distinguish *this capability is
   enabled* from *install its workflow*. Until then a Concourse-scanned repo's
   coverage column is wrong in the safe direction — it shows less than is
   actually running, rather than more.

1. **TheHub's test suite is invoked on faith.** This pipeline runs `pytest`
   where a `tests/` directory exists and announces that it found none where it
   does not. Whether that is TheHub's real test command, and whether its tests
   need any of its twelve services running, is not knowable from this
   repository and needs confirming against TheHub itself.
2. **The demo environment has no data-seeding step.** An empty stack is
   healthy and mostly untestable by DAST, which will spider a login page and
   little else. Authenticated DAST needs a seeded account and a ZAP context
   file, which is a larger piece of work than this spec.
3. **Prod deploy has no scheduled window.** A person can promote at any hour.
   That is right for a single operator and wrong the moment TheHub has users
   who would notice.
