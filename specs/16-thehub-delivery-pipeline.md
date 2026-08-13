# Spec 16 — TheHub Delivery Pipeline

**Status:** Draft for review
**Depends on:** [04 — Scanner Workflows](04-scanner-workflows.md), [06 — Aegis](06-aegis-integration.md), [09 — Oracle](09-oracle-risk-decision-engine.md), [12 — Security](12-security-and-secrets-management.md), [15 — Concourse Pipeline](15-concourse-pipeline.md)

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
| demo | `thehub-demo` | `((thehub-demo-url))` | Oracle says anything other than `no_go` |
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
   git ──▶ unit ─┐
                 ├──▶ build ──▶ containers ─┐
   git ──▶ secrets ──────────────────────────┤
   git ──▶ sast (semgrep) ───────────────────┤
   git ──▶ dependencies (osv) ───────────────┼──▶ oracle gate
   git ──▶ insider (aegis) ──────────────────┘         │
                                                       │ not no_go
                                             ┌─────────▼─────────┐
                                             │   deploy demo     │
                                             └─────────┬─────────┘
                                                       │ healthy
                                             ┌─────────▼─────────┐
                                             │   dast (ZAP)      │  ◀── probes demo
                                             └─────────┬─────────┘
                                                       │
                                             ┌─────────▼─────────┐
                                             │   deploy prod     │  ◀── MANUAL
                                             └───────────────────┘

   timer ─▶ cloud posture (prowler, Azure)   ── independent of any commit
```

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

**The security lanes still all complete before the gate.** Spec 15 §3's
reasoning holds unchanged: Oracle scores the whole picture, and gating on a
partial one produces a decision the next finding invalidates.

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
pipeline, so TheHub needs the pipeline to be able to act. It gets a narrower
capability than a socket:

**A forced-command SSH key per environment.** The pipeline holds a private key
whose `authorized_keys` entry on the host is

```
command="pwsh -NoProfile -File C:\...\Invoke-TheHubDeploy.ps1 -Environment demo",
  no-agent-forwarding,no-port-forwarding,no-pty,no-X11-forwarding ssh-ed25519 AAAA...
```

The client's command line is ignored by sshd; it arrives as
`SSH_ORIGINAL_COMMAND` and the script reads exactly one thing out of it, a
40-character hexadecimal commit SHA, which it validates before use. The key
cannot open a shell, cannot forward a port, and cannot deploy to an environment
other than the one its own `authorized_keys` line names.

Three properties follow, and they are the reason this is not "a socket with
extra steps":

- **The demo key cannot reach production.** Separation is enforced by sshd on
  the host against the key that authenticated, not by the pipeline choosing to
  pass a different argument. Spec 15 §6 asks for deploy credentials scoped to
  the deploy job; this scopes them to the *environment*, which is stronger.
- **The blast radius is one script.** Compromising a pipeline task yields the
  ability to deploy a commit SHA that is already in the registry. It does not
  yield the ability to run a command.
- **The host key is pinned.** `StrictHostKeyChecking` stays on with a
  `known_hosts` supplied from the credential store. A deploy job that would
  accept any host key is a deploy job that can be pointed at a different host.

**Rollback.** The script records the SHA it deployed per environment before it
starts. If the stack does not become healthy within the timeout it restores the
previous SHA and fails the job. A deploy that half-lands and reports success is
worse than one that fails.

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

## 12. Before the first run

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

## 13. Open questions

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
