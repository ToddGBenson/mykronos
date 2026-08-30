# Spec 15 — Concourse Pipeline

**Status:** Draft for review
**Depends on:** [04 — Scanner Workflows](04-scanner-workflows.md), [05 — Data Lake](05-datalake.md), [12 — Security](12-security-and-secrets-management.md), [14 — Network Scanning](14-network-scanning.md)

---

## 1. Purpose

A self-hosted Concourse pipeline that takes a commit through unit tests,
functional tests, QA checks, the security capabilities, build and deploy —
recording every result in Mykronos through the same Ingestion API that the
GitHub Actions workflows use, and every artifact in durable storage.

## 2. Why this exists, given GitHub Actions already works

This is the first question to answer honestly, because a second CI system that
duplicates the first is a liability rather than a feature. Three reasons, and
only the first two are sufficient on their own.

**It is the second execution environment spec 14 already requires.** Network
scanning cannot run on a GitHub-hosted runner: that runner is in Microsoft's
cloud and cannot see `192.168.0.0/16`. Spec 14 §4 states this and rejects
self-hosted Actions runners for a specific security reason — wiring a LAN
scanner to a *public* repository's workflow means a fork pull request can
execute code on a host inside the network being scanned. Spec 14 currently
proposes "orchestrated by the Mykronos backend directly", which means building
a scheduler, a container runner, log capture and retry into the backend.
Concourse is that component, already written.

**GitHub Actions minutes are finite on private repositories, and the
constraint is real rather than theoretical.** During Phase 7, `ToddGBenson/TheHub`
exhausted its allowance and every workflow began failing instantly with no
logs — fifteen checks red for a billing reason, on the day container scanning
was first enabled. Public repositories are unaffected, so the platform's own
development was not blocked, which is exactly the kind of asymmetry that hides
a problem until it matters.

**Build and deploy do not belong in the security workflows.** The ten
capability workflows are installed *into other people's repositories* by the
Workflow Installer (spec 03). They must stay minimal and reviewable, and they
have no business knowing how to build or where to deploy. That work belongs in
a pipeline the operator owns.

**What this is not.** It does not replace the capability workflows. A repo
onboarded to Mykronos keeps its GitHub Actions scanners, because those run on
pull requests from contributors who have no access to this Concourse instance,
and because the installer's whole model is that a repository carries its own
security configuration.

## 3. Topology

```
                          ┌────────────────────┐
   git resource ─────────▶│  quality gate      │
   (poll or webhook)      │  unit · functional │
                          │  QA · lint · types │
                          └─────────┬──────────┘
                                    │ all green
                          ┌─────────▼──────────┐
                          │  security          │
                          │  sast · secrets    │
                          │  atlas · containers│
                          │  iac               │
                          └─────────┬──────────┘
                                    │ findings uploaded
                          ┌─────────▼──────────┐
                          │  oracle gate       │──▶ no_go stops here
                          └─────────┬──────────┘
                                    │ go
                          ┌─────────▼──────────┐
                          │  promote           │──▶ :SHA retagged :latest
                          └─────────┬──────────┘
                                    │
                          ┌─────────▼──────────┐
                          │  deploy (by hand)  │  deploy.ps1 pulls :latest
                          └────────────────────┘
```

`build` and `publish` sit **above** this, between the quality gate and the
security jobs, rather than below the Oracle gate where an earlier draft of
this spec put them. An image has to exist before `containers` can scan it, and
gating the build deadlocked the pipeline against its own container findings
(D-045).

What the gate holds is therefore the tag, not the artifact. Images publish as
`:${SHA}`, `containers` scans that SHA, and `promote` moves `:latest` — the
tag `deploy.ps1` pulls — only after a `go` (D-047). A refused commit leaves an
image in the registry that nothing points at.

The security jobs run **in parallel** and all of them complete before the
Oracle gate. That ordering is deliberate: Oracle scores the whole picture
(spec 09 §8), and gating on a partial one produces a decision that a later
finding invalidates.

`iac` runs checkov over Dockerfiles and workflow definitions. It is named in
the diagram above because it was always specified; it did not exist as a lane
until D-046. Compose files are not covered — `docker_compose` is not a checkov
framework — and that gap is documented rather than papered over.

## 4. Reusing the ingestion contract

Every Concourse task that produces findings does exactly what the composite
action does, because the logic lives in the `mykronos` package rather than in
the action (D-012):

```yaml
- task: sast
  config:
    image_resource: { type: registry-image, source: { repository: python, tag: "3.13" } }
    run:
      path: sh
      args:
        - -ec
        - |
          pip install --quiet "mykronos @ git+https://github.com/ToddGBenson/mykronos@v2#subdirectory=backend"
          # Print the commit the pin resolved to (D-051): a pinned ref is a
          # good practice and a silently stale one is not, and the difference
          # is one line of output.
          # ...run the scanner...
          python -m mykronos.upload \
            --capability sast --tool codeql \
            --results-path results --ingestion-url "$MYKRONOS_URL" \
            --token "$MYKRONOS_TOKEN" --repo "$REPO" --commit-sha "$SHA" \
            --branch "$BRANCH" --workspace "$PWD/source"
```

This is the payoff from keeping the uploader in the package. The lake, Oracle,
the dashboard and the Knowledge Store cannot tell which CI produced a finding,
and must not care — the same seam spec 14 §4 relies on.

**`--workspace` matters.** Findings carry repo-relative paths only because the
adapter is told where the checkout is; a Concourse task's working directory is
not the runner path an absolute SARIF URI would name.

**Pin a versioned tag (`v2` today), pass it as `mykronos-ref`, and cut the
next version deliberately.** The package and the action are versioned
together, and three separate outages in Phase 7 came from those two drifting
apart. The tag does not float: `v1` sat 53 commits stale while CI silently
installed a platform that rejected four capabilities (D-051), which is why
every install site now prints the commit its pin resolved to. Moving forward
is cutting `v3` on purpose, never moving `v2`.

## 4a. The return path: Mykronos reads Concourse

§4 says the lake, Oracle, the dashboard and the Knowledge Store cannot tell
which CI produced a finding, and must not care. That stands, and this section
does not weaken it: **nothing Mykronos reads from Concourse is an input to a
finding, a score or a decision.** A finding from Concourse and the same
finding from Actions remain indistinguishable to every analysis path, which is
the seam that let a second CI cost almost nothing.

What was missing is narrower and entirely one-directional today. Traffic runs
from Concourse to Mykronos and never back, so the dashboard can say a scan ran
and cannot say *where*, and a person looking at a finding has no way to reach
the build that produced it without knowing which of three pipelines to open.
That is a navigation gap, not an analysis one.

**Mykronos reads Concourse's own API for pipeline state.** Per repository:
which pipeline covers it, whether that pipeline is paused, and each job's last
build with a link to it.

**Which pipeline covers a repository is derived, not configured.** The pipeline
is the repository name, lowercased — `ToddGBenson/TheHub` to `thehub`. If
Concourse has no pipeline by that name, the repository has no pipeline, and the
dashboard says exactly that. `keel` is in this state and should be: it is
onboarded and scanned by Actions, and nothing in Concourse covers it.

The rejected alternative was a configured mapping, per repository, in either
settings or a new database column. It is more flexible and it is a second place
for the truth to live: a repository whose pipeline was renamed then shows a
dead link rather than the honest answer, and nobody notices until they click.
Deriving the name and checking it against the live pipeline list cannot go
stale, because it is re-derived on every read.

**Read anonymously, against exposed pipelines.** Every job in these pipelines
is already declared `public: true`, so `fly expose-pipeline` matches the intent
already in the YAML rather than widening it. Concourse binds to loopback and is
not fronted by the tunnel, so the reachable audience is this host and the LAN.

Two things this deliberately does *not* do:

- It does not read build logs. Those contain scanner output and, until CNC-2
  lands, resolved `((var))` values. The job list carries names, statuses and
  timestamps, which is what a link needs.
- It does not authenticate. Adding a Concourse credential to Mykronos to read
  a status that is already public would create exactly the secret CNC-2 exists
  to remove. If Concourse is ever fronted publicly, this becomes an
  authenticated read and the credential belongs in the manager, not in
  `.env`.

**Failure is silent and visible.** Concourse being unreachable must not affect
a page about findings: the panel says the pipeline state is unavailable and
every other part of the repository view renders. A dashboard that 500s because
a CI server is restarting is worse than one that admits it does not know.

### 4a.1 The coverage cross-check (added 2026-08-15)

Reading Concourse back enables the check this section is cited for elsewhere:
lining each scanning job up against the newest scan run it should have
produced, and rendering the disagreement. Its first day of existence found a
lane that had been green on every build and had never reported once (L0003).

Per repository, every capability in the standard set resolves to one state:

| State | Meaning |
|---|---|
| `not_enabled` | Nobody asked for it. An absence, not a problem. |
| `reporting` | The job succeeded and its results reached the lake within the grace window. |
| `silent` | The job succeeded and nothing arrived — green pipeline, stale data, and this row is the only thing that says those two facts disagree. |
| `never_reported` | Enabled, the job runs, and no scan run has ever landed. |
| `no_job` | Enabled and nothing in the pipeline produces it — the repository believes it is covered and no job disagrees, because no job exists. |
| `not_run` | The job exists and has never run (a paused lane reads this way). |
| `event_driven` | Aegis, Oracle and Patchwork never produce a ScanRun from a pipeline lane — webhooks, decisions and fix PRs respectively — so the job-versus-scan comparison has no sides. Not a gap. |

Three rules the first implementation got wrong, kept here so they stay right:

- **What "enabled" means depends on who scans the repo.** For Actions-scanned
  repositories it is the installer's ledger — an unmerged install PR genuinely
  means not-yet-enabled. For everything else the ledger never moves, so the
  capability *grants* are the truth: what may write is what is enabled.
- **A job may produce several capabilities.** `demo-and-dast` runs the
  functional suite through ZAP's proxy and then scans — one build, two
  uploads. Each capability answers for itself: the functional upload landing
  does not vouch for a DAST upload that failed.
- **These states are two tiers, not a ranking.** `reporting` and
  `event_driven` mean findings from this capability are in the lake.
  `no_job`, `not_run`, `never_reported`, `silent` and `not_enabled` all mean
  they are not. Within that second group there is no order: the states differ
  in what a human should go look at, not in how covered the repository is.
  The parity check (spec 32 §9) ranked all seven on a line, which put
  `not_run` above `silent` — so a capability going from "runs and reports
  nothing" to "has never run at all" was announced as an improvement, and
  keel was cleared for pipeline deletion with zero coverage under either
  system (L0005). Comparisons ask one question: was it covered before, and is
  it covered now.

**One caveat on acceptance criterion 8.** Re-applying the pipeline reproduces
the pipeline *definition*; it also deliberately re-asserts operational pause
state (D-053) from the set-pipeline scripts, because a `fly pause` is state
only an operator remembers and a re-apply for an unrelated change once
resurrected a paused DAST scan on a host it had already starved.

## 5. Storage

Two different things need keeping, with different requirements.

| What | Where | Why |
|---|---|---|
| Findings, scan runs, evidence | Mykronos lake, via the Ingestion API | Already the system of record. Nothing new. |
| Raw tool output | Mykronos, via `/api/ingest/raw` | Spec 05 §7 archival, and the input `reprocess` needs when an adapter is corrected |
| Build artifacts, images, SBOMs | NAS, via MinIO (S3-compatible) | Concourse's `s3` resource is first-class; a plain volume is not versioned and has no retention story |
| Concourse's own state | Postgres on the NAS | Pipeline config, build logs, resource versions |

**MinIO rather than a mounted share.** Concourse's `s3` resource type handles
versioning, retention and immutability, and an S3 API means the same pipeline
runs unchanged against real S3 later. A CIFS mount into a container is a
different failure mode on every worker restart.

**Retention.** Build artifacts are the largest and least valuable class here —
they age out at 30 days. Raw scan output follows spec 05 §7. SBOMs are
evidence and are kept per release indefinitely, because their whole purpose is
answering a question asked long afterwards.

## 6. Secrets

Concourse pipeline YAML is committed. Nothing sensitive may appear in it.

- **A credential manager, not `((vars))` in a file.** Concourse supports
  Vault, AWS SSM, and a Kubernetes secrets backend. For a single-host
  deployment, **Vault in dev-less mode on the NAS** is the smallest thing that
  is not a plaintext file.
- **One ingestion token per repository**, exactly as spec 12 §2 requires, with
  the same 90-day rotation. The pipeline reads it from the credential manager;
  Mykronos already mints and rotates it.
- **The GitHub App private key never reaches Concourse.** Concourse produces
  findings; it does not open pull requests. Anything that needs the App —
  Patchwork, the installer — stays in the backend.
- **Deploy credentials are scoped to the deploy job**, not to the whole team.
  A pipeline where the test job can read production credentials has no
  meaningful separation between the two.

## 7. Hardening (spec 12)

The current `docker-compose-concourse.yml` in TheHub runs
`concourse/concourse:7.14` in `quickstart` mode with `admin:admin` and
`CONCOURSE_EXTERNAL_URL: http://localhost:8080`. That is correct for trying it
out and must not be what runs a deploy job. Before this is load-bearing:

- **Replace the local admin user** with an OIDC connector, or at minimum a
  generated password in the credential manager. `admin:admin` on a host that
  can deploy is the single largest risk in this design.
- **TLS, via the existing Cloudflare tunnel.** The tunnel already fronts
  `mykronos.toddbenson.net`; a `concourse.` hostname is one ingress rule, and
  it means no port is opened on the router.
- **`privileged: true` is required for the worker and is the reason isolation
  matters.** Container-image builds need it. Tasks that do not build images
  must not run privileged, which Concourse controls per task.
- **The worker is inside the LAN**, which is the point for network scanning
  and the risk for everything else. A compromised pipeline task has the
  network position spec 14 §4 was worried about — which is why untrusted pull
  requests from public repositories are scanned by GitHub Actions and never
  by this pipeline.

## 8. Network scanning (spec 14)

This pipeline is where spec 14's capability becomes buildable. A scheduled job
runs `nmap` and `nuclei` against the authorised ranges from a `NetworkAsset`,
inside the LAN, and uploads through the same Ingestion API.

Spec 14 §5's `asset_type` / `asset_id` migration is a prerequisite and is
explicitly *not* part of this spec: findings need somewhere to say they are
about a network rather than a repository before a network scan can record one.

## 9. Acceptance criteria

1. A commit to the configured branch triggers the pipeline within one minute.
2. Unit, functional and QA jobs run in parallel and a failure in any one stops
   the pipeline before the security stage.
3. Security findings appear in Mykronos with **repo-relative paths** and, for
   dependency and container findings, a package name and version — verified
   against the dashboard, not the pipeline's own logs.
4. Raw tool output is archived and a subsequent `mykronos reprocess` can
   re-derive findings from it.
5. An Oracle `no_go` stops the build job, and the decision is visible in the
   dashboard with its reasoning.
6. Build artifacts and SBOMs land in MinIO and are retrievable by build number.
7. No credential appears in pipeline YAML, in build logs, or in a container
   image layer.
8. Tearing down and re-applying the pipeline from `fly set-pipeline` produces
   an identical configuration — the pipeline definition is the source of
   truth, not the running state.

## 10. Open questions

All three are now answered. They are kept rather than deleted because the
answers are only readable next to the questions.

1. ~~**Does Concourse duplicate scanning that GitHub Actions already does for
   the same repo?**~~ **Answered twice.** D-038 said yes, and split the two
   lanes by purpose — Actions for pull-request feedback, Concourse for the full
   pipeline. That rule was withdrawn once the full capability set actually ran
   in Concourse: this repository's own workflows were scanning the identical
   commits and producing findings the ingestion upsert made
   indistinguishable. `.github/workflows/` is removed and its function lives in
   `pipelines/mykronos.yml`. See [16 §4](16-thehub-delivery-pipeline.md) for
   what that costs, and note that `workflow-templates/` — the workflows
   *installed into other people's repositories* — are unaffected and remain the
   platform's product.
2. ~~**What happens when the NAS is unavailable?**~~ **The pipeline fails**
   (D-038). The ingestion check is a gate, not a best-effort step, and the
   `put` to MinIO is a step whose failure fails the build. Neither is wrapped
   in a tolerant `|| true`.
3. ~~**Who owns the deploy target?**~~ **Answered per pipeline.** For Mykronos,
   D-038: this host, in Docker, with a one-way registry handoff and a human
   running `deploy.ps1`. For TheHub, [16 §7](16-thehub-delivery-pipeline.md):
   two compose stacks on the same host, reached by a forced-command SSH key
   scoped to one environment each — narrower than a Docker socket, and enough
   for the pipeline to act on its own between the gate and production.
