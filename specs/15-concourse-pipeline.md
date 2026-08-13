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
                                    │
                          ┌─────────▼──────────┐
                          │  build             │──▶ image + SBOM to registry
                          └─────────┬──────────┘
                                    │
                          ┌─────────▼──────────┐
                          │  deploy            │
                          └────────────────────┘
```

The security jobs run **in parallel** and all of them complete before the
Oracle gate. That ordering is deliberate: Oracle scores the whole picture
(spec 09 §8), and gating on a partial one produces a decision that a later
finding invalidates.

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
          pip install --quiet "mykronos @ git+https://github.com/ToddGBenson/mykronos@v1#subdirectory=backend"
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

**Pin `@v1`, and pass `mykronos-ref` where the composite action is used.** The
package and the action are versioned together, and three separate outages in
Phase 7 came from those two drifting apart.

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
