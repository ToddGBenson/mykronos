# The pipeline standard

One shape for every delivery pipeline this platform runs, and a per-lane
conformance table against it.

Mykronos runs three Concourse pipelines — `mykronos`, `thehub`, `personal-soc`
— and ships a fourth execution environment as its product: the GitHub Actions
workflows the Workflow Installer renders into other people's repositories
(spec 03). The Actions side has had a shared skeleton since it was written:
`workflow-templates/_base.yml.j2` factors the header, the fail-fast probe, the
concurrency group and the upload step, so "a change to the upload contract is
one edit rather than ten."

The Concourse side never had one. Each lane hand-rolled the same six lines of
`apt-get`, `pip install`, uploader-provenance echo and `python -m
mykronos.upload`, and thirty-eight of them drifted apart in every way that
sequence can drift. This document is the missing skeleton, written as rules
with the failure each one prevents, because a rule whose cost is not stated
gets dropped the first time it is inconvenient.

Every rule is numbered `PS-n` and cited by that number in the pipeline YAML at
the point it applies. If you are reading a comment that says `PS-3`, this is
what it means and why.

---

## The stage taxonomy

Spec 15 §3 already names the stages. This is that diagram with the two things
it left implicit made explicit: which capability each stage produces, and what
"produces" means.

```
  quality gate        unit · qa · lint · types · frontend contract
        │             ── every lane reports a ScanRun, no findings (D-046)
        ▼
  build + publish     image :SHA — no tag anything deploys
        │
        ▼
  security            sast · secrets · atlas · iac · ai · containers · aegis
        │             ── every lane reports findings AND a ScanRun
        ▼
  gate                oracle — scores the whole picture, blocks on what this
        │                      commit introduced (D-048)
        ▼
  promote             :SHA → :latest, the pointer the deploy reads
        │
        ▼
  runtime             dast · functional · patchwork · cloud
```

Two orderings differ between pipelines and both are deliberate, both are
spec'd, and neither is a drift to fix:

| | `mykronos` | `thehub` |
|---|---|---|
| Where the gate sits | after the static + container scans, before `promote` | after DAST, so runtime findings reach the score (spec 16 §3) |
| Where `aegis` sits | **before** the gate, so insider risk is an Oracle input | **after** the gate, as the last check before a human promotes (spec 16 §3) |

TheHub's ordering buys runtime findings in the score and pays for it by
dropping insider risk out of the score. Spec 16 §3 states that trade. It is
listed here as a **known divergence**, not a conformance failure — see
[Open items](#open-items), which proposes closing it.

---

## The rules

### PS-1 — A stage that does not report does not exist

Every job that runs against a commit reports a `ScanRun` to Mykronos. Not
"every scanner": every job. A lint lane, a contract check and an API-inventory
diff are all evidence about a commit, and evidence that reaches only the
Concourse UI is evidence the platform cannot use.

**What it prevents.** Spec 15 §4a.1's coverage cross-check resolves each
capability to `reporting`, `silent`, `never_reported`, `no_job` or
`not_enabled`. A green job that uploads nothing produces no row at all — it is
invisible, which reads exactly like a capability nobody enabled. L0003 is the
lesson: a check that cannot report is a check that does not exist. Its first
day of existence found a lane green on every build that had never reported
once.

**How.** Quality stages that are not test suites use
`python -m mykronos.junit_stage` to turn exit codes into a JUnit document, then
upload as `qa`/`junit`. The capability has exactly one registered adapter
(`adapters/registry.py`), so inventing a tool name fails the upload with "No
adapter for capability 'qa'". Several `qa` runs per commit is intended, not a
collision: quality stages carry no findings (D-046), so they cannot overwrite
each other the way two scanners on one capability would.

**And the job has to be in `CAPABILITY_BY_JOB`** (`backend/mykronos/ci.py`),
or the cross-check will not compare it. Reporting without being checked buys
half of what it should.

### PS-2 — Fail before scanning, not after

Every reporting job runs the `preflight` task — one `curl` against
`/api/ingest/health` with the ingestion token — after its `get:` steps and
before any scanner.

**What it prevents.** `_base.yml.j2` has had this since it was written: "better
to stop in ten seconds than scan for twenty minutes and find at upload time
that the results have nowhere to go." Not one Concourse job had it. TheHub's
`unit` is capped at sixty minutes and its `functional-dast` at a hundred and
twenty, on a single worker.

A failure here is a real failure, never a skip. A scan whose results cannot
land *is* the `never_reported` state, and producing one deliberately is worse
than not starting.

### PS-3 — Report the scan that broke

A scanner's exit code must never be able to skip the upload. Two shapes,
depending on whether the scan and the upload are in one task:

- **One task** — capture the code (`rc=0; scanner ... || rc=$?`), upload, then
  `exit "$rc"`.
- **Two tasks** — the upload hangs off the scan task as an `ensure:` hook.

**What it prevents.** Actions uploads under `if: always()` for this exact
reason, spelled out in `_base.yml.j2`: "a scan that failed still has to
register its ScanRun — 'never ran' and 'ran and broke' must stay
distinguishable in the lake (spec 04 §6, §7)." Concourse had no equivalent, so
a broken scanner silently degraded a capability to `never_reported`.

`mykronos.upload` is built for this: it registers the ScanRun *before* it
interprets anything and finalises in a `finally`, so even a crashed adapter
leaves evidence — but only if it is called. And an empty results directory is a
**failure**, not an empty scan (`adapters/registry.py`), which is why an
`ensure` hook over a declared-but-unwritten output volume produces the honest
answer rather than a false clean.

**The shell trap this hides.** Tasks run under `bash -ec`, so errexit is on
before the script's first line, and `set -uo pipefail` turns pipefail *on*
without turning errexit *off*. A failing `scanner | tee` therefore kills the
shell at the pipe, before `${PIPESTATUS}` can be read. Any lane measuring an
exit code through a pipe needs an explicit `set +e` around it.

### PS-4 — Scanning waits for the quality gate

Every security lane declares `passed: [<the quality gate>]` on its `source`
get.

**What it prevents.** Spec 15 §3: "there is no value in scanning a commit that
does not pass its own tests." Five of TheHub's lanes had no `passed:` at all,
so they spent the single shared worker producing findings about code already
known not to work.

### PS-5 — A capability is granted, or it has a lane, or it has neither

`no_job` — the repository believes a capability is covered and nothing produces
it — is the one cross-check state that is always a bug. Close it by adding the
lane or by revoking the grant. Never by leaving it.

A lane that cannot find a target is not the fix. `no_applicable_targets` is a
real `ScanStatus` and saying "there was nothing to scan" is honest; inventing a
lane so a column turns green is the failure this platform exists to catch.

### PS-6 — Nothing in a lane names its own branch, repo, or default

The branch comes from `$SCANNED_BRANCH`, set once in the `mykronos_env` anchor
from a pipeline var.

**What it prevents.** The git resource checks out a detached HEAD, so asking
git for the branch returns the literal string `HEAD` — TheHub recorded that as
the branch on every scan run until it was fixed. The mykronos pipeline avoided
that by hardcoding the default branch in ten uploads, which was true and would
have stopped being true the first time the pipeline was pointed anywhere else.

### PS-7 — Every task has a timeout, including the hooks

No exceptions, and the hooks least of all.

**What it prevents.** A build that hangs occupies the worker until a human
notices. TheHub's `unit` job already carries the scar: one ran for 47 minutes
and was still going when it was killed by hand, and nothing in the pipeline
would ever have stopped it. There is one worker and it also hosts TheHub's live
stack.

Numbers come from measurement — comfortably above the worst observed run — not
from a target. The point is that a hung task releases the worker, not that a
slow one is punished.

### PS-8 — Pin the bytes, not just the version

Any binary a task downloads and executes is checksummed. Any installer is a
release artifact, never `curl … | sh`.

**What it prevents.** `osv-scanner` was already checksummed. `gitleaks` was
fetched over HTTPS and executed unverified, and `syft` — in the lane that
produces this platform's supply-chain evidence — was installed by piping an
*unpinned* installer script from a third party's `main` branch into a shell.
An SBOM is worth exactly what the thing that generated it is worth, and this is
the class of finding the platform reports in other people's repositories.

### PS-9 — A credential manager, not `((vars))` in a file

Spec 15 §6: "Concourse pipeline YAML is committed. Nothing sensitive may appear
in it." Concourse stores pipeline configuration verbatim, so a secret passed
with `--load-vars-from` is readable afterwards by anyone who can run
`fly get-pipeline`.

Vault has been wired into this Concourse since 2026-08-13
(`CONCOURSE_VAULT_URL`, prefix `/concourse`). The `set-pipeline` scripts probe
each credential in Vault; present means it is omitted from the vars file
entirely, absent means it falls back **and the script names it**. Moving a
credential is then one `vault-secret.ps1 set` and a re-apply.

**The shape matters, not just the storage.** Slack alerts post through
`chat.postMessage` with a bot token in an `Authorization:` header rather than
through an incoming webhook, because Vault can substitute a header value and
cannot substitute a secret embedded in the URL path of the endpoint being
called. Switching was the prerequisite for the credential leaving the file, not
a separate tidy-up.

### PS-10 — A notifier that cannot deliver is worse than none

Alert hooks fail open — an unconfigured credential exits 0 — but they must
verify delivery when they do run.

**What it prevents.** Two live bugs, one per pipeline, both invisible by
construction. TheHub's notifier wrote its payload to a root-owned working
directory as an unprivileged user, so it died on "Permission denied" *inside*
the `on_failure` hook. The mykronos notifier never built its payload at all: it
computed the message text, discarded it, posted `-d @payload.json` against a
file nothing ever wrote, and swallowed the curl error before `exit 0`. Every
`on_failure` and `on_error` in that pipeline had been decorative since the day
it was added. The only symptom in both cases was a red job that was already
red.

So: write to `/tmp`, and check the response body — Slack answers `200` with
`{"ok":false}` when a post is rejected, and without that check an undelivered
alert reads exactly like a delivered one.

### PS-11 — The applied pipeline is the pipeline

The configuration Concourse is running must match the file in this repository.
Not "should" — checked, by `scripts/check_applied_pipelines.py`.

**What it prevents.** The pipelines that run are applied from a working copy,
and on 2026-08-20 that copy was **eighteen commits behind `main`** with
uncommitted edits to five files — including a disabled Oracle gate that existed
nowhere in git (D-081). The repository said the gate blocked; the applied
pipeline let every `no_go` through; nothing reconciled the two, and the
divergence was found by accident while looking for a missing `.env`.

That is L0004: a copy close enough to be plausible is worse than one obviously
different, because nothing about using it feels wrong until it has already cost
you something.

**Three differences are expected and are not drift**, because Concourse
normalises what it stores: it drops `anchors:` after expanding the aliases,
drops falsy defaults (`public: false`, `passed: []`), returns jobs in its own
order, and names every anonymous `image_resource`. All four looked like drift
on the check's first run, and all four are now understood rather than
suppressed.

**It also answers PS-9 from the other end.** A `((var))` in the file is either
still a reference in the applied config — resolved from Vault at runtime — or a
literal, supplied through `--load-vars-from` and readable by anyone who can run
`fly get-pipeline`. The check reports which, and names the ones that look like
credentials. It never prints a value: the applied config holds resolved secrets,
and a drift report that leaked them would be the worse problem.

### PS-12 — Retry the fetch, never the verdict

D-123. `attempts:` may appear only on a step whose non-success is necessarily
an **error** and can never be a **failure**. Two kinds of step qualify: every
`get:`, and the `report-to-hub` and `notify-slack` hooks. Nothing else, ever.

And every `get:` must carry it. The rule runs in both directions, because half
of it is a security control and the other half is the reason the rule exists.

**What it prevents, in both directions.**

*Nothing retried.* On 2026-09-10 seven lanes across four pipelines were red and
six of them went green on a re-trigger with no code change, after being red for
between eight hours and three days: a Vault that had sealed itself, an iptables
lock lost when ten keel jobs scheduled in the same second onto two workers, and
a DNS timeout reaching Docker Hub. All three are ordinary infrastructure
weather and all three cleared on their own. Nothing retried and nothing
escalated, so weather became a permanently dark security lane, and the only
reason any of it was found is that somebody read every job on every pipeline by
hand. That is the failure this platform exists to catch — it says so in the
README — happening to the platform's own pipelines.

*Everything retried.* Concourse's `attempts:` re-runs a step on **any**
non-success. It operates *inside* the step, *beneath* the build-level
`errored`/`failed` routing that `on_error:` and `on_failure:` hooks are written
against, and fires before either hook is reached. A semgrep exiting 1 on a real
finding and a semgrep dying on DNS are the same event to it. Applied to
scanners it would auto-retry `dast-staging`'s refusal to report an empty scan
as clean, and `netassess-ingest`'s refusal to pass a check that reported
`unknown` — laundering a red gate green by repetition, which is worse than the
noise it removes. The two halves of the requirement are unsatisfiable with the
built-in knob applied naively; they are only satisfiable together on a surface
where the knob cannot see a verdict in the first place.

**Why these two kinds of step and no others.**

- A `get:` has no exit code. It fetches or it errors; it renders no judgement
  about the commit, so a retry has nothing to launder.
- `report-to-hub` and `notify-slack` end `exit 0` unconditionally, by
  construction, so the only way either reaches a non-success is never having
  run. `check_pipeline_conformance.py` asserts that last line rather than
  trusting it: the exemption is worth exactly what `exit 0` is worth, and an
  edit that gives either hook a non-zero path has to take the exemption with
  it.

That is also the surface all three observed causes actually struck. The sealed
Vault died resolving a git private key for a `get:`; the iptables lock was lost
in "find or create container" running a check; the DNS timeout was "checking
origin concourse/registry-image-resource". Not one of them was a scanner. The
retryable surface and the observed-transient surface are the same surface, and
it is disjoint from the verdict surface.

**`preflight` is deliberately excluded**, even though it is a hook and is
listed in `HOOK_TASKS` for PS-7. It *can* fail: a rejected ingestion token is
an answer, and PS-2 says a failure there is a real failure. So its retry lives
inside its `curl` — `--retry 4 --retry-delay 5 --retry-connrefused`, which
re-tries a connection refused, reset or timed out and a 5xx from the platform,
and does not re-try the 401 that means the token is wrong. Same shape as the
DAST guard's `curl --retry 5 --retry-delay 6 --retry-all-errors` reachability
loop: re-try being unable to ask, never the answer. In-task classification is
the idiomatic route in these pipelines and it predates this rule.

**Inside the step, not around the build.** An outer retry — something
re-triggering errored builds — would re-run the job-level hooks and post a
second `dast_headers` report for the same commit, which is the path that
reopened TheHub's abandoned deploy run 5772 on 2026-09-10 and would mint
duplicate attempts on it. `attempts:` fires beneath the hooks, so a retried
fetch still produces exactly one report per stage per build. That property is
as much the reason for this shape as the errored/failed line is.

**Three attempts on a fetch, two on a hook, and PS-7 is why.** Concourse
applies `timeout:` per attempt rather than per step, so a retried hook doubles
the longest it can hold the estate's single worker — TheHub's notifier goes
from a five-minute ceiling to a ten-minute one. That is a real cost against
PS-7 and it is paid deliberately, because what is being protected is the alert
about an errored lane. It is not worth a third attempt. `get:` steps carry no
timeout, so the same arithmetic does not apply to them.

**What it does not buy, stated so nobody expects it to.** Concourse does not
delay between attempts, so three of them absorb a lost lock or a resolver blip
and nothing longer. A Vault that stays sealed for three days stays red, and
correctly — the lane genuinely cannot run. A *task* that errors rather than
fails (an OOM kill, a worker vanishing mid-scan) is also not retried, because
`attempts:` on that task could not tell that from a finding. Both cases are
handed to the `on_error:` hooks, which now say which of the two happened: an
errored lane did not run and re-triggering it is the correct response, a failed
lane ran and answered and re-triggering it is not. Told only "job X failed",
nobody can tell those apart — and for three days in September nobody did.

---

## Conformance: the fifteen capabilities

`sast · dast · secrets · containers · iac · cloud · aegis · atlas · patchwork ·
oracle · network · unit · functional · qa · ai` (`schemas.py`, `Capability`).

| Capability | `mykronos` | `thehub` |
|---|---|---|
| `sast` | ✅ semgrep + import reachability | ✅ semgrep |
| `secrets` | ✅ gitleaks | ✅ gitleaks |
| `atlas` | ✅ osv-scanner + syft SBOM + provenance | ✅ same |
| `containers` | ✅ trivy, both images | ✅ trivy |
| `iac` | ⚠️ checkov, `dockerfile github_actions` only | ⚠️ same |
| `unit` | ✅ pytest | ✅ pytest on a real Postgres |
| `qa` | ✅ link check + lint/types + frontend contract | ✅ **new lane** + api-inventory |
| `ai` | ✅ mykronos-ai-checks | ✅ model inventory + **prompt evals, newly wired** |
| `aegis` | ✅ pre-gate | ⚠️ post-gate — not an Oracle input (spec 16 §3) |
| `oracle` | ✅ | ✅ |
| `patchwork` | ✅ now waits on `iac` too | ✅ now waits on `iac` too |
| `functional` | ⚠️ only inside the paused `demo-and-dast` | ✅ Playwright through ZAP |
| `dast` | ⚠️ paused (D-053), and not an input to the gate | ✅ demo + prod baseline |
| `cloud` | ❌ **no lane** | ✅ prowler, nightly |
| `network` | ❌ no lane | ❌ no lane |

**⚠️ `iac` in both** — `docker_compose` is not a checkov framework, so compose
files are not covered by this lane and nothing else covers them. Both
pipelines are substantially compose. Documented rather than papered over, and
still a real gap.

**❌ `cloud` on mykronos** — the platform is self-hosted end to end: one host,
a local registry, MinIO, a Cloudflare tunnel. There is no subscription for
prowler to assess. Under PS-5 the fix is to **revoke the grant**, not to add a
lane that would report nothing; that is an operator action against the running
instance, not a change to this file. Left open deliberately.

**❌ `network` in both** — spec 14 is built and waiting on an authorized CIDR.
Accepted, and recorded in the README's status table.

---

## What changed to get here

| Rule | `mykronos` | `thehub` |
|---|---|---|
| PS-1 | `lint-and-types`, `frontend` now report `qa` | new `qa` lane; `api-inventory` → `qa`; `prompt-evals` → `ai` |
| PS-2 | preflight in 14 jobs | preflight in 16 jobs |
| PS-3 | `secrets`, `ai`, `dependencies` capture rc; `iac`, `containers` upload under `ensure` | `secrets`, `dependencies` capture rc; `iac`, `containers`, `cloud-posture` upload under `ensure` |
| PS-4 | already conformant | 5 lanes gated on `unit` |
| PS-6 | 10 hardcoded branches → `$SCANNED_BRANCH` | already conformant |
| PS-7 | 27 task timeouts (was 0) | 23 more, plus both hook anchors |
| PS-8 | gitleaks + syft checksummed | gitleaks + syft checksummed |
| PS-9 | Vault-first credentials; webhook → bot token | already partly conformant |
| PS-10 | notifier repaired — it had never delivered | already repaired |
| PS-12 | 44 fetches retried, 0 verdicts; notifier says *errored* or *failed* | 52 fetches retried, 0 verdicts; same, plus `report-to-hub` |
| — | `remediate` waits on `iac` | `remediate` waits on `iac` |
| — | `groups:` added | `groups:` added |

PS-12 landed on `personal-soc.yml` too — 29 fetches, 13 notifier hooks — which
the table has no column for and which matters here more than tidiness: it is
the pipeline holding `netassess-ingest`, one of the two refusals the rule is
written to protect.

Plus, outside the pipelines: `mykronos.junit_stage` (new module),
`check_pinned_ref.py` extended to assert the raw-fetched scripts exist at the
pin, and `CAPABILITY_BY_JOB` taught the eight newly-reporting job names.

---

## Open items

These are named rather than done, each with the reason.

1. **`cloud` is granted to a repository with no cloud.** Revoke the grant for
   `ToddGBenson/mykronos` (PS-5). Operator action against the running instance.
2. **Cut `mykronos-ref` v4.** `pin-check` will go red as soon as this lands:
   the pipelines now invoke `mykronos.junit_stage`, which does not exist at
   `v3`. That is the check working. TheHub's new `qa` lane and its
   `prompt-evals` reporting need the new tag before they turn green; the
   mykronos lanes run their reporter from the checkout and do not.
3. **Aegis is not an Oracle input for TheHub.** Moving `insider` alongside the
   security lanes and into `oracle-gate`'s `passed:` would give TheHub both —
   insider risk in the score *and* a gate before the human promotes, since
   `deploy-prod` would then pass from `oracle-gate`. It contradicts spec 16 §3
   as written, and spec changes land as their own commits before the code that
   depends on them, so it is proposed here rather than done.
4. **Two jobs upload `dast` for one TheHub commit** (`dast-demo` and
   `functional-dast`). Distinct ScanRuns, so no data is lost, but the same
   finding fingerprints churn `last_seen_scan_run_id` between them. Worth a
   `--scan-run-id` convention or one lane owning the capability.
5. **No image signing or SBOM attestation.** Provenance is a JSON object posted
   to the ingestion API, which is a record rather than a verifiable claim.
   `cosign sign` on the `:SHA` tag and an attached SBOM attestation is the next
   real step in supply-chain integrity, and it is a bigger piece of work than
   anything above.
6. **DAST does not gate anything on mykronos.** `demo-and-dast` is not in
   `oracle-gate`'s `passed:` list, so runtime findings never reach the decision
   — the ordering TheHub deliberately adopted (spec 16 §3). Moot while the lane
   is paused under D-053, and worth revisiting when it is unpaused.
7. **PS-12 does not reach keel, and keel is where the stampede is.** keel's
   `daily` resource is `interval: 24h` rather than a window, and `get: daily`
   appears ten times, all ten with `trigger: true` — build, lint, test,
   secrets, sca, iac, suppression-audit, platform-integrity, compliance-daily
   and sast all schedule in the same instant onto two workers, which is what
   produced the iptables contention PS-12 now retries around. The three
   pipelines in this repository are structurally immune to the same thing:
   `thehub` uses a `2:00–3:00 AM` window and puts every job in one
   `serial_groups: [worker]`, `mykronos` and `personal-soc` use windows too.
   But keel's pipeline is not maintained here — `docs/current-state/keel-pipeline.yml`
   is a captured snapshot, not a source — so the fan-out fix belongs in keel's
   own repository. Retrying a stampede is treating the symptom; the two changes
   are complementary and only one of them can be made from here.
8. **Nothing yet notices a lane that is still red tomorrow.** PS-12's
   `on_error:` hooks now say *errored* rather than *failed*, and say what to do
   about each — which is the difference between an alert and a notification.
   It is still one message at the moment of failure, though. The lanes that
   went dark on 2026-09-07 would have produced one Slack message each on the
   seventh and then nothing for three days.

   A standing signal does exist, and the honest first step is to find out why
   it did not fire rather than to build a second one. `ci.py` already counts
   `errored` among the statuses that did not succeed
   (`_DID_NOT_SUCCEED`, `last_build_failed`), and the coverage cross-check
   resolves each capability to `reporting` / `silent` / `never_reported` /
   `failed` and leads the briefing with the ones that cannot close a finding.
   That machinery covers what is onboarded and listed in `CAPABILITY_BY_JOB` —
   which the five keel compliance and AI-assurance jobs that stayed red for
   three days are not. So the question to answer before writing anything is
   whether this was a detector that failed or a lane outside the detector's
   scope, and the answer decides whether the fix is a backend change or a
   grant. That is a story of its own; PS-12 does not close it and does not
   claim to.
