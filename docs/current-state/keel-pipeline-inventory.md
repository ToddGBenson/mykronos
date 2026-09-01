# keel — pipeline inventory

**Read-only. Measured against the running Concourse on 2026-09-01 (B-012).**

`keel` is a Concourse pipeline this platform is responsible for and had never
written down. TheHub's runbook described it as 11 jobs in 3 groups; it is 26
jobs in 7 groups plus a display group, so fifteen jobs existed in neither
repository — including an `agent-assurance` job anyone planning AI-assurance
work would want to know about.

The exported configuration is beside this file as
[`keel-pipeline.yml`](keel-pipeline.yml), taken with `fly get-pipeline -p keel`.

**It is deliberately not in `deploy/concourse/pipelines/`.** That directory is
the set of pipelines this repository *applies*, and `check_applied_pipelines.py`
reads it to detect drift. Putting keel's exported config there would claim this
repo is the source of its definition, which is the opposite of what is true —
see Ownership below. The export is a record of what is running, not a thing to
apply.

The four credentials in the config remain unresolved `((vars))` in the export —
`anthropic_api_key`, `git_private_key`, `mykronos_ingestion_token`,
`webhook_token`. `fly get-pipeline` does not inline them, so nothing secret is
committed here.

## Three corrections to what was believed

**keel is not paused.** The story this came from recorded it as paused by the
`mykronos` user. The API reports `paused: false`, with `paused_by` and
`paused_at` both null, and jobs have run since. Whatever paused it was undone
before this was measured. This matters beyond bookkeeping: the entry was
iceboxed on the trigger *"keel is unpaused"*, so that trigger had already fired.

**Seven groups, plus a display group.** The count is eight, and the eighth is
`all`, whose only member is the wildcard `*`. Concourse groups are a view, not
a partition — `suppression-audit` is in both `security` and `governance`, and
five jobs appear in `scheduled` as well as their own group. Seven real groups
is right; the total is 26 *distinct* jobs, not the sum of the group sizes.

**The `mykronos` group was failing, and is not any more.** All three of its
jobs were red when this inventory was taken, on the ingest preflight with
`401 ... token is unknown, revoked, or expired` — the same outage that took
four lanes of the `mykronos` pipeline down on 2026-08-31, in a third reader
nobody had found. Repaired the same day; all three now succeed. See
[`DECISIONS.md` D-097](../DECISIONS.md) for why it happened three times.

## Ownership

keel belongs to MyKronos, and every signal agrees:

- It **self-sets**. `parent_job_id = 931` resolves to build 375158, whose job
  is `set-pipeline` **in the `keel` pipeline itself**. The definition lives in
  the `ToddGBenson/keel` GitHub repository and re-applies from there — so the
  "a production pipeline with no definition in any repo" diagnosis does not
  apply here. That repo is simply not checked out on this machine.
- It is named as a migration subject in
  [spec 32 §1–2](../../specs/32-github-actions-delivery.md) and D-093.
- It is absent from `scripts/check_applied_pipelines.py`, correctly: this
  repository does not hold its definition and must not claim to.
- TheHub's own `concourse/pipelines/README.md` says only `thehub` is theirs.

**One correction carried over:** D-079 covers `thehub` and `mykronos` and does
not name keel, so it neither exonerates nor implicates it.

## The 26 jobs

Status is the last finished build as of 2026-09-01.

| Job | Groups | Last finished |
|---|---|---|
| `agent-assurance` | ai, scheduled | succeeded |
| `ai-evals` | ai | succeeded |
| `ai-guardrails` | ai, scheduled | succeeded |
| `authorize-release` | release | **never run** |
| `build` | commit | succeeded |
| `build-and-attest` | commit | succeeded |
| `compliance-daily` | governance, scheduled | **errored** |
| `compliance-monthly` | governance, scheduled | succeeded |
| `compliance-weekly` | governance, scheduled | succeeded |
| `container-scan` | security | **never run** |
| `full-suite` | commit | succeeded |
| `iac` | security | succeeded |
| `lint` | commit | succeeded |
| `metrics-snapshot` | governance, scheduled | succeeded |
| `mykronos-atlas` | mykronos | succeeded (was failing) |
| `mykronos-sast` | mykronos | succeeded (was failing) |
| `mykronos-secrets` | mykronos | succeeded (was failing) |
| `platform-integrity` | governance | succeeded |
| `release-preflight` | release | **never run** |
| `sast` | security | succeeded |
| `sca` | security | succeeded |
| `secrets` | security | succeeded |
| `set-pipeline` | commit | succeeded |
| `suppression-audit` | security, governance | succeeded |
| `test` | commit | succeeded |
| `verify-artifact` | commit | succeeded |

## Findings

**F1 — The `release` group has never executed.** Both `release-preflight` and
`authorize-release` have no finished build and no next build. A release path
that has never run is not a release path; it is an untested one, and the first
time it matters will be the first time it runs.

**F2 — `container-scan` has never run.** The only never-run job outside
`release`, and it sits in `security` beside five lanes that all report. A
security group where one lane has never executed reads as covered and is not —
the same shape as the reporting cross-check in spec 15 §4a exists to catch.

**F3 — `compliance-daily` is errored.** Not failed: *errored*, which in
Concourse means the task did not complete rather than completed unhappily. Its
weekly and monthly siblings both succeed, so this is specific to the daily
lane rather than to compliance.

**F4 — No job is paused, and the pipeline is not paused.** Recorded because it
was believed otherwise, and because it means nothing here is dormant by
intention — a red or never-run job is a real gap rather than a switched-off one.

**F5 — keel had a third stale copy of the mykronos ingestion token.** Found
while taking this inventory. Recorded in full under D-097; noted here because
it is the reason the `mykronos` group is worth watching after any rotation.

## What was not done

Nothing here set, unpaused, modified or triggered any pipeline configuration.
The inventory is read from the Concourse API and `fly get-pipeline`.

Three keel jobs *were* triggered — `mykronos-sast`, `mykronos-secrets`,
`mykronos-atlas` — to verify the credential repair in F5. That is the token
outage being fixed, not this inventory being taken, and it is called out rather
than folded in.

F1 to F4 are recorded, not acted on. Deciding what a never-executed release
path or an errored compliance lane deserves is keel's own work, in keel's own
repository, and this document exists so that decision starts from what is
actually there.
