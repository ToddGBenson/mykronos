# Backlog

Open work that is not a decision and not a retro. Decisions that settle *how*
something is built belong in [`DECISIONS.md`](DECISIONS.md); what happened on a
bad day belongs in [`retros/`](retros/). This file is what is *not done yet*.

Format: `B-nnn` / size / state / the problem / acceptance criteria / provenance.
Entries move to the Closed section when they land, with the closing commit or
decision noted, rather than being deleted outright.

**States:** `open` — scoped and actionable. `icebox` — deferred on a named
trigger; the trigger is recorded so it can be watched for. (`needs scoping`
existed briefly for the three cross-repo entries; the scoping was done on
2026-08-31 and none of them needed the state afterwards. Nothing is iceboxed
today — and B-012 is why the state deserves a periodic re-read: its trigger had
fired without anybody noticing.)

Every entry carries a **Verified** date. That means the defect was reproduced
against this codebase on that date — not that the entry was merely read.
Re-verify before pulling one up; the code moves.

## Provenance

Twelve stories were exported from TheHub on 2026-08-31 and folded in here. They
had been filed against TheHub because that is where the evidence was found, but
TheHub's `CLAUDE.md` is explicit that that repo does not build MyKronos, so the
three cross-repo ones sat blocked there from 2026-08-18. Arriving here removed
that block: the data and the authority they need are in this codebase.

**Scoping those three against this repo mattered more than expected.** Two of
their premises were stale — written against TheHub, or predating work that has
since landed here. B-009 turned out to have been decided in full by D-047
before the story ever arrived, and B-010's central claim ("nothing surfaces
that revisit") is false here: the endpoint exists and the revisit is
automated. Only B-008 survived roughly intact, and it shrank. None of the
three needed the state they arrived with, which is the argument for scoping a
carried-over story against the receiving codebase before believing it.

TheHub story ids are kept in each entry so the trail back is not lost. One
story that matched the `mykronos` tag was deliberately excluded from the export
— TheHub #58508, a docker-compose env mapping, which is TheHub's own work and
already shipped.

---

## Open

Five entries from a monitoring sweep of the running platform on 2026-09-01.
Every one was reproduced against the live system before it was written; the
evidence is in each entry rather than a link to a dashboard that will have
moved on.

Ordered by consequence. The first two are the platform being wrong about its
own health, which is worse than the thing it is wrong about.

### B-014 — The one check that would have caught a sealed Vault is inert, and reports FAILED anyway

**Size:** S **State:** open **Verified:** 2026-09-01
**Specs:** [32 §8.1](../specs/32-github-actions-delivery.md)

`mykronos self-check` reports:

```
vault   FAILED   No Vault is configured for this deployment.
Not reachable: vault
```

**`vault_url` is empty, and is set nowhere** — not in `backend/.env`, not in
`deploy/`. `jobs.check_vault` returns `reachable=False` with that detail when
the URL is blank, and the CLI renders that as `FAILED`.

Two separate defects, and the second is the expensive one:

1. **A deliberate absence is reported as a failure.** The backend has no Vault
   client on purpose — D-086 treats giving it one as a boundary to argue about
   rather than cross quietly. A permanent `FAILED` on a dependency the platform
   has decided not to have is the "permanent false alarm that trains people to
   ignore the panel" this codebase already names in `last_successful_scan_at`.
   Every `self-check` run has been red since it shipped, so the command cannot
   report anything else going wrong.

2. **`check_vault` already detects a sealed Vault, and never runs.** It reads
   `/v1/sys/health`, distinguishes sealed from unreachable, and its message
   even names the fix script. Vault sealed on 2026-09-01 and nothing surfaced
   it — the pipelines would have failed on unresolvable vars in a way that
   looks like a credentials bug, which is exactly what that detail exists to
   prevent. The detection is written, correct, and unreachable.

**Acceptance criteria**

- `vault_url` is configured for this deployment, so the seal check runs.
- An unconfigured dependency reports as unavailable or skipped, never
  `FAILED` — the same distinction this platform draws between "not enabled"
  and "enabled and silent" everywhere else.
- A sealed Vault makes `self-check` say so, with the unseal script named.
- A test covers all three states: unconfigured, sealed, healthy.

---

### B-015 — Three capabilities are permanently "enabled and silent", by design

**Size:** S **State:** open **Verified:** 2026-09-01
**Specs:** [06 §3](../specs/06-aegis-integration.md), [10 §7](../specs/10-jded-dashboard.md)

`aegis`, `oracle` and `patchwork` show `has_scanned: false` on every repository
that enables them, for ever. Measured across the whole lake:

```
sast 365 · secrets 282 · atlas 234 · qa 209 · iac 141
unit 137 · containers 130 · ai 82 · dast 40 · functional 16
aegis 0 · oracle 0 · patchwork 0 · cloud 0 · network 0
```

The first three are zero **by design and always will be**: aegis writes an
`InsiderRiskSignal`, oracle writes a `RiskDecision`, patchwork writes a
`RemediationEvent`. None of them writes a `ScanRun`, and
`_capability_scan_state` reads `scan_runs` and nothing else.

`last_successful_scan_at` already solves exactly this, with a comment saying
why: *"Looking for it in scan_runs reports every insider job as having reported
nothing, which is both wrong and the kind of permanent false alarm that trains
people to ignore the panel."* `capability_states` never got the same treatment.

**This became consequential with B-008**, which is why it is filed now rather
than left. Before that change, "enabled and silent" was an absence a caller had
to infer; now it is a named state a caller is invited to act on — so three of
fifteen capabilities permanently assert a problem that does not exist. The
field made the platform more honest about one thing and more wrong about
another.

**Acceptance criteria**

- A capability that reports through a table other than `scan_runs` is read from
  the table it actually writes, as `last_successful_scan_at` does.
- Its state on the portfolio distinguishes "has reported" from "cannot report
  this way", rather than reporting silence.
- A test asserts each of the three is not permanently silent, so the next
  capability that reports differently is caught when it is added.
- `cloud` and `network` are genuinely at zero and must keep reporting as such —
  see B-018 for `cloud`.

---

### B-016 — personal-soc has been scanning and filing nothing since 2026-08-12

**Size:** S **State:** open **Verified:** 2026-09-01
**Specs:** [15 §6](../specs/15-concourse-pipeline.md)

The applied `personal-soc` pipeline carries, verbatim:

```yaml
params:
  MYKRONOS_TOKEN: ""
```

`PERSONAL_SOC_INGESTION_TOKEN` is **absent from `deploy/concourse/.env`**, and
`set-personal-soc-pipeline.ps1:187` reads it with `Read-EnvValueOptional` — so
a missing credential applies cleanly as an empty string. The `.env` files were
rebuilt from running containers on 2026-08-23 after being lost; this key was not
among what came back.

The lake agrees: personal-soc's newest scan run is **2026-08-12**, twenty days
before this was measured, and the portfolio flags it `is_stale`.

**The pipeline is honest about it and nobody is listening.** Each task checks
for an empty token and prints `NO MYKRONOS TOKEN — RESULTS WERE NOT FILED`,
with a comment saying that beats a green tick implying otherwise. It is right,
and it is buried in a build log: the job still goes green, so nothing on any
dashboard says this repository stopped reporting.

**Acceptance criteria**

- The token is restored and the pipeline re-applied, so results file again.
- `set-personal-soc-pipeline.ps1` refuses to apply with an empty ingestion
  token rather than treating it as optional — an unset credential is a
  configuration error, not a setting.
- A repository that stops reporting is visible without reading a build log.
  The reporting cross-check (spec 15 §4a) is the existing home for this.
- Note for whoever takes this: the same rotation family that caused D-097 also
  touched this token (`rotation-resync`, 2026-08-21). Deliver to every reader
  in one operation.

---

### B-017 — Three personal-soc jobs have been failing for a week

**Size:** M **State:** open **Verified:** 2026-09-01

`netassess-ingest`, `netassess-freshness` and `package` are all red and not
paused. `netassess-ingest` has failed since 2026-08-24, `package` since
2026-08-31 — its last success was 2026-08-12, the same day the repository
stopped filing results.

Not yet root-caused. `netassess-ingest`'s log reaches the failure-notify hook
with almost no task output before it, which points at an early exit rather than
a check that ran and reported. Whether these share a cause with B-016's empty
token is exactly the question to answer first — the dates line up and the same
pipeline holds both.

**Acceptance criteria**

- Each of the three has a named cause, or is retired if the job no longer has a
  job to do.
- Whether B-016 is the cause is answered explicitly rather than assumed either
  way.
- `personal-soc` reaches a state where every unpaused job is green or is
  deliberately paused with the reason recorded, as `demo-and-dast` is.

---

### B-018 — `cloud` is enabled on a repository and its lane cannot run

**Size:** S **State:** open **Verified:** 2026-09-01

`cloud` is enabled on `ToddGBenson/TheHub` and has produced zero scan runs
across the entire lake, ever. The reason is upstream of the platform:
`thehub`'s `cloud-posture` job is paused because `deploy/concourse/.env` has no
Azure service principal — `set-thehub-pipeline.ps1` refuses to apply without one
unless `-AllowMissingAzure` is passed, and the applied pipeline's
`AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID` and
`AZURE_SUBSCRIPTION_ID` are all empty.

So the capability reads as enabled on the dashboard and is structurally
incapable of reporting. That is the same shape as spec 14's network claim
(B-007, closed): a capability the platform presents as available and cannot
perform.

**This needs a decision before code.** Either the Azure principal is restored —
only the operator knows whether it was lost with the rest of `.env` on
2026-08-23 or deliberately never set — or `cloud` is disabled on TheHub and
recorded as not available on this deployment. Both are defensible; leaving it
enabled and inert is not.

**Acceptance criteria**

- Either `cloud-posture` can run, or `cloud` is not presented as enabled.
- Whichever way it goes is written down, as D-053 did for DAST.
- Distinct from B-015: `cloud`'s zero is real, and must keep reading as real.

---

## Watching, not filed

Recorded so the next sweep does not rediscover them, and deliberately not turned
into entries here:

- **`thehub`: `deploy-demo` and `api-inventory` are failing.** `deploy-demo`
  timed out after 25 minutes waiting for the demo environment to report a SHA
  ("host-side poller is not running, or it failed and rolled back");
  `api-inventory` reports "The API surface has changed and the inventory has
  not". Both are TheHub's own code, in TheHub's repository. This repo holds the
  pipeline definition, not the fix.
- **`keel`: `compliance-daily` is errored** — *errored*, not failed, so the task
  did not complete rather than completing unhappily. Its weekly and monthly
  siblings pass. Recorded in
  [`current-state/keel-pipeline-inventory.md`](current-state/keel-pipeline-inventory.md)
  as F3, along with three never-run jobs; keel's work belongs in keel's repo.
- **Two overdue critical findings on TheHub.** Past their `due_at` and open.
  That is the ownership-and-deadlines mechanism working as designed (spec 24) —
  a thing for somebody to do, not a defect in the platform.

---

## Closed

Eight entries closed on 2026-08-31. Seven were built: each was re-verified
against the working tree before it was touched, every one still reproduced, and
each is recorded where the repo already looks — a decision for the two that
changed what the platform promises, a spec amendment for the four that made a
document match the code. The eighth, B-009, was closed without code because the
decision it asked for already existed.

Backend after all seven: 2277 tests pass, mypy clean over 107 files, ruff
clean. Frontend `tsc --noEmit` clean. `api-types.d.ts` regenerated.

### B-011 — A fix pull request can produce a regression link — **done**

The producer spec 31 §2 describes existed nowhere. Every link in a running
system had been written by `tests/test_regression_coverage.py` hand-crafting an
HTTP request, so the number the whole incentive design rests on could not move
outside the suite.

Patchwork's PR body now carries the block spec 31 asks for — *"if you add a
regression test, name it here"* — and `outcomes._link_regression_test` parses it
on merge, keyed so a redelivered webhook updates one link rather than inflating
the count. Same shape as `rejection.py`, which already asks the closer of an
unmerged draft why: the person writing the regression test is the person merging
the fix, and that is the cheapest moment anyone will ever be asked.

**It produces `asserted`, and that is the honest grade rather than a shortfall.**
The entry asked for a production path writing `demonstrated`. Building it showed
why the spec does not put `demonstrated` here: the test arrives *in* the fix pull
request, so it does not exist on the parent commit, and no ordinary lane run
there can have exercised it. A lane that went red-to-green across the merge is
evidence about the lane, not about this test. `demonstrated` needs the new test
run against the *old source* — a lane invocation taking a ref, and
`dispatch(repo_full_name, capability)` takes no commit. Spec 31 §8 already
contemplates exactly this: *"`demonstrated` cannot be established; the link
stays `asserted` and says why."*

Claiming otherwise would have been the worst available outcome. Oracle weights
`demonstrated` above `asserted` precisely because it means more (spec 26 §2,
spec 31 §6), so a fabricated grade would corrupt the one number spec 31 exists
to make trustworthy.

**What remains, precisely:** commit-targeted lane dispatch. That is
infrastructure — GitHub Actions `workflow_dispatch` takes a ref, Concourse does
not without a pipeline change in every repository — and it is its own entry
whenever somebody wants it.

The entry's other criterion is now a test: `TestTheProducerIsNotAFixture`
asserts the linker's source file is not under `backend/tests/`, so a fixture can
never again be the only writer.

### B-012 — keel is exported, inventoried, and its findings recorded — **done**

Read-only, into
[`docs/current-state/keel-pipeline-inventory.md`](current-state/keel-pipeline-inventory.md)
with the config beside it. Deliberately not in `deploy/concourse/pipelines/`:
that directory is what this repo *applies*, and putting keel there would claim
ownership of a definition that lives in `ToddGBenson/keel`.

**Its icebox trigger had already fired, and nobody noticed.** The entry was
deferred until "keel is unpaused". keel is not paused — `paused: false`,
`paused_by` and `paused_at` both null. Two other premises also needed
correcting: eight groups rather than seven (the eighth is an `all` wildcard,
and groups overlap, so seven real groups over 26 *distinct* jobs is the right
reading).

Confirmed as filed: 26 jobs, fifteen written down nowhere, three never-run
(`container-scan`, `release-preflight`, `authorize-release`), the entire
`release` group never executed, and keel self-setting from its own
`set-pipeline` job — so the "no definition in any repo" diagnosis does not
apply and the next reader will not repeat it.

**It also found a live outage.** All three `mykronos-*` jobs were failing on the
same 401 that took four `mykronos` lanes down on 2026-08-31 — a third stale
copy of the ingestion token, at `concourse/main/keel/mykronos_ingestion_token`,
that the earlier repair never reached. Repaired by rotating and delivering to
both readers at once; all three now succeed. Recorded under D-097.

Nothing in the inventory set, unpaused, modified or triggered any pipeline. The
three keel jobs that *were* triggered belong to the credential repair, not to
the inventory, and the document says so rather than folding them in.

### B-008 — Every expected stage is named, including the ones with no job — **done**

The premise needed correcting before the work did. The story said AI,
functional and unit "do not exist as stages at all"; all four of those plus
`qa` are capabilities with workflow templates here. That was true of TheHub,
not of this repo, and twelve of the thirteen named stages already existed and
reported.

What was actually wrong was narrower: `capability_states` was built from
`sorted(enabled)`, so a capability nobody turned on was an *absence* — and so
was one that was enabled and had never reported. Two different answers, one
empty space. Every capability now gets a row carrying `enabled`, so
`enabled: false` ("not configured here") and `enabled: true, has_scanned:
false` ("enabled and silent") are distinguishable, and only one of them is
somebody's problem.

`has_scanned` is read for every capability rather than assumed false for the
disabled ones: a Concourse repo's grants are its ledger, and a capability can
report without appearing in the installer's list. Dropping those rows would
have hidden scans that actually happened.

**Already correct, and left alone:** the frontend renders all fifteen
capabilities with a "not enabled" tooltip, so the UI half of the criterion was
met before this. The API row was the half that disagreed with it, and now it
does not.

### B-010 — The vulnerability management view is finished — **done**

Most of this was already built and cited PIP-9 by name; the endpoint had simply
never been rendered. Three gaps closed:

**Aging carries the capability.** "Sixty high findings older than ninety days"
is a number to be alarmed by; "they are all container CVEs from one base image"
is the thing to act on. Without it the reader opens every finding to learn that.

**Acceptances are listed, not counted.** Counts cannot say what was accepted or
on what grounds, and the grounds are the part that decays. Each row now carries
`accepted_reason_code` and `accepted_until`, plus `now_fixable` — accepted for
want of a fix, and a fix now exists. That flag is deliberately narrow: it fires
only for `no_vendor_fix`, the one premise a scan can contradict and the only
one the daily sweep re-opens (spec 24 §3.2). A fix existing does not contradict
"not exploitable here", and calling that fixable would send somebody to
re-litigate a decision that is still true.

**A page renders it**, at `/vulnerability-management`, which was most of the
remaining value.

Building it surfaced a defect the type checker could not: rendered against the
currently-deployed backend the page 500s, because that backend has no
`accepted_risk_detail` and `undefined.filter` throws. During any rollout the
frontend is briefly newer than the backend, so the page now defaults its
sections and skips the capability tally when a row carries none — otherwise the
column read "undefined 205", which is the wrong-but-plausible render this repo
treats as worse than an empty one. Both were found by loading the page, not by
building it.

**Not done, and not needed:** the story asked for "a way to see which have
become fixable since". The daily acceptance sweep already re-opens those
automatically, so the page surfaces the state rather than adding a second
mechanism to chase it.

### B-013 — Rotation would have desynced Vault again — **done** (D-097)

Filed from the 2026-08-31 outage, fixed the same day.

D-086's guard was `scanned_by != "github_actions"`, and `scanned_by` holds one
value while describing "intent, not coverage" in its own docstring. A
repository migrating under spec 32 is scanned by both systems, so it declared
`github_actions`, passed the guard, and every rotation left Vault behind.

The fix asks who reads the token rather than what the repository declares:
`ConcourseClient.has_pipeline_for` answers from the Concourse server, so a
repository cannot be wrong about itself. It returns three states, and the third
is load-bearing — `None` for "could not be established" defers, because failing
open would say "nobody else reads this" on any day Concourse was down, which is
how the credential desynchronised in the first place.

Covers the faster trigger too: an active token with `secret_synced = 0` is
swept up and rotated again as a resync on the job's ordinary interval, so a
manual repair reaching Vault but not Actions used to arm the recurrence by
itself.

**Still true, and unchanged:** the platform cannot deliver to Vault, so
Concourse-scanned repositories still do not rotate automatically. D-097 makes
the deferral correct, not unnecessary. D-086's note that this is a real
regression against 90-day rotation stands.

The gap in the tests mirrored D-086's own: none described a repository scanned
by both systems, the only configuration where the bug appears. There is now a
test for that, and one asserting an Actions-only repository still rotates — so
the guard cannot quietly end rotation altogether.

### B-009 — AI as its own stage — **closed, already decided** (D-047)

Not built, not scoped: **already answered before the story arrived here.**

B-009 asked for "a decision naming what the AI stage asserts and what it does
not", and D-047 — *"AI is four concerns; three become a capability and one
stays where it is"* — is that decision, taken 2026-08-13 against this repo and
citing the same PIP-7 the story came from. It names all four concerns
(prompt-injection surface, model/dependency provenance, evaluation regression,
disclosure of AI authorship), puts 1–3 in the `ai` capability, and keeps 4 in
Aegis, with the boundary reasoning: Aegis assesses a pull request and its
author, the other three assess the code and its configuration and are true of a
commit whether or not anyone opened a pull request.

Every acceptance criterion is met by it:

- *A decision naming what the stage asserts and what it does not* — D-047.
- *Explicitly says whether the AI-authorship signal moves or stays* — it stays,
  and D-047 says why moving it would split Aegis's one coherent question across
  two capabilities.
- *Spec 06 updated if the boundary moves* — the boundary did not move. D-047
  cites spec 04 §3 and spec 06 §2 as they stand.

It is implemented, too: the `ai` capability exists with a workflow template,
an `AdapterSpec` accepting SARIF from any tool, and `ai_pin_check.py` as the
provenance third.

**What D-047 decided and nobody has built yet** — prompt-injection detection
and evaluation-regression detection — is named in `ai_pin_check.py`'s own
docstring as deliberately absent, because the first needs a semantic classifier
and the second a runtime eval harness. That is decided-and-unbuilt, which is a
different thing from undecided, and it belongs in a new entry if it is ever
wanted. It is not what B-009 asked for.

### B-001 — Codenames reaching users through the backend and OpenAPI — **done**

The four response strings now name the capability, and so does a fifth the
story missed: `webhooks.py:364` returned `{"ignored": "not a Patchwork
branch"}` in an actual response body.

The story's diagnosis was wrong about where the schema leak came from — it
named "14 `Field(description=)` blocks in capabilities.py, config.py,
dashboard.py", and no `description=` line anywhere carried a codename. The 38
occurrences came from **14 route docstrings** and **15 component sites** (model
docstrings, field descriptions, and three default *values*) across six modules.
Vocabulary follows `CAPABILITY_META`: Insider risk / Risk decisions /
Auto-remediation, with "the risk-decision engine" where an agent noun was
needed — spec 00's own wording.

**Nine occurrences deliberately remain**, all identifiers rather than prose, on
the same principle as the capability-keys carve-out: the `AegisAccepted`
response-schema type name (3), five response `title`s FastAPI synthesises from
the `/api/oracle/` path, and one `` `PatchworkPipeline.run_one` `` code pointer.
Zero product-name prose remains.

**The first pass was incomplete, and a second finished it.** Chasing the one
Atlas string above showed the sweep had been scoped to `api/*.py` and
`schemas.py` — but response values are also built in `governance.py`,
`dashboard.py`, `aegis.py`, `incident.py` and `oracle/engine.py`, and none of
those had been looked at. Ten more user-facing sites, found by asking what
*reaches* a user rather than which files seemed likely:

- `aegis.py:228` — the **Check Run body posted onto pull requests**: "Aegis
  cannot block, merge or close a pull request". The most-read string of the set.
- `aegis.py:156`, `governance.py:494`, `oracle/engine.py:252` — `reason` fields
  in API responses.
- `dashboard.py:283, :291` — worklist rank explanations shown per row.
- `incident.py:304` — the "last Atlas scan" note.
- `capabilities.py:303` and the `PatchworkConfig` / `OracleConfig` docstrings —
  served by `config_schema` at `repos.py:348`, which the UI renders its
  configuration forms from. Not obviously an API surface until you look.
- `ingest.py:740`, `schemas.py:459` — the Atlas equivalents of two sites already
  fixed for the other three names.

Atlas was folded in: it was excluded from the original entry because the
frontend already handled it, which was true of the frontend and not of the
backend.

**Verified by dumping both published surfaces** — `openapi.json` and every
`config_schema` — and grepping the output, rather than by grepping source for
names. Config schemas: zero. OpenAPI: twelve, all identifiers or path-derived
(`AegisAccepted`/`AtlasAccepted` type names, five titles FastAPI synthesises
from the `/api/oracle/` path, one code pointer). Zero prose across all four
names.

`config.py`'s descriptions were checked and deliberately left: `Settings` is
not exposed through any endpoint, so those are operator environment docs, not
a user surface.

### B-003 — `auto_merge_workflow_prs` — **done** (D-095)

Removed from model, schema and API. No UI rendered it and no test touched it.

**The story asked for "a migration drops the column" and there is no migration
framework** — `create_all` plus `add_missing_columns` (D-052) only ever *adds*.
So `Database.drop_retired_columns` was added against an explicit
`RETIRED_COLUMNS` list. Deliberately not the inverse of `add_missing_columns`:
"drop every column the models do not declare" is a data-loss bug waiting for
its first rollback. A test asserts no name is in `RETIRED_COLUMNS` and on a
model at once.

### B-002 — The fix generator that never generated — **done** (D-096)

Withdrawn, per the decision taken this session. Spec 08 §2 now specifies
deterministic fixers as the only generator; §5's config row is struck through.

Worse than the story recorded: **set**, the rationale read "No deterministic
fixer matches this finding", as though a generator had been consulted and
declined. Configuring the endpoint changed the sentence and nothing else, and
the new sentence was less true than the old one. The rationale is now one
sentence because there is one path.

The setting lives in the `capability_configs` JSON, not a column, so
`RETIRED_COLUMNS` does not apply — but the models are `extra="forbid"` while
the read path deliberately does not validate, so a repo configured before the
withdrawal would fail its next save on a field the operator cannot see.
`RETIRED_CONFIG_KEYS` strips withdrawn keys on save. An unknown key is still
refused.

### B-005 + B-004 — Atlas on the Concourse path — **done**

**These were one root cause.** The Concourse atlas task is a reduced copy of
the Actions one. The Actions template *does* pass `--check-freshness` (gated on
config) and *does* call `atlas_sbom`; a flag search misses it because it sits
inside a `.j2` conditional. Both pipelines now pass `--sbom`, so license
evidence no longer depends on which CI system finished last, and both can pass
`--check-freshness` behind `ATLAS_CHECK_FRESHNESS`.

**Freshness stays off, by decision.** The pass calls the npm and PyPI
registries, which spec 07 §7 requires be opted into. Capable, and not enabled.

**The dashboard now says which zero it is.** The `stale_dependencies` term was
emitted only when it scored, so "nobody asked" and "asked, nothing stale" were
both the term being *absent*. It is now always emitted in three states, with
not-measured rendered `—` by the existing three-state renderer. Underneath was
a second bug: `maintenance_known` falls back to `dependency_count` when the
field is absent, so a runner that never looked up a date was indistinguishable
from one that found every date — the term needed a separate "did anyone
measure" signal. No trust score moves; a test asserts that.

### B-006 — The incident drill-down 404 — **done**

`AffectedRepoOut` carries `repo_id`; the page links with it and falls back to
plain text where the exposure outlived the onboarding. Unknown tab ids now
render an `ErrorPanel` naming the valid ones instead of quietly rendering
Dashboard. `_resolve_repo`'s docstring claims "every response that links here
already carries `repo_id`" — this was the counterexample, and now it is not.
`tab-inventory.md` F1 corrected from hypothetical to shipped-and-fixed.

### B-007 — Spec 14's claim — **done**

The story asked for "spec 14 status rows Built → Not started". **Spec 14 has no
status rows** — its header said "Approved for build", which was honest. The
false claim was in the README: "Built; awaiting an authorized CIDR to scan",
which said the only missing input was permission when authorizing a range would
still have scanned nothing.

New spec 14 §0 inventories what exists against what does not. `network.py` is
annotated dormant, kept rather than deleted with the reason. The absence of
`network` from `DISPATCHABLE_CAPABILITIES` is documented as intentional.

**One nuance the story missed:** the nmap/nuclei adapter is registered, so
externally-produced scan output *does* ingest. Enabling the capability is not
useless — the platform just never runs the scan. The dashboard label carries
that note rather than being removed, and the toggle was left working, because
disabling it would break a path that does work.
