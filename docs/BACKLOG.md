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
2026-08-31 and none of them needed the state afterwards.)

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

None. B-008 and B-010 landed on 2026-09-01; B-013 the same day. What remains
is two entries deferred on triggers that have not fired.

---

## Icebox

Deferred on a named trigger. The trigger is recorded so it can be watched for
rather than rediscovered.

### B-011 — Only a test fixture can produce a demonstrated regression link

**Size:** M **State:** icebox **Verified:** 2026-08-31
**Specs:** [26 §2](../specs/26-oracle-as-adviser.md), [31 §6](../specs/31-regression-coverage.md)
**Was:** TheHub #58498

Spec 31 defines three sources for a finding-to-test link. Only one exists, and
the one carrying the reward does not. `demonstrated` is written in exactly one
place: `backend/tests/test_regression_coverage.py:149`. Every non-test mention in
`backend/mykronos/` reads or coalesces the grade — `regression.py:48` defines the
constant, `regression.py:238` compares against it, `lake/compaction.py:195`
preserves it — and none writes it. The Patchwork-PR-body source has no production
code at all.

Specs 26 §2 and 31 §6 both describe "demonstrated outweighs asserted" as the
point of the design. The winning grade is unreachable outside the test suite, so
the incentive the whole scoring model rests on cannot fire.

**Why iceboxed:** the reward mechanism cannot be exercised without production
Patchwork traffic. Building the producer now ships code nothing can exercise —
the exact defect this entry was written to fix.

**Brings it back:** Patchwork producing real PRs in MyKronos.

**Acceptance criteria**

- A production code path writes `link_source=demonstrated` — the Patchwork
  PR-body parser from spec 31.
- A test asserts the producer is **not** under `backend/tests/`, so a fixture can
  never again be the only writer.
- The portfolio regression-coverage number changes when a real Patchwork PR lands.
- Existing `asserted` links are left intact and are not silently upgraded.

---

### B-012 — Export keel's 26 jobs so it can be read, then review it here

**Size:** M **State:** icebox **Verified:** 2026-08-31 (evidence is TheHub's, not re-measured here)
**Specs:** [32 §1–2](../specs/32-github-actions-delivery.md) **Was:** TheHub #58537

keel is ours: a separate GitHub repo, self-setting from `ToddGBenson/keel`
(`pipelines.parent_job_id = 931`, job 931 being `set-pipeline` inside keel
itself), paused by the `mykronos` user, claimed as a migration subject in spec 32
and D-093, and named as not-TheHub's by TheHub's
`concourse/pipelines/README.md`. It is absent from our own drift checker
(`scripts/check_applied_pipelines.py:59-63`) because there is no local file.

TheHub's records of keel are wrong — its runbook lists 11 jobs in 3 groups; the
server has **26 jobs in 7 groups** (`commit`, `security`, `mykronos`,
`governance`, `ai`, `scheduled`, `release`). Fifteen jobs are written down in
neither repo, including an existing `agent-assurance` job anyone planning this
work would want to know about. keel's `release` group has never executed at all.

It is readable today: the Concourse database holds 28 readable job configs for
keel totalling 10,494 bytes, unencrypted, and TheHub's existing exporter already
takes `--pipeline` and resolves any pipeline by name.

**Correction carried over:** D-079 covers `thehub` and `mykronos` and does not
name keel, so it neither exonerates nor implicates it.

**Why iceboxed:** keel is paused and migrating to Actions per D-093.
**Brings it back:** keel is unpaused, or the Actions migration needs the inventory.

**Acceptance criteria**

- keel's live configuration is exported and readable, using the existing exporter
  unmodified where possible.
- All 26 jobs and 7 groups are recorded accurately, including the 15 currently
  undocumented.
- The paused state, `paused_by`, `paused_at` and the three never-run jobs are
  recorded as findings alongside the inventory.
- The finding that keel self-sets from `ToddGBenson/keel` is recorded, so the
  next reader does not repeat the "no definition in any repo" diagnosis.
- Nothing in this entry sets, unpauses, modifies or triggers any pipeline; it is
  read-only against the Concourse database and API.

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
