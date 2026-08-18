# Decision log

Implementation decisions that the specs do not settle, plus anything that
should become a spec change. Append-only: supersede an entry with a new one
rather than editing history.

Format: `D-nnn` / status / the decision / why / spec follow-up (if any).

---

## D-001 — Finding identity is anchored to code, not line numbers

**Status:** Decided, spec updated
**Spec:** [05 §5](../specs/05-datalake.md)

`finding_id` hashes a stable location fingerprint — `file_path` + `symbol` +
normalized `code_snippet` for code findings, `package_name` for dependency
findings — instead of `line_start`.

**Why:** hashing the line number meant any unrelated edit above a finding
retired it as `fixed` and re-reported the identical issue as newly discovered,
destroying `first_seen_at` and every metric derived from it: finding age,
mean-time-to-fix, Oracle's age-escalation term (spec 09 §5), and every
dashboard trend line (spec 10 §2.3).

Landed as a spec change first (commit `spec(05)`) and then implemented, per the
agreed process. Regression test: `tests/test_lake.py::test_line_shift_preserves_the_finding`.

---

## D-002 — `POST /api/ingest/scan-run` is an upsert

**Status:** Decided, spec amended
**Spec:** [05 §4](../specs/05-datalake.md)

Spec 05 §4 says the endpoint is "called first, at workflow start", but nothing
defines how `completed_at`, `scan_status` and `finding_count` get populated —
they are not known until the scan ends. There is no finalise endpoint.

The client generates `scan_run_id` before scanning and POSTs twice: once at
start, once at completion. The second POST upserts onto the first by
`scan_run_id`. This keeps one row per run (spec 05 §3) and stays idempotent
under workflow retries.

**Spec follow-up:** ✅ landed. Spec 05 §4 documents the two-phase call, the
upsert key, and why there is deliberately no separate finalise endpoint.

---

## D-003 — Compaction reads buffer segments with DuckDB, not Python

**Status:** Decided
**Spec:** [05 §2, §9](../specs/05-datalake.md)

Compaction points `read_json` at the JSONL segment files directly rather than
parsing them in Python and loading via `executemany`.

**Why:** DuckDB's `executemany` inserts row by row — measured at ~21s for
10,000 rows of five columns, which alone blows the 30-second budget in spec 05
§9. Reading the files natively is a vectorised scan: the same 10,000-finding
path now completes in **0.7s**, and the hand-written type-coercion layer
between the buffer's JSON and the table's types disappears.

---

## D-004 — Findings are attributed from the token, never the payload

**Status:** Decided
**Spec:** [05 §4](../specs/05-datalake.md), [12 §4](../specs/12-security-and-secrets-management.md)

`FindingSubmission` has no `repo_full_name` or `capability` field. The server
stamps both from the authenticated token's scope.

**Why:** it makes spec 12's blast-radius claim structural rather than a
validation rule someone could later relax. A workflow cannot file findings
against another repo because there is no field in which to say so.

For the same reason `finding_id`, `status` and the `first_seen`/`last_seen`
fields are server-assigned: an adapter able to name its own finding_id could
silently fork or merge identities.

---

## D-005 — A row lives in the partition of the date it was first seen

**Status:** Decided
**Spec:** [05 §2](../specs/05-datalake.md)

`findings` partitions on `date(first_seen_at)`, `scan_runs` on
`date(started_at)`, permanently.

**Why:** upserting into Parquet means rewriting a file. Partitioning on
first-seen means an update rewrites one *known* partition rather than migrating
a row between partitions, and old partitions stop changing once their findings
stop recurring. Each rewrite consolidates its partition to a single part file,
so repeated rescans do not fragment the lake.

---

## D-006 — Only `fixed` reopens; human dispositions survive a rescan

**Status:** Decided
**Spec:** [05 §5](../specs/05-datalake.md)

A finding marked `fixed` that reappears flips back to `open`, as the spec
requires. A finding marked `false_positive`, `accepted_risk` or `suppressed`
does **not**.

**Why:** the spec only names `fixed`. The other three are human decisions
rather than observations, and a scanner reporting the same finding again is not
new information about them — it is the exact thing the human already ruled on.
Overturning them would also generate a spurious retro signal in Phase 5.

---

## D-008 — GitHub App permission set corrected

**Status:** Decided, spec updated
**Spec:** [02 §4](../specs/02-onboarding-and-github-app.md), [12 §6](../specs/12-security-and-secrets-management.md)

Added `workflows: write` and changed Secrets from "No access" to `write`.

**Why:** the App as originally specified could not do its job. GitHub gates
`.github/workflows/` behind its own permission and refuses a `contents: write`
token there, so no install PR could ever commit. And the Actions Secrets API
requires `secrets: write` for any create-or-update — there is no create-only
tier, so the ingestion secret could not be provisioned either.

Spec 12 §6 had justified withholding Secrets on the grounds that Mykronos must
never read repo secrets. That goal survives, guaranteed by GitHub rather than
by the grant: the Secrets API never returns a value to any caller.

Both failures would have surfaced late — after the App was registered and
installed by repo owners, at per-repo PR-commit time — and re-registering a
permission set forces every installation to re-consent. Hence the smoke test
now gating Phase 1 (spec 02 §8).

Also added spec 12 §6.1, stating the App key's blast radius plainly: the key
can write workflows into every onboarded repo, and code in CI can read that
repo's secrets, so the indirect path to secrets exists even though the API
path does not. Inherent to any tool that installs CI workflows elsewhere, but
understating it made §2's key handling read as bureaucratic.

---

## D-009 — One ingestion token per repo, with capability grants

**Status:** Decided, spec updated. **Supersedes part of D-004.**
**Spec:** [05 §4](../specs/05-datalake.md), [03 §5](../specs/03-workflow-installer.md), [12 §4](../specs/12-security-and-secrets-management.md)

One token per repo, carrying server-side capability grants, instead of one
token per `(repo, capability)` pair.

**Why:** the per-capability boundary was not real. GitHub Actions repository
secrets are readable by every workflow in the repo, so a compromised runner
already holds all of that repo's tokens regardless of which workflow each was
provisioned for. The repo is the smallest boundary GitHub enforces. The split
cost a tenth of each customer repo's 100-secret budget and put 2,000 secrets
on independent 90-day clocks at 200 repos, for containment that did not exist.

Revocation gets *stronger*: dropping a registry grant is local, immediate and
cannot partially apply, where deleting a GitHub secret is an API call that can
fail and leave a live credential behind.

**Correction to earlier analysis.** I previously characterised the rotation
load as "~22 rotation PRs/day." That was wrong — rotation updates a secret
through the Secrets API and opens no PRs at all. The real costs are the ones
above, plus the rotation race the spec omitted entirely (below). The
conclusion holds; the stated reason for it was partly incorrect.

**Rotation overlap.** A job reads the secret when it starts and may post
findings many minutes later, so a naive swap `401`s runs already in flight.
Rotation is now dual-validity: both tokens accepted for a configurable window
(default 24h), then the superseded hash is purged.

**Code impact, not yet applied.** Phase 0 infers `capability` from the token
scope (D-004). With one token spanning capabilities that no longer works:
`FindingBatch` needs an explicit `capability`, validated against the grant
set, and `TokenRegistry` needs grants plus superseded-token handling. Repo
attribution stays structural — there is still no request field naming a repo.
Tracked as the first task of Phase 1.

---

## D-010 — Operational state lives in SQLite, not the data lake

**Status:** Decided, spec amended
**Spec:** [01 §3](../specs/01-architecture.md)

Spec 01 §3 names DuckDB + Parquet for the data lake but never says where
*operational* state lives — `RepoOnboarding`, `CapabilityConfig`, ingestion
tokens, the audit log. A gap, not a contradiction.

These are small, transactional, frequently-updated rows with foreign keys and
uniqueness constraints. DuckDB is an OLAP engine: single-writer, columnar,
tuned for scans. Row-level updates there would also land in the path of the
compaction job. So: SQLite through SQLAlchemy, in `mykronos.db`.

Same local-first argument as the lake, and the same upgrade path — everything
goes through SQLAlchemy, so Postgres is a URL change.

**Spec follow-up:** ✅ landed. Spec 01 §3's tech-stack table now carries an
"Operational store" row, so the next reader does not have to infer it from the
code.

---

## D-011 — `repo_full_name` becomes `asset_id`, when the second asset type arrives

**Status:** Decided, spec written, **migration not yet applied**
**Spec:** [14 §5](../specs/14-network-scanning.md), [05 §3](../specs/05-datalake.md)

Network scanning (spec 14) examines running infrastructure, not a codebase, so
it is the first capability whose findings have no repository. `Finding` gains
`asset_type` (`repo` | `network`) and `asset_id`, and `repo_full_name` is
retired rather than kept alongside — two columns meaning the same thing is how
a data model rots.

Rejected: registering networks as pseudo-repos so `repo_full_name` could hold
`network/home-lab`. Zero migration, and that is its only merit. It leaves the
column storing your network called `repo_full_name` forever, makes every
repo-scoped query silently match networks, and makes D-009's token scoping
incoherent.

**Timing.** Nothing needs this until the network capability is built. The
rename touches the finding schema, compaction, the ingestion API and the token
grant model, and its cost grows with the codebase — so it is the *first* task
of whichever phase builds spec 14, not something deferred inside it.

Doing it now would be cheaper in isolation but would stall Phase 1 for a
capability with no consumers yet. Doing it after Phase 4 would be materially
more expensive. The trigger is spec 14 entering a phase, whenever that is.

---

## D-012 — Adapters return `FindingSubmission`, and live in the package

**Status:** Decided, spec amended
**Spec:** [04 §4](../specs/04-scanner-workflows.md)

Two small departures from spec 04 §4, both in service of one thing: a single
definition of the finding schema.

**Return type.** The spec writes the adapter signature as
`normalize(...) -> list[Finding]`. A `Finding` (spec 05 §3) carries
server-assigned fields — `finding_id`, `status`, `first_seen_at` — that an
adapter must not supply and could not compute. Adapters return
`FindingSubmission`.

**Location.** The spec sketches a top-level `adapters/` directory. They live
in `backend/mykronos/adapters/` instead, and the composite action installs the
package in CI. A separate copy of `FindingSubmission` that could drift from
the server's is a worse trade than the directory layout.

**Spec follow-up:** ✅ landed. Spec 04 §4 now shows the `FindingSubmission`
return type, the package location, and why identity is the server's to assign.

---

## D-013 — Snippet capture is layered, and its degradation is reported

**Status:** Decided
**Spec:** [05 §5](../specs/05-datalake.md), [04 §4](../specs/04-scanner-workflows.md)

D-001 made `finding_id` depend on the code snippet. That only pays off if
adapters actually supply one, so capture tries four tiers in order of
reliability: SARIF `contextRegion.snippet`, SARIF `region.snippet`, reading
the file from the working tree, then nothing.

The fourth tier is the failure D-001 exists to prevent, and the important
design choice is that it is **counted and reported** in the step summary
rather than silently accepted. A run that quietly fell back to positional
identity would otherwise only become visible weeks later as an unexplained
break in the trend line — by which time `first_seen_at` is already destroyed
for those findings.

Two supporting decisions:

- **Symbol inference is a heuristic, not a parser.** It scans backwards for a
  declaration. Being occasionally wrong is acceptable because `symbol` is one
  input among several and only disambiguates identical snippets in one file.
  What matters is that it is *deterministic* — a consistently-wrong symbol
  still yields a stable fingerprint; an inconsistent one would not.
- **Reads are confined to the workspace.** A SARIF result naming
  `../../../../etc/passwd` is refused rather than pulling host files into
  stored, displayed finding records.

---

## D-014 — Absence reconciliation writes to the lake, and why that is not a §9 violation

**Status:** Decided
**Spec:** [05 §5, §9](../specs/05-datalake.md)

Spec 05 §9 says no component other than the Ingestion API writes to the
Parquet partitions. The absence reconciler writes: it flips `open` findings to
`fixed` once two consecutive qualifying scans have failed to report them.

The rule exists so that all *ingestion* passes through one validating,
deduplicating path. This is not ingestion — it is a derived state transition
that belongs to the lake, which is why it lives in `mykronos/lake/` beside
compaction rather than in a service that merely reads.

Routing it through the findings endpoint would be actively wrong. That path
means "I observed this again", and its upsert deliberately flips a `fixed`
finding back to `open` (spec 05 §5). Closing a finding by posting it as an
observation would immediately reopen it.

Two supporting decisions:

- **Only `success` and `no_applicable_targets` scans confirm an absence.** A
  failed or partially-failed scan reporting nothing is not evidence a finding
  is gone; counting it would close findings every time CI had a bad day.
- **Absence is derived, not counted.** Rather than an absence counter on each
  finding, a finding is absent if its `last_seen_scan_run_id` is not among the
  two most recent qualifying runs for its (repo, capability). No extra mutable
  state to keep correct, and it self-corrects if scans are backfilled.

Insufficient history is reported rather than silently skipped: "we have not
looked enough times yet" and "there is nothing to close" are different facts.

---

## D-015 — Token rotation tracks whether the secret actually landed

**Status:** Decided
**Spec:** [05 §4](../specs/05-datalake.md)

`IngestionToken.secret_synced` records whether a token's plaintext reached the
repo's Actions secret.

Without it there is a silent failure with a 24-hour fuse. Rotation creates the
new token and supersedes the old *before* writing the secret, so that a failed
write leaves the old token valid — that part is deliberate. But the new token
then has a fresh 90-day clock, so a due-date sweep never looks at it again,
nothing retries, and the repo's CI breaks the moment the old token's overlap
expires. The failure surfaces a day later, in someone else's repo, as an
unexplained 401.

The rotation job therefore sweeps `due_for_rotation() | unsynced_repos()`, so
a write that failed because of a transient GitHub error or a missing
permission is repaired on the next run rather than after 90 days.

One repo failing does not stop the sweep: an unreachable repo must not prevent
every other repo from rotating.

---

## D-016 — Dashboard aggregates are computed live, not materialized

**Status:** Decided, revisit on measurement
**Spec:** [10 §3, §6](../specs/10-jded-dashboard.md)

Spec 10 §3 calls for heavy aggregates pre-computed on a 15-minute schedule
into materialized DuckDB views, so that §6's budget — the portfolio view
loading in under two seconds for 200 repos — is met.

The live query already meets it with room to spare. Measured end to end
through the HTTP endpoint, including the DuckDB aggregate, the SQLite
onboarding join and JSON serialisation:

> **0.145s for 200 repos and 5,000 findings.** Budget: 2.000s.

Building a cache for that would add a staleness window, a refresh job, and a
second source of truth for numbers the dashboard claims are traceable to the
lake (spec 10 §6 requires exactly that traceability). All in exchange for
1.85 seconds nobody is waiting on.

So it is deferred — but on evidence, not by omission. The measurement is an
enforced test, `test_portfolio_endpoint_stays_within_budget`, which fails the
build if the live query ever outgrows the budget. At that point materialization
stops being premature and the test says so in its failure message.

What would change this: findings growing by an order of magnitude, trend
queries over long histories (spec 10 §2.3, Phase 7), or Oracle's portfolio
decisions joining in per-repo. Each is a reason to re-measure, not a reason to
build the cache now.

---

## D-017 — The lake and the operational database are joined in Python

**Status:** Decided
**Spec:** [10 §3](../specs/10-jded-dashboard.md)

A portfolio row needs finding aggregates from DuckDB and onboarding state from
SQLite (D-010). DuckDB can attach SQLite directly and do it in one query.

It is not worth it. The join is a few hundred rows against a few hundred rows,
and pulling in a DuckDB extension for that adds a dependency that can fail at
runtime, in a deployment, for reasons that have nothing to do with the
dashboard. The Python join is measured as part of the 0.145s above.

---

## D-018 — Finding contributions follow a curve, and the raw score is kept

**Status:** Decided, spec amended
**Spec:** [09 §5](../specs/09-oracle-risk-decision-engine.md) — closes open question 4

Spec 09 §5 weighted findings linearly — 40 points per critical, summed, then
clamped to 100. Three open criticals reached the clamp. So did three hundred.

Every vulnerable repo therefore scored exactly 100: the portfolio view could
not rank anything, the trend line was flat by construction, and `no_go`
stopped distinguishing "two aged criticals" from "a catastrophe". The
deliberately-vulnerable demo apps make this immediate rather than theoretical
— Juice Shop alone produces dozens of criticals.

Two changes:

**A curve per severity band.** `weight × log2(1 + count)`, so criticals score
40 / 63 / 80 / 93 for 1 / 2 / 3 / 4. Strictly increasing, so ranking is
preserved, but flattening — the gap between "a few" and "some" matters more
than between "many" and "very many", which is how a person triages.

**The unclamped total is recorded.** `inputs_snapshot.totals.raw_score` keeps
the pre-clamp value, so two repos that both display 100 can still be ordered.
Without it every repo past the ceiling ties and sorting by risk silently stops
working.

**What this does not do.** The displayed score still clamps, and a genuinely
bad repo still shows 100 — that is correct, and the thresholds are doing their
job. What changed is that 100 is now reached by repos that deserve it rather
than by any repo with three findings, and that ranking survives the ceiling.

**Spec follow-up:** ✅ landed. Spec 09 §5 now carries the curve, the reason
for it, and the `raw_score` rule, replacing the superseded linear arithmetic.

---

## D-019 — A decision is immutable; re-evaluating creates a new one

**Status:** Decided
**Spec:** [09 §10](../specs/09-oracle-risk-decision-engine.md)

`risk_decisions` upserts only `human_override` and `github_check_run_id`.
Everything else — score, recommendation, snapshot, reasoning, policy version —
is write-once.

Spec 09 §10 requires a past decision to stay reproducible after a policy
change. That only holds if the row is not rewritten: a decision that quietly
re-scored under a new policy would make the audit trail a record of the
present rather than of what was decided at the time. Re-evaluating the same
commit produces a *new* decision row, and the history shows both.

The two mutable fields are the exceptions that prove it. An override is a
human acting on the decision that was made, and the check run id is
bookkeeping about where it was published — neither changes what was decided.

`gate_outcome` later joined them (D-021), on the same reasoning: what happened
to the pull request is not part of the decision.

---

## D-020 — Compaction must not collapse sparse patches

**Status:** Decided
**Spec:** [05 §9](../specs/05-datalake.md)

`_stage_incoming` collapses duplicate keys within a batch last-write-wins
before the upsert runs. That is right for tables whose upsert overwrites its
columns, and wrong for columns that arrive on an otherwise-empty row meaning
"set this one field, leave the rest alone".

Found by a failing test, not by inspection: overriding a risk decision and
then merging its pull request inside one five-minute compaction window
silently lost the override. The patch row for `gate_outcome` was newer, so the
collapse discarded the `human_override` row entirely and the upsert's
`coalesce` never saw it. Nothing errored. The override simply was not there
afterwards — the worst shape a data bug can take in an audit trail.

`PATCH_COLUMNS` now names those columns per table, and the collapse takes the
newest *non-null* value for them (`first_value(... IGNORE NULLS)` over the
whole partition) instead of the newest row. Both are declared in
`lake/tables.py` next to the upsert they belong to, so adding a third partial
update means adding it to one list rather than rediscovering this.

The window is five minutes, so any two human-or-webhook actions on the same
decision within five minutes hit this. It was reachable from day one of the
override endpoint existing.

---

## D-021 — Advisory mode is the measurement, so record the outcome

**Status:** Decided
**Spec:** [09 §6](../specs/09-oracle-risk-decision-engine.md)
**Resolves:** open question 5

Spec 09 §6 makes Oracle advisory by default but gives no path to ever turning
blocking on. "The tool has been running a while" is not evidence, and neither
is a low false-positive rate — the question is not whether the findings are
real, it is whether stopping those merges would have been worth what it cost.

Advisory mode is already the natural experiment for this. Every `no_go` that
merged anyway is a merge blocking mode *would* have stopped. So
`risk_decisions.gate_outcome` records what actually happened to the pull
request, set from the `pull_request.closed` webhook against the most recent
`pr_gate` decision for that PR — earlier ones were superseded by later pushes
and were never the standing verdict when the merge button was pressed.

`GET /api/oracle/shadow-mode` reports `would_have_blocked` alongside
`would_have_blocked_and_overridden`, deliberately in the same table: an
override is a human who looked at the `no_go`, wrote down why it was
acceptable, and shipped. A report that counted only the catches would be an
argument dressed as a measurement.

What it does not claim: whether blocking those merges would have been
*correct*. That needs the incident record for them, which lives in Phase 5's
Knowledge Store. This is the denominator, and it starts accumulating from the
first decision rather than from the day someone asks the question.

---

## D-022 — Aegis scores a pull request, never a person

**Status:** Decided, spec amended
**Spec:** [06 §9](../specs/06-aegis-integration.md), [12 §5.1](../specs/12-security-and-secrets-management.md)

Every other capability in Mykronos scores code. Aegis attaches an
`insider_risk_score` to a named GitHub login, which makes its rows personal
data and makes a growing table of them a dossier on your colleagues whatever
the intent behind it. Spec 06 said nothing about this, and spec 12 §5 opened by
claiming the platform processes tool output rather than application data —
true of everything except this.

Six things follow, all of them enforced rather than documented:

**`author_login` is required.** This reads backwards until you work it
through: omitting the author does not de-identify the row, because repo plus
pull-request number identifies it trivially. It only makes the row unauditable
and undeletable. Recording it is what lets a deletion request actually be
honoured, and what lets somebody challenged by a score see what was said about
them.

**Detail is admin-only at the query layer.** `author_login` and
`signal_breakdown` are not selected for a viewer, not hidden in the UI — the
same rule as raw tool output, for a different reason, which is why
`may_see_insider_risk` is a separate property from `may_see_raw_output`.
Collapsing them would make the next role change silently alter both. Viewers
keep the verdict per pull request, which anyone with repo access already sees
on the Check Run; withholding that too would be theatre.

**Retention is a job, not a sentence.** Rows are deleted after
`retention_days` (default 90) by a daily sweep that rewrites the Parquet
partitions. A real delete, not a tombstone column: a flag on a row still in the
file would not honour a deletion request, it would only stop the dashboard
showing what the system holds. Emptied partitions have their directories
removed, because an empty file in a dated directory still announces the day
somebody was assessed. Repos with no config get the default — the absence of a
setting is not consent to keep the data forever — and so do rows whose repo was
offboarded, or deletion would depend on a record that no longer exists.

**Nothing aggregates.** Oracle consults insider risk only for a pull-request
gate, and only for *that* pull request. Reaching for "the worst recent score in
this repo" would carry one contributor's signal into an unrelated colleague's
decision. There is no per-author endpoint, no contributor ranking, no per-person
trend, and a test asserts no such route exists — if someone adds one, that test
is where the conversation should happen.

**No single heuristic can block.** Signals are capped per key and the two
largest caps sum to less than the default block threshold, so a block always
needs at least three independent signals agreeing. A heuristic that fires
wrongly costs a review, not a merge.

**The framing is part of the design.** The Check Run says "this PR touches auth
config", not "this author is risky", and deliberately does not print the
author's login next to the score — everyone can already see who opened the pull
request, and repeating it beside a risk number is what turns a review prompt
into a label. The dashboard leads every row with the pull request and carries
the author as a field beneath it. Same data, and the arrangement is the
difference between a review prompt and a file on someone.

---

## D-023 — AI-authorship classification is off by default

**Status:** Decided, spec amended
**Spec:** [06 §2, §5](../specs/06-aegis-integration.md), [12 §5.2](../specs/12-security-and-secrets-management.md)

`ai_classifier_url` defaults to null, which disables the signal entirely.

It is the only path in the whole platform that causes repository content to
leave the runner: every scanner runs inside the customer's own Actions runner
and sends Mykronos findings, never source. There is deliberately no default
endpoint and there must never be one — a default would mean a deployment that
changed no configuration was shipping its code to a third party, which is
precisely the decision an operator has to make deliberately.

With the URL unset, `ai_authorship_flag` is null and the breakdown says which of
the two nulls applies: nothing configured, versus configured and unreachable.
Both mean "we did not look"; only one is a fault. The runner-side scorer always
reports null, never false, because a local heuristic cannot stand in for
classification and reporting false would claim "we checked, it is human".

---

## D-024 — Runner-side collectors report observations, not scores

**Status:** Decided
**Spec:** [06 §4](../specs/06-aegis-integration.md), [07 §5, §7](../specs/07-atlas-integration.md)

`mykronos.aegis_signals` and `mykronos.atlas_counts` run on the runner and emit
*what they saw* — which globs matched, how many criticals in which ecosystem.
The weights, caps, thresholds and formulas stay in the platform.

Spec 07 §7 makes reproducibility an acceptance criterion, and a score the runner
calculates drifts the moment two repos are on different versions of the action.
It also means changing how risk is weighted is a platform deploy rather than a
template resync across every onboarded repo, and that a repo cannot quietly run
a forked scorer with its own thresholds. `/api/ingest/atlas` rejects a submitted
`trust_score` with a 422 rather than ignoring it, so the boundary is enforced
rather than assumed.

The cost is that adapters, collectors and server-side scoring all live in one
package — the same trade spec 04 §4 already made, for the same reason: one
definition of the schema beats a tidier directory layout.

---

## D-025 — `fnmatch` alone cannot express "at any depth"

**Status:** Decided
**Spec:** [06 §5](../specs/06-aegis-integration.md)

Spec 06 §5's default sensitive-path list includes `**/.github/workflows/**`.
Under plain `fnmatch` that does **not** match `.github/workflows/ci.yml`,
because the leading `**/` requires a literal slash before `.github` and git
reports repo-relative paths with no leading slash.

So the single most sensitive path in any repository — the file that defines what
CI runs, and the canonical example the default list exists to catch — silently
failed to match. Same for `secrets.yml`, `auth/` and `iam/` at the top level.
Nothing errored; the signal simply never fired.

`matches_glob` treats a leading `**/` and a trailing `/**` as optional, which is
what "at any depth, including the root" actually means. Found by a test written
to check the *rationale text*, not the matching — which is the argument for
writing the test that looks redundant.

---

## D-026 — A learning is a pattern, not an event

**Status:** Decided, spec amended
**Spec:** [11 §3, §5](../specs/11-knowledge-rag-learning.md)

`KnowledgeEntry.entry_id` is derived from tier + repo + source_type +
`subject`, where `subject` is the thing that recurs: the `rule_id` for a
dismissal, the overturned recommendation for an override. A second dismissal
of the same rule *updates* the entry — resetting decay, incrementing
`observations`, appending the reason — rather than appending a row.

Spec 11 §3 specified a random UUID while §5 described reconfirmation as
resetting decay. Those cannot both be true: with a random id, every dismissal
is a new entry that has never been reconfirmed, so confidence never rises,
decay never resets, and the model is decorative. Third time this defect has
appeared in a spec (D-002, spec 06 §3, spec 07 §3), and the pattern is now
clear enough to state as a rule: **any record that can legitimately be
produced twice needs a natural key, not a UUID.**

What recurs is also what a policy change would address. "We keep overriding
no_go on this repo" is actionable; "we overrode decision 4f2a once" is not.

---

## D-027 — Reasons gate everything, and are worth more than counts

**Status:** Decided
**Spec:** [11 §4, §6.1](../specs/11-knowledge-rag-learning.md)

A dismissal with no written reason is recorded and deliberately made useless.
It starts at lower confidence, a reconfirmation without a reason resets the
decay clock but does not raise confidence, and it can never support dampening
or promotion.

Spec 11 §4 asks for this; the reason it matters is that the alternative is a
system driven by click counts, in which the loudest and most-dismissed rule is
quietened fastest whether or not anybody could say what was wrong with it.

Two consequences worth naming:

- **`accepted_risk` teaches nothing about the rule.** It says the finding is
  real and we are living with it — a statement about appetite, not about
  detection quality. Only `false_positive` produces a learning. Dampening a
  rule because somebody accepted its risk would be exactly backwards.
- **Confidence rises with diminishing returns and never reaches 1.0.** The
  third dismissal tells you much less than the second, and nothing should
  reach certainty from clicks alone.

Reconfirmation boosts from the *decayed* value, not the stored one. Rebuilding
from the stored figure would let an entry nobody has touched in two years jump
straight back to where it was, which would make decay decorative.

---

## D-028 — Dampening applies inside the curve, not to the band

**Status:** Decided
**Spec:** [11 §6.1](../specs/11-knowledge-rag-learning.md), [09 §5](../specs/09-oracle-risk-decision-engine.md)

Spec 09 §5 says a dampened rule's "severity weight is multiplied by
(1 - dampening_factor)". Taken literally against D-018's curve, that would
mean halving the whole severity band — and only *some* of a band's findings
come from the dampened rule. Four criticals with one from a dismissed-often
rule would score as though all four were suspect.

So the factor applies to the count *inside* the curve: the band contributes
`weight × log2(1 + undampened + dampened × (1 - factor))`. Four criticals with
one dampened score as 3.5 findings, the real ones keep their full weight, and
the band's `detail` string says so in words.

The evidence travels with the decision — rate, counts, observation count and
the human reasons — because a weight that quietly halved is precisely the
hidden input spec 09 exists to prevent.

Dampening is also strictly an adjustment on top of a correct score. No
Knowledge Store, an unreadable one, or a failed query all produce *undampened*
scores rather than no scores (spec 11 §6).

---

## D-029 — `restricted` withholds the prose, not the observation

**Status:** Decided
**Spec:** [11 §2, §3](../specs/11-knowledge-rag-learning.md)

Captured dismissals default to `sensitivity: restricted`, because the reason
is free text somebody typed about their own codebase and assuming it is safe
to circulate is the wrong default.

The first implementation then excluded restricted entries from promotion
entirely, per a literal reading of spec 11 §2. That made promotion **dead on
arrival**: every captured entry is restricted by default, so nothing was ever
a candidate, and the feature appeared to work while doing nothing. Caught by a
test that expected a candidate and got an empty list.

The split that actually matches §3 is finer than the spec's wording suggests.
"Rule X was dismissed in repositories A and B" is an observation about a
*rule*, and it is what generalises. "Because our payments vendor ships this
pattern in every module" is the confidential part. A restricted entry
therefore counts toward the recurrence and has its reasons withheld — with the
number of withheld reasons *reported*, because a reviewer weighing thin
evidence is entitled to know that some of it is not shown. A proposal where
every reason is withheld says so and tells the reviewer to ask the
repositories involved.

---

## D-030 — Retrieval works with no embedding backend

**Status:** Decided, spec amended
**Spec:** [11 §8](../specs/11-knowledge-rag-learning.md), [12 §5.2](../specs/12-security-and-secrets-management.md)

The default retriever is lexical — overlap on content words after stripping
the template vocabulary — and `embed_fn` upgrades it to semantic. Results
carry the mode that produced them.

Two reasons, both about defaults rather than about quality. A deployment with
no embedding gateway configured would otherwise have a learning loop that
silently did nothing, which is the same failure mode as a scanner that skips
without saying so (spec 01 §6). And embedding every dismissal reason means
sending it off-host, which is a decision an operator should make deliberately
— the same rule as Aegis's classifier (D-023).

Not TF-IDF, deliberately: the corpus is short, highly templated sentences,
where inverse document frequency mostly measures how the text was generated
rather than what it says. Overlap on content words is both more honest about
what it does and easier to explain when somebody asks why an entry was
retrieved.

A broken embedding backend falls back to lexical rather than failing, and
`retrieve_similar` returns `[]` on any error — spec 11 §6 makes graceful
degradation a requirement, because a triage step that dies over a corrupt JSON
file is worse than one that proceeds without the extra context.

---

## D-031 — "Never merges" is enforced by an absent method, not a permission

**Status:** Decided, spec amended
**Spec:** [08 §3](../specs/08-patchwork-integration.md)

Spec 08 §3 originally said Patchwork "has no merge permission" and that the
App "should not request merge rights". Neither is achievable. Merging a pull
request through the API needs `contents: write`, which the App already holds
and cannot give up — it is what lets the Workflow Installer commit workflow
files at all (D-008). Any deployment where Patchwork can open a pull request
is one where the App could technically merge one.

Stating otherwise put a guarantee in the spec that nothing was enforcing,
which is worse than no guarantee: somebody reading it would have believed the
platform was constrained in a way it was not.

The constraint now lives where it can be checked. `GitHubClient` exposes no
merge operation, neither implementation has one, and three tests fail if that
changes — including one asserting `draft=True` is written at the call site
rather than threaded through from configuration. Adding merge support means
editing a shared interface with failing tests attached, which is a visible,
reviewable act.

Same posture as spec 14 §4's authorization boundaries: where a platform
permission cannot express the constraint, the constraint lives in code with a
test that fails if it is removed.

---

## D-032 — Deterministic fixers are the product, not the fallback

**Status:** Decided, spec amended
**Spec:** [08 §2](../specs/08-patchwork-integration.md)

v1 ships pattern-based fixers for the classes where the correct change is
mechanical, and requires a configured endpoint for anything else.

The bar for a deterministic fixer is stated in the module and is deliberately
high: it belongs there only if the change is *provably* the right shape given
the finding, with no judgement about the surrounding code. Pinning a
dependency to a patched version is that. Parameterising a query is not — it
needs to understand what the query does, and getting it subtly wrong produces
a diff that looks right and breaks at runtime.

Both shipped fixers refuse more than they accept, and the refusals are the
interesting part:

- The pinner leaves `urllib3>=2.0` alone. Narrowing a range to an exact pin is
  a change to the project's dependency *policy*, not a security fix.
- The secret fixer refuses anything more structured than a plain assignment. A
  regex rewriting arbitrary code around a credential turns a leaked credential
  into a leaked credential *and* a broken build.
- Its first review note is "rotate the credential first". Removing a literal
  from the working tree removes it from nothing else, and a fix that made a
  repository look clean while the credential stayed valid would be worse than
  no fix.

LLM generation needs `fix_generator_url` and is off when unset — same rule as
Aegis's classifier (D-023). Without it, findings outside the deterministic
classes reach `no_fix_available` with a rationale saying exactly that, which
is a true statement about the deployment rather than a claim about the
finding.

---

## D-033 — A detected combination suppresses the individual fixes

**Status:** Decided
**Spec:** [08 §2, §8](../specs/08-patchwork-integration.md)

Findings inside a toxic combination are not fixed in isolation. Two reasons,
and the first is the one that matters.

Fixing one half of an unauthenticated injectable endpoint **closes the finding
without closing the risk**, and leaves the code looking attended to. The
composite is the problem; addressing half of it is worse than addressing none,
because the remaining half no longer has a partner to make it visible.

The second is mechanical: two fixes touching the same request path produce two
draft pull requests that cannot both merge cleanly, which is spec 08 §8's
overlap case.

A finding belongs to at most one combination — first rule wins, in rule order
— because overlap would let one finding generate several draft pull requests,
which is the flooding backpressure exists to prevent arriving by another
route.

The built-in rule set is deliberately tiny. A large default set of speculative
combinations produces noise that discredits the real ones, and spec 08 §5
already allows admins to add their own.

---

## D-034 — Remediation in flight is a discount, and it expires

**Status:** Decided
**Spec:** [08 §9](../specs/08-patchwork-integration.md), [09 §5](../specs/09-oracle-risk-decision-engine.md)

A finding with an open Patchwork pull request counts for half. Not zero: a
repository with ten open auto-fixes is not a safe repository, it is a
repository with ten unmerged fixes. The discount says somebody is on it, which
is a statement about urgency rather than about risk.

Applied inside the curve like dampening (D-028), and capped at the undampened
remainder so a finding that is both dismissed-often and being fixed cannot be
discounted twice.

`human_edited` counts as in flight. A person took the draft and started working
on it, which is *more* evidence of remediation underway than an untouched one.

**The expiry is the half that is easy to miss.** When the pull request closes
— merged or abandoned — the discount stops. Without that, a closed-unmerged
auto-fix keeps lowering the repository's score forever, and the score looks
attended to when nobody attended to it. Both directions are tested; the
abandoned case is the important one.

---

## D-035 — A gate never waits for itself, and Oracle waits for Patchwork

**Status:** Decided
**Spec:** [08 §6](../specs/08-patchwork-integration.md), [09 §8](../specs/09-oracle-risk-decision-engine.md)

The installer's `gate_depends_on` list was built once and handed to every
template, which produced two silent faults the moment a second
`workflow_run`-triggered capability existed.

Patchwork's own trigger listed `Mykronos patchwork` — a workflow triggering on
its own completion. And Oracle and Patchwork both waited on the scanners, so
they raced: Oracle could score before the draft pull requests existed, and the
`remediation_in_flight` discount would be missing from exactly the decision a
reviewer was reading.

Neither produces an error. A `workflow_run` trigger naming a workflow that does
not exist simply never fires, and a race just gives the wrong answer sometimes.
That is why the fix comes with five unit tests over the helper rather than
relying on the rendered YAML looking right.

Gates now have an explicit order — Patchwork, then Oracle — and each waits for
every scanner plus every gate before it.

---

## D-036 — Patchwork's identity check fails closed

**Status:** Decided
**Spec:** [08 §3, §8](../specs/08-patchwork-integration.md)

Two behaviours decide whether a team keeps auto-remediation switched on, and
neither is about the quality of the fix.

**Never overwrite somebody's edit.** A `push` webhook on a `mykronos/fix-`
branch compares each commit's author against Patchwork's configured bot
logins. Any commit that is not ours flips `pr_status` to `human_edited`
permanently, and the pipeline skips that finding from then on — with no event
written, because the existing one already records that a person is on it and
overwriting it with a fresh assessment would lose that.

The `push` event is the only way to learn this. Pull-request events do not
fire for a plain push to an existing branch, so without the handler Patchwork
would keep regenerating over somebody's work — the single behaviour spec 08 §3
says it must never have.

**The identity check fails closed, and this is the interesting decision.**
With no bot login configured, *nothing* is recognised as Patchwork's, so every
fix branch reads as human-edited and refreshes stop. That looks like the
capability quietly breaking, and it is still right: the two mistakes are not
symmetric. Wrongly leaving a branch alone costs one unrefreshed fix. Wrongly
overwriting costs a colleague's commit and the team's willingness to let a bot
near their repositories again.

**Never leave a stale draft open.** A six-hourly sweep closes fixes whose
finding is no longer open — fixed, dismissed, or gone from the lake entirely —
with a comment saying why rather than vanishing. A queue of drafts nobody
needs is how the ones that matter stop being read.

`human_edited` branches are exempt from that sweep too. Somebody is working on
it, and the finding's status stops being Patchwork's business once a person
has taken the change over: they may have dismissed the finding precisely
because they are mid-fix.

One structural note: `BRANCH_PREFIX` moved from the pipeline to the
stewardship module. The pipeline creates these branches, but stewardship owns
the question "is that one ours", and the other arrangement is a circular
import.

---

## D-037 — The installer cannot participate in a repo's own process

**Status:** Known limitation, deliberate for now
**Spec:** [03 §4](../specs/03-workflow-installer.md), [02 §5](../specs/02-onboarding-and-github-app.md)

Onboarding four real repositories produced four pull requests. Three merged.
The fourth was refused by its own repository, and the refusal was correct.

`ToddGBenson/keel` runs a `pr-governance.yml` gate that hard-fails a pull
request unless the body carries a linked issue, an `## AI authorship`
declaration naming which parts were machine-authored, a `## Definition of
Done` checklist with at least one item engaged, a Conventional Commit title,
and either an approving review from a second identity or a committed
self-review artifact under `evidence/<issue>/g3/`. Its default branch sets
`enforce_admins: true`, so an administrator cannot merge past any of it.

The Workflow Installer writes its own pull request body (`_pr_body`) and knows
nothing about any of that. It cannot: it has never read the repository's
`PULL_REQUEST_TEMPLATE.md`, has no issue to link, and has no way to produce a
review artifact. So on a repo with real process, the installer opens a pull
request that cannot be merged, and nothing in the platform notices.

**The gap is Mykronos's, not keel's.** It would have been easy to read this
the other way round — a governance gate obstructing an automated improvement —
and the temptation is to widen the tool's permissions until the obstruction
goes away. That is the wrong direction. A repository that refuses a bot's pull
request on process grounds, and does not let the bot's operator override it
either, is a repository whose controls work. The platform should learn to
comply, not acquire a way to bypass.

**Two things were specifically not done.**

The AI-authorship section could have been added honestly, because the change
genuinely is machine-authored and saying so is exactly what the rule asks. The
Definition of Done could not: it is an attestation about testing and review
that only the person merging can make. Ticking those boxes to turn a check
green would be falsifying a compliance record from inside a compliance gate.
The check is not a formality standing between us and the real work; it *is*
the work it describes.

`enforce_admins` was also left alone. Relaxing it would have merged the pull
request in one call, and it is the single most valuable line in that
repository's configuration.

**What a fix looks like**, when it is worth building: render the repository's
`PULL_REQUEST_TEMPLATE.md` when one exists and fill the sections the installer
can answer truthfully, plus a per-repo configurable preamble for what it
cannot. That still leaves the linked issue and the review artifact, which are
human acts by design — so the honest ceiling is a pull request that fails on
two named items rather than five, with the remainder clearly the operator's.

Until then the platform's answer is that a repository can have requirements
the installer cannot meet, and the pull request waits for a person. That is a
worse product and a better outcome than the alternative.

One note for the demo, because it is easy to miss: keel requires AI-authorship
disclosure on every change, which is the same control Aegis implements as
`ai_disclosure_required` (spec 06 §2). The rule Mykronos ships for other
people's repositories is one its own pull requests failed to satisfy.

---

## D-038 — Three decisions the Concourse pipeline was waiting on

**Status:** Decided
**Spec:** [15 §2, §5, §6](../specs/15-concourse-pipeline.md)

Spec 15 shipped with three open questions rather than guesses. All three now
have answers, and two of them were answered by running the thing.

**What does deploy deploy to? This host, in Docker.** (CNC-10)

Mykronos runs today as bare processes: no Dockerfile anywhere, no restart
policy, no supervision. Over one working session that cost the backend being
restarted by hand six times, an orphaned `next dev` degrading for two days
until it was hunted down by PID -- the twenty-six-second page loads -- port
collisions with Docker Desktop and TheHub, and a manual rebind to 0.0.0.0
that a reboot forgets. TheHub already runs twelve containers on this host with
`restart: unless-stopped`.

So deploy means: build an image, push it, and bring the compose stack up
behind the tunnel that already fronts it. The alternative considered was the
NAS, and it was rejected for now because it moves the service away from the
tunnel and the backend that Concourse reaches by host IP, solving nothing that
is currently broken.

**Does Concourse duplicate what GitHub Actions already scans? Yes, and the
split is by purpose rather than by capability.** (CNC-9)

Actions keeps pull-request feedback, because it runs for contributors who
have no access to this Concourse instance and because the Workflow Installer's
whole model is that a repository carries its own security configuration.
Concourse owns the full pipeline: quality gate, security, Oracle, build,
deploy.

Where both scan the same commit the ingestion upsert makes the duplication
invisible, which is worse than harmless -- identical findings, doubled runner
time, and no way to tell which lane last reported. The rule is therefore that
a repository gets one lane or the other for a given capability, not both, and
TheHub is the current example: it has no Actions minutes, so Concourse scans
it and its workflows stay merged but inert.

**What happens when the NAS is unavailable? The pipeline fails.** (CNC-11)

Concourse's Postgres and MinIO both live there. A pipeline that cannot record
its results must not deploy anyway, which is the same reasoning as spec 05
§4's fail-fast probe in the capability workflows: better to stop in ten
seconds than to scan for twenty minutes and discover the results have nowhere
to go.

Concretely: the ingestion check is a gate, not a best-effort step, and the
`put` to MinIO is a pipeline step whose failure fails the build. Neither is
wrapped in a tolerant `|| true`. The whole session argues for that -- a
blanket `|| true` on the osv-scanner step is what hid a missing scanner
binary for the entire life of that lane.

---

## D-039 — This repository's GitHub Actions are removed, superseding half of D-038

**Status:** Decided
**Spec:** [16 §4](../specs/16-thehub-delivery-pipeline.md), [15 §10](../specs/15-concourse-pipeline.md)

D-038 split the two CI systems by purpose: Actions kept pull-request feedback,
Concourse owned the full pipeline. That rule is withdrawn for repositories this
operator owns. `.github/workflows/` is deleted and its function lives in
`deploy/concourse/pipelines/mykronos.yml`.

**Why the reasoning that created the rule also retires it.** The split only
pays for itself when both halves run. TheHub's half never runs — it has no
Actions minutes, which is the entire subject of spec 15 §2. Mykronos's half
did run, against the identical commits Concourse scanned, producing identical
findings that the ingestion upsert made indistinguishable. D-038 called that
"worse than harmless" in the same paragraph that kept it, on the grounds that
nothing yet ran the full capability set in Concourse. That is no longer true:
`frontend`, `sast` and `insider` were added, and Atlas evidence — the SBOM and
the trust score, which Concourse never reported at all — moved into
`dependencies` where Oracle can read it before it gates.

**What it costs, stated rather than discovered later.** Pull requests get no
checks from a system running on GitHub's infrastructure. Concourse polls a
branch; a fork's pull request is not scanned by it and must not be, because
spec 14 §4 and spec 15 §7 both refuse to run untrusted code on a worker inside
the LAN. For a single-operator repository that is acceptable and it is a real
regression, not a neutral one. The trigger to revisit is the first pull request
from somebody else, and the answer then is to restore the Actions lanes *for
pull requests only* rather than to widen what Concourse trusts.

**What is explicitly not removed.** `workflow-templates/` and
`actions/upload-results`. They are installed into other people's repositories
by the Workflow Installer and are the platform's product. "Remove the GitHub
Actions" and "remove the GitHub Actions integration" are one word apart and
opposite instructions; `.github/README.md` exists so the next person to look at
an empty directory finds that sentence.

---

## D-040 — A forced-command SSH key is how Concourse deploys TheHub

**Status:** SUPERSEDED by D-042 — this host has no SSH server, which was not
checked before the mechanism was specified. Kept because the reasoning about
*why not a Docker socket* still stands and D-042 depends on it.
**Spec:** [16 §7](../specs/16-thehub-delivery-pipeline.md)

TheHub's pipeline deploys to demo automatically and to production on a click.
Both go through `ssh` to this host with a key whose `authorized_keys` entry
pins one command and one environment. The client's command line is ignored by
sshd and arrives as `SSH_ORIGINAL_COMMAND`, out of which
`Invoke-TheHubDeploy.ps1` reads exactly one thing: a 40-character hexadecimal
commit SHA, validated against an anchored pattern before use.

**Why not the Docker socket.** D-038 and spec 15 §7 refuse it, and that refusal
still holds: a socket mounted into one task is a socket available to every task
in every pipeline, on a worker that sits inside the LAN. The objection was
never "deploys are dangerous", it was "that grant is unbounded".

**Why not Mykronos's registry-only handoff.** That is the right answer for
Mykronos, where a human runs `deploy.ps1` and the pipeline's job ends at the
registry. It is the wrong answer here, because a pipeline that waits for a
person at *both* environments is not a delivery pipeline — the demo deploy is
the step that makes DAST possible at all.

**What the grant actually is.** The ability to deploy a commit that is already
in the registry, to one environment. Not the ability to run a command. The demo
key cannot reach production because sshd starts a different process for it, not
because the script checked an argument — separation enforced against the key
that authenticated is stronger than separation the caller opts into. Spec 15 §6
asks for deploy credentials scoped to the deploy job; this scopes them to the
environment.

`StrictHostKeyChecking` stays on with a pinned `known_hosts`, because a deploy
job that accepts any host key is a deploy job that can be pointed at a
different host. And the script records the SHA each environment is on before it
starts, so a stack that does not become healthy is rolled back rather than left
half-landed — a deploy that half-lands and reports success is worse than one
that fails, because DAST then probes whatever happens to be up.

---

## D-041 — Semgrep replaces CodeQL in Concourse, and the finding sets differ

**Status:** Decided
**Spec:** [16 §5](../specs/16-thehub-delivery-pipeline.md), [04 §3](../specs/04-scanner-workflows.md)

The `sast` capability defaults to CodeQL. Both Concourse pipelines run Semgrep
instead, and pass `--tool semgrep` explicitly rather than letting the
capability default decide.

**Why.** CodeQL's CLI needs a multi-hundred-megabyte bundle per language on
every run, and its licence covers Actions on public repositories and GitHub
Advanced Security customers — not a self-hosted worker scanning a private
repository. Semgrep is already a registered `sast` tool (spec 04 §3 names it as
the secondary), emits SARIF, and installs from PyPI.

**The explicit `--tool` matters more than it looks.** Without it the lake would
record `codeql` for findings Semgrep produced, and the dashboard would imply
coverage from an analyser that never ran. This is the same class of mistake as
the workflow templates defaulting `tool` to the capability name, which produced
`tool: secrets` and an upload that failed at the last step.

**Expect the finding set to move on the cutover.** Semgrep's rule packs are
pattern-based; CodeQL's `security-extended` includes dataflow queries the free
Semgrep rules do not reproduce. Findings will appear and disappear, and that is
a tool change rather than a change in the code's security. Worth writing down
because the alternative reading — that a deploy introduced or fixed a dozen
issues — is the one the dashboard suggests.

`--config auto` is deliberately not used: it reports the repository to
semgrep.dev, which is the class of thing spec 12 §5.2 makes opt-in. Named rule
packs download rules; the source stays on the worker.

---

## D-042 — The deploy instruction is a pointer the host pulls, superseding D-040

**Status:** Decided, supersedes [D-040](#d-040--a-forced-command-ssh-key-is-how-concourse-deploys-thehub)
**Spec:** [16 §7](../specs/16-thehub-delivery-pipeline.md)

D-040 chose a forced-command SSH key per environment. It was never run,
because the host has no SSH server: `Get-Service sshd` returns nothing and only
the disabled `ssh-agent` exists. The decision was made against an assumed
capability rather than a checked one.

**Why not just install sshd.** It would work. It also means standing up a
listening service on the machine spec 15 §7 is already uneasy about — a worker
inside the LAN — for the sole purpose of receiving deploy instructions. The
installation is a bigger change to this host's attack surface than the feature
it unlocks, and it needs an administrator, which makes it a change nobody can
reverse by editing a file in this repository.

**Why not TheHub's existing docker-socket-proxy.** This was the reflex answer —
it is already running, and a filtered socket sounds narrower than a raw one.
Checking what it is actually configured for killed the idea: `POST=0`,
`ALLOW_RESTARTS=0`, `ALLOW_START=0`, `ALLOW_STOP=0`. It is read-only, serving
uptime monitoring. Making it deploy means `POST=1` plus `CONTAINERS=1`, and
that combination permits `/containers/create` — which permits a container with
a host bind mount, which is root on the host. It would have been a raw socket
wearing a proxy's name. It is also on TheHub's compose network with no
published port, so Concourse cannot reach it without a second change.

**What was built instead.** The deploy job writes a commit SHA to
`<env>.requested` in MinIO. A Scheduled Task on the host polls, pulls that
image by SHA, deploys, and writes `<env>.deployed`. Concourse waits for its own
SHA to come back before reporting success, so `passed: [deploy-demo]` still
means demo is serving this commit rather than that a request was filed.

It is the one-way handoff D-038 already chose for the artifact, applied to the
instruction as well: nothing Concourse can do restarts a service, and the host
opens no port to be told to. The pipeline's entire vocabulary is one
hexadecimal string in one object — a compromised task can ask for a different
already-built image and cannot ask for anything else, because there is no other
field to say it in.

**The cost, which is real.** Deploys are as slow as the poll interval, and the
host-side task becomes a component that can itself be down. SSH failed loudly
at connect time; a stalled poller looks like a slow deploy. The deploy job
therefore times out with the Scheduled Task named in the message, so the error
points at the thing to restart.

**The general lesson.** D-040 specified a mechanism against an assumed
capability. Ten seconds of `Get-Service` would have caught it before the spec
was written, the script was written, and the key-provisioning helper was
written. Check the substrate before designing against it.

---

## D-043 — `fly set-pipeline` printed every credential it interpolated

**Status:** Decided, fixed
**Spec:** [15 §6](../specs/15-concourse-pipeline.md), [16 §11](../specs/16-thehub-delivery-pipeline.md)

Running `set-pipeline.ps1` scrolled the ingestion token, the Oracle gate token
and every other `((var))` across the terminal in plaintext. `fly set-pipeline`
prints the *resolved* configuration as a diff, and `--load-vars-from`
substitutes the variables before that diff is produced. `--non-interactive`
suppresses the prompt, not the output.

Every acceptance criterion about this was satisfied and none of them covered
it: spec 15 §6 and spec 16 §11 say no credential appears in pipeline YAML, in
build logs, or in an image layer. The vars file was written to a temp path and
deleted in a `finally`. The pipeline file holds no secrets. And the one place
they were all visible at once — set-pipeline's own stdout, in the scrollback of
whoever ran it, and in any recording of that session — was named in none of
them.

**Fixed** by piping the call to `Out-Null` in all three set-pipeline scripts.
Errors still surface: fly writes those to stderr and `$LASTEXITCODE` is checked
regardless.

**This is a mitigation, not the fix.** The real answer is spec 15 §6's
credential manager, so that the configuration never contains a secret to print.
Until then the property holds only because one line suppresses output, which is
one careless edit from regressing.

**Rotate anything that was displayed.** A credential that has been on a screen
is a credential that has been disclosed, and the cost of rotating an ingestion
token here is one command.

---

## D-044 — Rotation is not revocation, and the CLI was writing to a database nobody serves

**Status:** Decided, fixed
**Spec:** [12 §2](../specs/12-security-and-secrets-management.md), [15 §6](../specs/15-concourse-pipeline.md)

D-043 said a credential that has been on a screen is disclosed and should be
rotated. It was rotated. It kept working for the rest of the day, and finding
out why turned up two independent defects that each looked like the other's
symptom.

**1. The CLI and the running backend use different databases.** The host CLI
resolves `sqlite:///mykronos.db` relative to `backend/`. The container resolves
`sqlite:////data/mykronos.db` inside the `mykronos-data` volume. Since D-038
moved the platform into containers, every `mykronos` command run from a shell
has been writing to a database nothing serves.

The rotations landed there. So did the `dast`, `cloud` and `oracle` grants for
TheHub — which is why that pipeline's new lanes were about to 403 at the upload
step after running perfectly, and why the *old* token kept answering 200 while
the new one in `.env` answered 401. The symptom that finally exposed it was the
pipeline breaking the moment `.env` was updated to match the unserved database.

**2. `rotate` is graceful by design, which is exactly wrong for a leak.** It
supersedes the old token and keeps it valid for `token_overlap_hours` (24), so
that a job which read the secret a second earlier still finishes — spec 05 §4,
and correct for a *scheduled* swap. For a disclosed credential the entire
requirement is that it stops working, and the command with "rotate" in its name
was reached for without anybody re-reading what it promised.

`rotate(..., immediate=True)` and `rotate-token --immediate` now expire the old
value at once. The success message branches, because the old one cheerfully
printed "the previous token stays valid for 24h" while somebody was containing
an incident.

**The first attempt at that fix did not work either, and the reason is worth
keeping.** `immediate` expired only the *active* token. The leaked one had
already been superseded by an earlier rotation, so it sat inside its overlap
untouched while the fix expired its replacement. Containment means every
previously issued value, not the one that happens to be current.
`test_immediate_expires_tokens_superseded_earlier` is that bug.

**What this changes operationally.** Any `mykronos` CLI command that mutates
state must run inside the container — `docker exec mykronos-backend python -m
mykronos.cli ...` — until the CLI resolves the same database the API does.
Running it on the host is not an error and produces no warning; it just edits a
different system. That is the next thing to fix, and it is a bigger change than
this entry: the host path is genuinely useful before the stack is up.

---

## D-045 — The Oracle gate can deadlock on the images it gates

**Status:** Decided, implemented in 566f571
**Spec:** [15 §3](../specs/15-concourse-pipeline.md), [09 §6](../specs/09-oracle-risk-decision-engine.md)

The `containers` lane scans the images the pipeline publishes. It found 5
criticals and 46 highs in them, Oracle refused the next build at no_go, and
the images were duly hardened — curl removed from both, npm removed from the
frontend, dev dependencies no longer shipped.

Those fixes could not ship. `build` is gated on Oracle, `publish` follows
`build`, and `containers` scans what `publish` pushed. So the findings that
block the gate are findings in an artifact the gate prevents replacing. There
is no path from "vulnerability found" to "fix published" through the pipeline
alone, and nothing in it says so — the job simply fails, with a reason that
looks like ordinary risk rather than a cycle.

It was broken by hand: the hardened images were built on the host, pushed to
the registry, and the `containers` job triggered against them, after which the
pipeline resumed normally. That works and should not be necessary, and an
operator stepping outside the pipeline to unblock the pipeline is worth
writing down rather than repeating.

**Decision as implemented: the gate moves after publish, not the scan before
it.** This entry first decided to move the container scan between `build` and
`publish` so the gate judged the candidate. What shipped in 566f571 is the
stronger version of the same idea: `build` no longer waits on Oracle at all,
and `oracle-gate` now waits on `containers`.

    before                          after
    oracle-gate <- code scans       build       <- quality gate
    build       <- oracle-gate      containers  <- publish
    publish     <- build            oracle-gate <- ... + containers

The reasoning that settled it: gating `build` bought nothing. A build is a
file, and publishing is a tag that nothing deploys on its own — the deploy is
`deploy.ps1`, run by a person on the host (D-038). So the gate was refusing to
produce an artifact that could not hurt anyone, at the cost of never being
able to improve one. Moving it after publish means Oracle sees container
findings for the commit in front of it rather than the one before, and the
thing it actually guards — a person choosing to deploy — is unchanged.

TheHub's pipeline already put build before the gate (spec 16 §3) for the
related reason that you cannot scan an image you have not built, so this makes
one rule out of two either way.

The narrower original — scan between build and publish — also works and is
recorded because it may be the right answer once something deploys
automatically. At that point publishing stops being inert and the tag becomes
the thing worth gating.

**Rejected: exempt `containers` findings from the gate.** The argument is that
an unpublished image cannot be exploited, so the gate should judge the deploy
instead. It is true and it is the wrong trade: it means the one capability
that scans the artifact this pipeline actually produces is the one capability
the gate ignores.

**Rejected: let the operator push a fixed image whenever this happens.** That
is what was done here, and it is a workaround, not a design. It puts an
artifact in the registry that no pipeline built, which is precisely the
provenance the SBOM and the wheel-per-commit exist to establish.

## D-046 — The platform had ten capabilities and the pipelines ran eight

**Status:** Decided, implemented
**Spec:** [04 §3](../specs/04-scanner-workflows.md), [15 §3](../specs/15-concourse-pipeline.md), [16 §5](../specs/16-thehub-delivery-pipeline.md)

`capabilities.py` registers ten capabilities and names checkov as the `iac`
scanner. Neither pipeline ran it. Nothing was red about this — the dashboard
column for `iac` was simply always empty, which reads exactly like a
capability with nothing to report rather than one with nothing to run.

Both repositories are substantially infrastructure. Dockerfiles, compose
files, an nginx config, and in this repository the pipeline definitions
themselves. A container that never drops root, a service bound to 0.0.0.0, a
missing healthcheck — none of it is application code, so SAST cannot see it,
and the container scanner sees packages rather than configuration. The gap
was between two lanes that each correctly reported nothing.

The first run proved the point in the least flattering way available: it
found three highs in TheHub, and two of them were about the container running
as root. Both are false in effect — `entrypoint.sh` drops to `appuser` with
`gosu` — which is itself the finding worth having, because it means the answer
"we already handle that" was written in a comment nobody could check.

**Rejected: `--framework` left to autodetect.** Checkov will look for
Terraform, CloudFormation, Helm and Kubernetes, none of which exist in either
repository. Naming the frameworks is not just speed; an autodetected scan
silently changes what it covers when a file appears.

**Rejected: letting checkov's exit code fail the job.** `--soft-fail`, and
the severity decision stays with Mykronos and the repository's configured
threshold (spec 04 §5). A findings-driven exit code here would move the gate
into the scanner, where this platform has consistently refused to put it. The
job still fails on a non-zero exit or a missing SARIF, because that is the
scan failing rather than the scan finding something.

**Not covered, and said out loud: compose files.** `docker_compose` is not a
checkov framework — passing it makes checkov refuse the entire run with
"Invalid frameworks specified", which is how this was discovered. Compose
files are therefore scanned by nothing, and the comment in both pipelines
says so, because an `iac` lane going green otherwise reads as "the compose
files were checked".

---

## D-047 — Publishing by SHA is what made the Oracle gate mean anything

**Status:** Decided, implemented
**Spec:** [15 §3](../specs/15-concourse-pipeline.md)

D-045 moved `build` off the gate to break a deadlock, and closed by noting
that the narrower design becomes right "once something deploys automatically.
At that point publishing stops being inert and the tag becomes the thing worth
gating." The condition was already met and had been all along. `publish`
pushed `:latest`, and `deploy.ps1` pulls `:latest` (D-038, D-042). So a `no_go`
changed nothing an operator would ever meet: the refused build was already
sitting under the tag the deploy script reads, and the next deploy would ship
it. Nothing in the pipeline depended on `oracle-gate` at all. The gate was
decoration, and it had been decoration since D-045 fixed the deadlock.

`build` and `publish` still run ahead of the gate, for D-045's reason — an
image has to exist before it can be scanned. What is gated is the **pointer**.
Images publish as `${REGISTRY}/mykronos-backend:${SHA}`, `containers` scans
that same SHA, and a new `promote` job retags it `:latest` with crane only
after `oracle-gate` passes.

A refused commit now leaves an image in the registry that nothing points at.

**Why TheHub does not need this, and why that is not an inconsistency.** Spec
16 §2 considered a promote job for TheHub and dropped it, and that is still
right. TheHub's deploy is a Concourse job that pulls `thehub:${SHA}`, so the
gate can sit on the deploy directly and there is no floating tag to move. This
pipeline's deploy is `deploy.ps1`, run by a person on the host (D-038), which
Concourse cannot gate at all — the tag is the only handle it has on what that
person will get. Different mechanisms because the deploys are different, not
because the rule is.

**Rejected: gate `publish` instead of adding `promote`.** That is D-045's
deadlock again, one step later: the fix for a container finding cannot be
published while the finding blocks publishing.

**Rejected: have `deploy.ps1` pull by SHA.** It would work and it moves the
decision onto the operator, who would have to know which SHA Oracle cleared.
The tag is the right place to carry that, precisely because the person
deploying should not have to look it up.

---

## D-048 — Answering a scanner made the finding count go up

**Status:** Decided, implemented
**Spec:** [04 §8](../specs/04-scanner-workflows.md), [05 §7](../specs/05-datalake.md)

The `iac` lane (D-046) found two highs saying TheHub's containers never drop
root. Both are true about the Dockerfile and false about the container, which
`exec gosu appuser` in `entrypoint.sh`. The standard answer is the scanner's
own pragma — `# checkov:skip=CKV_DOCKER_3: <reason>` — so that was written,
with the justification, in both files.

The scan then reported 184 passed, 0 failed, 2 skipped. Mykronos recorded
**five** open findings where there had been three.

Checkov emits a skipped check as an ordinary SARIF result carrying
`suppressions: [{"kind": "inSource", "justification": ...}]` at
`level: warning`. `sarif_to_findings` never looked at that key, so the
suppressed result was ingested as a new open finding — at `medium`, because
the level differs — while the original `high` stayed open. Worse, adding the
comment shifted every line below it, and a finding without a code snippet is
identified positionally (fingerprint v1-line, spec 05 §5), so the same finding
under a new identity could not be reconciled against the old one either.

The net behaviour: documenting an answer to a finding produced two findings.
Every SARIF-based capability had this — `# nosemgrep` and `.trivyignore` are
the same mechanism — so it was not specific to the lane that exposed it.

**Decision: a suppressed result is not ingested, and the suppression is
reported.** `_is_suppressed` follows SARIF §3.27.23: a non-empty `suppressions`
array means suppressed unless a `status` of `rejected` says the silencing was
refused. Absent status means accepted, per the spec.

**Rejected: ingest them with `status = suppressed`.** This was the first
instinct and it contradicts the lake. Suppression is a decision, and
compaction already treats decisions as things a rescan must not overwrite
(spec 05 §7). A pragma in someone's repository rewriting that status on every
scan would turn the decision back into an observation, and would also mean a
contributor can mark a finding accepted in this platform by editing a comment
in their own repo. `FindingSubmission` has no status field, and it should not
gain one for this.

**Rejected: drop them silently.** Then a check that was answered looks exactly
like a check that never ran, which is the failure D-046 was written to avoid
one entry earlier. The adapter warns with the count and the rule IDs, so the
scan record shows what was silenced.

**What this does not do: judge the justification.** `# checkov:skip=` with a
made-up reason silences a real finding, and nothing here notices. That is the
same trust boundary as the capability config the repo already carries, but it
is worth stating rather than discovering. A reviewer reads the pragma; the
platform counts it.

---

## D-049 — TheHub's delivery pipeline shipped without supply-chain evidence

**Status:** Decided, implemented
**Spec:** [07 §4, §5a, §7](../specs/07-atlas-integration.md), [16 §5](../specs/16-thehub-delivery-pipeline.md)

Mykronos's pipeline produces an SBOM, provenance and ecosystem counts, and
posts them to `/api/ingest/atlas`. TheHub's did not. Its `dependencies` job
ran osv-scanner, uploaded findings, and stopped — so the SSCS panel was empty
for every commit this pipeline built, and Oracle scored the repository with no
Atlas evidence to read.

It was not that the evidence was never wanted. `.github/workflows/ci.yml`
builds a CycloneDX SBOM and its header lists that among the things only GHA
can do. Retiring those workflows for Concourse — which is the stated plan —
would have taken the SBOM with it and put nothing in its place. A migration
loses things quietly when the replacement is judged by whether it goes green.

The task mirrors Mykronos's, including its placement in `dependencies` rather
than `build`: Oracle reads Atlas evidence, and evidence produced after the
gate is evidence the gate could not use. TheHub now reports 100/100 across 67
resolved dependencies, and archives the SBOM to `thehub-sboms`.

---

## D-050 — A clean dependency tree was indistinguishable from an unscanned one

**Status:** Decided, implemented
**Spec:** [07 §4, §5a](../specs/07-atlas-integration.md)

The first run of the above said `Supply-chain trust: NOT ASSESSED - no
dependencies were resolved` in the same output where osv-scanner had just
logged "found 63 packages", "found 4 packages", and the SBOM listed 67
components.

`atlas_counts` reads packages from osv-scanner's JSON `results` array, and
that array contains only packages that have vulnerabilities. A repository
whose tree resolves completely and cleanly produces an empty `results`, zero
ecosystem counts, and therefore the exact output spec 07 §5a introduced to mean
something entirely different: *the scan resolved nothing*.

That distinction is the whole point of §5a — a scan that resolved nothing is
not a clean scan — and this bug collapsed it in the other direction, reporting
the cleanest possible result as an unknown one. `--all-packages` makes the
JSON list everything resolved rather than only the vulnerable subset.

Mykronos carried the identical line and the identical bug. It never showed
because that repository has vulnerable dependencies, which populate `results`
and make the counts look correct. Fixed in both, and worth noting as a class:
a defect that only appears once the thing being measured is healthy will be
found by the healthiest repository, not the sickest.

---

## D-051 — The pipelines install a version of the platform that is 53 commits old

**Status:** Resolved — option 1, 2026-08-14. `v2` was cut at the D-052
schema-upgrade fix: a commit chosen on purpose, at a moment when the stale pin
had become an outage (`mykronos-upload` at `v1` rejects `--capability ai` and
`qa`, so both lanes fail on upload). Both set-pipeline scripts now pin `v2`,
every install site prints the commit it resolved, and the next jump is a
deliberate `v3`, not a moved tag.
**Spec:** [15 §4](../specs/15-concourse-pipeline.md), [16 §15](../specs/16-thehub-delivery-pipeline.md)

Every scanning task installs the uploader with

    pip install "mykronos @ git+https://github.com/ToddGBenson/mykronos@${MYKRONOS_REF}#subdirectory=backend"

and `mykronos-ref` is set to `v1` in both `set-pipeline.ps1` and
`set-thehub-pipeline.ps1`. The `v1` tag has not moved in 53 commits.

This was found the direct way: D-048's suppression fix was written, tested,
committed and pushed, both pipelines were re-run, and the lane went on
ingesting suppressed results as open findings. The fix was on `main`. CI
installs `v1`.

The consequence is general, not specific to that fix. Every change to an
adapter, to `mykronos.upload`, to `atlas_counts` or to fingerprinting since
the tag was cut is inert in CI while being green in the unit tests. The tests
and the pipeline are testing two different versions of the same package, and
nothing reports the gap — the install line prints no version.

**Not resolved at first, deliberately.** Moving `v1` would land 53 commits of
platform change across both pipelines at once, including work in flight from
others, and that is a release decision rather than a pipeline repair. The
options, in the order they seemed preferable (option 1 is what happened):

1. Cut `v2` from a commit chosen on purpose and point `mykronos-ref` at it.
   Pinning stays meaningful and the jump is deliberate.
2. Move `v1` if it was always intended as a floating major tag in the
   `actions/checkout@v1` sense. Cheapest, and makes the next fix reach CI
   automatically — but a floating tag that has not floated for 53 commits is
   evidence the convention was not being followed.
3. Point `mykronos-ref` at `main`. Fixes reach CI immediately and pinning is
   given up entirely, so a bad commit breaks every lane in both pipelines at
   once. Cheapest to do and the easiest to regret.

**Worth doing regardless of which:** have the install step print the resolved
commit. A pinned ref is a good practice and a silently stale one is not, and
the difference is one line of output.

---

## D-052 — The operational store upgrades its own schema on startup

**Status:** Decided and shipped
**Trigger:** Production outage, 2026-08-14

`scanned_by` was added to `RepoOnboarding`, shipped through a green build, and
took the repository list down with `no such column` — while the container
reported healthy and 1088 tests passed. The mechanism: `create_all` creates
missing *tables* and deliberately leaves existing ones alone, so a column added
to an existing model reaches every database created after the change (all test
databases, which are built fresh) and none of the databases that already exist
(production). The test suite structurally cannot catch this class of failure,
because its databases are never old.

**Decision:** `Database.create_all()` now also adds any column the models
declare that the database lacks — the same lazy upgrade the lake has done for
Parquet partitions since spec 05 §5a, applied to SQLite. Existing rows get the
model's own default (it is what the application would have written had the
column existed), indexed columns get their index, and the upgrade logs what it
changed. A required column with no default is refused loudly at upgrade time —
and refused earlier than that by a drift-guard test asserting every column in
the models can be added to a table that already has rows. Identity columns that
shipped with their tables are grandfathered in a frozen list; the list is
asserted not to grow.

**Alternative rejected:** Alembic. Right answer for a schema with forks in its
history; this store has one deployment and additive changes only, and a
migration tool nobody runs on deploy fails in exactly the way `create_all`
just did.

**Also fixed here:** the healthcheck said healthy the whole time, because it
checks liveness, not whether the schema can serve the queries the UI makes.
Left as a known limitation — a startup that upgrades the schema removes the
disagreement at its source.

---

## D-053 — DAST is paused and out of the mandatory chain, temporarily

**Status:** Decided — explicitly temporary, revisit owed
**Trigger:** ZAP's active scan measured at 548% CPU / 7 GiB on the shared host

Everything runs on one machine: production Mykronos, TheHub demo, Concourse,
and ZAP. While an active scan runs, production requests time out at 30+
seconds — from a browser, the platform is down. A security lane that takes the
platform down while it runs costs more than the findings it produces are
worth, *on this hardware, today*.

**Decision:**
- `mykronos/demo-and-dast`: paused. Nothing downstream depends on it, so
  pausing blocks nothing. Trigger by hand when a DAST pass is wanted.
- `thehub/functional-dast`: paused, and `oracle-gate` re-pointed from
  `passed: [functional-dast]` to `passed: [deploy-demo]` so TheHub can still
  reach prod. The job definition stays; a manual trigger still reports into
  Mykronos.

**What this costs while it lasts:** no continuous DAST coverage, and the
platform's own coverage cross-check (spec 15 §4a) will rightly show `dast`
enabled with no scans arriving. That is the correct signal — the gap is real
and should show as one.

**To restore it, the scan needs a resource budget it can live within.** The
candidates, roughly in order of realism here: cap the ZAP container
(`cpus`/`mem_limit` in the demo compose) and accept a slower scan; schedule
the lane off-hours with a `time` resource instead of on every commit; or move
DAST to hardware that production does not share. Capping is the cheapest and
should be tried first — the scan has no deadline, and a scan that takes an
hour at 2 CPUs starves nobody.

---

## D-046 — Test results are ScanRuns with no findings, not a new capability

**Status:** Decided
**Spec:** [04 §3](../specs/04-scanner-workflows.md), [05 §3](../specs/05-datalake.md)
**Story:** PIP-1

Unit and functional testing are wanted as first-class pipeline stages. They
are not security scanners: they produce a pass/fail and a count, not findings
with a severity and a location.

**Decision: they are `ScanRun` rows with `finding_count = 0`.** The lake
already models exactly this — a capability, a `scan_status` of `success` /
`failure` / `partial_failure`, a count, and a commit. "The suite ran and three
failed" fits it without inventing anything, and `no_applicable_targets`
already means "there was nothing to run", which is the state a repository with
no tests is in.

`unit` and `functional` are therefore capabilities *for the purpose of
reporting a run*, and produce no findings.

**Rejected: a failing test becomes a finding.** It is the uniform answer and
it is untrue. A failing assertion is not a vulnerability, it has no severity
that means the same thing as a CVE's, and it would flow into Oracle's risk
score — so a broken test would raise a repository's *security* risk and a
deleted test would lower it. That is a direct incentive to delete tests, which
is the worst property a metric can have.

**Rejected: a separate quality-signal table.** Cleaner in the abstract and
worse in practice: every view that answers "what happened to this commit"
would need to read two tables and reconcile them, and the freshness logic that
already exists for scan runs would need a second implementation.

**Consequence for Oracle, stated because it is the part that could go wrong
quietly.** Oracle scores findings. A capability with no findings contributes
nothing to a risk score, and that is correct — a failing unit test is a reason
not to *ship*, which is the pipeline's job to enforce by failing the job, not
a reason to call the repository more dangerous. The gate stops the build; the
risk score stays about risk.

---

## D-047 — "AI" is four concerns; three become a capability and one stays where it is

**Status:** Decided
**Spec:** [04 §3](../specs/04-scanner-workflows.md), [06 §2](../specs/06-aegis-integration.md)
**Story:** PIP-7

PIP-7 sat in `intake` because the word covers at least four separable things,
and building the wrong one is expensive. Named explicitly:

1. **Prompt-injection surface** — untrusted input reaching a model prompt
   without separation.
2. **Model and dependency provenance** — which model, pinned to what, from
   where.
3. **Evaluation regression** — an AI feature whose measured quality dropped.
4. **Disclosure of AI-authored changes** — a pull request written by a model
   and not saying so.

**Decision: 1–3 become the `ai` capability. 4 stays in Aegis.**

The boundary is the subject. Aegis assesses a *pull request and its author*
(spec 06 §2): it answers "did a person disclose how this was written", which
is about conduct and belongs beside review integrity and the sensitive-path
signals. The other three assess *the code and its configuration* — they are
true of a commit whether or not anyone opened a pull request, and they are
found by reading the repository.

Moving disclosure into `ai` would split Aegis's one coherent question across
two capabilities and give the AI stage a per-author dimension that spec 06 §9
deliberately refuses to build.

**`ai` produces findings, unlike unit, functional and QA.** D-046 kept those
finding-free because a failing assertion is not a vulnerability. A prompt
injection that succeeds *is* one; an unpinned model is a supply-chain fact of
the same kind as an unpinned dependency, which Atlas already treats as a
finding. They have a location, a severity that means what it means everywhere
else, and something to fix.

Evaluation regression is the exception inside the exception: it is a quality
signal, so it sets `scan_status` and produces no finding, exactly as a unit
suite does.

**SARIF, not a bespoke format.** The capability accepts SARIF so any tool can
feed it, and the first-party checker emits SARIF like everything else. A
capability that only accepts its own tool's output is a capability with one
tool for ever.

---

## D-048 — The Oracle gate is advisory, and that is a problem to solve

**Status:** Resolved — option 2 chosen and implemented.
**Spec:** [09 §6](../specs/09-oracle-risk-decision-engine.md), [15 §3](../specs/15-concourse-pipeline.md)

`oracle-gate` no longer fails the build on `no_go`. It reports, loudly, and
the pipeline continues.

**Why it had to change.** Oracle scores the repository's *entire open
backlog*, not the change in front of it. This repository now carries 156 DAST
findings from a single demo scan and 243 accepted container risks, so the
score describes an estate rather than a commit. A one-line fix to something
unrelated is refused by the accumulated weight of everything already known,
and every subsequent commit is refused identically.

A gate that refuses everything is not a gate. It gets switched off or routed
around, and then it protects nothing — which is strictly worse than an
advisory one that still says so on every build.

**What this costs, stated plainly so nobody discovers it later.** A green
pipeline no longer means Oracle approved the commit. The promote job still
runs, so `:latest` moves on a refused commit, and the only remaining barrier
between a refused commit and production is that a person runs `deploy.ps1`.
That is a real reduction in safety and it is the reason this entry exists
rather than a quiet edit.

**What has to be built before this becomes a gate again.** The gate needs to
judge the change, not the estate. Three candidates, none yet chosen:

1. **Score the delta.** Findings first seen at this commit, against a
   threshold. Answers "did this change make things worse", which is the
   question a gate on a commit should ask. Needs care: a finding whose
   identity churns for unrelated reasons would read as new work.
2. **Gate on severity floors rather than a composite.** "No new criticals,
   no new highs" is unambiguous and hard to argue with, and does not move as
   the backlog grows.
3. **Age the backlog out of the score.** Findings older than the current
   change are context, not verdict — closer to what the maturity model
   already does.

### Resolution: option 2, the severity floor

The gate blocks when a commit **introduces** an open critical or high
finding. The composite score is still computed, still recorded, still drives
the dashboard and the maturity model — it just no longer decides whether a
build proceeds.

Three details that make it a floor rather than another backlog gate:

**"Introduced" means `first_seen_scan_run_id` belongs to a scan of this
commit**, not `first_seen_at` near it in time. Time would sweep in whatever a
concurrent scan of a different commit happened to report, and the whole point
is attributing a finding to the change in front of you. A finding reported by
two consecutive scans is introduced by the first — otherwise every unfixed
finding is re-introduced on every commit, and the backlog gate returns by
another route.

**A dispositioned finding does not block the commit that introduced it.** An
accepted risk with a written reason is a decision, not an obstacle. This is
the release valve that stops the floor becoming something people route
around.

**The floor is a constant, not policy.** Critical and high, in code. A floor
an operator can lower under deadline pressure is a floor that reaches zero,
and the argument for lowering it is always available and always plausible.
Mediums are recorded and triaged; they do not block.

The advisory period lasted one commit. What was true during it — a green
pipeline did not mean Oracle approved the commit — is no longer true: a green
pipeline now means this commit introduced no new critical or high finding,
which is a narrower claim than the original gate implied and a true one.

---

## D-007 — Deferred to a later phase

Recorded so they are not mistaken for oversights.

"Lands in" names a phase only while that phase is ahead. Once it has passed,
the entry says what would actually trigger the work instead — a row still
pointing at a delivered phase is the table quietly lying about its own
backlog.

| Deferred | Why | Lands in |
|---|---|---|
| `finding_reopened` events persisted as retro signals | Returned from `compact()` and logged. The Knowledge Store now exists to receive them, so this is a wiring job rather than a missing dependency — a finding that came back is a strong signal that whatever closed it did not work | Next |
| LLM-assisted fix generation | The deterministic fixers ship and are the primary path; the open-ended classes need `fix_generator_url` and an endpoint to point it at (D-032) | When a gateway exists |
| SSO replacing the admin-token stub | spec 12 §3 requires the organisation's SSO with roles from identity groups. The stub fails closed and is labelled everywhere it appears, but it is still one token with full rights | Before any multi-person use |
| Raw-output retention sweep | spec 05 §7's archival is built; the scheduled purge that bounds disk usage is not. Insider-risk rows already expire (D-022) — this is the larger, less sensitive pile | When disk becomes a constraint |

| Tier promotion *execution* | Candidates are found, proposals are rendered, and the Oracle policy proposal is written. Actually moving a row between tier files on approval is a dashboard action with no consumer yet — the team and org tiers have nothing reading them until more than one repo is onboarded | When a second repo is onboarded |
| Automatic draft-PR opening for policy proposals | `render_policy_proposal` produces the body; opening it needs the App installed on the Mykronos repo itself, which is a different installation from the ones being scanned | When the App is registered |
| Aegis's `privilege_adjacent` signal | spec 06 §2 makes it conditional on an external event feed that is off by default and has no configured source. The signal key is registered and capped, so a deployment that adds a feed needs no platform change | When a feed exists |
| SBOM **download** endpoint | `sbom_ref` is recorded and surfaced; serving the archived file to a browser is a separate authorisation question from serving the evidence row | When somebody needs to download one |
| Rate limiter behind shared storage | In-process memory is correct for a single-process deployment | When the backend scales out |
| Installer honouring a repo's `PULL_REQUEST_TEMPLATE.md` | D-037. On a repository with a governance gate the installer opens a pull request that cannot be merged, and the platform does not notice. The template is readable through the same `get_file` the collision check already uses | When a second repo refuses one |

---

## Open questions carried from the spec review

| # | Question | Blocks | Status |
|---|---|---|---|
| 1 | GitHub App needs `workflows: write` — absent from spec 02 §4 / 12 §6. Without it the installer cannot commit workflow files at all | Phase 1 | **Resolved** — D-008 |
| 2 | GitHub App needs `secrets: write` — spec 12 §6 claims otherwise | Phase 1 | **Resolved** — D-008 |
| 3 | Ten tokens per repo on ten independent 90-day clocks | Phase 1 | **Resolved** — D-009 |
| 4 | Oracle's score saturates: criticals weigh 40, clamped at 100, so three of them pins every repo at 100 forever | Phase 3 | **Resolved** — D-018 |
| 5 | "Advisory by default" has no stated path to ever turning blocking on. Needs a shadow-mode metric to make the case with data | Phase 3 | **Resolved** — D-021 |

All five are now answered. Questions 4 and 5 were Oracle's and were held until
Phase 2 had produced real findings to answer them against, which is what made
D-018's saturation curve and D-021's shadow-mode metric arguable from data
rather than from taste.

## D-054 — Unauthenticated baseline DAST replaces the functional/active lane

**Status:** Decided and running green on demo and prod
**Trigger:** D-053 left DAST paused with a resource budget owed; this pays it

D-053 paused DAST because ZAP's *active* scan measured 548% CPU / 7 GiB and
took production down. The budget it asked for turned out to be available a
cheaper way than capping or new hardware: stop running an active scan at all.

`zap-baseline.py` spiders the target and applies **passive** rules only — it
analyses responses it was already going to receive and never sends an attack
payload. Measured here, prod stayed at `health=healthy`, `restarts=0` and
served 200s throughout its own scan.

**Decision:**
- `thehub/dast-demo` and `thehub/dast-prod`: unauthenticated baseline scans,
  triggered by `passed: [deploy-demo]` / `[deploy-prod]`, capped with `-m 5`.
- `thehub/functional-dast`: stays paused and stays in the file. Restoring it
  still needs D-053's resource budget; this decision does not grant one.

**Why unauthenticated, and why both environments.** This is the view an
anonymous attacker gets. Demo runs with the gate off, so the scan sees the
whole application (19 URLs, 41 findings). Prod runs with the gate on, so the
scan sees the perimeter refusing anonymous callers (3 URLs, 12 findings). The
small prod number is the result, not a failed scan — the shapes differing in
exactly that direction is evidence the gate works.

**Four defects had to be fixed to get there, all in the same seam** — a
non-root tool image meeting root-owned Concourse volumes:
1. `zap-baseline` refuses a `-J` report unless `/zap/wrk` exists. Its warning
   says "is not mounted", but the check is `os.path.exists`, so `mkdir` is the
   whole fix. The wording cost more time than the bug.
2. The report could not be copied into a task output: outputs are root-owned
   0755 and this image runs as `zap` (uid 1000) with no sudo. Pre-chmodding
   from a root task does not help — a task's output is a fresh volume, not the
   same-named input. Fixed by scanning and uploading in one task, so the
   report never crosses a volume boundary.
3. PEP 668 blocks `pip` on this Debian base; `--user --break-system-packages`
   installs to `~/.local` and touches nothing system-wide.
4. `git` refused the root-owned source checkout ("dubious ownership"), so
   `rev-parse` printed nothing and the upload posted an empty `commit_sha`,
   which Mykronos rejected with a 422 that read like a schema bug. Fixed with
   `safe.directory`, plus an explicit check — a scan that cannot say what it
   scanned is not a result (L0001, as with the reachability check).

## D-055 — Concourse runs two workers, and the web node stops being one

**Status:** Decided and running
**Trigger:** One worker meant one queue, and TheHub starved behind Mykronos

`quickstart` runs web and worker in one container. That was right until the
day a single Mykronos commit fanned 17 jobs onto the one worker and left
TheHub with 11 builds pending and 0 started — resource *checks* included, so
the pipeline looked broken rather than queued. The compose header had said
since spec 15 that the split would be a compose change rather than a redesign.
It was.

**Decision:** `concourse` (`command: web`) plus `concourse-worker-1` and
`concourse-worker-2`, defined from one anchor so they cannot drift.

**This adds no CPU** — it is the same host — so it is not a throughput fix.
What it buys is that the two pipelines stop queueing behind each other, which
is the failure that was actually observed.

**Two things it also bought, neither of them planned:**
- The web node is no longer `privileged`. Only a worker needs the container
  runtime; quickstart forced that privilege onto the web half, which is the
  half that faces the tunnel.
- `CONCOURSE_WORKER_GARDEN_NETWORK: host` turned out to be dead. The worker
  forwards `CONCOURSE_GARDEN_*` to gdn as flags, gdn has no `--network`, and
  both workers died on boot with `unknown flag 'network'`. Under quickstart
  the name never matched the forwarding prefix, so it had never done anything.
  Configuration that only looks load-bearing is worse than none.

**The keys had to become permanent.** The old note said pinning the TSA and
worker keys broke the handshake, and for quickstart it did — two processes in
one container, keys managed internally. Between separate containers the
handshake is real and both ends must agree across a restart, so ephemeral keys
cannot work: the web node would mint a new host key on every recreate and
every worker would refuse it. setup.ps1 had already generated the full set.

**Capped at 6 CPUs and 6g each, and the asymmetry is deliberate.** The CPU cap
is the point — D-053 is the record of a scan taking 548% CPU and making
production serve timeouts, and two capped workers can take 12 of 20 cores and
leave the rest. The memory ceiling is loose on purpose: a CPU cap slows a build
down, a memory cap kills it, and an OOM mid-scan reads as a tool bug for as
long as it takes to find the limit.

**What this does not fix.** TheHub's own jobs still share `serial_groups:
[worker]`, so they still run one at a time; a second worker only decouples the
two pipelines from each other. And the host is a laptop running production,
three databases and a CI farm — Docker sees 15.49 GiB of its 31.8 GB because
of the WSL2 default, which is a likelier binding constraint than core count and
is free to change.

---

## D-056 — The repo page is one dashboard, and its findings list is a list of decisions

**Status:** Decided and running
**Spec:** [10 §2.2](../specs/10-jded-dashboard.md)
**Trigger:** Four tabs for four questions nobody asks separately

The per-repo page had Findings and Scan health as separate tabs and the CI
panel above both. Answering "what is outstanding here, and is anything still
scanning" therefore took two navigations, and "is the pipeline green" a third
— which is why nobody checked the third. They are one page now. The other four
tabs stayed: a risk decision, an SBOM, an insider-risk signal and a draft pull
request are different subjects, not other views of the same findings.

**Open findings only, by default.** A list that mixes outstanding findings
with ones somebody already accepted cannot be counted, and a count nobody
trusts gets ignored. Every other status is one labelled click away, because an
accepted risk is a decision with an owner and a reason (PIP-9) and hiding it
would be worse than mixing it in.

**Rows group on `(rule_id, package)`.** Not on the file: one rule firing in
forty files is one decision and forty places to change it, and the same CVE
reported by both the dependency scan and the container scan is one
vulnerability reported twice. The version is deliberately outside the key, so
a CVE on two pinned versions of one library does not read as two problems.
Every occurrence is still carried and keeps its own `finding_id` — a
disposition applies to the occurrence, because accepting the risk in one file
is not accepting it in forty — and the group's severity is its worst member's,
because scanners disagree about a CVE constantly and the lower number is never
the safe one to display.

**Toxic combinations are detected from the findings, not read from
`remediation_events`.** Those rows only exist where Patchwork has run, and a
repository that never enabled auto-remediation is exactly the one nobody has
told about its unauthenticated database. The dashboard calls the same
`patchwork/correlate.detect()` over the same capability set the pipeline uses,
so the two cannot report different combinations for the same lake. Detection
runs over every open finding rather than the filtered subset: half a
combination is routinely a medium from another scanner, and a view filtered to
`critical` that reported no combinations would go quiet at exactly the moment
somebody is looking at the worst row.

**A combination overrides the per-finding verdict, including a dismissal.**
Each half being individually unremarkable is what a toxic combination *is*, so
triaging the halves is how one gets waved through twice.

**Triage moved out of the pipeline into `patchwork/triage.py`** so both
callers share it. Two implementations would have let the platform call a rule
a likely false positive on one page while generating a fix for it on another,
and the Knowledge Store's whole purpose — not repeating a judgement somebody
already made — would have held in only one of the two places.

**Indicator lights say their state in words.** Five stage states differ by one
shade otherwise, and "which of these dots is amber" is not a question a
dashboard should ask of anybody. The distinction the colours exist to keep is
"not enabled" versus "enabled and silent": they render as the same absence
everywhere else, and only one of them is a problem.

**Raw tool output is not served by the grouped endpoint at all**, for any
role. A group is a decision to make; the bytes of a secrets finding belong on
the detail pane, behind the admin check that always guarded them (spec 12 §5).
The detail pane fetches one finding by id — once occurrences are grouped, the
one somebody clicked is routinely not in the first hundred rows of anything.

---

## D-057 — Harness and Findings split back out of the one dashboard, on request

**Status:** Decided and running — amends D-056, does not reverse it
**Spec:** [17](../specs/17-harness-threat-intel-and-i2i.md)
**Trigger:** An operator asking for a harness tab and a findings tab by name

D-056 folded Findings, Scan health, jobs and stages into one "Dashboard" tab
because the four questions people ask together weren't reachable without
navigating, and that reasoning still holds — nothing about *how* those four
things are computed changed here. What changed is that the merged page turned
out to still be two different jobs wearing one label: "is the harness healthy"
and "what did it find" are asked by different people at different times, and a
single long scroll made neither quick to reach on its own. **Harness**
(capability enable/disable, scan health, pipeline coverage) and **Findings**
are tabs again. The other four — decisions, supply chain, insider risk,
remediation — were never part of the question this reopens and are unchanged.

**The capability buttons gained the same colour vocabulary the panel below
them already had**, rather than a second one. `CapabilityManager` used to
render its own `border-accent`/muted palette for on/off/pending; it now asks
`pipelines.tsx`'s `stageTone()` — the same function `StageLights` uses — so a
button and the coverage row explaining it can never disagree about what green
or red means. Fixed one real gap in `stageTone()` along the way: an enabled,
correctly-silent capability (Aegis/Oracle/Patchwork, which write no `ScanRun`
by design) fell through to the same tone as "not enabled" — a working
capability read as switched off. It now reads `ok`, worded `event-driven`.

**Colour is run health, not a finding-severity indicator.** A repo with forty
open criticals and a passing pipeline is still green on the Harness tab; its
risk is Oracle's question, answered elsewhere on the same page. Conflating the
two would hide a broken scanner behind a clean-looking finding count — the
exact thing `partial_failure` (spec 04 §8) exists to keep visible.

**Findings/triage filtering gained `rule_id` (free-text, matched against
`rule_id` and `title`) and two status values that were already real and had no
button: `suppressed` and `superseded`.** The second was the more interesting
gap — `Finding.superseded_by` (spec 05 §5a) was never even selected by the
dashboard's queries, so a re-fingerprinted finding's replacement was
unreachable by name from the API, not just from the UI.

**Threat intelligence (CISA KEV, FIRST EPSS) is new, not a reorganisation.**
Nothing in the platform read either feed before this. It lives in the
operational database (`ThreatIntelMatch`, alongside `CapabilityGrant`), not
the lake — it's a current-value table, upserted daily, and treating a revised
EPSS score as an event to append rather than a correction to overwrite would
have been the wrong data model for what it actually is. Only CVEs an open
finding actually names are fetched and stored; the full catalogs are orders of
magnitude larger than anything a portfolio this size references.

**What spec 17 describes and this change does not build**, so it is a
follow-up rather than a silent gap: reachability scoring, exploitability as an
Oracle input, on-demand scan dispatch, a default tool for the `ai` capability,
and the i2i grooming process (finding → dev-ready GitHub issue). Each needs
either a new `GitHubClient` method, a language-aware analysis this change
correctly declined to fabricate a shortcut for, or both — tracked as issues
against spec 17 rather than left as a paragraph nobody re-reads.

---

## D-058 — D-057's deferred list, closed out except reachability

**Status:** Decided and running
**Spec:** [17](../specs/17-harness-threat-intel-and-i2i.md)
**Trigger:** "keep going"

Four of D-057's five deferred rows landed in the same sitting, in dependency order —
exploitability first, because everything after it either cites it or assumes the
`GitHubClient` surface it shares a shape with.

**Exploitability required threading a new dependency through `OracleEngine` that
never existed before: the operational database.** Every other input Oracle reads
comes from `self.catalog` (the lake); `ThreatIntelMatch` lives in SQLite. Rather
than restructure the constructor, `db` joined `store` as a second optional
keyword-only parameter, defaulting to `None` everywhere — the same shape, the
same reason: a caller that hasn't wired one up gets `unavailable`, not a crash.
Thirteen-plus test call sites across the suite construct `OracleEngine`/
`OracleService` positionally and needed to change nothing.

**The boost is additive, not a move between severity bands.** spec 17 §5.4 as
originally written said a KEV-listed finding's "effective severity weight" gets
raised a band, which reads like re-bucketing the finding into the next band's
curve. That would touch `_band_contribution`'s tested arithmetic for every
finding sharing that band, KEV-listed or not. Instead each KEV-listed finding
gets its own `Term` worth `weight(next_band) - weight(this_band)` — the ordinary
bands are computed exactly as before, and the exploitability contribution is
individually auditable rather than folded into an aggregate nobody can
re-derive by hand.

**`kev_boosted()` is a function over detected combinations, not a field on
`CombinationRule`.** The spec's first draft proposed a static
`exploitability_boost: bool` on the rule. Whether a *specific instance* of a
detected combination involves an actively-exploited CVE is a fact about which
findings matched it, not about the rule that fired — a static per-rule flag
could not express that, and would have needed to be `True` on every rule to
mean anything.

**Scan dispatch needed a Concourse write path that has never existed.** Spec
15 §4a is anonymous reads only, by design — a status page has no business
holding a credential. Triggering a build is a write, so it gets its own
credential (`concourse_api_token`, unset by default) rather than reusing or
widening the read path's trust. The job-name mapping for a Concourse trigger
is the same documented heuristic `ci.py`'s read path already uses in reverse
(`CAPABILITY_BY_JOB`) — a pipeline naming its job differently is simply not
reached, the same safe-to-be-wrong direction the read side already commits to.

**The `ai` capability's adapter already existed.** Confirmed by rereading the
registry before writing anything: `AdapterSpec("ai", "mykronos-ai-checks", ...)`
predates this work. The gap was narrower than D-057 first described it — no
tool produced SARIF for that intake to receive, not no intake at all. Fixing
the spec text to say so mattered as much as landing the checker itself; a spec
describing a bigger gap than the real one sends the next person to rebuild
something that already works.

**i2i needed a permission nothing in this codebase had asked for.**
`issues: write` joins `REQUIRED_PERMISSIONS` — previously six entries, all of
which existed because an earlier phase's own outage demanded them (D-008's
`workflows`/`secrets`). This one is added ahead of an incident, which is the
better order and worth naming as the exception. It is scoped narrowly on
purpose: distinct from `pull_requests: write`, spent only by the groom
endpoints, so the permission review (spec 12 §6) can say exactly where it goes.
Spec 02 §4 and spec 12 §6 both updated in the same change — restating a
permission list in two places and updating only one is exactly how D-008
happened the first time.

**What's still open.** Reachability (#15) has no engine and none was attempted
here — the honest plumbing (an Oracle category, always `available: false`)
already landed with exploitability, and a call-graph analysis is real,
separate, language-aware work this sitting correctly left alone. `min_epss`/
`kev_only` finding filters and the same KEV badge on the Triage queue (#20)
remain — `triage_queue()` is a flat query, not the grouped one the badge
attaches to.

## D-059 — #20 closed: KEV/EPSS reach the Triage queue

**Status:** Decided and running
**Spec:** [17](../specs/17-harness-threat-intel-and-i2i.md)
**Trigger:** "keep going"

D-058 left one row of D-057's list open: `triage_queue()` had no `kev_only`/
`min_epss` filters and no KEV badge, because it is a flat per-finding query and
`_attach_threat_intel` was written for the grouped shape `open_findings()`
returns.

**`_attach_threat_intel` was generalized rather than duplicated.** It keyed its
output by group identity; retargeted to key by `id(row)` instead, it stamps
`cve_id`/`in_kev`/`epss_score` onto either a grouped finding or a flat triage
row with the same call. Writing a second, near-identical stamping function for
the flat case would have meant two places that could drift on what "in KEV"
means — the failure mode D-008 already named once.

**The two query paths stay genuinely separate, not just labeled that way.**
`open_findings()`'s existing behavior — `rows[:limit]` applied before
grouping — had to survive unchanged for every caller that isn't filtering by
threat intel, since grouping after limiting and limiting after grouping count
`shown`/`deduplicated` differently. Only when `kev_only`/`min_epss` is active
does the query switch to fetching up to `CORRELATION_CEILING` candidates,
filtering, and limiting the *groups* afterward — the same trade `open_findings`
already made for correlation, reused rather than reinvented for a second axis
of filtering. `triage_queue()` picked up the identical branch.

**A schema-drift bug from D-058 surfaced during this sitting's full-suite run,
unrelated to this change, and got fixed here rather than left for later.**
`GroomedStory` (D-058) shipped with six required columns and no defaults —
correct for a table created whole by `create_all()`, but the drift guard
(`tests/test_schema_upgrade.py`, D-052) checks every model column as if it
might need adding to a table that already exists, and doesn't distinguish "new
table, ships with the column" from "existing table, column added later". The
established answer for that distinction is `GRANDFATHERED`, not a default that
would be a lie (`groomed_stories.dev_ready` defaulting to `false` for rows that
can't exist without a value) — the same reasoning already applied to
`workflow_install_events.repo_onboarding_id`. All six columns joined it.

## D-060 — Four days of merges never reached prod; an unpinned pydantic did it

**Status:** Decided, fixed
**Spec:** [15 §3](../specs/15-concourse-pipeline.md) (the `frontend` job), [17](../specs/17-harness-threat-intel-and-i2i.md)
**Trigger:** "make sure all changes end up in prod. I'm not seeing it all"

Every PR in this spec's implementation (#14, #21, #22, #23, #24) merged clean —
green CI on GitHub, green local verification, each merge synced to `main`. None
of it reached the running containers. The Concourse `frontend` job had been
failing since 2026-08-16, on every commit since, silently: `unit`,
`lint-and-types`, and `qa-spec-links` kept passing and re-triggering, but
`build`/`publish-backend`/`publish-frontend`/`promote` all gate on
`passed: [..., frontend]` (spec 15 §3), so nothing after that job built. The
registry's newest image was still tagged `62ca9bf` — the commit before this
spec's first PR.

**The failure was a committed-artifact drift, not a code bug.** `frontend`'s
`lint-types-build` task runs `python scripts/dump_openapi.py` then
`openapi-typescript`, and fails the build if the result differs from
`frontend/lib/api-types.d.ts` — the check D-0xx's OpenAPI-sync convention
exists to enforce. It fired because `pydantic>=2.9` in `pyproject.toml` has no
upper bound, and somewhere between whenever `api-types.d.ts` was last
regenerated and 2026-08-16, PyPI shipped a pydantic minor version that started
emitting a dataclass's docstring as its schema `description` where it
previously did not — one field, `PortfolioSummary`. Every task in the pipeline
runs `pip install --quiet -e .` fresh, so the moment that pydantic release
existed, every build after it would resolve to it and disagree with a types
file generated under the old one — including builds carrying no relevant
change at all, which is exactly what four days of PRs were.

**Diagnosed by reproducing the CI environment, not by reading the diff.** The
committed file matched what this host's own `python -m pip show pydantic`
would generate locally (2.12.5) — the discrepancy only exists against a fresh
install (2.13.4 resolved during this fix), so a local regenerate looked like a
no-op until it ran in an isolated venv rather than the host's shared
site-packages. That shared install is depended on by other tools on this
machine (`anthropic`, `openai`, `mcp`, `aegis-product-coach`,
`triage-shared`); upgrading it in place to chase this down would have been a
second, unrelated blast radius for a one-file fix.

**Fixed by regenerating, not by pinning.** `pyproject.toml`'s loose bounds are
what let this project's own supply chain stay current — the same posture a
security platform auditing everyone else's dependencies should hold for its
own — so the fix is the regenerated `api-types.d.ts`, not a ceiling on
`pydantic`. The same class of break can recur on a future pydantic release;
the guard that would catch it — `frontend` failing loud, `promote` never
running — is the one that just did its job, four days late only because
nobody was watching the pipeline itself rather than each PR's own checks.

**What this changes going forward.** A merged PR's own CI (GitHub-side
lint/type/test) says the code is correct. It says nothing about whether
Concourse's build of that same commit got past its own gates — those are two
different pipelines checking two different things, and only one of them
publishes what `deploy.ps1` pulls. "Merged" is not "deployed"; confirming
deploy means checking the Concourse job graph itself, the way this fix was
found.

## D-061 — Spec 18: the repo page rework, on request

**Status:** Decided and running
**Spec:** [18](../specs/18-repo-page-rework-threat-model-and-remediation.md)
**Trigger:** User-reported portfolio/Findings count mismatch, plus a direct
request for tab restructuring, filters, on-demand remediation, and a defined
SBOM process

Three scoping questions were asked before writing anything, because each had
more than one reasonable reading and the wrong one would have meant building
the wrong thing at spec-18 scale:

**"Threat Model" meant a formal STRIDE analysis, not a repackaging of KEV/EPSS
data.** The cheaper reading — consolidate exploit-exposure data already
computed elsewhere into one tab — was offered and declined. The chosen scope
is a real, new capability: a STRIDE-categorized attack-surface inventory. Built
capability-level rather than CWE-level because no `Finding` carries a
structured CWE today (`rule_id` is a free-form tool string) — see spec 18 §6.3
for why that resolution is disclosed rather than papered over.

**The narrative layer is honest plumbing, not a new LLM dependency.** Asked
directly, given that this backend has never called an LLM (confirmed by
re-reading specs 06/08/09/12 and the actual code — `fix_generator_url` and
`ai_classifier_url` are both nullable, validated, and never dereferenced) and
Oracle's own spec explicitly chose templates over free-form narrative. The
answer chosen was the same pattern reachability got: a nullable
`narrative_generator_url`, unavailable by default, no SDK added, no key
required. Building a real LLM call was the other option on the table and was
declined — worth naming because "AI-generated threat model" is exactly the
kind of request that quietly grows into a new external dependency if the
question isn't asked first.

**Dashboard duplicates content on purpose.** Spec 17 split Harness and
Findings apart for good reasons that still hold; this spec adds Dashboard back
as an eighth tab carrying the pre-split combined view *and* new summary cards,
even though most of that content already has its own tab. Offered as "pick
one," the answer was "both" — confirmed rather than assumed, since building a
tab whose entire purpose is answering a question two other tabs already answer
is the kind of thing worth checking before writing it.

**The count-mismatch bug traces to the same `asset_id`/`repo_full_name`
migration D-052's drift guard exists near.** Portfolio aggregates
(`_open_severity_counts`, `_capability_scan_state`) never moved off
`repo_full_name` when every other repo-scoped query in `dashboard.py` did;
`migrate_assets.py` existed specifically to backfill the column this bug shows
the consequence of not universally depending on. Fixed by making the portfolio
queries match everything else, not by adding a third convention.
