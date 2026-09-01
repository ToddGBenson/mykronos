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

*Two entries share this number — a numbering collision from 2026-08-13, not a supersession. Both stand. See [D-082](#d-082--two-sessions-took-the-same-decision-number).*

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

*Two entries share this number — a numbering collision from 2026-08-13, not a supersession. Both stand. See [D-082](#d-082--two-sessions-took-the-same-decision-number).*

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

*Two entries share this number — a numbering collision from 2026-08-13, not a supersession. Both stand. See [D-082](#d-082--two-sessions-took-the-same-decision-number).*

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

*Two entries share this number — a numbering collision from 2026-08-13, not a supersession. Both stand. See [D-082](#d-082--two-sessions-took-the-same-decision-number).*

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

*Two entries share this number — a numbering collision from 2026-08-13, not a supersession. Both stand. See [D-082](#d-082--two-sessions-took-the-same-decision-number).*

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

*Two entries share this number — a numbering collision from 2026-08-13, not a supersession. Both stand. See [D-082](#d-082--two-sessions-took-the-same-decision-number).*

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

## D-062 — Spec 18 closed out in five PRs, in dependency order

**Status:** Decided and running
**Spec:** [18](../specs/18-repo-page-rework-threat-model-and-remediation.md)
**Trigger:** "keep going" (four times, across #26-#30)

D-061's scope landed as five independent PRs rather than one — the same
reasoning D-057/D-058 already established for spec 17: each is reviewable and
deployable on its own, and a failure in one does not block the others from
reaching prod. Order followed what each piece needed already built: the tab
restructure before anything that lives inside a tab, findings filters before
nothing (independent), remediation and the SBOM download last because neither
gated on the other three.

**The `run_one` per-finding path reuses `_attempt_fix` rather than
duplicating it.** The alternative — a second, lighter fix-generation function
for the on-demand case — was rejected for the same reason spec 08's own
triage logic lives in one place two callers share: a fix a person could get
on demand that the batch sweep would have refused is a platform arguing with
itself. `preview_only` is one new parameter on the existing method, not a
parallel implementation of it.

**A preview writes nothing, deliberately, including no `RemediationEvent`.**
The alternative — recording every preview the same way a real attempt is
recorded — would have made "how many fixes has Patchwork attempted" ambiguous
between "generated a draft" and "a person looked and closed the tab." Spec 08
§7's own standard (every *routed* finding produces exactly one event) is
preserved by `run_one` only routing a finding through `_record`'s
`buffer.append` when the call was not a preview.

**What's still open.** Reachability (#15, spec 17) remains the only
deliberately unbuilt item across specs 17 and 18. Threat Model's CWE-aware
refinement (spec 18 §6.3) and an actual LLM-backed narrative layer (§6.6) are
both named, scoped, and left undone on purpose — the first needs adapters to
carry a taxonomy field they do not have today, the second needs a deployment
decision (a new dependency, a key, a cost) nobody has been asked to make yet.

## D-063 — Dashboard *is* the Harness content; Harness becomes a real test tab

**Status:** Decided and running
**Spec:** [18](../specs/18-repo-page-rework-threat-model-and-remediation.md)
**Trigger:** Direct correction after D-061/D-062 shipped

D-061's "both" answer — Dashboard carries the old combined view *and* new
summary cards, duplicating Harness and Findings on purpose — was reversed on
sight of the result. The corrected shape: Dashboard *is* what D-061 called
Harness (capability manager, scan health, enabled jobs), promoted to the
default tab rather than duplicated into a second one; it carries no findings.
Harness stops being a second view of the same thing and becomes what its name
already implied and nothing had built yet: a tab that runs tests.

**"Run tests" surfaced a real gap, not just a missing button.** `unit`,
`functional`, and `qa` (D-046 — pass/fail `ScanRun`s, never `Finding`s) were
never in `DISPATCHABLE_CAPABILITIES`, so `scan_now` never had a path for
them. Adding them exposed that the gap is deeper on the GitHub Actions side:
no workflow template exists for any of the three
(`workflow-templates/manifest.json`), and an Actions-scanned repo's install
PR is generated *from* the templates of the capabilities being enabled — so
the capabilities endpoint itself refuses to enable `unit`/`functional`/`qa`
there with a 422, before dispatch is ever reached. On-demand test running
therefore works today for Concourse-scanned repositories only, through the
same `_JOBS_BY_CAPABILITY` mapping (`ci.py`'s `CAPABILITY_BY_JOB`, reversed)
every other on-demand dispatch already resolves through — reused, not
rebuilt. This is said plainly on the tab rather than left to look broken for
an Actions-scanned repo.

**`ScanNowButton` gained an optional `capabilities` scope rather than a
second button component.** The Test Harness tab's "run tests" needed to
dispatch unit/functional/qa only, not bundle in a security scan — one prop,
reused by both call sites, rather than a parallel dispatch button that could
drift from the one Dashboard already uses.

**What's still open.** Building an actual GitHub Actions workflow template
for unit/functional/qa was explicitly not attempted here — D-046's own
reasoning ("a repository's test runner is decided by its language and its
own conventions") is exactly why no single generic template could serve
every repo honestly; a real answer needs either a per-language template set
or a convention this platform does not yet have. Concourse-scanned repos are
a complete, working answer today; Actions-scanned repos are not, and the tab
says so rather than pretending otherwise.

## D-064 — `privilege_adjacent` reads a GitHub org role, not a personnel feed

Spec 06 §2 named the signal and `SIGNAL_CAP` has weighted it at 30 since that
spec shipped, but nothing ever produced it: the intended input was an external
event feed carrying access-grant changes, and no deployment has one. It sat in
the deferred table indefinitely.

The narrower reading needs no new integration. GitHub already knows the
author's role on the repository, and `admin`/`maintain` is the part that
matters — those are the people who can change branch protection, add a deploy
key, or otherwise alter the controls the *other* signals measure. That is what
makes the change worth a second look. `write`, `triage` and `read` are ordinary
contributor access and do not fire it.

Three things this deliberately does not do:

- **It does not treat an unresolved role as ordinary access.** The collaborator
  permission endpoint needs push access, so the lookup can fail. A failed
  lookup makes the signal *absent*, never zero-scored. Recording "not
  privileged" because a `curl` returned 403 would be a claim nobody checked.
- **It does not escalate the Actions workflow's permissions to get it.** spec
  06 §6 withholds `pull-requests: write` so Aegis structurally cannot merge,
  close or force-push, and the collaborator endpoint sits behind push access.
  Actions-scanned repos lose this one signal; the guarantee is worth more. The
  Concourse pipelines pass it, their credential having push access already.
- **It does not name the person in the rationale.** spec 06 §9's purpose
  limitation holds: the text says what role the change came from and why that
  matters, not who wrote it. The rationale is a sentence a colleague may end up
  reading.

The block invariant is unaffected — the two heaviest caps still sum to less
than the default threshold of 80, so no single signal, this one included, can
block on its own.

## D-065 — License data rides in `ecosystems_json`, not a new lake column

Spec 22 §1.2 asks for a `licenses_json` column on `sscs_evidence`. It does not
ship, and this is deliberate rather than an omission.

`licenses_seen` is a field on `EcosystemEvidence`, and `to_row` already
serialises every ecosystem's full `model_dump()` into `ecosystems_json` — so
the data is in the lake either way. A dedicated column would store it twice,
and adding a column to a lake table has a specific, recently-demonstrated
cost: it has to be added to `_UPDATE_SETS` as well, and omitting it there
drops the value silently on every UPDATE. That exact bug cost `scan_runs.detail`
its message for any scan longer than the compaction interval, and the first
regression test written for it did not catch it. A column carrying a copy of
data already present is not worth re-entering that class of risk for.

What this costs: querying licenses across the fleet means unpacking JSON
rather than selecting a column. That is already true of `score_terms`,
`floored`, and the per-ecosystem counts — every consumer of this table already
reads the blob.

## D-066 — Freshness is opt-in, and absent is not zero

Spec 22 §2's registry lookup makes outbound calls to npm and PyPI for every
resolved package. Spec 07 §7 already holds Atlas to "no default-on external
call", which is the same rule Aegis's `ai_classifier_url` follows, so
`check_freshness` defaults to false and the workflow only passes the flag when
a repository has asked for it.

The more consequential half is what happens when it does not run, or runs and
fails for one package. `maintenance_data_available_for` stays null — which
spec 07 §8 already knows how to read — rather than being set to
`dependency_count`. A package whose registry lookup timed out, or that is not
on a public registry at all, is counted in neither the numerator nor the
denominator. Both alternatives were available and both are claims: counting it
fresh says somebody is maintaining it, counting it stale says nobody is, and
the truth is that nobody asked successfully.

This matters more here than for most terms because `stale_dependencies` has
been in the trust formula since spec 07 shipped and has contributed exactly
zero to every score ever computed — nothing populated it. The first thing that
does must not make "we now check" indistinguishable from "we found nothing".

## D-067 — Policy history comes from the decisions, not from git

Spec 21 §5 asks for `GET /api/oracle/policy/history` reading
`oracle-policy-v1.yaml`'s commit history through the GitHub API and rendering
each bump as a diff. The diff half does not ship: reading that file's history
needs the App installed on the Mykronos repository itself, which is the same
thing already blocking automatic policy-proposal pull requests and is still
not true. Building it against a credential that does not exist would have
produced an endpoint that 403s.

The endpoint ships anyway, answering a different and — on reflection — more
useful question, from data the platform already holds. Every `risk_decisions`
row has recorded `policy_version` since spec 09, so the platform can say which
decisions were made under which version, over what window, across how many
repositories, and how many of them were `no_go`.

That is the question somebody actually has when they open an old decision they
disagree with: *were these the rules we have now?* A textual diff would not
answer it — knowing that a threshold moved does not tell you whether this
decision predates the move.

The endpoint's own `note` names what is missing rather than letting the
feature's title imply it is complete. Until the App is installed, the file's
textual history is where it has always been, in git.

## D-068 — The AI-authorship classifier call, and why a hedge is null

`ai_authorship_flag` has had three-state logic, a `SIGNAL_CAP` entry, and a
dead "configured but unreachable" branch since spec 06. `ai_classifier_url`
has been a validated config field the whole time. Nothing anywhere called it —
the Aegis workflow template said so in a comment. Spec 20 §1 wires the call.

Four choices worth recording.

**The step is rendered, not guarded.** With `ai_classifier_url` unset the
generated workflow contains no classifier step at all, rather than one behind
an `if:`. Somebody auditing what a repository sends to third parties should be
able to answer that by reading the workflow file, and an `if:`-guarded step
that POSTs a diff is a step that POSTs a diff as far as that reading goes.

**A hedge is null, not true.** The response contract is one boolean and one
confidence float; anything else — free-form text, a missing field, a
confidence out of range — is discarded. Below `AI_CLASSIFIER_MIN_CONFIDENCE`
(0.7) the answer is thrown away entirely. "Probably, 0.3" has established
nothing, and recording it as `true` would let a model's guess read as a
finding about a named person. Spec 06 §5 already has a value for
not-established, and it is the one this uses.

Restricting what comes *back* matters as much as restricting what goes out.
`ai_classifier_url` is the only setting in this platform that sends repository
content to a third party; letting that party write free-form text into a
record about a colleague would give away on the return trip exactly what §5
protects on the way out.

**It runs before the scorer.** The answer is an input to the assessment, not a
footnote on it — it can raise `unverified_ai` for a pull request whose
description disclosed nothing. It cannot do the reverse: a PR that says it was
AI-assisted was, whatever a model thinks, so a `false` from the classifier
never withdraws a disclosure. The flag reports what the classifier said; the
signal reports what the author said. They are different questions and the code
keeps them apart.

**The diff does not outlive the request.** Capped at 200KB before it is sent —
an unbounded POST of a forty-megabyte refactor to a third party is a different
act from asking about a change somebody could read — and deleted from the
workspace immediately after, because a copy left behind is a copy something
later could pick up.

## D-069 — Blast radius counts findings, not dependencies

Spec 19 §2.4 asks for a portfolio-wide map built by aggregating
`sscs_evidence.ecosystems_json` into package-name → dependent-repo-count. That
blob does not contain package names. It contains per-ecosystem *counts*, which
is exactly what spec 07 §4 asks the runner to report, so the full resolved
dependency set is not in the lake at all.

Two ways forward: add a package list to the evidence submission, or count
something already recorded. The second wins, and not only because it is
cheaper. `findings.package_name` is already there, and for a *prioritisation*
signal it is the better population: the question this input answers is "is
this vulnerable package one that many teams are exposed to", and a repository
with no finding on a package has nothing here to prioritise.

The cost is stated in the code and worth repeating: a repository that depends
on the package but whose scan found nothing wrong with it is not counted. The
map under-reports true dependency spread and never over-reports it, which is
the correct direction of error for a signal that *adds* points. Resolved
findings are excluded too — a package everyone has already fixed is not a
concentration risk, and counting it would make the signal insensitive to
exactly the work it exists to encourage.

The weight is small and hard-capped (`cap: 20`, below the `no_go` threshold),
because the map behind it is package-name matching rather than version
resolution. A deliberately approximate signal should not be able to change a
verdict on its own, and SSCS trust already scores a repository's own
dependency health at length — this is only the concentration on top of it.

## D-070 — One combination rule gets a partial fix, and only one

Spec 08 §8 stops Patchwork fixing any half of a toxic combination, because
closing one half usually closes the *finding* without closing the *risk*. That
default is right and stays.

Spec 19 §3.3 carves out one exception, and the shape of the carve-out is the
decision worth recording: it is a field on `CombinationRule`
(`safe_partial_fix`), null for nine rules out of ten, rather than a generic
"fix half a combination" capability. A platform-wide switch would repeat §8's
mistake for nine rules in order to get it right for one. Adding a second is a
reviewed, per-rule change, and `test_no_other_built_in_rule_has_a_partial_fix`
is what makes somebody make that decision deliberately.

The one rule is `secret-and-public-surface`. Removing a committed credential
is correct whether or not the unauthenticated surface beside it is ever fixed:
the danger is a leaked credential somebody can find a use for, and pulling the
credential closes that half outright rather than hiding it. The other half — an
unauthenticated surface — is a design question, and fixing it blind is exactly
how a combination gets closed without being understood.

The combination event still reads `needs_human_judgment`. What changes is only
that the credential does not sit in the repository waiting for that person to
arrive. The rationale says both things, because "needs human judgment" next to
an open pull request reads as a contradiction otherwise.

`detect` resolves *which* finding may be fixed, not the pipeline. Only `detect`
knows which finding satisfied which requirement — the pipeline sees a set of
ids and could not tell the credential from the surface.

## D-071 — The remediation digest groups by rule, not by rule and fixer

Spec 19 §3.4 asks to group open remediation PRs by `(rule_id, fixer_name)` and
says it needs "no new backend query logic". Both are slightly wrong about the
schema. `remediation_events` has neither column: `rule_id` lives on the finding
(so the digest joins), and `fixer_name` is not recorded anywhere at all.

Grouping is therefore by rule alone. That is the coarser key, and coarser is
the safe direction to be wrong in here: two fixers for one rule land in one
card, which a reviewer can see and separate, whereas one fixer's work split
across two cards is a duplication they cannot see and would review twice.

The page groups and never merges. Ten repositories with the same fix stay ten
pull requests — one pull request touching ten repositories would bypass
per-repo review and CODEOWNERS, which is most of what makes a draft PR an
acceptable thing for a bot to open. The page says so in its own note rather
than leaving a reader to assume the opposite.

## D-072 — Import reachability: a discount, and the first negative weight

Spec 17 §5.3 built the `reachability` Oracle category, declined to build a
call-graph engine, and left the category permanently `available: false`.
Declining was right — a call graph that handles dynamic dispatch, decorators
and framework registration is a project. What it left unbuilt was the floor
underneath: for Python only, does anything in this repository import this file.

That is much less than reachability and the snapshot says so in its own
`reason` field, because "not listed as orphaned" must not be read as "proven
reachable".

**It subtracts.** A finding in a file nothing imports is lower priority than
the same finding on a request path, so this is the only negative weight in
`oracle-policy-v1.yaml`. That inverts which way a wrong answer hurts: every
other input, being wrong means raising a score somebody will investigate and
dismiss; here it means quietly lowering one nobody looks at again. Every
design choice follows from that:

- A file that will not parse is never called orphaned — and neither is
  anything else in that repository. Its imports are unknown, so it might have
  been the only importer of anything else in the tree. One bad file silences
  the signal for the whole repo. Blunt, and the right way round: this category
  subtracts, so the safe failure is saying nothing. `files_unparseable` is
  recorded so an operator can see why it went quiet.
- Entry points are detected from an `if __name__ == "__main__"` block, not
  only from a glob list. The first run over Mykronos itself reported `cli.py`
  and the analysis module as orphaned — true about their imports, false about
  their purpose — and a glob list would have needed a new entry for every such
  file forever.
- Import matching deliberately over-matches: every suffix of a dotted path,
  both halves of `from pkg.thing import x`, relative imports resolved against
  the file's own package. A spurious edge costs a signal; a missed edge calls
  live code dead.
- The discount is capped at 15, less than the gap between `review_recommended`
  and `no_go`, so it can never clear a threshold on its own.

**Stored operationally, not in the lake.** `ReachabilityReport` is one row per
repository, replaced outright. Every other scan observation is append-only
because its history is evidence; this is current state about the tree, wholly
superseded by the next analysis, and a row per commit would be a growing table
nothing reads the old rows of. Same reasoning as `RiskProfile`.

**Ingested under the `sast` token.** Reachability is a fact about source code
and `sast` is the capability whose findings it prioritises. A capability of its
own would mean a separate grant for something with no findings, no workflow,
and nothing to enable.

## D-073 — A container CVE is keyed on its package, not its image

Found while asking why TheHub's Oracle gate was blocking. Sixteen critical
Perl CVEs were displaying the image name `library/mykronos-scan` — an image
that is not in the registry and not what the pipeline scans. The archived
SARIF from the same scan said `thehub` for 252 of its 256 results, so Trivy,
the pipeline and the adapter were all correct.

Two separate things were wrong underneath.

**The stored image name was stale, and now is not.** `compaction.py`'s
`_UPDATE_SETS["findings"]` did not include `file_path`, so the value written
at first sighting was never refreshed. For most findings that is invisible —
`file_path` is part of identity for the snippet and line fingerprints, so a
different path is a different finding. It can only drift for the two
fingerprints that exclude it, `v2-package` and `v2-repo`. These rows were
created on 2026-08-12 under the tag the retired Actions workflow used, and
still carried it a week later. Fixed by adding the column to the SET clause.

**Identity ignores the image, deliberately, and that is now pinned.**
`compute_finding_id` dispatches on `package_name` before `file_path`, so a
container CVE is keyed on `(repo, capability, rule_id, package_name)`. The
same CVE and package in two different images is one finding.

`test_two_images_do_not_collapse_into_one_finding` claimed to prevent exactly
that, and had never tested it: its helper called `compute_finding_id` without
`package_name`, taking the `v1-line` branch where the path *is* part of
identity. Production passes `package_name` and takes `v2-package`. The test
asserted an invariant the production call path violates, and passed because it
was not the production call path. It now makes the same call `api/ingest.py`
makes, and asserts what actually happens.

**The collapse stays, for now.** Spec 05 §5's dependency rule was written for
dependency manifests, where a repository has one dependency tree; a repository
building two images has two, which is where the assumption stops holding.
Including the image in the key would fix that — and would retire and recreate
every existing container finding, destroying `first_seen_at`, which
`fingerprint.py`'s docstring names as the thing it exists to protect. That is
roughly 410 rows on TheHub alone, and it buys nothing today: no onboarded
repository builds more than one image. Deferred until one does, at which point
the migration is worth its cost. Pinned by a test either way, so the next
person meets a decision rather than a surprise.

**What this did not change:** the sixteen Perl criticals are real, current, and
in TheHub's own image. The gate was right to block on them.

## D-074 — `v3`, and a check so there is no D-0xx for `v4`

**Status:** Decided and shipped

D-051 found the `mykronos-ref` pin 53 commits stale, resolved it by cutting
`v2` at a chosen commit, and wrote: "the next jump is a deliberate `v3`, not a
moved tag." This is that jump. The pin was 61 commits behind, and the
prediction in D-051's own resolution — that this would recur — was right.

Found the same way as last time, which is the part worth fixing. The
reachability step shipped in #39/#40 ran on its first Concourse build and
printed `No module named mykronos.reachability`. It degraded correctly and
cost nothing, but the feature had been merged, deployed and reported as
working while being inert in CI.

Everything runner-side added since `v2` was affected: `atlas_sbom`,
`atlas_freshness`, `reachability`, `ai_pin_check`, and the `--author-role`,
`--ai-classifier-file`, `--sbom` and `--check-freshness` flags. Two of those
were latent *hard* failures rather than graceful ones — `--sbom` is passed
unconditionally by the Actions atlas template inside `set -euo pipefail`, and
`--author-role` survives only because `${ROLE:+…}` omits it when the
collaborator lookup fails, which it currently always does.

**What is different this time.** D-051's "worth doing regardless" was to have
the install step print its resolved commit. That shipped, and it did not
prevent this: printing a fact into a build log nobody reads is not a control.

`scripts/check_pinned_ref.py` is. It runs from the source checkout, installs
the pinned ref exactly as every scanning task does, and asserts that each
module the pipelines invoke and each flag they pass is actually there. Run
against `v2` it reproduces all eight problems by name and says to cut a tag.

Three properties it was given on purpose:

- **Not a version-distance check.** "You are 61 commits behind" every build is
  noise, and a pin being old is fine. A pipeline invoking something the pin
  does not have is not fine, and that is the only thing it asserts.
- **It gates nothing.** A stale pin makes a loud red job, not a stopped fleet:
  the scans still running produce real results, they are only missing what
  came after the tag. Gating `build` would turn "one signal is inert" into
  "nothing ships".
- **It cannot go quiet.** A module whose `--help` cannot be read is reported
  as unverifiable rather than passed. A guard that says nothing when it cannot
  tell is how the pin went stale unnoticed twice.

A companion test asserts the requirement list matches every `python -m
mykronos.*` call across all three pipelines and every workflow template. It
earned itself on its first run by finding `mykronos.ai_pin_check`, which the
manual sweep of the same question had missed.

## D-075 — "Done" needs somewhere a person can look

Spec 19 §2.1 was marked Done with the analysis built, ingested, stored,
scored, weighted in policy and tested — and no way for anyone to see the
result. Mid-session I wrote "now surface reachability in the frontend",
grepped, found nothing existed, and updated the status table instead of
building it. The status was wrong and the omission was mine.

`GET /api/repos/{repo_id}/reachability` and a card on the Risk Decision tab
close it. Three details worth keeping:

- **Absent is a 200, not a 404.** "No analysis has run" is a real answer about
  the repository; a 404 makes the caller guess between that and "no such
  repo".
- **The card refuses to conflate the two empty states.** Never-analysed and
  analysed-with-nothing-orphaned both show no files, and Oracle scores them
  differently, so they get different renderings.
- **It sits beside the risk profile**, the other Oracle input recorded outside
  the score. This one *lowers* scores, which is exactly why it needs to be
  inspectable: a penalty gets disputed when it is wrong, a discount never
  does, because the finding it quietened is the one nobody looked at twice.

The general lesson, and the reason this is a decision rather than a commit
message: a capability that produces data no interface exposes is not done, and
a status table is the easiest place in this repository to write something
untrue. Two prior entries (D-051 on the stale pin, D-071 on the digest) were
found the same way — by using the thing rather than by reading the code.

## D-076 — "No fixer for it" and "no fix exists" are different sentences

I told the operator twice that TheHub's sixteen critical Perl CVEs were one
base-image rebase away from closing, and offered to build a base-image fixer
to do it. Both were wrong, and the data said so the moment anyone looked:
every one of the sixteen carries `fixed_version: null`. Across all 256 of
TheHub's open container findings, 253 have no fixed version. Debian has
shipped no patch. No rebuild, no bump, and no fixer this platform could write
closes any of them.

The inference that misled me was reasonable and unchecked: four CVEs across
`perl`, `perl-base`, `perl-modules-5.40` and `libperl5.40` are one source
package, therefore one upstream bump fixes all sixteen. True, if a bump
exists. Nobody asked whether one did.

The platform made the same conflation. `_suggested_fix` reported Patchwork's
verdict, and Patchwork's `no_fix_available` means *this platform has no
fixer* — which a developer reads as unassigned work. For a distribution
package it usually means the maintainer has not shipped a patch, and the
distinction is the difference between a task and a wait.

Stories now say which. When the scanner recorded a fixed version, the story
names it and says a rebuild closes it. When it did not, the story says so
outright and names the dispositions that actually exist — accept the risk with
a reason, or wait and let the next scan close it automatically. Silent when
the finding names no package, because appending "no upstream fix exists" to a
SQL-injection story would be false; that one is entirely fixable by the person
reading it.

**The base-image fixer was not built.** With 253 of 256 findings having
nothing to bump to, it would have been a fixer with nothing to fix. What the
data argues for instead is scoring: sixteen unfixable criticals contribute 177
points and pin the repository at 100/100, so the gate is currently measuring
Debian's release schedule rather than anything the team controls. That is a
policy change and is not made here.

## D-077 — An unfixable finding counts for less, not for nothing

TheHub's sixteen critical Perl CVEs contributed 177 points and pinned the
repository at 100/100. Every one had `fixed_version: null` — Debian had
shipped no patch, so no rebuild, bump or fixer closed any of them. The gate
therefore read `no_go` whether the team had fixed everything they could or
nothing at all, which is the state in which a gate has stopped carrying
information. That is what this addresses, not the backlog.

`unfixable_dampening.factor` (0.5, matching `false_positive_dampening`)
applies inside the curve to the *count*, the same mechanism dampened rules and
in-flight fixes already use, and capped against them so a finding cannot be
discounted twice.

**Dampened, never excluded.** An unpatched critical in production is real
risk. Scoring it at zero would say something false and would make ignoring
upstream the cheapest way to improve a score.

**Gated on `package_name`, and that guard is the whole risk in this change.**
A SAST finding has no `fixed_version` and never will: absence there means the
field does not apply, not that upstream has shipped nothing. An unguarded
check would have quietened every injection finding in the fleet — the single
worst outcome available in this file, and the reason most of
`test_unfixable_dampening.py` is about SAST findings rather than about the
discount.

**It does not clear TheHub's gate, and was not tuned to.** Modelled against
the live numbers, the raw score falls 346 → 310 and still clamps to 100. The
factor was chosen for consistency with the existing dampener, not to produce a
verdict; picking a number because of the answer it yields is scoring
backwards. What does move is `raw_score`, which is what the portfolio ranks on
(D-018) — a repository with unfixable findings now ranks below one with the
same count of fixable ones, which is the ordering a person would choose.

Policy 1.4. Unlike every bump before it, this one changes existing scores on
purpose: `fixed_version` has been on every dependency and container finding
all along and nothing read it.

---

## D-078 — One pipeline standard, numbered, cited from the YAML

**Status:** Decided and shipped
**Doc:** [`docs/pipeline-standard.md`](pipeline-standard.md)

The GitHub Actions side has had a shared skeleton since it was written:
`workflow-templates/_base.yml.j2` factors the header, the fail-fast probe, the
concurrency group and the upload step so that "a change to the upload contract
is one edit rather than ten." The Concourse side never had one. Thirty-eight
jobs across two pipelines each hand-rolled the same `apt-get` / `pip install` /
`python -m mykronos.upload` sequence, and they had drifted in every way that
sequence can drift: `set -uo` against `set -euo` against `set -eu`, ten uploads
naming the default branch as a literal against `$SCANNED_BRANCH`, nine of
thirty-eight capturing a scanner's exit code so the upload still ran and
twenty-nine not.

Ten rules, `PS-1` through `PS-10`, each stating the failure it prevents. They
are cited by number from the YAML at the point they apply, so a comment reading
`PS-3` has somewhere to lead.

**Why numbered rules rather than a description of the current state.** Every
one of these came from a real failure that was invisible while it was
happening — a lane green on every build that had never reported (L0003), a
scanner that broke and made its capability look un-enabled, a notifier that had
never delivered. A standard that only says what the files do now cannot stop
the next one; the cost of each rule is what makes it survive being inconvenient.

**What is deliberately *not* standardised.** The two pipelines order the Oracle
gate and the Aegis lane differently, and both orderings are spec'd: `thehub`
puts the gate after DAST so runtime findings reach the score, and pays for it
by dropping insider risk out of the score (spec 16 §3). That is recorded as a
known divergence with a proposal to close it, not flattened into conformance.
Standardising a decision somebody made on purpose is how a standard loses.

---

## D-079 — The alerting had never fired, in both pipelines, by construction

**Status:** Decided and shipped

Two bugs, one per pipeline, each of which could only ever manifest as a red job
that was already red.

TheHub's notifier wrote its JSON payload to the task working directory.
`curlimages/curl` runs as an unprivileged user and Concourse creates that
directory owned by root, so the write failed and the hook died before reaching
curl. That one was found and fixed; the comment recording it is still in the
file.

The mykronos notifier was worse and had not been found. It computed `$TEXT`,
discarded it, and posted `-d @payload.json` against a file no line in the task
ever wrote — the escaping step that was supposed to build it had been left as a
comment with nothing under it. curl failed on the missing file, `|| echo`
swallowed the failure, and the hook exited 0. Every `on_failure` and `on_error`
in that pipeline had been decorative since the day it was added.

**Why neither was noticed.** A notifier only runs when something else has
already failed, and it is required to fail open so that a missing credential
does not become a second failure on top of the first. Failing open and failing
silently are one line apart, and both of these were on the wrong side of it.

**What changed.** Both post through `chat.postMessage` with a bot token and
check the response body — Slack answers `200` with `{"ok":false,"error":…}`
when a post is rejected, so the status code proves nothing and an undelivered
alert otherwise reads exactly like a delivered one. That is `PS-10`.

The bot token also made `PS-9` possible for the mykronos pipeline. A webhook's
secret sits in the URL path of the endpoint being called, so the pipeline has
to hold it; a bot token sits in an `Authorization:` header, which the Vault
credential manager can substitute at egress. Moving to `chat.postMessage` was
the prerequisite for the credential leaving the config, not a separate tidy-up
— the same reasoning thehub already recorded when it switched.

---

## D-080 — TheHub's Mykronos Actions lanes are retired, as this repo's were

**Status:** Decided, applied on a branch
**Spec:** [16 §4](../specs/16-thehub-delivery-pipeline.md)

D-038 named the problem and spec 16 §4 settled it for this repository: two CI
systems scanning the same commits produce findings the ingestion upsert makes
indistinguishable, so a repository's capability coverage is decided by whichever
uploaded last. This repository's five Actions lanes were removed once Concourse
ran the full capability set.

TheHub's five were not, and they were worse than a straight duplicate: they
installed the uploader at `@v1` and called the composite action at `@8b329fc5`
while the Concourse pipeline ran `v3`. Two systems, two uploader generations,
one commit, five shared capabilities.

`codeql.yml` stays — GitHub's own analysis, not a Mykronos capability upload,
and it never reaches the lake.

**What this costs**, in the same words spec 16 §4 used: a pull request from a
fork gets no checks. Concourse polls a branch, and running an untrusted
contributor's code on a worker inside the LAN is what spec 14 §4 and spec 15 §7
both refuse. If anyone other than the operator starts opening pull requests
against TheHub, the answer is to restore these lanes **for `pull_request` only**
— never with the `push:` and `schedule:` triggers that made them duplicates,
and never by widening what Concourse trusts.

Concourse now covers more of TheHub than Actions ever did: `iac`, `cloud`,
`dast`, `unit`, `functional`, `ai` and — as of this change — `qa`.

---

## D-081 — Two live overrides existed only in a working tree

**Status:** Decided and shipped

The pipelines that actually run are applied from a **second clone** of this
repository — `PDSO2/`, which is where the Concourse stack's compose project
lives. It was eighteen commits behind `main` and carried uncommitted changes
to five files. Most were hand-copied versions of things that had since landed
upstream. Two were not, and neither existed anywhere in git:

- **TheHub's Oracle gate was disabled.** `exit 1` on a `no_go` was commented
  out on 2026-08-18 at the operator's explicit instruction. The gate was
  blocking correctly on a real finding rather than malfunctioning — score
  100/100, 21 open critical findings — and TheHub still needed to ship.
- **TheHub's pipeline watched `main`, not `develop`.** `$Branch` was changed
  in the same session, because watching the integration branch made every
  direct push race the local `deploy.sh` path (SDLC-7 #49216).

Both are reasonable operational calls. Neither was reviewable, and that is the
decision being recorded.

**Why this is the same bug three times over.** The repository said the gate
blocked; the applied pipeline let every `no_go` through. The repository said
`develop`; the pipeline watched `main`. Nothing reconciled either pair, and
the only way to find out was to run `git status` in a directory nobody would
think to open. This is precisely what D-079 found in the notifier — a control
that had never once fired, invisible because its failure looked like the
failure it was reporting — and precisely what the coverage cross-check (spec
15 §4a.1) exists to catch for scan results. A disabled security control is the
worst thing yet to hold in an unversioned working tree.

**What changed.** The branch default is now `main` in the committed script,
with the SDLC-7 rationale next to it. The gate is now controlled by
`((thehub-oracle-blocking))`, set from `set-thehub-pipeline.ps1`, and the job
announces the override on every `no_go` — in the build log and in the Slack
message, which now says the deploy proceeded rather than that nothing was
deployed. Restoring the gate is one word in one file, or
`-OracleBlocking true` on the command line.

A var rather than a restored `exit 1`, because the override is still wanted:
the 21 criticals are not dispositioned. What was wrong was never the decision
to ship — it was that a person reading this repository could not learn the
decision had been made.

**The general lesson.** A deployment checkout that drifts from the repository
is a second source of truth, and the pipeline it applies is the one that
counts. The reconciliation here was manual and found by accident, while
looking for a `.env`. Worth a check that compares the applied pipeline config
against the committed file — `fly get-pipeline` can answer it, once CNC-2 has
moved the last credentials into Vault so its output is safe to read.

---

## D-082 — Two sessions took the same decision number

**Status:** Decided and shipped

`D-046`, `D-047` and `D-048` each appear **twice** in this log, with entirely
different content. Both sets are real decisions, both were implemented, and
both are cited from live code and specs today.

| | First (18:13, 2026-08-13) | Second (21:36, same day) |
|---|---|---|
| D-046 | The platform had ten capabilities and the pipelines ran eight | Test results are ScanRuns with no findings |
| D-047 | Publishing by SHA is what made the Oracle gate mean anything | "AI" is four concerns; three become a capability |
| D-048 | Answering a scanner made the finding count go up | The Oracle gate is advisory, and that is a problem |

Two sessions three hours apart, each appending to the end of the file, each
taking the next number it could see. Neither was wrong at the time it looked.

**Nothing is renumbered, and that is the decision.** The obvious tidy-up —
give one set fresh numbers — is worse than the collision. Roughly thirty
citations exist across `backend/`, `deploy/` and `specs/`, and they do *not*
all mean the same set: `specs/15 §3` and `specs/16 §3` cite the first D-046
for the checkov lane, while `schemas.py`, `ci.py`, `capabilities.py`,
`registry.py` and a dozen spec rows cite the second for the quality stages.
Repointing them means thirty individual judgement calls against the documents
that are this project's contract, and a citation that points confidently at
the wrong entry is worse than one a reader has to disambiguate. This log is
also append-only by its own header.

So each of the six headings now carries a line saying the number is shared and
linking here. A reader who lands on either entry learns immediately that there
is another, and which is which.

**What stops the next one.** `tests/test_decisions_log.py` asserts every
`## D-nnn` heading is unique. It fails on the working tree today unless the
three known collisions are in its allow-list, which is where they are recorded
in code as well as prose — a new collision fails the `unit` lane, an old one
does not. That is the same shape as `check_pinned_ref.py`: the rule is worth
nothing without something that notices when it breaks, and this one broke
silently for a week.

## D-083 — TheHub's gate blocks on what a commit introduced, like the other one

**Status:** Decided and shipped
**Supersedes the override in:** D-081

TheHub's Oracle gate blocked on the composite risk score. D-048 had already
written down why that does not work, for the mykronos pipeline:

> the composite score describes the whole estate […] so gating on it refused
> every commit regardless of content, and a gate that refuses everything gets
> switched off or routed around.

TheHub's gate refused everything, and on 2026-08-18 an operator switched it
off. The lesson had been learned once, applied to one pipeline, and left
unapplied to the other — which is the more interesting failure than either
gate's behaviour. A decision record is only worth what it changes.

The gate now blocks on `introduced_blocking` from the same
`/api/oracle/evaluate` response it already called, which needed no backend
change: `introduced` has been on that response since D-048. "No new criticals,
no new highs" does not drift as a backlog grows, so the gate can be on
permanently rather than until the next bad week.

**What did not clear it.** All 21 of TheHub's open criticals were
dispositioned first — 16 as accepted risks with no upstream fix (Trivy reports
`fixed_version: null`; Debian has shipped no patch) and 5 as false positives
verified line by line against the source: three `Bearer YOUR_TOKEN`
placeholders in documentation, one prose line in a usage string, and one local
variable named `token`. That took the raw score from 309 to 157 and the open
criticals to zero, and the gate still said `no_go` on 77 open highs. It would
have refused every commit exactly as before.

So dispositioning was worth doing and was not the fix. Recording that because
the obvious reading — "clear the backlog and the gate works" — is wrong, and
acting on it would mean grinding through 77 highs to reach the same place this
change reaches directly.

**The override stays.** `thehub-oracle-blocking` is restored to `true` rather
than deleted. D-081 added it because the previous override existed only in a
deployment working tree, so the repository claimed the gate blocked while the
applied pipeline let everything through. That reasoning is untouched by this
change: a control switched off invisibly is worse than one switched off
loudly. What changed is that it now guards a floor worth guarding.

## D-084 — The benchmark ships before the reviewer, and the corpus is its own repository

**Status:** Decided — spec 23 drafted, nothing built
**Spec:** [23](../specs/23-agentic-source-code-review.md)

Mandiant published its Agentic Vulnerability Discovery Harness — a six-phase
agentic code-review pipeline — and the question was what of it to build here.
Most of the answer is an ordering decision rather than an architecture one,
which is why it is a decision record and not only a spec.

**The order is benchmark, surface, threat model, finder — and the finder is
last.** The obvious reading of that article is "build the bug-finding agents";
they are its centrepiece and its headline number. Building them first here
would produce findings nobody can size. This platform runs fifteen checks and
has never measured recall for any of them, so a sixteenth detector's output
would arrive into a triage queue with no baseline to compare against and no way
to tell an improvement from a model change upstream. Spec 04 §7 has asked for a
seeded corpus since the beginning and the bar it set — "at least one `Finding`"
— cannot tell nine-of-ten from one-of-ten. The benchmark is worth building even
if nothing agentic is ever built, and nothing agentic is worth trusting until it
exists.

D-053 is the other half of the argument. DAST is paused platform-wide for want
of a resource budget. Agentic review over a whole tree costs more than DAST,
recurs weekly rather than once, and would be paused the same way — after the
money was spent rather than before.

**The corpus is a separate repository, and repositories get a `synthetic`
flag.** The tempting shortcut is a `bench/` directory in this repo. It cannot
be one: the corpus has to be scanned by the real pipelines to measure anything,
and scanning deliberately vulnerable code under this repo's `repo_full_name`
puts real findings in this repo's lake, raises its risk score, and reaches its
own Oracle gate. A separate repository fixes that and creates the second
problem — spec 21's portfolio aggregation would count it, permanently, as the
fleet's worst repo. Hence a flag on `Repository` rather than a hardcoded name
somewhere: the platform needs a concept for "real code, not real risk", and
one exclusion list per aggregate would drift apart.

**The entry-point inventory is an inventory, and reachability stays
`available: False`.** The surface is the one agentic phase worth building
early, because an entry point is verifiable — it exists at that `file:line` or
it does not — and a wrong one dies at approval instead of in triage. What it
must not do is answer the Oracle category it looks like it answers. An
inventory establishes that a file *is* on an entry path; it establishes nothing
about a file that failed to appear in it, and the only use Oracle has for a
partial answer is discounting the findings that did not appear. That is the
exact direction `reachability.py` was written to refuse — *"a false 'this is
orphaned' tells somebody a live request handler is dead code"* — and an agent's
recall is a much weaker guarantee than an import graph's. The category earns
`available: True` when a number from §1's corpus says it can, in a later spec.

**Two smaller things worth writing down before they are rediscovered.** The
article's "low temperature to generate, high temperature to validate" does not
port: `temperature` is removed on Opus 5, Sonnet 5 and Opus 4.7/4.8 and returns
a 400. Validator diversity has to come from distinct prompts instead, which is
the better mechanism anyway — identical validators agree on identical mistakes.
And AVDH's grading agent solves a problem this platform will not have: its
findings land on client code with no ground truth, while a seeded corpus has a
manifest, so grading is a diff and not a judgement. Skipping it removes an LLM
from the one component whose whole job is to be trusted.

**What this does not decide.** Whether §5 gets built at all. The gate in spec
23 §5.1 is four conditions, and if the reviewer's measured recall on the corpus
does not beat the scanners already running, the honest outcome is a spec status
row saying so and no fifth workstream.

## D-085 — One platform review became eight specs, and the ordering is the argument

**Status:** Decided — specs 24–31 drafted, nothing built
**Specs:** [24](../specs/24-ownership-deadlines-and-acceptance-review.md),
[25](../specs/25-fix-efficacy-and-verification.md), [26](../specs/26-oracle-as-adviser.md),
[27](../specs/27-the-worklist.md), [28](../specs/28-threat-model-resolution.md),
[29](../specs/29-component-inventory-and-incident-mode.md),
[30](../specs/30-change-governance-posture.md), [31](../specs/31-regression-coverage.md)

A full read of the eight repo-page subsystems — Findings, Harness, Threat
Model, Supply chain, Insider Threat, Risk Decision, Triage, Remediation —
turned up twenty-two gaps. Three choices about what to do with them are worth
recording, because each was a fork where the obvious option was worse.

**Eight specs, not one and not twenty-two.** One spec would have been a
three-thousand-line document nobody reviews in a sitting; one per gap would
have produced twenty-two specs whose dependencies could not be read off their
numbers. Eight follows the shape specs 18–22 already set — a spec is a depth
pass over a subsystem — and it makes the sequencing legible: 24 before
everything because ownership is what the rest attaches to, 26 after 24, 25 and
31 because its scoring credits are worthless until something produces the
evidence, 27 after 26 because the worklist consumes `path_to_green` rather
than recomputing it.

**Six of the twenty-two gaps are one gap.** A finding with no owner never
closes; a fix with no verification never proves it worked; a test with no link
to a finding never protects it; an acceptance with no expiry never gets
re-decided; a gate with no shadow report never gets switched on; a detector
with no benchmark never gets trusted (spec 23). The platform is built for the
forward pass and missing the return path. Naming that as one problem is what
made the ordering obvious — and it is why the first three specs are all
plumbing rather than features.

**Two claims in these specs contradict things this repository has written
down, and both were checked against the code rather than the prose.**

Spec 18 §6 and `dashboard.threat_model()` both explain the capability-level
STRIDE mapping by saying no `Finding` carries a structured CWE. That is true of
the schema and not of the data: SARIF carries `properties.tags`, CodeQL and
Semgrep both populate it with CWE identifiers, and `adapters/sarif.py` reads
exactly one property — `security-severity` — and discards the rest. The
reasoning was right when it was written about what the lake stores, and it has
been quietly wrong about what arrives ever since. Spec 28 §1 corrects it.

D-069 chose to compute blast radius from findings because
`sscs_evidence.ecosystems_json` holds counts rather than package names. Also
correct, and it recorded the alternative — add a package list to the
submission — as the option not taken. Spec 29 §1 takes it, because the same
missing table is what makes "who uses this package" unanswerable on an incident
day, and that is a much larger cost than one approximated signal.

**What none of these specs do.** Nothing here lets an agent guess reachability,
aggregates an insider signal per person, gives Patchwork a merge operation, or
introduces a number that cannot be traced to a lake row. Those four refusals
are the most valuable thing this codebase has and every spec in this set was
written to inherit them rather than to spend them. Spec 30 §3 is the sharpest
case: the useful aggregate of Aegis's signals is a fact about a repository's
controls, and the same data grouped by author is a fact about colleagues that
spec 06 §9 already refused — so the repository framing is not a compromise, it
is the more actionable of the two.

## D-086 — Rotation wrote the new token where nothing reads it, and reported green

**Status:** Decided and shipped

`rotate_ingestion_tokens` rotates any token past its 90-day mark and then
writes the new value as a **GitHub Actions secret** — unconditionally, whatever
`scanned_by` says. For a Concourse-scanned repository that write *succeeds*:
GitHub accepts a secret for a repository whose Actions lanes were retired
(D-080). The job then called `mark_secret_synced` and reported a successful
rotation.

Meanwhile the pipeline goes on reading `((mykronos-ingestion-token))` from
Vault, which still holds the old value. So every scheduled rotation quietly
desynchronised every Concourse repo, and the repository broke when the
24-hour overlap expired — a failure whose only warning was the uploader's
`X-Mykronos-Token-Rotated` header, which is exactly the warning that was
crashing (#87).

This is D-051 and D-083's shape a third time: a lesson applied to one lane and
not the other. Spec 15 and 16 moved this estate to Concourse; the rotation job
never followed.

**Deferred, not performed.** For anything not scanned by Actions the job now
logs what an operator has to do and moves on, counting the repo as `deferred`.
The alternative — rotate and hope somebody notices — is strictly worse: an
un-rotated token keeps working, while a rotated-and-undelivered one breaks the
repository as soon as the overlap ends. Doing nothing loudly beats doing the
wrong thing quietly.

**What this costs, stated plainly.** Concourse-scanned repositories no longer
rotate automatically. That is a real regression against the intent of a 90-day
rotation, and it is honest about a capability this platform does not have: it
cannot write to Vault. The delivery path — giving the backend a Vault client
and the credentials to use it — is the actual fix and is deliberately not
smuggled in here, because it means the platform reaching into the
infrastructure that runs it, which spec 15 §7 treats as a boundary worth
arguing about rather than crossing quietly.

**What the tests were doing.** All four rotation tests asserted the Actions
write succeeded — against repositories whose `scanned_by` was `concourse`, the
model default, because the test helper never set it. They tested a
configuration this estate does not run and passed. The helper now defaults to
`github_actions` and says why, so the assumption is stated rather than
inherited.

Found while repairing the live token by hand on 2026-08-23, after a manual
rotation expired the value Vault was serving. The manual repair is now: rotate,
write to `backend/.env`, write to Vault, verify against `:8100`.

## D-087 — The score can now go down for work done, and the first attempt rewarded the clock

**2026-08-24. Spec 26 §2. Policy 1.8.**

Oracle had nine modifiers and one negative — the import-reachability discount,
which is a fact about code structure rather than a reward for anything anybody
did. So the number could only ever go up. A team that spent a quarter adding
regression tests, verifying its fixes and clearing its backlog inside target
watched the score not move, which is how a model stops being acted on and
starts being argued with.

`posture_credits` adds three additive negative terms, each gated on evidence a
*different* spec produces: a test pinned to a fixed finding (spec 31), a fix
verified gone by a re-scan of its merge commit (spec 25 §2), a finding closed
inside its remediation window (spec 24 §2). None can be earned by changing a
setting — the rule `maturity-model-v1.yaml` states for its own criteria, for
the same reason.

**The floor is the part that matters.** Credits may not take a repository
below the review threshold while a critical is open. Without that rule the
arithmetic lets a team test its way out of an exploited critical, which is the
single outcome this idea must not produce. It is applied in `evaluate` rather
than inside the snapshot because it needs the score the rest of the model
produced, and the terms are rescaled when it bites so the published breakdown
still sums to what was applied — a breakdown whose parts do not add up is one
nobody can check.

**The first `within_target` was wrong, and the golden tests caught it.** It
credited findings that were open and merely *not late yet*. A repository full
of brand-new criticals is inside every remediation window by construction, so
it would have earned the full six points for having done nothing at all. That
is the evidence-not-switches rule failing in its subtlest form: not a flag
somebody flips, but a credit that rewards the passage of time. The shipped
term counts findings *closed* inside their window over the last 90 days,
windowed for `mean_time_to_fix`'s reason — an all-time rate is dominated by
whatever happened when the platform was switched on.

Worth stating that the pinned golden scores are what surfaced it. The credit
looked right in isolation and looked right in its own unit test; what failed
was a fixed-input score moving in a direction nobody could justify. That is
the whole argument for pinning them.

**Two record-keeping repairs alongside.** The policy file's version log stopped
at 1.4 while the file said 1.7 — 1.5, 1.6 and 1.7 were bumped correctly and
never written down, which made the log the one place a reader could not see
what had changed. Reconstructed from the commits. And its header pointed at
`tests/test_oracle_golden.py`, a file that has never existed; the golden values
are in `tests/test_oracle.py`. A pointer to nothing is worse than no pointer,
because somebody following it concludes there is no such guard.

## D-088 — One test-lane template serves every language, because it declines to know any of them

**2026-08-24. Spec 31 §4, §5. Closes a gap spec 18 §0a named and left.**

Spec 18 §4 reasoned that no single generic workflow template could serve every
repository honestly, because D-046 says a repository's test runner is decided
by its language and its own conventions. It concluded that a real answer needed
a per-language template set or a convention the platform did not have, and left
the Harness tab dark for every Actions-scanned repository.

The reasoning was right and the conclusion did not follow. The template's job
is to *not decide*. `command` is required config with no default; an Actions
install without one is refused with a 422 naming the field; and the rendered
workflow fails loudly rather than silently if it ever renders without one — a
lane that runs nothing and reports success is exactly what the refusal exists
to prevent. One template serves every language precisely because it knows
nothing about any of them.

What it does supply is the part that genuinely is universal, and none of it is
about a test runner: the fail-fast probe, the results contract, an upload that
happens even when the suite fails, and a build failure that comes *after* the
run is recorded. That ordering is the whole point — failing earlier would make
the pipeline's verdict and the platform's record disagree exactly when somebody
needs them to agree.

**A test lane is arbitrary code execution on the runner, by definition.** There
is no version of "run this repository's test suite" that is not "run what this
config says". The boundary is therefore who may set it — capability config is
admin-only — and that a command cannot escape its own step into the rest of the
workflow. Newlines are refused in `command` and in every `setup` line; shell
metacharacters are allowed, because refusing those would refuse most real test
commands. The guard is about YAML structure, not about shell syntax, and
conflating the two would have produced security theatre that broke the feature.

**Found while building: a coverage report was making the record worse.** The
JUnit adapter globs `*.xml`. A repository writing `coverage.xml` beside
`unit.xml` — the default layout of pytest-cov, of jest, and of every Maven
build — was handing a Cobertura document to a JUnit parser, which found no
`testsuite`, warned "the report contains no test suites", and downgraded a
green run to `no_applicable_targets`. The file carrying the most useful context
about a suite had been actively degrading the record of that suite since D-046.
Cobertura and JaCoCo are now recognised by root element.

**Coverage is not a security metric and the page says so beside the number.**
The label is not a disclaimer bolted on; it is the reason showing this is safe
at all. Ninety percent coverage with zero regression links (spec 31 §3) means
the tests are thorough about something other than what has actually gone wrong
here, and a number displayed without that sentence next to it will be read as a
security score by the third person who sees it.

Two smaller calls, both instances of rules already in the file. Null coverage
is not zero coverage — a lane whose runner never wrote a report and a lane
measured at zero are different facts (spec 05 §7a). And sharded suites take the
highest report rather than the sum or the mean: summing exceeds 1.0, averaging
understates a repository whose shards are deliberately narrow, and the largest
is at least a number somebody observed.

## D-089 — A declared control lives in the operational store, and the spec that said otherwise was wrong

**2026-08-24. Spec 28 §3, §4.**

Spec 28 §3.2 specified `repo_controls` as a lake table. That contradicted the
rule this platform had already applied three times, and applying it here makes
the rule explicit rather than incidental.

**Everything in the lake is append-only because its history is evidence.** You
have to be able to say what a finding looked like in March. A declared control
is not an observation: it is an editable statement about the present, corrected
in place when it turns out to be wrong, and the lake's compaction and
partitioning model is built for scan results (spec 05 §2). `RiskProfile`,
`ReachabilityReport` and `TriageState` each made this call and each wrote down
why; the register is the fourth.

**The register exists because a threat model is made of four things and this
platform had one.** Assets, entry points, trust boundaries, mitigations — the
Threat Model tab had findings, grouped six ways. It could say what was found
and not what stops it, and both halves of that get worse as the platform
improves: the tab can only grow more red as scanning gets better, and a team
that spends a quarter adding controls sees no change at all.

**Declared is not verified, and no wording anywhere upgrades it.** A row says a
person asserted this, which is a weaker and clearer claim than a machine
implying it, and it is useful the day it ships where a register waiting on
spec 23 §2's entry-point inventory stays unbuilt for a year. What stops it
being a wiki is that the platform can *contradict* it. `verified_by_capability`
is therefore derived from the control's kind and never accepted from the
caller: it names the capability that could disprove the control, which is a
property of what the control is, not a choice a declarer gets to make. A
control naming a capability that cannot see it would look checked and be
nothing of the kind, and a kind nothing can check — `logging`, `rate_limiting`
— reports `checkable: false` rather than staying quiet about it.

**A control over open findings is shown, not resolved.** The platform has no
basis to decide whether such a control is wrong, bypassed, or narrower than its
description. All three are worth somebody's attention, so both facts are put on
the page together.

**§4's real subject was never the controls.** An empty STRIDE category read as
safe: one with no findings because DAST has never run in this repository
rendered identically to one with no findings because the code is clean, and the
scan-health data that separates them was already being fetched on the same
page. Four states now, and `unscanned` is checked before any other, because
whatever else is true of a category nothing has ever looked at, `clean` is not
it. `scanned` counts capabilities that have actually reported rather than
capabilities that are enabled — a lane switched on last week and never run is
precisely the case this is for.

`unmitigated` renders muted rather than green. Scanned, clean and nothing
declared is a fine place to be and is not an achievement; colouring it like
`mitigated` would put it level with a category somebody built a control for.

**Withdrawing deletes the row**, unlike almost everything else here. A control
is a claim about the present, a withdrawn one is not evidence of anything, and
the audit entry records who removed it. Offboarding does the same to the whole
register — and wiring that up turned up `worklist.purge_for_repo` (spec 27 §3),
written and never called, so triage claims had been surviving offboarding
since. Both are wired to the offboard route now, with their counts in the audit
entry so a deletion is recorded even though the rows are not.

## D-090 — The SBOM was already on disk, and provenance can only ever be a credit

**2026-08-25. Spec 29 §1, §1.4, §2, §3.**

Since spec 07 the platform has generated an SBOM on every Atlas run and only
ever archived it: downloadable per repository, queryable across none of them.
So the one question that matters at two in the morning — *which of our
repositories contain this package* — could not be answered about data the
platform had already collected and was storing as an opaque blob.

**Nothing new is uploaded.** Spec 29 §1.2 says to write the table from the Syft
output the runner already produces; the implementation goes one step further
and adds no upload at all. The archived SBOM's ref already arrives on the Atlas
evidence submission, so the components are extracted server-side from a file
already on disk. That means no workflow resync across every onboarded
repository, and it means a repository whose SBOM was archived last month gets
an inventory on its *next report* rather than on its next resync.

Reading a caller-supplied ref means resolving a path, so it is resolved and
then checked to be inside the archive directory. Somebody who can post
supply-chain evidence must not be able to name `../../etc/passwd`.

**Extraction failures are swallowed, deliberately.** The evidence row is what a
release gate reads and is already in the buffer. Losing a trust score because
an SBOM was truncated in transit would trade the number that matters for a
convenience index.

**Blast radius merges the two populations rather than choosing one.** D-069
counted findings because package names were unavailable; they are available
now. But a portfolio part-way through adopting Atlas has both kinds of
repository in it at once, and picking a single source outright would either
drop the SBOM-less repositories from every count or throw the graph away
because one repository lacks it. The larger of the two wins per package, which
is safe in the one direction that matters: the finding-derived count only ever
*misses* repositories, never invents them. Which population produced a number
is published, for the reason spec 28 publishes `mapping_resolution`.

**Incident mode has three states, and the third is the entire design.**
`affected`, `clear`, and `not_checked`. A repository with no SBOM cannot be
reported as unaffected — converting an absence of data into a statement of
safety is the worst thing this view could do and precisely what it would do by
default. The same rule twice more: a CVE with no threat-intelligence record
reads as *not checked against KEV*, never *not exploited*; and a CVE nothing
has ever reported on resolves to no packages and reports nothing affected,
rather than reporting the whole estate clean of an advisory the platform cannot
recognise.

The batch actions of §2.1 are **not built and are named as not built.** Both
existing paths are per-subject — `triage_story.py` grooms a finding, Patchwork
fixes a finding — while this view's subject is a package across repositories.
Half-building the fan-out would produce exactly what §2.3 refuses: a button
that opens pull requests nobody quite asked for.

**Provenance terms are credits, and that is forced rather than chosen.** Spec
29 §3.2 reads as though they are penalties like every other trust-score term.
They cannot be: the score starts at 100 and subtracts, its ceiling means
*nothing wrong found*, and a term deducting for a missing attestation would
change every repository's score on the day it shipped — which §4 explicitly
forbids. So they add and are clamped at the ceiling. A clean repository gains
nothing and is unchanged; a penalised one recovers ground for building
carefully. That is the only shape a hygiene bonus can take inside a subtractive
score, and it meets the acceptance criterion by arithmetic rather than by a
special case.

Null is not zero on all three. A branch the token could not read has not failed
the signing check, and scoring the two alike turns a permissions problem into a
supply-chain verdict. A signed-commits ratio below ten commits reports
unavailable — one person signing one merge is a coincidence, not a policy.
`attestation_present` is asked only on a release, because a commit with no
published artefact has nothing to attest and `false` would penalise every push.

**Two guards earned their keep here.** The observations run in a step of their
own with `continue-on-error` rather than `|| true` inside the evidence step,
because `test_adapters_phase2` fails the build on a scanner step that
blanket-ignores an exit code — that is how a failed scan comes to look like a
clean one. And the same file caught a release tag being interpolated into a
shell body; a tag is chosen by whoever cut the release, `${{ }}` is substituted
before bash parses it, and the tag is bound to `env:` now.

## D-091 — Governance is read but never rewarded, and the permission to read it stays optional

**2026-08-25. Spec 30. Policy 1.9, shipped dark.**

Aegis has nine signals and every one describes a pull request after the fact.
`self_approval` fires when somebody approved their own change — a symptom.
*"Self-approval is permitted on the default branch"* is the cause, and it was
invisible from anywhere in this platform. The GitHub App has been installed the
whole time and the client had no operation that read a single control.

**`administration: read` is optional, not required.** Spec 30 §1.2 anticipated
"a documented, additive permission bump". Making it required would fail the
spec 02 §8 permission smoke test for every installation that already exists —
turning an additive panel into a breaking change across the estate, to read
settings that are useful and are necessary for nothing else. It lives in a
separate `OPTIONAL_PERMISSIONS` set. An App without it reports every control as
`unknown`, with the reason and the permission named, which is §2's own rule
applied to itself: a permissions gap is not a security failure.

That distinction is enforced twice over. GitHub returns 404 for *"this branch
is not protected"*, which is an answer and a bad one; a 403 raises instead. So
"we were not allowed to look" can never render as "there is no protection" —
the two are opposite claims and confusing them is the worst thing this panel
could do.

**Only a penalty, never a credit, and spec 30 §4 was wrong about that.** §4
expected strong governance to earn the reward side of spec 26 §2 "without a new
term being invented for it". It cannot. Branch protection is a *switch*, and
spec 26 §2.3 refuses credit for switch-flipping in as many words, because the
fastest route to a good score must never be a setting. What survives is the
asymmetry §4's own framing supports: weak controls do not make a SQL injection
worse, they make this repository a worse place for one to be, which is exactly
what the risk profile carries.

**Shipped dark at zero points.** Every repository's score is unchanged until an
operator has seen the panel, agreed the weights in `governance-policy-v1.yaml`
describe their estate, and set a number. A term that began scoring on deploy
day would move every score in the portfolio for a reading nobody had reviewed —
which is the shape of D-048 and D-083's mistake, made once with a gate and not
worth making again with a term.

**Stale is unavailable, not old.** The reading lives in `repo_governance`
because Oracle cannot make an HTTP call, and a reading more than fourteen days
old returns nothing rather than an old number: it describes a repository that
may have been reconfigured twice since. Fewer than five controls read is also
unavailable — a score over two controls is not a weaker posture, it is not a
posture.

It is not a `RiskProfile` column, though §4 puts governance "into the profile".
Every field of a profile is somebody's stated belief about what the application
is; a machine-read setting in the same row would be indistinguishable from one,
which is the distinction spec 21 §1 built that table around.

**Two smaller calls.** Rulesets merge as *the strongest wins*: a repository can
use branch protection, rulesets, both or neither, and reading only the older
model would report a modern well-governed repository as wide open. Only
`active` rulesets count — an `evaluate`-mode ruleset is a dry run that blocks
nothing. And a single required approval is `partial` rather than `on`, because
that is precisely the configuration `self_approval` and `sole_approver` fire
under, and calling it "on" would put a repository one rubber stamp from a bad
merge level with one that requires two people.

`list_admin_bypasses` from §1.2 does **not** ship: the endpoints behind it are
plan-gated and it would be a permanently empty column for most installations.
`enforced_for_admins` answers the question that actually matters — whether the
rules bind administrators at all — and is weighted alongside the two entry
controls for that reason.

## D-092 — The detectors get a ground truth, and the corpus is counted in nothing

**2026-08-25. Spec 23 §1.**

Spec 04 §7's acceptance criterion has never been implementable. Its bar — "at
least one `Finding`" — cannot distinguish a scanner catching nine of ten seeded
injections from one catching one, and there was no seeded corpus to try it
against. A search for precision, recall, false negatives or ground truth across
this repository returns prose about the concepts and no measurement of any of
them.

So the platform runs fifteen checks and cannot say how well any of them works
on code like its own. That is worth fixing before anything agentic is built and
independently of whether anything agentic is ever built, which is why spec 23
gates its other four workstreams behind this one.

**`synthetic` exists so the corpus is counted in nothing.** Seeded
vulnerabilities are real findings in the lake — they have to be, or grading
them would exercise a different code path from the one that runs — so without
the flag the corpus becomes, permanently, the fleet's worst repository, and
deliberately vulnerable code is counted as estate risk. The portfolio summary,
the trend series and the fleet risk mean all skip it.

Only the *aggregates* skip it. The bench repository is listed, opened and
scanned like any other, because a benchmark whose results nobody can inspect is
a benchmark nobody trusts.

**Stated at onboarding, never inferred.** Guessing from a repository name is how
a *real* repository silently stops being counted, which is a worse failure than
a corpus that is counted until somebody notices.

**Which repositories are synthetic is passed into the lake queries, never
looked up by them.** That fact lives in the operational store, and a lake query
reaching into the database to find it out would couple the two in the one
direction this codebase has kept clear.

**Matching is by file and line window, never by rule id.** A rule identifier is
a free-form string the reporting tool chose (spec 18 §6), so pinning a grade to
one would grade the tool's *naming* rather than its detection, and every
scanner rename would need a manifest rewrite. Five lines of drift are allowed,
because the finding fingerprint already assumes that much (spec 05 §5) — a
grader stricter than the platform's own identity model would report regressions
the platform does not believe in.

**The grade reads the lake, not the scanner's output file.** What is graded is
what the platform *ingested*, so an adapter dropping a finding on the way in is
a detection failure this notices. Grading raw tool output would measure the
tools and quietly exempt the platform.

**No precision figure, and `unmatched` fails nothing.** The corpus is seeded,
not *clean*: an unmatched finding may be a genuine flaw somebody wrote by
accident while writing a fixture. Calling it a false positive would manufacture
a quality number out of an assumption. It is a property on the report for a
human to investigate, and a lane whose green depended on nobody having written
an extra bug into a fixture would be green for the wrong reason.

A capability with nothing seeded has **no** recall rather than zero — spec 31
§3's empty-denominator rule applied to a second number, for the identical
reason. And `--fail-under` is off by default: the first runs of a new corpus
establish a baseline, and a threshold picked before there is one is a number
somebody invented.

**What is not built, and cannot be from here.** Creating `mykronos-bench`,
writing deliberately vulnerable fixtures into it, and installing the App on it
is an operator action — and one that should be taken deliberately rather than
automated by a security platform. The platform side is ready; the corpus is a
person's decision.

---

## D-093 — Three repositories leave Concourse by dissolving the LAN, not by moving the runner

**2026-08-28. Spec 32.**

`mykronos`, `keel` and `personal-soc` move from Concourse to GitHub Actions.
TheHub does not. Concourse, Vault, `ConcourseClient` and `scanned_by=concourse`
all stay, because the pipeline that deploys to production is the one that is
not moving.

Spec 15 §2 gave three reasons a second CI system existed, and two of them have
expired. Going public settles the Actions-minutes reason outright. The first
reason — a second execution environment inside the LAN, for network scanning —
**was already false and nothing said so.** `personal-soc.yml`'s
`netassess-ingest` records that the scan runs under a Windows Scheduled Task
and publishes to MinIO, because an nmap sweep from a Concourse task reported
all 256 addresses up while the host's ARP table had 38: Docker Desktop's NAT
answers every probe, and MAC-keyed inventory needs L2 adjacency a container
does not have. The capability that justified a LAN worker had already left it.
Spec 14 §4 and spec 15 §8 still say otherwise and need amending.

**The LAN dependencies dissolve; they are not relocated.** This is the whole
decision, and the alternative is what makes it one. A self-hosted Actions
runner would have kept every endpoint where it is and cost almost nothing to
migrate — and a public repository with a self-hosted runner means a fork's pull
request executes at `192.168.0.14`, beside the registry, MinIO, TheHub's
Postgres and the Vault. That is precisely what spec 14 §4 and spec 15 §7
refused when the question was Concourse's worker, and the answer does not
change because the runner has a different logo. A third option — a private ops
repository owning the LAN runner, driven by `repository_dispatch` — is secure
and was rejected for keeping two CI systems and adding a hop that makes "which
build produced this finding" harder to answer.

So each endpoint moves to something that is reachable from anywhere, and each
move is worth making on its own terms rather than only as migration cost. The
registry becomes GHCR, gaining authentication it does not have today and
immutable digests a tag race cannot defeat. Build artifacts and SBOMs become
Actions artifacts and release assets, at the same retentions spec 15 §5 already
specified. The netassess ingest becomes a backend scheduled job, which is what
it always was — it consumes no source and is triggered by an artifact
appearing, and it lived in Concourse because Concourse was the only scheduler.

**The demo environment is the one that pays for itself immediately.**
`demo-and-dast` carries `serial: true`, a "rebuild it on the host" preflight
and a seeded-repository count check, and all three exist because one
long-lived, hand-maintained stack is shared between builds — builds 8 and 9
wiped build 7's ZAP site tree. An ephemeral stack stood up inside the job
cannot be shared, cannot be stale, and cannot be missing. It is also the
largest piece of work in the migration and the one most likely to need a second
attempt, because `Invoke-DemoRebuild.ps1` is PowerShell and the seeding is what
the count check guards.

**Install stays a pull request; enable and disable become API calls.** Adding
or removing code that runs in a repository is a change a human reviews, which
is spec 03 §3 and is not weakened. But spec 03's `--soft-disable` — set the job
to `if: false` — makes "stop this lane now" a commit, a pull request and a
review round-trip, when what an operator needs at 2am is the `fly pause` that
spec 15 §4a.1 calls "state only an operator remembers". GitHub has a
first-class API for exactly this, so the off switch is one call and the file on
disk still says what the lane does when it comes back.

**Workflow state is derived, never stored**, for the same reason §4a derives
the pipeline name: a `workflow_enabled` column is a second place for the truth
to live, and it is wrong the moment somebody clicks Disable in the GitHub UI.
`disabled_inactivity` is rendered distinctly from `disabled_manually`, because
a scheduled lane GitHub switched off after 60 days of no pushes is a real
coverage gap that otherwise looks identical to a deliberate pause.

**Enable and disable do not touch `enabled_capabilities`.** A disabled workflow
is an enabled capability whose lane is paused. Conflating them would make the
grant registry lie about what may write, and the grants are what the coverage
cross-check trusts for any repository the installer's ledger never moves for
(spec 03 §3a).

**`ci.py` is split behind a protocol rather than rewritten.**
`Reporting`, `StageCoverage`, `coverage()` and `reconcile()` already take job
names, statuses and timestamps and know nothing about Concourse; only
`ConcourseClient` does. Those two functions are also the ones §4a.1 records
getting wrong twice. An `ActionsClient` beside the existing client keeps them
untouched, and dispatches on `scanned_by` exactly as `scan_now` and fix
verification already do.

Two properties change and are worth naming rather than discovering. The
job-to-capability mapping stops being a heuristic — the installer chose the
filename, so `mykronos-<capability>.yml` is exact for every installed lane.
And the read **stops being anonymous**: Concourse was read with no credential
because the pipelines are `public: true` on a loopback-bound server, while
GitHub needs an installation token, from inside a dashboard request, against a
5000/hour limit shared with token rotation, the installer and Patchwork. The
status panel is the least important consumer of that budget and must be the
first to give up, which makes a cache and a ceiling part of the design rather
than an optimisation.

**The parity check decides when Concourse is destroyed, not a green badge.**
Every capability that reads `reporting` under Concourse must read `reporting`
under Actions first. The lanes run in both systems for a period, and the
duplicate findings that D-039 removed are accepted deliberately and briefly —
the ingestion upsert makes the two indistinguishable, which is the only reason
a parity check is possible at all. Spec 15 §4a.1's first day of existence found
a lane green on every build that had never reported once; this migration is the
largest opportunity to recreate that failure since it was written.

**No App re-registration is needed, contrary to the first draft of spec 32.**
That draft made granting `actions: write` and re-consenting every installation
the blocking first step. `actions: write` has been in `REQUIRED_PERMISSIONS`
since the scan-now button needed it for `dispatch_workflow` (spec 17 §2.5), and
it is the same permission GitHub documents for enabling, disabling and reading
workflows. So §6 and §7 are buildable today with no 403 window and nothing to
schedule around. Recorded rather than deleted, because "the App needs a new
permission" is a prerequisite that gets planned around for weeks.

**What is not built, and cannot be from here.** Making the three repositories
public is an operator action, and it is gated on a full-history secret scan
rather than on the working-tree scans the `secrets` lanes already run.

## D-094 — Both halves of D-051, and a parity check that could not see an empty repository

**Date:** 2026-08-29 · **Supersedes nothing; completes D-051**

Two pins install the `mykronos` package into the same job:
`mykronos_package_spec`, which the aegis, atlas, ai and sast templates
pip-install for their collectors, and `upload_action_ref`, which the shared
upload action is resolved at. The templates install first. `pip install` of an
already-satisfied requirement is a no-op — no version comparison, no warning —
so whichever runs first decides the uploader, and the second silently does
nothing.

`upload_action_ref` had been moved forward repeatedly. `mykronos_package_spec`
had never moved at all: it was still `@v1` while the tag series reached `v7`.
So the package spec won every time, and the action's pin was decorative. The
lanes failed as

    argument --capability: invalid choice: 'ai'

which is v1's `Capability` enum, in a job whose action was pinned to a commit
that knew both `ai` and `atlas`. `sast` and `aegis` were unaffected only
because v1 already knew those names — which is why this survived so long. It
presented as two broken capabilities rather than as a stale pin.

**Both now pin the same 40-character commit, and a test asserts they are
equal.** Commit rather than tag on both, so the invariant is checkable without
a network call. The tag is `v8`, cut deliberately at current main rather than
reusing `v7` — which is 16 commits behind and lacks the containers root-context
fix, the named qa checks, the fail-fast retry, and the action provenance line
that is D-051's own remedy.

**The parity check was passing the migration it exists to block.** Retiring a
pipeline is authorised by "no capability got worse", and "worse" needed an
ordering, so `_STATE_RANK` put seven states on a line. Four of those positions
are real; three were invented, and the invention was `not_run` above `silent`.
It sounds right — a lane that has not fired yet is more innocent than one
visibly failing to report. Innocent is not the question. Covered is, and
neither state is covered.

So `mykronos parity ToddGBenson/keel` reported three capabilities `improved`,
printed "No capability is worse under Actions", and exited 0 — the
authorisation to delete keel's pipeline — while every Actions lane on keel had
never executed once.

The states are now two tiers. `reporting` and `event_driven` are coverage;
`no_job`, `not_run`, `never_reported`, `silent` and `not_enabled` are not, and
within that group there is no order, because they differ in what a human should
go look at and not in how covered the repository is. Moving between them is
`no better` — a verdict that did not exist, which is why `improved` was
returned instead.

`not_enabled` leaves the covered tier, which is a change. It ranked alongside
`reporting` because a capability nobody asked for is not a gap — true when both
sides agree, and that case still compares as `same`. But it also meant a
capability reporting under Concourse that merely never got enabled in the
Actions ledger passed in silence, and forgetting to enable something is the
most likely migration mistake there is.

**A gate that detects loss cannot detect absence.** "Nothing got worse" is
satisfied by two systems that both do nothing, so the verdict now states
coverage on both sides before stating change, and refuses outright when the new
system covers nothing: that is not parity, it is two systems agreeing about
silence.

**What that check now says about keel: covered 0 under Actions, 0 under
Concourse.** Which is the real finding, and it changes the migration. keel's
Concourse lanes were already `silent`, so there is no coverage to migrate and
nothing that retiring the pipeline would lose — but neither is there a green
Actions run to retire it *on*. keel needs its lanes made to report before
anything is deleted, not a pipeline retirement. Recorded as L0005.

---

## D-095 — A setting that contradicts a refusal is removed, not documented

**Status:** Decided, spec updated
**Spec:** [03 §5.1](../specs/03-workflow-installer.md), [08 §3](../specs/08-patchwork-integration.md)

`repo_onboardings.auto_merge_workflow_prs` is removed from the model, the
`RepoDetail` schema and the API response, and the column is retired from
existing databases on start.

**Why:** it could never act. Spec 08 §3 deliberately gives `GitHubClient` no
merge method, and two tests assert that no method whose name contains "merge"
exists on the interface or on either implementation. So the setting was stored,
returned to any consumer of the contract, rendered by nothing, and consumed by
nothing — the only thing it could change was what an operator believed the
platform would do.

Two specs each correct on their own produced a dead option between them. The
alternative — documenting it as "not implemented yet" — keeps a toggle that
quietly contradicts a refusal D-085 counts among the most valuable properties
in the codebase. A refusal that ships with an off switch reads as a default,
not a guarantee.

Spec 03 §5.1 now states the refusal positively, so the next reader finds an
answer rather than a gap.

**Retirement mechanism.** There is no migration framework here; `create_all`
plus `add_missing_columns` (D-052) only ever *adds*. A removed column would
therefore persist in every deployed database and be absent from every freshly
built test database — the same disagreement D-052 was written to end, pointing
the other way.

`Database.drop_retired_columns` closes it against an explicit
`RETIRED_COLUMNS` list. Deliberately **not** the obvious inverse of
`add_missing_columns`: "drop every column the models do not declare" is a
data-loss bug waiting for its first rollback, because a deploy that briefly
runs the previous image would drop live columns and repopulate nothing. Naming
each retirement means a column only goes when somebody decided it should. A
test asserts no name is in `RETIRED_COLUMNS` and on a model at once — that
combination would drop the column on every start and fail on the next write.

Regression tests: `tests/test_patchwork.py::TestTheHardConstraint::test_no_setting_anywhere_claims_the_platform_can_merge`,
`tests/test_schema_upgrade.py::TestARetiredColumn`.

---

## D-096 — The LLM fix generator is withdrawn, not implemented

**Status:** Decided, spec updated
**Spec:** [08 §2 stage 4, §5](../specs/08-patchwork-integration.md)

`PatchworkConfig.fix_generator_url` is removed from the schema, the API and the
pipeline. Spec 08 §2 now specifies deterministic fixers as the only generator.

**Why:** it never made a call. The value was validated as an `http(s)` URL,
persisted, exposed through the API and threaded through `PatchworkPipeline` to
exactly one place — a conditional choosing between two rationale sentences. No
HTTP request was ever issued to it.

The failure mode was worse than an inert setting. **Unset**, a finding with no
deterministic fixer got "no fix generator endpoint is configured for this
deployment, so nothing was attempted" — which invited an operator to configure
one. **Set**, the same finding got "No deterministic fixer matches this
finding" — which reads as though the generator had been consulted and declined.
Configuring the endpoint changed the sentence and nothing else, and the new
sentence was less true than the old one.

**Why withdrawn rather than built.** Spec 08 §2 described the feature but never
specified it: no request or response contract, no timeout or failure
behaviour, no statement of whether a failed generation blocks the pull request,
no cost or rate ceiling, and nothing about what stops a generated fix reaching
a reviewer as though a deterministic fixer had produced it. Building it would
have meant inventing all of that against no endpoint to test with. The
deterministic fixer is the half that works.

Adding an LLM generator later is a design change that reverses this decision
and answers those questions first.

**Migration.** The setting lives in the `capability_configs` JSON blob, not a
column, so there is nothing for `RETIRED_COLUMNS` (D-095) to drop. But the
config models are `extra="forbid"` while the read path deliberately returns
stored config unvalidated (`capability_config_for`), so a repository configured
before this change keeps the dead key in its stored JSON — and the next save,
the UI echoing back what it loaded, would fail on a field the operator can
neither see nor remove.

`RETIRED_CONFIG_KEYS` strips withdrawn keys on the way into `validate_config`
and logs that it did. Deliberately narrow: an unknown key is still refused, so
this is a named exception rather than a hole in `extra="forbid"`.

Regression tests: `tests/test_patchwork.py::TestTheHardConstraint::test_no_fix_generator_setting_exists_anywhere`,
`::test_a_config_still_carrying_the_withdrawn_key_can_be_saved`,
`::test_an_unknown_key_is_still_refused`.

---

## D-097 — Rotate only when the job can reach every reader, not when one field says so

**Status:** Decided and shipped
**Spec:** [15 §7](../specs/15-concourse-pipeline.md), supersedes nothing — extends [D-086](#d-086--rotation-wrote-the-new-token-where-nothing-reads-it-and-reported-green)
**Trigger:** four lanes down on 2026-08-31

`rotate_ingestion_tokens` now also asks Concourse whether a pipeline exists for
the repository, and defers when one does — or when the answer cannot be
established.

**Why D-086 was not enough.** Its guard is `scanned_by != "github_actions"`.
`scanned_by` holds one value and, by its own docstring, "records intent, not
coverage". A repository migrating from Concourse to Actions under spec 32 is
scanned by *both*: `ToddGBenson/mykronos` declares `github_actions`, has 14
active Actions workflows, and has a Concourse pipeline reading the same
ingestion token from Vault.

So it passed D-086's check. A rotation on 2026-08-30 issued a new token, wrote
it to the Actions secret, marked the repo synced and reported green — while
Vault kept the old value. When the 24-hour overlap expired, `unit`,
`lint-and-types`, `qa-spec-links` and `frontend` all began failing on the
ingest preflight with a 401, each inside two minutes. This is D-086's own
failure mode in the one shape D-086 did not cover, which is the third time a
lesson has been applied to one lane and not the other (D-051, D-083, D-086).

**The question is who reads the token, not what the repository declares.** The
job's only delivery path is a GitHub Actions secret, so it may rotate only when
that reaches everybody. A Concourse pipeline is a second reader it cannot write
to. `ConcourseClient.has_pipeline_for` answers from the server rather than from
a declaration, so a repository cannot be wrong about itself.

**Three answers, and the third is the point.** `True`, `False`, or `None` for
"could not be established" — Concourse unreachable, or not configured. `None`
defers. Failing open would tell the job "nobody else reads this" on any day
Concourse happened to be down, which is exactly how the credential
desynchronised; and D-086's reasoning applies unchanged — an un-rotated token
keeps working, a rotated-and-undelivered one breaks the repository when the
overlap ends.

**What this does not do.** It still cannot deliver to Vault. Concourse-scanned
repositories still do not rotate automatically, and D-086's note that this is a
real regression against a 90-day rotation stands. This decision makes the
deferral *correct*, not unnecessary. The actual fix remains a Vault client in
the backend, which spec 15 §7 treats as a boundary worth arguing about rather
than crossing quietly.

**A second trigger, faster than the 90-day clock.** An active token with
`secret_synced = 0` is picked up by the unsynced sweep and rotated *again* as a
resync, on the job's ordinary interval. A manual repair that delivers to Vault
and `.env` but not to Actions leaves precisely that state, so the repair arms
the recurrence unless the flag is set. The new guard covers that path too.

**What the tests were doing, again.** D-086 recorded that all four rotation
tests asserted against a configuration this estate does not run. The equivalent
gap here was that none of them described a repository scanned by both systems —
the only configuration in which the bug appears. There is now a test for it,
and one asserting an Actions-only repository still rotates, so the guard cannot
quietly end rotation altogether.

**A third reader, found 2026-09-01.** After the `mykronos` and `.env` copies
were repaired, keel's Concourse pipeline was still failing all three of its
`mykronos-*` jobs on the same 401. It holds its own copy at
`concourse/main/keel/mykronos_ingestion_token`, and keel is
`scanned_by=github_actions` — so the rotation job wrote its new token to the
GitHub Actions secret and left Vault behind, exactly as it did for mykronos.
Same bug, third instance, found only because B-012's inventory went looking at
keel for an unrelated reason. Repaired by rotating and delivering to *both*
readers in one operation, which is the practice this decision exists to make
the job follow.

Regression tests: `tests/test_jobs.py::TestRotation::test_a_repo_scanned_by_both_systems_is_deferred`,
`::test_an_actions_only_repo_still_rotates`,
`::test_an_unreachable_concourse_defers_rather_than_assumes`,
`::test_the_unsynced_sweep_cannot_rotate_a_both_systems_repo`,
`tests/test_ci.py::TestWhoReadsTheToken`.

## D-098 — A briefing after every deploy, led by the lanes that cannot close

**2026-09-01.** The dashboard reported 115 open DAST findings against
`ToddGBenson/mykronos` and was correct. The findings were also fixed: the
security headers they name are set in `frontend/next.config.ts` and served on
the wire. The number had been meaningless for two days and nothing said so.

The mechanism is `reconcile_absences` requiring `REQUIRED_ABSENCES = 2`
consecutive **successful** scans before a finding becomes `fixed` (spec 05 §5).
That rule is right — it is flap protection for `resolved_at` and every metric
built on it — and it has a consequence nobody had stated: **a capability whose
lane is failing cannot close anything.** The DAST lane had failed seventeen
times running. However thoroughly the defect was fixed, no scan would ever
observe its absence.

So the decision: **every deploy ends with a briefing, and its first section is
lanes that cannot close findings.** Not severity, not the worst repository —
those surfaces already exist and neither would have caught this. `deploy.ps1`
runs `mykronos briefing` after health passes, and never fatally: a deploy that
worked did work, and a briefing that cannot read the lake must not retract it.

Three constraints the implementation holds to.

**A group gets a button only where a route already exists.** A stalled lane
gets `POST /api/repos/{repo}/scan?capabilities={cap}`, which is real. Sast gets
the classifier queue. Containers, secrets and iac get nothing, because a
base-image rebuild is a Dockerfile change and a committed secret needs rotating
before anything else. This is B-021's lesson applied before the fact rather
than after: an affordance that looks like capability and is not is worse than
an absence, and the Remediation tab already taught us that once.

**A stalled lane's button says "repair the job first".** Re-running a broken
workflow fails again and closes nothing, and a one-button remediation that
quietly does nothing is the failure mode this whole entry is about.

**The numbers must not overstate what was read.** The failure streak is counted
over a ten-run window, so it reads "at least 10" when it fills that window —
printing a bare count said ten failures where the truth was seventeen, which
reads as a bad afternoon rather than a two-day outage. Last-success is queried
over all history instead, or a lane that failed more times than the window is
wide would report as having never worked.

**A lane can stall in two ways, and the second was nearly missed.** The first
version only looked at `scan_status`, so it caught mykronos DAST failing
seventeen times and reported the estate otherwise fine. It was not fine.
`ToddGBenson/TheHub` had not scanned since 2026-08-27 — every lane *succeeded*
and then simply never ran again. A check that reads `scan_status` sees nothing
wrong with that: there is no error to notice.

Silence is the worse of the two, and by some distance. 316 TheHub findings were
frozen behind it against 115 behind the lane that was visibly broken. Together
that is 431 of 475 open findings across the estate — **91% of the backlog could
not close**, and the platform reported a healthy dashboard.

So silence is detected too, measured against **each lane's own cadence** rather
than a fixed threshold. This estate mixes daily and weekly schedules and runs
some lanes on every push; any single number either misses a stopped daily lane
or cries wolf at every weekly one. The median gap between a lane's own runs,
times three, floored at two days. Median rather than mean, because a
push-triggered lane has a few enormous gaps around holidays and a mean would
let it go dark for a fortnight before anybody was told.

The two reasons get different wording on the button, and flattening them would
make it a lie half the time: a silent lane was working when it stopped, so
dispatching it *is* the fix, while a failing lane will just fail again. Telling
somebody to repair a job that has nothing wrong with it is how a briefing gets
ignored.

Filed as B-024. Tests: `tests/test_briefing.py`.

**A page for the question people actually ask, added 2026-09-01.**
`/remediate` answers *how do I remediate the open findings today*, and it is
ordered by **what it costs you** rather than by severity. That inversion is the
whole design: a critical nobody can close today belongs below a hundred
findings that close for free.

The section that makes it work is the one added last — **findings already gone,
waiting only on a sweep.** Separating those from the open count is what stops a
backlog looking larger than the work in it. Measured on the day: 593 open, of
which 109 needed nothing at all, 316 could not be touched because their lanes
were not producing scans, and 0 were auto-fixable. That leaves 168 that were
actually work, and no surface in the platform had ever said so.

`awaiting_closure` deliberately mirrors `reconcile_absences` — the same
`CONFIRMING_STATUSES`, the same "not among the most recent runs" test, the same
`asset_id`/`repo_full_name` join — and a test asserts the two agree on the same
estate. A page that promised something would close on a different rule from the
one that closes it would be worse than saying nothing.
