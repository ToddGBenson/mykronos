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

**Status:** Decided, **spec follow-up needed**
**Spec:** [05 §4](../specs/05-datalake.md)

Spec 05 §4 says the endpoint is "called first, at workflow start", but nothing
defines how `completed_at`, `scan_status` and `finding_count` get populated —
they are not known until the scan ends. There is no finalise endpoint.

The client generates `scan_run_id` before scanning and POSTs twice: once at
start, once at completion. The second POST upserts onto the first by
`scan_run_id`. This keeps one row per run (spec 05 §3) and stays idempotent
under workflow retries.

**Spec follow-up:** amend 05 §4 to document the two-phase call and the upsert
key. Not done yet — flagged rather than silently invented.

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

**Status:** Decided, **spec follow-up needed**
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

**Spec follow-up:** add a row to spec 01 §3's tech-stack table for the
operational store, so the next reader does not have to infer it from the code.

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

**Status:** Decided, **spec follow-up needed**
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

**Spec follow-up:** correct the §4 signature. Low priority — it is imprecision
rather than a contradiction, and nothing is blocked by it.

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

## D-007 — Deferred to a later phase

Recorded so they are not mistaken for oversights.

| Deferred | Why | Lands in |
|---|---|---|
| `finding_reopened` events persisted as retro signals | Currently logged and returned from `compact()`; there is no Knowledge Store to write them to yet | Phase 5 |
| `POST /api/ingest/{capability}` bodies | Route returns 501 naming the phase; the target tables belong to Aegis/Atlas/Patchwork/Oracle | Phases 3–6 |
| Raw output **retention sweep** (spec 05 §7) | Archival is built; the scheduled purge that bounds disk usage is not | Phase 7 |
| Rate limiter behind shared storage | In-process memory is correct for a single-process deployment | When the backend scales out |

---

## Open questions carried from the spec review

| # | Question | Blocks | Status |
|---|---|---|---|
| 1 | GitHub App needs `workflows: write` — absent from spec 02 §4 / 12 §6. Without it the installer cannot commit workflow files at all | Phase 1 | **Resolved** — D-008 |
| 2 | GitHub App needs `secrets: write` — spec 12 §6 claims otherwise | Phase 1 | **Resolved** — D-008 |
| 3 | Ten tokens per repo on ten independent 90-day clocks | Phase 1 | **Resolved** — D-009 |
| 4 | Oracle's score saturates: criticals weigh 40, clamped at 100, so three of them pins every repo at 100 forever | Phase 3 | Open |
| 5 | "Advisory by default" has no stated path to ever turning blocking on. Needs a shadow-mode metric to make the case with data | Phase 3 | Open |

Nothing now blocks Phase 1. Questions 4 and 5 are Oracle's, and are best
answered with real findings in the lake — defer until Phase 2 has produced
some.
