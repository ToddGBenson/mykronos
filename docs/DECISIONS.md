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

## D-007 — Deferred to a later phase

Recorded so they are not mistaken for oversights.

| Deferred | Why | Lands in |
|---|---|---|
| Absence reconciliation (mark `fixed` after two consecutive absent scans, spec 05 §5) | Needs scan-completeness tracking per capability, which needs onboarding to know what *should* have run | Phase 1–2 |
| `finding_reopened` events persisted as retro signals | Currently logged and returned from `compact()`; there is no Knowledge Store to write them to yet | Phase 5 |
| `POST /api/ingest/{capability}` bodies | Route returns 501 naming the phase; the target tables belong to Aegis/Atlas/Patchwork/Oracle | Phases 3–6 |
| Raw tool output archival (`raw_output_ref`, spec 05 §7) | Field is carried through the schema; the upload path and retention sweep are not built | Phase 1 |
| 90-day token rotation job | Registry records `rotate_after`; nothing acts on it. See the open question below | Phase 1 |
| Rate limiter behind shared storage | In-process memory is correct for a single-process deployment | When the backend scales out |

---

## Open questions carried from the spec review

Not yet decided; each needs an answer before the phase named.

| # | Question | Blocks |
|---|---|---|
| 1 | GitHub App needs `workflows:write` — absent from spec 02 §4 / 12 §6. Without it the installer cannot commit workflow files at all | Phase 1 |
| 2 | GitHub App needs `secrets:write` — spec 12 §6 claims otherwise. The security *intent* holds (GitHub never returns secret values) but the stated mechanism is wrong | Phase 1 |
| 3 | Ten tokens per repo on ten independent 90-day clocks is ~2,000 secrets and ~22 rotation PRs/day at 200 repos. Keep the scoping, change the rotation shape | Phase 1 |
| 4 | Oracle's score saturates: criticals weigh 40, clamped at 100, so three of them pins every repo at 100 forever | Phase 3 |
| 5 | "Advisory by default" has no stated path to ever turning blocking on. Needs a shadow-mode metric to make the case with data | Phase 3 |
