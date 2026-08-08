# Spec 05 — Data Lake

**Status:** Approved for build
**Depends on:** [01 — Architecture](01-architecture.md)

---

## 1. Purpose

Provide **one local, normalized, queryable store** that every capability
(SAST, DAST, Secrets, Containers, IaC, Cloud, Aegis, Atlas, Patchwork,
Oracle) writes its results to, and that the Dashboard (spec 10) and the
Knowledge Store (spec 11) read from. This is the single most important
integration point in the whole system: **every scan must run its scan and
then upload its results here** — no capability is allowed to keep its
results siloed in its own tool's UI only.

## 2. Storage engine

- **Engine:** DuckDB, an embedded analytical database, reading/writing
  **Parquet files on local disk** (or a local-network-attached volume).
  No cloud storage service, no external SaaS — this satisfies the "local
  data lake" requirement directly: data never leaves the org's own
  infrastructure boundary.
- **Layout:**
  ```
  datalake/
  ├── findings/                # partitioned by dt=YYYY-MM-DD
  │   └── dt=2026-08-07/part-0000.parquet
  ├── scan_runs/
  ├── risk_decisions/           # written by Oracle, spec 09
  ├── remediation_events/       # written by Patchwork, spec 08
  ├── insider_risk_signals/     # written by Aegis, spec 06
  ├── sscs_evidence/            # written by Atlas, spec 07
  └── _manifest.duckdb          # DuckDB catalog/views over the above
  ```
- Writes happen via an **append-only ingestion buffer**: the Ingestion API
  writes incoming records to a small write-ahead JSONL buffer file
  immediately (durability), then a background compaction job batches the
  buffer into Parquet partitions every N minutes (default 5). This avoids
  small-file-per-request Parquet writes while still making data available
  to DuckDB queries within minutes.
- Upgrade path: because ingestion is via an HTTP API and not direct file
  writes, the storage engine can later be swapped for a networked Postgres
  or a real data lake (e.g., an on-prem MinIO + Iceberg) without changing
  anything upstream of the Ingestion API.

## 3. Core schemas

### `ScanRun` (one row per workflow run per capability)
| Field | Type | Notes |
|---|---|---|
| `scan_run_id` | UUID | PK |
| `repo_full_name` | string | |
| `capability` | enum | `sast, dast, secrets, containers, iac, cloud, aegis, atlas, patchwork, oracle` |
| `tool_name` | string | e.g. `codeql`, `trivy` |
| `tool_version` | string | |
| `commit_sha` | string | |
| `branch` | string | |
| `pr_number` | int, nullable | |
| `triggered_by` | enum | `pull_request, push, schedule, workflow_dispatch, manual` |
| `github_workflow_run_id` | string | for traceability back to Actions logs |
| `started_at` / `completed_at` | datetime | |
| `scan_status` | enum | `success, no_applicable_targets, partial_failure, failure` |
| `finding_count` | int | denormalized for fast dashboard queries |
| `raw_output_ref` | string | pointer to the archived raw tool output (see §7) |

### `Finding` (one row per normalized security issue)
| Field | Type | Notes |
|---|---|---|
| `finding_id` | string (hex) | PK — deterministic hash over a *stable location fingerprint*, computed server-side by the Ingestion API, never supplied by the client. See §5 for the exact input tuple. |
| `scan_run_id` | UUID | FK → ScanRun |
| `repo_full_name` | string | |
| `capability` | enum | |
| `rule_id` | string | tool's rule/check identifier, e.g. `CWE-89`, `CKV_AWS_23` |
| `title` | string | |
| `description` | text | |
| `severity` | enum | `info, low, medium, high, critical` (normalized from tool-native scale) |
| `cvss_score` | float, nullable | |
| `file_path` | string, nullable | |
| `line_start` / `line_end` | int, nullable | **Display metadata only — not part of `finding_id`.** Updated in place each time the finding is re-observed, so the dashboard always deep-links to the current location. |
| `symbol` | string, nullable | Enclosing function/class/resource name at the finding's location, where the tool reports one. Part of the fingerprint (§5). |
| `code_snippet` | text, nullable | The few lines of source at the finding's location, captured by the adapter at scan time while the repo is checked out. Normalized and hashed into the fingerprint (§5); retained for display and for re-fingerprinting during a future migration. |
| `fingerprint_version` | string | Which fingerprint rule produced `finding_id` (e.g. `v2-snippet`, `v1-line`). Required so a future change to the rule is detectable and migratable rather than silently re-identifying every finding. |
| `package_name` / `package_version` | string, nullable | for SCA/dependency findings |
| `status` | enum | `open, fixed, false_positive, accepted_risk, suppressed` |
| `first_seen_scan_run_id` | UUID | |
| `last_seen_scan_run_id` | UUID | |
| `first_seen_at` / `last_seen_at` | datetime | |
| `resolved_at` | datetime, nullable | |
| `raw_finding_json` | JSON | full original tool record, preserved verbatim |

### `RiskDecision`, `RemediationEvent`, `InsiderRiskSignal`, `SscsEvidence`
Owned by Oracle (spec 09 §3), Patchwork (spec 08 §4), Aegis (spec 06 §3),
and Atlas (spec 07 §3) respectively — each is its own table in the data
lake but follows the same base fields (`repo_full_name`, `commit_sha` or
`pr_number`, `created_at`, plus capability-specific payload).

## 4. Ingestion API

### Auth

Every onboarded repo's workflows authenticate to the Ingestion API with **one
Mykronos-issued opaque bearer token per repo** (not a GitHub token), stored as
a single GitHub Actions repo secret named `MYKRONOS_INGESTION_TOKEN` by the
Workflow Installer (spec 03 §4a). The token:

- Is bound to exactly one `repo_full_name`. This is the isolation boundary.
- Carries a set of **capability grants**, held server-side in the token
  registry rather than encoded in the token string, so grants can change
  without reissuing the secret.
- May call the ingestion endpoints only for its own repo, and only for
  capabilities currently granted to it.
- Is rotated every 90 days by a scheduled job, with an overlap window (below).

Only the token's SHA-256 and its metadata are persisted; the plaintext exists
once, at issuance, on its way into the repo secret (spec 12 §2).

#### Why one token per repo, and not one per capability

An earlier draft scoped a separate token to each `(repo, capability)` pair.
That boundary does not exist at runtime: **GitHub Actions repository secrets
are readable by every workflow in the repo.** A compromised runner in repo X
can read all of repo X's secrets regardless of which workflow they were
provisioned for, so it already holds every one of that repo's capability
tokens. Splitting them bought no containment while costing:

- **Secret budget.** GitHub caps repository secrets at 100 per repo. Ten
  Mykronos secrets consume a tenth of a customer repo's budget for a boundary
  that is not enforced.
- **Rotation surface.** 200 repos × up to 10 capabilities is 2,000 secrets on
  2,000 independent 90-day clocks — roughly 22 Secrets API calls a day, each
  of which can fail, and each failure becomes a silent future `401` in
  someone's CI unless separately tracked and reconciled. One token per repo
  reduces this to ~2 a day.

The security property the earlier draft claimed is preserved exactly, because
it was always a repo-level property: a compromised repo's CI can pollute that
repo's own findings and nothing else. It cannot read or write another repo's
data, and it cannot reach the GitHub App's credentials at all.

What is *not* preserved is the ability to distinguish which capability's
workflow made a given call, since they now share a credential. That
distinction was never enforceable anyway (any workflow could read any of the
tokens), so relying on it would have been false assurance.

#### Capability grants and revocation

Grants live in the registry, keyed by `(repo_full_name, capability)`:

- Enabling a capability adds a grant. No secret is written, so no GitHub API
  call is involved and nothing can half-succeed.
- Disabling a capability removes the grant (spec 03 §5). Further ingestion for
  that capability is rejected with `403` from the very next request, while the
  repo's other capabilities keep working on the same token.
- Offboarding a repo revokes the token itself, so every capability stops at
  once.

This is a stronger revocation guarantee than the earlier design, which had to
delete a GitHub secret to revoke — an API call that can fail, leaving a live
credential behind. Registry-side revocation is local, immediate, and cannot
partially apply.

#### Rotation, and the overlap window

Rotation reissues the token and updates the repo secret. A workflow reads that
secret when its job starts and may not post findings until many minutes later,
so a naive swap will `401` runs that were already in flight through no fault
of their own — turning CI red for a reason that has nothing to do with the
code under scan, which is exactly the kind of noise that gets a security
platform switched off.

Therefore rotation is dual-validity:

1. Issue the new token, mark the previous one `superseded` with an expiry of
   `now + overlap_window` (deployment-configurable, default 24 hours).
2. Update the repo secret to the new value.
3. Accept **both** tokens until the superseded one expires, then purge its
   hash.

A rotation that fails at step 2 leaves the old token valid and is retried;
nothing is stranded. Ingestion responses carry an advisory
`X-Mykronos-Token-Rotated: true` header while a superseded token is still
being accepted, so a repo still presenting an old token after the window is
diagnosable from logs rather than only from its eventual `401`.

#### Attribution

`repo_full_name` is taken from the authenticated token and is **not** accepted
as a request field on the findings path — a workflow cannot file findings
against another repo because there is no field in which to say so. Because one
token now covers several capabilities, a findings batch must declare its
`capability` explicitly; the server rejects it with `403` unless that
capability is currently granted to the token, and it must match the
`capability` of the `ScanRun` it references.

### Endpoints
| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/ingest/scan-run` | Register or finalise a `ScanRun`. Upserts on `scan_run_id` — see below |
| `POST` | `/api/ingest/findings` | Submit a batch of normalized `Finding` records for a `scan_run_id` |
| `POST` | `/api/ingest/{capability}` | Capability-specific payloads for Aegis/Atlas/Patchwork/Oracle tables |
| `GET` | `/api/ingest/health` | Liveness check the workflow can call before scanning, to fail fast if the data lake is unreachable |

**`scan-run` is called twice per run, and is an upsert.** `completed_at`,
`scan_status` and `finding_count` are not known at workflow start, and there is
deliberately no separate finalise endpoint — a second verb would be a second
thing to get wrong under retry.

The client generates `scan_run_id` itself before scanning and POSTs once at
start and once at completion; the second POST upserts onto the first by
`scan_run_id`. That keeps one row per run (§3) and makes the call idempotent
under workflow retries, which matters because the completion POST runs under
`always()` and a re-run of a failed job will send it again.

A run that never sends its second POST stays visible as a started-but-unfinished
row rather than disappearing, which is the distinction §7 needs between "never
ran" and "ran and broke".

Every write endpoint:
1. Validates the payload against its Pydantic schema — reject (`422`) with
   a clear error rather than partially ingesting malformed data.
2. Writes to the durability buffer (§2) synchronously before returning
   `200`, so a `200` response is a durability guarantee, not just an
   in-memory ack.
3. Returns the count of records accepted.

## 5. Deduplication

`Finding.finding_id` is a SHA-256 over a **stable location fingerprint**,
computed by the Ingestion API (never by the client, so the rule has exactly
one implementation). It never includes `commit_sha` — the same underlying
issue found again on a later commit must update the existing row's
`last_seen_at`/`last_seen_scan_run_id`, not create a duplicate.

**It also never includes `line_start`.** An earlier draft of this spec hashed
the line number, which meant any unrelated edit above a finding — adding an
import, reformatting — shifted it, retired the original row as `fixed`, and
re-reported the identical issue as newly discovered. That silently destroys
`first_seen_at`, and with it finding age, mean-time-to-fix, the age-escalation
term in Oracle's policy (spec 09 §5) and every trend line in the dashboard
(spec 10 §2.3). Line numbers are display metadata, updated in place.

The fingerprint tuple depends on what kind of finding it is:

| Kind | Condition | Fingerprint inputs |
|---|---|---|
| **Dependency** | `package_name` is set | `repo_full_name`, `capability`, `rule_id`, `package_name` |
| **Code** | `file_path` is set | `repo_full_name`, `capability`, `rule_id`, `file_path`, `symbol`, `normalize(code_snippet)` |
| **Repo-level** | neither is set | `repo_full_name`, `capability`, `rule_id`, `title` |

Notes on each:

- **Dependency findings exclude `package_version`.** A CVE that still applies
  after a version bump is the same finding; one that no longer applies is
  resolved by the normal absence-reconciliation path below.
- **`normalize(code_snippet)`** strips leading/trailing whitespace from each
  line, collapses internal whitespace runs to a single space, and drops blank
  lines. It is deliberately *not* language-aware: no comment stripping, no
  parsing, no case folding. A finding survives reindentation and code motion,
  and is correctly retired when the vulnerable code itself changes.
- **`symbol` is included but tolerated as null**, since not every tool reports
  one. Where present it disambiguates identical snippets appearing twice in a
  file (two copies of the same unsafe call in different functions).
- **Degradation is explicit, not silent.** If an adapter supplies neither
  `code_snippet` nor `symbol` for a code finding, the API falls back to
  hashing `line_start` and stamps `fingerprint_version = "v1-line"`. Those
  rows are known to be churn-prone and are reportable as a data-quality
  metric; the intended path stamps `v2-snippet`.
- Changing the fingerprint rule in future requires a new
  `fingerprint_version` and a migration that re-derives `finding_id` from the
  retained `code_snippet`, carrying `first_seen_at` across. Changing it in
  place is prohibited.
- If a finding_id previously marked `fixed` reappears, flip its `status`
  back to `open` and log a `finding_reopened` event (feeds spec 11 retro
  signals — a reopened finding is a useful learning signal).
- If a finding_id is absent from the latest scan of a given capability for
  a repo (i.e., it was open before, not reported this time), a background
  reconciliation job marks it `fixed` — but only after two consecutive
  scans confirm its absence, to avoid flapping on flaky scanners.

## 6. Rate limiting & backpressure

- Ingestion API enforces a per-token rate limit (default: 100 requests/min,
  10,000 findings/request max batch size) to protect the compaction job
  from being overwhelmed by a misbehaving workflow.
- The shared `mykronos/upload-results` composite action (spec 04 §2)
  implements exponential backoff on `429`/`503` responses, up to a
  configurable ceiling, then fails the workflow step (never silently drops
  data — architecture constraint, spec 01 §6).

## 7. Raw output retention

- The original, unmodified tool output (SARIF file, Gitleaks JSON, etc.) is
  stored alongside the normalized data, referenced by
  `ScanRun.raw_output_ref` (a path under `datalake/raw/<repo>/<scan_run_id>/`).
- Retention period is deployment-configurable (default: 1 year), after
  which raw files (not normalized `Finding` rows) are purged by a scheduled
  job, to bound local disk usage.

## 8. Query access for Dashboard & Oracle

- Dashboard (spec 10) and Oracle (spec 09) query the data lake via DuckDB
  SQL directly against the Parquet partitions (read-only), through a thin
  internal query service in the backend — they never write to
  `findings/`/`scan_runs/` directly, only through the Ingestion API, to keep
  a single write path and consistent validation/dedup logic.

## 9. Acceptance criteria

- A scanner workflow can register a `ScanRun` and submit 10,000 findings in
  under 30 seconds against a locally running instance.
- Re-ingesting identical findings from a re-run of the same commit does not
  increase `Finding` row count — only updates `last_seen_at`.
- **Fingerprint stability:** re-ingesting a finding whose `line_start` has
  shifted (unrelated lines inserted above it) but whose `code_snippet`,
  `symbol` and `file_path` are unchanged resolves to the *same* `finding_id`,
  preserves `first_seen_at`, and updates `line_start` in place. This is a
  required regression test, not an aspiration — it is the behaviour §5 exists
  to guarantee.
- Disabling a capability revokes its grant immediately: the next ingestion
  attempt for that capability is rejected with `403`, while the same repo's
  other granted capabilities continue to succeed on the same token.
  Offboarding a repo revokes the token itself and rejects everything with
  `401`.
- **Rotation does not break in-flight workflows.** A token rotated after a job
  has read the secret but before it posts its findings still succeeds, for the
  duration of the overlap window; once the window passes, the superseded token
  is rejected. Both halves are required — an overlap that never expires is not
  a rotation.
- All data lake writes are queryable via DuckDB SQL within 5 minutes of
  ingestion (matching the compaction interval, §2).
- No component other than the Ingestion API ever writes to the Parquet
  partitions.

## 10. Edge cases

- Ingestion request arrives for a `repo_full_name`/`capability` whose
  `RepoOnboarding` was just set to `removed` — accept the write (data in
  flight shouldn't be lost) but flag it in a `late_arrival` audit log for
  review.
- Two workflow runs for the same commit run concurrently (e.g., retried
  workflow) — both `ScanRun` rows are kept (accurate audit trail); `Finding`
  dedup (§5) still collapses to one open finding row.
- Compaction job crashes mid-batch — the write-ahead buffer is the source
  of truth until compaction confirms success; buffer entries are only
  deleted after their corresponding Parquet write is confirmed.

## 11. Dependencies

- Spec 02/03 for how per-repo ingestion tokens are provisioned as GitHub
  secrets.
- Spec 04, 06, 07, 08, 09 for what each capability submits.
- Spec 10 for how the Dashboard queries this data.
- Spec 11 for how retro/learning signals relate to `Finding.status` changes.
