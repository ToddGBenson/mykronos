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
| `finding_id` | UUID | PK — deterministic hash of (repo, capability, rule_id, location, commit_sha) for natural dedup, see §5 |
| `scan_run_id` | UUID | FK → ScanRun |
| `repo_full_name` | string | |
| `capability` | enum | |
| `rule_id` | string | tool's rule/check identifier, e.g. `CWE-89`, `CKV_AWS_23` |
| `title` | string | |
| `description` | text | |
| `severity` | enum | `info, low, medium, high, critical` (normalized from tool-native scale) |
| `cvss_score` | float, nullable | |
| `file_path` | string, nullable | |
| `line_start` / `line_end` | int, nullable | |
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
- Every onboarded repo's workflows authenticate to the Ingestion API using
  a **per-repo, per-capability scoped token** (a Mykronos-issued opaque
  bearer token, not a GitHub token), stored as a GitHub Actions repo secret
  by the Workflow Installer (spec 03 §3). This token:
  - Is scoped to exactly one `(repo_full_name, capability)` pair.
  - Can only call `POST /api/ingest/{capability}` for that repo.
  - Is rotated automatically every 90 days by a scheduled job (re-issues
    the secret via the same mechanism used to create it).
  - Can be revoked instantly by disabling the capability (spec 03 §5).
- This design means a compromised repo's CI can only ever pollute that
  repo's own findings for its enabled capabilities — it cannot read or
  write another repo's data, and it cannot access the GitHub App's
  credentials at all.

### Endpoints
| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/ingest/scan-run` | Register a `ScanRun` (called first, at workflow start) |
| `POST` | `/api/ingest/findings` | Submit a batch of normalized `Finding` records for a `scan_run_id` |
| `POST` | `/api/ingest/{capability}` | Capability-specific payloads for Aegis/Atlas/Patchwork/Oracle tables |
| `GET` | `/api/ingest/health` | Liveness check the workflow can call before scanning, to fail fast if the data lake is unreachable |

Every write endpoint:
1. Validates the payload against its Pydantic schema — reject (`422`) with
   a clear error rather than partially ingesting malformed data.
2. Writes to the durability buffer (§2) synchronously before returning
   `200`, so a `200` response is a durability guarantee, not just an
   in-memory ack.
3. Returns the count of records accepted.

## 5. Deduplication

- `Finding.finding_id` is a deterministic hash (e.g., SHA-256) of
  `(repo_full_name, capability, rule_id, file_path, line_start, package_name)`
  — **not** including `commit_sha`, so the same underlying issue found
  again on a later commit updates the existing row's `last_seen_at`/
  `last_seen_scan_run_id` rather than creating a duplicate.
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
- Disabling a capability's ingestion token immediately (within one request)
  rejects further ingestion attempts with `401`.
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
