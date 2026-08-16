# Mykronos backend

One FastAPI service (spec 01 §2 specifies one backend, not a fleet) carrying
every phase of [`specs/13-build-roadmap.md`](../specs/13-build-roadmap.md):
the data lake and its single write path, onboarding and the GitHub App, the
workflow installer, Aegis, Atlas, Oracle, Patchwork, the Knowledge Store, and
the dashboard query service. The quick start below still describes the Phase 0
core, which remains the spine everything else mounts onto.

The operational store upgrades its own schema on startup (D-052): a column
added to a model reaches databases that already exist, with the model's own
default backfilled. A required column with no default fails the test suite
before it can fail a deploy.

## Quick start

```bash
cd backend
python -m venv .venv
.venv/Scripts/activate          # Windows;  source .venv/bin/activate elsewhere
pip install -e ".[dev]"

python -m mykronos.cli init-lake
python -m mykronos.cli mint-token example-org/payments-api sast
python -m uvicorn mykronos.main:app --reload --port 8077
```

Interactive API docs at <http://127.0.0.1:8077/docs>.

## The Phase 0 demo

Spec 13 §3: *"curl a fake finding into the Ingestion API, query it back out via
DuckDB SQL."*

```bash
TOKEN=<the token mint-token printed>

# 1. Register the scan run (workflow start).
curl -X POST http://127.0.0.1:8077/api/ingest/scan-run \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"scan_run_id":"demo-run-1","repo_full_name":"example-org/payments-api",
       "capability":"sast","tool_name":"codeql","tool_version":"2.19.0",
       "commit_sha":"a91f2c7","branch":"main","pr_number":2841,
       "triggered_by":"pull_request","started_at":"2026-08-07T12:00:00",
       "scan_status":"success","finding_count":1}'

# 2. Submit findings.
curl -X POST http://127.0.0.1:8077/api/ingest/findings \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"scan_run_id":"demo-run-1","findings":[{
        "rule_id":"CWE-89","title":"SQL injection via string concatenation",
        "severity":"critical","file_path":"orders/query.py",
        "line_start":214,"symbol":"get_order",
        "code_snippet":"cursor.execute(\"SELECT * FROM orders WHERE id = \" + order_id)"}]}'

# 3. Fold the buffer into Parquet (the server also does this every 5 minutes).
python -m mykronos.cli compact

# 4. Read it back.
python -m mykronos.cli query \
  "SELECT rule_id, severity, file_path, line_start, status FROM findings"
```

## How a write lands

```
POST /api/ingest/*
      |
      v
write-ahead buffer            one fsync'd JSONL segment per request,
datalake/_buffer/<table>/     renamed into place atomically
      |
      | compaction, every 5 min or `mykronos compact`
      v
datalake/<table>/dt=YYYY-MM-DD/part-0000.parquet
      |
      | DuckDB views over the Parquet glob
      v
read-only queries (dashboard, Oracle)
```

Two properties this shape exists to provide:

**A 200 is a durability guarantee** (spec 05 §4). The response is not returned
until the bytes are fsync'd. Writing one Parquet file per request would shred
the lake into thousands of tiny files, so the buffer absorbs request-rate
writes and compaction batches them.

**Segments are deleted only after their Parquet write is confirmed**
(spec 05 §10). A crash in between replays those rows on the next run, which
the upsert makes idempotent.

## Finding identity

`finding_id` is a SHA-256 over a stable location fingerprint, computed
server-side — clients never supply one, so the rule has a single
implementation. It is anchored to the *code*, not the line number:

| Kind | Fingerprint inputs |
|---|---|
| Dependency (`package_name` set) | repo, capability, rule_id, package_name — **not** version |
| Code (`file_path` set) | repo, capability, rule_id, file_path, symbol, normalized snippet |
| Repo-level | repo, capability, rule_id, title |

An adapter that supplies no snippet or symbol degrades to hashing
`line_start` and is stamped `fingerprint_version = "v1-line"`. Those rows are
churn-prone by construction and countable as a data-quality metric, rather than
silently mixed in with stable ones.

See [`docs/DECISIONS.md`](../docs/DECISIONS.md) D-001 for why, and spec 05 §5
for the rule itself.

## CLI

| Command | Purpose |
|---|---|
| `init-lake` | Create the directory layout and catalog views |
| `mint-token <owner/repo> <capability>` | Issue a scoped ingestion token (printed once) |
| `revoke-token <owner/repo> <capability>` | Revoke immediately — takes effect on the next request |
| `list-tokens` | Scopes and hashes, never plaintext |
| `compact` | Fold the buffer into Parquet now |
| `stats` | Row counts and buffer depth |
| `query "SELECT ..."` | Read-only SQL against the lake (`--json` for machine output) |

## Tests

```bash
pytest                  # everything, as CI runs it
pytest -m "not slow"    # inner loop, ~12s
```

`tests/test_acceptance.py` holds the measured criteria from spec 05 §9 —
notably 10,000 findings registered, submitted and compacted inside 30 seconds.
`tests/test_lake.py::test_line_shift_preserves_the_finding` is the regression
that the D-001 spec change exists to guarantee.

## Layout

```
mykronos/
├── config.py         settings, with each spec default cited inline
├── schemas.py        wire + storage models; Submission vs Record split
├── fingerprint.py    finding identity (spec 05 §5) — the only implementation
├── auth.py           per-(repo, capability) token registry, hashes only
├── ratelimit.py      per-token sliding window (spec 05 §6)
├── api/ingest.py     the single write path
├── lake/
│   ├── tables.py     column definitions — one source of truth for the schema
│   ├── buffer.py     write-ahead JSONL segments
│   ├── catalog.py    DuckDB views; read-only connections for consumers
│   └── compaction.py buffer -> Parquet, with upsert
└── cli.py            operator commands
```
