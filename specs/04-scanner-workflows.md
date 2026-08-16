# Spec 04 — Scanner Workflows (SAST, DAST, Secrets, Containers, IaC, Cloud)

**Status:** Approved for build
**Depends on:** [01 — Architecture](01-architecture.md), [05 — Data Lake](05-datalake.md)

---

## 1. Purpose

Define the six baseline scanning capabilities that run as GitHub Actions
inside every onboarded repo (as selected by the admin), the specific tools
each uses, and — critically — the **common contract every scanner workflow
must follow to upload its results to the data lake.**

## 2. Common contract (applies to all six + Aegis/Atlas/Patchwork/Oracle)

Every workflow template in `workflow-templates/` MUST end with a shared
composite action step, `mykronos/upload-results`, that:

1. Collects the scanner's native output file(s) (SARIF, JSON, or
   tool-specific format).
2. Normalizes them into the internal `Finding` schema (spec 05 §2) using a
   per-capability adapter script (see §4 below — one adapter per tool).
3. POSTs the normalized payload **and** the raw original file to the
   Ingestion API (spec 05 §3), authenticated with the repo-scoped ingestion
   token (spec 05 §4).
4. Fails the workflow step (non-zero exit) if the upload fails — findings
   must never be silently dropped (architecture constraint, spec 01 §6).
5. Emits a `$GITHUB_STEP_SUMMARY` block showing counts by severity, so the
   PR/Actions UI always shows a human-readable summary even without opening
   the dashboard.

This upload step is a single shared, versioned, reusable composite action
(not copy-pasted per workflow) so that ingestion behavior stays consistent
as it evolves.

## 3. Capability-to-tool mapping (v1 defaults, overridable per repo)

| Capability | Default tool(s) | Trigger | Native output format |
|---|---|---|---|
| **SAST** | CodeQL (primary), Semgrep (secondary/optional) | `pull_request`, `push` to default branch, weekly schedule | SARIF |
| **DAST** | OWASP ZAP baseline scan | scheduled (nightly/weekly) against a designated staging/test URL; optional `workflow_dispatch`. **Paused platform-wide until the scan has a resource budget (D-053, 2026-08-15)** — manual trigger still runs and still reports | ZAP JSON report (converted to SARIF-like internal shape) |
| **Secrets** | Gitleaks (primary), TruffleHog (optional) | `pull_request`, `push`, full-history scan on onboarding | Gitleaks JSON |
| **Containers** | Trivy (image + Dockerfile scan) | `pull_request` touching Dockerfile/image build paths, `push`, scheduled re-scan of latest published image | SARIF (Trivy supports native SARIF output) |
| **IaC** | Checkov | `pull_request` touching IaC paths (`*.tf`, `cloudformation/**`, `k8s/**`, etc.), `push` | SARIF (Checkov supports native SARIF output) |
| **Cloud** | Cloud-provider posture scan (e.g., a Prowler/ScoutSuite-style scan against the account(s) tied to the repo's declared environment) | scheduled (daily) | Tool-native JSON |
| **AI** | `scripts/check_ai.py` (prompt-injection surface, model provenance, evaluation coverage) — any SARIF-emitting tool | `pull_request`, `push` | SARIF. Produces findings, unlike the other quality stages (D-047) |
| **QA** | The repository's own quality checks — link integrity here, contract or schema checks elsewhere | `pull_request`, `push` | None — a `ScanRun` with `finding_count = 0` (D-046) |
| **Unit** | The repository's own test runner | `pull_request`, `push` | None — a `ScanRun` with `finding_count = 0` (D-046) |
| **Functional** | The repository's own functional suite, run against a deployed lower environment | after deploy to the demo environment | JUnit XML, uploaded as capability `functional` (amended 2026-08-15) — plus the proxied traffic DAST consumes when the DAST lane runs (spec 16) |
| **Network** | Active scan of operator-owned network ranges — see **[spec 14](14-network-scanning.md)**. Listed here for completeness only: it is *not* a workflow template, because a GitHub-hosted runner cannot reach a private network. It is orchestrated by the backend | scheduled (weekly) | nmap XML / nuclei JSON |

**Unit, functional and QA produce no findings**, and that is the whole of D-046.
They report that a suite ran, how it ended and how many cases failed. A
failing assertion is not a vulnerability: giving it a severity would let a
broken test raise a repository's security risk score and a deleted test lower
it, which is an incentive to delete tests. The pipeline stops the build; the
risk score stays about risk.

Tool choice per capability is a **configurable default**, not hardcoded —
`CapabilityConfig.config_json` (spec 02 §3) may override the tool, its
version pin, and its severity threshold per repo. The workflow template
renders whichever tool is configured; the adapter step (§4) is selected to
match.

## 4. Normalization adapters

One adapter module per (capability, tool) pair, e.g.:

```
backend/mykronos/adapters/
├── sast_codeql.py
├── sast_semgrep.py
├── dast_zap.py
├── secrets_gitleaks.py
├── secrets_trufflehog.py
├── containers_trivy.py
├── iac_checkov.py
└── cloud_generic.py
```

They live inside the backend package rather than in a top-level directory so
there is exactly one definition of the finding schema. The composite upload
action installs the package in CI; a second copy of `FindingSubmission` that
could drift from the server's would be a worse trade than the directory
layout.

Each adapter exposes one function:

```python
def normalize(raw_output: bytes, context: ScanContext) -> list[FindingSubmission]:
    """Parse tool-native output and return the findings it describes.
    Must not raise on partial/malformed input — log and skip the
    unparseable record, returning whatever *did* parse."""
```

**`FindingSubmission`, not `Finding`.** A `Finding` (spec 05 §3) carries
server-assigned fields — `finding_id`, `status`, `first_seen_at` — that an
adapter must not supply and could not compute: identity is assigned by the
Ingestion API precisely so the rule has one implementation (spec 05 §5).
`FindingSubmission` is the subset a scanner can actually observe.

`ScanContext` carries: `repo_full_name`, `capability`, `tool_name`,
`tool_version`, `commit_sha`, `branch`, `workflow_run_id`, `triggered_by`
(`pull_request` | `push` | `schedule` | `workflow_dispatch`), `pr_number`
(nullable). This context is stamped onto every `Finding` produced.

Where a tool natively emits SARIF, prefer a single shared `sarif_to_finding`
converter over a bespoke per-tool parser, to minimize adapter code
duplication; tool-specific adapters (Gitleaks, ZAP, cloud) that don't emit
SARIF get bespoke parsers.

## 5. Configuration

Per-capability config schema (validated JSON Schema, stored in
`CapabilityConfig.config_json`), common fields across all six:

| Field | Type | Default | Notes |
|---|---|---|---|
| `enabled_tool` | string | capability default (§3) | Must be in the allowed tool list for that capability |
| `severity_threshold` | enum (`info`,`low`,`medium`,`high`,`critical`) | `low` | Findings below this are still ingested (for completeness/trend data) but not surfaced as PR-blocking |
| `blocking` | bool | `false` | If true, a finding at/above `severity_threshold` fails the PR check |
| `paths_include` / `paths_exclude` | glob list | tool default | Scan scope |
| `schedule_cron` | string | tool default (§3) | For scheduled capabilities (DAST, Cloud) |

Capability-specific extra fields (e.g., DAST's target URL, Cloud's account
IDs) are documented in that capability's own config schema file under
`workflow-templates/config-schemas/`.

## 6. No-op / not-applicable behavior

If a scanner finds nothing to scan (e.g., IaC scan on a repo with no IaC
files, Container scan on a repo with no Dockerfile), the workflow:
- Still runs and still calls the upload step with an empty `Finding` list
  and a `scan_status: "no_applicable_targets"` flag on the ingestion
  payload metadata (spec 05 §2), so the data lake and dashboard can
  distinguish "scanned, found nothing" from "scanned, 0 findings" from
  "never ran." This is required — see spec 05 §2 `ScanRun` record.
- Exits 0 (success) — a repo genuinely having no Dockerfiles is not a
  failure condition.

## 7. Acceptance criteria

- Each of the six capabilities, when enabled on a test repo with known
  seeded vulnerabilities, produces at least one `Finding` in the data lake
  matching the expected severity/category within one workflow run.
- Disabling a capability (via spec 03) stops new findings from that
  capability from being generated, without deleting prior `Finding` rows.
- A misconfigured tool (e.g., invalid `enabled_tool` value) fails onboarding
  validation at the `PATCH /api/repos/{id}/capabilities` step (spec 02 §7),
  not silently at workflow run time.
- Every workflow run — success, no-op, or failure — creates exactly one
  `ScanRun` record in the data lake (spec 05 §2), so scan coverage/freshness
  can be audited from the data lake alone.

## 8. Edge cases

- Tool produces non-UTF8 or truncated output (crash mid-scan) — adapter
  must catch parse errors and still call the upload step with whatever
  partial results exist plus a `scan_status: "partial_failure"` flag, and
  the workflow step must still fail (non-zero exit) so CI is visibly red
  even though partial data was preserved.
- Duplicate findings across scans of the same commit (e.g., re-run of a
  workflow) — deduplication is the **data lake's** responsibility (spec 05
  §5), not the adapter's; adapters always submit what the tool reported.
- Rate-limited or unavailable Cloud provider APIs during the Cloud scan —
  retry with backoff up to a configurable ceiling, then fail the run
  (visible, not silent) if still unavailable.

## 9. Dependencies

- Spec 05 for the `Finding`/`ScanRun` schema and ingestion API contract.
- Spec 03 for how these templates get installed into a repo.
- Spec 02 for per-repo capability configuration storage.
