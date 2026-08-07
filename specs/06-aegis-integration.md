# Spec 06 — Aegis Integration (Insider Risk)

**Status:** Approved for build
**Depends on:** [04 — Scanner Workflows](04-scanner-workflows.md), [05 — Data Lake](05-datalake.md)

---

## 1. Purpose

Add an **insider-risk and AI-authorship PR gate** capability, modeled on the
existing internal "Aegis Guard" GitHub Action pattern: on every pull
request, assess signals that indicate insider threat risk or undisclosed
AI-generated authorship, and produce a go/no-go recommendation attached to
the PR — feeding into Oracle (spec 09) as one input among several, not a
final verdict on its own.

## 2. Scope of "insider risk" signals (v1)

Aegis evaluates a PR and computes a set of signals, each independently
scored, then combined into an `insider_risk_score` (0–100, higher = riskier):

| Signal | Description | Data source |
|---|---|---|
| **Author baseline deviation** | Commit timing, volume, and file-touch patterns vs. that author's own historical baseline for this repo | Git history via GitHub API |
| **Sensitive path touch** | PR modifies paths flagged as sensitive (auth, secrets config, CI/CD config, access-control code) — configurable glob list per repo | Repo config (`CapabilityConfig`) |
| **AI-authorship likelihood** | Heuristic/LLM-based estimate of whether code was AI-generated and, if so, whether the PR description discloses it | Diff content passed to an LLM classifier |
| **Access anomaly** | Author has write access but has never contributed to this repo before, or contributes from a first-time, unverified device/location signal if available | Repo contributor history |
| **Rapid privilege-adjacent change** | PR modifies permission/role definitions (IAM policies, RBAC configs) shortly before or after a personnel-sensitive event, *if such an event feed is configured* (optional integration, off by default — no HR system integration in v1) | Optional external signal, disabled by default |

**v1 explicitly does NOT integrate with HR/personnel systems.** The
"rapid privilege-adjacent change" signal only activates if a deployment
operator configures an external event feed; out of the box, insider-risk
scoring uses only Git/GitHub-native signals.

## 3. Data model — `InsiderRiskSignal` (data lake table)

| Field | Type | Notes |
|---|---|---|
| `signal_id` | UUID | PK |
| `repo_full_name` | string | |
| `pr_number` | int | |
| `commit_sha` | string | head commit evaluated |
| `insider_risk_score` | int (0–100) | combined score |
| `signal_breakdown` | JSON | per-signal sub-scores + short human-readable rationale for each (never just a number — must be explainable, matching architecture constraint spec 01 §6) |
| `ai_authorship_flag` | bool | true if AI-authorship likely and undisclosed |
| `recommendation` | enum | `pass, review_recommended, block_recommended` |
| `evaluated_at` | datetime | |
| `github_check_run_id` | string, nullable | if a GitHub Check Run was posted |

## 4. Workflow behavior

- Template: `workflow-templates/aegis.yml.j2`, triggered on `pull_request`
  (opened, synchronize, reopened).
- Steps: checkout PR diff → run Aegis scorer (calls an LLM via the
  org's approved AI gateway, using only the diff + PR metadata, never the
  full repo contents unless the sensitive-path signal requires reading
  surrounding context) → post a GitHub Check Run summarizing the
  recommendation and top contributing signals → call
  `POST /api/ingest/aegis` (per the shared upload contract, spec 04 §2) to
  write the `InsiderRiskSignal` row.
- `recommendation: block_recommended` does **not** auto-block the PR merge
  by itself — it surfaces a failing Check Run if `CapabilityConfig.blocking`
  is `true` for Aegis on that repo (same blocking config pattern as spec 04
  §5); otherwise it's advisory only. Either way, human review of the PR is
  still required before merge (architecture constraint, spec 01 §6).

## 5. Configuration (`CapabilityConfig` for `aegis`)

| Field | Type | Default | Notes |
|---|---|---|---|
| `sensitive_paths` | glob list | `["**/auth/**", "**/*secret*", "**/.github/workflows/**", "**/iam/**"]` | |
| `blocking` | bool | `false` | |
| `block_threshold` | int | `80` | `insider_risk_score` at/above this triggers `block_recommended` when `blocking=true` |
| `ai_disclosure_required` | bool | `true` | if true, undisclosed AI-authorship raises the score even if the code itself looks fine |

## 6. Acceptance criteria

- Every PR on a repo with Aegis enabled produces exactly one
  `InsiderRiskSignal` row and one GitHub Check Run.
- `signal_breakdown` always contains a rationale string for every
  sub-signal that contributed non-zero score — no opaque numeric-only
  output.
- Aegis never merges, closes, or force-pushes a PR — read/comment/check
  permissions only.

## 7. Edge cases

- LLM/AI gateway unavailable — Aegis falls back to non-AI signals only
  (author baseline, sensitive path, access anomaly), sets
  `ai_authorship_flag = null` (not `false`, to distinguish "not evaluated"
  from "evaluated, not AI"), and still ingests a signal row rather than
  failing the whole workflow.
- First-ever PR from a repo (no baseline history) — author baseline
  deviation signal is skipped (insufficient data) rather than defaulting
  to a false-positive-prone extreme score.

## 8. Dependencies

- Spec 05 for ingestion contract and table schema.
- Spec 09 (Oracle) consumes `InsiderRiskSignal.insider_risk_score` as one
  weighted input to its overall risk decision.
- Spec 11 (Knowledge Store) — human overrides of an Aegis recommendation
  (e.g., admin dismisses a `block_recommended` as a false positive) are
  captured as retro signals to improve future scoring calibration.
