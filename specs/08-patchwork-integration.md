# Spec 08 — Patchwork Integration (Auto-Remediation)

**Status:** Approved for build
**Depends on:** [04 — Scanner Workflows](04-scanner-workflows.md), [05 — Data Lake](05-datalake.md), [11 — Knowledge Store & RAG](11-knowledge-rag-learning.md)

---

## 1. Purpose

Add an **auto-remediation** capability, modeled on the existing internal
"Project Patchwork" pattern: when SAST/Secrets/Containers/IaC findings
appear on a PR, an agent pipeline triages them, groups related findings
("toxic combinations" — multiple findings that combine into a worse
composite risk), generates candidate fixes, and opens **draft** pull
requests for a human to review. **Patchwork never merges anything itself.**

## 2. Pipeline stages (multi-agent, sequential)

1. **Ingest** — read new `Finding` rows (spec 05 §3) for the current PR's
   commit, filtered to capabilities configured to feed Patchwork (default:
   `sast`, `secrets`, `containers`, `iac`).
2. **Triage** — classify each finding: true positive / likely false
   positive / needs-human-judgment, using the Knowledge Store (spec 11) to
   retrieve similar past findings and how they were previously resolved.
3. **Correlate** — detect "toxic combinations": sets of findings that,
   combined, represent higher risk than any one alone (e.g., an
   unauthenticated endpoint + a SQL-injectable query in the same request
   path). Correlation rules are configurable (see §5); v1 ships a small
   built-in rule set and allows custom rules to be added without code
   changes.
4. **Generate fix** — for findings classified as true positives with a
   known safe fix pattern, generate a code change (e.g., parameterize a
   query, pin a vulnerable dependency version, add input validation).
5. **Open draft PR** — commit the fix to a new branch, open a **draft** PR
   referencing the original finding(s), with a description explaining the
   fix and linking back to the finding in the dashboard.
6. **Record outcome** — write a `RemediationEvent` row (§4) regardless of
   whether a fix was generated, so the data lake always shows what
   Patchwork did or didn't do and why.

## 3. Human-in-the-loop guarantee (hard constraint)

- Every Patchwork-generated PR is opened as a **draft**. Patchwork has no
  merge permission — the GitHub App permission set for repos with
  Patchwork enabled explicitly does not need (and should not request)
  merge/administration rights beyond opening PRs.
- No `blocking`/auto-merge configuration exists for Patchwork — unlike
  other capabilities, this is not configurable per repo. This is
  intentional and must not be made configurable without a deliberate,
  separately-reviewed design change.
- If a generated fix later needs modification, a human edits the draft PR
  branch directly (normal GitHub workflow) — Patchwork does not
  automatically re-push over human edits once a PR has received a human
  commit or review comment.

## 4. Data model — `RemediationEvent` (data lake table)

| Field | Type | Notes |
|---|---|---|
| `event_id` | UUID | PK |
| `repo_full_name` | string | |
| `finding_id` | UUID | FK → `Finding` (spec 05 §3); nullable if event is about a toxic combination rather than a single finding |
| `toxic_combination_id` | UUID, nullable | groups multiple `finding_id`s when a combination was detected |
| `pipeline_stage_reached` | enum | `triaged, correlated, fix_generated, pr_opened, no_fix_available, skipped_low_confidence` |
| `triage_classification` | enum | `true_positive, likely_false_positive, needs_human_judgment` |
| `fix_pr_number` | int, nullable | |
| `fix_pr_url` | string, nullable | |
| `pr_status` | enum, nullable | `draft_open, human_edited, merged, closed_unmerged` — kept in sync via `pull_request` webhook |
| `rationale` | text | human-readable explanation of the triage decision and, if generated, the fix approach |
| `created_at` | datetime | |

## 5. Configuration (`CapabilityConfig` for `patchwork`)

| Field | Type | Default | Notes |
|---|---|---|---|
| `source_capabilities` | list | `["sast", "secrets", "containers", "iac"]` | which capabilities' findings feed Patchwork |
| `min_confidence_to_generate_fix` | float (0–1) | `0.7` | below this, stage stops at `no_fix_available` rather than generating a possibly-wrong fix |
| `toxic_combination_rules` | list of rule refs | built-in default set | admin-extensible rule definitions |
| `max_open_draft_prs_per_repo` | int | `10` | backpressure — prevents flooding a repo with draft PRs; new candidates queue until existing ones are resolved |

## 6. Workflow behavior

- Template: `workflow-templates/patchwork.yml.j2`, triggered on
  `pull_request` (after the source-capability scanner workflows have
  posted their findings — implemented as a `workflow_run` trigger that
  fires once the relevant scanner workflow completes, to guarantee
  ordering) and optionally on a schedule to sweep existing open-finding
  backlog.
- Steps: call the Patchwork pipeline (backend service, not purely a
  GitHub Action — the multi-agent pipeline runs server-side for
  observability and shared LLM-cost tracking) → pipeline reads relevant
  `Finding` rows from the data lake → executes stages 1–6 above → the
  final step of the *workflow* (not the pipeline) calls the shared upload
  step (spec 04 §2) to ensure `RemediationEvent` rows land in the data
  lake even if invoked as a backend job rather than in-workflow.

## 7. Acceptance criteria

- No Patchwork-authored PR is ever created as non-draft, and no Patchwork
  service credential has merge permission.
- Every finding routed to Patchwork produces exactly one `RemediationEvent`
  row, even when no fix is generated (`no_fix_available`).
- A detected toxic combination produces one `RemediationEvent` with a
  populated `toxic_combination_id` referencing all contributing findings.
- `max_open_draft_prs_per_repo` is enforced — exceeding it queues rather
  than creates additional draft PRs.

## 8. Edge cases

- Two findings on the same PR both map to overlapping code regions — avoid
  generating two separate conflicting draft PRs; Patchwork should detect
  the overlap and either combine into one PR or defer the second to
  `needs_human_judgment`.
- The original finding is resolved/fixed by a human before Patchwork's fix
  PR is reviewed — a reconciliation job checks whether the source finding
  is still `open`; if not, auto-closes the now-redundant draft PR with a
  comment explaining why, rather than leaving stale PRs open.
- LLM/agent pipeline failure mid-run — must still emit a
  `RemediationEvent` with `pipeline_stage_reached` set to wherever it got
  to, not silently disappear (architecture constraint, spec 01 §6).

## 9. Dependencies

- Spec 04/05 for the findings Patchwork consumes and the events it
  produces.
- Spec 11 (Knowledge Store) — triage decisions and PR outcomes
  (`merged` vs `closed_unmerged`) are the single richest source of retro
  learning signal in the whole system; Patchwork must write these outcomes
  in a form spec 11's ingestion can consume (see spec 11 §4).
- Spec 09 (Oracle) may consider "an auto-fix is already in flight for this
  finding" as a factor in its risk decision (e.g., lower urgency to block a
  release if a fix PR already exists).
