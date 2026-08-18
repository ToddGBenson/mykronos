# Spec 18 — Repo Page Rework, Threat Model, and On-Demand Remediation

**Status:** Draft for review
**Depends on:** [05 — Data Lake](05-datalake.md), [06 — Aegis Integration](06-aegis-integration.md),
[07 — Atlas Integration](07-atlas-integration.md), [08 — Patchwork Integration](08-patchwork-integration.md),
[09 — Oracle](09-oracle-risk-decision-engine.md), [10 — JDED Dashboard](10-jded-dashboard.md),
[17 — Harness, Threat Intel, i2i](17-harness-threat-intel-and-i2i.md)

---

## 0. What this spec is against

Spec 17 split one overloaded "Dashboard" tab into **Harness** (is it running, is it healthy) and
**Findings** (what it found), on the reasoning that those are different questions asked by different
people. That reasoning holds. This spec is not a reversal of it — it is what came after using the
split for a few days: a portfolio-level data bug surfaced, and six tabs turned out to answer six
different subjects with three different information densities, three of which (risk decisions,
supply chain, insider risk) are already mature, and one of which (remediation) has been read-only
since spec 08 shipped it, with no way to act from the page that shows the problem.

This spec covers, precisely:

1. A real data bug: the portfolio's per-repo "open findings" count disagrees with the count the
   repo's own Findings tab shows (§2).
2. A repo page with eight tabs instead of six, in a specific order, three of them renamed, one of
   them new (§3, §4).
3. The Harness tab loses its "Pipeline stages" section and restyles "Enabled jobs" to match the
   dashboard-card idiom used everywhere else on this page (§5).
4. Findings gains two filters: triage classification (already computed, not yet filterable) and
   found-by capability (already displayed, not yet clickable) (§6).
5. A new Threat Model tab: a STRIDE-categorized attack-surface inventory derived from data already
   in the lake — not a diagram tool, not an LLM narrative (§7).
6. Remediation stops being read-only: a finding can be previewed for an auto-generated fix and, on
   request, have Patchwork actually open the draft pull request (§8).
7. Supply chain gains an actual SBOM download, and the SBOM lifecycle gets written down as a defined
   process rather than left implicit across three specs (§9).
8. The triage process (spec 17 §5) gets a short consolidating pass — no new classification logic,
   just closing the gap between what it already decides and what a person can see and filter on (§10).

## 0a. Implementation status (as of this spec's first commit)

| Item | Status |
|---|---|
| Portfolio/Findings open-count mismatch (§2) | Done — D-061 |
| Tab restructure and renames (§3) | Done |
| Dashboard tab — summary cards + the pre-spec-17 combined content (§4) | Done |
| Harness tab: remove Pipeline stages, restyle Enabled jobs (§5) | Done |
| Findings: `triage` filter | Done |
| Findings: `found_by` (capability) filter made clickable | Done |
| Threat Model tab: capability-level STRIDE inventory | Done |
| Threat Model: CWE-tag-based refinement (SARIF `properties.tags`) | Not planned this pass — capability-level mapping ships first; noted as an explicit, honest gap, not silently approximated |
| Threat Model: AI-generated narrative | Plumbing only, off by default — same treatment as reachability (spec 17 §5.3). No LLM client exists in this backend and this spec does not add one |
| Remediation: per-finding fix preview (no PR) | Done |
| Remediation: per-finding "create PR" | Done |
| Supply chain: SBOM download endpoint | Planned |
| SBOM process documented (§9) | Planned |

## 1. The bug: portfolio and Findings disagree on "open"

### 1.1 Root cause

Every repo-scoped query in `dashboard.py` keys off `asset_id` — the canonical column since spec 14
§5 (`_status_clause()` at `dashboard.py:616`, used by `_finding_count`, `_severity_counts`,
`_finding_rows`, and therefore by `open_findings()` and `findings()`). The portfolio's per-repo
aggregates do not: `_open_severity_counts()` (`dashboard.py:279-291`) and `_capability_scan_state()`
(`dashboard.py:293-324`) both `GROUP BY repo_full_name` — the column `lake/tables.py:32-35`'s own
comment calls "retired in favour of `asset_id` ... kept for one migration step only."

Every current writer (`api/ingest.py`, `reprocess.py`) sets both columns to the same value, so a
freshly-ingested finding agrees on both counts. A finding written before `asset_id` existed, or
carried across a lake restore that predates the migration, does not: it is **counted** by the
`repo_full_name`-keyed portfolio query (present) and **invisible** to every `asset_id`-keyed query
(null or stale). That is exactly the reported symptom, and it is a genuine correctness bug, not two
differently-scoped metrics wearing the same label.

### 1.2 Fix

- `_open_severity_counts()` and `_capability_scan_state()`'s `open_counts` query both switch from
  `GROUP BY repo_full_name` to `GROUP BY asset_id`, joined back to `RepoOnboarding.github_repo_full_name`
  the same way every other repo-scoped query already resolves that join. One-column swap, no shape
  change to `PortfolioRow` or its callers.
- `backend/mykronos/migrate_assets.py` is run against the live lake as part of deploying this fix —
  not optional. Skipping it does not reintroduce the bug; it would make it worse in a way that fails
  silently: any row whose `asset_id` is still unset would drop out of the portfolio *and* the
  Findings tab both, agreeing with each other while being wrong about the count in the same
  direction. The two counts agreeing is necessary but not sufficient; the migration is what makes
  agreement also correct.
- Longer term (tracked, not blocking this spec): either drop `repo_full_name` from `findings` per
  the column's own comment, or add a compaction-time assertion that `asset_id` is never null on a
  write, so this class of drift cannot recur by omission.

## 2. Tab restructure

### 2.1 New tab order and labels

Eight tabs, in this order, replacing the current six:

| id | Label | Backing today | Change |
|---|---|---|---|
| `dashboard` | Dashboard | — (new) | New: §4 |
| `findings` | Findings | `OpenFindings` | Filters added, §6 |
| `harness` | Harness | `HarnessTab` | Restyled, §5 |
| `threat-model` | Threat Model | — (new) | New: §7 |
| `sscs` | Supply chain | `SscsTab` | SBOM download added, §9 |
| `insider` | Insider Threat | `InsiderRiskTab` | Renamed only (was "Insider risk") |
| `decisions` | Risk Decision | `DecisionsTab` | Renamed only (was "Risk decisions") |
| `remediation` | Remediation | `RemediationTab` | Gains action buttons, §8 |

`Dashboard` becomes the default tab (`?tab=` omitted), matching how `harness` is the default today —
the landing view changes, not the mechanism.

### 2.2 Why Dashboard duplicates content on purpose

Asked directly: should the new Dashboard tab be a lightweight new summary, or the old pre-spec-17
combined view (capability toggles + findings list together) brought back? The answer was **both** —
Dashboard carries the old combined content *and* new at-a-glance summary cards, even though Harness
and Findings already show most of that content on their own tabs. This is a deliberate acceptance of
duplication, not an oversight: Dashboard is for "what's the state of this repo, right now, without
navigating," the same question spec 17 §0's original combined tab answered, while Harness and
Findings remain the deeper, single-subject views for someone who came specifically to toggle a
capability or triage a finding. Two tabs answering related questions at different depths is a known,
accepted shape elsewhere on this page already — Risk Decision's per-decision cards and the portfolio
verdict pill both summarize the same Oracle score at different resolutions.

## 3. Dashboard tab

Composed of, top to bottom:

1. **Summary cards** (new): risk score and recommendation (reusing `Verdict`/`ScoreMeter` from
   `decisions.tsx`), severity counts (reusing `StatTile` from the triage queue page), last-scan
   recency, and a stale-scan warning — the same fields `PortfolioRow` already carries for this repo,
   fetched once rather than recomputed.
2. **Capability manager** (existing `CapabilityManager`, unchanged) — enable/disable, same
   `IndicatorTone` coloring as Harness.
3. **Scan health boxes** (existing `ScanHealthBoxes`, unchanged).
4. **Open findings** (existing `OpenFindings` grouped view, unchanged component, same data as the
   Findings tab) — the combined-tab content spec 17 §0 described, restored here specifically.

No new backend endpoint: item 1 is assembled from `getRepo` (already fetched for the page shell) plus
one `getDecisions` call for the latest decision; items 2-4 reuse the exact queries Harness and
Findings already issue. The Dashboard tab's added cost is one extra Oracle-decisions fetch per page
load, not new query logic.

## 4. Harness tab

- **Removed**: the "Pipeline stages" section (`StageLights`, `pipelines.tsx:89-122`) and its
  surrounding `Section`. `PipelineLinks` (the Built-by/Scanned-by links at the top of the page,
  spec 17 §2.3) is unaffected — it is a separate component, already outside `HarnessTab`.
- **Restyled**: "Enabled jobs" (`JobLights`, `pipelines.tsx:166-195`) moves from a list of rows to a
  grid of cards matching `ScanHealthBoxes`' tile idiom — one card per job, `IndicatorTone`-colored
  the same way capability buttons already are, with the job name, last-run status, and a relative
  timestamp. `stageTone`/`stageState` (already exported from `pipelines.tsx`, reused by
  `capability-manager.tsx`) drive the coloring; no new tone vocabulary.
- `PipelineCoverage`'s export shrinks to just this restyled jobs grid; `StageLights` and its
  `Section` wrapper are deleted from `pipelines.tsx`, not merely unmounted — spec 17 §2.1's original
  reasoning for showing pipeline stages (this component is what "Harness" already imports) still
  applies to jobs, not to stages, once the pipeline links at the top of the page already say whether
  Concourse is green.

## 5. Findings: two new filters

### 5.1 `triage`

`classify()` (`patchwork/triage.py:27`) already runs per finding-group inside `open_findings()`
(`dashboard.py:794-815`) and its result — `true_positive` / `likely_false_positive` /
`needs_human_judgment`, plus `toxic_combination` for correlated groups — is already rendered as a
Pill with rationale in `GroupDetail`. It is not a query parameter on either `open_findings()` or
`findings()`. Adding it is filtering on data already computed, not new classification: both backend
functions gain a `triage: str | None` param, applied after grouping (triage is a property of the
group, not a column any row carries), and `open-findings.tsx`'s `FindingsQuery` gains a `triage`
field with pill controls next to the existing status pills.

### 5.2 `found_by` (capability)

The Findings table's "Found by" column already renders `group.capabilities` as icons
(`open-findings.tsx:425`); the `capability` filter already exists in `FindingsQuery` and in both
backend query functions. What's missing is the connection between them — clicking a capability icon
in the Found By column does not currently set the filter; only the separate capability chip in the
filter bar does, and per the current code that chip is read-only (settable elsewhere, only clearable
in place). This ships as a UI-only change: each icon in the Found By column becomes a link that sets
`?capability=`, matching how every other filterable column on this page already behaves. No backend
change — `capability` is already a first-class filter parameter.

Tool-level filtering (Semgrep vs. Trivy, both currently "sast"/"containers") is out of scope: no
`Finding` column carries a tool name today, only `ScanRun.tool_name` does, and joining every findings
query to `scan_runs` for one filter is a bigger, separate change than this spec's scope.

## 6. Threat Model tab

### 6.1 What it is, and what it deliberately is not

An attack-surface inventory, grouped by STRIDE category, derived entirely from findings and evidence
already in the lake. It is **not** a data-flow diagram, an architecture chart, or an AI-authored
narrative — building any of those honestly would need either structured data this platform does not
collect (component boundaries, network topology, explicit trust-zone declarations) or an LLM call
this backend has never made and this spec does not add. What ships is real and load-bearing: every
row on this tab traces to an actual finding or piece of supply-chain evidence, the same standard
Oracle's `inputs_snapshot` holds itself to.

### 6.2 STRIDE mapping

Because no `Finding` carries a structured CWE (`schemas.py`'s `FindingSubmission` has `rule_id` as a
free-form tool-specific string, never a CWE number), the mapping this pass ships is
**capability-level**, applied deterministically:

| Capability | STRIDE categories |
|---|---|
| `dast` | Spoofing, Tampering (findings are observed at a live entry point — the trust boundary is the endpoint itself) |
| `network` | Spoofing, Denial of Service (an exposed port/service is a boundary before anything about it is known) |
| `cloud` | Elevation of Privilege, Information Disclosure (identity/permission and public-resource findings dominate this capability) |
| `iac` | Elevation of Privilege, Tampering (misconfiguration that would grant more than intended, or allow unintended change) |
| `secrets` | Information Disclosure |
| `sast` | Tampering, Information Disclosure (the two categories code-level findings most often fall under; see §6.3 for the caveat) |
| `containers` | Tampering, Elevation of Privilege |
| `atlas` | Tampering, Information Disclosure (a vulnerable dependency is code you didn't write with the same access as code you did) |

A finding can appear in more than one STRIDE bucket — the mapping is capability → categories
(plural), not finding → category (singular), and the tab says so rather than forcing a false choice
each finding's own data cannot support.

### 6.3 Honest about resolution

The tab's header states plainly that this categorization is capability-level, not per-finding: a
`sast` SQL injection and a `sast` hardcoded-credential finding land in the same two buckets today,
even though a CWE-aware mapping would separate them. This is the same posture as Oracle's
reachability input (spec 17 §5.3) — present and clearly scoped rather than silently approximated as
something finer-grained than it is. A follow-up that extracts CWE tags from `raw_finding_json` where
adapters already emit SARIF `properties.tags` (many do) would sharpen individual findings' placement
without changing the table shape; it is out of scope here and tracked, not attempted.

### 6.4 Data sources

- **Entry points / trust boundaries**: open findings from `dast`, `network`, and `cloud`, grouped the
  same way `open_findings()` already groups (`rule_id`, package/location) — reusing that grouping
  logic rather than a second one.
- **Elevation-of-privilege surface**: open findings from `iac`, `cloud`, `containers`.
- **Supply-chain exposure**: `sscs_evidence`'s latest row (dependency count, vulnerable dependency
  count, trust score — already computed by `atlas.py:78`) plus open `atlas`-capability findings.
- **Data-at-rest exposure**: open `secrets`-capability findings.

### 6.5 API

`GET /api/dashboard/repos/{repo_id}/threat-model` (principal-authenticated, same tier as the other
per-repo dashboard reads) — no new query engine underneath; it composes `open_findings()` (capability
subsets), `sscs_evidence()`, and the static mapping table in §6.2, and returns them pre-grouped by
STRIDE category. `ThreatModelSnapshot { categories: [{ stride: str, findings: [...], evidence_note: str | null }], mapping_resolution: "capability" }` — `mapping_resolution` is the field a future
CWE-aware pass would flip to `"cwe"`, so the frontend's disclosure banner (§6.3) is driven by data,
not a hardcoded string that could drift from what the backend actually did.

### 6.6 The narrative field — plumbing, not a feature

`ThreatModelConfig.narrative_generator_url: str | None`, following the exact pattern
`PatchworkConfig.fix_generator_url` already established: nullable, validated as an `http(s)://` URL
only, never dereferenced by an HTTP client in this change. Null — the default — means the tab shows
no narrative section at all, honestly, rather than a placeholder claiming one is coming. Wiring an
actual call to it is future work requiring an SDK dependency, an API key, and a deployment decision
this spec does not make, matching the answer given when asked directly: deterministic now, this field
as the same kind of honest plumbing reachability got.

## 7. Remediation: preview and on-demand PR

### 7.1 Current state

`PatchworkPipeline.run()` (`pipeline.py:202`) is repo-scoped and batch-only — it triages and attempts
fixes for every `true_positive` finding across the whole repo in one pass, triggered by
`POST /api/patchwork/run` (workflow-token auth, meant for CI). There is no path from "a person looking
at one finding" to "a fix gets generated for that finding." `_attempt_fix()` (`pipeline.py:308`)
already does the real work per finding — read the file, run the deterministic fixers, check
confidence, open a draft PR — it is simply never called for one finding on its own today.

### 7.2 Two new endpoints, both admin-authenticated (principal, not workflow token — a person clicking a button, not a CI job)

**`POST /api/patchwork/findings/{finding_id}/preview`** — read-only from the caller's perspective
(it does read the file from GitHub, but writes nothing). Runs `_triage()` to classify the finding,
and — if `true_positive` and not on a human-edited branch (`branches_off_limits`, unchanged) — runs
`fixers.generate()` against the current file content to produce the same `ProposedFix` `_attempt_fix`
would use, without opening anything. Returns the classification, rationale, and, when a fix would be
generated: fixer name, confidence, summary, and the file diff. This is "auto remediation identified" —
what the finding's detail panel shows before anyone commits to opening a PR, and it is safe to call
repeatedly (same inputs, same deterministic output, per the fixer contract `render_pr_body` already
advertises: "re-running produces the same diff").

**`POST /api/patchwork/findings/{finding_id}/fix`** — calls `_attempt_fix()` for real: opens the
branch, commits the fix, opens the draft PR. Same guardrails as the batch path, unmodified: `draft=True`
always, the open-draft-PR budget (`max_open_draft_prs`) still applies and this endpoint counts against
it, a branch a human has touched is still permanently off-limits, and the `GitHubClient` protocol
still exposes no merge method — nothing added here can merge, structurally, same as spec 08 §3. Writes
exactly one `RemediationEvent` via the buffer, same as the batch path, so a person-triggered fix and a
scheduled one are indistinguishable in the Remediation tab's history — which is correct, since they
went through the identical pipeline stage.

### 7.3 Frontend

- **Findings tab**: `GroupDetail` (the panel that opens when a finding is clicked) gains a
  "Remediation" section. On open, it calls `preview`; if a fix is available, it shows the diff and a
  "Create PR" button that calls `fix` and then shows the resulting PR link inline. If no fix is
  available (`needs_human_judgment`, `likely_false_positive`, no matching fixer, or low confidence),
  it shows the same rationale text the batch path already writes to `RemediationEvent.rationale` —
  one vocabulary for "why nothing happened," not a second one invented for this button.
- **Remediation tab**: gains a "Preview and fix" action inline on any history row still at
  `no_fix_available` or `triaged` — the same two calls, reachable from the tab that already shows
  remediation history, for someone who starts there instead of from Findings.

## 8. Supply chain: SBOM download and the defined process

### 8.1 The gap

`sscs_evidence.sbom_ref` (`lake/tables.py:148`) is a path string pointing into raw-output storage
(spec 05 §7) — the file itself is never served. `sscs.tsx` renders the string as truncated text.
There is no API route to fetch the bytes.

### 8.2 New endpoint

`GET /api/dashboard/repos/{repo_id}/sscs/sbom?evidence_id={id}` — admin-only
(`principal.may_see_raw_output`, the same gate every other raw-output access already uses, spec 12
§5), streams the file at `settings.datalake_dir / evidence.sbom_ref` with its original content type
(CycloneDX/SPDX JSON, whichever syft produced). 404 if the evidence row names no `sbom_ref`, or if
the file named by a `sbom_ref` from an old row has since been pruned by retention — the two are
distinguished in the response detail, because "we never had one" and "we had one and it aged out" are
different facts about the same 404.

### 8.3 The defined SBOM process

Written down here because it currently exists only as the union of three specs' incidental mentions:

1. **Generation.** Concourse's `sbom` resource step (spec 15) runs `syft` against the built image
   during the `build` job, producing a CycloneDX JSON document.
2. **Storage.** The raw SBOM is archived via the same raw-output path every other tool's original
   output uses (`POST /api/ingest/raw`, spec 05 §7) — capability `atlas`, so it is subject to the
   same admin-only visibility and retention window as any other raw archive, not a special case.
3. **Linkage.** `atlas.py`'s scoring pass records the resulting `raw_output_ref` as
   `sscs_evidence.sbom_ref` alongside the trust score computed from the same document (spec 07 §3),
   so the score and the artifact that produced it are always the same row.
4. **Consumption.** Per-vulnerability findings (`capability=atlas`, one `Finding` row per vulnerable
   dependency) are what Findings, Threat Model, and Oracle's exploitability input already read. The
   SBOM document itself — the full dependency graph, not just the vulnerable slice — is for a human
   or an external tool that needs the whole bill of materials, which is what §8.2's download exists
   for.
5. **Retention.** Unchanged from spec 05 §7's general raw-output retention; this spec does not carve
   out a longer or shorter window for SBOMs specifically, on the reasoning that inventing a
   supply-chain-specific retention policy without a stated compliance requirement driving it would be
   a rule with no reason attached.

## 9. Triage process — consolidation, not new logic

Spec 17 §5 already defines dedup, prioritization, reachability, exploitability, false-positive
dampening, and toxic-combination detection, and `classify()` already implements the false-positive /
true-positive / needs-human-judgment split every caller (Findings, Patchwork) shares. What this spec
adds is visibility, covered above: `triage` as an actual filter (§5.1) and the Threat Model tab
reading the same grouped-findings data triage already annotates (§6.4). No new classification
category, no new engine — the gap being closed is "you can see it" versus "you can act on it," the
same gap §7 closes for remediation and §8 closes for the SBOM artifact itself.

## 10. Acceptance criteria

- A repo with a `Finding` row whose `asset_id` is null shows the same open-findings count on the
  portfolio and on that repo's Findings tab (both reduced by the same amount, not disagreeing) after
  `migrate_assets.py` runs; before the migration, both undercount consistently rather than
  disagreeing.
- The repo page renders exactly the eight tabs in §2.1's order and labels; `Dashboard` is the default.
- Harness renders no "Pipeline stages" section; "Enabled jobs" renders as a tile grid using
  `IndicatorTone` coloring, not a list.
- Findings can be filtered by `triage` (all four values) and by clicking a capability icon in the
  Found By column; both are reflected in the URL query string, matching every other filter on the
  page.
- The Threat Model tab renders at least the four groupings in §6.4 for a repo with findings in each
  of `dast`, `iac`, `atlas`, and `secrets`, each finding attributed to at least one STRIDE category
  from §6.2's table, and states `mapping_resolution: capability` visibly.
- `narrative_generator_url` unset (the default) renders no narrative section and no error.
- Clicking a finding with a `true_positive` classification and a matching deterministic fixer shows a
  diff via `preview` without opening a PR; clicking "Create PR" opens exactly one draft PR and the
  event appears in the Remediation tab's history with `pipeline_stage_reached=pr_opened`.
- Calling `fix` twice on the same finding after the first PR is already open does not open a second
  PR for the same finding (existing `off_limits`/branch-naming behavior, unchanged, exercised through
  the new endpoint).
- `GET .../sscs/sbom` returns the archived SBOM bytes for a repo with `sscs_evidence.sbom_ref` set,
  403s for a non-admin caller, and 404s with a distinguishing message for a row with no `sbom_ref` versus
  one whose file has been pruned.

## 11. Edge cases

- A finding with no `file_path` (e.g., a dependency-level `atlas` finding) previews as
  `no_fix_available` with the same rationale text `_attempt_fix` already produces for that case — no
  special-casing in the new endpoint.
- A finding that becomes part of a toxic combination between `preview` and `fix` (a second finding
  landed in between) is refused by `fix` with a rationale explaining the combination now claims it —
  reusing the existing `claimed` check from the batch path rather than allowing a fix that would
  conflict with a combination-level remediation.
- A repo with zero findings in any of the four Threat Model source capabilities renders every STRIDE
  category as empty with "no findings observed in the capabilities this category is derived from" —
  not hidden, on the same "silence is a bug" standard spec 01 §6 already holds every other view to.
- An `sscs_evidence` row with `sbom_ref` set but the underlying capability (`atlas`) currently
  disabled for the repo still serves the download — the artifact was captured while atlas was
  enabled and does not retroactively vanish because a toggle changed since.

## 12. Dependencies

Spec 05 (raw-output storage, §8.2), spec 06 (Aegis — Insider Threat tab rename only), spec 07 (Atlas —
`sscs_evidence`, §8), spec 08 (Patchwork — `_attempt_fix`, guardrails, §7), spec 09 (Oracle —
`inputs_snapshot` pattern reused for Threat Model's `mapping_resolution` honesty field, §6), spec 10
(dashboard query layer, §1), spec 14 (asset_id migration, §1), spec 17 (triage `classify()`, §5.1;
KEV/EPSS pattern that Threat Model's "present, clearly scoped" posture follows, §6.3).
