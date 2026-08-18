# Spec 17 — Harness Promotion, Threat Intelligence, and the i2i Grooming Process

**Status:** Draft for review
**Depends on:** [04 — Scanner Workflows](04-scanner-workflows.md), [05 — Data Lake](05-datalake.md),
[08 — Patchwork Integration](08-patchwork-integration.md), [09 — Oracle](09-oracle-risk-decision-engine.md),
[10 — JDED Dashboard](10-jded-dashboard.md), [11 — Knowledge Store & RAG](11-knowledge-rag-learning.md),
[15 — Concourse Pipeline](15-concourse-pipeline.md)

---

## 0. What this spec is against

The roadmap (spec 13) closed at Phase 7; work since then is tracked as decisions and retros
rather than phases (README "Status"), and this spec follows that convention — it is not a
new roadmap phase. It is also written against the **current** state of the repo pages, not
the Phase-7 snapshot: as of this spec, the "Dashboard" tab (`frontend/app/repos/[repoId]/page.tsx`)
already renders capability toggles (`CapabilityManager`), pipeline stage/job status
(`PipelinesPanel`, spec 15 §4a), and an open-findings list, all as sections inside one tab. A
first read of "add a harness tab, add a findings tab, put build links at the top" could sound
like new features. They mostly are not — the content already exists and is already good; it is
organized as sections of a general-purpose tab rather than as the dedicated views their own
weight justifies. This spec is explicit throughout about which parts are **reorganization of
real, working code** and which parts are **genuinely new** — conflating the two would misstate
how much of this is actually risk.

## 0a. Implementation status (as of this spec's first commit)

Built in the same change that added this spec, so the table below is not
aspirational — each `done` row has a merged implementation and tests:

| Item | Status |
|---|---|
| Harness tab (§2.1, §2.2) — `CapabilityManager` + scan health + `PipelineCoverage`, buttons on real `IndicatorTone` colour | Done |
| Built by / Scanned by at the top of the page (§2.3) | Done |
| Findings tab, split from the former combined "Dashboard" tab (§2.4) | Done |
| Findings/triage `rule_id` search, `suppressed`/`superseded` status filters, `superseded_by` surfaced (§3) | Done |
| `first_seen_after`/`first_seen_before` on the flat `findings()` endpoint (§3) | Done — not yet wired into `open_findings()` or any filter UI |
| Threat Intelligence: `ThreatIntelMatch`, KEV/EPSS fetch+parse+upsert, daily job, `/api/dashboard/threat-intel`, nav page (§4) | Done |
| Exploitability as an Oracle input, KEV boost on toxic combinations (§5.4) | Done — `OracleEngine(db=...)`, `correlate.kev_boosted()` |
| Reachability as an Oracle input (§5.3) | Done, honestly — always `available: False`; no call-graph engine exists, this is the "present, not omitted" plumbing only |
| KEV/EPSS badges on Findings-tab rows (§4.4) | Done — `_attach_threat_intel`, `cve_id`/`in_kev`/`epss_score` on each group |
| `min_epss`/`kev_only` finding filters; the same badge on the Triage queue (§3, §4.4) | Not started — `triage_queue()` is a flat query, not the grouped one the badge attaches to |
| On-demand scan dispatch (§2.5) | Done — `dispatch_workflow`, `ConcourseClient.trigger_job`, `POST /api/repos/{id}/scan`, "scan now" button |
| `ai` capability default tool (§6) | Done — `mykronos/ai_pin_check.py` (SDK pin check), `workflow-templates/ai.yml.j2`; prompt-injection and eval-regression detection remain unbuilt on purpose |
| i2i grooming (§7) | Not started |

The unstarted rows are not silently dropped — see `docs/DECISIONS.md` for the
entry logging this split and the follow-up issues it points to.

## 1. Purpose

Four real gaps, named precisely:

1. The Harness and Findings content is buried in a catch-all "Dashboard" tab instead of having
   its own tabs, and the capability enable/disable buttons don't use the color vocabulary the
   rest of the dashboard already has for exactly this distinction (§2).
2. Findings filtering stops at severity/capability/status, and two real `Finding.status` values
   (`suppressed`, `superseded`) are invisible in the UI entirely (§3).
3. Nothing in the platform consumes public exploitation data — no KEV, no EPSS — so "how urgent
   is this, right now, in the world" is a question only Oracle's static severity weighting
   answers (§4, §5.4).
4. There is no path from "the triage queue says this matters" to "a developer has a ticket with
   acceptance criteria," and the `ai` capability (D-047) is a registered config slot with no
   default tool behind it (§6, §7).

## 2. Harness: promotion, not invention

### 2.1 What already exists, and what doesn't

`CapabilityManager` (`frontend/components/capability-manager.tsx`) is a real, working
enable/disable control — one button per capability, calling the existing
`PATCH /api/repos/{id}/capabilities`. `PipelinesPanel` (`frontend/components/pipelines.tsx`) is
a real, working consolidation of exactly what this spec's original draft asked for: it already
renders `PipelineLinks` ("Built and scanned by", GitHub + Concourse), `StageLights` ("Pipeline
stages" — the standard-set coverage cross-check, spec 15 §4a.1), and `JobLights` ("Enabled
jobs" — each Concourse job's last build, linked). **Combining pipeline steps and enabled jobs
is already done** — `PipelinesPanel` is that combination, one component, already.

What's missing is placement and one piece of styling:

- All of this renders **inside the "Dashboard" tab**, below the tab bar, mixed with the Scan
  health section and the open-findings list (`page.tsx` §Dashboard component). It reads as one
  long page rather than a place to go specifically to check "is scanning healthy" versus "what
  did scanning find."
- `CapabilityManager`'s buttons use `border-accent`/`bg-accent` styling for on/live states and
  `border-rule` for off — a different, narrower palette than `IndicatorTone`
  (`primitives.tsx`: `ok`/`bad`/`warn`/`idle`/`off`, already mapped to `bg-pass`/`bg-critical`/
  `bg-high`/neutral) that `PipelinesPanel` uses two sections below it, on the same page, for the
  same underlying question ("is this running and is it healthy").

### 2.2 The change

**New top-level tab: Harness**, replacing the "Dashboard" tab's current catch-all role for this
content. It contains, in order: `CapabilityManager`, then `PipelinesPanel`. No new data-fetching
— both already read from `GET /api/repos/{id}` and `GET /api/dashboard/repos/{id}/ci`
respectively.

**Button color, restated on the existing vocabulary** — no new tone system:

| `IndicatorTone` | When a capability button is in this state |
|---|---|
| `ok` (green, `bg-pass`) | Enabled, and reporting — `PipelineStatus` shows a job for it with `status: "succeeded"` within the reporting grace window (`ci.py` `Reporting.state == "reporting"`), or it's a non-scanning event-driven capability (`aegis`, `oracle`, `patchwork` — `ci.py` `NON_SCANNING`) that's simply enabled |
| `bad` (red, `bg-critical`) | Enabled, and its `Reporting.state` is `never_reported` or its stage `StageCoverage.state` is `no_job` — running and not answering, or claimed and nothing produces it |
| `warn` (amber) | Enabled, `Reporting.state == "silent"` — was reporting, has gone quiet |
| `idle` | Enabled, `not_run` — enabled, hasn't had a build yet, not a fault |
| `off` | Not enabled |

This is exactly `ci.py`'s existing `coverage()`/`reconcile()` output — `CapabilityManager`
today receives `enabled`/`pending`/`live` (a derived boolean) and needs to additionally receive
the `CiPage` the Harness tab is already fetching for `PipelinesPanel`, so one button can answer
from the same `StageCoverage`/`Reporting` rows the sections below it already render. No new
backend computation — a prop, not a new endpoint.

Clicking a `bad` (red) button does not immediately toggle it off — matching `PipelinesPanel`'s
own `ReportingGaps` pattern, it expands to show *why* (`StageCoverage.problem` reason, or the
matching `Reporting` row), since the first useful action on a red capability is reading why it's
red, not silencing it.

### 2.3 Built by / Scanned by, moved to the top

`PipelineLinks` moves out of the Harness tab's body and renders once, directly under the page
header (`Crumb`/repo name/status pill), above the tab bar — visible regardless of which tab is
open. This is a placement change to an existing component, not new data or a new query; `GET
/api/dashboard/repos/{id}/ci` is already fetched once per page load today and stays that way.

### 2.4 Findings: promotion, not invention

**New top-level tab: Findings**, containing exactly what the "Dashboard" tab's "Open findings"
section renders today (`OpenFindings`, grouping, toxic-combination block, disposition detail
pane) — moved, not rebuilt. The "Dashboard" tab is removed once Harness and Findings absorb its
two halves; nothing about the repo page loses a capability, it gains two names for what used to
be one undifferentiated one.

### 2.5 On-demand scan — genuinely new

No "scan now" capability exists anywhere in the platform today (confirmed: no `dispatch_workflow`
call site, no Concourse trigger-build call site, no such UI). Given spec 15 made Concourse the
primary execution environment, dispatch has to branch on `RepoOnboarding.scanned_by`
(`concourse | github_actions | none`, `db/models.py`):

- **`concourse`**: a new `ConcourseClient.trigger_job(pipeline: str, job: str) -> None` (`ci.py`),
  `POST /api/v1/teams/{team}/pipelines/{pipeline}/jobs/{job}/builds`. Unlike the read path
  (§4a, anonymous), triggering a build is a write against infrastructure spec 15 §7 already
  flags as sensitive (a worker inside the LAN), so this call requires the credential-managed
  Concourse token spec 15 §6 already establishes for the deploy job — not a new secret, a new
  authorized use of the existing one, admin-only (same `AdminDep` gate as
  `PATCH /api/repos/{id}/capabilities`).
- **`github_actions`**: the new `GitHubClient.dispatch_workflow` (§2.5.1).
- **`none`**: the action is disabled in the UI with the same explanation `PipelinesPanel`
  already gives for an unconfigured repo.

```python
async def dispatch_workflow(
    self, repo_full_name: str, workflow_file: str, ref: str, inputs: dict[str, str] | None = None
) -> None: ...
```

added to the `GitHubClient` Protocol (`github/client.py`) alongside every other method, on both
`RestGitHubClient` (`POST /repos/{owner}/{repo}/actions/workflows/{id}/dispatches`) and
`FakeGitHubClient` (records the call, same pattern as every other fake method — spec 08 §3's
"no merge method exists" precedent is the model for how a fake asserts a protocol boundary).

`POST /api/repos/{id}/scan` dispatches every currently-enabled scanning capability (`sast`,
`dast`, `secrets`, `containers`, `iac`, `cloud`, `atlas`) via whichever path `scanned_by`
selects, and refuses (`409`) a capability still `pending` install. It does not wait for a
result — both dispatch APIs are fire-and-forget; the new runs surface on the Harness tab the
same way a scheduled run would once they complete and call the existing upload step.

## 3. Findings — filter and status-visibility gaps

Confirmed absent today, across `dashboard.py findings()`/`open_findings()`/`triage_queue()` and
their API/UI layers: `rule_id` search, any date-range filter. Also confirmed: `Finding.status`
has seven real values (`schemas.py`) — `open`, `accepted_risk`, `false_positive`/dismissed,
`fixed`, **`suppressed`**, **`superseded`** — and the UI's status filter (`open-findings.tsx`
`STATUSES`) offers four of them. `superseded_by` isn't even selected in the query column list,
so there's no way to follow a re-fingerprinted finding to what replaced it (§5.1 restates why
this matters).

Additive changes, no breaking response-shape change:

| New parameter | Applies to |
|---|---|
| `rule_id` (substring, case-insensitive, matched against `rule_id` and `title`) | `findings`, `open_findings`, `triage_queue` |
| `first_seen_after` / `first_seen_before` | `findings`, `open_findings` |
| `status` gains `suppressed`, `superseded` as valid values | `open-findings.tsx` `STATUSES`, and the backend already accepts any `FindingStatus` value — this is a frontend-only gap |
| `superseded_by` added to the selected columns | `findings()`, so a superseded row can link to its replacement |
| `min_epss`, `kev_only` | `findings`, `open_findings`, `triage_queue` — depends on §4 |

## 4. Threat Intelligence — genuinely new

Confirmed absent entirely: no `epss`/`kev`/`threat_intel` anywhere in the codebase.

### 4.1 Sources

| Source | Provides | Cadence |
|---|---|---|
| **CISA KEV** (Known Exploited Vulnerabilities catalog) | Boolean: actively exploited in the wild | Daily, full-catalog JSON |
| **FIRST EPSS** | 0–1 probability of exploitation in the next 30 days | Daily, full-catalog CSV |

Both are public, unauthenticated, CVE-keyed data about vulnerabilities in general — not a repo's
own content leaving the platform, unlike `ai_classifier_url`/`fix_generator_url` (spec 06 §5,
spec 08 §5, spec 12 §5.2). No opt-in gate is needed for the fetch itself for that reason.

### 4.2 Data model — `ThreatIntelMatch` (data lake table, `lake/tables.py`)

| Field | Type | Notes |
|---|---|---|
| `cve_id` | VARCHAR | PK |
| `in_kev` | BOOLEAN | |
| `kev_added_at` | DATE, nullable | |
| `kev_due_date` | DATE, nullable | |
| `epss_score` | DOUBLE, nullable | 0–1 |
| `epss_percentile` | DOUBLE, nullable | 0–1 |
| `fetched_at` | TIMESTAMP | |

One row per CVE platform-wide, not per finding — matched at query time against
`Finding.rule_id`/`title` via a `CVE-\d{4}-\d+` pattern (Trivy's `rule_id` is the CVE itself;
Atlas/OSV-derived findings carry it in `title`). Computed in the query layer, not stamped onto
`Finding` at ingestion, because `epss_score` moves daily for a CVE whose finding hasn't changed
at all.

### 4.3 Refresh job

Daily, same scheduling pattern as the retro/trend jobs (spec 11 §7). Upserts only CVEs actually
referenced by an open finding somewhere in the portfolio — not the full ~1,300 KEV entries or
~280,000 EPSS-scored CVEs. Fetchers are injectable (`fetch_kev`, `fetch_epss`), same pattern as
`embed_fn` (spec 11 §8): tests exercise parsing/matching against fixtures, never a live call.
Fetch failure logs and keeps yesterday's rows rather than blocking anything — same
degrade-not-block rule as spec 11 §6's retrieval failures.

### 4.4 Surfacing

- Findings tab / Triage queue: a `KEV`-listed finding gets a critical-tone pill next to its
  severity regardless of the scanner's own rating — a KEV medium is a medium the scanner
  underrated, not one to skip. `epss_score >= 0.5` gets a smaller marker.
- **New top-level nav item: Threat Intelligence** — every CVE currently matched to an open
  finding, sorted `in_kev` then `epss_score` descending, linking to every affected repo/finding.
  A separate ordering from Oracle's severity-driven queue on purpose: EPSS moves day to day in a
  way severity doesn't, and merging the two orderings would make neither legible.

## 5. Triage, named against what's actually there

### 5.1 Dedup — mostly built; the visible gap is narrow

Deduplication itself is real and working: findings are grouped `(rule_id, package_name)` in the
query layer (`dashboard.py`) and the UI shows a "+N more occurrences" count and a
`page.deduplicated` summary figure. What's genuinely missing is narrower than "dedup
visibility" as a whole: `FindingStatus.SUPERSEDED` — a re-fingerprinted finding's *prior*
identity — has no UI representation at all: not filterable, not fetched (`superseded_by` isn't
even selected), not displayed. §3's `superseded` status option and `superseded_by` column close
exactly this, and nothing more.

### 5.2 Prioritize — already built

Oracle (spec 09) plus the triage queue's severity-then-age ordering. No new work. §4.4 adds a
second, EPSS-driven ordering alongside it, not a replacement.

### 5.3 Reachability — new, and staying honest about v1's limit

Confirmed absent: no reachability scoring, field, or engine anywhere. **Is the vulnerable code
reachable from anything the application runs**, as opposed to dead code or a vendored,
never-imported dependency.

v1 wires a `reachability` category into Oracle's `inputs_snapshot`, present with
`available: False` and a reason on every decision (spec 09 §9's own rule for unwired categories)
rather than silently absent. It does **not** add a `Finding`-level column or a call-graph/
import-tracing engine — a lake column that is `unknown` on every row until an engine exists
would be exactly the "dashboard-only number nothing traces to" spec 10 §6 forbids, just moved
into the schema instead of the UI. When a real engine exists, it earns a `Finding.reachability`
column and this category starts reporting `available: True` for the repos it covers; until then,
the honest thing is one static category, not a field nothing populates.

### 5.4 Exploitability — new, and fully defined via §4

**Is this specific finding believed to be exploited right now** — different from severity, which
describes the vulnerability class rather than current activity. §4's `ThreatIntelMatch` answers
this directly for any finding with a matchable CVE: `in_kev`, `epss_score`. Findings without a
CVE (most SAST/IaC findings) stay `unknown` — there's no public feed for "is this SQL-injection
*pattern* being exploited," and a fabricated proxy score would violate Oracle's own
"explainability over sophistication" principle (spec 09 §5).

Wired into Oracle as a new additive term, not a restructuring of the tested band-count curve
(spec 09 §9's determinism guarantee): each open, in-scope, KEV-listed finding contributes
`weight(next_band) - weight(this_band)` — one band's worth of points — as its own `Term`, cited
by CVE id and KEV date, so it's individually auditable rather than folded into an aggregate. A
`critical` finding has nowhere further to boost and contributes nothing extra; the exploitation
is already reflected in every band below it. Requires `OracleEngine(db=...)` — the operational
database `ThreatIntelMatch` lives in, not the lake `OracleEngine` otherwise only reads — optional
like `store`, so a caller that hasn't wired it up gets `exploitability: unavailable` rather than
a crash.

`patchwork/correlate.py` gains `kev_boosted()`, a function over already-detected combinations
rather than a static field on `CombinationRule` — whether a *specific detected instance* involves
an actively-exploited CVE is a fact about which findings matched, not about the rule that fired,
and a rule-level flag couldn't express that. When a combination's members include a KEV-listed
CVE, its `rationale` is prefixed to say so — a toxic pair under active exploitation is a different
urgency
than one that merely could be.

### 5.5 False positive — already built; one scope note

Patchwork's triage stage already classifies `true_positive`/`likely_false_positive`/
`needs_human_judgment` via the Knowledge Store, and Oracle already dampens confirmed
dismissal history (spec 09 §5, spec 11 §6.1). Both are scoped to Patchwork's
`source_capabilities` (default `sast, secrets, containers, iac`) — `dast`/`cloud`/`network`
findings are dismissible from the dashboard but never reach the classifier. No schema change
needed (`source_capabilities` is already per-repo config); this spec's only recommendation is
widening the platform default so "false positive" triage isn't silently narrower than the
dismiss button implies.

### 5.6 Toxic combination — already built and mature

`patchwork/correlate.py` already implements exactly this: declarative rules, a built-in set
spanning single-capability, cross-capability, and network-crossed-with-application combinations
(the last of these already correlating DAST/SAST/Secrets/Cloud/Network — more thorough than a
first read of "flesh this out" would suggest is needed). §5.4 above is this spec's only addition
to it.

## 6. The `ai` capability — fleshing out a real gap, correctly named

**"AI CI/CD checks" already names something specific in this codebase**, and it isn't a Check
Run — it's the `ai`/`ai-checks` capability (D-047), covering three of the four concerns "AI" was
split into: prompt-injection surface, model/dependency provenance, and evaluation regression
(the fourth, AI-authorship disclosure, deliberately stays in Aegis). The capability is already
registered (`Capability.AI`, `AiConfig`) and the adapter side already accepts SARIF from any
tool — `adapters/registry.py`'s `AdapterSpec("ai", "mykronos-ai-checks", ...)` predates this
spec. What's missing is narrower than "no adapter": **no default tool is wired** — no
`workflow-templates/ai.yml.j2`, so nothing ever produces the SARIF that adapter is waiting for.
It is a slot with a working intake and nothing feeding it, which is the honest reading of
"flesh out."

v1 adds one deterministic, first-party checker (`mykronos/ai_pin_check.py`) — matching the
D-047 framing verbatim ("an unpinned model is treated like an unpinned dependency") — rather
than a model-based scanner, consistent with Patchwork's own "deterministic first, LLM-assisted
later, off without a configured endpoint" pattern (spec 08 §2 stage 4):

- **Provenance/pin check**: scans `requirements*.txt` and `package.json` for a named set of AI
  SDK packages (`anthropic`, `openai`, `google-generativeai`, `@anthropic-ai/sdk`, etc.) pinned
  to a floating version (`>=`, `^`, `~`, no version, `latest`) rather than an exact one — the
  same class of finding Atlas already produces for ordinary dependencies, scoped to a named AI
  package list rather than every dependency. Deliberately **not** scanning source code for
  literal model-name strings (`claude-*-latest`) — that needs per-language parsing to avoid
  false-positiving on string literals that aren't API calls, and is a larger, separate piece of
  work than a manifest pin check. Emits SARIF directly (no bespoke adapter needed, since the
  intake already accepts any SARIF), uploaded through the standard contract (spec 04 §2).
- Prompt-injection-surface and eval-regression detection are **not** built in v1 — they need
  either a runtime harness (eval regression) or a semantic classifier (prompt injection) that
  a deterministic pattern check cannot honestly claim to do, and are left as the capability's
  next tool rather than stubbed with a check that would produce false confidence.

`workflow-templates/ai.yml.j2` follows the same pattern as `atlas.yml.j2`'s own first-party
Python step: install the `mykronos` package (`mykronos_package_spec`), run the module, upload
through the shared step with no `tool_name` override needed — `default_tool("ai")` already
resolves to `mykronos-ai-checks`.

## 7. i2i — from triage output to a dev-ready story

Confirmed absent: no issue-creation method on `GitHubClient`, no grooming/story logic anywhere.

### 7.1 Dev-ready fields

A `TriageStory` is dev-ready only when every field is populated (missing fields render as
missing, never silently dropped — `dev_ready: false` names the gap):

| Field | Populated from |
|---|---|
| Title, description | `Finding.title`/`.description`, or `Combination.rationale` (§5.6) |
| Severity + Oracle contribution | `Finding.severity`; its weighted contribution from the repo's last `RiskDecision.inputs_snapshot` |
| Reachability | §5.3 — `unknown` is honest and does not block dev-ready status |
| Exploitability | §5.4 — same rule |
| Dedup history | count of prior `superseded` identities for this fingerprint lineage (§5.1) |
| False-positive precedent | any Knowledge Store entry for this `rule_id` in this repo |
| Suggested fix | `RemediationEvent.rationale` if Patchwork already produced one, else `no_fix_available` verbatim |
| Acceptance criteria | generated per capability from a template (e.g., SAST: "the flagged line no longer matches `rule_id`'s pattern on re-scan"; dependency: "the pinned lockfile version is at or above the fixed version") |

### 7.2 Mechanics

```python
async def create_issue(
    self, repo_full_name: str, title: str, body: str, labels: list[str] | None = None
) -> IssueRef: ...
```

added to `GitHubClient` alongside `dispatch_workflow` (§2.5.1), on the Protocol and both
implementations. `POST /api/triage/{finding_id}/groom` (and a `/combinations/{id}/groom`
variant) builds a `TriageStory`, renders it as an issue body, and opens or updates it — looked
up by a derived id (SHA-256 over `repo_full_name` + finding/combination id, same pattern as
`finding_id`/`event_id`/`entry_id`) so grooming twice updates one issue rather than duplicating
it. Labelled `mykronos:dev-ready` or `mykronos:needs-triage` per §7.1's check.

**This is issue creation, not pull-request creation, and not a merge.** Patchwork's hard line —
opens draft PRs, never merges, enforced by the protocol having no merge method at all — is
untouched: `create_issue` is a work item, not a repository content change, and independent of
whether Patchwork ever generates a fix for it. A human still writes and merges the actual change.

### 7.3 From dev-ready to shipped

Ordinary GitHub flow from there: a branch, a PR referencing the issue, review, merge. Nothing new
is needed to close the loop — Oracle already gates the PR, Patchwork may already have a companion
draft PR open, and `RemediationEvent` outcomes already feed the Knowledge Store regardless of
whether the fix started from a groomed issue.

## 8. API endpoints (new)

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/repos/{id}/scan` | Dispatch every enabled scanner now, via Concourse or Actions per `scanned_by` (§2.5) |
| `GET` | `/api/dashboard/threat-intel` | Portfolio-wide CVE list with KEV/EPSS (§4.4) |
| `POST` | `/api/triage/{finding_id}/groom` | Build/open a dev-ready GitHub issue for one finding (§7.2) |
| `POST` | `/api/triage/combinations/{id}/groom` | Same, for a toxic combination |

`GET /api/dashboard/repos/{id}/findings`, `/open-findings`, and `GET /api/dashboard/triage`
gain the §3 filter parameters — additive only.

## 9. Acceptance criteria

- The Harness tab renders `CapabilityManager` and `PipelinesPanel` with no new data-fetching
  beyond what each already performs today; the Findings tab renders exactly what the current
  "Open findings" section renders. The "Dashboard" tab is retired once both absorb its content.
- A capability button is green only when enabled and reporting (or event-driven and enabled);
  red only when enabled and `never_reported`/`no_job`; using `IndicatorTone`, not a new palette.
- "Built and scanned by" renders once, above the tab bar, regardless of the active tab.
- `POST /api/repos/{id}/scan` dispatches via Concourse for `scanned_by: concourse` repos and via
  GitHub Actions for `scanned_by: github_actions` repos, and refuses (409) a pending capability.
- `suppressed` and `superseded` are selectable status filters, and a superseded finding's row
  links to `superseded_by`.
- `ThreatIntelMatch` rows exist only for CVEs referenced by an open finding; a feed failure
  leaves prior rows in place.
- `Finding.reachability`/`.exploitability` never render identically to a confirmed-absent state
  when their true value is `unknown`.
- The `ai` capability produces at least one real finding class (unpinned AI dependency/model
  reference) end to end: workflow template → adapter → lake → dashboard.
- Grooming the same finding twice updates one GitHub issue, never opens a second.

## 10. Edge cases

- A repo has no capabilities enabled — Harness renders all rows `off`, "Scan now" is inert with
  an explanation, and the Built/Scanned-by line shows nothing (no run has ever happened).
- A finding's `rule_id` looks like a CVE but isn't (rare false match against the pattern) — the
  threat-intel join simply returns no row, same as any CVE with no KEV/EPSS data; not an error.
- A repo's `scanned_by` is `concourse` but its derived pipeline name (§15 §4a) doesn't exist in
  Concourse — "Scan now" reports the same "no pipeline named X" state `PipelineLinks` already
  surfaces, rather than attempting a dispatch against nothing.
- KEV/EPSS data changes after a `TriageStory` was already groomed against it — the issue isn't
  retroactively updated; re-running `/groom` refreshes it, matching §7.2's update-not-duplicate
  behavior, but nothing pushes unsolicited changes into an issue nobody asked to refresh.

## 11. Dependencies

- Spec 04/05 for `ScanRun`/`Finding` and the dedup/superseded semantics §5.1 surfaces.
- Spec 08 for Patchwork's triage/correlate/remediation machinery extended by §5.4–§5.6, §7.3.
- Spec 09 for the `inputs_snapshot` contract §5.3/§5.4 must honor.
- Spec 10 for the dashboard views restructured (Harness, Findings) and added to (Threat Intel).
- Spec 11 for the Knowledge Store consulted by §5.5 and fed by §7.3.
- Spec 15 for `ConcourseClient`, `scanned_by`, and the coverage cross-check §2.2's colors reuse.
