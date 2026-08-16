# Spec 10 — JDED Unified Dashboard

**Status:** Approved for build
**Depends on:** [05 — Data Lake](05-datalake.md), [09 — Oracle](09-oracle-risk-decision-engine.md)

---

## 1. Purpose

A single web dashboard ("JDED") giving security admins, developers, and
auditors one place to see security posture across every onboarded repo —
from a portfolio-wide view down to a single finding — replacing the need to
check each tool's own separate UI.

## 2. Views

### 2.1 Portfolio view (landing page)
- Table/grid of all onboarded (`status=active`) repos, one row each, showing:
  - Repo name, with direct links to the GitHub repository and its Concourse
    pipeline — "which pipeline produced this" should not cost a navigation
    (amended 2026-08-15)
  - The standard set of fifteen capabilities as icon badges, one consistent
    icon per capability everywhere in the UI: solid = implemented and
    reporting, dimmed = enabled but silent, greyed = not enabled. What is
    missing reads straight off the row.
  - **What "enabled" means depends on who scans the repo (amended
    2026-08-15):** the installer's ledger for Actions-scanned repositories,
    unioned with the capability *grants* for everything else. A
    Concourse-scanned repo never merges an install PR, and reading only the
    ledger showed three capabilities per repo while eleven were reporting.
  - Latest `overall_risk_score` (from Oracle's most recent `portfolio`
    decision, spec 09 §2)
  - **One open-findings count** (amended 2026-08-15). The severity breakdown
    lives on the repo page and the triage queue; the landing page answers
    "how much is open", once, per repo.
  - Latest Oracle recommendation (`go` / `review_recommended` / `no_go`)
  - Last scan freshness (most recent `ScanRun.completed_at` across all its
    capabilities)
- Sortable/filterable by risk score, capability, recommendation, org.
- Portfolio-wide summary cards: total open critical/high findings, repos
  with a stale scan (no run in > 7 days), count of `no_go` repos.

### 2.2 Per-repo drill-down
- **CapabilityManager** (added 2026-08-15): the standard fifteen checks as
  one-click toggles above the tabs. Enabling syncs ingestion grants
  immediately for pipeline-scanned repos and opens the workflow-install PR
  for Actions-scanned ones — the same `PATCH /api/repos/{id}/capabilities`
  either way (spec 03 §3a). The admin token stays server-side behind a route
  handler; the browser never holds it.
- **One dashboard** (revised 2026-08-16), then the views that are about
  something else. Findings, scan health, pipeline stages and pipeline jobs
  were four separate places, which meant the four questions people ask
  together — what is outstanding, is anything still scanning, is the pipeline
  green, is every stage covered — could not be answered without navigating.
  They are one labelled page. **Risk Decisions** (Oracle history with
  expandable `inputs_snapshot`/`reasoning`), **Supply chain** (Atlas trust
  score trend + SBOM links), **Insider Risk** (Aegis signal history per PR)
  and **Remediation** (Patchwork `RemediationEvent` history + draft PR links)
  stay behind tabs: each is a different subject with its own vocabulary, not
  another view of the same findings.
- **Open findings**, and three things that separate the view from the record
  the API also serves. All three pull the same way — towards a list of
  decisions rather than a list of reports:
  - *Open only.* A list mixing outstanding findings with ones somebody already
    accepted cannot be counted, and a count nobody trusts is ignored. The
    other statuses are one labelled click away, never hidden.
  - *Deduplicated.* Rows group on `(rule_id, package)`, so one rule firing in
    forty files is one row and one decision, and one CVE reported by both the
    dependency scan and the container scan is one vulnerability rather than
    two. Every occurrence is carried in the row and keeps its own
    `finding_id`: a disposition applies to the occurrence, because accepting
    the risk in one file is not accepting it in forty.
  - *Correlated.* Toxic combinations (spec 08 §5) are detected over the open
    findings themselves rather than read out of `remediation_events`, which
    only exist where Patchwork has run — and a repository that never enabled
    auto-remediation is exactly the one nobody has told about its
    unauthenticated database. They are drawn above the table and colour the
    rows that belong to them, because a combination whose halves are
    individually unremarkable sorts below a lone high on every
    severity-ordered list ever built.
  - Each row carries the same triage classification Patchwork uses
    (`patchwork/triage.py`), so the platform cannot call a rule a likely false
    positive on one page while generating a fix for it on another.
- A finding detail panel: full `raw_finding_json`, first/last seen,
  status, and a "mark as false positive" / "accept risk" action that
  writes back to `Finding.status` (spec 05 §3) **and** logs a retro signal
  (spec 11 §4). Fetched by id rather than found in a page of the flat list —
  once occurrences are grouped, the one somebody clicked is routinely not in
  the first hundred rows of anything.
- **Scan health** is one box per check rather than a table: the fraction of
  that capability's runs that succeeded, with the counts under it so the
  percentage can be checked rather than believed. A box is drawn for every
  *enabled* capability, not only for those with run history — a lane switched
  on that has never run is the gap nothing else shows, because no failing run
  disagrees with it.
- **Pipeline stages and enabled jobs** are rows of labelled indicator lights.
  Colour is never the only carrier: each light is followed by its state in
  words, and a legend sits under each row. "Not enabled" and "enabled and
  silent" stay visibly different states — they render as the same absence
  everywhere else, and only one of them is a problem.
- **Where this repository is built and scanned.** A link to the repository
  on GitHub, and — where Concourse has a pipeline for it (spec 15 §4a) —
  that pipeline with each job's last build and a link to it. A repository
  with no Concourse pipeline says so rather than showing an empty panel: it
  is scanned by Actions, and that is a fact about it, not a gap in the page.

  Deliberately a link, not a mirror. Mykronos does not restate a build's
  outcome as its own; the pipeline's own UI is one click away and is the
  authority on its own state. What the dashboard adds is knowing *which*
  pipeline, from a page that is already about this repository.

### 2.3 Maturity / trend view

**Trends** — per-repo and portfolio-wide series over time: finding count by
severity, `overall_risk_score`, SSCS trust score, mean time-to-fix.

**`superseded` findings are excluded from every one of these** (spec 05 §5a).
A record withdrawn because the adapter that produced it was wrong is neither
outstanding work nor completed work. Counting it as open overstates the
backlog; counting it as fixed reports resolution that never happened, and
mean-time-to-fix reads only `fixed`, so a corrected adapter would register as
a mass remediation. The status exists precisely so neither number moves.

No time-series table is needed for any of these, and adding one would be a
mistake. Every series is reconstructible from records the lake already holds:
a `Finding` carries `first_seen_at` and `resolved_at`, so the open count on
any past date is a query rather than a snapshot; `risk_decisions` and
`sscs_evidence` are already append-only per evaluation. A parallel table of
daily rollups would be a second copy of the truth, able to disagree with the
first, and §6 requires every number to be reproducible from the underlying
rows.

**Maturity** — a qualitative tier per repo, inferred from quantitative
signals, in the spirit of BSIMM/SAMM. Tiers and thresholds live in
`maturity-model-v1.yaml` at the repository root, versioned and reviewed in a
pull request for the same reason the Oracle policy is (spec 09 §5): a
definition of "good" that can be edited in a database is one nobody can
audit.

**Criteria measure evidence, not switch positions.** An earlier draft of this
spec gave "Oracle blocking enabled" as an example criterion. That contradicts
spec 09 §6, which makes blocking opt-in, off by default, and conditional on
shadow-mode data showing what it would have cost. A maturity model that scores
a team higher the moment they flip that switch is pushing them to do the thing
spec 09 says to do only with evidence in hand — and the fastest way to a high
score would be to turn on a gate nobody agreed to, which is how the whole
platform gets switched off.

So the criteria reward the *evidence*: enough judged pull requests to have a
shadow-mode signal at all, dismissals carrying written reasons, findings not
ageing. A repo that has earned the right to turn blocking on scores as a repo
that has earned it, whether or not it has.

**Every tier shows its working.** A tier is a derived label, and §6 forbids
dashboard-only numbers that cannot be traced back. The view therefore renders
each criterion with its measured value, its threshold, and whether it passed —
so "Tier 2" is never the whole answer, and the next tier always comes with the
specific thing standing between the repo and it.

### 2.4 Retro / learning view
- Surfaces the Knowledge Store's synthesized retro reports (spec 11 §6):
  recurring false-positive patterns, categories of overridden decisions,
  trend reports across sprints/periods.

## 3. Data access pattern

- All dashboard views are **read-only queries against the data lake**
  (DuckDB, spec 05 §8) through a thin backend query service — the frontend
  never talks to the data lake directly.
- Query service exposes paginated, filterable REST endpoints per view
  (e.g., `GET /api/dashboard/portfolio`, `GET /api/dashboard/repos/{id}/findings`)
  backed by parameterized DuckDB SQL views defined once in the backend
  (not ad hoc query strings scattered across endpoint handlers).
- Heavy aggregate queries (portfolio summary cards, trend lines) *may* be
  pre-computed on a schedule into small materialized DuckDB views to keep
  dashboard load times fast regardless of data lake size — but only where a
  measurement shows they need to be. Materialization buys speed with a
  staleness window and a refresh job to keep working; that is a bad trade for
  a query already inside the §6 budget. The portfolio aggregate was measured
  and left live (docs/DECISIONS.md D-016), with the budget enforced as a test
  so the decision is revisited by a failure rather than by an opinion. Trend
  series are held to the same rule.

## 4. API endpoints (backend, dashboard-facing)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/dashboard/portfolio` | Portfolio view data (§2.1) |
| `GET` | `/api/dashboard/repos/{id}/findings` | Filterable finding list for one repo — the record, every status, one row per report |
| `GET` | `/api/dashboard/repos/{id}/open-findings` | The view: open findings only, grouped one row per problem, triaged, with toxic combinations named (§2.2) |
| `GET` | `/api/dashboard/findings/{finding_id}` | One finding, for the detail panel. Raw output admin-only (§5) |
| `GET` | `/api/dashboard/repos/{id}/decisions` | Oracle decision history for one repo |
| `GET` | `/api/dashboard/repos/{id}/remediation` | Patchwork event history for one repo |
| `GET` | `/api/dashboard/repos/{id}/sscs` | Atlas evidence/trust-score history |
| `GET` | `/api/dashboard/repos/{id}/insider-risk` | Aegis signal history |
| `GET` | `/api/dashboard/repos/{id}/scan-health` | ScanRun history/freshness |
| `GET` | `/api/dashboard/repos/{id}/ci` | Where this repo is built: GitHub links, and Concourse pipeline state where there is one (spec 15 §4a) |
| `PATCH` | `/api/dashboard/findings/{finding_id}/status` | Mark false positive / accept risk (writes `Finding.status` + retro signal) |
| `GET` | `/api/dashboard/trends` | Portfolio and per-repo trend series |
| `GET` | `/api/dashboard/retros` | Latest synthesized retro reports (spec 11) |

## 5. Auth & access control

- Admin/auditor authentication is separate from the GitHub App
  service-to-service auth (spec 02) — see spec 12 §3 for the human-user
  auth model (SSO recommended).
- Role-based access: `admin` (can onboard repos, change capability config,
  override decisions), `viewer`/`auditor` (read-only across everything),
  optionally a `repo-scoped` role limited to specific repos' data (for
  large orgs where not every viewer should see every repo).

## 6. Acceptance criteria

- Portfolio view loads in under 2 seconds for a portfolio of 200 onboarded
  repos. (Originally "using pre-aggregated materialized views" — the live
  aggregate was measured comfortably inside the budget and the cache was
  deliberately not built; the measurement is an enforced test. See D-016 and
  §3.)
- Every number shown in the UI is traceable to its underlying data lake
  rows (no dashboard-only derived numbers that can't be reproduced by a
  direct data lake query — required for audit trust).
- Marking a finding as a false positive updates its status immediately in
  the UI and is reflected in Oracle's next evaluation (via the false-positive
  dampening input, spec 09 §4) within one scheduled decision cycle.

## 7. Edge cases

- Repo has capabilities enabled but zero scans have completed yet
  (freshly onboarded) — dashboard shows an explicit "awaiting first scan"
  state per capability, not a blank/misleading "0 findings." The stages
  cross-check (spec 15 §4a.1, added 2026-08-15) generalises this:
  enabled-versus-reporting is rendered per stage, with `event_driven` for
  capabilities that never produce a ScanRun, and enabled-plus-never-reported
  flagged as the problem it is.
- A repo is `removed` (offboarded) — excluded from the live portfolio view
  by default, but remains queryable via an "include removed repos"
  toggle for audit purposes (historical data is retained per spec 02 §6).

## 8. Dependencies

- Spec 05 for all underlying data.
- Spec 09 for decision data and explainability fields.
- Spec 11 for retro/trend report content.
- Spec 12 for human-user authentication and RBAC.
