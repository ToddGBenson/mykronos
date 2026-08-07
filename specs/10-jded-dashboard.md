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
  - Repo name, enabled capabilities (icon badges)
  - Latest `overall_risk_score` (from Oracle's most recent `portfolio`
    decision, spec 09 §2)
  - Open finding counts by severity
  - Latest Oracle recommendation (`go` / `review_recommended` / `no_go`)
  - Last scan freshness (most recent `ScanRun.completed_at` across all its
    capabilities)
- Sortable/filterable by risk score, capability, recommendation, org.
- Portfolio-wide summary cards: total open critical/high findings, repos
  with a stale scan (no run in > 7 days), count of `no_go` repos.

### 2.2 Per-repo drill-down
- Tabs: **Findings** (filterable table by capability/severity/status),
  **Risk Decisions** (Oracle history for this repo with expandable
  `inputs_snapshot`/`reasoning`), **Remediation** (Patchwork
  `RemediationEvent` history + links to draft PRs), **SSCS Evidence**
  (Atlas trust score trend + SBOM download links), **Insider Risk**
  (Aegis signal history per PR), **Scan health** (per-capability
  `ScanRun` history/freshness/failure rate).
- A finding detail panel: full `raw_finding_json`, first/last seen,
  status, and a "mark as false positive" / "accept risk" action that
  writes back to `Finding.status` (spec 05 §3) **and** logs a retro signal
  (spec 11 §4).

### 2.3 Maturity / trend view
- Per-repo and portfolio-wide trend lines over time: finding count by
  severity, `overall_risk_score`, SSCS trust score, mean time-to-fix.
- An illustrative maturity roadmap (baseline → target posture) per repo,
  in the spirit of a BSIMM/OWASP SAMM-style view — qualitative maturity
  stage inferred from quantitative signals (e.g., "all 6 core scanners
  enabled + Oracle blocking + <5 open criticals older than 30 days" maps to
  a defined maturity tier; tiers and thresholds are configurable).

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
- Heavy aggregate queries (portfolio summary cards, trend lines) are
  pre-computed on a schedule (e.g., every 15 minutes) into small
  materialized DuckDB views/tables to keep dashboard load times fast
  regardless of data lake size.

## 4. API endpoints (backend, dashboard-facing)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/dashboard/portfolio` | Portfolio view data (§2.1) |
| `GET` | `/api/dashboard/repos/{id}/findings` | Filterable finding list for one repo |
| `GET` | `/api/dashboard/repos/{id}/decisions` | Oracle decision history for one repo |
| `GET` | `/api/dashboard/repos/{id}/remediation` | Patchwork event history for one repo |
| `GET` | `/api/dashboard/repos/{id}/sscs` | Atlas evidence/trust-score history |
| `GET` | `/api/dashboard/repos/{id}/insider-risk` | Aegis signal history |
| `GET` | `/api/dashboard/repos/{id}/scan-health` | ScanRun history/freshness |
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
  repos, using pre-aggregated materialized views (§3).
- Every number shown in the UI is traceable to its underlying data lake
  rows (no dashboard-only derived numbers that can't be reproduced by a
  direct data lake query — required for audit trust).
- Marking a finding as a false positive updates its status immediately in
  the UI and is reflected in Oracle's next evaluation (via the false-positive
  dampening input, spec 09 §4) within one scheduled decision cycle.

## 7. Edge cases

- Repo has capabilities enabled but zero scans have completed yet
  (freshly onboarded) — dashboard shows an explicit "awaiting first scan"
  state per capability, not a blank/misleading "0 findings."
- A repo is `removed` (offboarded) — excluded from the live portfolio view
  by default, but remains queryable via an "include removed repos"
  toggle for audit purposes (historical data is retained per spec 02 §6).

## 8. Dependencies

- Spec 05 for all underlying data.
- Spec 09 for decision data and explainability fields.
- Spec 11 for retro/trend report content.
- Spec 12 for human-user authentication and RBAC.
