# Spec 01 — Architecture

**Status:** Approved for build
**Depends on:** [00 — Overview & Glossary](00-overview-and-glossary.md)

---

## 1. High-level component diagram

```
                                   ┌────────────────────────┐
                                   │   Security Admin UI     │
                                   │  (Next.js frontend)      │
                                   └───────────┬──────────────┘
                                               │ REST/JSON (HTTPS)
                                   ┌───────────▼──────────────┐
                                   │   Mykronos Backend API    │
                                   │      (FastAPI)             │
                                   │  ┌──────────────────────┐ │
                                   │  │ Repo Onboarding       │ │
                                   │  │ GitHub App Service    │ │
                                   │  │ Workflow Installer    │ │
                                   │  │ Ingestion API         │ │
                                   │  │ Oracle (decision svc) │ │
                                   │  │ Knowledge/RAG service │ │
                                   │  │ Dashboard/query API   │ │
                                   │  └──────────────────────┘ │
                                   └───────┬───────────┬────────┘
                                           │           │
                       ┌───────────────────┘           └───────────────────┐
                       │                                                   │
             ┌─────────▼─────────┐                                ┌────────▼────────┐
             │   Data Lake         │                                │ Knowledge Store   │
             │ (local DuckDB +     │◄───────────────────────────────┤ (JSONL + vector   │
             │  Parquet files)     │      retro/learning writes      │  index, local)    │
             └─────────▲─────────┘                                └──────────────────┘
                       │ normalized upload (HTTPS, internal network only)
     ┌─────────────────┼──────────────────────────────────────────────────────────┐
     │                 │                                                          │
┌────┴─────┐   ┌────────┴───────┐   ┌────────────┐   ┌────────────┐   ┌────────────────┐
│  SAST     │   │  DAST           │   │ Secrets     │   │ Containers  │   │ IaC / Cloud     │
│ workflow  │   │  workflow       │   │ workflow    │   │ workflow    │   │ workflows       │
└──────────┘   └────────────────┘   └────────────┘   └────────────┘   └────────────────┘
┌──────────┐   ┌────────────────┐   ┌───────────────────┐
│  Aegis    │   │  Atlas          │   │  Patchwork          │
│ (insider  │   │  (SSCS/SCA)     │   │  (auto-remediation) │
│  risk)    │   │                 │   │                     │
└──────────┘   └────────────────┘   └───────────────────┘

   ── all of the above run as GitHub Actions inside each ONBOARDED REPO ──
```

## 2. Components

| Component | Responsibility | Spec |
|---|---|---|
| **Frontend** | Admin UI for onboarding repos, toggling capabilities, viewing dashboards | 10 |
| **Backend API** | Single FastAPI service exposing all REST endpoints; hosts business logic for onboarding, workflow install, ingestion, Oracle, knowledge/RAG, and dashboard queries | 02, 03, 05, 09, 10, 11 |
| **GitHub App Service** | Authenticates as the Mykronos GitHub App; mints short-lived installation tokens; calls GitHub REST/GraphQL APIs on behalf of onboarded repos | 02 |
| **Workflow Installer** | Renders capability-specific GitHub Actions YAML from templates and opens a PR into the target repo | 03 |
| **Scanner workflows** | GitHub Actions running inside each onboarded repo: SAST, DAST, Secrets, Containers, IaC, Cloud | 04 |
| **Aegis** | GitHub Action: insider-risk + AI-authorship PR gate | 06 |
| **Atlas** | GitHub Action(s) + optional long-running service: SSCS/SCA evidence collection | 07 |
| **Patchwork** | GitHub Action + backend agent pipeline: auto-remediation draft PRs | 08 |
| **Oracle** | Backend service: consumes data lake, produces explainable risk decisions | 09 |
| **Data Lake** | Local storage (DuckDB + Parquet) holding every raw + normalized signal | 05 |
| **Knowledge Store / RAG** | Local JSONL + vector index storing retro learnings, feeding LLM-assisted triage/retros | 11 |
| **Dashboard** | Portfolio and per-repo views over the data lake | 10 |

## 3. Tech stack

| Layer | Choice | Rationale |
|---|---|---|
| Frontend | Next.js (React, TypeScript) | Matches existing internal platform conventions; SSR for dashboard pages |
| Backend | FastAPI (Python 3.11+) | Matches existing internal platform conventions; async I/O for GitHub API calls |
| Data lake | DuckDB (embedded OLAP engine) over Parquet files on local disk | Zero-infrastructure, local-first (no cloud egress requirement), excellent for portfolio-wide analytical queries (aggregation, trend lines), can be upgraded to a networked Postgres later without changing the ingestion contract |
| Knowledge store | JSON Lines file + local vector index (e.g., FAISS) | Simple, auditable, portable; matches proven internal pattern |
| Auth to GitHub | GitHub App (JWT → installation access tokens) | Least-privilege, short-lived tokens, no long-lived PAT storage (see spec 12) |
| Secrets at rest | OS keychain / cloud KMS-backed secret manager (deployment-specific) for the GitHub App private key | Only long-lived secret in the system |
| Workflow config format | YAML (GitHub Actions native) | Required by GitHub Actions |
| Finding interchange format | SARIF where the source tool supports it; a normalized internal JSON `Finding` schema everywhere else | SARIF is the industry standard; internal schema unifies everything for the data lake regardless of source |

## 4. Deployment topology (reference)

Mykronos backend + data lake + knowledge store run as one deployable unit
("the platform"), reachable only from:
1. GitHub Actions running in onboarded repos (outbound HTTPS calls to the
   ingestion API, authenticated with a per-repo/per-installation short-lived
   token — see spec 05 §4).
2. The security admin's browser (frontend + backend API).

No component in this architecture requires public internet-facing storage of
findings data; "local" data lake means it lives inside the org's own network
boundary, not a third-party SaaS.

## 5. End-to-end data flow (narrative)

1. Admin registers a repo in the frontend → backend calls GitHub App install
   flow (spec 02).
2. Admin selects capabilities to enable for that repo (checkbox grid).
3. Workflow Installer renders the relevant workflow YAML files from
   `workflow-templates/` (spec 03) and opens a PR titled
   `Mykronos: enable <capabilities>` on the target repo. A human approves
   and merges it (or the admin can pre-authorize auto-merge for this PR
   specifically — configurable, off by default).
4. On every subsequent push/PR/schedule trigger, the installed workflows run
   the actual scanners (spec 04) and Aegis/Atlas/Patchwork (specs 06–08).
5. Each workflow's final step calls the **Ingestion API** (spec 05) with its
   results, authenticated via a scoped token minted for that specific
   workflow run.
6. The Data Lake stores the raw payload (as submitted) and a normalized
   `Finding`/`Signal` record.
7. Oracle (spec 09) runs on a schedule and/or is invoked synchronously by a
   PR-gate workflow step; it reads relevant data lake rows and writes a
   `RiskDecision` record back to the data lake, and optionally posts a PR
   check/comment.
8. The Dashboard (spec 10) queries the data lake directly (read-only) to
   render portfolio and per-repo views.
9. When a human takes an action on a finding (dismiss, mark false positive,
   override an Oracle decision, approve/reject a Patchwork PR), that action
   is captured as a retro signal and written to the Knowledge Store
   (spec 11), which periodically synthesizes retro reports and feeds
   relevant prior learnings back into Oracle's and Patchwork's prompts.

## 6. Cross-cutting constraints

- **No component silently drops data.** If ingestion fails, the calling
  workflow must fail loudly (non-zero exit) so the CI run is visibly red.
- **All timestamps UTC**, ISO-8601.
- **Every data lake row is attributable**: repo, capability, workflow run id,
  commit SHA, and ingestion timestamp are mandatory on every record (spec 05).
- **No capability auto-merges or auto-applies a change to a customer repo**
  without explicit human approval, except where a spec explicitly says
  otherwise (Patchwork opens draft PRs only — never merges; see spec 08 §6).
- **Every Oracle decision must be explainable** — store the inputs and
  reasoning alongside the decision, not just a pass/fail (spec 09 §5).
