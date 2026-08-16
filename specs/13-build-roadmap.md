# Spec 13 — Build Roadmap

**Status:** Approved for build
**Depends on:** all preceding specs (00–12)

---

## 1. Purpose

Give a developer building this from scratch a concrete, incremental
delivery order — each phase produces something independently testable and
demoable, rather than requiring the whole system to be built before
anything works end to end.

## 2. Guiding principle

Build a **thin vertical slice first** (one repo, one capability, data lake,
minimal dashboard), then broaden. Do not build all ten capabilities before
anything can be seen end to end.

## 3. Phases

### Phase 0 — Foundations
- Stand up the backend (FastAPI) and frontend (Next.js) skeletons.
- Stand up the Data Lake (spec 05): DuckDB + Parquet layout, write-ahead
  buffer, compaction job, and the `ScanRun`/`Finding` schemas.
- Implement the Ingestion API (spec 05 §4) with a hardcoded/test token
  (before GitHub App auth exists) so ingestion can be tested in isolation.
- **Demo:** `curl` a fake finding into the Ingestion API, query it back out
  via DuckDB SQL.

### Phase 1 — Onboarding & one real capability (SAST)
- Register the GitHub App (spec 02 §4) against a single test repo.
- Build the onboarding flow (spec 02 §5) and Workflow Installer (spec 03)
  for exactly one capability: SAST (CodeQL).
- Wire the SAST workflow template's upload step to the real Ingestion API
  with a real per-repo scoped token.
- **Demo:** onboard a real test repo, merge the install PR, open a PR with
  a known vulnerability, see the finding land in the data lake.

### Phase 2 — Remaining core scanners
- Add DAST, Secrets, Containers, IaC, Cloud (spec 04) following the same
  template pattern established in Phase 1.
- Build the basic dashboard portfolio + per-repo findings view (spec 10
  §2.1, §2.2, minus trend/maturity views) reading directly from the data
  lake.
- **Demo:** a repo with all six scanners enabled, findings from each
  visible in one dashboard view.

### Phase 3 — Oracle (v1, deterministic policy only)
- Implement the `RiskDecision` schema and deterministic scoring policy
  (spec 09 §3–§5) using only the six core scanners' findings as input
  (Aegis/Atlas/Patchwork inputs come later, treated as "not available yet"
  in `inputs_snapshot` until Phase 4/5).
- Implement the `oracle-gate.yml` workflow template and PR gate behavior
  (spec 09 §8, advisory-only/non-blocking by default).
- **Demo:** a PR gets a Check Run showing Oracle's recommendation with a
  full, human-readable reasoning breakdown.

### Phase 4 — Aegis & Atlas integrations
- Implement Aegis (spec 06): insider-risk signals, PR Check Run.
- Implement Atlas (spec 07): SCA/dependency scan, SBOM, provenance, trust
  score.
- Extend Oracle's `inputs_snapshot` to include these two new input
  categories (spec 09 §4).
- Extend the dashboard with the Insider Risk and SSCS Evidence tabs
  (spec 10 §2.2).
- **Demo:** Oracle's decision now visibly incorporates insider-risk and
  dependency-trust signals, not just static-analysis findings.

### Phase 5 — Knowledge Store & RAG
- Implement `KnowledgeStore` (spec 11 §9) and the dashboard's "mark false
  positive" / override capture flow (spec 10 §2.2, spec 11 §4).
- Wire Oracle's false-positive dampening input (spec 09 §4, §5) to real
  Knowledge Store data.
- Implement confidence decay and tier-promotion proposal jobs (spec 11 §5,
  §7) — even if retro/trend reports are still basic at this stage.
- **Demo:** dismiss a finding as a false positive twice across two
  different PRs on the same repo; show Oracle's next decision reflects a
  dampened weight for that rule_id.

### Phase 6 — Patchwork (auto-remediation)
- Implement the Patchwork pipeline (spec 08 §2) and `RemediationEvent`
  schema, starting with triage + toxic-combination detection before fix
  generation (fix generation is the highest-risk, most complex stage —
  build and test triage/correlation thoroughly first).
- Implement draft-PR generation for at least one well-understood fix
  pattern (e.g., pinning a vulnerable dependency version) before
  attempting more complex code-transform fixes.
- Wire remediation outcomes into the Knowledge Store (spec 11 §4).
- **Demo:** a known-vulnerable dependency PR triggers an automatic draft PR
  pinning the safe version, with the human merging it manually.

### Phase 7 — Trend/retro reporting, maturity view, polish
- Implement the trend report and retro report jobs (spec 11 §7) and the
  dashboard's Retro/Trend/Maturity views (spec 10 §2.3, §2.4).
- Implement bulk workflow template resync (spec 03 §6) for maintaining
  many onboarded repos over time.
- Harden rate limiting, backpressure, and reconciliation jobs across all
  specs (spec 05 §6, §10; spec 03 §8).
- Full security review against spec 12's acceptance criteria before any
  production rollout.

## 4. What NOT to build first

- Do not attempt Oracle's release-gate decision type (spec 09 §2) before
  the PR-gate type is solid — release gating depends on the same
  machinery plus SSCS evidence (Phase 4), so sequence accordingly.
- Do not build Patchwork's fix-generation stage before triage/correlation
  are reliable — a wrong auto-generated fix is worse than no fix; get
  human trust in the triage step first (Phase 6 ordering above is
  deliberate).
- Do not attempt cross-org (`org` tier) knowledge promotion automation
  before `personal`/`team` tiers have real data to learn from — there's
  nothing to promote yet in early phases.

## 5. Definition of done (overall v1)

The v1 build is complete when:
- All capabilities in the standard set (fifteen as of 2026-08-15: the
  original ten plus Unit, QA, Functional, AI and Network) can be enabled
  per-repo through the dashboard — one click per capability — and produce
  data lake records within one run of whichever CI scans the repo.
- The dashboard shows a live portfolio view across at least 3 real
  onboarded repos with real (not seeded/synthetic) findings.
- Oracle produces explainable PR-gate decisions incorporating findings,
  insider-risk, and SSCS trust score.
- At least one full retro cycle (dismiss → dampen → visible in Oracle's
  next decision) has been demonstrated.
- Spec 12's security acceptance criteria all pass.
