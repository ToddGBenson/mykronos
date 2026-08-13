# Spec 07 — Atlas Integration (SSCS / SCA)

**Status:** Approved for build
**Depends on:** [04 — Scanner Workflows](04-scanner-workflows.md), [05 — Data Lake](05-datalake.md)

---

## 1. Purpose

Add a **Software Supply Chain Security (SSCS)** capability — covering
Software Composition Analysis (SCA/dependency risk) as its core, plus SBOM
generation and basic provenance evidence — modeled on the existing internal
"Project Atlas" pattern, scoped down to what a single onboarded repo needs
(Atlas internally runs 23 specialized agents; Mykronos v1 implements the
subset directly relevant to per-repo trust evidence, described below).

## 2. Scope (v1)

| Function | Description |
|---|---|
| **SCA / dependency scan** | Identify direct + transitive dependencies and known vulnerabilities in them (e.g., via `osv-scanner`, `pip-audit`, `npm audit`, or an equivalent tool per ecosystem) |
| **SBOM generation** | Produce a CycloneDX or SPDX Software Bill of Materials for the repo on every release/tag |
| **Provenance evidence** | Record build provenance metadata: what workflow run produced a given artifact, from what commit, using what runner — a minimal SLSA-style provenance statement |
| **Supplier/dependency trust scoring** | A simple per-dependency trust score based on: known-vulnerability count/severity, maintenance recency (last release date), and whether the package is pinned to an exact version (vs. a floating range) |

Explicitly **out of scope for v1** (may be added later, mirroring Atlas's
fuller 23-agent model): continuous supplier scorecards across an entire
vendor ecosystem, policy engine, compliance reporting, alert routing. v1 is
scoped to "what evidence exists for this repo's dependencies and releases,"
not a standalone governance platform.

## 3. Data model — `SscsEvidence` (data lake table)

| Field | Type | Notes |
|---|---|---|
| `evidence_id` | string | PK. **Derived, not random**: SHA-256 over `repo_full_name` + `commit_sha`. §7 requires exactly one row per tagged release and §8 one per commit, which a random UUID cannot deliver — a re-run would append a second row and both acceptance criteria would quietly stop holding. Same reasoning as `finding_id` (spec 05 §5) |
| `repo_full_name` | string | |
| `commit_sha` | string | |
| `tag_or_release` | string, nullable | populated on release-triggered runs |
| `sbom_ref` | string, nullable | path to the generated SBOM file in raw output storage (spec 05 §7) |
| `dependency_count` | int | |
| `vulnerable_dependency_count` | int | count with ≥1 known CVE at/above the configured severity threshold |
| `trust_score` | int (0–100), **nullable** | aggregate, higher = more trustworthy. **Null when the scan resolved no dependencies** — see §5a. Deliberately not 0 and deliberately not 100: neither is true of a repository nobody managed to inspect |
| `raw_trust_score` | float | Pre-clamp value. Ranking has to survive the floor: without it every repo past 0 ties and sorting by supply-chain trust silently stops working. Same rule as Oracle's `raw_score` (spec 09 §5) |
| `provenance_json` | JSON | minimal SLSA-style statement: builder id, source repo/commit, build workflow run id, timestamp |
| `evaluated_at` | datetime | |

Individual vulnerable-dependency findings are **also** written as regular
`Finding` rows (spec 05 §3) with `capability = "atlas"`, so they show up in
the same portfolio-wide finding views as SAST/DAST/etc. `SscsEvidence` is
the aggregate/summary record; `Finding` rows are the detail records.

## 4. Workflow behavior

- Template: `workflow-templates/atlas.yml.j2`.
- Triggers: `pull_request` (dependency manifest changes only, e.g.
  `package.json`, `requirements.txt`, `go.mod`), `push` to default branch,
  and on `release`/tag creation (for SBOM + provenance).
- Steps: resolve dependency tree → run SCA tool per detected ecosystem(s) →
  generate SBOM (on release triggers) → compute provenance statement (build
  metadata already available from `GITHUB_*` env vars in the Actions
  runner) → compute `trust_score` → call the shared upload step (spec 04
  §2) to submit both the `SscsEvidence` summary and per-vulnerability
  `Finding` rows.

## 5. Trust score calculation (v1, deterministic — no ML)

```
trust_score = 100
            - 20 * log2(1 + critical_vuln_count)
            - 10 * log2(1 + high_vuln_count)
            -  3 * log2(1 + medium_vuln_count)
            - (floating_version_ratio * 10)   # % of deps not pinned exactly
            - (stale_dependency_ratio * 10)   # % with no release in 2+ years
clamped to [0, 100]; the unclamped value is kept as raw_trust_score
```

This formula is intentionally simple and documented so it is fully
explainable (architecture constraint, spec 01 §6) — a future iteration may
replace it with a more nuanced model, but v1 favors transparency over
sophistication.

**Why the vulnerability terms are curved.** An earlier draft of this spec
subtracted linearly: 20 points per critical. Five critical CVEs in the
dependency tree therefore floored the score at 0 — and so did five hundred.
That is not a hypothetical for dependency scanning specifically: `npm audit`
on an unmaintained project routinely reports dozens of criticals in
transitive packages nobody chose directly, and the deliberately vulnerable
demo applications floor on their first scan. Every such repo would report
`trust_score: 0`, the trend line in spec 10 would be flat by construction,
and Oracle's `sscs_trust` penalty would saturate at its cap for all of them
equally.

Curving keeps the score strictly decreasing — more vulnerable dependencies
always score worse — while preserving the ordering that matters: the
difference between two criticals and ten is more informative than the
difference between two hundred and three hundred. This is the same correction
made to Oracle's finding weights (docs/DECISIONS.md D-018), for the same
reason, and the ratio terms are left linear because a ratio is already bounded
at 1 and cannot saturate.

## 5a. A scan that resolved nothing is not a clean scan

`score([])` and `score([eco(dependency_count=0)])` both returned 100 — the
same answer given to a repository with four hundred dependencies and no known
vulnerability in any of them. That is wrong in the direction that matters.

It is not hypothetical. `ToddGBenson/TheHub` declares its Python dependencies
as ranges (`fastapi>=0.120.0`) rather than pins. With transitive resolution
disabled — itself a workaround, because deps.dev returns an internal error for
any `requirements.txt` containing sqlalchemy — osv-scanner has no concrete
versions to check advisories against. It reports nothing, the scan is recorded
as a success, and the repository shows a supply-chain trust it never earned.

**A resolved dependency count of zero produces `trust_score = null`.** The
platform already has this distinction and applies it elsewhere: Oracle's
`risk_score` is null rather than 0 for a repo it has not judged (spec 10
§2.1), and Aegis records `ai_authorship_flag = null` rather than false when no
classifier ran (§7 here). "We did not look" is a third state, and collapsing
it into either of the other two is a claim the data does not support.

Consequences, all of them required:

- **Oracle must not credit it.** A null trust score contributes no term to the
  risk decision, and the decision's reasoning says supply chain was not
  assessed — the same treatment it already gives an unconsulted capability.
- **The maturity model must not count it as evidence.** Supply-chain evidence
  means a scan that resolved something.
- **The dashboard shows "not assessed", not a number.** A repository whose
  dependencies could not be resolved needs to look different from a clean one,
  because the remedy is different: pin the dependencies.
- **The finding rows are unaffected.** A scan that resolved nothing produces
  no vulnerability findings either, which is already the correct answer.

## 6. Configuration (`CapabilityConfig` for `atlas`)

| Field | Type | Default | Notes |
|---|---|---|---|
| `ecosystems` | list | auto-detected | override to force/limit which package ecosystems are scanned |
| `severity_threshold` | enum | `medium` | shared pattern with spec 04 §5 |
| `sbom_format` | enum (`cyclonedx`, `spdx`) | `cyclonedx` | |
| `min_trust_score` | int | `50` | if `blocking=true`, releases with a trust score below this fail the release workflow |
| `blocking` | bool | `false` | |

## 7. Acceptance criteria

- Every dependency-manifest-touching PR produces `Finding` rows for any new
  vulnerable dependency introduced.
- Every tagged release produces exactly one `SscsEvidence` row with a
  non-null `sbom_ref` and `provenance_json`.
- `trust_score` is reproducible: re-running the same commit's scan yields
  the same score (deterministic formula, §5) **and upserts the same row**
  rather than producing a second one (§3).

## 8. Edge cases

- Monorepo with multiple ecosystems (e.g., a Python backend + JS frontend
  in one repo) — scan each detected ecosystem independently and combine
  into one `SscsEvidence` row per commit, with `dependency_count` and
  `vulnerable_dependency_count` summed across ecosystems, but keep
  per-ecosystem detail in `provenance_json`/raw output for drill-down.
- Dependency with no publicly available maintenance-recency data (private
  registry package) — exclude it from the `stale_dependency_ratio`
  denominator rather than penalizing or crashing.

## 9. Dependencies

- Spec 05 for ingestion contract and shared `Finding` schema.
- Spec 09 (Oracle) consumes `trust_score` and `vulnerable_dependency_count`
  as inputs to its release-gating decisions.
- Spec 10 (Dashboard) surfaces SBOM download links and trust-score trend
  per repo.
