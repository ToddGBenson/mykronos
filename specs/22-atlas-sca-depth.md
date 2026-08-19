# Spec 22 — Atlas (SCA) Depth: License Compliance, Freshness, Denylists, and a Missing Combination Rule

**Status:** Draft for review
**Depends on:** [07 — Atlas Integration](07-atlas-integration.md), [08 — Patchwork Integration](08-patchwork-integration.md),
[09 — Oracle](09-oracle-risk-decision-engine.md)

---

## 0. What this spec is against

Atlas's trust score is the most rigorously hardened number in this platform — reproducible, curved,
with a real null state proven out by two production incidents. What a full read turned up is not a
weak scoring model but four real absences: license data that Syft already captures and nothing reads,
a freshness penalty term that has existed in the formula since spec 07 shipped and has been
permanently zero because nothing populates it, no way to ban a specific package or license, and a
toxic-combination rule that considers a vulnerable container layer but not a vulnerable dependency —
despite both being CVE-bearing findings this platform already treats identically everywhere else.

Two things this spec deliberately does not attempt: re-enabling transitive dependency resolution
(blocked on a live upstream deps.dev bug, not this codebase) and continuous supplier scorecards,
compliance reporting, or alert routing (spec 07 §2's own stated v1 exclusions, still out of scope).

## 0a. Implementation status

| Item | Status |
|---|---|
| License data: captured, scored, surfaced | Built |
| Freshness penalty: a real data source | Built (opt-in) |
| Package/license denylist | Built |
| Combination rule: vulnerable dependency + reachable service | Built |

## 1. License compliance

### 1.1 Current state

Zero code, zero schema field, anywhere in this platform. Syft (already run for every SBOM) captures
license metadata in the CycloneDX/SPDX output it produces; nothing reads it.

### 1.2 What ships

- `atlas_counts.py` (runner-side, per spec 07's counts-on-the-runner/scoring-on-the-platform split)
  gains a license pass over the same Syft SBOM already generated: for each resolved component, extract
  its declared license(s) from the CycloneDX/SPDX `licenses` field. Emits a per-ecosystem
  `licenses_seen: dict[str, int]` (license identifier → component count) alongside the existing
  vulnerability counts — no new scan, no new tool, a second read of output already produced.
- `EcosystemEvidence` (`schemas.py`) gains `licenses_seen: dict[str, int]`, following the existing
  field's optionality conventions — absent/empty is "not computed for this ecosystem," not "no
  licenses found."
- `sscs_evidence` (lake table) gains `licenses_json`, mirroring how `ecosystems_json` already carries
  a structured blob the platform doesn't need a dedicated column per field for.

### 1.3 Scoring

A new, small, policy-configured penalty — copyleft and unknown licenses are the two categories that
actually create obligations, not "any license we haven't seen before":

```yaml
  # New block in oracle-policy-v1.yaml's spirit, but owned by Atlas's own
  # (smaller, per-capability) scoring surface, matching how the trust-score
  # formula already lives in atlas.py rather than in the global Oracle
  # policy — license risk is a fact about the dependency tree, the same
  # category vulnerability/staleness/floating-version penalties already are.
  license_penalty_per_flagged_component: 2   # capped, same curve discipline as everything else
  flagged_licenses: [gpl-3.0, agpl-3.0, sspl-1.0]   # copyleft/restrictive, admin-editable
  unknown_license_penalty_per_component: 0.5        # smaller — "we don't know" is a lesser risk
                                                     # than "we know it's restrictive"
```

Surfaced in `sscs.tsx`'s existing term-breakdown table (`score_terms`), not a new UI section — license
penalty is a trust-score term exactly like the vulnerability/floating-version/staleness terms already
there.

## 2. Freshness — a real data source

### 2.1 Current state

`stale_dependencies` and `maintenance_data_available_for` exist in the schema, the trust formula has a
live penalty term for them, the frontend labels it "Unmaintained packages" — and `atlas_counts.py`
initializes `stale_dependencies: 0` and never increments it. osv-scanner has no last-release-date
signal. The term has contributed exactly zero to every trust score ever computed.

### 2.2 What ships

A second, narrow, opt-in lookup — not a replacement for osv-scanner, an addition alongside it,
following the same "explicit opt-in, no default-on external call" rule spec 07 §7 already holds Atlas
to (mirroring Aegis's `ai_classifier_url` pattern):

- For ecosystems with a package-registry API that returns last-publish date cheaply (npm registry,
  PyPI's JSON API — both unauthenticated, both already rate-limit-friendly for the volumes involved),
  a runner-side step queries each resolved package's most recent release date and flags a dependency
  `stale` if nothing has shipped in `staleness_threshold_days` (policy-configurable, default 730 — two
  years, long enough that an actively-abandoned package is what triggers it, not a merely-mature one).
- `maintenance_data_available_for` finally gets populated — the ecosystems the lookup ran for, exactly
  as the schema field's existing (currently always-empty) intent describes.
- Ecosystems with no cheap registry API (or where the lookup is not configured) stay honestly absent
  from `maintenance_data_available_for` — the staleness term contributes zero for those, distinctly
  from "checked, found nothing stale."

### 2.3 What does not ship

A generic "package health" service integration, deprecation-flag scraping, or maintainer-activity
scoring beyond last-publish-date. The cheapest signal that makes the existing term real, nothing more.

## 3. Package and license denylist

### 3.1 Current state

`AtlasConfig` has three fields: `ecosystems`, `sbom_format`, `min_trust_score`. No way to say "this
package is banned here" or "this license is never acceptable, regardless of the point penalty above."

### 3.2 What ships

`AtlasConfig` gains `banned_packages: list[str]` and `blocked_licenses: list[str]` — per repo,
following the existing per-repo capability-config pattern (a fleet-wide default is real future work,
noted and not attempted here: the existing config surface has no organization-wide policy concept for
*any* capability, and inventing one for Atlas alone would be a bigger architectural addition than this
gap justifies).

- A dependency matching `banned_packages` (exact name match, per ecosystem) or a component whose
  license is in `blocked_licenses` produces a `Finding` — capability `atlas`, severity `high` by
  default, rule_id `atlas-banned-package`/`atlas-blocked-license` — not just a score penalty. A banned
  package is a policy violation a person needs to act on, the same standard every other `Finding`
  already sets; a silent score deduction would bury it in a single number nobody reads term-by-term.
- This is additive to the existing per-vulnerability findings from `atlas_osv.py`, produced by a
  second pass over the same SBOM already read for licenses (§1), not a second scan.

## 4. Combination rule: vulnerable dependency, reachable service

### 4.1 Current state

`atlas` is already in `DEFAULT_CORRELATION_CAPABILITIES` (the eligible pool for toxic-combination
detection) — it has been since spec 08 shipped. No rule in `BUILT_IN_RULES` has ever named it. The
closest existing rule, `exploitable-dependency-reachable` ("Exploitable dependency in a running,
reachable service"), pairs a `containers` CVE finding with a `dast` reachability signal — the identical
shape a vulnerable *application* dependency (not just a vulnerable container layer) already has, since
`atlas` findings are already CVE-bearing (confirmed: Oracle's KEV boost already reads CVEs out of them
generically, with no atlas-specific code path).

### 4.2 What ships

Widen the existing rule's first `Requirement` from `capability="containers"` alone to match either
`containers` or `atlas` — one rule covering "a known-exploitable component, wherever it lives, behind
a service that's reachably disclosing itself" rather than two near-duplicate rules that could drift.
`Requirement` already supports this shape (a regex matched against `rule_id`/`title`, capability as a
separate field) — this is a data change to one rule, not new matching logic:

```python
CombinationRule(
    rule_id="exploitable-dependency-reachable",
    name="Exploitable dependency in a running, reachable service",
    requires=(
        Requirement(r"CVE-", capability="containers", min_severity="high"),
        Requirement(r"CVE-", capability="atlas", min_severity="high"),  # new: either may satisfy
        Requirement(r"auth|exposed|version|banner|outdated|fingerprint", capability="dast"),
    ),
    ...
)
```

(`Requirement` matching today is "any requirement of this shape satisfied by at least one finding";
the exact mechanism for "either containers or atlas satisfies the first slot" — an explicit OR inside
one requirement vs. two alternative requirements sharing a satisfied-by-either flag — is an
implementation-time decision `correlate.detect()`'s matching loop should make explicit, not left
ambiguous by this spec.)

## 5. Acceptance criteria

- A repo whose SBOM includes a GPL-3.0-licensed component shows a `license_penalty` term in its trust
  score breakdown, distinct from the vulnerability-count terms.
- A repo with `blocked_licenses: [gpl-3.0]` configured produces an actual `Finding` (not just a score
  deduction) for any GPL-3.0 component.
- An npm/PyPI dependency with no release in over two years (default threshold) contributes a nonzero
  `stale_dependencies` term; `maintenance_data_available_for` names `npm`/`pip` when the lookup ran for
  them.
- A repo with `banned_packages: ["left-pad"]` configured and `left-pad` present in its dependency tree
  produces a `Finding`, independent of whether `left-pad` has any known vulnerability.
- A high-severity CVE in an `atlas` finding, paired with a `dast` finding showing the service reachable
  and disclosing its version, is detected as the same combination a `containers` CVE in that position
  already triggers.

## 6. Edge cases

- A component with multiple licenses (a real, common SBOM shape) is flagged if *any* of its declared
  licenses is in `flagged_licenses`/`blocked_licenses` — the restrictive one governs, not the most
  permissive one present.
- The staleness lookup (§2) failing for one package (registry timeout, package delisted) does not fail
  the whole scan — that package's staleness stays unknown, every other package's lookup still counts.
- A package appearing in both `banned_packages` and already carrying a vulnerability finding produces
  two distinct `Finding` rows, not one conflated one — "banned" and "vulnerable" are different facts
  about the same package and a person disposing of one should not silently dispose of the other.
- Widening the combination rule (§4) must not double-fire when a repo has *both* a `containers` and an
  `atlas` finding for the same underlying CVE (a common case — the same vulnerable package appears in
  the built image and in the manifest) — `correlate.detect()`'s existing dedup-by-combination-id
  behavior already prevents two separate combination rows for the same finding set; this needs
  confirming against the widened rule specifically, not assumed to carry over.

## 7. Dependencies

Spec 07 (Atlas — trust score formula, SBOM generation, the null-state convention every new term here
follows), spec 08 (Patchwork — `correlate.py`, `DEFAULT_CORRELATION_CAPABILITIES`), spec 09 (Oracle —
KEV/exploitability's existing capability-agnostic CVE extraction, unaffected but relevant context for
why atlas findings already participate in that one cross-cutting mechanism and not yet in this one).
