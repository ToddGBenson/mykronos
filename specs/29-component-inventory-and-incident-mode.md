# Spec 29 — Component Inventory, Incident Mode, and Provenance

**Status:** Draft for review
**Depends on:** [07 — Atlas Integration](07-atlas-integration.md), [05 — Data Lake](05-datalake.md),
[17 — Harness, Threat Intel, i2i](17-harness-threat-intel-and-i2i.md),
[19 — Harness, Triage and Remediation Depth](19-harness-triage-and-remediation-depth.md),
[22 — Atlas (SCA) Depth](22-atlas-sca-depth.md)

---

## 0. What this spec is against

Atlas is rigorous: a reproducible trust score with a real null state proven by two production
incidents, SBOM generation and download, license capture and denylists, opt-in freshness. What it
cannot do is answer the question every supply-chain incident opens with.

**The lake holds dependency counts, not dependency names.** D-069 records this precisely: the
per-ecosystem evidence blob contains counts, which is what spec 07 asks the runner to report, *"so the
full resolved dependency set is not in the lake at all"*. Blast radius had to be computed from
findings instead of from the dependency graph, and that workaround is documented rather than fixed.
The consequence is that **"who uses log4j" is unanswerable** without opening each repository's SBOM by
hand — on the day when time matters most.

**There is no incident mode.** A new critical CVE lands at 4pm. The platform holds every input needed
to answer *which of my repositories are affected, how badly, and what do I do about it* in one screen,
and offers no route to it. Nobody browses eight tabs on that day.

**Nothing checks that the artefact you shipped is the one you built.** The trust score grades what you
depend on. It never grades provenance: no signature verification, no attestation, no check that a
published image digest matches the commit that produced it. D-047 established publishing by SHA as a
real control in the pipeline, and it is invisible as a repository-level signal.

## 0a. Implementation status

| Item | Status |
|---|---|
| `sbom_components` — the resolved dependency set, by name (§1) | **Built** — extracted server-side from the archived SBOM, not uploaded; see §1.5 |
| Blast radius computed from the graph rather than proxied (§1.4) | **Built** — both populations, larger wins, source published |
| Incident mode: one question, every repository (§2) | **Built** — the read; batch actions deliberately deferred, see §2.4 |
| Provenance as trust-score terms (§3) | **Built** — as credits, which is the only honest shape; see §3.4 |

## 1. The component inventory

### 1.1 Current state

`atlas_counts.py` reads the Syft SBOM and reports per-ecosystem counts; spec 22 added a second read
of the same SBOM for licenses. `sscs_evidence.ecosystems_json` carries the counts. The SBOM artefact
itself is downloadable per repository (spec 18 §8) and is not queryable across repositories.

### 1.2 What ships

A lake table `sbom_components`, written from the same Syft output already produced — a third read of
a file the runner has already generated, not a new scan:

| Column | Notes |
|---|---|
| `component_id` | primary key; hash of repo, ecosystem, name, version |
| `repo_full_name`, `commit_sha`, `scan_run_id` | provenance of the row itself |
| `ecosystem`, `package_name`, `package_version` | the resolved component |
| `direct` | boolean or null — null where the SBOM does not distinguish |
| `purl` | the package URL where Syft emits one; the join key that survives naming differences |
| `license_ids_json` | already captured by spec 22 §1, stored here rather than only aggregated |
| `observed_at` | partition and ordering source, per `lake/tables.py` conventions |

**Volume is the objection and it is smaller than it looks.** Four repositories with a few thousand
resolved components each, rewritten per scan, is well inside what the compaction model already handles
for findings — and the row is narrow. If a future portfolio makes this expensive, the fix is retaining
only the latest commit per repository, which is what every query below wants anyway.

### 1.3 What does not ship

Transitive resolution beyond what Syft already reports. Spec 22 records that deps.dev transitive
resolution is blocked on a live upstream bug, and that is unchanged here: this table stores what the
SBOM contains, and says so, rather than implying a complete graph.

### 1.4 Blast radius, properly

D-069 chose to count findings because package names were unavailable. With this table the original
intent from spec 19 §2.4 becomes computable: package name → the repositories that depend on it. The
finding-derived measure stays as a fallback for repositories with no SBOM, and the response says which
of the two produced the number — the same treatment `mapping_resolution` gets in spec 28.

**Built, and one detail this section did not settle: the two counts are merged per package, taking
the larger.** A portfolio part-way through adopting Atlas has both kinds of repository in it at once,
and picking a single source outright would either drop the SBOM-less repositories from every count or
throw the graph away because one repository lacks it. Taking the maximum is safe in the one direction
that matters: the finding-derived count only ever *misses* repositories, never invents them, so it can
raise a package's count above the graph's only where the graph itself has a hole.

### 1.5 Corrected while building: nothing is uploaded

§1.2 describes writing the table "from the same Syft output already produced". The implementation goes
one step further and adds no upload at all. The SBOM is already archived through `/api/ingest/raw`,
and its ref already arrives on the Atlas evidence submission — so the components are extracted
**server-side from a file already on disk**.

Three things follow, and the second is why it was worth doing this way:

- No workflow template change for the inventory, so no resync across every onboarded repository.
- A repository whose SBOM was archived last month gets an inventory on its **next report**, rather
  than on its next workflow resync.
- Reading the ref means resolving a caller-supplied path, so it is resolved and then checked to be
  inside the archive directory. A caller who can post evidence must not be able to name
  `../../etc/passwd`, and there is a test that says so.

Extraction failures are swallowed deliberately and logged. The evidence row is what a release gate
reads and is already in the buffer; losing a trust score because an SBOM was truncated in transit
would trade the number that matters for a convenience index.

## 2. Incident mode

### 2.1 What ships

A single view, reachable from the portfolio and from any threat-intel row: **give it a CVE, a package
name, or a purl.** It returns, across every onboarded repository:

- which repositories contain it, at which versions, direct or transitive where known,
- whether a fixed version exists (Atlas already learns this) and what it is,
- each repository's standing Oracle verdict and risk profile, so triage order is obvious,
- whether the CVE is in KEV and its EPSS score (spec 17 §4),
- whether Patchwork has a fixer for that ecosystem — and therefore how much of this is one click.

And two batch actions on the result set: **open a story per affected repository**, or **open the fix
PRs**, both through the existing paths (`triage_story.py`, Patchwork), both still draft-only, both
still requiring the reasons those paths already require.

### 2.2 Why this is one screen and not a report

The operating assumption of the whole view is that it is used under time pressure by somebody who has
just been paged. Everything on it is a fact already in the platform; the only new thing is that they
are on the same page, joined by package name, ordered by exposure. That is the entire feature, and it
is worth more than any individual signal it displays.

### 2.3 What does not ship

No automatic action on a feed. The platform does not open forty pull requests because KEV published
overnight. A person asks the question and a person triggers the batch — the same standard the
"scan now" button and the override button already hold.

### 2.4 Built: the read. The batch actions are deferred, and named.

The view ships: query, affected repositories with versions and as-of dates, open findings and the fix
version beside mere presence, each repository's standing Oracle verdict, KEV and EPSS on a CVE, and
the three-way split below. The batch actions of §2.1 — open a story per affected repository, open the
fix PRs — are **not built**, and are listed here rather than quietly dropped.

The reason is that both existing paths are per-subject: `triage_story.py` grooms *a finding* and
Patchwork fixes *a finding*, while this view's subject is a package across repositories. Fanning one
out to the other is a real piece of work with its own deduplication question (spec 29 §5's "a batch
action over a repository already carrying an open story"), and half-building it would produce exactly
the thing spec 29 §2.3 refuses: a button that opens pull requests nobody quite asked for. The
per-repository links are on every row, and each of them reaches the paths that already work.

**Three states, not two, and this is the whole design of the view.** `affected`, `clear`, and
`not_checked`. A repository with no SBOM cannot be reported as unaffected — converting an absence of
data into a statement of safety is the single worst thing this page could do, and it is what it would
do by default. `not_checked` renders in its own block, in a warning tone, saying in words that it is
not a clean result.

The same rule applies twice more. A CVE with no threat-intelligence record renders as *not checked
against KEV*, never as *not exploited*. And a CVE nothing has ever reported on resolves to no
packages and reports nothing affected — rather than reporting every repository clean of an advisory
the platform simply cannot recognise.

## 3. Provenance

### 3.1 Current state

The trust score's terms are vulnerability counts, floating versions, staleness, and — after spec 22 —
licenses. Every one is a fact about dependencies. Nothing scores the integrity of the repository's own
outputs.

### 3.2 What ships

Three small, capped terms, each reading something the platform can already see or cheaply fetch:

```yaml
provenance:
  signed_commits_ratio_at_1_0: 3     # verified signatures on the default branch, last 90 days
  attestation_present: 3             # a build provenance attestation exists for the latest release
  digest_pinned_deployment: 4        # the deployed image is pinned by digest, not by tag
```

- **Signed commits** come from the GitHub API on the default branch.
- **Attestation** is presence-only in v1: does a provenance attestation exist for the published
  artefact. Verifying its contents is a larger piece of work and presence is the signal that
  distinguishes almost every repository from almost every other one today.
- **Digest pinning** is readable from the deployment manifests the platform already scans for IaC.

Each is `available: False` where it cannot be determined, never zero — a repository whose default
branch the platform cannot read has not failed the check.

### 3.3 Why in the trust score rather than as findings

A missing attestation is not a vulnerability with a location; it is a property of how the repository
builds. The trust score is where properties of a repository's supply-chain hygiene already live, and
spec 22 set the precedent that a *policy violation* (a banned package) becomes a `Finding` while a
*degree of hygiene* becomes a term.

### 3.4 Corrected while building: they are credits, and that is forced

§3.2's YAML reads as though these are penalties like every other term. They cannot be. The trust
score starts at 100, subtracts, and its ceiling means *nothing wrong found* — so a term that deducted
for a missing attestation would change the score of every repository in the estate on the day it
shipped, which §4 explicitly forbids: *"the trust score for a repository with no provenance data is
identical to today's."*

So they add, and they are clamped at the ceiling. A clean repository gains nothing and scores exactly
as before; a repository carrying penalties gets some back for building carefully. That is the only
shape a hygiene bonus can honestly take inside a subtractive score, and it satisfies §4's criterion by
arithmetic rather than by a special case.

**Null is not zero, on every one of the three.** A repository whose default branch the token could not
read has not failed the signing check. Scoring the two the same way turns a permissions problem into a
supply-chain verdict, so each term reports `available: False` with a reason and the tab renders a dash
rather than `−0.0`.

**A signed-commits ratio needs a sample.** Below ten commits the term reports unavailable: one person
signing one merge is a coincidence, not a signing policy, and the sample rides on the term so a reader
can judge a ratio of 1.0 for themselves.

**`attestation_present` is asked only on a release.** A commit with no published artefact has nothing
to attest, and reporting `false` for it would penalise every ordinary push for a build that never
happened.

The observations come from a workflow step of its own with `continue-on-error`, not from `|| true`
inside the evidence step. A blanket `|| true` on a scanner step is how a failed scan comes to look
like a clean one — `test_adapters_phase2` fails the build over exactly that, and caught this. It also
caught a release tag being interpolated into a shell body — the injection Semgrep found in the
composite action at high severity, and which that test was written to keep out. A tag is chosen by
whoever cut the release and `${{ }}` is substituted before bash parses it, so the tag is bound to
`env:` now.

## 4. Acceptance criteria

- After one Atlas scan, `sbom_components` holds one row per resolved component with a `purl` wherever
  Syft emitted one.
- A package-name query returns every repository containing it in under two seconds for the current
  portfolio, and the portfolio-load budget in spec 10 §6 is unaffected.
- Blast radius for a package present in three repositories reports three, from the graph, and states
  that the graph produced it.
- A repository with no SBOM contributes to no graph-derived answer and is listed explicitly as
  "no SBOM" in the incident view, never as "not affected".
- Incident mode's batch action opens one story per affected repository, each carrying that
  repository's own acceptance criteria, and opens no pull request that is not a draft.
- Provenance terms report `available: False` with a reason where the underlying fact could not be
  read, and the trust score for a repository with no provenance data is identical to today's.

## 5. Edge cases

- **The same package at different versions in one repository** — routine in npm. One row per
  (name, version); the incident view groups by name and lists the versions, because "we have three
  copies and one is patched" is the actual state and a single row would hide it.
- **A package renamed upstream.** `purl` is the join key where present; name matching is the fallback
  and the view says which matched.
- **A CVE affecting a package the platform cannot see** — a vendored copy, a system library inside a
  base image. Container findings already cover the second; the first is a stated limitation of SBOM
  scope, said once in the view rather than implied by absence.
- **A repository scanned six months ago.** The inventory is as of its last scan, and every row in
  incident mode carries that date. Stale data presented as current is the failure mode this view
  could most easily have.
- **A batch action over a repository already carrying an open story for that CVE.** Deduplicated — the
  existing story is linked, not a second one opened.
- **An attestation that exists but does not verify.** Out of scope in v1 and stated as such: presence
  is the term, and a repository must not read "attested" when the attestation is invalid. The term is
  named `attestation_present` for exactly that reason.

## 6. Dependencies

Spec 07 (the counts-on-the-runner split this follows, and the trust-score formula §3 extends), spec 05
(lake table conventions), spec 17 §4 (KEV and EPSS in the incident view), spec 19 §2.4 (the blast
radius this finally computes as intended), spec 22 (the SBOM re-read pattern and the
violation-versus-hygiene precedent), spec 08 and `triage_story.py` (the batch actions' existing paths).
