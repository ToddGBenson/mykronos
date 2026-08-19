# Spec 19 — Test Harness Depth, Triage Automation, Remediation Growth, and Auto-Routing

**Status:** Draft for review
**Depends on:** [08 — Patchwork Integration](08-patchwork-integration.md), [09 — Oracle](09-oracle-risk-decision-engine.md),
[11 — Knowledge Store & RAG](11-knowledge-rag-learning.md), [17 — Harness, Threat Intel, i2i](17-harness-threat-intel-and-i2i.md),
[18 — Repo Page Rework, Threat Model, Remediation](18-repo-page-rework-threat-model-and-remediation.md)

---

## 0. What this spec is against

Specs 17 and 18 built the Harness tab, the triage vocabulary (`classify()`, toxic combinations,
KEV/EPSS), on-demand Patchwork remediation, and i2i grooming (finding → dev-ready issue). All four
shipped thin on purpose — each one real and working, none of them as deep as the subject deserves, and
none of them connected to the others by anything but a person's own judgment about which button to
click. This spec is the depth pass: no new tabs, no new pages, four existing systems made to do more
of what they already do, plus the one connective piece that was never built — a policy deciding, for
every open finding, which of those systems should act on it without somebody deciding by hand.

It is deliberately narrower than "make everything possible." Reachability's real form (a call-graph
engine) stays out of scope here too — what's in scope is a *cheap, honest* first cut that turns
`unavailable` into a real signal for a bounded class of findings, not the full engine spec 17 §5.3
correctly declined to build.

## 0a. Implementation status

| Item | Status |
|---|---|
| Test Harness: pass-rate trend | Done |
| Test Harness: real failure text (`scan_runs.detail`) | Done |
| Test Harness: flaky-test flagging | Done |
| Triage: reachability, cheap first cut (import-reachable) | Planned |
| Triage: combination-rule discovery (candidate surfacing) | Planned |
| Triage: cross-repo dampening approve/reject UI | Planned |
| Triage: blast-radius signal | Planned |
| Remediation: new deterministic fixers | Planned |
| Remediation: auto-preview on ingestion (`fixable` badge) | Planned |
| Remediation: toxic-combination partial fixes | Planned |
| Remediation: cross-repo batch digest | Planned |
| Auto-routing: fixable → PR, not-fixable → story | Planned |
| Auto-routing: `auto_fix_min_severity` config knob | Planned |

## 1. Test Harness depth

### 1.1 Pass-rate trend

`ScanHealthBoxes` shows the current rate only. Add a sparkline per test lane, same idiom
`sscs.tsx`'s trust-score-over-time chart already uses — reusing the component rather than building a
second charting primitive. Backed by `maturity.trend_series()` (already computes a point-in-time
series for a repo+capability; `unit`/`functional`/`qa` are not special-cased there, so this is a
frontend wiring change, not a new backend query) — `GET /api/dashboard/trends?repo_id=&capability=unit`
already answers this shape.

### 1.2 Real failure text

Today: the JUnit adapter (`adapters/tests_junit.py`) computes a real message —
`"3 of 10 test(s) failed (2 failure(s), 1 error(s))."` — and it never reaches the backend.
`scan_runs` has no free-text field; the message dies after `_write_step_summary` writes it to the
CI run's own log. `scan_status` alone survives to Mykronos.

**Fix:** add `scan_runs.detail: VARCHAR`, nullable, no default — passes the schema-drift guard
(`test_schema_upgrade.py`, D-052) without a `GRANDFATHERED` entry, since a nullable column with no
default needs neither. `ScanRunSubmission` (`schemas.py`) gains an optional `detail: str | None`
field, capped at a short length (200 chars — a summary, not a log dump; the *file* is already
archived via `raw_output_ref` for anyone who needs the whole thing). The JUnit adapter's existing
warning string becomes this field's value instead of dying in the CI log. Every other adapter is
unaffected — `detail` stays `None` for everything that has nothing specific to say, which is most
scans most of the time.

`ScanHealthBoxes` renders `detail` as a one-line subtext under the box when the most recent run set
one — generically, not JUnit-specific, so a future capability with something worth saying for free
gets the same treatment without new frontend code.

### 1.3 Flaky-test flagging

A lane that fails, then passes, then fails again on the *same commit* is a different problem than a
regression — and today looks identical to one in `ScanHealthBoxes`' percentage. Compare the last two
`ScanRun`s for a lane: if `commit_sha` is unchanged between them and `scan_status` flipped, render a
"flaky — flipped without a code change" note instead of (or alongside) the raw pass rate. Pure
comparison of two already-fetched rows; no new data source.

## 2. Triage automation

### 2.1 Reachability — a cheap, honest first cut

Spec 17 §5.3 built the plumbing (`reachability: {available: false}` in every Oracle snapshot) and
correctly declined to build a call-graph engine. This spec adds the cheapest signal that is still
*true*: **is the file a `sast` finding is in imported from anywhere else in the repo at all** — not
full call-graph reachability, just "is this file reachable from the rest of the codebase, or does
nothing import it."

- A new, narrow analysis: for each repo's most recent commit, build an import edge list per language
  the platform already has an adapter for (start with Python — `ast`-parse `import`/`from` statements,
  no dependency resolution) and mark a file `orphaned` if nothing in the repo imports it and it is not
  an entry point (a file matching common entry-point globs: `main.py`, `manage.py`, `wsgi.py`, files
  under `scripts/`).
- This is honestly partial: `available: true` only for languages with a parser built (Python first),
  `available: false` everywhere else — the same disclosed-resolution pattern the Threat Model tab
  already uses for its capability-level STRIDE mapping (spec 18 §6.3). A finding in an orphaned
  Python file gets a real, auditable `reachability` contribution in Oracle; a finding in any other
  language, or in a repo with no import graph built, stays `unavailable`, not guessed.
- **Not attempted**: cross-file call resolution, dynamic imports, reflection, or any non-Python
  language. This is the floor that makes the category honestly non-empty for some real findings, not
  the ceiling spec 17 declined to build.

### 2.2 Combination-rule discovery

The 9 rules in `patchwork/correlate.py` are hand-written and will always need to be — `BUILT_IN_RULES`
staying declarative and human-reviewed is spec 08 §5's whole point, and this does not change that.
What it adds is *finding candidates for a human to review*, the same shape spec 11's
`find_cross_project_candidates` already uses for false-positive promotion:

- A retro job scans `remediation_events`/`risk_decisions` for pairs of capabilities that co-occur in
  the same file across multiple repos more often than chance (a simple co-occurrence count, not a
  statistical model) and that are *not* already covered by an existing `CombinationRule`.
- Surfaced in the existing retro report (`knowledge/reports.py`) as a new section, "Candidate
  combinations" — capability pair, co-occurrence count, repos, example finding pairs. A person turns
  a candidate into a real `CombinationRule` by writing one, the same as today; nothing here writes to
  `correlate.py` automatically.

### 2.3 Cross-repo dampening: an actual approve/reject action

`find_cross_project_candidates` and `GET /api/knowledge/promotion-candidates` already exist and work
(spec 11 §9) — the gap is that "approved in the dashboard" (the module's own docstring) was never
built as an *action*. Today a candidate is visible only in the `/retro` report; there is no button.

- `POST /api/knowledge/promotion-candidates/{subject}/approve` — admin-only (`may_write`), moves the
  matching entries to `to_tier` (the same `NEXT_TIER` mapping `promotion.py` already defines),
  audit-logged (`db.audit`, matching the Oracle-override pattern spec 09 §6 already established).
  Explicitly a human decision recorded, not an automatic promotion — `promotion.py`'s own docstring
  ("Nothing here writes to a target tier ... on its own. The scheduled job finds candidates; a person
  decides") stays true; this endpoint *is* the person deciding, not a new automatic path.
- Frontend: a "Candidates" section on the `/retro` page (already the promotion-candidates' one
  consumer) gains an "approve" button per candidate, calling the new endpoint through a proxy route,
  same shape as every other admin action in this app.

### 2.4 Blast-radius as a prioritization signal

A finding in a library 40 repos in the portfolio depend on is a different priority than the same
finding in a leaf repo — and nothing today reads across repos to know the difference; each repo's
Atlas evidence is self-contained.

- A portfolio-wide job aggregates `sscs_evidence.ecosystems_json` across every active repo, building a
  package-name → dependent-repo-count map (approximate — package name matching, not exact version
  resolution, since exact cross-repo version-graph resolution is a much larger undertaking than this
  signal is worth).
- Exposed as a new, `available`-gated Oracle input, `blast_radius`, following the established honest
  pattern: `available: true` only when the portfolio-wide job has run at least once; a finding whose
  `package_name` matches a package depended on by ≥5 other active repos gets a modest contribution
  (magnitude to be set in `oracle-policy-v1.yaml`, not hardcoded — matching every other weight in the
  policy). Below 5, or no match, contributes nothing — this is a signal about *concentration risk*,
  not a general dependency-count penalty (which SSCS trust already covers per-repo).

## 3. Remediation growth

### 3.1 New deterministic fixers

`patchwork/fixers.py` has two: `pin_python_requirement`, `remove_committed_secret`. Add, in priority
order (most common finding types first, per the same "narrow, deterministic, one job each" shape the
existing two already establish):

1. **`pin_npm_dependency`** / **`pin_go_module`** — same shape as `pin_python_requirement`
   (`package.json`/`go.mod` version-bump to the finding's `fixed_version`), one fixer function per
   ecosystem rather than a single generic one, matching the existing one-fixer-per-manifest-format
   convention (`FIXERS` is a flat list checked in order, `fixers.py:195-199`).
2. **IaC encryption/CIDR fixes** — a bounded set of Checkov/tfsec finding patterns that are genuinely
   mechanical (add an `encryption { }` block with a sane default, tighten an `0.0.0.0/0` ingress CIDR
   to the finding-reported value) — scoped to the handful of rule IDs where the "right" fix has no
   ambiguity, not an attempt to auto-fix IaC generally.
3. **Missing security header** — a narrow, framework-specific fixer (starting with the one or two
   frameworks most represented in the portfolio) that adds a one-line middleware registration for a
   missing `Content-Security-Policy`/`Strict-Transport-Security` header, only when the framework's
   entry-point file is unambiguous.

Each new fixer follows `ProposedFix`'s existing contract unchanged (`confidence`, `review_notes`,
`files`, `touched`) — no change to `_attempt_fix`, `run_one`, the preview/fix endpoints, or their
guardrails. This section is additive to `FIXERS`, nothing else.

### 3.2 Auto-preview on ingestion

`preview_only` (spec 18 §7.2) already writes nothing and is safe to call repeatedly — today it only
runs when a person clicks a finding. Running it once, automatically, the moment a finding is
classified `true_positive` at ingestion time (in `_group_findings`, where `classify()` already runs)
would let the Findings tab show a `fixable` badge on a group *before* anyone opens it — cheap, because
the underlying call is already idempotent and already used defensively for exactly this reason.

- New field on `FindingGroupOut`: `fixable: bool | None` — `None` when not yet checked (e.g. a
  combination, or a classification other than `true_positive`, where preview is never attempted),
  `true`/`false` once it has been.
- Computed lazily, not eagerly at write time: `open_findings()` calls `preview_only` for the *visible
  page* of `true_positive` groups only (bounded, same "don't compute for a thousand-row page" caution
  `_attach_threat_intel` already applies to KEV lookups) — not a new background job, not a write to
  the lake.
- A new `Filters()` toggle, "fixable only" — reachable the same way `triage`/`kev_only` already are.

### 3.3 Toxic-combination partial remediation

Today a combination gets `needs_human_judgment` and Patchwork stops — correctly, since fixing one
half in isolation can close the finding without closing the risk (spec 08 §8). This section scopes
*which* combination rules have a safe partial fix, rather than building a generic "fix half a
combination" capability that would repeat the same mistake for every rule at once:

- Exactly one candidate to start: **"Committed credential on a public surface"**
  (`committed-credential-public`, `correlate.py`). The credential-removal half
  (`remove_committed_secret`, already a real fixer) is safe to run *even inside a combination*,
  because rotating/removing a leaked credential is correct regardless of whether the "public surface"
  half also gets fixed — the combination's danger is a credential reachable from outside, and pulling
  the credential closes that regardless of what fixes the reachability.
- Implemented as a new, narrow field on `CombinationRule`: `safe_partial_fix: str | None`, naming
  which `Requirement` (by capability) may still be routed to `_attempt_fix` individually even while
  the combination as a whole stays `needs_human_judgment`. Every other rule keeps `None` — no partial
  fix — by default; adding one is a reviewed, per-rule decision, not a platform-wide behavior change.

### 3.4 Cross-repo batch digest

Ten repos with the same unpinned dependency today means ten separate draft PRs, reviewed one at a
time with no indication they're the same fix. Still ten PRs — never one PR touching ten repos, which
would break per-repo review and CODEOWNERS — but grouped for the *reviewer*:

- A new admin view, `/remediation` (portfolio-wide, alongside `/decisions` and `/pull-requests`),
  grouping open `RemediationEvent`s across every repo by `(rule_id, fixer_name)` — "12 open PRs, same
  fix, same rationale, across 12 repos" as one card linking out to each individual PR.
- No new backend query logic: `remediation_events` already carries everything needed
  (`repo_full_name`, `fix_pr_url`, `triage_classification`, `rationale`); this is a grouping/rendering
  change over data already queried by the existing per-repo `GET /api/patchwork/repos/{repo_id}`,
  generalized to no `repo_id` filter.

## 4. Auto-routing: closing the loop between triage and action

### 4.1 What this replaces

Today, classification (`classify()`) decides what a finding *is*, and two independent, entirely
manual actions exist to do something about it: Patchwork's on-demand fix (spec 18 §7) and i2i grooming
(spec 17 §7). Nothing connects the three. A `true_positive` finding with a matching fixer sits exactly
as inert as one without a fixer until a person opens it and clicks something — the platform already
knows enough to act and doesn't.

The axis that decides which action fits is **fixability, not severity**. A critical SQL injection has
no deterministic fixer and never will — no script safely rewrites a query without understanding the
surrounding logic, so it needs a story regardless of how urgent it is. A medium unpinned dependency has
had a working fixer since spec 08 shipped — routing it to "file a story" when a safe PR could exist in
seconds is makework. Severity still matters — it decides *urgency*, i.e. whether the resulting story is
filed immediately and labeled loudly or batched into a backlog sweep — but it is not what decides
*which* of the two systems handles the finding.

### 4.2 The routing table

Run at the same point `classify()` already runs (`_group_findings`, so the Findings tab, Patchwork, and
this routing pass are always looking at the identical classification — one function, three consumers,
never three opinions):

| Classification | Fixable (§3.2's `preview_only` says yes) | Not fixable |
|---|---|---|
| `true_positive` | Already automatic: Patchwork's batch sweep opens the PR unprompted (unchanged) | **New:** auto-groom into a story immediately, `priority: urgent` label |
| `needs_human_judgment` | **New:** auto-groom into a story, batched (§4.4), `priority: normal`/`low` by severity | Same |
| `toxic_combination` | Unaffected by this section — §3.3 already covers the one rule with a safe partial fix; everything else stays `needs_human_judgment` and is groomed as a combination story (already possible via `groom_combination`, just not automatic — this section makes it automatic too) | Same |
| `likely_false_positive` | Never routed to either — dampened, per spec 11, on purpose | Same |

### 4.3 What ships

- A new scheduled pass (same job shape as the Knowledge Store's retro report, `knowledge/reports.py`,
  and the promotion-candidate scan §2.3 already adds) that walks each active repo's open,
  `true_positive`/`needs_human_judgment`/`toxic_combination` groups, checks `fixable` (§3.2's
  now-precomputed field, so this pass costs nothing new for `true_positive` findings — the check
  already happened), and for anything not fixable and not already groomed, calls the same
  `gather_finding_story`/`gather_combination_story` + `_open_or_update` path `POST
  /api/triage/.../groom` already uses — reused directly, not reimplemented, so an auto-filed story and
  a manually-groomed one are produced by the exact same code and are indistinguishable once filed.
- **Idempotent by construction, not by a new check**: `story_id()` is already deterministic
  (repo + subject), and `_open_or_update` already updates the existing issue rather than duplicating
  it (spec 17 §7.2) — running this pass on a schedule against findings it already groomed is a no-op
  update, not a growing pile of duplicate issues.
- **Never for a repo without `patchwork`/i2i capability configured** — this pass calls the same
  `_github_for` lookup the manual groom endpoint already uses, and a repo with no App installation
  simply has nothing to route, same as today.
- Each auto-filed story is labeled with a priority derived from severity (`urgent` for
  critical/high `true_positive`-not-fixable, `normal` for medium, `low` for low) — a label on the
  issue, not a new field in `TriageStory` or a change to `render_issue_body`'s existing shape.

### 4.4 Batching for `needs_human_judgment`

Filing one issue per medium/low finding the instant it's seen would flood a tracker with backlog noise
— the same "a draft PR for a low finding costs more review attention than it's worth" reasoning
`classify()` already states for auto-fix applies here to auto-filing. `needs_human_judgment` findings
are swept **once per day**, not on ingestion, and — where `gather_finding_story` already groups by
`rule_id` for the story's own content — one issue per `(repo, rule_id)` rather than one per finding,
matching how the Findings tab already collapses the same rule into one group (`_group_findings`'s
existing key). A rule firing in fifteen files is fifteen occurrences and one story, exactly as it is
already one row on the Findings tab.

### 4.5 The severity floor, made configurable

`classify()`'s `true_positive` gate is hardcoded to `severity in ("critical", "high")`. Spec 19 §3
grows the fixer library; once a medium/low finding is reliably auto-fixable, keeping the gate
hardcoded means it can never benefit from that growth without a code change. New `PatchworkConfig`
field, `auto_fix_min_severity: str`, default `"high"` (today's actual behavior, unchanged by default),
following `min_confidence_to_generate_fix`'s exact shape (a per-repo-configurable threshold, not a
platform-wide constant). Lowering it to `"medium"` for a specific repo means that repo's medium
findings become eligible for the *unprompted* batch sweep the moment a fixer matches — the on-demand
per-finding fix (spec 18 §7) is unaffected either way; it has never been severity-gated, only the
unprompted batch sweep was.

## 5. Acceptance criteria

- A unit/functional/qa lane with at least 3 historical runs renders a sparkline on the Harness tab.
- A JUnit-adapted scan run with failures shows its warning text on the corresponding `ScanHealthBoxes`
  tile, not just the pass rate.
- A lane whose last two runs share a commit sha and disagree on `scan_status` is labeled flaky.
- A Python file nothing in the repo imports, with an open `sast` finding in it, shows a non-zero,
  auditable `reachability` term in that repo's next Oracle decision; a finding in any non-Python file
  still shows `reachability: {available: false}`.
- The `/retro` page's promotion candidates each have a working "approve" button that moves matching
  entries to the next tier and is visible in the audit log.
- A `true_positive` finding with a matching deterministic fixer shows `fixable: true` on the Findings
  tab without anyone having clicked into it first.
- The credential-removal half of a detected "committed credential on public surface" combination can
  be fixed via the existing per-finding `fix` endpoint even while the combination event itself still
  reads `needs_human_judgment`.
- A rule dismissed with the same reason in 3+ repos appears as a "candidate combination" or promotion
  candidate as appropriate, without a person having compared repos by hand.
- A `true_positive` finding with no matching fixer gets a dev-ready GitHub issue opened within one
  routing cycle, without anyone clicking "groom as story."
- A `true_positive` finding *with* a matching fixer does not also get a story filed — it stays on the
  Patchwork PR path exactly as today, not routed to both.
- Fifteen `needs_human_judgment` occurrences of the same rule in one repo produce exactly one issue,
  not fifteen.
- Setting `auto_fix_min_severity: "medium"` on a repo with the npm-pin fixer (§3.1) available makes a
  medium-severity unpinned-dependency finding eligible for the unprompted batch sweep; the same repo's
  default (`"high"`) leaves it fixable only on demand.

## 6. Edge cases

- A repo with no `sscs_evidence` (atlas never run) is `available: false` for `blast_radius`, exactly
  like it already is for `sscs_trust` — no new failure mode, same existing null convention.
- Auto-preview (§3.2) never runs for a repo whose Patchwork capability is disabled — `preview_only`
  still needs a `PatchworkPipeline` instance, which needs `patchwork` capability config; a group's
  `fixable` stays `None` rather than attempting a call with nothing configured.
- A candidate combination (§2.2) that would duplicate an existing `CombinationRule`'s coverage (same
  capability pair, overlapping file scope) is excluded from the report — a duplicate suggestion is
  worse than no suggestion.
- The flaky-test flag (§1.3) never fires across a rebase/force-push that changes `commit_sha` without
  changing test content — this is a known, accepted false-negative (the alternative is diffing test
  file contents across commits, out of scope here).
- A finding that flips from `needs_human_judgment` to `true_positive` between routing cycles (e.g. its
  severity was corrected upstream) is not double-filed — `story_id()`'s determinism means the next
  cycle updates the existing issue rather than opening a second one, and if it's now also fixable,
  Patchwork's batch sweep picks it up independently on its own next run; the two paths do not need to
  coordinate because `_open_or_update` and `_attempt_fix` are each idempotent on their own.
- A repo with `patchwork` capability disabled but i2i/GitHub App still installed still gets stories
  filed for non-fixable findings (grooming needs the App, not the `patchwork` capability grant) — only
  the auto-fix half of routing needs `patchwork` configured.
- Lowering `auto_fix_min_severity` does not retroactively re-triage findings already routed to a story
  under the old threshold — a finding already groomed stays groomed; only its *next* routing-eligible
  state (if it's re-ingested, e.g. after a rescan) sees the new threshold.

## 7. Dependencies

Spec 08 (Patchwork — fixers, combination rules, `_attempt_fix`, `PatchworkConfig`), spec 09 (Oracle —
input-category pattern every new signal here follows), spec 11 (Knowledge Store —
`find_cross_project_candidates`, tier promotion), spec 17 (triage `classify()`, reachability plumbing,
i2i grooming — `gather_finding_story`/`gather_combination_story`/`_open_or_update`), spec 18 (Test
Harness tab, per-finding preview/fix, Threat Model's disclosed-resolution pattern).
