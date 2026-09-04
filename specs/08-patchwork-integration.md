# Spec 08 — Patchwork Integration (Auto-Remediation)

**Status:** Approved for build
**Depends on:** [04 — Scanner Workflows](04-scanner-workflows.md), [05 — Data Lake](05-datalake.md), [11 — Knowledge Store & RAG](11-knowledge-rag-learning.md)

---

## 1. Purpose

Add an **auto-remediation** capability, modeled on the existing internal
"Project Patchwork" pattern: when SAST/Secrets/Containers/IaC findings
appear on a PR, an agent pipeline triages them, groups related findings
("toxic combinations" — multiple findings that combine into a worse
composite risk), generates candidate fixes, and opens **draft** pull
requests for a human to review. **Patchwork never merges anything itself.**

## 2. Pipeline stages (multi-agent, sequential)

1. **Ingest** — read new `Finding` rows (spec 05 §3) for the current PR's
   commit, filtered to capabilities configured to feed Patchwork (default:
   `sast`, `secrets`, `containers`, `iac`).
2. **Triage** — classify each finding: true positive / likely false
   positive / needs-human-judgment, using the Knowledge Store (spec 11) to
   retrieve similar past findings and how they were previously resolved.
3. **Correlate** — detect "toxic combinations": sets of findings that,
   combined, represent higher risk than any one alone (e.g., an
   unauthenticated endpoint + a SQL-injectable query in the same request
   path). Correlation rules are configurable (see §5); v1 ships a small
   built-in rule set and allows custom rules to be added without code
   changes.
4. **Generate fix** — for findings classified as true positives with a
   known safe fix pattern, generate a code change.

   **Two generators, and the deterministic one is not a fallback.** v1 ships
   pattern-based fixers for the classes where the correct change is mechanical
   and verifiable — pinning a vulnerable dependency to a known-good version,
   removing a committed credential and replacing the reference, adding a
   missing IaC property with a documented default. These need no model, they
   are reviewable line by line, and their output is identical every run.

   **Deterministic fixers are the only generator (D-096).** This section
   previously specified a second, LLM-backed one behind a `fix_generator_url`
   endpoint. That setting was validated, stored, exposed through the API and
   threaded into the pipeline — and never used to make a request. Its only
   effect was to choose between two rationale sentences, one of which read as
   though a generator had been consulted and declined. It was withdrawn rather
   than implemented: the deterministic half is the half that works, and an
   endpoint an operator can configure and watch do nothing is worse than an
   honest absence.

   Findings outside the deterministic classes reach `no_fix_available` with a
   rationale saying exactly that. Adding an LLM generator later is a design
   change that needs its own decision — including the request and response
   contract, failure behaviour, and what stops a bad fix reaching a pull
   request — none of which this spec ever specified.
5. **Open draft PR** — commit the fix to a new branch, open a **draft** PR
   referencing the original finding(s), with a description explaining the
   fix and linking back to the finding in the dashboard.
6. **Record outcome** — write a `RemediationEvent` row (§4) regardless of
   whether a fix was generated, so the data lake always shows what
   Patchwork did or didn't do and why.

## 3. Human-in-the-loop guarantee (hard constraint)

- Every Patchwork-generated PR is opened as a **draft**.

- **The guarantee is structural, not permission-based.** An earlier draft of
  this spec said Patchwork "has no merge permission" and that the App "should
  not request merge rights". That is not achievable and stating it was
  misleading. Merging a pull request through the API needs `contents: write`,
  which the App already holds and cannot give up: it is what lets the Workflow
  Installer commit workflow files at all (spec 02 §4, D-008). Any deployment
  where Patchwork can open a PR is one where the App could technically merge
  one.

  So the guarantee is enforced where it can actually be checked. The
  `GitHubClient` protocol (spec 02) **exposes no merge operation** — there is
  no method to call, in either the real or the fake implementation — and a
  test asserts that no such method exists. A future contributor who wants
  Patchwork to merge has to add a capability to the client interface, which is
  a visible, reviewable act rather than a config flag.

  This is the same posture spec 14 §4 takes for network scanning: where a
  platform-level permission cannot express the constraint, the constraint
  lives in code with a test that fails if it is removed.
- No `blocking`/auto-merge configuration exists for Patchwork — unlike
  other capabilities, this is not configurable per repo. This is
  intentional and must not be made configurable without a deliberate,
  separately-reviewed design change.
- If a generated fix later needs modification, a human edits the draft PR
  branch directly (normal GitHub workflow) — Patchwork does not
  automatically re-push over human edits once a PR has received a human
  commit or review comment.

  "Has received a human commit" is determined by comparing the PR's commit
  authors against Patchwork's own bot identity, not by trusting a flag. Once
  any commit on the branch has a different author, `pr_status` becomes
  `human_edited` and Patchwork stops touching that branch permanently — there
  is no path back, deliberately. Somebody's edit being silently overwritten by
  a bot is the single fastest way to lose a team's trust in this capability.

## 4. Data model — `RemediationEvent` (data lake table)

| Field | Type | Notes |
|---|---|---|
| `event_id` | string | PK. **Derived, not random**: SHA-256 over `repo_full_name` + `finding_id`, or over the sorted contributing finding ids for a combination. §7 requires exactly one event per finding routed, and the pipeline re-runs on every push to a pull request — a random id would append a row per run and the requirement would quietly stop holding. Same rule as `finding_id` (spec 05 §5), `signal_id` (06 §3), `evidence_id` (07 §3) and `entry_id` (11 §3) |
| `repo_full_name` | string | |
| `finding_id` | UUID | FK → `Finding` (spec 05 §3); nullable if event is about a toxic combination rather than a single finding |
| `toxic_combination_id` | string, nullable | Derived from the rule id and the sorted contributing findings, so the same combination detected twice is the same combination |
| `contributing_finding_ids` | list[string] | The findings a combination is made of. §7 requires the event to "reference all contributing findings" and the original model had nowhere to put them — with `finding_id` null for a combination, the event named no findings at all |
| `pipeline_stage_reached` | enum | `triaged, correlated, fix_generated, pr_opened, no_fix_available, skipped_low_confidence, queued, superseded`. `queued` is what §5's backpressure actually produces and the original enum had no value for it. `superseded` is §8's case: the finding was fixed by a human before the draft PR was reviewed |
| `triage_classification` | enum | `true_positive, likely_false_positive, needs_human_judgment` |
| `fix_pr_number` | int, nullable | |
| `fix_pr_url` | string, nullable | |
| `pr_status` | enum, nullable | `draft_open, human_edited, merged, closed_unmerged` — kept in sync via `pull_request` webhook |
| `rationale` | text | human-readable explanation of the triage decision and, if generated, the fix approach |
| `created_at` | datetime | |

## 5. Configuration (`CapabilityConfig` for `patchwork`)

| Field | Type | Default | Notes |
|---|---|---|---|
| `source_capabilities` | list | `["sast", "secrets", "containers", "iac"]` | which capabilities' findings Patchwork may generate a **fix** for. Code-fixable by construction — see §5a |
| `correlation_capabilities` | list | every capability | which capabilities' findings **toxic-combination detection** may consider (§5a) |
| `min_confidence_to_generate_fix` | float (0–1) | `0.7` | below this, stage stops at `no_fix_available` rather than generating a possibly-wrong fix |
| ~~`fix_generator_url`~~ | — | — | **Withdrawn (D-096).** Never reached an HTTP call; see §2 stage 4. Stripped from stored configs on save rather than rejected, so a repo configured before the withdrawal still saves |
| `toxic_combination_rules` | list of rule refs | built-in default set | admin-extensible rule definitions |
| `max_open_draft_prs_per_repo` | int | `10` | Backpressure. A repository that wakes up to forty draft pull requests does not triage them, it turns the capability off. Over the limit, a candidate's event is recorded with `pipeline_stage_reached: queued` and the fix is *not* generated — the queue is the event table itself, re-examined on the next run, not a separate structure holding unreviewed generated code |

### 5a. Correlation sees more than fix generation

`source_capabilities` answered two different questions with one list, and got
the second one wrong.

Which findings Patchwork can write a patch for is a narrow set, correctly:
SAST, secrets, containers and IaC findings all point at a line in a file that
a deterministic fixer can change. A DAST finding does not. Neither does a
cloud-posture finding, or an open port.

Which findings can *participate in a toxic combination* is a different and
much wider question, and using the narrow list for it made a whole class of
combination undetectable. The clearest example is the one this platform is
for:

> A DAST scan reports an unauthenticated endpoint on the running application.
> A secrets scan reports a live credential committed in the handler behind
> it. Separately: a medium and a high. Together: an unauthenticated endpoint
> that hands out a working credential.

Under the old rule the DAST half was never a candidate, so the combination
could not fire — and each half, viewed alone, looks like ordinary backlog.

**Correlation considers every capability. Fix generation still considers
only `source_capabilities`.** A combination whose members include a finding
Patchwork cannot fix is not a problem: a detected combination already stops
individual fix generation and routes to `needs_human_judgment` (§2 stage 3).
Combinations spanning a runtime finding and a code finding are the ones most
likely to need a person, so the path they take is the right one.

**Consequence for scope.** File-scoped rules cannot express these. A DAST
finding's `file_path` is a URL path or empty; a cloud finding's is a resource
id. Cross-capability rules are therefore `repo`-scoped, and the rule set has
to earn that with specific `rule_id` patterns rather than broad ones —
repo scope plus a loose pattern is how a correlation engine starts reporting
that everything is toxic.

## 6. Workflow behavior

- Template: `workflow-templates/patchwork.yml.j2`, triggered on
  `pull_request` (after the source-capability scanner workflows have
  posted their findings — implemented as a `workflow_run` trigger that
  fires once the relevant scanner workflow completes, to guarantee
  ordering) and optionally on a schedule to sweep existing open-finding
  backlog.
- Steps: call the Patchwork pipeline (backend service, not purely a
  GitHub Action — the multi-agent pipeline runs server-side for
  observability and shared LLM-cost tracking) → pipeline reads relevant
  `Finding` rows from the data lake → executes stages 1–6 above → the
  final step of the *workflow* (not the pipeline) calls the shared upload
  step (spec 04 §2) to ensure `RemediationEvent` rows land in the data
  lake even if invoked as a backend job rather than in-workflow.

## 7. Acceptance criteria

- No Patchwork-authored PR is ever created as non-draft, and no Patchwork
  service credential has merge permission.
- Every finding routed to Patchwork produces exactly one `RemediationEvent`
  row, even when no fix is generated (`no_fix_available`).
- A detected toxic combination produces one `RemediationEvent` with a
  populated `toxic_combination_id` referencing all contributing findings.
- `max_open_draft_prs_per_repo` is enforced — exceeding it queues rather
  than creates additional draft PRs.

## 8. Edge cases

- Two findings on the same PR both map to overlapping code regions — avoid
  generating two separate conflicting draft PRs; Patchwork should detect
  the overlap and either combine into one PR or defer the second to
  `needs_human_judgment`.
- The original finding is resolved/fixed by a human before Patchwork's fix
  PR is reviewed — a reconciliation job checks whether the source finding
  is still `open`; if not, auto-closes the now-redundant draft PR with a
  comment explaining why, rather than leaving stale PRs open.
- LLM/agent pipeline failure mid-run — must still emit a
  `RemediationEvent` with `pipeline_stage_reached` set to wherever it got
  to, not silently disappear (architecture constraint, spec 01 §6).

## 9. Dependencies

- Spec 04/05 for the findings Patchwork consumes and the events it
  produces.
- Spec 11 (Knowledge Store) — triage decisions and PR outcomes
  (`merged` vs `closed_unmerged`) are the single richest source of retro
  learning signal in the whole system; Patchwork must write these outcomes
  in a form spec 11's ingestion can consume (see spec 11 §4).
- Spec 09 (Oracle) may consider "an auto-fix is already in flight for this
  finding" as a factor in its risk decision (e.g., lower urgency to block a
  release if a fix PR already exists).
