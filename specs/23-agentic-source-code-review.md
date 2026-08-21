# Spec 23 — Agentic Source Code Review: Measure the Detectors, Map the Surface, Defer the Finder

**Status:** Draft for review
**Depends on:** [04 — Scanner Workflows](04-scanner-workflows.md), [05 — Data Lake](05-datalake.md),
[09 — Oracle](09-oracle-risk-decision-engine.md), [11 — Knowledge Store & RAG](11-knowledge-rag-learning.md),
[15 — Concourse Pipeline](15-concourse-pipeline.md), [17 — Harness, Threat Intel, i2i](17-harness-threat-intel-and-i2i.md),
[18 — Repo Page Rework](18-repo-page-rework-threat-model-and-remediation.md)

---

## 0. What this spec is against

Mandiant's writeup of its Agentic Vulnerability Discovery Harness — *Staying ahead of adversarial AI
through agentic source code review* — describes a six-phase pipeline: threat modelling, entry-point
discovery, context enrichment, hypothesis generation, multi-agent validation, human review. Read
against this platform, four of those six phases are not new capabilities at all. They are the engines
behind gaps this project has already found, named, and declined to fill:

- **Reachability.** Spec 17 §5.3 wired the Oracle category and left it permanently `available: False`,
  because a call graph is a project rather than a feature. D-072 later added the honest floor —
  for Python only, does anything import this file.
- **A threat model with real resolution.** Spec 18 §6 ships STRIDE by *capability*, and
  `mapping_resolution` says so in the response, because no `Finding` carries a structured CWE.
  D-063 recorded the narrative layer as honest plumbing with no LLM wired.
- **Detector quality.** Spec 04 §7 asks for "a test repo with known seeded vulnerabilities" producing
  "at least one `Finding`". No such repository exists. Nothing in this platform measures recall, false
  negatives, or drift for any of the fifteen checks it runs.

**The cadence difference is what this spec refuses to import.** AVDH is engagement-shaped: drop into an
unfamiliar codebase, derive a threat model, produce a report, bill. This platform is continuous over
four known repositories. Re-deriving the same threat model every week is money spent to learn what was
already approved last week. So the sequential six-phase pipeline is not copied as an architecture: the
surface is derived once, persisted, approved by a human, and re-derived only against its own diff.

**What is deliberately built last.** The vulnerability-finding agents — hypothesis generation and
validation — are AVDH's centrepiece and the most expensive, highest-false-positive part of it. They
are §5 of this spec, behind a gate, because D-053 already records what happens to an expensive scan
with no resource budget: DAST is paused platform-wide, and it is cheaper than this would be.

## 0a. Implementation status

Nothing here is built. The order is the point, and each row is gated on the one above it.

| # | Workstream | Status | Gate to start |
|---|---|---|---|
| 1 | Detector benchmark corpus and grading lane (§1) — no LLM anywhere in it | Not started | — |
| 2 | `review` capability: attack-surface inventory, discovery only (§2) | Not started | §1 lane green |
| 3 | Threat model at entry-point resolution (§3) | Not started | §2 surface approved for one repo |
| 4 | Rule pack and Knowledge Store at prompt time (§4) | Not started | §2 shipped |
| 5 | Hypothesis generation and validation (§5) | Not started | §5.1's four conditions, all of them |

## 1. Detector benchmark — and no LLM in it

### 1.1 Current state

Spec 04 §7's acceptance criterion has never been implementable: there is no seeded corpus, and its bar
— "at least one `Finding`" — cannot distinguish a scanner catching nine of ten seeded injections from
one catching one. A search for precision, recall, false negatives or ground truth across `specs/`,
`docs/`, `backend/` and `scripts/` returns prose about the concepts and no measurement of any of them.

This matters before anything agentic is built, and independently of whether anything agentic is ever
built: the platform runs fifteen checks and cannot say how well any of them works on code like its own.

### 1.2 What ships

A corpus of seeded vulnerabilities with a machine-readable manifest, and a lane that grades scan
results against it.

- **The corpus is its own repository**, onboarded like any other (`mykronos-bench`), not a directory in
  this one. Seeded vulnerabilities inside the platform repository would be ingested under this repo's
  `repo_full_name` as real findings, raise its risk score, and reach its own Oracle gate. The corpus
  must be scanned by the real pipelines to be worth anything, so it must live somewhere that scanning
  it is harmless.
- **`Repository` gains `synthetic: bool`** (default `false`). A synthetic repo is excluded from
  portfolio aggregation (spec 21 §2) and from fleet term analytics. Without this the corpus becomes,
  permanently, the fleet's worst repository — deliberately vulnerable code counted as estate risk.
- **`bench/manifest.yaml`** in that repository: one entry per seeded issue, naming `file`, a line
  window, the expected `capability`, and a prose description of the flaw. It names the expected
  capability and **not** the expected `rule_id` — a rule identifier is a free-form string the reporting
  tool chose, exactly as spec 18 §6 says, and pinning a grade to one would grade the tool's naming.
- **`scripts/bench_grade.py`** reads the manifest, queries the lake for that repo and commit, matches
  each seeded issue to findings by file and line window (with the same tolerance for drift the
  fingerprint already assumes — a finding two lines off is the same finding), and emits JUnit XML.
- The grade lands as a **`functional` ScanRun on the bench repository** (D-046: a quality stage reports
  a run and never a finding — a detector missing a seeded bug is not itself a vulnerability).

### 1.3 What it reports, and the number it refuses to report

Per capability: `seeded_total`, `seeded_detected`, and `unmatched` — findings with no manifest entry.

`unmatched` is **not** reported as false positives, and no precision figure is computed. The corpus is
seeded, not *clean*: an unmatched finding may be a genuine flaw somebody wrote by accident while
writing a fixture. Calling it a false positive would manufacture a quality number out of an
assumption, which is the failure spec 10 §6 forbids in the dashboard and this would only move into a
test report. `unmatched` is a count a human reads and investigates.

### 1.4 What does not ship

A grading agent. AVDH needs one because its findings land on real client code with no ground truth; a
seeded corpus has a manifest, so grading is a diff. No public benchmark dataset is used, for the reason
the article gives: modern models may have memorised the solutions.

## 2. The `review` capability — an attack-surface inventory, and nothing else

### 2.1 Current state

`reachability.py` answers one question, for Python only: does anything in this repository import this
module. Its docstring names the failure mode it refuses — *"a false 'this is orphaned' tells somebody a
live request handler is dead code"* — and its output is a capped discount, never a promotion. Oracle's
`reachability` category is `available: False` on every decision ever made.

Nothing anywhere enumerates what an attacker can actually reach: routes, handlers, webhook receivers,
queue consumers, CLI entry points, scheduled jobs.

### 2.2 What ships

A sixteenth capability, `review`, whose entire v1 output is an inventory. It is the one agentic phase
worth building early because it is *verifiable*: an entry point either exists at that `file:line` or it
does not, and a reviewer confirms it in seconds. A wrong entry falls out at approval instead of
consuming triage.

- `Capability.REVIEW = "review"`, one `AdapterSpec("review", "mykronos-agentic-review", ...)`, a
  `DEFAULT_TOOLS` entry, a `ReviewConfig` in `capabilities.py`, a `STRIDE_BY_CAPABILITY` row, and a
  lane in `mykronos.yml` conforming to PS-1…PS-10.
- **The standard set becomes sixteen.** Spec 10 §2.1's icon badges, §2.2's CapabilityManager, `docs/pipeline-standard.md`'s
  conformance table, the icon set, and the coverage cross-check all say *fifteen* today. A capability
  that exists in the enum and not in those places is a capability the dashboard cannot enable.
- **Discovery runs on the runner, storage on the platform** — the split spec 07 already holds Atlas to.
- **A new lake table, `review_surface`**, following the `sscs_evidence` conventions (`surface_id`
  primary key, partitioned and ordered on `discovered_at`): `repo_full_name`, `commit_sha`, `kind`
  (`http_route` | `cli` | `webhook` | `queue_consumer` | `scheduled` | `ipc`), `identifier` (the route
  or handler name), `file_path`, `line_start`, `symbol`, `auth_expected` (`true` | `false` | null —
  null is "the discovery pass could not tell", and is not `false`), `evidence_json`, `model_id`,
  `rule_pack_version`, `approval_state`, `approved_by`, `approved_at`.
- **A human approves the surface before anything consumes it.** `approval_state` is
  `pending` | `approved` | `rejected`; only `approved` rows feed §3 or §5. This is AVDH's consultant
  gate, and it is the same shape as Oracle's override (spec 21 §4): a human verdict, attributed, with a
  reason, recorded next to the machine's rather than replacing it.
- **Re-derivation is incremental.** A scheduled run derives the surface only for files changed since
  the last approved run; unchanged entry points keep their approval. A whole-tree pass is a manual
  action, not a weekly one. This is the cadence fix from §0, and it is what makes the cost defensible.

### 2.3 Egress — D-068's rules, restated for a whole repository

D-068 records that `ai_classifier_url` is *"the only setting in this platform that sends repository
content to a third party"*, capped at 200KB, deleted after the request, and rendered as an unguarded
step so that reading the workflow tells you what leaves. This sends far more, so the same four rules
bind harder:

1. Per-repository grant. `review` is off unless explicitly granted, like every other capability.
2. Caps in `ReviewConfig`: `max_files`, `max_bytes`, and an excluded-path list defaulting to vendored
   trees. A run that would exceed them stops and reports `partial_failure` naming what it covered —
   PS-3, and never a silent truncation.
3. The pipeline step is rendered, not `if:`-guarded, for the reason D-068 gives.
4. The model writes into a fixed schema with capped fields. Free-form text does not enter a record.
   Nothing from this capability reaches Aegis: that is a question about a person, and spec 06 §9 keeps
   those apart.

### 2.4 What does not ship

No `Finding` from this lane — an entry point is not a vulnerability. No `Finding.reachability` column.
**Oracle's `reachability` category stays `available: False`.** An inventory says a file is on an entry
path; it cannot say a file is *not*, and the only thing that category could do with a partial answer is
discount findings that failed to appear in it. That is precisely the direction `reachability.py`
refuses to guess in. The category earns `available: True` when something measured on §1's corpus
justifies it — a later spec, with a number in it.

## 3. The threat model, at entry-point resolution

Spec 18 §6 groups open findings by capability and maps each capability to the STRIDE categories it can
speak to. With an approved surface, the same tab can group by *entry point*: this route, these
findings, this authentication expectation, these STRIDE categories.

- `mapping_resolution` gains `entry_point` alongside today's `capability`, per repository. The field
  already exists to say what resolution the answer has; this gives it a second value rather than
  quietly improving what the first one means.
- A repository with no approved surface renders exactly as it does today. Absent is not blank.
- Still no per-finding CWE, and no claim of one. The improvement is in the grouping, not in the
  taxonomy.

## 4. The rule pack, and the Knowledge Store at prompt time

AVDH injects consultant expertise as a hierarchy of rules — software domain, then language, then
framework, then vulnerability class. This platform can do that, and has half of it already.

- **`review-rules-v1.yaml`** at the repository root, beside `oracle-policy-v1.yaml` and
  `maturity-model-v1.yaml`, versioned the same way and for the same reason: the prompt is policy, and
  policy that changes without a version is policy nobody can reproduce a result against.
- **Every artefact records `model_id` and `rule_pack_version`.** Model identifiers are pinned exactly —
  this platform's own `check_ai.py` reports an unpinned model identifier as a finding, and a reviewer
  that fails the platform's own check is not shippable.
- **Retrieval already exists.** `knowledge/` captures reasoned dismissals per `rule_id` and spends them
  on Oracle dampening. The same retrieval, injected into §5's validator prompts and §2's discovery
  exclusions, is the repository-specific half of AVDH's rule hierarchy — accumulated automatically
  every time somebody triages, rather than hand-authored.

## 5. Hypothesis generation and validation — last, and gated

### 5.1 The gate

All four, before this is written, not before it is enabled:

1. §1's corpus exists and its lane is green.
2. The reviewer's own recall on that corpus is measured and published in this spec's status table.
3. A token and cost ceiling is configured per run.
4. The repository has an approved surface (§2).

### 5.2 What ships, when it does

- **Diff-scoped on pull requests**, whole-tree only on a schedule. AVDH analyses tens of millions of
  lines because a client is paying for one engagement; here the same spend recurs weekly, forever.
- **Two hypothesis passes**, following the article's split because it matches the vulnerability classes
  cleanly: access control (missing authorisation, privilege escalation, CSRF) over the surface from §2,
  and data flow (injection, XSS, path traversal) from entry point to sink.
- **Validators differ by lens, not by temperature.** The article's "high temperature during validation"
  does not port: `temperature` is removed on Claude Opus 5, Sonnet 5 and Opus 4.7/4.8 and returns a
  400. Diversity comes from distinct prompts — correctness, compensating controls, does-it-reproduce —
  which is a better fit anyway, since three identical validators agree on the same mistake.
- **Consensus before ingestion.** A hypothesis becomes a `Finding` only when a majority of lens
  validators and the synthesis pass confirm it. Everything else goes to the Knowledge Store as
  precedent, not to the lake as a low-confidence row. Confidence and the validator verdicts ride in
  `raw_finding_json`, so a triager can see what disagreed.
- **`review` is added to `capabilities_excluded_from_gates`** in `oracle-policy-v1.yaml` — where
  `network` already sits — until §5.1's recall number exists. An unmeasured detector does not get to
  refuse a commit.

## 6. Model and cost shape

Two tiers, because the phases have genuinely different needs:

| Phase | Model | Rate (per MTok) | Why |
|---|---|---|---|
| Discovery, enrichment (§2) | `claude-haiku-4-5` | $1 / $5 | High fan-out, one file at a time, mechanical |
| Hypothesis, validation (§5) | `claude-opus-5` | $5 / $25 | Multi-hop reasoning; adaptive thinking, `effort: high` |

- Scheduled runs use the **Batch API** (50%): nothing about a weekly surface refresh is
  latency-sensitive.
- The repository-context prefix is cached (`cache_control`), and the lane asserts
  `usage.cache_read_input_tokens > 0` on the second call. An unverified cache is usually an absent one.
- Streaming for anything with a large `max_tokens`, so a long run does not die on an HTTP timeout.

## 7. Acceptance criteria

- The bench repository is onboarded, scanned by the real pipelines, and its findings do not appear in
  any portfolio aggregate or fleet term.
- The grading lane reports per-capability `seeded_detected`/`seeded_total` and `unmatched`, as a
  `functional` ScanRun, and reports no precision figure.
- Deleting one detection rule from a scanner's configuration lowers exactly one capability's recall in
  the next grade — the benchmark notices a regression it is supposed to notice.
- `review` appears in the capability manager as the sixteenth check, with an icon, one-click
  enable/disable, and a row in `docs/pipeline-standard.md`'s conformance table.
- A `review` run on a repository with no grant makes no external call and reports
  `no_applicable_targets`, not a failure.
- An unapproved surface changes nothing: the Threat Model tab renders exactly as it did before, and
  Oracle's `inputs_snapshot` is byte-identical.
- Every `review_surface` row names the model identifier and rule-pack version that produced it.
- `check_ai.py` run against this platform reports no unpinned model identifier introduced by §5.

## 8. Edge cases

- **A repository with no entry points at all** — a library — produces an empty surface with
  `scan_status: no_applicable_targets`, distinctly from a run that failed to find the ones there are.
  A library is the case where an empty answer and a broken run look most alike.
- **A route the discovery pass invents.** Approval catches it; the cost is one reviewer's minute. The
  reverse — a real route the pass missed — is the dangerous one and is invisible at approval, which is
  why §2.4 forbids the surface from discounting anything.
- **A file changed by a formatter.** Incremental re-derivation is keyed on content, so a
  whitespace-only commit must not expire the approval on every entry point in the repository.
- **The bench corpus drifting into a real dependency.** A seeded vulnerability that Atlas resolves
  against a real advisory would be counted twice. Seeded issues are first-party code only.
- **A model deprecation.** A pinned identifier eventually retires; the lane must fail loudly with the
  identifier named, the way TheHub's model-inventory job already does, rather than silently falling
  back to a default.
- **Two validators confirming and one refuting a hypothesis that is genuinely wrong.** This will
  happen; §1's corpus is how it gets counted rather than argued about.

## 9. Dependencies

Spec 04 (§7's unbuilt acceptance criterion, which §1 finally makes testable), spec 05 (the lake table
conventions `review_surface` follows), specs 09 and 21 (Oracle's determinism guarantee, the
`capabilities_excluded_from_gates` knob, and the override pattern §2.2's approval mirrors), spec 11
(the Knowledge Store retrieval §4 spends), spec 15 and `docs/pipeline-standard.md` (the lane's shape),
spec 17 §5.3 (reachability's declared limit, which §2.4 does not lift), spec 18 §6 (the threat model §3
extends), and D-046, D-047, D-053, D-063, D-068, D-072 — each named where it binds.
