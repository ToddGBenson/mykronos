# Spec 09 — Oracle: Risk Decision Engine

**Status:** Approved for build — **NEW COMPONENT, does not exist anywhere yet.**
This is the most novel part of the system; build it carefully and
incrementally (see spec 13 roadmap).

**Depends on:** [05 — Data Lake](05-datalake.md), [06](06-aegis-integration.md),
[07](07-atlas-integration.md), [08](08-patchwork-integration.md),
[11 — Knowledge Store & RAG](11-knowledge-rag-learning.md)

---

## 1. Purpose

Oracle gathers every relevant data point about a repo, PR, or release from
the data lake and produces an **explainable, risk-based decision**: is this
safe to merge / release / promote, or does it need review or should it be
blocked? Oracle replaces ad hoc, tribal-knowledge risk judgment calls with a
consistent, auditable, continuously-improving decision process — but it is
advisory by default (see §6) and never silently overrides a human.

## 2. Decision types

| Decision type | Trigger | Scope of evaluation |
|---|---|---|
| **PR gate decision** | `pull_request` event (opened/synchronize) on a repo with Oracle enabled | All findings introduced/still-open on this PR's commit, Aegis insider-risk signal for this PR, any in-flight Patchwork remediation for these findings |
| **Release gate decision** | `release`/tag creation | All open findings for the repo above the configured severity floor, Atlas `SscsEvidence.trust_score`, unresolved insider-risk flags from recent PRs into this release |
| **Portfolio risk decision** | Scheduled (daily) per repo | Full current risk posture snapshot — feeds the Dashboard's portfolio view, not a gate on any specific action |

## 3. Data model — `RiskDecision` (data lake table)

| Field | Type | Notes |
|---|---|---|
| `decision_id` | UUID | PK |
| `repo_full_name` | string | |
| `decision_type` | enum | `pr_gate, release_gate, portfolio` |
| `pr_number` | int, nullable | |
| `release_tag` | string, nullable | |
| `commit_sha` | string | |
| `overall_risk_score` | int (0–100) | higher = riskier |
| `recommendation` | enum | `go, review_recommended, no_go` |
| `inputs_snapshot` | JSON | **every input value considered**, see §4 — this is the explainability record |
| `reasoning` | text | human-readable explanation generated from the inputs (template-based in v1, not free-form LLM narrative — see §5) |
| `policy_version` | string | version of the scoring policy applied (see §5, policies are versioned config, not hardcoded) |
| `evaluated_at` | datetime | |
| `human_override` | JSON, nullable | if a human overrides the recommendation, who/when/why (captured, feeds spec 11) |
| `github_check_run_id` | string, nullable | for `pr_gate`/`release_gate` types |

## 4. Inputs considered (v1)

Oracle reads from the data lake (never re-runs scans itself — it is a
**consumer**, not another scanner):

| Input | Source table | Weight category |
|---|---|---|
| Open findings by severity (SAST, DAST, Secrets, Containers, IaC, Cloud) | `Finding` (spec 05 §3) | Core |
| Insider-risk score for the PR's commit | `InsiderRiskSignal` (spec 06 §3) | Core |
| SSCS trust score / vulnerable dependency count | `SscsEvidence` (spec 07 §3) | Core |
| In-flight remediation status (is a fix PR already open for the blocking findings?) | `RemediationEvent` (spec 08 §4) | Modifier — lowers urgency, not the underlying score |
| Historical false-positive rate for this rule_id in this repo | Knowledge Store retro signals (spec 11 §3) | Modifier — dampens weight of rule_ids with a high human-dismissal rate |
| Time since finding was first seen (finding age) | `Finding.first_seen_at` | Modifier — aging unresolved criticals increase score over time |

## 5. Scoring policy (v1 — deterministic, versioned, explainable)

Oracle's policy is **not a black-box ML model in v1.** It is a versioned,
human-readable weighted rule set, stored as config
(`oracle-policy-v1.yaml`, checked into the Mykronos repo, editable by
security admins with review), of the shape:

```yaml
version: "1.0"
findings:
  # Contributions follow a curve, not a straight line. See below.
  curve: log2
  weights:
    critical: 40
    high: 20
    medium: 5
    low: 1
    info: 0
modifiers:
  insider_risk_score_multiplier: 0.3      # insider_risk_score(0-100) * 0.3 added
  sscs_trust_score_penalty: "100 - trust_score, capped at 20"
  remediation_in_flight_discount: 0.5      # multiplies the contribution of findings that already have an open fix PR
  finding_age_escalation:
    over_30_days_critical: +15
    over_90_days_high: +10
  false_positive_dampening:
    # If a rule_id's historical false-positive rate is at or above this
    # threshold, its severity weight is multiplied by (1 - dampening_factor).
    # The rate and its minimum sample size are defined in spec 11 §6.1 --
    # crucially, dampening requires min_observations *reasoned* dismissals,
    # so a single click cannot quieten a rule.
    threshold: 0.5
    dampening_factor: 0.5
    min_observations: 3
thresholds:
  no_go: 70          # overall_risk_score >= 70 => no_go
  review_recommended: 30   # >= 30 and < 70 => review_recommended
  # < 30 => go
scope:
  minimum_severity: low
  statuses_considered: [open]   # a human disposition is a decision already taken
  capabilities_excluded_from_gates: [network]   # spec 14 §7
```

The checked-in `oracle-policy-v1.yaml` is the source of truth; the block above
is a sketch of its shape. The engine refuses to start on an unknown curve, a
missing severity weight, or inverted thresholds — a policy that half-loads
would score every repo wrong and say nothing about it.

### Why a curve and not a sum

Each severity band contributes `weight × log2(1 + count)`, summed across
bands, then clamped to [0, 100].

An earlier draft of this spec summed linearly: 40 points per critical. Three
open criticals reached the clamp — and so did three hundred. Every vulnerable
repo therefore scored exactly 100, which meant the portfolio view could not
rank anything, the trend line was flat by construction, and `no_go` stopped
distinguishing "two aged criticals" from "a catastrophe". A deliberately
vulnerable demo application produces dozens of criticals and pins the ceiling
on its first scan.

Under the curve, criticals score 40 / 63 / 80 / 93 for 1 / 2 / 3 / 4. Strictly
increasing, so ranking is preserved, but flattening — the gap between "a few"
and "some" matters more than the gap between "many" and "very many", which is
how a person actually triages.

**The unclamped total is recorded** as
`inputs_snapshot.totals.raw_score`, so two repos that both *display* 100 can
still be ordered. Without it every repo past the ceiling ties and sorting by
risk silently stops working. The displayed score still clamps, and a genuinely
bad repo still shows 100 — that is correct, and the thresholds are doing their
job. What changed is that 100 is reached by repos that deserve it rather than
by any repo with three findings.

**Every term that
contributes to the final score must be listed in `inputs_snapshot`** with
its individual contribution value — this is what makes `reasoning` (§3)
generatable as a template ("Blocked because: 2 critical SAST findings open
for 45 days (+55), insider-risk score 82 (+24.6)...") rather than an opaque
LLM narrative. This is a deliberate v1 design choice: **explainability over
sophistication.** A future version may introduce a learned/ML scoring model
as an *additional* signal, but the deterministic policy must remain
available as a fallback/audit baseline.

## 6. Advisory vs. blocking behavior

- Oracle **always** writes a `RiskDecision` row and posts a GitHub Check
  Run summarizing it.
- Whether `no_go` actually fails the PR/release check (blocking) is a
  **per-repo configuration** (`CapabilityConfig` for `oracle`,
  `blocking: bool`, default `false`) — consistent with every other
  capability's blocking pattern (spec 04 §5, spec 06 §5).
- Even when `blocking: true`, a human with appropriate repo permissions can
  still merge past a failing check (standard GitHub behavior, unless the
  repo's own branch protection makes the check a hard requirement — that is
  the repo owner's choice, not Oracle's).
- Every override (merge-past-a-blocking-decision, or an admin explicitly
  marking a decision "overridden" in the dashboard) populates
  `RiskDecision.human_override` and is captured as a high-value retro
  signal (spec 11 §4) — these overrides are exactly the data that should
  most influence policy tuning over time.

## 7. API endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/oracle/evaluate` | Synchronously request a decision (called by the `oracle-gate.yml` workflow template at PR/release time); body: `repo_full_name`, `decision_type`, `commit_sha`/`pr_number`/`release_tag` |
| `GET` | `/api/oracle/decisions/{repo_full_name}` | List recent decisions for a repo (dashboard use) |
| `POST` | `/api/oracle/decisions/{id}/override` | Record a human override with a required free-text reason |
| `GET` | `/api/oracle/policy` | Return the currently active policy version + full weight config (transparency — any admin can see exactly how scores are computed) |

## 8. Workflow behavior

- Template: `workflow-templates/oracle-gate.yml.j2`, triggered on
  `pull_request` and `release` events (mirrors spec 04's trigger pattern).
- This workflow does **not** run a scan itself — it waits for the relevant
  scanner workflows to complete (via `workflow_run` dependency, same
  pattern as Patchwork, spec 08 §6) then calls `POST /api/oracle/evaluate`
  and posts the returned recommendation as a Check Run.

## 9. Acceptance criteria

- Every PR/release on a repo with Oracle enabled produces exactly one
  `RiskDecision` row with a fully populated `inputs_snapshot` (no input
  category silently omitted — if a category has no data, e.g. no Atlas
  evidence exists yet, it is present in the snapshot with a `null`/`not
  available` value, not absent).
- Given identical inputs (same findings, same insider-risk score, same
  trust score), the same policy version always produces the same
  `overall_risk_score` (deterministic — required for auditability and
  testability).
- `reasoning` text is generated purely from `inputs_snapshot` and the
  active policy — no hidden inputs.
- Overriding a decision requires a non-empty reason and is retrievable via
  `GET /api/oracle/decisions/{repo_full_name}`.

## 10. Edge cases

- Repo has Oracle enabled but no other capabilities enabled yet (nothing to
  evaluate) — Oracle still runs, produces a decision with
  `overall_risk_score = 0` and `recommendation = go`, and `inputs_snapshot`
  explicitly shows zero findings considered (not "no data" — a real,
  if unremarkable, decision).
- Policy file is updated mid-flight (new `policy_version`) — in-progress
  evaluations use whichever version was active when they started; new
  evaluations use the new version. Historical `RiskDecision` rows retain
  the `policy_version` they were computed with, so past decisions remain
  reproducible/auditable even after policy changes.
- Conflicting signals (e.g., low finding severity but very high
  insider-risk score) — both flow into the same weighted sum; there is no
  special-cased "any one signal above X auto-blocks" rule in v1, to keep
  the model simple and consistent. If experience shows a need for hard
  circuit-breakers (e.g., "insider risk >= 95 always blocks regardless of
  other factors"), that should be added explicitly to the policy schema in
  §5 as a reviewed change, not bolted on ad hoc.

## 11. Dependencies

- Spec 05 for all consumed tables and the query service.
- Spec 06/07/08 for the specific inputs from Aegis/Atlas/Patchwork.
- Spec 11 for the false-positive-rate dampening input and for capturing
  overrides as retro signals.
- Spec 10 (Dashboard) for surfacing decisions and the "why" behind them to
  humans.
