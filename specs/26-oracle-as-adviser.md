# Spec 26 — Oracle as Adviser: Path to Green, Terms That Reward, and a Shadow Report

**Status:** Draft for review
**Depends on:** [09 — Oracle](09-oracle-risk-decision-engine.md), [21 — Oracle Depth & Risk Profile](21-oracle-depth-and-risk-profile.md),
[10 — JDED Dashboard](10-jded-dashboard.md), [24 — Ownership and Deadlines](24-ownership-deadlines-and-acceptance-review.md),
[25 — Fix Efficacy](25-fix-efficacy-and-verification.md), [31 — Regression Coverage](31-regression-coverage.md)

---

## 0. What this spec is against

Oracle is the most rigorously built component in the platform: a versioned policy, a tested band
curve, `available` on every input category, an override that demands a reason, policy history derived
from the decisions themselves, and a gate that blocks on what a commit introduced rather than on a
backlog it cannot control.

It is also, still, only a scorer. Three consequences:

1. **Nothing says what would make this repository go.** The engine holds every term, its weight, and
   the exact distance to the threshold. It reports a verdict and a breakdown, and leaves the reader
   to solve the inverse by hand — which is the first question anybody asks on seeing `no_go`.
2. **Only one term can lower a score.** Nine modifiers; the import-reachability discount (D-072) is
   the sole negative, capped, and Python-only. Everything a team could *do* — fix fast, keep findings
   inside their targets, add regression tests, tighten review governance — is unrepresentable. A model
   that can only punish gets argued with rather than acted on.
3. **Blocking is opt-in and nothing shows what turning it on would cost.** The maturity model
   deliberately rewards *earning* the switch rather than flipping it, and then the evidence needed to
   decide is nowhere on the page. D-083 records the consequence in the other direction: TheHub's gate
   was switched off by an operator because its real cost was discovered after enabling.

## 0a. Implementation status

| Item | Status |
|---|---|
| Path to green: the minimal action set (§1) | Not started |
| Terms that reward, capped and evidence-backed (§2) | Not started |
| 30-day shadow report of what the gate would have refused (§3) | Not started |
| Forecast: when this repository turns no-go on ageing alone (§4) | Not started |

## 1. Path to green

### 1.1 Current state

`RiskDecision` carries `score_terms` — every contributing term with its value and its reasoning
sentence — and the threshold it was compared against. The Risk Decision tab renders that breakdown
faithfully. Neither says which findings to close.

### 1.2 What ships

A new field on the decision, computed by the same engine pass, in the same pure function:
`path_to_green` — an ordered list of actions, each naming the finding or combination, the points it
carries, and the band it would move the repository into.

The computation is a bounded search, not an optimiser: for each open finding, the engine already
knows the points it contributes (the band curve is `weight × log2(1 + count)`, so removing one
finding from a band has a computable effect). Sort by points removed per action, take the prefix that
crosses each threshold, stop.

```
This repository is no_go at 84. Threshold for review_recommended is 70; for go, 30.

  1.  CVE-2026-1337 in requests (critical, KEV)      -9   → 75
  2.  hardcoded-credential × 3 occurrences (high)    -6   → 69   review_recommended
  3.  exploitable-dependency-reachable (combination) -18  → 51
  4.  sql-injection in handlers.py (high)            -6   → 45
      ... 3 more to reach go
```

**Two rules keep this honest.**

- **It names actions, not outcomes.** Each row is "close this finding", never "reduce criticals by
  two" — an instruction the reader cannot act on directly is the kind of number this platform throws
  out.
- **It is capped at what actually crosses a threshold**, plus the count of what remains. A list of
  forty items ordered by weight is the findings tab again; the value here is the prefix.

### 1.3 What does not ship

No effort estimate inside Oracle. Whether a fix takes ten minutes or two days is a Patchwork and
worklist question (spec 27 §2), and the risk engine has no business pretending to know. The worklist
consumes `path_to_green` and adds effort; Oracle stays a pure function of the snapshot.

## 2. Terms that reward

### 2.1 Current state

The nine modifiers are insider risk, SSCS trust, remediation in flight, finding age, false-positive
dampening, risk profile, blast radius, reachability, and unfixable dampening. Reachability discounts;
unfixable dampening reduces the weight of what cannot be fixed. Neither is a reward for having done
something — the first is a fact about code structure, the second is a concession.

### 2.2 What ships

Three additive negative terms, each gated on evidence that a *different* spec produces, so none of
them can be satisfied by configuration:

```yaml
posture_credits:              # all capped; all default to a zero cap until their source ships
  regression_coverage:
    points_per_covered_finding: 0.5
    cap: 8                    # needs spec 31 — a finding↔test link
  verified_fix_rate:
    points_at_full_rate: 6    # needs spec 25 §3 — attempts, merges, verified
    minimum_sample: 10        # below this the rate is noise and the term is `available: False`
  within_target:
    points_at_full_compliance: 6   # needs spec 24 §2 — due_at on findings
```

**Every one of them requires something to have happened**, which is the same rule
`maturity-model-v1.yaml` states for its criteria and for the same reason: the fastest route to a good
score must never be a switch.

**Capped, and small relative to the finding weights.** A repository cannot test its way out of an
exploited critical. The credits are worth roughly one band of a medium-severity backlog in total —
enough that a quarter of real work moves the number, not enough to buy a verdict.

**`available: False` until the source exists**, with a reason, per spec 09 §9. A platform where the
credits silently contribute zero is one where teams conclude the model is rigged.

### 2.3 What does not ship

No credit for enabling a capability, installing a workflow, or turning on the gate. Those are the
switch-flipping incentives the maturity model was written to avoid, and they would be trivially
gamed.

No multiplicative terms. The curve's determinism guarantee (spec 09 §9) is worth more than the
expressiveness, and every term here is additive like the ones already there.

## 3. The shadow report

### 3.1 Current state

Gate outcomes are recorded — `_record_gate_outcome` on the webhook path, `gate_outcome` on the
decision. Nothing aggregates them into the question a team actually has: *if we turned blocking on,
what would have happened last month?*

### 3.2 What ships

A panel on the Risk Decision tab: over the last 30 days, every commit the gate would have refused,
with its date, its author-facing reason, and what it introduced. Plus the headline the decision turns
on — *"blocking would have refused 3 of 47 commits; all 3 introduced a new critical"* versus
*"blocking would have refused 31 of 47"*, which are opposite answers and currently look identical
from here.

It is a query over `risk_decisions` rows that already exist. No new recording, no new evaluation.

### 3.3 Why on this tab and not in a report somewhere

The switch lives here. Evidence that has to be fetched from elsewhere is evidence nobody fetches, and
the decision this informs is the single highest-consequence configuration change in the platform.

## 4. Forecast

`finding_age` escalates continuously, so a repository with a static backlog crosses a threshold on a
date that is already computable. The tab states it: *"with no changes, this repository reaches no_go
in 12 days as three high findings cross 90 days."*

Deliberately one sentence and deliberately not a chart. It is a projection of a known curve over
known ages — not a model, and it must not acquire the visual authority of one.

## 5. Acceptance criteria

- A `no_go` repository's decision carries a `path_to_green` whose listed actions, if all applied,
  demonstrably move the recomputed score below the threshold — asserted by a test that applies them
  to the snapshot and re-evaluates.
- `path_to_green` is empty and says so for a repository already at `go`.
- Every posture credit reports `available: False` with a reason until the spec that produces its
  evidence has shipped, and no credit can be earned by changing configuration alone.
- Total posture credit is capped such that a repository with one open, KEV-listed critical cannot
  reach `go` on credits.
- The shadow report's refused-commit count for a 30-day window equals the count of `introduced_blocking`
  decisions in that window — the same number, from the same rows.
- Adding the credits bumps the policy version, and the existing band-curve tests pass unchanged: the
  curve is not restructured, only extended (spec 09 §9).

## 6. Edge cases

- **A repository whose score is above the threshold entirely on one combination.** `path_to_green` has
  one row. Correct, and worth seeing — it is the clearest possible instruction.
- **Two findings whose removal is not additive** (both in the same band, where the log2 curve means
  removing one is worth more than removing the second). The path must recompute after each step
  rather than summing independent deltas, or the arithmetic it publishes will not match what happens.
- **A repository with fewer than `minimum_sample` fix attempts.** `verified_fix_rate` is
  `available: False`, not zero — a team that has fixed three things well has not earned a rate, and
  must not be scored as though it failed one.
- **A shadow report window with no commits.** Says "no commits in this window", never "0 would have
  been refused", which reads as a safe gate rather than an untested one.
- **An override in the window.** Counted and shown separately: a commit that a human let through is
  not evidence about what the gate would do unattended.

## 7. Dependencies

Spec 09 (the engine, the curve, the determinism guarantee every term here respects, and §9's rule for
unwired categories), spec 21 (the risk profile, the override, and the term-breakdown UI these render
into), spec 24 §2 (`due_at`, without which `within_target` cannot be computed), spec 25 §3 (the
efficacy numbers behind `verified_fix_rate`), spec 31 (the finding↔test link behind
`regression_coverage`), `maturity-model-v1.yaml` (the evidence-not-switches rule §2.2 inherits).
