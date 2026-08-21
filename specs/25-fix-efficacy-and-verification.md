# Spec 25 — Fix Efficacy: Verification, Attribution, and Learning From a Rejected Fix

**Status:** Draft for review
**Depends on:** [08 — Patchwork Integration](08-patchwork-integration.md), [05 — Data Lake](05-datalake.md),
[11 — Knowledge Store & RAG](11-knowledge-rag-learning.md), [19 — Harness, Triage and Remediation Depth](19-harness-triage-and-remediation-depth.md),
[24 — Ownership and Deadlines](24-ownership-deadlines-and-acceptance-review.md)

---

## 0. What this spec is against

Patchwork opens draft pull requests, cannot merge them, and says what it failed to do as loudly as
what it did. All of that is right and none of it changes here.

What the platform has never been able to say is whether any of it worked.

- **`handle_pull_request` already observes the merge.** A closed PR records a `RemediationEvent`
  outcome of `merged` or `closed_unmerged`. The observation exists; the follow-through does not.
  Nothing re-scans the merged ref, nothing links the merge to the finding transitioning to `fixed`,
  and nothing records that this fixer, on this rule, in this repository, actually removed the
  vulnerability.
- **So `mean_time_to_fix` cannot be attributed.** It exists at repository level and cannot distinguish
  a finding closed by a Patchwork PR from one closed by an unrelated refactor or by a scanner
  changing its mind.
- **`closed_unmerged` is counted and never learned from.** The Remediation tab flags those PRs with a
  tooltip asking exactly the right question — *"worth asking whether the fixes were wrong or simply
  unwanted"* — and then nothing asks it. A dismissed finding teaches the Knowledge Store; a rejected
  fix teaches nothing, though both are a human verdict on machine output.
- **The largest class of findings has no fixer.** The deterministic fixers are dependency-shaped.
  SAST findings route to a groomed story, which is a routing decision presented as remediation.

This spec closes the first three. The fourth is named, scoped, and gated in §4 rather than built.

## 0a. Implementation status

| Item | Status |
|---|---|
| Verification scan on fix-PR merge (§1) | **Built** |
| Attribution: which change closed which finding (§2) | **Built** |
| Per-fixer efficacy, published (§3) | Not started |
| Rejected-fix reasons into the Knowledge Store (§3.3) | Not started |
| A fixer for SAST-shaped findings (§4) | Deliberately gated — see §4 |

## 1. Verification

### 1.1 Current state

A fix PR merges. The webhook records the outcome. The next scheduled scan may or may not run against
that ref, on its own cadence, and when the finding eventually resolves nothing connects the two
events. In the window between merge and next scan — routinely days — the platform shows a finding
that is already fixed and a PR that already merged, with no relationship between them.

### 1.2 What ships

- On `pull_request.closed` with `merged: true` **for a PR this platform opened** (the
  `RemediationEvent` already identifies those; an unrelated PR merging triggers nothing), dispatch a
  scan of the merge commit for the capability that produced the finding — and only that capability.
  A full fifteen-check re-run on every fix merge is a cost this platform explicitly cannot afford at
  the cadence merges happen.
- Dispatch reuses the existing paths: `ci.trigger_job` for Concourse-scanned repositories,
  `GitHubClient.dispatch_workflow` for Actions-scanned ones. Both already exist and are already used
  by the "scan now" button.
- The dispatched run is tagged `triggered_by: verification` on its `ScanRun`, so verification traffic
  is distinguishable from scheduled traffic in scan-health and in any future cost accounting.

### 1.3 What does not ship

No blocking. The merge is not held pending verification — this platform has no merge authority and
should not acquire one by making merges wait for it. Verification is an observation after the fact.

No verification of a PR a person edited beyond recognition. `human_edited` is already tracked; the
scan still runs, and §2 records that the fix was edited, because "our fix worked after a human
rewrote it" is a materially different claim from "our fix worked".

## 2. Attribution

### 2.1 What ships

`RemediationEvent` gains four fields:

- **`verification_scan_run_id`** — the run dispatched in §1.
- **`verification_outcome`** — `verified_fixed` | `still_open` | `not_scanned` | `inconclusive`.
- **`verified_at`** — when the verifying run reported.
- **`time_to_verified_seconds`** — merge to verification, the only fix-latency number in this
  platform that will be attributable to a route.

`verified_fixed` requires the specific `finding_id` to be absent from the verifying run. Not "the
count went down" — the identity has to be gone, which is precisely what the code-anchored
fingerprint (D-001) exists to make possible.

**Read from the run, not from the finding's status** — a correction to this section's first draft,
made while building it. A finding is not marked `fixed` until it has been absent from *two*
consecutive scans (`reconcile.REQUIRED_ABSENCES`): flap protection, which exists to stop
`resolved_at` churning and answers a different question from this one. Waiting on it would leave a
working fix unverified until an unrelated second scan happened to run. So the evidence is the
verifying run itself — it succeeded, and it either re-reported the finding
(`last_seen_scan_run_id` points at it) or it did not. The finding's status stays the platform's own
conservative business; this column reports what one scan of one commit observed.

**Only a `success` run gives a verdict.** A `partial_failure` may not have scanned the file the
finding lives in, so an absence proves nothing there.

`inconclusive` is a real outcome and is reported as one: the verifying run failed or partly failed,
or returned `no_applicable_targets`, or the finding is no longer in the lake at all.
Folding any of those into `still_open` would slander a fix that may well have worked; folding them
into `verified_fixed` would flatter one that may not have.

### 2.2 What does not ship

Attribution for findings closed outside a Patchwork PR. When a finding transitions to `fixed` with no
verification event pointing at it, it stays unattributed and is reported as such. The platform is not
going to guess which of the week's forty commits removed a vulnerability; a "probable cause" column
would be a dashboard-only number of the kind spec 10 §6 forbids.

## 3. Efficacy, published

### 3.1 What ships

A per-fixer scoreboard, on the Remediation tab and portfolio-wide on `/remediation`:

| Column | Meaning |
|---|---|
| Attempts | fixes generated |
| PRs opened | reached a draft PR |
| Merged | a person merged it |
| Verified | the finding was gone on re-scan |
| Rejected | closed unmerged |
| Median time to verified | merge → verification |

Broken down by fixer and by `rule_id`, because those are the two axes a person can act on: a fixer
that works everywhere except one rule is a different problem from a fixer nobody trusts.

### 3.2 Why this matters more than it looks

Today a fixer that opens pull requests nobody merges is indistinguishable from one that silently
removes real risk every week. Both show as `pr_opened` rows. The first is a machine generating review
load, and the review load is paid by exactly the people this platform is meant to help.

### 3.3 Learning from a rejected fix

- Closing a Patchwork PR unmerged prompts for a one-line reason — via the PR itself (a comment
  template the platform posts when it opens the draft, which the closer fills in), not via a form in
  this dashboard nobody will visit at that moment.
- The reason is captured into the Knowledge Store with a new source type, `rejected_fix`, alongside
  the existing dismissal capture. Two codes matter and are offered explicitly: `fix_was_wrong` and
  `fix_was_unwanted`. They pull in opposite directions — the first should dampen the *fixer*, the
  second should not dampen anything at all, because a correct fix nobody wanted is a scheduling
  disagreement, not a defect.
- Dampening applies to the fixer's confidence for that rule, never to the finding. A rejected fix
  says nothing about whether the vulnerability is real, and letting it lower a finding's standing
  would let "we did not want this patch" read as "this was a false positive".

## 4. A fixer for SAST-shaped findings — named, scoped, gated

The review that produced this spec identified the absence of a code fixer as the largest single gap
in remediation, and this section deliberately does not close it.

**The gate.** Before an LLM-assisted code fixer is written: the detector benchmark in spec 23 §1
exists and is green; §3's efficacy scoreboard has at least one full quarter of data for the
deterministic fixers, so there is a baseline to be measured against; and the egress rules in spec 23
§2.3 apply unchanged.

**What it would be, when it is.** A draft PR under the same guarantee — the GitHub client exposes no
merge operation, and this does not add one — carrying the diff, the rule it addresses, and the model
and prompt-pack version that produced it (spec 23 §4). Verified by §1 like any other fix, and
scored by §3 beside the deterministic fixers rather than in a category of its own. If it does not
beat them on verified-fix rate, the honest outcome is a status row saying so.

**Why gated rather than deferred silently.** A generated fix that is measured is a capability. One
that is not is a liability with a pull-request queue, and this platform has a bad-week precedent
(D-053) for what happens to expensive capabilities nobody sized first.

## 5. Acceptance criteria

- Merging a Patchwork PR dispatches exactly one scan, for exactly the capability that produced the
  finding, tagged `triggered_by: verification`.
- Merging a pull request this platform did not open dispatches nothing.
- A finding that is gone from the verifying run records `verified_fixed` against the specific
  `finding_id`, not against a count.
- A verifying run that fails records `inconclusive`, and `inconclusive` never appears inside a
  verified-fix rate as either a success or a failure.
- The efficacy scoreboard reports per fixer and per `rule_id`, and a fixer with zero verified fixes
  and twenty opened PRs is visible as such on one screen.
- Closing a Patchwork PR unmerged with `fix_was_wrong` dampens that fixer's confidence for that rule;
  closing it with `fix_was_unwanted` dampens nothing.
- No path in this spec changes a `Finding.status` directly. Status still changes only through
  ingestion or a human disposition.

## 6. Edge cases

- **A fix PR that closes several findings.** One verification scan, several attributions — each
  finding evaluated on its own identity, and a partial result (three of four gone) recorded as three
  `verified_fixed` and one `still_open`, never as one aggregate verdict.
- **A merge into a branch that is not scanned.** `not_scanned`, said plainly. A fix merged to a
  feature branch nobody scans has not been verified and must not read as if it had.
- **A finding that returns two scans later.** The verification record stands — it was fixed and it
  regressed. This is the exact case regression coverage (spec 31) exists to catch, and the two specs
  should share the finding's history rather than each keeping their own.
- **A rebase or squash that changes the merge commit.** Verification scans the ref the webhook
  reports as merged, whatever its shape.
- **A repository where the verification dispatch is rate-limited or the pipeline is paused.**
  `not_scanned`, and the event is retried once on the next scheduled run for that capability rather
  than queued indefinitely.

## 7. Dependencies

Spec 08 (Patchwork's pipeline, `RemediationEvent`, and the no-merge guarantee this preserves), spec
05 §5 (code-anchored identity, without which `verified_fixed` could not be asserted about a specific
finding), spec 11 §4 (the capture path §3.3 extends with a second source type), spec 19 §4 (the
auto-routing that decides which findings reach a fixer at all), spec 23 §1 and §2.3 (the benchmark
and egress rules gating §4), spec 24 (ownership, so a rejected fix has somebody to go back to).
