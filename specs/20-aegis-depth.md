# Spec 20 — Aegis Depth: The AI-Authorship Classifier, `privilege_adjacent`, and UI Gaps

**Status:** Draft for review
**Depends on:** [06 — Aegis Integration](06-aegis-integration.md), [09 — Oracle](09-oracle-risk-decision-engine.md)

---

## 0. What this spec is against

Spec 06 shipped seven of nine spec'd signals as real, working collectors; the other two —
AI-authorship and `privilege_adjacent` — exist as named, weighted, capped slots in the scoring model
with nothing behind them. Both are honestly `null`/absent rather than faked, which is correct and not
what this spec changes. What this spec does is build the two real, working things spec 06 already
described but never finished, plus close two UI/config gaps a full read of the shipped code turned up.

This is not a reopening of spec 06 §9's purpose limitation — no per-author aggregation, no relationship
modeling, no trend view. Every constraint that section states stays exactly as strict.

## 0a. Implementation status

| Item | Status |
|---|---|
| AI-authorship classifier: workflow-side call, opt-in | Planned |
| `privilege_adjacent`: a cheap, honest first signal (org-role proxy) | Built (D-064) |
| UI: complete `SIGNAL_LABEL` map | Built |
| Config: `blocking` visibility check | Built — confirmed real, now stated per repo |

## 1. The AI-authorship classifier

### 1.1 Current state

`ai_authorship_flag` is fully handled server-side — three-state null logic, a cap in `SIGNAL_CAP`, a
dead error branch for "configured but unreachable" that nothing ever exercises. `ai_classifier_url`
is a validated config field. **No code anywhere calls it.** The workflow template says so explicitly
("is not invoked here at all"). This is spec 06 §5's one deliberately-opt-in exception to "nothing
leaves the runner except conclusions" — and it has never been wired, not even the plumbing to call it.

### 1.2 What ships

A new step in `workflow-templates/aegis.yml.j2`, gated entirely on `ai_classifier_url` being
configured (unset — the default — means this step does not run at all, not that it runs and no-ops):

- POSTs the PR's diff (title, description, changed-file diff) to the configured gateway URL, with a
  short timeout and a single retry — a slow or down classifier degrades to `ai_authorship_flag: null`
  ("configured but unreachable" is the branch this finally exercises), never blocks the workflow.
- The response is a single boolean plus a confidence float, nothing else accepted — no free-form text
  from the classifier reaches the platform, honoring spec 06 §5's "nothing leaves the runner except
  conclusions" for what comes *back* as much as what goes out.
- No credential for the gateway is embedded in the workflow template; it is read from a repository or
  org secret the same way every other capability's write-path credential already is (spec 12 §2).

### 1.3 What does not ship

The classifier itself. This spec wires the *call*; which model or vendor sits behind
`ai_classifier_url` is an operational decision for whoever configures it, explicitly out of scope —
matching how `fix_generator_url` (Patchwork) has never dictated what's behind it either.

## 2. `privilege_adjacent` — a cheap, honest first signal

### 2.1 Current state

Capped and named (`aegis.py:45`, weight 30.0) with zero collector logic. Deferred pending "an event
feed" — full org-chart/HR integration is real, separate work this spec does not attempt.

### 2.2 What ships

A narrower signal that needs no external feed: **is the PR's author a member of the repository's
GitHub org with `admin` or `maintain` role** — data the GitHub App already has read access to
(`repo:admin` scope, already granted for every other Aegis operation). Not a full privilege model —
an org-admin approving their own sensitive change is a real, cheap-to-detect proxy for "this person
already has more access than the review process assumes," which is what the signal's cap (30.0,
tied with `self_approval` as the two heaviest — spec 06 §2a's own reasoning: unambiguous when it
fires) already implies it should mean.

- Collector added to `aegis_signals.py`, following the existing shape exactly: a pure function
  returning `{key: "privilege_adjacent", score, rationale}`, called from the runner, scored
  server-side (D-024's split, unchanged).
- Fires only when the PR author's org role is fetchable and is `admin`/`maintain` — silently absent
  (not a zero-score entry, an *absent* one) when the GitHub App cannot resolve the author's org
  membership (e.g., an external contributor, or a permissions gap) — matching every other signal's
  "absent means not evaluated, not evaluated-and-clean" convention.

### 2.3 What does not ship

Any HR/personnel-system integration, any concept of "privileged" beyond GitHub's own org roles. If a
richer signal (title, department, access-review status) is wanted later, it is a new, separately
justified data source — this spec closes the gap with what's already available, not by opening a new
integration surface.

## 3. UI and config gaps

### 3.1 Complete the signal-label map

`frontend/components/insider-risk.tsx`'s `SIGNAL_LABEL` covers 5 of 9 signal keys; the four
review-integrity signals (`self_approval`, `sole_approver`, `fast_approval`, `unverified_ai`) fall
through to raw snake_case text. Add the missing four entries — a labeling gap, not a logic change.

### 3.2 Confirm `blocking` is real

Aegis's Check Run is advisory unless `blocking=true` is configured per repo (spec 06 §7). Confirm
`AegisConfig` actually carries this field with the same shape `AtlasConfig`/other capability configs
use, and that the governance note in the UI (`GovernanceNote`, `insider-risk.tsx`) states plainly
whether this repo's Aegis is blocking or advisory — today the note is generic; a repo-specific line
("this repository's Check Run is advisory" / "blocking") closes a small but real gap between what an
admin configured and what a reviewer reading the PR sees.

## 4. Acceptance criteria

- With no `ai_classifier_url` configured (the default), Aegis behaves identically to today — no new
  network call, `ai_authorship_flag` stays `null` for the "not configured" reason.
- With `ai_classifier_url` configured and reachable, a PR disclosing AI authorship in its description
  gets a real `ai_authorship_flag` from the classifier, not from keyword matching.
- With `ai_classifier_url` configured and unreachable, the workflow step fails soft — Aegis still
  posts its Check Run with every other signal, `ai_authorship_flag: null` for the "unreachable" reason
  (the previously-dead branch), not a workflow failure.
- A PR opened by a repository org admin/maintainer against their own change shows a non-zero
  `privilege_adjacent` contribution with a rationale naming their org role.
- A PR opened by a non-org-member (or when org-role lookup fails) shows `privilege_adjacent` absent,
  not scored zero.
- Every one of the nine signal keys renders a readable label in the Findings-adjacent insider-risk UI,
  not raw JSON keys.

## 5. Edge cases

- A classifier response that fails the boolean+confidence schema check is treated identically to
  "unreachable" — never partially trusted.
- An org-role lookup that succeeds but returns a role outside `{admin, maintain}` (e.g. `write`,
  `triage`, `read`) does not fire `privilege_adjacent` — the signal is specifically about elevated
  access, not any org membership.
- Revoking `ai_classifier_url` mid-flight (unset after being set) reverts immediately to the
  no-call, always-null-for-"not configured" behavior — no cached "last known" classification persists.

## 6. Dependencies

Spec 06 (Aegis — every signal, the scoring model, the null-vs-zero convention this spec extends
without altering), spec 09 (Oracle — how `insider_risk` is consumed, unaffected by this spec since no
new category is added, only two existing ones filled in), spec 12 §2 (credential handling for the
classifier gateway secret).
