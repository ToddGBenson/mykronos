## D-175 — Triage, correlation and remediation upgrade deterministically first; a model only proposes, in shadow, after the corpus can grade it

**2026-11-04.** **Status:** Decided 2026-10-12 (operator, option A of TheHub #60736); recorded here, children 1 and 3 to 6 implemented
**Story:** TheHub #60736 · Refs D-032, D-096, D-162, D-167, D-168, D-169, D-173, [spec 19](../../specs/19-harness-triage-and-remediation-depth.md), [spec 23 §1](../../specs/23-agentic-source-code-review.md), spec 28, spec 36

**The rule.** A model proposes; something deterministic decides. Every
upgrade to triage, toxic combinations and remediation is a deterministic
step first. A model is used only where those steps cannot settle a finding,
only once the benchmark corpus can grade it, and only as a proposal.

**The options weighed.** (A) a deterministic-first ladder: get the corpus
running, then distribution evidence, taint reachability and deterministic
fixes, with model use only once the corpus can grade it. (B) model-first in
shadow mode, with the deterministic work in parallel. (C) remediation-first:
tests on pull requests, then fixers. **A was chosen.** B produces verdicts
nobody can grade, because without the corpus there is no recall figure to
hold them to, and it adds a model call path that reads private code. C
merges fixes but does not reduce the triage load, which is the problem.

**The order.** Each child is a TheHub story tagged `repo:mykronos`.

1. **#60742 Run the spec 23 §1 corpus.** The `bench` Concourse lane and
   `GET /api/bench/runs` are built (#1107). Status 2026-11-04: **not
   running**. The `mykronos-bench` repository is not created or onboarded,
   so no graded run exists and the lane is red by design (spec 23 §1.6).
   That step is the operator's.
2. **#60743 The KPI on the dashboard**, with history and the recall guard.
   Not built. It is unblocked now that #1107 has merged.
3. **#60744 Distribution evidence for OS packages.** Built as the Debian
   security tracker (#1109): `not-affected`, `no-dsa` and `will-not-fix`
   label a finding `likely_false_positive` with the tracker URL cited, and
   never close it. A stale or unreachable tracker changes nothing. A VEX
   statement stays a person's record (D-169).
4. **#60745 Semgrep taint mode for Python reachability** (#1111). The import
   graph stays the fallback where no taint spec exists.
5. **#60746 Deterministic remediation** (#1112): Semgrep `fix:` rules, and
   digest-pinned base-image bumps checked against the registry, each as a
   pull request whose branch is rescanned.
6. **#60747 Backend tests on pull requests** (`backend-tests`, #808, D-162).
   Status: runs on every pull request and is required on `main` since
   2026-10-21. This is the prerequisite for any fix a model writes.
7. **#60748 Shadow model triage.** A per-finding code read, proposed under
   the existing `finding_disposition` duty in reviewer shadow mode. Not
   started. Its hard prerequisites are a graded corpus run (1) and the KPI
   baseline (2).
8. **#60749 Entry-point-scoped correlation and an attack graph.** Planning
   only. It is blocked on the spec 23 §2 entry-point inventory and on
   network and cloud data the lake does not hold.

**Departures from the story's order, with reasons.**
- **3 to 6 were built before 1 produced a graded run and before 2 existed.**
  None of them is a model, and each one ships with its own deterministic
  tests. The corpus is needed to *grade* triage changes, and it waits on an
  operator step. Holding deterministic work behind that step would have
  stopped the ladder on a step nobody in the build lane can take. The
  corpus still grades 3 and 4 once it runs (spec 19 §2.1.1).
- **6 was built first (merged 2026-10-13)** because D-162 needed it for every pull
  request, not only for this ladder.
- **The KPI baseline was taken late**, after 3 to 5 merged. The figure below
  still describes the classifier before them: the build that served it was
  deployed before #1109, #1111 and #1112.
- **7 does not move.** Model triage still waits on both prerequisites. No
  departure is granted for the model step.

**Every model use is a proposal.** Each proposed model use names the
`finding_disposition` approval duty, starts in reviewer shadow mode, and is
recorded the way D-173 §3 records model proposals. It **never changes a
finding** on its own, never raises an approval by itself, and never fires a
toxic combination that feeds the Oracle. A model may propose a new
`CombinationRule`, but only as a reviewed pull request. A move to live mode
is a later decision, taken on graded numbers. Nothing here grants it.

**A model-written fix stays out.** D-096 withdrew the LLM fix generator, and
D-032 makes deterministic fixers the product. A fix written by a model is
conditioned on a new decision amending D-096. That decision must answer
D-096's open questions (the contract, failure behaviour, cost ceiling, and
how a reviewer tells the fix from a deterministic one), and it needs
`backend-tests` on the fix's pull request and independent review before any
merge.

**Not re-proposed, because they are built.** EPSS and KEV ordering (the
`epss` rank weight, the KEV-first threat-intel view, the triage queue's
`min_epss` and `kev_only`, and the KEV floor on toxic combinations). CWE
normalisation of SARIF results (spec 28).

**The KPI.** The share of open findings whose triage verdict is
`needs_human_judgment`, measured weekly across active, non-synthetic
repositories. **Guard:** true-positive recall on the benchmark corpus must
not fall. A drop in the share while recall falls is a regression, not an
improvement.

**Baseline:** 173 of 208 open findings (83.2%) on 2026-11-04 at 05:25 UTC
were `needs_human_judgment`. It came from `GET /api/dashboard/triage`
(active repositories, snoozed findings included) on the build deployed then,
which predates children 3 to 5. Of the rest, 21 were `true_positive`, 14
`likely_false_positive` and none `toxic_combination`. No synthetic repository
was onboarded, so none is in the figure. **The recall half of the baseline is
not measured yet**: it is the first graded run of child 1. #60743 records
the weekly series from the day it ships, and it records the recall figure
beside it.
