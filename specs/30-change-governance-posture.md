# Spec 30 — Change-Governance Posture: From Odd Changes to the Controls That Would Catch One

**Status:** Draft for review
**Depends on:** [06 — Aegis Integration](06-aegis-integration.md), [20 — Aegis Depth](20-aegis-depth.md),
[02 — Onboarding & GitHub App](02-onboarding-and-github-app.md), [21 — Oracle Depth & Risk Profile](21-oracle-depth-and-risk-profile.md)

---

## 0. What this spec is against

Aegis is the most carefully-reasoned component in the platform. It scores changes, refuses to score
people, requires a written rationale on every sub-signal, treats a low-confidence classifier answer as
null rather than as a hedge, and states per repository whether it blocks. Spec 06 §9 draws a boundary
around what may be said about a person and everything downstream respects it. **None of that changes
here, and this spec inherits all of it.**

The gap is one step further on. Nine signals — sensitive path, first contribution, unusual size for
this author, AI authorship, privilege-adjacent change, self-approval, sole approver, approval faster
than the diff could be read, AI-authored without stated verification — and every one describes a
pull request *after the fact*.

None describes whether a bad change could get in at all.

> `self_approval` fires when somebody approved their own change. It is a symptom.
> **"Self-approval is permitted on the default branch"** is the cause, and it is invisible from here.

Branch protection, required reviewers, CODEOWNERS coverage, signed-commit enforcement, push
protection, admin bypasses — the controls that make the difference between a repository where a
malicious change is hard and one where it is trivial — are not read, not scored, and not shown. The
GitHub App is installed and the client has no operation that reads any of them.

The second gap follows from the first: **the signal reaches Oracle only as risk.** A repository with
exemplary review governance earns nothing for it, which is the same asymmetry spec 26 §2 addresses
across the scoring model generally.

## 0a. Implementation status

| Item | Status |
|---|---|
| Read branch protection / rulesets through the App (§1) | **Built** — two operations, and `administration: read` stays *optional*; see §1.4 |
| The control panel on the Insider Threat tab (§2) | **Built** |
| Repository-level governance aggregate (§3) | **Built** — `governance-policy-v1.yaml` |
| Into Oracle through the risk profile, not the finding score (§4) | **Built** — as a penalty only, and shipped dark; see §4.1 |

## 1. Reading the controls

### 1.1 Current state

`GitHubClient`'s protocol carries twenty-odd operations — repository read, file read, branches,
commits, pull requests, checks, secrets, check runs, workflow dispatch, issues. There is deliberately
no merge operation (spec 08's guarantee). There is also no read of branch protection, rulesets,
required status checks, or organisation policy.

### 1.2 What ships

Four read-only additions to the client, all against endpoints the existing installation permissions
cover or that need only a documented, additive permission bump recorded in spec 02:

- `get_branch_protection(repo, branch)` — required reviews, required approving count, dismiss stale
  reviews, required status checks, enforce-for-admins, linear history, force-push and deletion
  settings.
- `get_rulesets(repo)` — the newer ruleset model, which increasingly supersedes branch protection and
  which a repository may use instead.
- `get_codeowners_coverage(repo)` — derived, not fetched: read `CODEOWNERS` (already needed by spec
  24 §1) and compute the fraction of source paths it covers. Uncovered paths are where review routing
  silently does not happen.
- `list_admin_bypasses(repo, since)` — from the audit-log or bypass-request endpoints where the plan
  and permissions allow, and **absent rather than zero** where they do not.

Sampled on a schedule and on onboarding, stored in the operational store as current state with a
`read_at`. This is configuration, not scan output: it has no time series worth keeping in the lake,
and what matters is what is true now.

### 1.3 What does not ship

No writes. This platform does not turn on branch protection for anybody. Every control here is
observed and reported, and changing one is an action the repository's owners take in GitHub, where the
audit trail for it belongs.

### 1.4 Corrected while building

**`administration: read` is optional, not a required-permission bump.** §1.2 anticipated "a
documented, additive permission bump recorded in spec 02". Making it *required* would fail the spec 02
§8 permission smoke test for **every installation that already exists**, turning an additive panel
into a breaking change across the whole estate — to read settings that are useful and are necessary
for nothing else the platform does. It lives in a separate `OPTIONAL_PERMISSIONS` set, and an App
without it reports every control as `unknown` with the reason and the permission named. That is §2's
own rule applied to itself: a permissions gap is not a security failure.

**Two operations, not four.** `get_branch_protection` and `get_rulesets` ship. CODEOWNERS coverage is
derived from a file the client could already read (spec 24 §1), so it needed no new operation.
`list_admin_bypasses` does **not** ship: the endpoints behind it are plan-gated, and an operation that
returns "absent" for most installations would be a permanently empty column. `enforced_for_admins`
answers the question that matters — whether the rules bind administrators at all — and it is
weighted accordingly.

**Rulesets merge as the strongest wins, never as the newest wins.** A repository can use branch
protection, rulesets, both, or neither. Reading only the older model would report a modern,
well-governed repository as wide open; taking the newer one alone would under-report one governed
twice over. `source` says which model produced the answer. Only `active` rulesets count — an
`evaluate`-mode ruleset is a dry run that blocks nothing, and counting it would credit a repository
for a control that is switched off.

**A single required approval is `partial`, not `on`.** Four states rather than two, because that
configuration is exactly the one `self_approval` and `sole_approver` fire under, and calling it "on"
would put a repository one rubber stamp from a bad merge level with one that requires two people.

## 2. The control panel

A panel at the top of the Insider Threat tab — above the signals, because it explains them:

| Control | State |
|---|---|
| Pull request required on default branch | ✅ required |
| Approving reviews required | ⚠️ 1 (self-approval possible where CODEOWNERS is silent) |
| Stale reviews dismissed on push | ❌ off |
| CODEOWNERS coverage | ⚠️ 62% of source paths |
| Enforced for admins | ❌ off — 3 bypasses in 90 days |
| Signed commits required | ❌ off |
| Secret-scanning push protection | ✅ on |
| Required status checks | ✅ 4, including the Oracle gate |

**Each control links to the signals it would have prevented.** "Approved their own change" fired four
times in this repository; the row that explains why sits directly above it. That link is the whole
point of the panel — it converts a log of oddities into a diagnosis with a remedy the team can
action themselves.

**Unknown is a state.** A control the platform could not read is `unknown` with the reason, never a
red cross. A permissions gap is not a security failure and must not be scored as one.

**Built, with one restraint the table above did not specify.** A row names what it would have
prevented only when the control is *not* in force. Telling somebody that their working control "would
have prevented self-approval" reads as an accusation about something that did not happen, and the
whole value of the link is that it points at work worth doing.

## 3. The aggregate

One number per repository, `governance_score` (0–100), from the panel's controls, weighted in a
reviewed policy file rather than in code — same discipline as everything else that decides what a team
is told to aim at.

Alongside it, three counts over the last 90 days that are **facts about the repository, not about
people**:

- merges with a single approver on a sensitive path,
- merges where the approval came faster than the diff could plausibly be read,
- admin bypasses of a required control.

These are the existing Aegis signals, aggregated by repository rather than by author. That framing is
deliberate and it is what keeps this inside spec 06 §9: *"3 of the last 40 merges had a single
approver on a sensitive path"* is a statement about a control, and the remedy is a settings change.
The same data grouped by person is a statement about colleagues, and it is not built here — not
because it is hard, but because spec 06 §9 already decided, and this spec agrees.

### 3.1 Built

**Scored over what was read, never over what exists.** An `unknown` control is excluded from both
halves of the fraction, so a repository whose settings could not be read has *no* score rather than a
bad one — the same `available: False` rule spec 09 §9 applies to every Oracle input, for the identical
reason. `partial` earns half, because a binary would have to call one required approval either "on" or
"off" and it is honestly neither.

The weights are relative rather than absolute (`earned / possible`), so adding a control later does
not silently deflate every existing score. The one argument the file expects to have is weighting
`enforced_for_admins` alongside the two entry controls, and it makes the case in place: without it,
every rule above it describes what usually happens rather than what is enforced.

## 4. Into Oracle, through the profile

The governance aggregate becomes an input to the **risk profile** (spec 21 §1), not a term in the
finding score.

The distinction matters and is the same one spec 21 already draws: the profile carries context about
what a repository *is* — its exposure, its data classification, its criticality — and governance is
exactly that kind of fact. The finding score carries what was found. Weak review controls do not make
a SQL injection worse; they make this repository a worse place for one to be, and the profile is where
that belief already lives.

Consequences that fall out for free: `path_to_green` (spec 26 §1) can name a settings change as an
action, and a repository with strong governance gets the reward side of spec 26 §2 without a new term
being invented for it.

### 4.1 Corrected while building: it is a penalty, and only a penalty

The paragraph above is wrong about the reward, and the reason is a rule spec 26 wrote for itself.
**Branch protection is a switch.** Spec 26 §2.3 refuses credit for switch-flipping in as many words —
*"No credit for enabling a capability, installing a workflow, or turning on the gate… they would be
trivially gamed"* — so strong governance cannot earn the reward side of §2 without contradicting the
spec it is supposed to fall out of.

The asymmetry that survives is the honest one, and §4's own framing supports it: weak controls do not
make a SQL injection worse; they make this repository a worse place for one to be. That is a fact
about what the repository *is*, which is precisely what the profile carries. So the term only ever
adds, and it adds nothing at or above a `good_enough` bar deliberately set short of perfect — a term
that could only be silenced by a flawless configuration is one teams learn to ignore.

**Shipped dark.** `points_at_zero: 0` in `oracle-policy-v1.yaml` 1.9, so every repository's score is
unchanged until an operator has seen the panel, agreed the weights describe their estate, and set a
number. A term that started scoring on deploy day would move every score in the portfolio for a
reading nobody had reviewed.

**Stale is unavailable, not old.** The reading is stored in `repo_governance` — Oracle cannot make an
HTTP call — and a reading more than fourteen days old returns nothing rather than an old number. It
describes a repository that may have been reconfigured twice since, and scoring it would be worse than
scoring nothing. A reading covering fewer than five controls is also unavailable: a score over two
controls is not a weaker posture, it is not a posture.

**Not a `RiskProfile` column**, though this section puts governance "into the profile". Every field of
a profile is somebody's *stated belief* about what the application is; a machine-read setting in the
same row would be indistinguishable from one, which is the distinction spec 21 §1 built that table
around. It gets its own row and contributes a `risk_profile.`-prefixed term.

## 5. Acceptance criteria

- A repository whose default branch requires two approving reviews shows that in the panel, sourced
  from the API and stamped with `read_at`.
- A repository the platform lacks permission to read reports `unknown` per control with the reason,
  and its `governance_score` reports `available: False` — never a low score.
- Every `self_approval` signal in the list is reachable from the control row that permits it.
- CODEOWNERS coverage is computed over source paths only, excluding vendored and generated trees, and
  the exclusion list is stated in the response.
- The three 90-day counts are computed per repository and no endpoint in this spec returns a per-person
  aggregate.
- Changing governance changes the risk profile input and never a finding's severity, count, or status.
- Turning on a control does not by itself raise a maturity tier — the maturity model's
  evidence-not-switches rule still holds.

## 6. Edge cases

- **A repository using rulesets instead of branch protection** — increasingly the default. Both are
  read; the panel reports the effective state and names which model produced it.
- **An organisation-level ruleset the repository inherits.** Shown as inherited, because a team told
  to fix something they cannot change from their own settings page will conclude the panel is wrong.
- **A repository with no default-branch protection at all.** Every row red is correct and unhelpfully
  loud; the panel leads with a single sentence naming the two changes with the largest effect.
- **A monorepo whose CODEOWNERS covers 100% via a catch-all `*` line.** Coverage is 100% and the panel
  notes that a single catch-all owner is routing, not review — otherwise the metric rewards the least
  useful possible file.
- **Admin bypass data unavailable on the plan.** Absent, with the reason. This is the row most likely
  to be unreadable and the one whose absence would most easily be mistaken for zero.
- **A control read that fails mid-sample.** The previous reading stands with its original `read_at`,
  visibly ageing, rather than the panel emptying.

## 7. Dependencies

Spec 02 (the App, its installation permissions, and where an additive permission bump is recorded),
spec 06 (Aegis's signals, its rationale requirement, and §9's boundary this spec keeps), spec 20 (the
classifier and `privilege_adjacent`, whose org-role proxy is the nearest existing precedent for
reading a governance fact from GitHub), spec 21 §1 (the risk profile this feeds), spec 24 §1
(CODEOWNERS resolution, shared with ownership), spec 26 §1 (`path_to_green`, which can then name a
settings change).
