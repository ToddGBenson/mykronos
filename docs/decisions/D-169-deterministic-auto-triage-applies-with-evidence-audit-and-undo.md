## D-169 — Deterministic auto-triage applies on recorded evidence, with an audit row and a one-click undo

**2026-10-21.** **Status:** Decided, implemented
**Story:** TheHub #60888 (Triage T8) · Refs D-168, #713, operator decision 2026-10-22, [spec 19 §2.1](../../specs/19-harness-triage-and-remediation-depth.md), [spec 25 §1](../../specs/25-fix-efficacy-and-verification.md), [spec 27](../../specs/27-the-worklist.md), [spec 33](../../specs/33-risk-acceptance-and-poam.md)

**The rule.** Todd decided on 2026-10-22 that deterministic verdicts auto-apply
with an audit row and a one-click undo, and that a model's verdict never does.
`backend/mykronos/auto_triage.py` is the four lanes that qualify. Each closes an
open finding in an active repository on one kind of evidence the platform
already records, and stores a reference to it:

| Lane | Evidence | New status |
|---|---|---|
| `fix_verified` | a `remediation_events` row: fix PR merged, and the scan of its merge commit for the finding's capability succeeded without reporting it (`verified_fixed`), and the finding has not been seen since | `fixed` |
| `vex_not_affected` | a `VexStatement` with status `not_affected`, recorded by a person with its source, matching the advisory and package (and version or repository if it names one) | `suppressed` |
| `exact_duplicate` | a finding somebody other than auto-triage set to `false_positive` or `suppressed` (a person, or an agent within #713's limits), with the same cluster key (D-168) and, for a package, the same version | that verdict |
| `unreachable` | the repository's `ReachabilityReport` lists the Python file as orphaned, and no file failed to parse | `suppressed` |

Strongest evidence first: when two lanes match, the action records the first.

**A serious finding needs serious evidence.** A critical or high finding is
closed only by `fix_verified` or `vex_not_affected`. A duplicate verdict or an
orphaned file closes medium and below; on a high, the sweep counts it as
`held_serious` and leaves it for a person.

**What is never copied or read.** An acceptance is a governed record with a
review date (spec 33) and is never copied by `exact_duplicate`. A verdict the
platform set itself is never a precedent, so one human decision cannot spread
by chains of copies. The classifier (`patchwork/triage.py`) is not imported;
`tests/test_auto_triage.py` pins that at the source. Reachability evidence is
the import graph and nothing else.

**Audit and undo.** Each action is an `AutoTriageAction` row (rule, evidence,
summary, the finding's prior status, `resolved_at`, `accepted_until` and reason
code) and a `finding.auto_triage` audit entry by `auto-triage`, kind
`automation`. `POST /api/dashboard/auto-triage/actions/{id}/undo` with a reason
writes the prior state back, guarded on the finding still holding the status
the action set (409 otherwise), and audits `finding.auto_triage_undone`. Any
writer may undo, agents included: like reopening, it only adds tracking back.
A lane is never re-applied to a finding it was undone on, and a finding a
person reopened is left alone. Actions show on `GET /api/dashboard/findings/{id}`
(`auto_triage`), on the repository page's finding pane and in the Triage page's
last-24-hours panel.

**Why VEX statements are a person's act.** `POST /api/dashboard/vex-statements`
is `HumanDep`. A `not_affected` statement is evidence one lane closes critical
findings on, and an agent that may not close a critical itself (#713) must not be
able to write the statement that would.

**Kill switch.** `auto_triage.<lane>.enabled` in `oracle-policy-v1.yaml`
(policy 1.16, which changes no score). A disabled lane proposes nothing, and a
sweep reports how many findings it would have matched. Absent, a lane is off.
A change takes effect when the file is deployed.

**Running.** The `auto-triage` job runs hourly (`auto_triage_interval_seconds`)
under `LANE_CLOSURE_LOCK`, the lock every pass that closes findings holds.
`POST /api/dashboard/auto-triage/run` runs it now, as a dry run unless told
otherwise. `GET /api/dashboard/auto-triage/digest?hours=24` lists what was done,
by lane, and the briefing (`GET /api/dashboard/briefing`) carries the same digest.

**Found on the way.** `lake.mutate.update_findings` reports every id it was handed
as updated even when its `only_if_status` guard left the row alone, so its result
cannot say which rows moved. This module reads statuses before and after its
writes instead; the existing callers that trust the result are unchanged here.
*Since fixed (TheHub #60926):* `update_findings` now returns only the rows its
UPDATE wrote, so this module reads the result instead of re-reading statuses, and
the reopen route's 409 and the approval audit's `applied` flag are truthful.
