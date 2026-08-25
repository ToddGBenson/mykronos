# Spec 31 — Regression Coverage: The Finding-to-Test Link

**Status:** Draft for review
**Depends on:** [18 — Repo Page Rework](18-repo-page-rework-threat-model-and-remediation.md),
[19 — Harness, Triage and Remediation Depth](19-harness-triage-and-remediation-depth.md),
[03 — Workflow Installer](03-workflow-installer.md), [25 — Fix Efficacy](25-fix-efficacy-and-verification.md),
[26 — Oracle as Adviser](26-oracle-as-adviser.md), [28 — Threat Model Resolution](28-threat-model-resolution.md)

---

## 0. What this spec is against

Findings and Harness are adjacent tabs with no relationship whatsoever.

The Harness runs unit, functional and QA lanes as ScanRuns that deliberately never produce findings —
right, and D-046's reasoning holds. It reports pass rate over 90 days, flags flaky tests, and shows
real failure text. It says nothing about *what the tests are for*.

So the platform cannot answer the question a security team most wants answered:

> **Which of the vulnerabilities we have already fixed would we notice coming back?**

Today the honest answer is *none of them, reliably*. A finding is fixed, the row disappears, and
nothing is left behind in the repository that would fail if the same mistake were made again next
quarter. Every fix is a one-time event rather than a permanent change in what the repository will
tolerate.

Two smaller gaps sit alongside it, and both block making this universal:

- **Pass rate is not coverage.** A green lane says the tests that exist passed. A repository with one
  trivial test and a 100% pass rate renders identically to one with a real suite.
- **Actions-scanned repositories cannot use the Harness at all** — no workflow template exists for
  the three lanes, so they cannot even be enabled there. Named honestly in spec 18 §0a and still
  true. *Closed by §5: `unit.yml.j2`, `functional.yml.j2` and `qa.yml.j2` now exist, and the
  capabilities endpoint stops refusing these three for an Actions-scanned repository.*

## 0a. Implementation status

| Item | Status |
|---|---|
| The `finding_tests` link and its capture (§1, §2) | **Built** — via its own endpoint, not the disposition form; see below |
| Regression coverage, per repository and portfolio-wide (§3) | **Built** per repository; portfolio-wide not started |
| Coverage percentage beside pass rate (§4) | **Built** — and it fixed a bug: a coverage report was being parsed as broken JUnit, see §4 |
| Test-lane workflow templates for Actions (§5) | **Built** |
| Into Oracle as a posture credit (§6) | **Built** — landed with spec 26 §2 as `posture.regression_coverage` |

## 1. What a regression link is

A row in a new lake table, `finding_tests`:

| Column | Notes |
|---|---|
| `link_id` | primary key |
| `finding_id` | the vulnerability this test exists because of |
| `repo_full_name` | |
| `test_identifier` | the JUnit `classname.name` — what the runner already reports |
| `capability` | `unit` \| `functional` \| `qa`, the lane it runs in |
| `linked_by`, `linked_at` | a person or `patchwork` |
| `evidence` | `asserted` \| `demonstrated` |
| `last_seen_passing`, `last_seen_at` | from the JUnit results already ingested |

**`evidence` is the field that keeps this honest.** `asserted` means somebody said this test covers
that finding. `demonstrated` means the platform watched the test fail against the vulnerable code and
pass against the fixed code — which is the only proof that a test protects anything. Both are useful;
they are not the same claim and are never displayed as one.

## 2. Where links come from

Three sources, in increasing order of strength:

- **A person, on the finding.** Its own endpoint, and this section's first draft was wrong about
  where: it said "when a finding is marked `fixed` by hand, the form offers a test identifier".
  Nobody can mark a finding fixed by hand — `HUMAN_DISPOSITIONS` excludes it deliberately, because
  `fixed` is an observation the scanners and the reconciler own and letting a person assert it would
  put a claim in the lake no scan supports. So the moment the spec described does not exist. What
  does exist is a person who has just written the test, and
  `POST /api/dashboard/findings/{id}/regression-test` is where they say so. Optional, for the reason
  the draft gave: a mandatory field here would be answered with garbage.
- **A fix pull request.** Patchwork's PR body gains a line: *"if you add a regression test, name it
  here"*, parsed on merge. The person writing the test is the person merging the fix, and this is the
  cheapest possible moment to ask.
- **Demonstrated, from verification.** This is the valuable one and it composes with spec 25 §1. The
  verification scan already runs against the merge commit. If the repository's test lane runs in the
  same pipeline and a **newly-added** test is present in that run, the platform can check the stronger
  claim: run that test against the pre-fix ref; if it fails there and passes here, the link is
  `demonstrated`. One extra lane invocation on the parent commit, only for fix PRs, only when a new
  test appeared.

### 2.1 What does not ship

**No test generation in v1.** The platform does not write the test. That is a genuinely attractive
use of a model and it belongs behind spec 23 §1's benchmark and spec 25 §4's gate — and more
importantly, a generated test that asserts the wrong thing is worse than no test, because it will be
counted as coverage forever. The link comes first; generation can come later against a measurement
that already exists.

**No inference from names.** A test called `test_sql_injection` is not linked to a SQL-injection
finding by string similarity. That is exactly the kind of guess this platform refuses elsewhere, and
it would inflate the one number this spec exists to make trustworthy.

## 3. Regression coverage

The number, on the Harness tab:

> **Regression coverage — 12 of 61 fixed findings have a test pinned.**
> 4 demonstrated, 8 asserted. 3 links are stale (test not seen in 30 days).

And its portfolio equivalent on the trends page.

**What staleness can and cannot catch — narrower than this section assumed.** The JUnit adapter
records suite totals, not case names (D-046: "what reaches the lake is that a suite ran, how it
ended, and how many cases failed"). So `lane_last_green_at` knows when the *lane* last ran green and
cannot know whether one particular test still exists inside it. A deleted test keeps counting until
its whole lane stops running. That is a real limit on the number and is why `stale` is reported
beside the headline rather than folded into it; closing it means recording per-test results, which
is its own piece of work and is not smuggled in here.

**Stale links matter as much as missing ones.** A pinned test that stopped running — deleted, renamed,
skipped, or in a lane nobody enabled any more — is a protection that quietly expired, and it is the
failure mode this table would otherwise create: a coverage number that only ever goes up. `last_seen_at`
is what catches it, and a stale link is reported separately rather than silently counted or silently
dropped.

**Fixed findings are the denominator, not all findings.** A vulnerability never fixed does not need a
regression test; it needs a fix. Using every finding as the denominator would make the number
unimprovable and therefore ignored.

## 4. Coverage beside pass rate

Line and branch coverage where the runner reports it — every major test runner emits it, and the
Concourse lanes already have the output in hand. Reported as a `ScanRun` metric on the existing
`unit`/`functional` runs, rendered next to the pass-rate sparkline.

**Explicitly not a security metric, and labelled that way.** It is context that stops a green
sparkline being read as more than it is. Coverage of 90% with zero regression links means the tests
are thorough about something other than the things that have gone wrong here.

### 4.1 Found while building: a coverage report was making the record worse

The JUnit adapter globs `*.xml`. A repository that wrote `coverage.xml` beside `unit.xml` — which is
the default layout of pytest-cov, of jest, and of every Maven build — was handing a Cobertura
document to a JUnit parser. It found no `testsuite` element, warned "the report contains no test
suites", and downgraded a green run to `no_applicable_targets`.

So the file carrying the most useful context about a suite was actively degrading the record of that
suite, and had been since D-046. Cobertura and JaCoCo are now recognised by their root element and
yield coverage rather than a warning.

**Null is not zero, and the tab distinguishes them.** A lane whose runner never wrote a coverage
report and a lane measured at zero are different facts. Rendering both as 0% would make the honest
one look like the broken one, which is spec 05 §7a's convention applied to a new number.

**Sharded suites take the highest report, not the sum or the mean.** Each shard measures only the
code its own shard touched: summing exceeds 1.0, and averaging understates a repository whose shards
are deliberately narrow. The largest is at least a number somebody actually observed.

## 5. The Actions gap

Three workflow templates — `unit.yml.j2`, `functional.yml.j2`, `qa.yml.j2` — following the existing
installer conventions, so `DISPATCHABLE_CAPABILITIES` can include the test lanes for Actions-scanned
repositories and the Harness tab stops being dark for a whole class of onboarded repos.

Mechanical work, listed last in this spec and yet a precondition for regression coverage meaning
anything portfolio-wide: a coverage number computed over only the Concourse repositories would be a
statement about the pipeline, not about the estate.

### 5.1 What the templates decided that this section did not

**The command comes from config and has no default.** A test lane runs the repository's own suite,
whose runner is decided by its language and its own conventions (D-046). Guessing `pytest` because a
`.py` file exists ships a workflow that fails on every run for reasons the team did not choose, so
an Actions install without a command is refused with a 422 naming the field. The template carries a
second, redundant guard that fails the run loudly if it ever renders without one — a lane that runs
nothing and reports success is precisely the outcome the refusal exists to prevent.

**This is arbitrary code execution on the runner, by definition.** There is no version of "run this
repository's test suite" that is not "run what this config says". The boundary that matters is
therefore who may set it — capability config is admin-only — and that a command cannot escape its own
step into the rest of the workflow. Newlines are refused in `command` and in each `setup` line, for
exactly that reason; shell metacharacters are allowed, because refusing them would refuse most real
test commands.

**The functional lane offers the DAST proxy rather than asserting it.** Actions has no long-lived ZAP
instance for a workflow to route through — that is the Concourse lane's arrangement. What this can
honestly do is tell the suite where a proxy is when one is configured, and say nothing when one is
not. A workflow claiming a DAST corpus it never produced would be worse than producing none.

## 6. Into Oracle

`regression_coverage` becomes the first of spec 26 §2's posture credits, capped, and — importantly —
**counting `demonstrated` links at full weight and `asserted` links at a fraction of it.** A team that
proves its tests protect something earns more than a team that says so. That asymmetry is the whole
incentive design, and it is the reason `evidence` is a column rather than a boolean.

## 7. Acceptance criteria

- Marking a finding `fixed` with a test identifier creates an `asserted` link; the finding's page
  shows the test and its last-seen-passing date.
- A fix PR whose body names a test creates a link on merge, attributed to `patchwork`.
- Where the pre-fix ref is available and a new test appeared, the platform runs it against that ref and
  records `demonstrated` only when it fails there and passes after.
- A linked test absent from 30 days of runs is reported as stale and is excluded from the headline
  count rather than silently retained.
- The denominator is findings ever transitioned to `fixed` for that repository, and it is stated on
  the tab.
- An Actions-scanned repository can enable `unit`, `functional` and `qa`, and dispatch them from the
  Harness tab.
- The Oracle credit weights `demonstrated` above `asserted`, is capped, and reports `available: False`
  for a repository with no fixed findings at all.

## 8. Edge cases

- **A test that covers three findings** — one fix, three linked findings. Many-to-many, and the
  headline counts findings covered, never links, or the number inflates on a single good test.
- **A finding that regresses.** The pinned test either caught it (it failed, and the finding reopened
  from a test failure rather than from a scan) or it did not — and the second case is the most
  valuable row in the table: a test believed to protect something that did not. Flagged, not deleted.
- **A flaky pinned test.** Spec 19 §1 already flags flakiness; a flaky test is shown as a weak link,
  because protection that fails randomly is not protection.
- **A repository with no test lane enabled.** Regression coverage is `available: False`, not 0%. The
  distinction is the same one this platform draws everywhere else and it is the difference between
  "no protection" and "no information".
- **A finding fixed by deleting the file.** No test is possible and none should be demanded — the
  disposition offers "removed, not fixed" and that finding leaves the denominator.
- **The pre-fix ref no longer building** (a dependency vanished, the branch was garbage-collected).
  `demonstrated` cannot be established; the link stays `asserted` and says why.

## 9. Dependencies

Spec 03 (installer conventions the three templates follow), spec 18 §4 and D-046 (the Harness, and the
rule that a test run is a ScanRun and never a finding — unchanged: a regression link is metadata about
a finding, not a finding produced by a test), spec 19 §1 (flaky-test flagging, reused for weak links),
spec 25 §1 (the verification scan `demonstrated` composes with), spec 26 §2 (the posture credit), spec
28 §3 (a demonstrated test is the strongest available evidence for a declared control, and the two
registers should link).
