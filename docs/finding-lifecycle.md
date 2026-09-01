# The finding lifecycle

How a finding travels from a scanner to a closed record: **deduplication →
false-positive elimination → triage → remediation**.

Every stage of this already existed. None of it was written down in one place —
the mechanisms are spread across fifteen specs, and no document said what
happens to a finding between arriving and closing, or which stage owns which
decision. This states the process, names what each stage guarantees, and
measures the estate against it.

**Measured 2026-09-01.** The numbers are what the lake actually held that day,
not an illustration. Re-measure before trusting them; the queries are in each
section.

---

## The shape of it

```
   scanner
      │
      ▼
┌─────────────────┐   identity is content, not position
│ 1. DEDUPLICATE  │   one finding per real defect, however often it is seen
└────────┬────────┘
         ▼
┌─────────────────┐   a machine proposes, a person disposes
│ 2. FALSE        │   dismissals need a reason; reasons earn dampening
│    POSITIVE     │
└────────┬────────┘
         ▼
┌─────────────────┐   rank by consequence, claim by person, expire by date
│ 3. TRIAGE       │   "not now" must not become "not ever"
└────────┬────────┘
         ▼
┌─────────────────┐   deterministic fixes only, always a draft, never merged
│ 4. REMEDIATE    │   verified against the merge commit, or reported unverified
└────────┬────────┘
         ▼
   fixed · accepted_risk · false_positive · suppressed · superseded
```

The five terminal states are not interchangeable, and the distinctions are
load-bearing:

| Status | Means | Counts toward |
|---|---|---|
| `fixed` | Gone from two consecutive scans | Mean time to fix |
| `accepted_risk` | Real, and we are living with it | Nothing — reported separately, never as resolved |
| `false_positive` | Not a defect | The dampening denominator |
| `suppressed` | Real, deliberately not shown | Nothing |
| `superseded` | The *record* was wrong; the defect may persist under a new id | Nothing — deliberately not `fixed` |

`superseded` exists because retiring a mis-identified finding as `fixed` would
report a mass remediation every time an adapter was corrected. There are 457 of
them, so this is not hypothetical.

---

## 1. Deduplication

**Guarantee: one finding per defect, stable across unrelated edits.**

`fingerprint.compute_finding_id` hashes a content fingerprint — file path,
symbol, normalised snippet, or package name — never the line number (D-001).
Hashing the line meant any edit above a finding retired it and re-reported the
identical issue as new, destroying `first_seen_at` and every metric built on
it: age, mean time to fix, Oracle's age term, every trend line.

Three further collapses sit on top:

- **Occurrence grouping** (`_group_findings`) — the same rule firing many times
  in a repository is one row with a count, not many rows.
- **Toxic combinations** — several findings that are only dangerous together
  become one decision, with `toxic_combination_id`. Five so far.
- **Supersession** — a corrected adapter retires the old record and names the
  replacement in `superseded_by`.

**Measured:** 2,070 finding records; 457 superseded.

```sql
SELECT status, count(*) FROM findings GROUP BY 1;
```

---

## 2. False-positive elimination

**Guarantee: a machine may propose, only a person disposes — and a dismissal
without a reason buys nothing.**

Three inputs, in increasing order of authority:

**Patchwork proposes.** `patchwork/triage.classify` labels each finding
`true_positive`, `likely_false_positive` or `needs_human_judgment`, always with
a written rationale — spec 01 §6 makes an unexplained verdict a bug. It never
changes a finding's status. A machine that could dismiss findings would
eventually dismiss a real one, silently.

**A person disposes.** `PATCH /api/dashboard/findings/{id}/status` is the only
path to `false_positive`, and the reason is what makes it worth anything: spec
11 §4 records a bare click as low-confidence and bars it from promotion.

**Dampening turns dismissals into a score change** — the one place a learning
moves a number, which is why it is gated twice. The lake supplies the
denominator (how often the rule actually fired; the Knowledge Store cannot
know, because nobody clicks anything about the findings that were real) and the
store supplies the licence (a human wrote down *why*, at least
`min_observations` times). Without the denominator, one dismissal of a rule
seen once is a 100% false-positive rate.

A parallel loop runs for fixes: closing a Patchwork PR unmerged with
`reason: fix_was_wrong` dampens that fixer for that rule in that repository
after two rejections — scoped to the repository, because a fixer wrong about a
rule in a vendored tree is not thereby wrong about it everywhere.

**Measured:** 43 false positives (sast 29, secrets 14) against 480 open. No
container, DAST or IaC finding has ever been dismissed — worth knowing before
reading the dampening numbers, since those two capabilities are the whole
denominator.

---

## 3. Triage

**Guarantee: ranked by consequence, owned by somebody, and "not now" cannot
become "not ever".**

- **Ranking** (`dashboard._rank`) — severity, blast radius, KEV and EPSS,
  whether the repository is already `no_go`, whether the file is imported by
  anything, whether a fix exists.
- **Ownership** is `Finding.owner`, from CODEOWNERS — who is *answerable*,
  stable, about the code (spec 24 §1).
- **A claim** is who is *doing it now* — self-service, short-lived, expiring
  visibly. Conflating the two would mean nobody could help a neighbouring team
  without rewriting ownership.
- **A snooze never touches status.** A snoozed finding is still open, still
  scores, still goes overdue. That separation is the entire defence against
  "not now" becoming "not ever".
- **Acceptances expire.** `accepted_until` and `accepted_reason_code` make an
  acceptance revisitable by machine, and a daily sweep re-opens anything
  accepted as `no_vendor_fix` once a vendor ships one (spec 24 §3).

**Measured:** 480 open, 294 accepted risk, 2 overdue criticals.

---

## 4. Remediation

**Guarantee: deterministic fixes only, always a draft, never merged, and
verified against the merge commit or reported unverified.**

Stages: `triaged → correlated → would_fix → fix_generated → pr_opened`, with
`no_fix_available`, `queued`, `skipped_low_confidence` and `superseded` as
exits. Every finding records the stage it reached, so a fix that went nowhere
says where it stopped.

The hard constraint is structural, not configured: `GitHubClient` has no merge
method, and a test asserts no method whose name contains "merge" exists on the
interface or either implementation (spec 08 §3, D-095). Every PR is a draft.

Verification (spec 25 §1) re-scans the merge commit for the one capability that
produced the finding, and reports `verified_fixed`, `still_open`,
`not_scanned` or `inconclusive` — never a guess. Closure itself is separate and
stricter: `reconcile_absences` requires a finding to be absent from **two**
consecutive successful scans before it becomes `fixed`, which is flap
protection for `resolved_at` and every metric built on it.

**Measured, and this is the stage to look at:**

| Stage reached | Count | Classification |
|---|---|---|
| `triaged` | 399 | needs_human_judgment |
| `superseded` | 87 | true_positive |
| `no_fix_available` | 47 | true_positive |
| `triaged` | 22 | likely_false_positive |
| `correlated` | 5 | needs_human_judgment |

**Nothing has ever reached `fix_generated` or `pr_opened`.** Zero pull
requests, zero verifications, across 560 remediation events.

That is not a defect, and it is worth stating precisely rather than alarming
about: there are four deterministic fixers — Python requirement pinning, npm
pinning, Go module pinning, and committed-secret removal — and the estate's
open findings are 234 container, 147 DAST and 88 SAST. Almost nothing in the
backlog is a class any fixer covers. The pipeline is declining to guess, which
is what it is for.

The consequence is that spec 25's efficacy view has nothing to measure, and
B-011's regression links have no production traffic to run on. Both are honest
consequences of fixer coverage, not bugs in either.

---

## The stage that has no owner: closure

A finding becomes `fixed` when `reconcile_absences` sees it absent from **two
consecutive successful scans**. That rule is deliberate — it is flap protection
for `resolved_at` and every metric built on it — and it has a consequence that
belongs written down next to it:

> **A capability whose lane is failing cannot close anything.**

Not slowly. At all, for ever, however thoroughly the defect was fixed. The
scans that would observe the absence never run, so the absence is never
observed.

This is not a hypothetical. On 2026-09-01 this repository held **115 open DAST
findings naming security headers that were already set** in
`frontend/next.config.ts` and verifiably being served. The DAST lane had failed
seventeen times running since 2026-08-30 — the ZAP spider hit its 600s budget,
`bash -e` killed the step, and the JSON report was never written. The dashboard
showed 115 open findings and was correct. The number had been meaningless for
two days.

Nothing reported it, because every existing surface answers a different
question. The portfolio ranks repositories, the worklist ranks findings, the CI
view shows job status per repository — and none of them joins "this lane is
broken" to "so these findings are frozen".

`mykronos briefing` does, and `deploy.ps1` runs it after every deploy (D-098).
Its first section is stalled lanes and what each is holding open; the rest
groups open findings by what would fix them. **Fix the lane before the
finding** — re-running a broken workflow fails again and closes nothing.

**And repairing a lane can tell you something you were wrong about.** The
first successful DAST run after this one was fixed returned 86 findings, 69 of
which reproduced — at `/healthz` and `/api/dashboard/trends`. Those are
FastAPI paths. The headers were fixed on the *frontend* and the **backend had
never had them at all**, which nobody could see while the lane that would have
said so was down. A stalled lane does not only freeze the record; it hides
what the record would have said next (B-025).

```bash
docker exec mykronos-backend mykronos briefing
docker exec mykronos-backend mykronos briefing --json   # for a pipeline step
```

---

## Where the process broke, and what closed it

Three gaps, all at handoffs rather than inside a stage. All three are now
closed (B-019, B-020, B-021); they are kept here because the shape of them is
the useful part.

**The machine's proposals reached nobody.** 22 findings were labelled
`likely_false_positive` and 399 `needs_human_judgment`, and the ranked queue
could not filter by classification at all — only the per-repository findings
view could. So "show me everything the machine could not judge" meant one
request per repository, which is not a worklist. The queue now takes a
`triage` filter and carries the classification and its rationale on every row,
whether or not anybody filters.

**The false-positive funnel had no confirmation step.** A
`likely_false_positive` sat at `triaged` until somebody opened the right
repository and dispositioned it by hand, and the dampening loop that depends on
those dispositions was fed by whoever happened to look. The evidence it was not
working: 43 dismissals ever recorded, all sast and secrets, against 234 open
container findings.

`POST /api/dashboard/findings/{id}/classification-review` makes it one action,
and records **both** answers. The triage queue renders it: a Classifier column
and filter, the rationale on hover, and a review control on every row (B-022). Agreement already left a trace — the status
changes and the rule earns a dismissal observation. Disagreement left none, so
a classifier calling real findings false positives was indistinguishable from
one nobody had got to. A verdict nothing ever contradicts is a verdict nobody
is checking.

Rejection is its own knowledge type and deliberately does not dampen: it
teaches about the classifier, not the rule, and quietening a rule because
somebody said its finding was real would invert the loop. Agreement is
delegated to the disposition endpoint rather than reimplemented, so the two
routes to the same decision cannot drift apart — and agreeing with
`needs_human_judgment` is refused outright, because that is the one thing this
endpoint must not become a shortcut for.

**Remediation coverage was unstated.** That four fixers cover four narrow
classes is true, defensible, and was written down nowhere a reader of the
Remediation tab would find it. The efficacy response now carries `coverage` —
what has a fixer and what does not, with the reason — and `measured`, which
separates "no fix has reached a pull request" from "fixes were made and did not
remove risk". An all-zero table meant both, and a reader could not tell which.

## Re-measuring

Every number here comes from `mykronos query`, in the container:

```bash
docker exec mykronos-backend mykronos query \
  "SELECT status, count(*) FROM findings GROUP BY 1 ORDER BY 2 DESC"

docker exec mykronos-backend mykronos query \
  "SELECT pipeline_stage_reached, triage_classification, count(*) \
   FROM remediation_events GROUP BY 1,2 ORDER BY 3 DESC"

docker exec mykronos-backend mykronos query \
  "SELECT capability, count(*) FROM findings WHERE status='open' GROUP BY 1"
```

## Where each stage lives

| Stage | Specs | Code |
|---|---|---|
| Deduplicate | 05 §5, D-001 | `fingerprint.py`, `dashboard._group_findings`, `patchwork/correlate.py` |
| False positive | 10 §2.2, 11 §4 §6.1 | `api/dashboard.py` disposition, `knowledge/dampening.py`, `patchwork/triage.py`, `patchwork/rejection.py` |
| Triage | 19, 24, 27 | `dashboard.py` ranking, `worklist.py`, `ownership.py` |
| Remediate | 08, 25, 31 | `patchwork/pipeline.py`, `patchwork/verification.py`, `regression.py` |
| Closure | 05 §5a | `lake/reconcile.py`, `briefing.py` |
