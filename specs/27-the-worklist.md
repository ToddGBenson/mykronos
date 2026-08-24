# Spec 27 — The Worklist: Ranked Triage, Claimable Rows, and a Weekly Digest

**Status:** Draft for review
**Depends on:** [10 — JDED Dashboard](10-jded-dashboard.md), [17 — Harness, Threat Intel, i2i](17-harness-threat-intel-and-i2i.md),
[19 — Harness, Triage and Remediation Depth](19-harness-triage-and-remediation-depth.md),
[24 — Ownership and Deadlines](24-ownership-deadlines-and-acceptance-review.md),
[26 — Oracle as Adviser](26-oracle-as-adviser.md)

---

## 0. What this spec is against

The triage queue holds, on every row: severity, capability, rule, the repository's standing Oracle
verdict, CVE, KEV membership, EPSS score, and first-seen date. Elsewhere in the platform, for the same
findings, there is age, blast radius, import reachability, whether Patchwork can fix it mechanically,
and — after spec 24 — an owner and a due date.

`triage_queue()` orders by **severity, then age**.

So every input needed to answer *"what should I do first"* is present, and the ordering answers
*"what is nominally worst"* instead. Those diverge constantly: a medium with an EPSS of 0.7 in a
production-facing repository, fixable by a one-click PR, sits below a critical in a library nothing
imports.

The second gap is that the queue has no state. A row can be dispositioned or groomed into a story. It
cannot be claimed, snoozed, or batched; two people triaging at once cannot see each other's work; and
nothing records that triage happened at all — there is no throughput, no burn-down, no "what did we
clear last week".

## 0a. Implementation status

| Item | Status |
|---|---|
| Ranked ordering with visible inputs (§1) | **Built** |
| Effort estimate from observed outcomes (§2) | **Built** |
| Claim, snooze, and batch actions (§3) | **Built** |
| Weekly per-owner digest (§4) | **Built** — off unless `digest_enabled` |
| Throughput and burn-down (§5) | **Built** |

## 1. Ranking

### 1.1 What ships

A `rank` ordering alongside the existing severity ordering — not replacing it, because "show me every
critical" remains a legitimate question and a queue that refuses to answer it is a worse queue.

The score is a small, explainable, additive expression over signals the row already carries:

The `orphaned_discount` term ships with a weight and **does not fire yet**: import reachability is a
per-repository report in the operational store, and this queue is cross-repo with no session for it
at the point the rank is computed. Absent rather than assumed false, which is the direction that
cannot bury live work — the same rule D-072 applies to the risk model.

```yaml
# New block in oracle-policy-v1.yaml. Reviewed in a pull request like every
# other policy value, and versioned with it: an ordering that decides what a
# team looks at first is policy, not a constant in a module.
triage_rank:
  severity:            {critical: 40, high: 25, medium: 12, low: 4, info: 0}
  in_kev:              25        # actively exploited, right now, in the world
  epss_at_1_0:         20        # scaled linearly by the score itself
  overdue:             15        # past due_at (spec 24 §2)
  due_soon:            5
  blast_radius_at_max: 10        # scaled by dependent-repo count
  repo_is_no_go:       8         # the same finding matters more in a failing repo
  orphaned_discount:  -10        # import-unreachable (D-072), a discount as it is everywhere
  fixable_bonus:       6         # a one-click fix removes risk cheaply, so it goes first
```

**Every term is shown on the row.** A rank a person cannot argue with is a rank they will ignore, and
this platform's standing rule is that a derived number carries its working (spec 10 §6). Hovering or
expanding a row lists the contributing terms exactly as Oracle's breakdown does.

**`fixable_bonus` is the interesting one.** It is not a claim that a fixable finding is more
dangerous — it is a claim that it is cheaper, and the queue's job is risk removed per unit of work.
That makes the ordering explicitly economic, which is what a worklist is.

### 1.2 What does not ship

No machine learning, no personalisation, no "findings like the ones you usually fix". The ranking is
a documented weighted sum that a person can recompute on paper, for the same reason Oracle's is.

## 2. Effort

Alongside rank, each row carries a coarse effort band — `one_click` | `small` | `investigation` —
derived only from things the platform has observed:

- `one_click`: Patchwork has a fixer and has previewed a fix successfully (the existing `fixable`
  badge, which spec 19 already derives from observed outcome rather than prediction).
- `investigation`: the row is a toxic combination, or is a finding whose capability has no fixer at
  all.
- `small`: everything else.

Three bands, not an hour estimate. An estimate this platform cannot verify would be a number nobody
should plan against, and after spec 25 §3 the verified-fix data can sharpen these bands with evidence
rather than by guessing harder.

## 3. State on a row

### 3.1 What ships

- **Claim.** A row can be claimed by a handle; claimed rows show who holds them and since when.
  Claims expire after a configurable interval (default 7 days) so an abandoned claim does not hide
  work forever — an expiry that is visible in the UI as it approaches, not a silent release.
- **Snooze with a date and a reason.** Distinct from `accepted_risk`, which is a decision about the
  vulnerability; a snooze is a decision about *this week*. It hides the row from the default view
  until its date, and it never touches `Finding.status` — the finding is still open, still counted by
  Oracle, still overdue if it is overdue. This distinction is the whole reason snooze is a queue
  concept rather than a status.
- **Batch actions** over a selection: groom as stories, claim, snooze, or disposition — each still
  requiring its own reason where the single-row action requires one. Batching must not become a way
  to skip the reason field, which is what makes the Knowledge Store worth anything (spec 11 §4).

### 3.2 Where the state lives

In the operational store, not the lake. A claim is not a fact about a finding; it is a fact about who
is working on it this week, it changes many times a day, and the lake's compaction and partitioning
model is built for scan results rather than for UI state (spec 05 §2).

## 4. The weekly digest

One message per owner (spec 24 §1), per week:

- what is newly overdue,
- what is claimed and ageing,
- the top-ranked unclaimed items in repositories they own,
- what they closed last week, and whether it verified (spec 25 §2).

Delivered through the existing notifier (`notify.py`), which already carries the "a notifier that
cannot deliver is worse than none" rule from `docs/pipeline-standard.md` PS-10 — a digest that
silently fails to send is the same failure and must be surfaced the same way.

**The last bullet is not filler.** A weekly message that only ever lists new obligations trains people
to stop opening it. The one that also says "the four things you fixed last week are verified gone" is
the one that gets read, and it is only possible because spec 25 makes verification real.

## 5. Throughput

A small panel above the queue: opened, closed, and verified this week against the same three numbers
last week; median time from first-seen to closed for what closed. Every number a query over
`first_seen_at`, `resolved_at`, and the verification events — no new table, following the same rule
`maturity.py` already applies to its trend series.

## 6. Acceptance criteria

- Ranked ordering places a fixable, KEV-listed, overdue medium above a non-fixable, import-orphaned
  critical, and the row shows the terms that produced that order.
- Switching to severity ordering returns exactly today's order — the existing behaviour is preserved,
  not replaced.
- A claimed row shows the holder to a second viewer immediately, and an expired claim returns the row
  to the pool with a visible transition rather than a silent one.
- A snoozed finding remains `open` in the lake, still counts toward the repository's Oracle score, and
  still appears in the overdue tile if it is overdue.
- A batch disposition records one reason per finding, not one reason for the batch.
- The digest for an owner with nothing outstanding is not sent at all, rather than sent empty.
- A digest that fails to deliver is visible as a failure, per PS-10.

## 7. Edge cases

- **Two people claiming the same row within a second.** First write wins; the second is told, and the
  row shows the holder. A silent overwrite here is two people fixing the same finding.
- **A snoozed finding that becomes KEV-listed.** The snooze is broken and the row returns, flagged:
  the world changed, and that is exactly the event a snooze should not survive.
- **A finding whose owner changes while claimed.** The claim stands. It is a statement about a person
  working on it, not about routing.
- **The ranking policy changing mid-week.** Order changes, and the panel says the policy version that
  produced it — the same treatment Oracle's decisions already get.
- **An owner with three hundred rows.** The digest names the top items and the totals; a digest that
  lists everything is a report, and a report is what the queue already is.
- **A row ranked highly by `fixable_bonus` whose fix was already rejected once** (spec 25 §3.3). The
  bonus does not apply a second time — the platform has learned that this one is not cheap.

## 8. Dependencies

Spec 10 (the queue and portfolio views this extends), spec 11 §4 (reason capture, which batching must
preserve), spec 17 §4 (KEV/EPSS on the row), spec 19 §2 (blast radius, import reachability, and the
`fixable` badge derived from observed outcome), spec 24 (owner and `due_at` — the ranking's overdue
terms and the digest's addressee both depend on them), spec 25 §2 (verification, for the digest's
closing bullet and for sharpening effort bands), spec 26 §1 (`path_to_green`, which the worklist
consumes and annotates with effort rather than recomputing).
