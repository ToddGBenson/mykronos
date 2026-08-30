# L0005: A comparison invents the gradient it needs

**Date:** 2026-08-29 · **Class:** learned here, migrating three repositories off Concourse
**Applies to:** every gate that authorises destroying the thing it is comparing against
**Landed as:** `_COVERED` / `_covers()` replacing `_STATE_RANK`, the coverage counts in
`mykronos parity`, and its refusal to bless a migration where the new system covers nothing

## The lesson, in one line

**Ordering states so they can be compared is a modelling decision, and the states that
carry no information about the question will be assigned an order anyway — one that
looks reasonable and answers a different question than the one being asked.**

## What happened

The parity check exists to answer exactly one question, at the only moment it can be
asked: *may this Concourse pipeline be deleted?* Once it is gone, the old system cannot
be consulted again, so the check compares each capability's state under both systems and
refuses if any got worse.

"Worse" needed an ordering, so `_STATE_RANK` put the seven states on a line:

    no_job(0) never_reported(1) silent(2) not_run(3) reporting(4) event_driven(4) not_enabled(4)

Four of those positions are real. Three are invented — and the invention is `not_run`
above `silent`. It reads as sensible: `silent` is a lane visibly failing to report, and
`not_run` is a lane that has simply not fired yet, which sounds more innocent. But
"innocent" is not the question. *Covered* is the question, and neither state is covered.

So `mykronos parity ToddGBenson/keel` printed:

    atlas    no_job  -> not_run  improved
    sast     silent  -> not_run  improved
    secrets  silent  -> not_run  improved

    No capability is worse under Actions.

Exit 0. Three capabilities improved. Every Actions lane on keel had never executed once.

The sentence was true, which is what made it dangerous. Nothing *was* worse — keel's
Concourse lanes had been `silent` for as long as anyone had looked, so both systems
covered nothing and agreed about it perfectly. A check written to prevent coverage
being lost in a migration cannot see a repository that had no coverage to lose, and it
reports that blind spot in the vocabulary of success.

## Why the ordering went wrong

Ranking is seductive because it makes an awkward question decidable. Seven states and a
`<` operator produce a crisp boolean, and the crispness hides that four of the seven were
ordered by how they *sound* rather than by anything measured.

The states genuinely divide in two: `reporting` and `event_driven` mean findings are in
the lake, and `no_job`, `not_run`, `never_reported`, `silent` and `not_enabled` mean they
are not. The second group differs in **what a human should go look at** — a missing job,
a paused lane, a broken uploader — which is worth rendering and worthless for comparing.
Sorting a diagnostic axis and reading it as a coverage axis is the whole defect.

`not_enabled` shows the same error with the opposite sign. It sat at the top, level with
`reporting`, on the reasonable grounds that a capability nobody asked for is not a gap.
True when both sides agree — and that case still compares as `same`. But it also meant a
capability reporting under Concourse that merely never got enabled in the Actions ledger
passed the gate in silence. Forgetting to enable something is the single most likely
migration mistake, and it presents exactly as a capability nobody asked for.

## The rule

- **Rank on the axis the decision turns on, and refuse to rank on any other.** If two
  states are indistinguishable to the question, they compare equal — even when one is
  obviously more alarming to a human.
- **A gate that can only detect loss cannot detect absence.** "Nothing got worse" is
  satisfied by two systems that both do nothing. State the absolute before the relative:
  what is covered now, what was covered before, and only then what changed.
- **Say "no better" out loud.** The verdict vocabulary had `same`, `improved` and
  `REGRESSED`, so a change that was neither better nor worse had to be called one of
  them, and `improved` was the default. A missing word in an enum is a wrong answer
  waiting for an input.

## What now enforces it

- `_covers()` is a two-tier predicate, not a rank; moving between uncovered states is
  `no better`, never `improved`.
- `not_enabled` is uncovered, so `reporting -> not_enabled` is a regression, while
  `not_enabled -> not_enabled` stays `same`.
- `mykronos parity` prints covered-count on both sides before its verdict, and exits 1
  when the new system covers nothing — "that is not parity, it is two systems agreeing
  about silence."
- `test_a_lane_that_has_never_run_is_not_an_improvement_on_a_silent_one` and
  `test_disabling_a_reporting_capability_is_a_regression` hold both halves.

## Promotable

Yes, and beyond CI. Any migration gate, SLO comparison, or before/after diff that maps
heterogeneous states onto one axis will acquire invented positions at the boundaries
where the axis stops meaning anything. The test to carry: for each pair of states your
comparator calls unequal, name the measurement that separates them. If the answer is how
they sound, they are equal.
