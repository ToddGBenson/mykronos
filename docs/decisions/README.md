# Decisions, one file each

From D-137 on, every implementation decision the specs do not settle is its own
file here (D-149). [`../DECISIONS.md`](../DECISIONS.md) holds D-001 to D-136 as
they were written, and the generated index of this directory.

**To record one:**

1. Take the next free number with
   `python scripts/check_decision_numbers.py --next`. It looks at main **and
   every open pull request**: one past the highest in `../DECISIONS.md`, here,
   and anything an open PR adds. "One past the highest on main" is not enough.
   Two sessions writing at once both take it, which happened four times on
   2026-10-11.
2. Write `D-nnn-<slug>.md`, where the slug is lowercase words joined by hyphens.
   The file holds one `## D-nnn — Title` heading, a `**Status:**` line, then the
   decision and why, in the log's usual format. Relative links are from this
   directory: `../../specs/…`, `../approvals.md`.
3. Run `python scripts/decisions_index.py` and commit the file together with
   the updated index.

A decision is superseded by a new file, never edited. `backend/tests/test_decisions_log.py`
fails on a number used twice (across the log and here), a heading whose number
is not the filename's, an index that does not match this directory, and an
entry with no reasoning in it.

## Numbers are unique across open pull requests (D-158)

Each branch passes the numbering test on its own, so a duplicate between two
open PRs only shows when the second one merges. Three places catch it before
then:

- **`python scripts/check_decision_numbers.py`** compares every open PR's
  added numbers with main's and with each other's, using `gh` and git. A
  number is "added" when it is in the PR's head and not at its merge-base, so
  moving an entry from the log into a file adds nothing. Use `--pr N` for one
  PR and `--head HEAD` for a branch with no PR yet. Each collision names both
  sides and the number to take instead, for example
  `#781 adds D-160, but #780 also adds it: renumber D-160 -> D-161 in #781.`
  Between two PRs, the later one renumbers.
- **The approval queue** runs it before each round's decisions. A PR that
  repeats main's number, or one a PR earlier in the round adds, is refused
  with that "renumber" line before anyone is asked to approve it.
- **The pre-push hook** (`python scripts/install_hooks.py`) prints the same
  line when a branch you push adds a decision. It is a hint and never blocks.

No CI lane runs it: the Concourse `source` resource tracks main only, so no
lane sees a pull request's head.
