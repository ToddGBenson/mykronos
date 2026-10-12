## D-158 — Decision numbers are checked across open pull requests, and the queue refuses a duplicate

**2026-10-11.** **Status:** Decided, implemented (TheHub #60726)
**Spec:** follows [D-149](D-149-approval-queue-and-one-file-per-decision.md) ·
scheme: [decisions/README.md](README.md)

**The problem.** One file per decision (D-149) ended the merge conflicts in
the log, but not duplicate numbers. Two sessions writing at once each take
"one past the highest on main" from the same main. On 2026-10-11 that
happened four times across open PRs: D-136 to D-139 once, and D-153 three
times. `test_decisions_log.py` passed on every branch, because each was
consistent with the main it started from. A duplicate only shows when the
second PR merges, and by then both numbers are cited.

**The decision (option C, plus a queue guard).**
- `scripts/check_decision_numbers.py` compares what every open PR adds with
  main and with each other:
  - A number is *added* when it is in the PR's head tree but not at its
    merge-base with main, counting both the log's `## D-nnn` headings and
    `docs/decisions/D-nnn-*.md` filenames.
  - Measuring trees rather than diffs means the transition's appended
    entries count, and the later move from log to file
    (`move-decisions-to-files.py`) adds nothing.
  - A collision names both sides and suggests the next free number above
    main and every open PR. Between two PRs, the later one renumbers.
  - `--next` prints the number to take. `--head HEAD` checks a branch that
    has no PR yet.
- **The approval queue** runs it on each round, in merge order, before any
  decision. A PR is refused when it repeats a number main already has, or
  one added by a PR earlier in the round that was not itself refused. The
  queue reports "renumber D-nnn -> D-mmm", not a test failure. The queue's
  copy finds the script beside itself, or in the repository.
- **A pre-push hook** prints the same line when a pushed branch adds a
  decision. It is a hint, never a block: it needs `gh` and the network, and
  the queue is the guard that holds.
- The script is `governance` in `change_classes`, beside the rest of the
  queue.

**Not done: a CI lane.** The Concourse `source` resource tracks `main` only,
so no lane sees a pull request's head. A lane on main would report other
PRs' collisions as main's failure. If a pull-request resource is added to
the pipeline later, the script needs nothing more than `--pr` to run there.

**Rejected.**
- *Number by date or by hash instead of a sequence.* Every existing citation
  is `D-nnn`, and the sequence is how a reader finds "the next one".
- *A reservation file on main that a PR must claim first.* That is one more
  merge for every decision, and the claim itself would conflict like the old
  log did.

**Measured when written, and the check's first catch.** The open PRs were
#775 (D-150), #780 (D-153), #781 (D-154) and #782 (D-156), with main at D-152.
The check found no collision, and this entry took D-157. By the time it was
committed, #784 had opened with D-157. Run on this branch, the check said
`HEAD (feat/decision-number-check) adds D-157, but #784 also adds it: renumber
D-157 -> D-158`. Hence D-158.
