## D-172 — TheHub's Concourse jobs queue in three serial lanes, not one

**2026-10-22.** **Status:** Decided, awaiting merge and measurement
**Story:** TheHub #60928 (mykronos#286 remainder) · Refs D-053, D-055

**The problem.** Every build and scan job in `deploy/concourse/pipelines/thehub.yml`
shared `serial_groups: [worker]`, so a develop commit's unit tier, six
scanners and DAST ran one after another: 62-81 minutes from commit to the last
scan (525152ee +81m, 3f392e89 +78m). Concourse's own build records for
2026-10-21/22 also show 10-20 minute gaps where `build` or `containers` waited
behind post-merge or another commit's scanners.

**Why it was one lane.** Seven jobs at once on the quickstart container, which
was web node and worker in one, took the box to 1.1 GB free and the kernel
OOM-killed Concourse itself. D-055 has since split the web node out and given
the estate two workers, each capped at 6 CPUs and 6g, so an OOM now kills a
build inside one worker's cgroup rather than the scheduler. D-055 recorded
that TheHub's single lane was the part it did not fix.

**The decision.** Three lanes, so at most three heavy jobs run at once:

- `unit-chain`: unit, build, containers. `build` is `passed: [unit]` and
  `containers` is `passed: [build]`, so this is the commit's critical path and
  nothing else queues in it. Median 19.0 + 5.4 + 4.3 = 28.7 minutes.
- `scanners`: qa, secrets, sast, dependencies, iac, prompt-evals, ai-models and
  remediate. About 21 minutes of median work, run while the unit tier runs.
- `dast`: every DAST lane (dast-demo, dast-prod, dast-edge, dast-staging,
  api-inventory, functional-demo), which the story asked to keep on its own,
  plus the jobs that are not on a commit's clock: post-merge (half-hourly),
  image-refresh (daily) and cicd-drift (quarterly). This lane has nothing to do
  for a commit's first ~35 minutes, until deploy-demo passes, so post-merge
  grading the same commit no longer pushes `build` back by up to 15 minutes.

The story's suggested two-way split (DAST, then everything else) would not
reach the target: the unit tier plus the scanners in one queue is still ~50
minutes of median work. Gating was not touched: `build` still waits for
`unit`, and oracle-gate and deploy-demo still wait for every scanner.

**How it is held.** `backend/tests/test_thehub_serial_lanes.py` replays one
commit through the pipeline as written (triggers, `passed:` and serial groups)
with medians of the last 50 succeeded builds of each job, and fails when the
last scan lands at or after 30 minutes, when post-merge's p90 arriving with the
commit pushes it there, when a scanner shares the unit tier's lane or DAST's,
when a heavy job loses its lane, or when a fourth lane appears.

**What it does not prove.** The replay is a projection and the margin is thin:
28.7 minutes against 30 at medians, and the unit tier's p90 is 45 minutes. The
same replay of the old single lane gives 51-67 minutes where Concourse measured
62-81, so it under-counts. The acceptance criterion - three consecutive
develop commits under 30 minutes - can only be read off Concourse after this
merges and `set-pipeline` applies it. If the unit tier's run time is the
binding constraint after that, the next lever is the unit tier itself, not
another lane. If two unit tiers at once (unit and post-merge, on separate
workers) press the host's memory, rolling back is renaming all three lanes to
`worker`.
