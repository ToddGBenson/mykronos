## D-152 — A pull request's evidence is compared against its base branch as it is now

**2026-10-11.** **Status:** Decided, implemented
**Spec:** [34 §4.2, §6.1](../../specs/34-duties-delegation-and-independent-approval.md) ·
follows [D-149](D-149-approval-queue-and-one-file-per-decision.md)

**The rule.** The `pull_request_merge` evidence lists what the head changes
since its merge-base with the base branch *as it stands when the evidence is
frozen*. That is GitHub's compare endpoint, `GET /compare/{base}...{head}`,
with `base` the branch name. It is no longer `/pulls/{n}/files`.

**Why.** The approval queue's first live run merged main into #775
(`910629b2` -> `37adbb13`). The evidence frozen for the new head listed 42
files for a 9-file change: `.gitattributes`, `approval-policy-v1.yaml`,
`approval-queue.ps1` and the rest of what main had gained. #777 did the same.
The operator was asked to approve main's changes as the PR's, and rightly
declined.

Measured on #775 after the run:

| source | files |
|---|---|
| `/pulls/775/files` and the PR's `changed_files` | 42 |
| `compare/75fa5043...37adbb13` (the PR's `base.sha`) | 42 |
| `compare/main...37adbb13` (merge-base `49d9a1d2`, main's tip) | 9 |
| `git diff $(git merge-base origin/main head) head` | 9 |

GitHub had left the pull request's `base.sha` at `75fa5043`, the main it was
opened against, while main had moved on. Both the file listing and
`changed_files` are measured from that stale base. The bug was the
platform's, not the queue's display: the queue showed exactly what the
platform froze.

**What changed.**
- `GitHubClient.compare` (REST and fake). `PullRequest.base_branch` is read
  from `base.ref`.
- `snapshot` builds the file list from the comparison and records
  `base_branch` and `merge_base_sha` in the evidence. A reviewer can see what
  the diff was measured from.
- A listing is incomplete when the comparison hits GitHub's 300-file cap.
  It is no longer judged by `changed_files > listed`. That count shares
  `base.sha`'s staleness, so after the fix it would have marked #775's
  correct 9-file listing incomplete and classed every merged-main-in
  production PR as governance.

**Test.** `test_pull_request_evidence_base.py` uses real git behind a fake
GitHub that answers each endpoint the way GitHub computes it: the PR changes
A, main changes B, main is merged in from either side. The evidence lists
only A.

**Known limit.** The comparison lists at most 300 files, where the old
listing went to 3,000. A larger PR is classed as the strictest tier with the
listing marked incomplete, as before, but that now happens at 300 files.
