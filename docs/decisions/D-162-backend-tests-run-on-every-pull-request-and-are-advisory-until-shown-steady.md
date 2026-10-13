## D-162 — Backend tests run on every pull request as `backend-tests`, advisory until two weeks of runs show they are steady

**2026-10-12.** **Status:** Mechanism decided and implemented (TheHub #60747). Whether the check is **required** on `main` is the operator's call. This entry recommends; it does not decide.
**Spec:** amends [D-151](../DECISIONS.md)'s "none of them is required" for this repository's own PRs · follows D-110 and D-136

**The problem.** Nothing tested a backend change before it merged. Concourse
`unit` tracks `main` only (`deploy/concourse/pipelines/mykronos.yml`, the
`source` resource), so pytest ran after the merge. `frontend-pr.yml` runs on
`frontend/**` only. Any automated or model-written fix needs a deterministic
answer on its own head commit before somebody merges it.

**The mechanism: a `pull_request` Actions workflow, `.github/workflows/backend-pr.yml`.**
- One job, `backend-tests`, and that is the check's name. It does the same
  install as Concourse `unit` (`pip install -e ".[dev]"` on Python 3.13), then
  runs `python -m pytest -q -n auto` over the whole suite.
- **Rejected: a Concourse pull-request resource posting a check through the
  D-136 path.** That needs a new resource type, PR-head polling on a worker
  this host already contends for, and a check posted by a second hop. Actions
  minutes are free here because the repository is public (D-117). GitHub
  attaches the check to the head commit natively.
- **No path filter.** The suite reads the decision index, the Concourse
  pipelines, compose, `workflow-templates/` and `specs/`. A docs-only change
  can turn it red. A filtered-out PR also never gets the check, so a required
  check would wait forever: D-110's deadlock.
- **Forks get no secrets.** The trigger is `pull_request`, never
  `pull_request_target`, and the token is `contents: read`. The workflow names
  no secret. `backend/tests/test_backend_pr_workflow.py` asserts all of this,
  along with the check name, the absent path filter and SHA-pinned actions.
- **Performance budgets scaled ×3** (`MYKRONOS_PERF_MULTIPLIER`), as on the
  Concourse lane and for its reason: the spec 05 §9 budgets describe a
  developer's machine, and a shared runner is not one.

**Run time: the full suite, split by `-n auto` and nothing else.**
- 4409 tests took **547s** at `-n auto` on the development host (20 logical
  CPUs, shared with the running stack) on 2026-10-12.
- The Concourse worker measured 218–238s at `-n 6` (D-117).
- A hosted runner has 4 vCPUs, so expect the order of 5–10 minutes. That is
  slower than the frontend check, and acceptable for an answer that arrives
  before merge.
- Not sharded across jobs. A matrix of shards would cost a separate install
  per shard, and it would turn one required context into several. Revisit if
  the first two weeks show runs regularly above 15 minutes.
- No coverage either. D-117 keeps coverage off the gating path.

**Required or advisory: the recommendation for the operator.**

| Option | What it means | Cost |
|---|---|---|
| A. Required now | A rule on `main` requires `backend-tests`. | Untried on hosted runners. Some tests run there that the Concourse image skips: `pwsh` is installed on `ubuntu-latest`. `enforce_admins` is on for this repository (read 2026-10-12), so a flaky first week blocks every PR, the owner's and Dependabot's included. |
| **B. Advisory now, required after two steady weeks (recommended)** | The check runs and shows on every PR. Nothing requires it yet. After 14 days, read the runs. If no run failed on a PR whose failure was not real, add `backend-tests` to `main`'s required status checks. | Two weeks in which a red check can still be merged past. That is the same exposure as today, but now visible. |
| C. Advisory permanently | The check is never required. | It stays detection, never prevention, and an automated fix can merge red. |

**Recommendation: B.** It earns the requirement with evidence rather than
assuming it. The two-week read is concrete:
`gh run list --workflow backend-pr.yml --created ">=<start>" --json conclusion,headBranch,url`.
Then classify every `failure` as real or flaky. Zero flaky failures means
require it.

**What is on GitHub now.** Read on 2026-10-12, `main` requires one status
check, `independent-review` (from app 4551328), and nothing else. This change
adds nothing to it. `backend-tests` is absent from the required list, so the
protection read back from GitHub matches "advisory". Under B, the change is to
add `backend-tests` (from the GitHub Actions app) beside `independent-review`.

**Rejected.**
- *Running only `tests/` for backend paths.* That is the same suite under a
  narrower trigger, and it has the deadlock above.
- *`pull_request_target` so forks get a token that can post results.* It
  runs fork code with secrets. No result here needs posting beyond the check
  GitHub creates itself.
