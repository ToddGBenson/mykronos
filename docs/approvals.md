# Approvals: how to use them

Specs 33 and 34 made risk acceptance and pull request merge **governed
duties**: someone independent of the requester approves, the platform records
who, and the approval is of exactly the evidence the platform froze. This page
is the operator's runbook. The specs say why.

All calls go to the backend on `127.0.0.1:8100` with the perimeter header
`X-Hub-Token` and a bearer credential. A person uses the admin token; an agent
uses its own `mka_` credential (`POST /api/agents/credentials`).

## Who can approve what

`approval-policy-v1.yaml` is the only source. In short:

| Duty | Tier | Approver |
|---|---|---|
| `risk_acceptance` | critical | a person |
| | high | a person, or a delegated agent of a *different* model family |
| | medium, low | a person, or a delegated agent |
| `pull_request_merge` | governance | a person |
| | production, routine | a person, or a delegated agent |
| `delegation_grant` | any | a person, requested by a person |

The requester never approves their own request. An agent's sub-agents are in
its lineage and cannot approve for it either. Under `single_operator` a person
may approve their own request after the tier's cooling-off; every such
decision is flagged `same_person`.

## Deciding a request

```
GET  /api/approvals?state=pending          what is waiting
GET  /api/approvals/{id}/evidence          the frozen bundle and its digest
POST /api/approvals/{id}/decisions         {"verdict", "rationale", "evidence_digest"}
GET  /api/approvals/{id}/chain             the hash-chained history, verified
```

`verdict` is `approve`, `reject` or `needs_info`. A rationale is required. The
digest must be the one from the evidence call: a decision about anything else
is refused. Requests expire after `request_ttl_hours` (7 days).

## Risk acceptances

`POST /api/risk-acceptances` proposes a record and opens its approval request
in one call; the tier comes from the record's residual severity. Nothing about
the findings changes until the request is approved. A rejected or expired
request closes the record as `not_approved` on the next sweep and releases its
findings.

Legacy row-level acceptances migrate as proposed records:
`POST /api/risk-acceptances/migrate-legacy` with `dry_run` (default true) and
`severities` to stage it.

## Pull requests

`POST /api/approvals/pull-requests` with `{repo, number, statement}`. The
platform reads the diff itself, computes the tier from the files touched
(`change_classes` in the policy), and posts an `independent-review` check run
on the head commit: in progress, then success or failure. The approval covers
that commit only; a new push needs a new request.

The check's summary names the requesting and approving principals. That is
the record an audit cites, because every GitHub action reads as one shared
account.

## Letting an agent approve

1. A person proposes a delegation: `POST /api/approvals/delegations` with the
   duty, tiers, model families and an expiry (at most 90 days).
2. A person approves that request after its one-hour cooling-off.
3. `POST /api/approvals/{id}/independent-review` then starts a
   platform-started reviewer for a request the delegation covers. It needs
   `MYKRONOS_REVIEWER_API_KEY`; without one it answers 503 and the request
   waits for a person.

Nothing starts that reviewer on its own in `live` mode: the shadow sweep runs
only in `shadow`, and the live reviewer runs when something calls step 3. The
approval queue below is what calls it. Starting a review is not choosing the
reviewer, so the queue may: the platform picks the model, the instructions and
the evidence.

`scripts/enable-agent-reviewer.ps1` does all three steps for
`pull_request_merge`, production and routine only (D-149):

- it stops first unless `MYKRONOS_REVIEWER_API_KEY` is set in `backend/.env`
  and compose passes it. `ANTHROPIC_API_KEY` in `backend/.env` does not reach
  the container;
- it proposes the delegation for the reviewer's model family
  (`MYKRONOS_REVIEWER_MODEL`, default `claude-opus-5`) with sampling 0.2 and a
  30-day expiry. Run it again after the one-hour cooling-off and it shows you
  the proposal and approves it with your decision;
- it sets `MYKRONOS_REVIEWER_MODE=live`, recreates the backend on the image it
  already runs, and checks that the backend reports `live`.

Fresh-context independence is not something a caller can assert: the
reviewer's credential is minted by the platform with `platform_started` set,
and `fresh_context` refuses every agent approver without that flag.

A share of delegated decisions is sampled for you to review afterwards
(`GET /api/approvals/samples`, `POST /api/approvals/samples/{decision_id}`).
A delegation is suspended when your agreement drops below 90% of recent
samples, or when samples sit unreviewed past 14 days.

Review samples with `scripts/approval-queue.ps1 -SamplesOnly`, which shows each
sampled decision and its rationale and records your agree or disagree. The
queue also offers them at the end of every run.

## The approval queue

`scripts/approval-queue.ps1` (operator-run, PowerShell 7) replaces approving
one PR at a time. Name the PRs in the order to merge, or pass `-All` for every
open PR, oldest first:

```
.\scripts\approval-queue.ps1 770 773 774
.\scripts\approval-queue.ps1 -All -DryRun     # the plan and the routing; nothing changes
```

It works in rounds. Each round:

1. **Brings every PR up to date, but only where it conflicts.** `main` does not
   require branches to be current, and a new head costs a new request, so a PR
   that is only behind is left alone. A conflicting PR is merged with
   `origin/main` in a temporary worktree, from main's side, with
   `docs/DECISIONS.md` merged by `merge=union` (`.gitattributes`). The merged
   log is read back (main's entries intact and first, no number taken twice,
   the branch's own entries ascending), `test_decisions_log.py` runs, and the
   result is pushed with `--force-with-lease`. It descends from the PR head, so
   the push is a fast-forward. Branches named `main`, forks and drafts are
   refused.
2. **Waits for the platform's request** on each current head, polling.
   `job:pull-request-requests` opens one about ten minutes after it first sees
   a head.
3. **Decides.** Governance requests come to you. So do production and routine
   requests unless the reviewer is `live` and a delegation covers the tier, in
   which case the queue asks the platform to start its reviewer. All of yours
   arrive in one batch: each PR's evidence summary first, then one y or n per
   PR, with a default rationale built from the evidence that you accept with
   Enter or replace.
4. **Merges** each approved PR in order once `independent-review` is green on
   its head (`gh pr merge --squash --match-head-commit`), and fast-forwards
   local `main`. A PR that the previous merge made conflict goes to the next
   round.

A failure skips that PR, with the engine's own message, and the queue carries
on: a conflict outside the decision log, a wrong union result, a red check, or
a refusal. Tokens come from `backend/.env` and are never printed. Every step is
logged to `~/approval-queue-logs/`.

**What union does not fix.** GitHub's merge button runs no merge drivers, so
two open PRs that both append to the decision log still conflict on GitHub.
Each merge therefore re-heads the next such PR, and that PR waits one more
request cycle (about ten minutes) and one more decision: an unattended one when
the reviewer decides it, another prompt when you do. PRs that do not touch the
log merge in the same round. D-149 records the follow-up that removes this.

