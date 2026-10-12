## D-159 — The deploy refuses only what the gate refuses

**2026-10-12.** **Status:** Decided, implemented
**Story:** TheHub #60732 · follows D-048 · amends D-126 and #735

**The rule.** `deploy/mykronos/deploy.ps1` refuses a sha only when its
decision has `introduced_blocking` true. That means the commit introduced an
open critical or high, which is the floor the `oracle-gate` job fails on
(D-048). The refusal still yields to `-Force -ForceReason`, and a recorded
override on the decision still clears it.

A `no_go` with `introduced_blocking` false describes the standing backlog. It
is no longer a refusal. The deploy prints a yellow banner with the
recommendation, the effective recommendation, the score and the policy, then
proceeds. The ledger line says `state: "backlog_no_go"`, so the ledger still
shows which case happened. Its other states are `clean`, `refused` with
`floor: true`, `override`, `unjudged` and `unasked`.

**Why.** The gate job and the deploy script disagreed about the same
decision. The job warns on a backlog `no_go` and passes. The script refused
it. Since the backlog score covers the whole estate and not the commit, a
`no_go` there says nothing about the change being shipped. So every deploy
during a `no_go` backlog needed `-Force`, and an override that is needed on
routine deploys stops recording anything worth reading. With one rule in both
places, `-Force` means "this ships despite what the gate refused", and
nothing else.

**Not chosen.**
- *Keep `deploy.ps1` strict.* That leaves the two disagreeing and turns
  `-Force` into routine.
- *Make the gate strict, failing the job on a backlog `no_go`.* D-048 retired
  exactly that: gating on the composite score refused every commit whatever it
  contained, and a gate that refuses everything gets switched off or routed
  around.

The operator chose this rule over both on 2026-10-12.

**Pinned by.** `backend/tests/test_deploy_follows_d048.py` runs the whole of
`deploy.ps1` with `-NoStart` and the gate job's own verdict script, cut from
`deploy/concourse/pipelines/mykronos.yml`, against the same decisions. It
asserts that they refuse exactly the same ones.
