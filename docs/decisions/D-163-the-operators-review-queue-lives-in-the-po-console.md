## D-163 — The operator's review work moves into the Product Owner console: a review queue and review packet first, verification checks as data next

**2026-10-14.** **Status:** Design decided. Slice 1 (the read-only review queue and review packet) implemented in this change; the rest is the order below.
**Spec:** extends [spec 35 §8.2](../../specs/35-product-owner-tab.md) and D-144 · applies [spec 34 §4](../../specs/34-duties-delegation-and-independent-approval.md) · relates to [`../approvals.md`](../approvals.md)

**The problem.** The product owner's role in spec 33/34 is the human second
party: agents request, a person decides, and an agent never approves its own
work. The work of that role has been done from operator-run PowerShell outside
the platform. Over 2026-10-13/14 four scripts grew up around it: one that walks
pending approvals, one that answers "what do I need to do" (decide, then merge
PRs whose `independent-review` passed, then the post-merge host steps), and two
one-off rollout walkers. `scripts/approval-queue.ps1` (PRs only) and
`scripts/review-inbox.ps1` (#841, every duty, with an AGREE/CHECK/WAIT
recommendation) are the in-repo versions. What made them useful:

1. **A verification check per request.** A question ("is every BASE_IMAGE
   pinned by tag and digest?") and a command whose output is the answer,
   shown before the claim.
2. **A review packet.** The platform reviewer's verdict, the check's output and
   the requester's claim, in that order, each labelled for what it is. The
   decision posts the frozen evidence's digest. Agreeing with the reviewer is
   recorded as concurrence quoting it; disagreeing needs the person's words.
3. **One queue.** Decisions, then merges, then post-merge steps, re-runnable,
   asking before each.
4. **An adversarial verifier.** Before the person decides, a fresh-context
   agent that did not write the request tries to disprove each claim with
   direct evidence. On 2026-10-14 it caught a materially wrong risk-acceptance
   justification and a real bug in a PR that 20 structural tests missed.

Scripts hold none of this where the platform can see it. The checks are
hard-coded by subject-ref prefix in a file on one host, their output is never
kept, and the queue's state lives in a terminal.

**How each maps into the app.**

**(a) Verification checks become data on the request.** The requester declares
them at creation: a question, and a check from a fixed catalogue the platform
knows how to run (read a file at a ref, grep a ref, read compose, read a PR's
checks, inspect a running container's user or ports). The platform runs them,
never the requester, and freezes question, check and output into the evidence
bundle before the digest is taken. So an approver decides against the output
the platform observed, and a later re-run that differs is a new request.
- Free-form shell commands are not accepted. A command the requester writes
  is the requester's claim in another form, and running it inside the
  platform's trust boundary is code execution.
- Host checks (Windows firewall rules, Docker Desktop's profile) stay in the
  operator's scripts. The platform cannot see them, and saying it did would be
  a false observation.
- A request may declare none. The packet then says "no verification check
  declared" rather than leaving the space blank.

**(b) The review packet is a PO console page** (this change):
`/product-owner/review-queue/{id}`, from
`GET /api/dashboard/product-owner/review-queue/{request_id}`. It shows four
sections and keeps them apart:
1. the claim, labelled as a claim;
2. the frozen evidence, with whether it still hashes to its digest and the
   policy's `reviewer_instructions` for the duty, which is the platform's
   question and never the requester's;
3. the reviewer's verdict, rationale and per-claim checks, as advice;
4. the decisions so far and the decision control.

The control is the repository tab's own `DecideApproval` (D-144). It posts the
digest the page rendered, and the engine applies every rule for the tier. A
request that names no onboarded repository is decided through
`POST /api/approvals/{id}/decisions`, and the packet says so. The rationale
box is empty: the person's words are their own. A "concur with the reviewer"
control, which records concurrence quoting the reviewer's rationale and its
timestamp the way `Review-PendingApprovals.ps1` does, is slice 3.

**(c) The operator queue is a PO console page** (this change):
`/product-owner/review-queue`, from `GET /api/dashboard/product-owner/review-queue`.
- **Pending decisions** across the whole estate, soonest expiry first, each
  with its summary, claim, digest and the reviewer's standing.
- **Approved pull requests still open**, with GitHub's live answer:
  - `ready`: at the approved head, with the check posted;
  - `new_commits`: the approval no longer covers the head;
  - `unknown`: not onboarded, or GitHub did not answer.

  Merged and closed PRs drop out.

Merging stays outside the app: the console never holds a merge-capable
action. Post-merge and deploy steps (apply compose pins, unseal Vault) are host
operations. They join the queue as **declared, not executed** items: a PR may
name its operator steps, and the queue lists them once it merges, until a
person marks them done (slice 4).

**(d) The adversarial verifier is a second mode of the platform reviewer, not
a new actor.** It is started by the platform under the same rules: its own
single-use credential, `platform_started`, fresh context, the frozen bundle
only. It differs in its instruction. The reviewer is asked whether the action
should go ahead; the verifier is asked to disprove each claim in the requester's
statement and the declared checks, and to return one entry per claim:
`{claim, holds, evidence}`. Its record sits beside the reviewer's, as advice,
and it never writes an `ApprovalDecision`. So it cannot satisfy a duty, and
`distinct_principal` against the requester holds by construction. The packet
puts it between the claim and the reviewer. The reviewer's existing `checks`
output (claim / holds / note) is the same shape, and this change already
renders it, so the verifier needs a prompt and a record, not a new view.

**Relationship to `review-inbox.ps1` (#841).** That script is the operator's
CLI over the same requests, and its rules (WAIT on a red check, CHECK on a
reviewer reject, governance rejects as advice, the risk-acceptance flags)
live in `scripts/review_inbox.py`. This change does not compute a
recommendation, so it cannot contradict one. Where both say something, they
agree:
- a reviewer reject on a human-only tier is advice, here as `delegable: false`
  (the shadow report's own rule);
- a request whose PR moved past its head is not "ready" in either.

Slice 2 moves the recommendation rules into the backend package, where the
image can import them. The console then shows the same AGREE/CHECK/WAIT and
the script reads it from the API instead of recomputing it.

**Invariants, unchanged.**
- An agent never approves its own work. The queue and packet only read, and
  every decision still goes through `engine.decide`.
- The person's rationale is their own words.
- Evidence is digest-frozen, and the packet shows a mismatch rather than
  hiding it.
- The browser holds no token. The Next server makes both reads with the token
  it already has, behind the perimeter gate.

**Authorisation.** Both routes are `PrincipalDep` reads, classified `principal`
in `test_route_authz_matrix.py`. A viewer may read them, as it may read the
per-repository inbox and `/api/approvals/{id}/evidence`.

**Order of the remaining slices, by value for size.**
1. *(done here)* Read-only review queue and review packet.
2. Recommendation rules from #841 moved into `mykronos/approvals/`, served
   on the queue, and `review-inbox.ps1` reading them from the API.
3. Concurrence: a "concur with the reviewer" control that records the
   reviewer's rationale quoted and attributed, and is offered only when the
   person's verdict matches the reviewer's.
4. Verification checks as data: a catalogue of platform-run checks declared at
   creation, frozen into the evidence before the digest is taken.
5. The adversarial verifier mode, run on request and by the shadow sweep.
6. Declared post-merge operator steps on the queue.

**Rejected.**
- *Running the requester's shell commands in the platform.* It is remote
  code execution chosen by the party being checked.
- *A decide button on the queue list.* A decision belongs on the page where
  the evidence is, and the list shows a summary.
- *Merging from the console.* It would put a merge-capable credential behind
  the dashboard's single gate, and the scripts do it fine with `gh`.
