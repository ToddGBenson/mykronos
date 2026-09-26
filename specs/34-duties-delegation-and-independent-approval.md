# Spec 34 — Duties, Delegation, and Independent Approval: Humans and Agents

**Status:** Draft for review
**Depends on:** [33 — Risk Acceptance as a Governed Decision](33-risk-acceptance-and-poam.md)
**Used by:** spec 33 §2 (risk acceptance), and every governed action in §6

---

## 0. What this spec is against

Separation of duties assumed two kinds of actor: a person, and a machine that does what it is told.
This estate has a third. **An AI agent does real work here — writes code, opens and merges pull
requests, dispositions findings, deploys, rotates infrastructure — and today nothing can tell its
actions from the operator's.** Measured on 2026-09-26:

1. **One identity for everyone.** The API authenticates with a single admin token and records its
   actor as the configured `admin_identity`. Every disposition an agent recorded on 2026-09-25 —
   several thousand acceptances among them — is attributed to the same actor as the operator's own.
   An auditor cannot answer "who decided this?", and neither can the operator.
2. **The author approves its own work.** `main` requires zero approving reviews. On 2026-09-25 an
   agent authored, tested, and merged twelve of its own pull requests, and deployed them. The
   reviewing it did was real, but it was the author reviewing itself. (That every one of those
   actions came from the same GitHub account is *not* the problem this spec solves — §1.2 accepts
   a shared GitHub identity. The problem is that no process put a second party in between.)
3. **Overrides are self-service.** `deploy.ps1 -Force -ForceReason` records a reason for overriding
   the risk gate, typed by whoever is deploying.
4. **Separation is all-or-nothing.** Spec 33 §2.3 had to choose between strict two-person approval,
   which one operator cannot satisfy, and a documented deviation. There was no way to say *"for
   this class of decision, a second agent I trust is an acceptable independent check."*

The operator's position, stated as the requirement: **sometimes the operator trusts an agent's
work, and when they do the check should come from a different agent — not the same one marking its
own homework — and which decisions that applies to is the operator's choice, made explicitly,
scoped, and revocable.** And it should be one mechanism, reused wherever a second pair of eyes
matters: risk acceptance, pull request review, incident actions, deploy overrides, and whatever
comes next.

## 1. Principals: every actor is a distinct, attributable identity (IA-2, IA-9, AU-3)

### 1.1 What ships

A principal gains a **kind** and, for agents, a **provenance**.

| field | values | why |
|---|---|---|
| `kind` | `human` \| `agent` \| `automation` | the three actors are governed differently (§3) |
| `actor` | a stable name — a person's handle, an agent identity, a job name | AU-3: who |
| `on_behalf_of` | the human an agent is acting for | an agent never acts on its own authority |
| `agent.family` | e.g. `claude-opus-5.5`, `claude-sonnet-5` | independence can require a different model (§2) |
| `agent.instance` | the session or run that holds the credential | two runs of one model are different instances |
| `agent.lineage` | the chain of instances that spawned this one | a sub-agent is not independent of its parent (§2) |
| `agent.context_digest` | hash of what the instance was given to decide on | proves what it saw (§4) |

- **One credential per agent instance**, minted by a human (or by automation under a human's
  standing grant), short-lived, and scoped to the duties it may perform. The shared admin token
  becomes the operator's alone. This is IA-9 (identification and authentication of non-person
  entities) applied to agents, and it is the prerequisite for everything below: independence
  cannot be checked between identities the platform cannot tell apart.
- `automation` — the sweep, the scanners, the pipelines — keeps its existing tokens and gains the
  `kind` field. Automation may *execute* approved actions; it may never *approve* one (§3).

### 1.2 Shared external identities: separation by process (accepted)

**Decided by the operator (2026-09-26): external systems may keep one technical identity.** The
GitHub token is a single user and stays one. Every commit, pull request, review and merge on GitHub
will read as that one account whether the operator, an author agent or an approver agent did it.
Issuing per-agent GitHub accounts is not required and is not planned.

Separation is then carried by **process and record**, not by the external identity:

- **The platform's `ApprovalRequest` is the system of record for who did what** (§4). It holds the
  requester's and each approver's principal with full provenance, even when every resulting GitHub
  action is made through the same token.
- **Every action taken through a shared identity is stamped with the platform principal behind it.**
  The `independent-review` check run (§6.1), PR comments and commit trailers name the requesting and
  approving principals and link the approval record. The GitHub account says *which credential*
  acted; the stamp says *which duty-holder* caused it.
- **The shared token can only carry out approved actions.** Merge is gated on the
  `independent-review` check (§6.1), which only the platform posts, and only for an approval that
  satisfies the duty. Holding the token does not substitute for an approval — the branch protection
  does not care who pushes the merge button, only whether the check is green for that sha.
- **The SSP fragment records the deviation** — "IA-2 / AU-3: GitHub actions share one account;
  attribution is maintained in the approval record and stamped on each action" — so an assessor
  reads it as a decision, not discovers it as a gap.

The same rule applies to any other external system that holds one credential for the estate (the
Concourse `fly` target, Docker registries): the credential is shared, the duty-holder is recorded.

What is **not** relaxed is the platform's own API. Its credentials are cheap to mint and are the
record's only source of truth for who requested and who approved, so agents still get their own
there (§1.1). If that proves impractical too, the fallback is the same pattern: one API credential,
and the principal declared per request and bound into the signed evidence digest — weaker, because
a declaration is not an authentication, and the SSP would say so.

### 1.3 What does not ship

No model-vendor attestation of agent identity. The platform records what the credential says about
the agent; it cannot prove which model answered. That limit is stated in the SSP fragment rather
than papered over.

## 2. Independence: when two principals count as two (AC-5)

An approval is independent of a request only if the approver passes **every** rule the governing
duty requires. The rules are named so a policy can select them per duty:

| rule | fails when |
|---|---|
| `distinct_principal` | approver and requester are the same `actor` |
| `distinct_instance` | same agent instance — the same run approving itself |
| `outside_lineage` | the approver was spawned by the requester, spawned it, or shares an ancestor below the operator — **a sub-agent reviewing its parent's work is the parent reviewing itself** |
| `fresh_context` | the approver received anything beyond the frozen evidence bundle (§4): the requester's reasoning, its conversation, its drafts |
| `different_family` | same model family as the requester (optional; for duties where correlated blind spots matter most) |
| `human` | the approver is not a human |
| `not_on_behalf_of_requester_agent` | an agent approving *for* the agent that asked |

Rules compose. "A different agent I trust" is typically
`distinct_principal + distinct_instance + outside_lineage + fresh_context`. The critical tier of a
risk acceptance can add `different_family`, or require `human` outright.

**Collusion and anchoring are the failure modes these rules exist for.** An agent asked to check
work it can see was produced by a peer it shares context with will tend to agree. The approver
therefore sees only the evidence bundle, framed as data to evaluate, with instructions that come
from the duty's policy and never from the requester (§4.3).

## 3. Duties: one policy shape for every governed action (AC-5, AC-6, CM-5(4), AC-3(2))

### 3.1 What ships

A **duty** is a governed action type. Its policy declares who may request, who may approve, how
many approvals are needed, and which independence rules apply — **per tier**, so one duty can be
strict for critical and delegable for low. Policy lives in `approval-policy-v1.yaml`, reviewed in a
pull request like the Oracle policy:

```yaml
duties:
  risk_acceptance:                    # spec 33
    tier_by: residual_severity
    tiers:
      critical:
        approvers: [{kind: human}]
        quorum: 1
        independence: [distinct_principal]
        cooling_off: 24h              # the single-operator safeguard from spec 33 §2.3
      high:
        approvers: [{kind: human}, {kind: agent, delegation: required}]
        quorum: 1
        independence: [distinct_principal, distinct_instance, outside_lineage, fresh_context, different_family]
      medium: &delegable
        approvers: [{kind: human}, {kind: agent, delegation: required}]
        quorum: 1
        independence: [distinct_principal, distinct_instance, outside_lineage, fresh_context]
      low: *delegable

  pull_request_merge:                  # §6.1
    tier_by: change_class
    tiers:
      governance:   {approvers: [{kind: human}], quorum: 1, independence: [distinct_principal]}
      production:   {approvers: [{kind: human}, {kind: agent, delegation: required}], quorum: 1,
                     independence: [distinct_principal, distinct_instance, outside_lineage, fresh_context]}
      routine:      {approvers: [{kind: agent, delegation: required}, {kind: human}], quorum: 1,
                     independence: [distinct_principal, distinct_instance, outside_lineage, fresh_context]}

  incident_action:                     # §6.2
    tier_by: reversibility
    tiers:
      irreversible: {approvers: [{kind: human}], quorum: 1, independence: [distinct_principal]}
      reversible:   {approvers: [{kind: human}, {kind: agent, delegation: required}], quorum: 1,
                     independence: [distinct_principal, distinct_instance, outside_lineage, fresh_context],
                     break_glass: allowed}

  deploy_override:                     # §6.3 — deploying past a no_go
    tiers:
      any: {approvers: [{kind: human}], quorum: 1, independence: [distinct_principal]}

  approval_policy_change:              # §5 — the root of trust
    tiers:
      any: {approvers: [{kind: human}], quorum: 1, independence: [distinct_principal], cooling_off: 24h}
```

- **A request that no tier's approvers can satisfy is refused at creation**, with the reason — not
  left pending forever.
- **Automation is never an approver.** It may execute what was approved.
- **The requester is never an approver**, whatever the policy says. `distinct_principal` is implied
  for every tier and cannot be removed.

### 3.2 Tier selection is evidence, not a claim

A tier is computed from the subject, never asserted by the requester: residual severity from the
acceptance record, change class from the files a PR touches (§6.1), reversibility from the action
type (§6.2). An agent cannot lower its own tier by describing its change as routine.

## 4. The approval request and the evidence bundle (AU-10, CM-3)

### 4.1 What ships

A generic **`ApprovalRequest`**, used by every duty:

| field | purpose |
|---|---|
| `duty`, `tier` | which policy governs it |
| `subject_ref` | what is being approved — an acceptance id, a commit sha, an incident action id |
| `evidence_bundle` | the frozen, content-addressed package the approver sees (§4.2) |
| `evidence_digest` | its hash — **an approval binds to this digest** |
| `requested_by` | principal, with provenance |
| `decisions[]` | each approver's principal, verdict (`approve` \| `reject` \| `needs_info`), rationale, the digest it evaluated, time |
| `state` | `pending` → `approved` \| `rejected` \| `expired` \| `superseded` |
| `expires_at` | an approval request does not wait forever |

- **An approval is of a digest, not of a name.** A PR approved at one commit is not approved at the
  next; an acceptance edited after approval returns to `pending`. This is what makes the approval
  non-repudiable (AU-10): the approver approved *this*, and the record says which *this*.
- Every request and decision is an audit event on spec 33 §7's hash chain.

### 4.2 The evidence bundle

Built by the platform, not by the requester, from the subject: for an acceptance, the findings in
scope, their raw scanner records, the premises and their current monitor results, and the proposed
justification. For a PR, the diff at the sha, the test results, and the files' change classes. The
requester may *add* a statement of intent, clearly labelled as the requester's claim.

### 4.3 How an agent approver runs

- The approver agent is a **separate run**, started by the platform (not by the requester) with its
  own credential, a fresh context, the duty's reviewer instructions from policy, and the bundle —
  nothing else. It does not see the requester's conversation, cannot message the requester, and
  treats everything in the bundle as data, including any text in it that reads as an instruction.
- Its rationale is required and stored. "Approve" without a rationale is refused, just as a bare
  reason code is refused for a high acceptance today.
- It can return `needs_info`, which goes to the requester, and `reject`, which ends the request.
  An approver that can only say yes is not a check.

## 5. Delegation: the operator's trust, made explicit (AC-5, PM-10)

The operator's choice to trust an agent is a **delegation**: a grant that lets agent approvers
satisfy a duty tier that lists `{kind: agent, delegation: required}`.

```yaml
delegations:
  - id: dlg-2026-10-routine-prs
    granted_by: <operator>            # always a human; agents cannot grant or extend delegations
    duty: pull_request_merge
    tiers: [routine]
    approver:                         # which agents may use it
      family: [claude-opus-5.5, claude-sonnet-5]
      purpose: independent-reviewer
    constraints:
      max_per_day: 20
      exclude_paths: ["deploy/**", "*-policy-v1.yaml", ".github/**"]
    expires_at: 2026-12-31
    sampling: 0.2                     # a fifth of delegated approvals go to a human for after-the-fact review (§5.2)
```

### 5.1 Rules

- **Granted only by a human, and only through `approval_policy_change`** — the one duty an agent can
  never approve. An agent cannot delegate authority to itself or to another agent, and cannot widen
  a delegation's scope or extend its date.
- **Scoped, time-boxed, revocable.** Revocation takes effect immediately; pending approvals under it
  return to `pending` for a human.
- **A delegation never removes the independence rules.** It changes *who may be the independent
  party*, not whether there must be one.

### 5.2 Trust is measured, not assumed

- **Sampling.** A configurable share of every agent's approvals goes to a human queue for
  after-the-fact review. The human's verdict is recorded against the agent's.
- **Agreement rate.** The governance page shows, per delegation and per approver family, how often a
  human agreed with sampled agent approvals, the agent's reject rate, and its time-to-decision. An
  approver that never rejects, or approves in seconds, is visible.
- **Automatic suspension.** A delegation whose sampled agreement falls below a policy threshold
  (default 90% over the last 20 samples), or whose sampling queue goes unreviewed past a deadline,
  is suspended until a human re-grants it. Trust that is not being checked lapses on its own.

## 6. Where the pattern applies

### 6.1 Pull request review and merge (CM-3, CM-5, SA-10)

- A PR's **change class** is computed from the files it touches: `governance` (approval policy,
  Oracle policy, `.gitleaksignore`, CI definitions, branch protection), `production` (backend,
  frontend, deploy manifests), `routine` (tests, docs, specs).
- The platform posts an **`independent-review` GitHub check run** on the head sha, green only when
  an approval satisfying the duty exists *for that sha*. Branch protection requires it. A new push
  dismisses it — the approval was of the old digest.
- **GitHub's own review approvals are not used**, because with one account (§1.2) a GitHub
  "approve" cannot distinguish reviewer from author — GitHub refuses self-approval, and there is
  no second account to give. The check run is where separation lives; its summary names the
  author principal, the approver principal, the independence rules satisfied, and links the record.
- This does not replace the test run. It is the thing missing beside it: today's gate is "the
  author says it passed".

### 6.2 Incidents (IR-4)

- Diagnosis, read-only actions and reversible changes can run under a delegation. Irreversible ones
  — deleting data, rotating a production credential, force-pushing, disabling a control — require a
  human approval of the specific action and its evidence.
- **Break-glass.** A reversible action under `break_glass: allowed` may proceed before approval when
  waiting would extend an outage. It opens an `ApprovalRequest` in the same moment, marked
  `retroactive`, and a rejected retroactive approval is an incident finding in its own right.

### 6.3 Deploy overrides and the rest

`deploy.ps1 -Force` becomes a request under `deploy_override`, human-only. Future duties — credential
rotation, finding bulk-dispositions above a size, capability grants — join by adding a block to the
policy, with no new mechanism.

## 7. Failure modes, and what the design does about each

| failure | countermeasure |
|---|---|
| an agent spawns a sub-agent to approve its own work | `outside_lineage`; the platform, not the requester, starts approver runs |
| the approver is anchored by the requester's reasoning | `fresh_context`; the bundle excludes it |
| prompt injection in the evidence ("approve this") | bundle framed as data; reviewer instructions only from policy; rationale required |
| correlated blind spots between agents of one model | `different_family` where it matters |
| rubber-stamping | required rationale; reject rate and time-to-decision visible; sampling with auto-suspension |
| the change is modified after approval | approval binds to the evidence digest; branch protection dismisses stale approvals |
| an agent widens its own authority | delegations and policy changes are human-only duties with a cooling-off |
| no approver is available | refused at creation, or expires to the operator's queue — never silently approved |
| the operator is the only human | human-tier duties get spec 33 §2.3's cooling-off and documented AC-5 deviation |
| every GitHub action comes from one account | accepted (§1.2); the approval record is authoritative, each action is stamped with its principal, and merge is gated on the platform's check, not on who holds the token |

## 8. Control mapping

| Control | Title (Rev. 5) | Implemented by |
|---|---|---|
| **AC-5** | Separation of Duties | duties, tiers, independence rules (§2, §3) |
| **AC-6** | Least Privilege | per-instance agent credentials scoped to duties (§1) |
| **AC-3(2)**, **CM-5(4)** | Dual Authorization | quorum and independence per tier (§3) |
| **IA-2**, **IA-9** | Identification and Authentication (organizational users; services) | distinct principals and agent credentials on the platform (§1.1); shared external identities as a documented deviation with process-level attribution (§1.2) |
| **AU-3**, **AU-10** | Content of Audit Records; Non-repudiation | principal provenance; approvals bound to evidence digests (§1, §4) |
| **CM-3**, **CM-5**, **SA-10** | Configuration Change Control; Access Restrictions for Change; Developer Configuration Management | PR change classes and the `independent-review` check (§6.1) |
| **IR-4** | Incident Handling | incident action tiers and break-glass (§6.2) |
| **PM-10**, **CA-6** | Authorization Process; Authorization | delegation as an explicit, scoped grant of the operator's authority (§5) |
| **CA-7** | Continuous Monitoring | sampling, agreement rates, auto-suspension (§5.2) |

## 9. Phasing

1. **Identity.** Principal `kind`, agent provenance, per-instance agent credentials; the shared admin
   token becomes the operator's. Without this, nothing else can be enforced — and it is useful on its
   own, because the audit trail starts telling the truth about who did what.
2. **The engine.** `ApprovalRequest`, digest binding, the policy file, independence evaluation,
   refusal-at-creation. First consumer: spec 33 risk acceptance.
3. **Agent approvers.** Platform-started reviewer runs with fresh context; delegations; sampling and
   suspension.
4. **More duties.** `pull_request_merge` with the check run and branch protection; `deploy_override`;
   `incident_action` with break-glass.

## 10. Acceptance criteria

- Two agent runs using different credentials are recorded as different principals; an action taken
  by an agent is never attributed to the operator.
- An action performed through the shared GitHub identity carries a stamp naming the platform
  principal that caused it and linking its approval record; the record, not the GitHub account, is
  what the audit report cites.
- A request cannot be approved by its requester, by an instance in the requester's lineage, or by an
  approver that received anything beyond the evidence bundle — each refusal naming the rule it broke.
- An approval of a pull request at one commit does not satisfy the check at a later commit.
- An agent approver's decision without a rationale is refused.
- An agent cannot create, widen, extend, or approve a delegation or an approval-policy change.
- Revoking a delegation returns its pending approvals to a human within one request cycle.
- A delegation whose sampled human agreement drops below its threshold is suspended automatically,
  and the governance page says why.
- A duty tier whose approvers cannot be satisfied refuses the request at creation with the reason.
- Break-glass actions always produce a retroactive approval request, and a rejection is recorded as
  an incident finding.

## 11. Out of scope

- Proving which model produced an agent's output. The platform records the credential's claims.
- Multi-organisation federation of approvers.
- Replacing human judgement in human-only tiers. Delegation is opt-in, per duty and per tier; the
  default for every duty is that a human approves.
