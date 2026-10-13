# Spec 36 — The Agent Contract: A Typed Work Queue, Caveats, Tools, Playbooks and a Track Record

**Status:** Approved for build (operator decision 2026-10-12). Phase 1 is §2–§3; phases 2–4 follow it in parallel
**Depends on:** [34 — Duties, Delegation and Independent Approval](34-duties-delegation-and-independent-approval.md) for identity and permission,
[27 — The Worklist](27-the-worklist.md) for claims, [24 — Ownership, Deadlines and Acceptance Review](24-ownership-deadlines-and-acceptance-review.md),
[33 — Risk Acceptance and POA&M](33-risk-acceptance-and-poam.md)
**Story:** TheHub #60738. The AI-in-the-platform ideas this spec deliberately leaves out are TheHub #60736.

---

## 0. What this spec is against

MyKronos is deterministic, and it is going to stay that way. Nothing in this spec puts a model inside it.
What changes is who operates it. The platform is increasingly worked by agents: they triage, disposition,
file acceptances, repair lanes and open pull requests. Spec 34 gave them an identity and a permission
model. Nothing yet gives them a way to read the platform that is as careful as the platform is.

The evidence is one long session, written up in #319, plus the memory file an agent keeps between sessions
so as not to repeat its own mistakes. Every one of these cost real work, and every one is a fact the API
knew and did not say:

| What the agent got wrong | What the platform knew |
|---|---|
| Treated an open count as "nobody fixed it" | The lane was failing, so nothing *could* close (`briefing.stalled`) |
| Dispositioned DAST findings that reappeared under new ids | DAST finding identity is not stable (#274) |
| Recommended pulling an image to fix container CVEs | `fixed_version` names a patched *package*, not a patched image |
| Reported an atlas version as the running one | `version_basis` said `declared_floor` |
| Read "true_positive" as a judgement | `classify()` derives it from severity alone |
| Read "nothing paused" when Concourse could not be asked | The briefing's `paused_unknown` was true; the API did not carry it |
| Rotated a token flagged `unverified` | D-097: unverified means "check scans arrive", never "rotate" |

Nine dashboard surfaces answer nine questions well. An agent arrives with one: *what needs doing, and what
don't you know?* It assembles the answer by hand, and each assembly is a new chance to drop an `_unknown`
flag or misread a label. This spec makes that answer a single typed response, and makes every known trap a
field on it.

## 1. The division of labour

**The platform decides three things, and the agent decides none of them:**

1. **What is true.** Lane state, finding state, what a scanner said, what could not be read.
2. **What is allowed.** The duties in `approval-policy-v1.yaml`. The work queue names the duty that governs
   each action; it never grants anything.
3. **When something is done.** A finding closes after two consecutive successful scans observe its absence.
   An agent cannot mark work complete. Each work item says what "done" will look like, so the agent knows
   when to come back rather than when to declare victory.

**The agent supplies judgement and asks permission.** It chooses *how* to do an item, writes the code or the
evidence, and requests the approval the item names.

The queue's order is deterministic and the agent should follow it. A dead lane comes before the findings in
it, because work on a frozen finding cannot be observed. That ordering is the briefing's own reasoning
(D-098), not a new one.

## 2. The work queue — `GET /api/agent/work` (phase 1)

A read. It does nothing, starts nothing, and is safe to call on every loop. Any principal may read it. The
actions it lists are not filtered by permission, because the routes they name enforce their own rules; a
finding another principal has claimed is left out, because working it would duplicate theirs.

### 2.1 The response

```
WorkQueue
  generated_at
  principal              who the queue was computed for (actor, kind)
  items[]                ordered; the agent works from the top
  waiting[]              things that need no action and must not be touched
  unknown[]              sources that could not be read, each with why
WorkItem
  item_id                stable: the same subject yields the same id on every call
  kind                   see §2.2
  band                   1 (platform) .. 6 (findings); the ordering's first key
  severity               where the subject has one
  repo_full_name         "" for estate-wide items
  title, summary
  evidence[]             {source, ref, detail}: where each fact came from
  preconditions[]        {description, met, blocked_by}: blocked_by is another item_id
  actions[]              {label, method, path, governed_by, effect}
  done_when              what the platform will observe when this is finished
  caveats[]              {code, detail}: see §3
```

**`unknown` is not an empty list.** A source that could not be read appears there and nowhere else. A queue
with no lane items and `unknown: [concourse]` says "I could not ask CI", which is a different sentence from
"CI is fine". The briefing already makes that distinction internally; this is where it reaches an agent.

**`governed_by` names the duty the action will be routed through for *this* principal**, for
example `finding_disposition` when an agent would close a high finding, or `null` when the route is a direct
write. It is computed with the same function the route uses (`finding_disposition.governed`), so the two
cannot disagree. The agent learns before it asks whether a person will be involved.

### 2.2 Kinds and order

| Band | Kind | Source | Done when |
|---|---|---|---|
| 1 | `lane_stalled` | `briefing.stalled` (failing, silent or blocked) | Two successful runs of the lane |
| 1 | `ci_job_failing` | Concourse, jobs failing and not paused | The job's latest build succeeds |
| 1 | `ci_job_paused` | Concourse, paused jobs | The job is unpaused and its next build succeeds |
| 1 | `platform_job_unhealthy` | `job_runs`, assessed by `platform_health` | The job's next run succeeds |
| 2 | `toxic_combination` | `toxic.detect` | Any one member closes and the combination stops firing |
| 2 | `public_exposure` | `exposure.summary`, endpoints with a high or critical observation | The next probe observes nothing at that severity |
| 3 | `approval_needs_info` | The principal's own requests answered `needs_info` | The request is decided |
| 4 | `acceptance_attention` | Acceptances `review_due`, `premise_failed`, with scope drift, or expiring within 14 days | Renewed, revoked or closed |
| 5 | `token_delivery` | Tokens the rotation sweep deferred to a person | Rotated (`due`) or a scan confirmed arriving (`unverified`) |
| 6 | `triage` | The ranked triage queue, unclaimed or claimed by this principal | The finding is dispositioned or two scans observe it gone |

Within a band, items sort by severity, then by how many findings they hold, then by `item_id`, so two calls
with the same state return the same order.

A `triage` item whose lane is stalled keeps its place but carries an unmet precondition naming the lane's
item, and the `lane_frozen` caveat. The agent can still read and triage it; it is told that a fix will not
show until the lane is repaired.

**`waiting`** holds findings already absent from their lane's newest successful scan (`awaiting_closure`) and
the principal's own requests still pending a decision. Both need nothing; touching either is wasted work.

**Every path can be called.** Repository-scoped routes take the onboarding id, not `owner/repo`. The briefing
prints its lane actions with the full name, which cannot route (TheHub #60739); the queue rewrites them, and
offers no action for a repository with no onboarding row rather than a dead one.

### 2.3 What the queue does not include, yet

`unread` lanes (B-051) need a live GitHub read per repository and are left to the briefing. Patchwork's
draft pull requests and an agent's own open PRs are phase 3, where playbooks give them steps. Network and
cloud findings are absent because the lake has never held any; `toxic.coverage()` already reports that, and
the queue carries its uncovered rules as a caveat.

## 3. Caveats (phase 1)

A caveat is a code an agent can branch on and a sentence a person can read. Codes are stable; sentences may
improve.

| Code | On | Meaning |
|---|---|---|
| `lane_frozen` | `triage` | The finding's lane is stalled. Nothing done to it will be observed until the lane runs. |
| `identity_unstable` | `triage`, DAST | DAST findings get a new id each scan (#274). A disposition will not follow the finding. |
| `fix_is_a_package` | `triage`, containers | A fixed version is a patched package, not a patched image. Compare digests before recommending a pull. |
| `declared_version` | `triage`, atlas | The version is the declared floor or pin, not the resolved one. The running version may differ. |
| `severity_only_triage` | `triage` | The `true_positive` label comes from severity alone; nothing read the code. |
| `do_not_rotate` | `token_delivery` | An `unverified` token is a reason to check scans arrive, never to rotate (D-097). |
| `partly_accepted` | `toxic_combination` | A member is an accepted risk; the combination still counts. |
| `rules_cannot_fire` | `toxic_combination` | Rules whose inputs never reach the lake; "no combination" from them is not evidence. |
| `probe_stale` | `public_exposure` | The last probe is older than two probe intervals. |

## 4. Tools — the MCP server (phase 2, closes #319)

An MCP server that wraps the API under the agent's own `mka_` credential. #319 lists the read tools from
experience; this spec adds the queue in front of them:

- **Read:** `work()`, `briefing()`, `findings(...)`, `finding(id)` with the parsed DAST instance,
  `lane_health(repo)`, `pipeline(repo)`, `coverage(repo)`, `whoami()`.
- **Write, few and governed:** `claim(finding_id)`, `disposition(finding_id, status, reason)` which routes to
  `disposition-requests` itself when governed, `accept(...)` through `/api/risk-acceptances`,
  `request_pr_review(repo, number, statement)`.
- **Never:** dispatch, revoke, purge, grant, or anything else that removes coverage or authority (#319's
  rule). An agent that can close findings is already a risk; one that can also stop the scans is a worse one.

Every write tool takes `dry_run`, which answers with the `governed_by` the real call would meet and makes no
change.

## 5. Playbooks as data (phase 3)

`agent-playbooks-v1.yaml` at the repository root, reviewed in a pull request like the other policies. One
playbook per work-item kind: ordered steps, the check between steps, the stop conditions, and when to
escalate to a person with what evidence. Each work item carries `playbook: <kind>@<version>`.

The six times TheHub's scanning stopped become branches of `lane_stalled`: read the failed job's annotation
first, then token, branch, red `unit`, Actions disabled, billing. That knowledge stops living in one agent's
memory file.

## 6. The track record (phase 4)

Computed per agent family and per instance from records that already exist. No new events are needed:

- dispositions overturned when sampled (`ApprovalDecision.sample_*`),
- the agent's pull requests rejected or closed unmerged,
- findings it reported fixed that reopened (`regression`),
- claims that lapsed with no disposition (`worklist`),
- `needs_info` answers per request.

A delegation (spec 34 §5) is then granted against a published record rather than on trust, and sampling and
suspension (`suspend_below_agreement`) already turn a falling record into consequences.

## 7. What this spec does not do

- **No model inside MyKronos.** The independent reviewer (spec 34 §4.3) is unchanged and remains the only
  model call. TheHub #60736 holds the ideas for more.
- **No new authority.** The queue is a read. Every action it lists is an existing route with its existing
  rules.
- **No completion by assertion.** Nothing here lets an agent mark an item done.

## 8. Implementation status

| Phase | Scope | Status |
|---|---|---|
| 1 | §2 work queue, §3 caveats | In this pull request |
| 2 | §4 MCP server (#319) | In review: `backend/mykronos/mcp_server/`, `mykronos-mcp`, [docs/agent-mcp.md](../docs/agent-mcp.md). Not built: `pipeline()` and `coverage()`, which have no route yet (#318) |
| 3 | §5 playbooks | After phase 1 merges |
| 4 | §6 track record | After phase 1 merges |
