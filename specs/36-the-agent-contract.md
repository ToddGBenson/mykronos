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
| Treated a DAST finding's URL as its identity | Since #440 the identity is the route; the URL is evidence in `raw_finding_json.instance.uri` |
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
  playbook               <kind>@<version>: how to work it, see §5
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
| `identity_is_the_route` | `triage`, DAST | The identity is the route (#440): one disposition covers every URL on it. The scanned URL is in `raw_finding_json.instance.uri`. |
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

### 5.1 As built

**The file.** `agent-playbooks-v1.yaml`, loaded through the `agent_playbooks_path` setting and copied into
the backend image beside the other reviewed files. `version` is quoted text (`"1.0"`), and each item's
`playbook` is `<kind>@<version>`.

```
playbooks.<kind>
  purpose              what the item means and what "done" is
  steps[]              ordered
    id                 stable slug
    do                 what to do
    check              what to confirm before moving on
    routes[]           "METHOD /path" this step reads or calls
    outside[]          evidence outside the API (a gh command, a build log)
    if_found           for a diagnostic branch: what it means when the check finds the cause
    then               continue | repair | escalate | stop
  stop_when[]
  escalate             {when[], evidence[]}
  never[]              what this kind of item tempts an agent to do that it must not
```

**The order in `lane_stalled`** differs from the list above in one place, and on purpose: it reads the
failure first, then checks for a quiet repository (a silent lane in a repository nobody pushed to is idle,
not stalled, and most lanes are commit-triggered), then billing, Actions disabled, a red upstream quality
lane, the wrong branch or a pinned commit, the ingestion token, and a host or Docker restart. Billing and
disabled Actions come before the token because they are read straight off the annotation and stop every job
at once. `ci_job_failing` follows the same order for a single job.

**The kinds are one list.** `agent_work.KINDS` names every kind `build` can emit. `WorkItem` refuses a
kind outside it; `mykronos.playbooks` refuses a file missing a kind or naming one that does not exist, and an
unknown key anywhere (a misspelt `stop_when` would otherwise load as a playbook with no stop conditions).

**The routes are checked.** `tests/test_playbooks.py` walks the app's routes and fails on any route a
playbook names that the app does not serve, naming the playbook and step. Renaming a route without updating
the playbook that sends agents to it fails CI.

**Read routes.** `GET /api/agent/playbooks` (all, in band order) and `GET /api/agent/playbooks/{kind}` (404
for an unknown kind), for any principal. A file that will not load answers 503 on these and on
`/api/agent/work`, rather than a queue whose items name playbooks nobody can read.

**What the file does not do.** It grants nothing: the routes it names enforce their own rules. It is not in
`approval-policy-v1.yaml`'s `governance` change class (that pattern is `*-policy-v1.yaml`), so a change to it
is reviewed at the `production` tier.

## 6. The track record — `GET /api/agent/scorecard` (phase 4)

Computed per model family and per instance from records that already exist. No new events and no new
tables: every number is a read over `approval_requests`, `approval_decisions`, `audit_log`,
`triage_state` and finding status in the lake (`mykronos/agent_scorecard.py`). Any principal may read it,
because it is the record a delegation (spec 34 §5) rests on, and an agent should read the same numbers
the operator does. It carries counts, never rationales or review notes.

**An agent is grouped as its records say.** Approvals, requests and audit entries each snapshot the
agent's `family` and `instance` when it acted, so a revoked credential cannot rewrite its record. A record
with no family is shown under `(unrecorded)`, never dropped. `family` and `instance` filter the
response; a family's aggregate always covers all its instances.

**Every metric carries its source, its denominator, and one of three states.** `computed` has a non-zero
denominator. `no_data` means the source was read and the denominator is zero, so an agent never sampled
has no agreement rate rather than 100% or 0%. `unavailable` means the source could not be read or no
record supports the number, and `note` says which. Neither of the last two is a zero. A source that
fails to read is also named in `unknown`.

| Metric | Value / denominator | Source |
|---|---|---|
| `approver.verdicts` | rejections / decisions as an approver, with every verdict in `breakdown` | `approval_decisions`, `approver_kind = agent` |
| `approver.sampled` | sampled / decisions made under a delegation | same |
| `approver.sample_reviewed` | reviewed by a person / sampled; `awaiting_review` is the queue | same |
| `approver.overturned` | `sample_verdict = disagree` / reviewed samples | same |
| `approver.agreement` | `agree` / reviewed samples, all time | same |
| `approver.agreement_window` | `agree` / the newest `agreement_window` reviewed samples, against `suspend_below_agreement` | same, in `sampling._agreement`'s order |
| `requester.rejected` | rejected / decided (approved + rejected), every state in `breakdown` | `approval_requests`, `requester_kind = agent` |
| `requester.needs_info` | requests answered `needs_info` at least once / requests made | `approval_requests` + `approval_decisions` |
| `dispositions.reopened` | reopened / `false_positive` and `suppressed` dispositions the agent applied | `audit_log` `finding.status` (`actor_kind = agent`) and `finding.reopened` |
| `claims.lapsed_open` | lapsed claims on a finding still `open` / claims recorded under the agent's actor | `triage_state` and lake `findings.status` |

`requests_by_duty` repeats `rejected` and `needs_info` for each duty, so `pull_request_merge` rejections
appear separately. A pending request past its expiry counts as `expired`, because the engine only marks
it lazily. Each group also lists the delegations its approvals were made under, with the agreement figure
from `sampling.delegation_stats`. That per-delegation figure is the one that suspends: suspension acts on
a delegation across every family it trusts, not on a family.

**Limits of what is derived:**

- `dispositions.reopened` counts a disposition as reopened only when the next status event on its
  finding is a reopen. If someone dispositioned it again first, the outcome is `superseded`. Who reopened
  it is in `breakdown` (`human`, `self`, `another_agent`). `accepted_risk` dispositions are counted as
  `not_measurable`, because an acceptance ends through the acceptance sweep, which writes no audit entry.
- `claims.lapsed_open` is a lower bound. `triage_state` keeps one claim per finding and claims are not
  audited, so a released or re-claimed claim leaves no trace. A claim's `by` is the handle the caller
  typed, and it is matched to the agent's actor name, which is the handle the work queue treats as the
  agent's own.
- `unattributed_dispositions` counts the `finding.status` entries that name no actor kind: entries
  written before spec 34 §1, or by a CLI or script. No agent's record includes them.

**Two items from the original list cannot be derived. Each is reported `unavailable` with its reason on
every group:**

- `findings.reported_fixed_reopened`: no principal reports a finding fixed. `fixed` is an observation the
  reconciler makes after two successful scans miss a finding, and the status route refuses it from
  anyone. When a fixed finding comes back, compaction reopens it and only logs a count
  (`CompactionResult.reopened`), so nothing records which finding reopened or which change claimed to fix
  it. `dispositions.reopened` is the measurable version.
- `pull_requests.closed_unmerged`: the platform records an approval request for each head commit, not
  what happened to the pull request on GitHub, so nothing stores a pull request closed without merging.
  Every GitHub action also comes from one shared account (spec 34 §1.2), so a close could not be
  attributed to an agent even if it were stored. Rejected `pull_request_merge` requests are measured.
  Requests the platform opens itself for unclaimed pull requests are `automation`, so they appear on no
  agent's record.

Closing either gap would need a new record: a per-finding reopen event from compaction, or the PR
stamp job recording a close. This phase adds neither.

A delegation is then granted against a published record rather than on trust, and sampling and
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
| 1 | §2 work queue, §3 caveats | Merged (#799) |
| 2 | §4 MCP server (#319) | Merged (#803): `backend/mykronos/mcp_server/`, `mykronos-mcp`, [docs/agent-mcp.md](../docs/agent-mcp.md). Not built: `pipeline()` and `coverage()`, which have no route yet (#318) |
| 3 | §5 playbooks | Built (§5.1): `agent-playbooks-v1.yaml`, `mykronos.playbooks`, `GET /api/agent/playbooks[/{kind}]`, `WorkItem.playbook` |
| 4 | §6 track record: `GET /api/agent/scorecard` | Merged (#802); two §6 items are reported `unavailable` with the reason (§6) |
