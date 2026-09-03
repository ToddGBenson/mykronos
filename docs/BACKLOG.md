# Backlog

Open work that is not a decision and not a retro. Decisions that settle *how*
something is built belong in [`DECISIONS.md`](DECISIONS.md); what happened on a
bad day belongs in [`retros/`](retros/). This file is what is *not done yet*.

Format: `B-nnn` / size / state / the problem / acceptance criteria / provenance.
Entries move to the Closed section when they land, with the closing commit or
decision noted, rather than being deleted outright.

**States:** `open` — scoped and actionable. `icebox` — deferred on a named
trigger; the trigger is recorded so it can be watched for. (`needs scoping`
existed briefly for the three cross-repo entries; the scoping was done on
2026-08-31 and none of them needed the state afterwards. Nothing is iceboxed
today — and B-012 is why the state deserves a periodic re-read: its trigger had
fired without anybody noticing.)

Every entry carries a **Verified** date. That means the defect was reproduced
against this codebase on that date — not that the entry was merely read.
Re-verify before pulling one up; the code moves.

## Provenance

Twelve stories were exported from TheHub on 2026-08-31 and folded in here. They
had been filed against TheHub because that is where the evidence was found, but
TheHub's `CLAUDE.md` is explicit that that repo does not build MyKronos, so the
three cross-repo ones sat blocked there from 2026-08-18. Arriving here removed
that block: the data and the authority they need are in this codebase.

**Scoping those three against this repo mattered more than expected.** Two of
their premises were stale — written against TheHub, or predating work that has
since landed here. B-009 turned out to have been decided in full by D-047
before the story ever arrived, and B-010's central claim ("nothing surfaces
that revisit") is false here: the endpoint exists and the revisit is
automated. Only B-008 survived roughly intact, and it shrank. None of the
three needed the state they arrived with, which is the argument for scoping a
carried-over story against the receiving codebase before believing it.

TheHub story ids are kept in each entry so the trail back is not lost. One
story that matched the `mykronos` tag was deliberately excluded from the export
— TheHub #58508, a docker-compose env mapping, which is TheHub's own work and
already shipped.

---

## Open

Three, and **all three need the operator rather than code**. B-018 is a
decision only they can make, B-035 needs a credential this repository must not
hold, and B-038 needs a decision about what this product is before it needs
scoping. Writing code against any of them would be guessing.

Everything from the 2026-09-01 monitoring sweep, all three gaps that writing
[`finding-lifecycle.md`](finding-lifecycle.md) exposed, and five of the seven
entries the 2026-09-03 DevSecOps assessment produced are in Closed. Every entry
here was reproduced against the live system before it was written; the evidence
is in each entry rather than a link to a dashboard that will have moved on.

**B-032 through B-038 came from a DevSecOps assessment of the workflow on
2026-09-03.** Five landed the same day — the check run now names what a change
introduced (B-036), every finding has an owner (B-034), the queue says what it
could not rank by (B-033), a finding has a record of its own (B-032), and the
current SBOM is reachable without knowing an evidence id (B-037). They shared a
shape worth noticing: almost none of them was a missing feature. The finding record is an assembly over eleven services that
already exist; the risk model is built and unpopulated; routing is switched on
and nothing is routed; the notifier is configured and addressed to nobody; the
check run's introduced-findings query has existed since D-048 and only the gate
reads it. The platform's capabilities are ahead of its wiring, which is a better
problem than the reverse and a different one from the backlog it usually
collects.

B-038 is the exception and the only one that is genuinely absent.

### The sequence, and why

Ordered by what each one unlocks rather than by size, because three of these are
prerequisites for something else being worth doing.

**1 · B-036 — the check run names the change.** Days of work, and it is the
first thing that makes the platform visible to somebody who is not on the
security team. Every other item on this list improves a page that developers do
not currently open; this one improves the only surface they cannot avoid.
Unblocked by the pull-request scoping already shipped.

**2 · B-034 — ownership.** Cheap, and it gates the value of everything
downstream: a notification about an unowned finding has nowhere to go, and a
finding record with an empty owner field is a record of an unmade decision. Do
this before B-035 or the alerts will be broadcasts.

**3 · B-035 — the notifier.** One environment variable once somebody supplies
the URL, and it converts the whole platform from pull to push. Held only because
the credential cannot live in this repository.

**4 · B-033 — say what the ranking is.** The honest half is small: the ranking
degrades to severity when no risk profile exists, and every surface that ranks
should say which one it is doing. Filling the profiles in is the operator's
half and needs nobody's code.

**5 · B-032 — the finding record.** The largest, and deliberately not first.
It is an assembly, and it assembles better once ownership is real (2) and the
ranking is labelled (4) — building it first would mean shipping a record whose
owner field is always empty and whose "does this matter here" block cannot
answer its own question.

**6 · B-037 — the current SBOM.** Real, and it has no dependents. It moves the
day somebody is asked for it.

**7 · B-038 — local feedback.** Last, because it needs a decision about what
this product is before it needs code, and that decision is not urgent while the
CI loop works.

**Not on this list:** turning the gate on. The shadow-mode evidence is there —
0 of 30 merges refused in ninety days by the gate that runs now, against 30 of
30 by the composite gate D-083 retired — and the call belongs to whoever owns
the consequence of a blocked release, not to this file.

**B-018** is a decision, not a defect. Both answers are defensible and only the
operator knows which is true — whether the Azure principal was lost with the
rest of `.env` on 2026-08-23 or deliberately never set — so writing code before
that choice would be guessing. It was deferred on 2026-09-01 with the capability
left enabled and inert, which this entry itself calls the one indefensible
state; that is a deliberate hold, not an oversight.

### B-018 — `cloud` is enabled on a repository and its lane cannot run

**Size:** S **State:** open **Verified:** 2026-09-01

`cloud` is enabled on `ToddGBenson/TheHub` and has produced zero scan runs
across the entire lake, ever. The reason is upstream of the platform:
`thehub`'s `cloud-posture` job is paused because `deploy/concourse/.env` has no
Azure service principal — `set-thehub-pipeline.ps1` refuses to apply without one
unless `-AllowMissingAzure` is passed, and the applied pipeline's
`AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID` and
`AZURE_SUBSCRIPTION_ID` are all empty.

So the capability reads as enabled on the dashboard and is structurally
incapable of reporting. That is the same shape as spec 14's network claim
(B-007, closed): a capability the platform presents as available and cannot
perform.

**This needs a decision before code.** Either the Azure principal is restored —
only the operator knows whether it was lost with the rest of `.env` on
2026-08-23 or deliberately never set — or `cloud` is disabled on TheHub and
recorded as not available on this deployment. Both are defensible; leaving it
enabled and inert is not.

**Acceptance criteria**

- Either `cloud-posture` can run, or `cloud` is not presented as enabled.
- Whichever way it goes is written down, as D-053 did for DAST.
- Distinct from B-015: `cloud`'s zero is real, and must keep reading as real.

---

### B-035 — The notifier is configured and addressed to nobody

**Size:** S **State:** open **Verified:** 2026-09-03

`MYKRONOS_SLACK_NOTIFY_MIN_SEVERITY=high` and `MYKRONOS_ROUTING_ENABLED=true`
are both set; `MYKRONOS_SLACK_WEBHOOK_URL` is empty. Everything in the platform
is therefore pull: a new critical, a KEV match, or a lane going silent reaches
somebody only if they remember to look.

**Needs the operator, not code** — the webhook URL is a credential this
repository must not hold.

**Acceptance criteria**

- Either a webhook is configured, or the absence is recorded as a decision the
  way D-053 recorded paused DAST, so it stops reading as an oversight.

**Provenance:** DevSecOps assessment, 2026-09-03.

---

### B-038 — Nothing runs before `git push`

**Size:** L **State:** open **Verified:** 2026-09-03

There is no pre-commit hook, no local scan command, and no editor path. The
`mykronos` CLI is an operator's tool — tokens, lake compaction, briefings — and
the fastest feedback a developer can get is a CI run after a push.

Defensible for a control plane: the scanners live in CI and the platform reads
them. But four of the open findings on this estate are committed credentials,
which is exactly the class a pre-commit hook exists to stop, and the cheapest
finding is the one that never reaches a branch.

**This is the one entry that needs a decision before scoping.** A thin path —
`mykronos scan --staged` shelling out to gitleaks and semgrep, reusing the
existing adapters — is days. An editor integration is a different product. The
platform's stated position is that it is a control plane and not a scanner, and
that position is either still true or it is not.

**Acceptance criteria**

- Either a local path exists, or "the loop starts at push" is recorded as a
  decision the way D-053 recorded paused DAST, so it stops reading as an
  omission.

**Provenance:** DevSecOps assessment, 2026-09-03.

---

## Watching, not filed

Recorded so the next sweep does not rediscover them, and deliberately not turned
into entries here:

- **`thehub`: `deploy-demo` and `api-inventory` are failing.** `deploy-demo`
  timed out after 25 minutes waiting for the demo environment to report a SHA
  ("host-side poller is not running, or it failed and rolled back");
  `api-inventory` reports "The API surface has changed and the inventory has
  not". Both are TheHub's own code, in TheHub's repository. This repo holds the
  pipeline definition, not the fix.
- **`keel`: `compliance-daily` is errored** — *errored*, not failed, so the task
  did not complete rather than completing unhappily. Its weekly and monthly
  siblings pass. Recorded in
  [`current-state/keel-pipeline-inventory.md`](current-state/keel-pipeline-inventory.md)
  as F3, along with three never-run jobs; keel's work belongs in keel's repo.
- **Two overdue critical findings on TheHub.** Past their `due_at` and open.
  That is the ownership-and-deadlines mechanism working as designed (spec 24) —
  a thing for somebody to do, not a defect in the platform.

---

## Closed

Nineteen entries, over two days.

**2026-08-31 — eight.** Seven built and one, B-009, closed without code because
the decision it asked for already existed. Each was re-verified against the
working tree before it was touched and every one still reproduced.

**2026-09-01 — eleven.** B-013 from the outage that day, then B-008 and B-010
rescoped from the import, then B-011 and B-012, which had been iceboxed and were
built rather than left waiting. B-012's trigger turned out to have fired
already, which is the argument for re-reading an icebox rather than trusting it
to announce itself.

Everything is recorded where this repo already looks: a decision for the four
that changed what the platform promises, a spec amendment for those that made a
document match the code. Final state: 2311 backend tests, mypy over 108 files,
ruff, tsc, eslint and `next build` all clean, merged to `main` and deployed.

### B-037 — The current SBOM is reachable without an evidence id — **done**

**Closed 2026-09-03** by #188. `evidence_id` is optional; omitting it resolves
the newest build that captured an SBOM. Pinning to a build stays correct — one
without a build is a guess about what shipped — so this is a lookup of a real
artifact rather than a floating document. A repository that has never built one
now says so, which is a different answer from "wrong id".

---

### B-032 — A finding has a record of its own — **done**

**Closed 2026-09-03** by #187. `GET /findings/{id}/record` and
`/repos/{repoId}/findings/{findingId}`. An assembly over eleven services that
already existed; the only genuinely new block is "can it close?", which was
inferable from scan health if you knew to go and look, and which is what stops
somebody fixing a defect twice.

Rendering it against live data found a bug in itself: `fixable: true` beside an
empty `fixed_version`, because the scanner writes `""` and the check was
`is not None`.

---

### B-033 — Say what the ranking is ranking by — **done** (the code half)

**Closed 2026-09-03** by #186. The queue returns and renders what it consulted
and what it could not. The gap turned out to be sharper than filed: business
context is not a *degraded* input, it is not a term in `rank_terms` at all, so
this was a threat-intel ranking presenting itself as a risk one.

Filling the profiles in remains the operator's half, and the disclosure
disappears on its own the moment they exist.

---

### B-034 — Every finding has an owner — **done**

**Closed 2026-09-03** by #185. A third rung — the account the repository
belongs to — plus a backfill for the 1001 findings that predated ownership
resolution. 282 unowned groups became 282 owned.

It forced a distinction the module had deliberately collapsed: "no CODEOWNERS
file" and "GitHub is down" both produced an empty rule list, which was fine
while both led to `unresolved` and wrong the moment one of them could lead to
an assignment.

---

### B-036 — The check run names the change — **done**

**Closed 2026-09-03** by #183, with #184 fixing the log-injection finding that
#183 itself introduced — the first time this feedback path closed on its own
output.

---

### B-024 — TheHub stopped scanning, and it was not the billing — **done**

**Size:** M **Verified:** 2026-09-01 **Closed:** 2026-09-01

No Mykronos scan ran against `ToddGBenson/TheHub` between 2026-08-27 and
2026-09-01, freezing **316 open findings**: a finding closes only after two
consecutive successful scans (spec 05 §5), and there were none.

**The first diagnosis was wrong and is worth keeping.** A `workflow_dispatch`
sat `queued` for 2h47m with `updatedAt` never moving off `createdAt`, and a
second run had been queued since 2026-08-18 — **336 hours**. TheHub is private,
`mykronos` is public and had zero queued runs, and an exhausted Actions-minutes
quota queues rather than fails. The evidence was real and the conclusion did
not follow: **TheHub is `scanned_by=concourse`.** GitHub Actions was never its
scanning path, so its quota could not be why scanning stopped. The queued runs
are a genuine second problem and not this one.

**The actual cause was D-097, a fourth time.** TheHub's ingestion token rotated
on 2026-08-31. The GitHub Actions secret was updated; the Vault copy Concourse
resolves `((thehub-ingestion-token))` from was left behind. Every Concourse job
then failed its preflight on a bare `curl: (22) ... 401` — proved by reading
the Vault value and putting it against `/api/ingest/health` directly. The guard
that prevents exactly this was written on 2026-09-01, one day too late for that
rotation.

Closed by `deploy/concourse/repair-ingestion-token.ps1`, which generalises
B-016's script: a `$READERS` table naming every reader of every repository's
token — Actions secret, Vault path, `.env` key — and the same order, **prove
every reader writable, then rotate, then deliver to all, then mark synced, then
re-apply.** The table is the point. Which places hold a copy was implicit, and
being implicit is what broke four lanes.

The Vault write pipes with `printf %s` and no trailing newline: a CRLF inside
an `Authorization: Bearer` header is a 401 nothing in the logs explains. It is
read back and compared byte-for-byte afterwards.

**Measured after the repair:**

| | before | after |
|---|---|---|
| findings blocked by a stalled lane | 316 | **32** |
| open findings | 596 | **472** |

Five TheHub lanes ran green (containers, sast, secrets, iac, dependencies) and
the closure sweep took 124. The 32 that remain are TheHub `dast`, whose
`functional-dast` job is paused under D-053.

**Not fixed here:** the queued Actions runs. TheHub does not need Actions to
scan, so this is no longer urgent, but a run queued for two weeks is still
worth someone reading the billing page for.

---

### B-026 — Remediation advice was invented here, and was wrong — **done**

**Size:** M **Verified:** 2026-09-01 **Closed:** 2026-09-01

Every scanner ships remediation advice and the platform threw all of it away.
`raw_finding_json` has carried it since the first ingest — ZAP writes a
`solution` per alert, Trivy a `Fixed Version` per package — and nothing read
any of it. The Remediation surfaces offered text written *here*, from a general
sense of what a class of finding usually needs.

**That was not merely lossy. It was wrong.** The standing text for containers,
which I shipped earlier the same day, said *"rebuild on a current base image
and one rebuild closes them together."* What Trivy actually reported:

| | findings |
|---|---|
| container findings with a `Fixed Version` | **3** |
| container findings with **no** fix published | **231** |

A rebuild would have closed nothing. Checked three ways rather than asserted:
`apt list --upgradable` in the running image is empty; `apt-cache policy`
reports Installed == Candidate for `libc6`, `libc-bin` and `perl-base`; and a
**freshly pulled `python:3.13-slim`** ships byte-identical versions
(`2.41-12+deb13u3`, `5.40.1-6`). The image is already on the newest Debian
publishes. The CVEs are unpatched upstream.

So the route for those 231 is an acceptance with `no_vendor_fix` and a review
date — which spec 24 §3 already re-opens automatically the day a vendor ships.
Guidance invented from a category was confidently sending somebody to do a day
of work that could not have closed a single finding.

`guidance.by_rule` now reads the scan, groups on the **rule** rather than the
finding — 57 CSP alerts across 57 URLs are one policy line, and listing them as
57 rows is how a five-minute change looks like a sprint — and labels each row
`scanner` or `standing`, because "the tool told us" and "we think" do not
deserve equal trust. Rendered on `/remediate` §3.

Two classification bugs found by looking at the output:

- ZAP titles a CSP alert without the word "header", so a naive match called 57
  findings a judgement and buried the second-cheapest item on the page.
- A `` written through a shell heredoc became a literal **backspace byte**
  inside the regex. `inspect.getsource` showed the pattern looking correct
  while it could never match; only disassembling the function revealed
  `header|CSP|...`.

Closed by `mykronos/guidance.py`; tests in `tests/test_guidance.py`.

---

### B-016 — personal-soc filed nothing because its token was empty — **done**

**Size:** S **Verified:** 2026-09-01 **Closed:** 2026-09-01

The applied `personal-soc` pipeline carried `MYKRONOS_TOKEN: ""` and the
repository's newest scan run was **2026-08-12**.

**A correction to this entry as first written.** It claimed
`set-personal-soc-pipeline.ps1` should refuse to apply with an empty token. It
should not: the script's own comment says empty is allowed on purpose — *"the
scan still runs and still gates, and says loudly in the build log that nothing
was filed"* — and names the command to mint one. The criterion asking to
reverse that was written before reading the comment beside the line it was
about, and the deliberate behaviour is unchanged.

**And the platform did surface it.** The portfolio flagged personal-soc
`is_stale`. What it did not say was *why*, which is a smaller gap than the
entry first described.

The token's plaintext survived only inside the write-only GitHub Actions
secret, so restoring the Concourse copy meant rotating — and rotating is
exactly the operation D-097 exists to constrain. personal-soc has **two**
readers, so the automatic rotation job correctly defers it forever rather than
half-fixing it, which is why this needed a deliberate one-shot repair.

Closed by `deploy/concourse/repair-personal-soc-token.ps1`, which does it in
the only safe order: **prove every reader is writable, then rotate, then
deliver to both, then mark synced, then re-apply.** A check that runs after the
rotation is not a check, it is a post-mortem. And because the rotation precedes
the writes, a delivery failure leaves the previous token valid for its overlap
window — recoverable by re-running, rather than an outage.

**Verified end to end:** the delivered token authenticates
(`/api/ingest/health` → 200), the applied pipeline carries a 43-character
`MYKRONOS_TOKEN` instead of `""`, and `personal-soc/secrets` ran and uploaded.
Newest scan run is now 2026-09-01, not 2026-08-12.

One bug found by running it: the closing hint used `\"` to escape a quote.
PowerShell escapes with a backtick, so the string terminated early and the
remainder parsed as commands. Fixed.

---

### B-025 — The API serves no security headers — **done**

**Size:** S **Verified:** 2026-09-01 **Closed:** 2026-09-01

Found by repairing B-023, and it corrects something I had asserted.

I said the DAST header findings were stale — that the headers were fixed and
the lane was the only problem. Half right. `next.config.ts` does set them and
the **frontend** serves them on every route including its 404. But the first
successful DAST run after the lane was repaired returned 86 findings, of which
69 reproduce, and their paths are `/healthz` and `/api/dashboard/trends`.
Those are FastAPI, not Next.js.

The functional suite proxies backend traffic through ZAP, so ZAP's site tree
covers the API — and `curl -D- http://localhost:8100/healthz` returns a bare
`200 OK` with no security headers at all. The backend never had them. It was
invisible because the lane had been failing for a fortnight, which is B-023's
whole point arriving from the other direction.

**An API's headers are not a page's headers.** This service returns JSON to
programs: no markup to sandbox, no styles to allow, no fonts to fetch. Its CSP
is `default-src 'none'`, stricter than the frontend's — permitting `'self'`
scripts on an endpoint that never serves a script is permitting a script to
run. `Strict-Transport-Security` is deliberately not set, because TLS
terminates at the proxy in front and serving it here over plain HTTP on the
LAN would pin a browser to a scheme this port does not speak.

Two details that would have been bugs:

- The middleware is added **last**, so it is outermost. `add_middleware`
  inserts at the front of the stack, so an earlier call would have put it
  *behind* the perimeter gate — and the gate's 401, the 404s and the 405s are
  exactly the responses ZAP counted.
- `/docs` and `/redoc` are exempted. `default-src 'none'` renders both blank;
  they load a script and a stylesheet from jsdelivr. Two exempted paths beats
  shipping a policy that breaks the docs, and beats weakening the policy
  everywhere to accommodate them.

Closed by `mykronos/headers.py`; tests in `tests/test_headers.py`.

---

### B-023 — 115 findings were fixed and could never close — **done** (D-098)

**Size:** M **Verified:** 2026-09-01 **Closed:** 2026-09-01

Filed and closed the same day, because the investigation *was* the fix.

The task was to add security headers to the frontend. They were already there:
`frontend/next.config.ts` sets X-Frame-Options, X-Content-Type-Options,
Referrer-Policy, Permissions-Policy and a CSP, `poweredByHeader` is false, and
all of it is served on the wire. The 115 open mykronos DAST findings naming
those headers were against a defect that no longer existed.

They could not close, and would not have closed if the headers were fixed a
hundred times. `reconcile_absences` needs a finding absent from two consecutive
**successful** scans (spec 05 §5). The DAST lane had failed seventeen times
running since 2026-08-30 — the ZAP spider hitting its 600s budget, `bash -e`
killing the step on the non-zero exit, and the report the step exists to
produce never written. No successful scan, no observed absence, no closure.

Two fixes, one narrow and one general.

- The ZAP report is now written unconditionally. A crawl that ran out of budget
  still saw most of the site, and a timeout is recorded as a warning on the run
  rather than thrown away along with the output.
- `mykronos briefing`, run by `deploy.ps1` after every deploy. Its first
  section is lanes that cannot close findings, because that is the class of
  defect nothing in the platform reported — the dashboard showed 115 open DAST
  findings and was correct, and the number had been meaningless for two days.

The briefing also groups open findings by what would fix them, with the
packages or rules each class concentrates in, and offers the one request that
acts on each group **only where one already exists**. Three classes get no
button on purpose; see D-098.

---

### B-022 — The review loop has a UI, so it can actually be used — **done**

B-019 and B-020 made the loop *possible*: the queue could be filtered to what
the classifier concluded, and one endpoint could confirm or reject it. Neither
made it *usable* — confirming a false positive still meant issuing a POST by
hand, which is the same shape as B-010's endpoint that existed for months with
nothing rendering it.

The triage queue now carries a **Classifier** column and filter. Every row
shows what the machine concluded, with its rationale on hover, and a `review`
control offering both answers.

**Both answers are offered on every row, and neither is the default.**
Confirming is only shown for `likely_false_positive` — agreeing with
`needs_human_judgment` would dismiss a finding the classifier explicitly
declined to judge, which the backend refuses with a 409, so the affordance is
not offered rather than offered and rejected. Disagreeing is shown everywhere,
because the row the classifier got *wrong* is exactly the one nobody could say
so about before.

Confirming demands a reason and the button stays disabled without one — the
same rule the backend enforces, said earlier and more kindly, because dampening
reads the reason rather than the click.

**The rollout window is handled, and it had to be.** Verified against the
currently-deployed backend, which predates B-019 and returns no classification
at all: `item.triage` is typed `string` and is `undefined` at runtime, which is
precisely the gap that took the vulnerability-management page down between two
deploys. The cell renders `—` and offers no review button rather than a control
that would 404. Confirmed by loading the page against that backend: 200, zero
review buttons, no server errors.

### B-019 / B-020 / B-021 — The three handoffs in the finding lifecycle — **done**

All three came from writing the lifecycle down end to end, and all three sat at
handoffs between stages rather than inside one. Fixed together because they are
one story: the platform did the analysis and could not hand the result to
anybody.

**B-019 — the queue carries what the machine concluded.** The ranked,
portfolio-wide queue took nine filters and not `triage`, while the
per-repository findings view had had one since spec 18. So the classification
existed, was displayed and was filterable — on the one surface that shows a
single repository at a time, which made "everything the machine could not
judge" one request per repository.

`triage` is now a filter, and `triage`/`triage_rationale` are stamped on every
row whether or not anybody filters — the same contract the KEV badge has, so a
caller does not need a second request to render it. Computed live via
`classify()` rather than read from `remediation_events`, matching
`open_findings`: a finding Patchwork has not reached yet still has a
classification. An unknown value is a 422 rather than a silently unfiltered
queue, which is the fall-through B-006 fixed on the repo page's tab parameter.

**B-020 — both answers are recorded now.** A `likely_false_positive` waited for
a person who had no list to work from, and the dampening loop that depends on
those dispositions was fed by whoever happened to look. 43 dismissals had ever
been recorded, all sast and secrets, against 234 open container findings.

`POST /api/dashboard/findings/{id}/classification-review` makes it one action.
Agreement delegates to the disposition endpoint rather than reimplementing it,
so the two routes to the same decision cannot drift; agreeing with
`needs_human_judgment` is refused with a 409, because dismissing a finding the
classifier explicitly declined to judge is the one thing this must not become a
shortcut for; and a reason is required, because dampening reads the reason
rather than the click.

Rejection is the half that recorded nothing before. It is its own knowledge
type, deliberately outside `TEACHES_ABOUT_THE_RULE`: it teaches about the
classifier, not the rule, and quietening a rule because somebody said its
finding was real would invert the loop. A test asserts a rejection never lands
as a dismissal.

**B-021 — zero reads as coverage, not failure.** `COVERAGE` and `NOT_COVERED`
state which classes have a deterministic fixer and which do not, with the
reason for each absence — an absence stated is a different thing from one
inferred from a blank table. The efficacy response carries them, plus
`measured`, separating "no fix has reached a pull request" from "fixes were
made and did not remove risk". An all-zero table meant both.

A test asserts `COVERAGE` names every entry in `FIXERS`, so the page cannot
silently fall behind the code, and another that no capability is listed as both
covered and not.

2334 tests pass, mypy over 108 files, ruff, tsc all clean.

### B-017 — netassess-ingest died on an unzip warning — **done**

Filed as three failing jobs. Two were stale and cleared by re-running them:

- **`netassess-freshness`** had failed on 2026-08-23 with *"no network scan
  published in 13 days"*. The host's `personal-soc Weekly Network Scan` task
  has since run, so it now reads *"newest run: 2026-08-31 (1 days old, limit
  10)"* and passes.
- **`package`** had failed at 18:02 on 2026-08-31 with *"no install
  acknowledgement within 8 min"*, inside the same window as the token outage
  and the sealed Vault. The host's install task polls every five minutes and is
  healthy; re-run, it succeeds in 22 seconds.

Neither was B-016's empty token, which the dates made tempting to assume.

**The third was a real bug, and it had hidden two security findings.**

`netassess-ingest` produced no output past `run under test:` and then failed.
The line after it was the diagnosis:

```
warning:  netassess-run/netassess-2026.8.31.zip appears to use backslashes
          as path separators
```

The archive is written by a Windows scheduled task, so its entries carry
backslash separators. `unzip` calls that a warning and **exits 1** — and
Concourse runs the task as `bash -ec`, so `-e` made a warning fatal. The job
died on the unzip, having printed nothing anybody could act on.

`unzip`'s contract is 0 clean, 1 warning with the files extracted anyway, 2 and
above a real error. An `unpack` helper now distinguishes them at both extract
sites: a warning is noted and execution continues, anything higher still stops
the job. Verified under `bash -e` against all three exit codes, since the shell
flag is the half of the bug that made it silent.

**What was behind it.** With the task running to completion, it reaches its own
verdict and reports:

```
::error:: NAS is exporting NFS shares
::error:: an open Wi-Fi AP is broadcasting
```

That is the check working. `netassess-ingest` has **never once succeeded** —
every build since it was created on 2026-08-12 has failed — so those two
findings have never been visible to anyone reading the pipeline. They are real,
current as of the 2026-08-31 scan, and they are the operator's to act on rather
than the platform's: an open access point and an NFS export are network posture,
not a defect in Mykronos.

That is the whole argument for the fix. A job that fails silently is not a
failing job, it is an invisible one, and this one was hiding exactly the sort of
thing it was built to find.

### B-014 — self-check tells the truth about Vault now — **done**

Two defects, both fixed.

**The check runs.** `MYKRONOS_VAULT_URL` is set in `backend/.env` and defaulted
in `deploy/mykronos/docker-compose.yml`, so `check_vault` now reaches
`/v1/sys/health` — read-only, unauthenticated, no token needed. Verified live:
`vault ok`, where every previous run of the command said `FAILED`.

Defaulted in compose rather than left to `.env` deliberately. An unset value
silently disables the one check that notices a sealed Vault, and this
deployment comes back sealed after every restart.

**A dependency nobody configured is no longer a failure.** `ReachabilityResult`
gained `configured`, and the CLI renders three states rather than two —
`ok`, `not configured`, `FAILED` — with unconfigured dependencies excluded from
the exit-status set and named on their own line: *"Not checked: vault —
configured for nothing, so a failure there would not appear here."* Coverage is
a fact worth stating, and the whole reason this command exists is that
something nobody was watching broke for a day.

**What the tests were doing.** `test_unconfigured_is_not_a_failure_to_report_loudly`
had asserted the distinction in its *name* since the day it was written and
never in its body: it checked `not reachable`, which is exactly what a sealed
Vault also returns. So the false alarm was tested into place. It now asserts
`configured is False`, and two new tests assert a real failure keeps
`configured is True` — otherwise fixing the false alarm would have hidden the
alarm.

The sealed-Vault detection was already written, already correct, and already
named the unseal script. It had simply never had a URL to run against. It would
have caught the seal on 2026-09-01, which was found by hand instead.

### B-015 — Capabilities that report elsewhere are read where they report — **done**

`aegis`, `oracle` and `patchwork` write an `InsiderRiskSignal`, a
`RiskDecision` and a `RemediationEvent`. None writes a `ScanRun`, so reading
only `scan_runs` reported all three silent on every repository for ever.

`_capability_scan_state` now overlays `REPORTS_ELSEWHERE` — a capability to
`(table, column)` map — after the scan-run query. The overlay never overwrites
a real run: if one of these ever starts writing runs, the run is the better
answer and this is the weaker one. Their status reads `reported` rather than
`success`, because inventing a scan status would claim a run that never
happened.

**The guard matters more than the fix.**
`test_no_capability_is_permanently_silent` walks every `Capability` and fails
unless it either has an adapter (so writes runs) or appears in
`REPORTS_ELSEWHERE`. The split is exact today — the three without adapters are
the three in the map — so the next capability that reports through a table of
its own is caught when it is added, rather than being silent quietly. Confirmed
by removing `oracle` from the map and watching it fail.

`cloud` and `network` keep reading as genuinely silent, which they are, and a
test pins that so the fix cannot make everything look busy.

**Why it was filed against my own change.** B-008 turned "enabled and silent"
from an absence a caller inferred into a state a caller is invited to act on.
The underlying gap predated it; B-008 is what made three of fifteen
capabilities permanently assert a problem that did not exist.

### B-011 — A fix pull request can produce a regression link — **done**

The producer spec 31 §2 describes existed nowhere. Every link in a running
system had been written by `tests/test_regression_coverage.py` hand-crafting an
HTTP request, so the number the whole incentive design rests on could not move
outside the suite.

Patchwork's PR body now carries the block spec 31 asks for — *"if you add a
regression test, name it here"* — and `outcomes._link_regression_test` parses it
on merge, keyed so a redelivered webhook updates one link rather than inflating
the count. Same shape as `rejection.py`, which already asks the closer of an
unmerged draft why: the person writing the regression test is the person merging
the fix, and that is the cheapest moment anyone will ever be asked.

**It produces `asserted`, and that is the honest grade rather than a shortfall.**
The entry asked for a production path writing `demonstrated`. Building it showed
why the spec does not put `demonstrated` here: the test arrives *in* the fix pull
request, so it does not exist on the parent commit, and no ordinary lane run
there can have exercised it. A lane that went red-to-green across the merge is
evidence about the lane, not about this test. `demonstrated` needs the new test
run against the *old source* — a lane invocation taking a ref, and
`dispatch(repo_full_name, capability)` takes no commit. Spec 31 §8 already
contemplates exactly this: *"`demonstrated` cannot be established; the link
stays `asserted` and says why."*

Claiming otherwise would have been the worst available outcome. Oracle weights
`demonstrated` above `asserted` precisely because it means more (spec 26 §2,
spec 31 §6), so a fabricated grade would corrupt the one number spec 31 exists
to make trustworthy.

**What remains, precisely:** commit-targeted lane dispatch. That is
infrastructure — GitHub Actions `workflow_dispatch` takes a ref, Concourse does
not without a pipeline change in every repository — and it is its own entry
whenever somebody wants it.

The entry's other criterion is now a test: `TestTheProducerIsNotAFixture`
asserts the linker's source file is not under `backend/tests/`, so a fixture can
never again be the only writer.

### B-012 — keel is exported, inventoried, and its findings recorded — **done**

Read-only, into
[`docs/current-state/keel-pipeline-inventory.md`](current-state/keel-pipeline-inventory.md)
with the config beside it. Deliberately not in `deploy/concourse/pipelines/`:
that directory is what this repo *applies*, and putting keel there would claim
ownership of a definition that lives in `ToddGBenson/keel`.

**Its icebox trigger had already fired, and nobody noticed.** The entry was
deferred until "keel is unpaused". keel is not paused — `paused: false`,
`paused_by` and `paused_at` both null. Two other premises also needed
correcting: eight groups rather than seven (the eighth is an `all` wildcard,
and groups overlap, so seven real groups over 26 *distinct* jobs is the right
reading).

Confirmed as filed: 26 jobs, fifteen written down nowhere, three never-run
(`container-scan`, `release-preflight`, `authorize-release`), the entire
`release` group never executed, and keel self-setting from its own
`set-pipeline` job — so the "no definition in any repo" diagnosis does not
apply and the next reader will not repeat it.

**It also found a live outage.** All three `mykronos-*` jobs were failing on the
same 401 that took four `mykronos` lanes down on 2026-08-31 — a third stale
copy of the ingestion token, at `concourse/main/keel/mykronos_ingestion_token`,
that the earlier repair never reached. Repaired by rotating and delivering to
both readers at once; all three now succeed. Recorded under D-097.

Nothing in the inventory set, unpaused, modified or triggered any pipeline. The
three keel jobs that *were* triggered belong to the credential repair, not to
the inventory, and the document says so rather than folding them in.

### B-008 — Every expected stage is named, including the ones with no job — **done**

The premise needed correcting before the work did. The story said AI,
functional and unit "do not exist as stages at all"; all four of those plus
`qa` are capabilities with workflow templates here. That was true of TheHub,
not of this repo, and twelve of the thirteen named stages already existed and
reported.

What was actually wrong was narrower: `capability_states` was built from
`sorted(enabled)`, so a capability nobody turned on was an *absence* — and so
was one that was enabled and had never reported. Two different answers, one
empty space. Every capability now gets a row carrying `enabled`, so
`enabled: false` ("not configured here") and `enabled: true, has_scanned:
false` ("enabled and silent") are distinguishable, and only one of them is
somebody's problem.

`has_scanned` is read for every capability rather than assumed false for the
disabled ones: a Concourse repo's grants are its ledger, and a capability can
report without appearing in the installer's list. Dropping those rows would
have hidden scans that actually happened.

**Already correct, and left alone:** the frontend renders all fifteen
capabilities with a "not enabled" tooltip, so the UI half of the criterion was
met before this. The API row was the half that disagreed with it, and now it
does not.

### B-010 — The vulnerability management view is finished — **done**

Most of this was already built and cited PIP-9 by name; the endpoint had simply
never been rendered. Three gaps closed:

**Aging carries the capability.** "Sixty high findings older than ninety days"
is a number to be alarmed by; "they are all container CVEs from one base image"
is the thing to act on. Without it the reader opens every finding to learn that.

**Acceptances are listed, not counted.** Counts cannot say what was accepted or
on what grounds, and the grounds are the part that decays. Each row now carries
`accepted_reason_code` and `accepted_until`, plus `now_fixable` — accepted for
want of a fix, and a fix now exists. That flag is deliberately narrow: it fires
only for `no_vendor_fix`, the one premise a scan can contradict and the only
one the daily sweep re-opens (spec 24 §3.2). A fix existing does not contradict
"not exploitable here", and calling that fixable would send somebody to
re-litigate a decision that is still true.

**A page renders it**, at `/vulnerability-management`, which was most of the
remaining value.

Building it surfaced a defect the type checker could not: rendered against the
currently-deployed backend the page 500s, because that backend has no
`accepted_risk_detail` and `undefined.filter` throws. During any rollout the
frontend is briefly newer than the backend, so the page now defaults its
sections and skips the capability tally when a row carries none — otherwise the
column read "undefined 205", which is the wrong-but-plausible render this repo
treats as worse than an empty one. Both were found by loading the page, not by
building it.

**Not done, and not needed:** the story asked for "a way to see which have
become fixable since". The daily acceptance sweep already re-opens those
automatically, so the page surfaces the state rather than adding a second
mechanism to chase it.

### B-013 — Rotation would have desynced Vault again — **done** (D-097)

Filed from the 2026-08-31 outage, fixed the same day.

D-086's guard was `scanned_by != "github_actions"`, and `scanned_by` holds one
value while describing "intent, not coverage" in its own docstring. A
repository migrating under spec 32 is scanned by both systems, so it declared
`github_actions`, passed the guard, and every rotation left Vault behind.

The fix asks who reads the token rather than what the repository declares:
`ConcourseClient.has_pipeline_for` answers from the Concourse server, so a
repository cannot be wrong about itself. It returns three states, and the third
is load-bearing — `None` for "could not be established" defers, because failing
open would say "nobody else reads this" on any day Concourse was down, which is
how the credential desynchronised in the first place.

Covers the faster trigger too: an active token with `secret_synced = 0` is
swept up and rotated again as a resync on the job's ordinary interval, so a
manual repair reaching Vault but not Actions used to arm the recurrence by
itself.

**Still true, and unchanged:** the platform cannot deliver to Vault, so
Concourse-scanned repositories still do not rotate automatically. D-097 makes
the deferral correct, not unnecessary. D-086's note that this is a real
regression against 90-day rotation stands.

The gap in the tests mirrored D-086's own: none described a repository scanned
by both systems, the only configuration where the bug appears. There is now a
test for that, and one asserting an Actions-only repository still rotates — so
the guard cannot quietly end rotation altogether.

### B-009 — AI as its own stage — **closed, already decided** (D-047)

Not built, not scoped: **already answered before the story arrived here.**

B-009 asked for "a decision naming what the AI stage asserts and what it does
not", and D-047 — *"AI is four concerns; three become a capability and one
stays where it is"* — is that decision, taken 2026-08-13 against this repo and
citing the same PIP-7 the story came from. It names all four concerns
(prompt-injection surface, model/dependency provenance, evaluation regression,
disclosure of AI authorship), puts 1–3 in the `ai` capability, and keeps 4 in
Aegis, with the boundary reasoning: Aegis assesses a pull request and its
author, the other three assess the code and its configuration and are true of a
commit whether or not anyone opened a pull request.

Every acceptance criterion is met by it:

- *A decision naming what the stage asserts and what it does not* — D-047.
- *Explicitly says whether the AI-authorship signal moves or stays* — it stays,
  and D-047 says why moving it would split Aegis's one coherent question across
  two capabilities.
- *Spec 06 updated if the boundary moves* — the boundary did not move. D-047
  cites spec 04 §3 and spec 06 §2 as they stand.

It is implemented, too: the `ai` capability exists with a workflow template,
an `AdapterSpec` accepting SARIF from any tool, and `ai_pin_check.py` as the
provenance third.

**What D-047 decided and nobody has built yet** — prompt-injection detection
and evaluation-regression detection — is named in `ai_pin_check.py`'s own
docstring as deliberately absent, because the first needs a semantic classifier
and the second a runtime eval harness. That is decided-and-unbuilt, which is a
different thing from undecided, and it belongs in a new entry if it is ever
wanted. It is not what B-009 asked for.

### B-001 — Codenames reaching users through the backend and OpenAPI — **done**

The four response strings now name the capability, and so does a fifth the
story missed: `webhooks.py:364` returned `{"ignored": "not a Patchwork
branch"}` in an actual response body.

The story's diagnosis was wrong about where the schema leak came from — it
named "14 `Field(description=)` blocks in capabilities.py, config.py,
dashboard.py", and no `description=` line anywhere carried a codename. The 38
occurrences came from **14 route docstrings** and **15 component sites** (model
docstrings, field descriptions, and three default *values*) across six modules.
Vocabulary follows `CAPABILITY_META`: Insider risk / Risk decisions /
Auto-remediation, with "the risk-decision engine" where an agent noun was
needed — spec 00's own wording.

**Nine occurrences deliberately remain**, all identifiers rather than prose, on
the same principle as the capability-keys carve-out: the `AegisAccepted`
response-schema type name (3), five response `title`s FastAPI synthesises from
the `/api/oracle/` path, and one `` `PatchworkPipeline.run_one` `` code pointer.
Zero product-name prose remains.

**The first pass was incomplete, and a second finished it.** Chasing the one
Atlas string above showed the sweep had been scoped to `api/*.py` and
`schemas.py` — but response values are also built in `governance.py`,
`dashboard.py`, `aegis.py`, `incident.py` and `oracle/engine.py`, and none of
those had been looked at. Ten more user-facing sites, found by asking what
*reaches* a user rather than which files seemed likely:

- `aegis.py:228` — the **Check Run body posted onto pull requests**: "Aegis
  cannot block, merge or close a pull request". The most-read string of the set.
- `aegis.py:156`, `governance.py:494`, `oracle/engine.py:252` — `reason` fields
  in API responses.
- `dashboard.py:283, :291` — worklist rank explanations shown per row.
- `incident.py:304` — the "last Atlas scan" note.
- `capabilities.py:303` and the `PatchworkConfig` / `OracleConfig` docstrings —
  served by `config_schema` at `repos.py:348`, which the UI renders its
  configuration forms from. Not obviously an API surface until you look.
- `ingest.py:740`, `schemas.py:459` — the Atlas equivalents of two sites already
  fixed for the other three names.

Atlas was folded in: it was excluded from the original entry because the
frontend already handled it, which was true of the frontend and not of the
backend.

**Verified by dumping both published surfaces** — `openapi.json` and every
`config_schema` — and grepping the output, rather than by grepping source for
names. Config schemas: zero. OpenAPI: twelve, all identifiers or path-derived
(`AegisAccepted`/`AtlasAccepted` type names, five titles FastAPI synthesises
from the `/api/oracle/` path, one code pointer). Zero prose across all four
names.

`config.py`'s descriptions were checked and deliberately left: `Settings` is
not exposed through any endpoint, so those are operator environment docs, not
a user surface.

### B-003 — `auto_merge_workflow_prs` — **done** (D-095)

Removed from model, schema and API. No UI rendered it and no test touched it.

**The story asked for "a migration drops the column" and there is no migration
framework** — `create_all` plus `add_missing_columns` (D-052) only ever *adds*.
So `Database.drop_retired_columns` was added against an explicit
`RETIRED_COLUMNS` list. Deliberately not the inverse of `add_missing_columns`:
"drop every column the models do not declare" is a data-loss bug waiting for
its first rollback. A test asserts no name is in `RETIRED_COLUMNS` and on a
model at once.

### B-002 — The fix generator that never generated — **done** (D-096)

Withdrawn, per the decision taken this session. Spec 08 §2 now specifies
deterministic fixers as the only generator; §5's config row is struck through.

Worse than the story recorded: **set**, the rationale read "No deterministic
fixer matches this finding", as though a generator had been consulted and
declined. Configuring the endpoint changed the sentence and nothing else, and
the new sentence was less true than the old one. The rationale is now one
sentence because there is one path.

The setting lives in the `capability_configs` JSON, not a column, so
`RETIRED_COLUMNS` does not apply — but the models are `extra="forbid"` while
the read path deliberately does not validate, so a repo configured before the
withdrawal would fail its next save on a field the operator cannot see.
`RETIRED_CONFIG_KEYS` strips withdrawn keys on save. An unknown key is still
refused.

### B-005 + B-004 — Atlas on the Concourse path — **done**

**These were one root cause.** The Concourse atlas task is a reduced copy of
the Actions one. The Actions template *does* pass `--check-freshness` (gated on
config) and *does* call `atlas_sbom`; a flag search misses it because it sits
inside a `.j2` conditional. Both pipelines now pass `--sbom`, so license
evidence no longer depends on which CI system finished last, and both can pass
`--check-freshness` behind `ATLAS_CHECK_FRESHNESS`.

**Freshness stays off, by decision.** The pass calls the npm and PyPI
registries, which spec 07 §7 requires be opted into. Capable, and not enabled.

**The dashboard now says which zero it is.** The `stale_dependencies` term was
emitted only when it scored, so "nobody asked" and "asked, nothing stale" were
both the term being *absent*. It is now always emitted in three states, with
not-measured rendered `—` by the existing three-state renderer. Underneath was
a second bug: `maintenance_known` falls back to `dependency_count` when the
field is absent, so a runner that never looked up a date was indistinguishable
from one that found every date — the term needed a separate "did anyone
measure" signal. No trust score moves; a test asserts that.

### B-006 — The incident drill-down 404 — **done**

`AffectedRepoOut` carries `repo_id`; the page links with it and falls back to
plain text where the exposure outlived the onboarding. Unknown tab ids now
render an `ErrorPanel` naming the valid ones instead of quietly rendering
Dashboard. `_resolve_repo`'s docstring claims "every response that links here
already carries `repo_id`" — this was the counterexample, and now it is not.
`tab-inventory.md` F1 corrected from hypothetical to shipped-and-fixed.

### B-007 — Spec 14's claim — **done**

The story asked for "spec 14 status rows Built → Not started". **Spec 14 has no
status rows** — its header said "Approved for build", which was honest. The
false claim was in the README: "Built; awaiting an authorized CIDR to scan",
which said the only missing input was permission when authorizing a range would
still have scanned nothing.

New spec 14 §0 inventories what exists against what does not. `network.py` is
annotated dormant, kept rather than deleted with the reason. The absence of
`network` from `DISPATCHABLE_CAPABILITIES` is documented as intentional.

**One nuance the story missed:** the nmap/nuclei adapter is registered, so
externally-produced scan output *does* ingest. Enabling the capability is not
useless — the platform just never runs the scan. The dashboard label carries
that note rather than being removed, and the toggle was left working, because
disabling it would break a path that does work.
