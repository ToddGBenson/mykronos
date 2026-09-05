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

Sixteen. **Eight need the operator rather than code**: B-018 is a decision only
they can make, B-035 and B-043 each need a credential this repository must not
hold, B-042 is a call about this repository's CI budget, B-044 is one
permission grant that lights four built-and-waiting features, and B-052 is one
repository grant that lets binnacle be scanned at all. Writing code
against any of them would be guessing.

**Four arrived from the 2026-09-03 second sweep, and they are one story told
four ways: nothing here checks that a scan covered anything.** B-045 is the
instance — TheHub has been scanned on `main` since 2026-08-19 while every commit
lands on `develop`, so 330 findings describe a tree eight days stale. B-046 is
the reason nobody saw it: the stalled-lane detector measures silence, not
coverage, and a lane re-scanning one frozen commit reports healthy forever.
B-047 is the exit that does not exist for the 32 findings a disabled capability
left behind. B-048 is the same blind spot from the other side — two lanes
scanning one repository at different path bases, each supplying the other's
absence evidence, and `parity` recommending that the wrong one be retired
because it compares what a lane reports and never what it reaches.
B-045 is a decision; B-046, B-047 and B-048 are code. B-050 is the one that is neither: four live vulnerabilities in TheHub, found by reading all twenty-one of its high findings by hand because B-045 means no scanner has looked at that code in sixteen days. B-051 came from asking what the other repositories look like, and is the widest gap here: four of the account's eleven repositories are watched at all, and two of the four are green because their analyser cannot read the language they are written in. B-049 arrived last and only because the operator half of B-033 was finally done: filling in the four risk profiles turned an accurate disclosure off without changing the rank behind it.

B-038 closed on 2026-09-03 as D-101 — the answer was that the position stands.
The risk gate was asked about at the same time and stays advisory, recorded as
D-102 rather than a backlog entry, because a deliberate posture with the
evidence to defend it is a decision and not outstanding work.

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

### B-043 — Free-text questions need a model credential this repo must not hold

**Size:** M **State:** open **Verified:** 2026-09-03

The Consult tab answers a fixed set of questions from records and links each
answer to the tab that produced it. It has no free-text box, and the brief
asked for a chat window.

**Two reasons it shipped without one, and only the first is a blocker.**

This repository holds no model API key and must not (spec 12 §2). A chat window
that needs one is blocked on the operator exactly as B-035 is, and shipping the
box before the credential is a feature that fails on first use.

The second is why this is M and not S: **grounding is the hard half.** A model
answering "what should I fix first here" is only as good as the facts handed
to it, and those facts are `consult.Facts` — already built, already tested,
already the thing the fixed answers are made of. Adding a model is a phrasing
layer over the same struct. Building the phrasing first and the grounding
later is how assistants end up confidently wrong, which is the failure this
platform can least afford: it exists to be believed about security.

**The refusals are not a placeholder.** `consult.UNANSWERABLE` names six
questions people will ask and this platform cannot answer, with the reason for
each. Those stay when a model arrives — a model that answers them anyway is
worse than the list, and the list is what makes the rest trustworthy.

**Acceptance criteria**

- The key reaches the backend the way every other secret does, via Vault.
- Free text is answered *only* from `consult.Facts` and whatever the caller is
  already authorised to read. No repository source, no lake queries the asker
  could not run themselves.
- Every sentence carries the same tab citation the fixed answers carry. An
  answer that cannot cite is not shown.
- It still cannot act: no dispositions, no acceptances, no scans, no PRs.
- A question on the `UNANSWERABLE` list is refused with its stated reason
  rather than attempted.

---

### B-044 — One App permission is holding four features shut

**Size:** S **State:** open **Verified:** 2026-09-03

`repo_governance` holds **zero rows**. Not stale ones — none, ever. Every
governance read on this deployment returns unreadable:

    GitHub refused the read: Could not read branch protection for
    ToddGBenson/mykronos: {"message":"Resource not accessible ..."}

The GitHub App does not carry `administration: read`. D-097 decided that
permission is *optional* rather than required, and that decision is right —
making it required would fail the spec 02 §8 permission smoke test for every
installation that already exists. But nobody has granted it here, and the
consequence is larger than the governance panel it was added for.

**Four things are inert because of it, and none of them is broken.**

1. The governance panel reports nine controls as `unknown`, correctly.
2. **SSDF PS.1, PS.2 and part of PW.7** report "could not be read" — three of
   the four practices `mykronos` cannot evidence, out of thirteen.
3. **Oracle's governance term** is permanently `available: False`, so no
   repository is scored on whether a bad change could get in.
4. **Control drift** (D-105) will never fire. The sweep runs, finds nothing
   readable, and records nothing — which is the correct behaviour and means
   the feature sits waiting.

**One click.** Granting `administration: read` on the App installation lights
all four with no code change, which is also the proof that each was built
right: none of them fabricated a value in its absence.

**Acceptance criteria**

- The permission is granted, or a decision is recorded that it will not be —
  as D-053 did for DAST.
- `repo_governance` carries a row per repository and the SSDF count moves.
- The first drift sweep after the grant produces no drift, because a first
  reading has nothing to compare against. That is expected, not a failure.

---

### B-042 — Coverage is plumbed end to end and no pipeline writes it

**Size:** S **State:** open **Verified:** 2026-09-03

Every test run in this lake reports `line_coverage = NULL`. All of them: 227
unit runs and 55 functional runs on `mykronos`, 36 unit runs on `TheHub`.

**Nothing is broken.** The JUnit adapter parses Cobertura `line-rate` and
JaCoCo `LINE` counters (`adapters/tests_junit.py`), the registry merges the
columns (`registry.py:223`), the lake stores them, `scan_health` reads the most
recent run that *reported* coverage rather than the most recent run, and the
uploader rglobs every `*.xml` under `$MYKRONOS_RESULTS` and merges the results.
Drop a `coverage.xml` beside `unit.xml` and the number appears.

No pipeline writes one. `mykronos`'s own unit lane runs
`python -m pytest -q -n auto --junitxml="$MYKRONOS_RESULTS/unit.xml"` and that
is the entire gap: no `--cov`, and `pytest-cov` is not in the `dev` extra.

This is the same shape as most of B-032 through B-038 — the capability is
ahead of its wiring — and it is why the new test-estate view renders "never
measured" for every lane on every repository.

**Not done here, deliberately.** Coverage collection under `pytest-xdist` costs
real time on a 14-minute suite that runs on every pull request, and spending
that is a call about this repository's CI budget rather than a defect to fix.
The per-repo lane `command` is operator config, not platform code.

**Acceptance criteria**

- `pytest-cov` in the `dev` extra and `--cov=mykronos
  --cov-report=xml:$MYKRONOS_RESULTS/coverage.xml` on the unit lane command.
- A figure appears on the Harness tab without any platform change, which is
  the proof that the plumbing was always right.
- The added CI time is measured and recorded, not assumed.

---

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

### B-045 — TheHub is scanned on a branch nobody merges to — **done**

**Size:** S **State:** open **Verified:** 2026-09-03

Mykronos's own record of TheHub says `default_branch: develop`. Its Concourse
pipeline watches `main`. Nothing reconciles the two, and the gap is now eight
days wide.

- `origin/main` is at `7197a028`, dated 2026-08-26. No merge since.
- `origin/develop` has commits through 2026-09-03 — eight of them that day.
- `develop` was scanned **295 times**, the last on **2026-08-19**. Not once since.
- Every TheHub scan run after that date carries
  `commit_sha = 7197a02837377eef0af70f14746102df33286de7` — the same frozen
  commit, re-scanned and recorded `success` each time.

TheHub's active branch has therefore been unscanned for sixteen days, and its
330 open findings describe a commit that is eight days behind the code people
are actually writing.

**This is not B-024.** That entry was the ingestion token (D-097) and it closed
correctly — scanning did resume, at 2026-09-01 20:07. It resumed against
`main`, so the repair bought nothing that lasts.

The branch is a parameter, `((thehub-branch))`, set by
`deploy/concourse/set-thehub-pipeline.ps1` and defaulting to `main` under an
operator directive dated 2026-08-18. That script's own comment records the
failure mode exactly: "the repository said `develop` while the applied pipeline
watched `main`, and nothing anywhere reconciled the two." It was written about a
working-tree divergence. The same sentence now describes the platform.

The directive was reasonable. It assumed the flow is PR -> merge to `main` ->
pipeline runs. That flow has not produced a merge in eight days, so what needs
re-deciding is the assumption, not the script.

**Acceptance criteria**

- A decision recorded on which branch TheHub is scanned on — matching
  `default_branch`, or stating in writing why it does not.
- If `develop`: the pipeline re-applied with `-Branch develop`, and a scan run
  recorded whose `commit_sha` is on `develop`.
- The 330 frozen findings re-evaluated against a current commit.

**Closed 2026-09-04.** The pipeline now watches `develop`. Getting there
took more than re-pointing it: `unit` was red on `develop`, and every scan
lane carries `passed: [unit]`, so the branch could not be scanned at all until
the twelve promotion-gate tests went green (B-055, TheHub #278/#279). The
branch question itself turned out to be forced rather than chosen — see B-056:
a lane has no branch dimension, so scanning `develop` while gating `main` is
not expressible, and the 2026-08-18 directive was the only option available.
The accepted cost is that `deploy-demo` now auto-deploys `develop` to the demo
environment; production is untouched, since `deploy-prod` carries no trigger.

**Provenance:** DevSecOps assessment, 2026-09-03 (second sweep).

---

### B-046 — A lane pinned to a stale commit reports as healthy

**Size:** M **State:** open **Verified:** 2026-09-03

The briefing leads with lanes that cannot close findings, which is the right
thing to lead with. It measures **wall-clock silence** — how long since this
capability last reported. It does not measure whether the scan covered anything
new.

A pipeline pinned to a branch that has stopped moving produces a successful run
on schedule, forever, against an unchanging commit. It never appears in that
section. TheHub's lanes surfaced only because they *also* went quiet for two
days (B-045); had the pipeline held its ten-hour cadence, 330 findings would
have been frozen against a stale tree with every indicator green.

Mykronos already holds both halves — `repo_onboarding.default_branch` and
`scan_runs.branch` / `scan_runs.commit_sha`. Nothing compares them.

Two checks, and the second is the one missing everywhere:

1. **Branch drift** — the branch a lane scans is not the repository's default
   branch.
2. **Commit staleness** — consecutive successful runs carrying the same
   `commit_sha`. A lane re-scanning ground it has already covered is not
   watching, whatever its cadence says.

The second also catches what the first cannot: a lane on the *right* branch
whose checkout is pinned or cached.

**Acceptance criteria**

- The briefing and `/api/dashboard/repos/{repo_id}/scan-health` report a lane
  whose recent successful runs share one `commit_sha`, naming the commit and
  the date it stuck.
- Branch drift against `default_branch` is surfaced per repository.
- TheHub reproduces both today, and stops reproducing them when B-045 lands.

**Provenance:** DevSecOps assessment, 2026-09-03 (second sweep).

---

### B-047 — Disabling a capability strands its findings open forever

**Size:** S **State:** open **Verified:** 2026-09-03

`ToddGBenson/TheHub` has `enabled_capabilities: aegis, atlas, containers, sast,
secrets`. `dast` is not among them. It holds **32 open findings**, and the
briefing reports that lane silent for fifteen days.

Those 32 cannot close by any path the platform offers. Closure requires two
consecutive *successful* scans that no longer observe the finding (spec 05 §5).
A capability that is switched off will never produce one, so absence can never
be established. They are not open because anything is unfixed — they are open
because the only mechanism that could close them has been removed.

This is the closure rule working exactly as designed and arriving somewhere it
has no exit from. The rule is right; the fix is not to relax it, but to make
removing a capability an explicit decision about what it was holding.

**Acceptance criteria**

- Disabling a capability requires a disposition for its open findings, or
  records one automatically with a written reason naming the removal.
- Findings stranded this way are distinguishable from merely stale ones, in the
  briefing and in the vulnerability-management view.
- TheHub's 32 `dast` findings reach a recorded state.

**Provenance:** DevSecOps assessment, 2026-09-03 (second sweep).

---

### B-048 — Two lanes record every IaC finding twice, and `parity` says retire the wrong one

**Size:** S **State:** open **Verified:** 2026-09-03

`mykronos` is scanned by both CIs during the migration, and the two lanes
disagree about paths. Concourse checks out into `repo/`, Actions at the root, so
checkov's identical output lands as two separate findings:

    CKV_GHA_7  repo/.github/workflows/promote.yml:34   first seen 2026-08-30
    CKV_GHA_7  .github/workflows/promote.yml:34        first seen 2026-09-01

On 2026-09-03 the two alternated all day about eight minutes apart, same tool
and version (checkov 3.2.334), one reporting five findings and the other two —
different counts because they also cover different trees.

Three effects. Open IaC counts are inflated. A finding has to be dispositioned
twice, and was on 2026-09-03. And the lanes supply each other's absence
evidence, so which findings close is decided by which lane ran last.

**The obvious fix is the wrong one, and `parity` recommends it.**
`mykronos parity ToddGBenson/mykronos` reports Actions at least as good on every
capability and better on two — `dast` and `functional` are `failed` under
Concourse and `reporting` under Actions, verdict `improved`. Read literally,
that says retire Concourse.

It is not comparing like with like. `parity` compares whether each capability
**reports**, never what it **reaches**:

| | Concourse `dast` | Actions `dast` |
|---|---|---|
| Runner | worker on this LAN | `runs-on: ubuntu-latest`, GitHub-hosted |
| Target | `((demo-host))` — an internal address | `localhost` inside the runner |
| Stack | a deployment that outlives the build | ephemeral, built and seeded per run |

A GitHub-hosted runner cannot reach an RFC1918 address on this network. So the
Actions lane is not a better version of the Concourse one — it is the only one
that can run *without* the LAN, and the Concourse one is the only one that can
scan anything actually deployed on it. Retiring Concourse would not consolidate
a duplicate; it would permanently remove the only path to scanning an internal
deployment, including TheHub's own prod, and would foreclose the network
capability the README already describes as having an authorization model and an
ingest path but no scanner.

This is the same caveat the README states about DAST — "reached a deployment,
which is not the same as internet-facing — that lane runs inside CI against an
ephemeral stack" — arriving as a decision rather than a disclosure. The honest
verdict for a capability whose two lanes reach different things is not
`improved`; it is that they are not comparable.

The Concourse `dast` and `functional` lanes being `failed` is therefore a bug to
fix, not evidence for retirement.

**Acceptance criteria**

- The path base is normalised so both lanes produce one finding, and no
  rule/line pair appears under two `file_path` values for one repository.
- `parity` distinguishes a capability whose lanes reach different targets from
  one where a lane is simply better, and does not return `improved` for the
  first. Reaching an internal target is stated where the verdict is.
- A decision recorded that Concourse is retained for internal-target scanning,
  so the next reader of `parity` does not re-derive the wrong conclusion.
- The Concourse `dast` and `functional` failures are diagnosed on their merits.

**Provenance:** DevSecOps assessment, 2026-09-03 (second sweep). The retirement
recommendation was corrected by the operator the same day; the original entry
had repeated `parity`'s verdict without checking what either lane reached.

---

### B-049 — Filling in a risk profile silences the disclosure without changing the rank

**Size:** S **State:** open **Verified:** 2026-09-03

B-033 gave the triage queue a disclosure: what the rank consulted, and what it
could not. It was accurate, and its closing note was sharper than the story —
business context "is not a term in `rank_terms` at all, so this was a
threat-intel ranking presenting itself as a risk one."

The disclosure is wired to whether a **profile exists**, not to whether the rank
**uses one**. `ranking_inputs` (`dashboard.py:315`) computes
`missing_profile = repos - repos_with_a_profile` and emits the "business
context — not consulted" line only when that set is non-empty. `consulted` is a
hardcoded four-element list that never contains business context at all.

So filling the profiles in — the operator half B-033 left open — turns an
accurate warning off:

| | `not_consulted` | is business context a rank term? |
|---|---|---|
| Before (no profiles) | "business context — no risk profile on …" | no |
| After (profiles set)  | `[]` | **still no** |

`rank_terms` (`dashboard.py:241`) is unchanged by this: its terms are severity,
`in_kev`, `epss`, `overdue`/`due_soon`, `blast_radius`, `repo_is_no_go`,
`orphaned` and `fixable`. Not one reads `internet_facing`,
`data_classification` or `business_criticality`. The queue now reports that
nothing is un-consulted while consulting exactly what it did before.

This could not be seen until a profile existed, which is why it survived
B-033's own review. It was found by filling all four in on 2026-09-03.

**The profiles are not wasted** — `oracle/engine.py:719-747` reads all three,
and mykronos's portfolio decision now carries `Handles confidential data
(+10.0)`. The Oracle consumes business context; the queue does not. That is the
defect: two rankings on one estate disagree about which inputs exist.

**Acceptance criteria**

- Either the rank gains terms for the three profile fields, or `not_consulted`
  reports business context whenever it is not a term — regardless of whether a
  profile exists.
- `consulted` is derived from the terms the rank can actually produce rather
  than restated as a literal.
- With all four profiles set, the queue's claim about its own inputs is true.

**Provenance:** DevSecOps assessment, 2026-09-03 (second sweep).

---

### B-050 — Eight live TheHub findings, verified against `develop`

**Size:** M **State:** open **Verified:** 2026-09-03

TheHub's twenty-one open high SAST findings were read one by one at the scanned
commit `7197a028`. Seventeen were dispositioned — fifteen `avoid-sqlalchemy-text`
false positives, one Dockerfile finding accepted on a verified compensating
control, one local-script XML parse accepted with a date. **Four are real**, and
because B-045 means the scanner is stuck on a frozen `main`, each was re-checked
against `origin/develop` by hand. All four are still present in the code people
are writing.

The fix lands in TheHub's repository, not this one. It is recorded here because
the findings are Mykronos's, they cannot close until TheHub ships, and this is
where the operator will look — it should be mirrored to TheHub rather than
worked from here.

**1 & 2 — Script injection in the production deploy workflow.**
`.github/workflows/deploy-prod.yml`, `run-shell-injection`, at lines 67 and 107
on `main` and 71 and 109 on `develop`:

    echo "reason: ${{ inputs.reason }}"
    echo "operator note: ${{ inputs.reason }}"

A free-text `workflow_dispatch` input interpolated straight into a shell `run:`
block. GitHub substitutes before the shell parses, so `"; curl … | sh; #`
executes. The job holds `secrets.HOMELAB_SSH_KEY`, `HOMELAB_HOST` and
`HOMELAB_USER`, so the payoff is the homelab SSH key.

Likelihood is genuinely low — `workflow_dispatch` needs repository write, and
someone with write can already edit workflows. It is still worth fixing: repo
write and *trusted with the prod SSH key* are not the same grant, and the fix is
one line. Pass it through `env:` and reference `$REASON`, which is what this
platform's own `promote.yml:69` and `demo-and-dast.yml:250` already do.

**3 & 4 — Unauthenticated encryption of intimacy data.**
`backend/services/intimacy_service.py:59` and `:67`,
`crypto-mode-without-authentication`. AES-256-CBC with no authentication tag, on
a module whose own docstring is "privacy-first encrypted intimacy tracking" —
the most sensitive data class in the estate, and the reason TheHub's risk profile
now records `data_classification: confidential`.

CBC without a MAC is malleable: anyone who can write the `intimacy_logs` row —
direct database access, a tampered or restored backup, an injection elsewhere —
can alter the ciphertext, and nothing detects it.

**The integrity control that looks like one is not one.** `_hash_data` (line 75)
is documented "SHA-256 hash for deduplication / integrity" and stored as
`data_hash` at line 129. It is **never read back** — no comparison exists
anywhere in the module — and it is an unkeyed digest, so anyone who alters the
ciphertext can recompute it. It provides deduplication. The docstring claims
integrity twice over that the code does not deliver.

**Not overstated:** there is no practical padding oracle. `list_logs` (line 158)
catches `Exception` broadly and returns the same response shape for a padding
failure and a JSON failure, so the two are not distinguishable to a caller. The
exception text does reach the log, which is a much weaker vector.

**Adjacent, not flagged by the rule:** `_get_encryption_key` derives the key as a
bare `hashlib.sha256(raw)` of `INTIMACY_ENCRYPTION_KEY`. That is adequate only
while the variable holds the high-entropy value the error message suggests
(`secrets.token_hex(32)`); a single fast hash over a passphrase is brute-forcible.
HKDF is the right primitive if the input is already a key.

**The migration is unusually cheap, and the module is why.** These logs
auto-purge after seven days. Switching `_encrypt` to `AESGCM` and keeping the CBC
path in `_decrypt` for one purge cycle retires the old format without a
backfill — after seven days no CBC row exists and the fallback is deleted.

**5 & 6 — Escaping applied everywhere except a few fields (added 2026-09-03).**
`react-unsanitized-method` at `frontend/js/dashboard/compliance-monthly.js:728`
and `finances.js:2460`. Both build markup in a template literal and hand it to
`insertAdjacentHTML`, and both escape *most* of what they interpolate — which is
what makes the gaps read as oversights rather than decisions:

- `compliance-monthly.js` wraps `content.topic` and `content.overview` in
  `escapeHtml()`, then writes `${data.completion_message}` raw.
- `finances.js` wraps `cat.category_name` and `cat.reason`, then writes
  `${cat.icon}` raw and `${label}` raw, where `label` falls back to `cat.status`
  when the status is not in its lookup map.

**None of the three is exploitable today, and each for a different reason** —
which is the argument for fixing them rather than closing them.
`completion_message` is a server-side string literal
(`backend/api/compliance_monthly.py:857`). `cat.icon` is
`Column(String(10))` (`models/financial_budget.py:23`), and ten characters will
not carry a working script payload. `cat.status` is computed server-side, not
stored from input.

Each is one `escapeHtml()` call, and each becomes a live stored XSS the moment
its field's source, length limit or content changes — on a system that is
internet-facing and holds personal financial data. `music.js:3968`, flagged by
the neighbouring `raw-html-format` rule, is the counter-example: it wraps every
interpolation in `_esc()` and was dispositioned as a false positive.

**7 — Production's CSP permits `'unsafe-inline'` for scripts (added 2026-09-03).**
Measured on the wire against prod rather than read from the config, which is the
check that matters (`curl -D - http://<prod>:8000/`):

    content-security-policy: default-src 'self';
      script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net ... ;
      ... frame-ancestors 'none'; base-uri 'self'; form-action 'self'

The policy is otherwise well built — `frame-ancestors 'none'`, `base-uri 'self'`
and `form-action 'self'` are all present and all correct, and the full header set
(HSTS, `X-Frame-Options: DENY`, `nosniff`, Referrer-Policy, Permissions-Policy) is
served on every response. `'unsafe-inline'` in `script-src` is the one line that
undoes the part that matters here: **it is exactly the defence that would have
contained findings 5 and 6.** An injected `<script>` or inline handler arriving
through one of the three unescaped `insertAdjacentHTML` interpolations executes,
because the policy permits inline script. The two findings are individually
survivable and compound badly.

Removing it needs the inline handlers in the dashboard JS to move to
`addEventListener`, or a nonce — the second is cheaper against a codebase this
size. Note `img-src` also ends in a bare `*`, which is a smaller matter but
undoes the rest of that directive.

**A correction worth keeping.** This started as "TheHub serves no security
headers", read from `nginx/conf.d/default.conf`, which declares none. That
conclusion was wrong about production: **nginx is the staging frontend**
(`thehub-staging-frontend`, `nginx:alpine`, `:8081`), and prod is
`thehub-backend` serving HTML directly on `:8000` with the FastAPI middleware at
`backend/main.py:464-492` applying the full set. What is true is narrower and
still worth recording — **staging serves none at all**, confirmed on the wire, so
staging and production do not share a security posture and any scan pointed at
staging measures something production is not.

**8 — Dependabot has no cooldown.** `.github/dependabot.yml` configures four
ecosystems and not one declares `cooldown:`, so a newly published version is
eligible for an automatic PR the day it appears. That is the window the recent
registry compromises used: publish a malicious release, get auto-PR'd within
hours, merged by a green pipeline. These four findings are **left open** rather
than dispositioned, because unlike the other 39 mediums read today they name a
real gap with a few lines of YAML as the fix.

**Also worth carrying:** the two nginx findings were accepted rather than
dismissed on the same reasoning. `proxy_set_header Host $host` is safe only
because no handler in TheHub builds a URL from the request host today — a
search finds `request.url.path` and nothing else — and the h2c `Upgrade`
passthrough is safe only because uvicorn implements no h2c upgrade. Both are
properties of the current code, not of the proxy.

**Acceptance criteria**

- `deploy-prod.yml` passes `inputs.reason` through `env:`; no `${{ }}` expansion
  of a user-supplied value remains inside a `run:` body.
- `intimacy_service` encrypts with an AEAD (AES-GCM), and a tampered ciphertext
  raises rather than returning `{}`.
- `data_hash` is either verified on read or its docstring stops claiming
  integrity.
- The three unescaped interpolations are wrapped in `escapeHtml()`.
- `'unsafe-inline'` leaves `script-src`, via a nonce or by moving inline
  handlers to `addEventListener`.
- `.github/dependabot.yml` declares a `cooldown` on all four ecosystems.
- Staging serves the same header set as production, or it is recorded why not.
- The four findings close on two consecutive successful scans — which requires
  B-045 first, since the lane cannot currently see `develop` at all.

**The classifier was right about all twenty-one.** Every `avoid-sqlalchemy-text`
finding was labelled `likely_false_positive` and all four of these were labelled
`true_positive`, with no misses in either direction. The manual pass confirmed
the separation rather than correcting it, which is worth recording: it is the
first time the triage classifier has been checked finding-by-finding against a
whole severity band, and the dampening it produces can be trusted that much more
for it.

**Provenance:** DevSecOps assessment, 2026-09-03 (second sweep).

---

### B-051 — SAST is language-blind, and two repositories are green because nothing can read them

**Size:** M **State:** open **Verified:** 2026-09-03

`keel` has recorded **47 successful SAST runs and zero findings, ever**. Its
`secrets` and `atlas` lanes are the same: 33 and 17 clean runs, one finding in
the repository's whole history, and that one a false positive. `personal-soc` has
nine clean `secrets` runs and has never recorded a finding either.

That reads as two well-kept repositories. It is not what happened.

**keel's analyser cannot read most of keel.** Its `sast` lane runs CodeQL
2.26.3, and CodeQL supports no shell language at all. GitHub's own byte counts:

| repo | composition | analysable by its configured SAST | actually analysed |
|---|---|---|---|
| `mykronos` | Python 80%, TypeScript 13% | 93% | 93% |
| `TheHub` | Python 67%, JavaScript 16% | 84% | 84% |
| **`keel`** | **Shell 69%**, Python 21%, JS 9% | **30%** | 30% |
| **`personal-soc`** | **PowerShell 100%** | **0%** | **no `sast` capability at all** |
| `binnacle` | Shell 67%, Python 23%, JS 9% | 32% | **0% — not onboarded** |

219 KB of keel's shell has never been read by any analyser in this platform, and
every run over it reported success. `personal-soc` is worse in a quieter way: it
carries one capability, `secrets`, so gitleaks greps its content and nothing ever
examines its PowerShell for a defect. Its 30 KB has never been analysed by
anything.

**This is the platform's own thesis, one level down.** Mykronos leads with silent
lanes because "a lane that reports nothing looks exactly like a clean
repository". A lane that reports nothing *because it cannot read the language*
looks exactly the same, and this one reports `success` while doing it — so it
does not appear in the stalled-lane section, does not appear in scan health, and
does not appear as a gap anywhere. It appears as a clean repo. The information
needed to catch it is one API call away: GitHub publishes `/languages` per
repository, and the adapter registry already knows which tool serves each
capability.

Related to B-046 and the same family: a lane whose runs are green while it
watches nothing. B-046 is about a lane pinned to a stale commit; this is a lane
pointed at a language its tool does not implement.

**Coverage across the account, since this is the first time it has been
counted.** Eleven repositories exist; **four are onboarded**. Of the seven that
are not, one matters now — **`binnacle`**, private, pushed 2026-08-31, 30 shell
scripts, 46 workflow YAMLs and 9 Python files, with no scanning of any kind. It
is a fork of `keel` and inherits the same shell-heavy shape.

The other six were examined by hand rather than assumed, and none is urgent:
`blog.toddbenson.net` (private, last pushed 2026-03-20), `apc` (an empty
repository), and four dormant since 2021 or earlier. Two of those are public and
were checked directly because a dormant repository still leaks:
`configFiles` holds cheatsheets and bookmarks with no credential files, and
`terraform-project` commits **no `.tfstate`** — its `0.0.0.0/0` rules are all
`egress`, its SSH ingress is restricted to a single /24, and only its web tier is
open. The one note is that the /24 is a real administrative range published in a
public repository.

**The unread code was read once, by hand, on 2026-09-03 — and it is clean.**
That result is the argument for the capability, not against it: it took a person
with a container and an afternoon to learn something the platform should report
on every push.

- **`keel` and `binnacle` shell** — ShellCheck 0.10.0 over all 30 scripts in
  each: **27 findings, none above `info`, in both**, and the two repositories
  produce byte-identical results because binnacle is a fork. The only
  security-adjacent hits are three `SC2086` unquoted expansions, and all three
  are deliberate: `sprint.sh:268` word-splits a git-derived file list into
  `printf` on purpose, and `ci/scripts/codeql.sh:74` wraps its unquoted `find`
  pattern in `set -f` / `set +f` precisely because the author knew. The six
  `SC2102` hits are ShellCheck misreading GitHub API bracket syntax in
  `configure-github.sh` — a script whose job is to *turn on* secret scanning,
  push protection and Dependabot updates.
- **`personal-soc` PowerShell** — all 608 lines read directly. No
  `Invoke-Expression`, no `DownloadString`, no `-ExecutionPolicy Bypass`, no
  credential literals. Native commands are invoked with the call operator and
  separate arguments rather than composed shell strings, and the HIBP query at
  `Invoke-BreachCheck.ps1:28` wraps the address in `[uri]::EscapeDataString`.
  The sharpest thing in it is deliberate: `Get-WifiPosture.ps1:26` runs
  `netsh wlan show profile key=clear`, which yields the PSK in cleartext, and
  then exports only `KeyLen` — the length of the key content, never the key.
  It answers "is this passphrase short" without writing a passphrase to disk.
- **`binnacle` also carries a fixed RCE worth reading** —
  `ci/scripts/atlas-evidence.sh:120-135` documents a first version that sourced
  the ingestion API's response body as shell, in a container holding the
  Mykronos token, and the positional-and-validated parse that replaced it.

So the finding is not that this code is bad. It is that **four of eleven
repositories are watched, two of the four are watched by a tool that cannot read
them, and the only reason anyone knows the difference today is a manual pass
that will not run again.**

**Acceptance criteria**

- A repository's languages are compared against what its configured capabilities
  can analyse, and a gap is reported where the briefing already reports silent
  lanes — naming the share of the codebase nothing reads.
- `keel` and `binnacle` gain a shell analyser (ShellCheck, or semgrep's bash
  rules) alongside CodeQL; `personal-soc` gains one that reads PowerShell
  (PSScriptAnalyzer). CodeQL supports neither language, so enabling `sast` on
  `personal-soc` as it stands would add a second green lane over unread code
  rather than coverage.
- `binnacle` is onboarded, or a decision is recorded that it will not be.
- The estate view states how many repositories exist versus how many are
  watched. Four of eleven was not visible anywhere before this entry.

**Provenance:** DevSecOps assessment, 2026-09-03 (second sweep), from the
question "what about the other repositories" — which the platform could not
answer because it only knows the ones it was told about.

---

### B-052 — binnacle is onboarded and one repository grant short of being scanned

**Size:** XS **State:** open **Verified:** 2026-09-03

`ToddGBenson/binnacle` was registered on 2026-09-03 (`POST /api/repos`, id
`8a597725`) and sits at **`pending_install` with zero capabilities**, because the
install PR cannot be opened:

    GitHub rejected the change: GET /repos/ToddGBenson/binnacle/pulls
    -> 404: {"message":"Not Found"}

**A 404 rather than a 403 is the diagnosis.** GitHub hides a repository's
existence from a token that has no grant for it. Checked directly with a minted
installation token:

| request | result |
|---|---|
| `GET /repos/ToddGBenson/keel` | 200 |
| `GET /repos/ToddGBenson/mykronos` | 200 |
| `GET /repos/ToddGBenson/binnacle` | **404** |
| `GET /installation/repositories` | 4 repos: TheHub, mykronos, keel, personal-soc |

Installation 152755402 is scoped to *selected repositories* and binnacle is not
among them. Nothing is misconfigured in this platform and no code is missing —
the App simply cannot see the repository.

**This is B-044's shape a second time**: a built-and-waiting capability held shut
by one setting in GitHub's UI. Add `binnacle` to the App installation's
repository list, then re-run the capability PATCH; the registration is
idempotent and already in place.

Worth doing because binnacle is the largest coverage gap in the estate (B-051):
private, pushed 2026-08-31, 30 shell scripts, 46 workflow YAMLs and 9 Python
files, with no scanning of any kind. `atlas`, `sast` and `secrets` — matching
`keel`, which it is a fork of — is the starting set.

**Acceptance criteria**

- `binnacle` appears in `GET /installation/repositories`.
- `PATCH /api/repos/8a597725-.../capabilities` with
  `["atlas","sast","secrets"]` opens an install PR.
- The repo reaches `active` and records its first scan run.
- Note B-051: CodeQL cannot read 67% of binnacle, so `sast` alone will report
  green over its shell. The grant is necessary and not sufficient.

**Provenance:** DevSecOps assessment, 2026-09-03 (second sweep). Registration was
attempted and the blocker found rather than predicted; the `pending_install` row
is deliberate and accurate — it records intent and disappears when the PR merges.

---

### B-053 — The DAST scanner is seventeen months old and says so itself

**Size:** XS **State:** open **Verified:** 2026-09-03

`ZAP-10116-CWE-1104` — "ZAP is Out of Date" — is open twice against `mykronos`,
and it is the scanner reporting on itself rather than on the application. It is
right. `deploy/demo/docker-compose.yml:124` pins
`ghcr.io/zaproxy/zaproxy:2.16.1`, published **2025-03-25**. The current stable
release is **v2.17.0**, published **2025-12-15**.

So the passive DAST lane has been running roughly nine months behind the current
detection rules, and a scanner that cannot see a class of defect reports the same
green as one that looked and found nothing. That is B-051's shape in a third
form: after a lane pinned to a stale commit and a lane pointed at a language its
tool cannot read, a lane running a tool too old to know what to look for.

**Not a one-line bump, which is why this is an entry rather than a fix.** D-053
paused ZAP's active scanning after it measured 548% CPU and 7 GiB and took
production down; spec 32 §11 holds that posture until somebody replaces it with
a measurement taken on a runner. Changing the version of the tool that caused
that outage deserves the same care — the passive lane is what is running today,
and a major-minor bump can change its resource profile.

**Acceptance criteria**

- Either the pin moves to 2.17.x with the demo lane's CPU and memory observed
  across a run, or a decision is recorded that it stays where it is and why.
- If it moves, the two `ZAP-10116` findings close on their own.
- Whatever is decided, the version is pinned rather than floating — `:2.16.1` is
  a deliberate pin and that part is right.

**Provenance:** DevSecOps assessment, 2026-09-03 (second sweep). Left open rather
than dispositioned during the sweep because it names a real gap; quantified here
because "out of date" without a version and a date is not something anybody can
act on.

---

### B-054 — The image registry the deploy path pulls from takes anonymous writes

**Size:** S **State:** open **Verified:** 2026-09-03

`mykronos-registry` (`registry:2`) listens on **0.0.0.0:5000**, plain HTTP, with
**no `auth:` block in its configuration at all**. Read it back from the running
container — `/etc/distribution/config.yml` declares `version`, `log`, `storage`,
`http` and `health`, and nothing else. There is no authentication to fail.

Anonymous read is demonstrable from any host on the network:

    $ curl http://192.168.0.14:5000/v2/_catalog
    {"repositories":["mykronos-backend","mykronos-frontend","thehub"]}

**The write side is what makes this more than disclosure.** A registry with no
`auth:` accepts pushes from anyone who can reach it, and something already runs
what it serves: `thehub-demo-backend` is running
`localhost:5000/thehub:7197a02837377eef0af70f14746102df33286de7` right now.
Overwriting a tag that the demo or deploy path consumes is code execution on this
host, from any device on the LAN, with no credential involved.

**Contrast, which is why this reads as an oversight rather than a posture.** The
same scan found MinIO on 9000 also LAN-reachable and correctly refusing an
anonymous bucket listing with `403 AccessDenied`, and Vault absent from the LAN
entirely (127.0.0.1 only), and the Mykronos API answering an unauthenticated
request with `401` plus a full security header set. Everything else on this host
is authenticated or loopback. The registry is the one thing that is neither.

**No scanner in this platform could have found it.** It is not in a repository,
so SAST, secrets and IaC never see it; it is not a dependency, so `containers`
and `atlas` never see it; DAST scans applications, not a registry API. It took a
port scan of the host, which is the capability the README records as **"Not
started — the authorization model and the ingest path exist; no scanner does."**
This is the argument for finishing that lane.

**Correction, 2026-09-04: do not bind this to 127.0.0.1.** The first version of
this entry proposed exactly that, and it would take the build down. The
exposure is load-bearing and the compose file says so at the service:
"Published on all interfaces because garden task containers reach it by host
IP; they cannot resolve Docker service names." Confirmed in the pipeline —
`set-thehub-pipeline.ps1:115` sets `$Registry = "192.168.0.14:5000"` and the
kaniko task pushes to `${REGISTRY}/thehub:${SHA}`. Concourse reaches this
registry at the **LAN address**, so no bind address can serve the build without
also serving the network. The proposed fix and the working pipeline were
mutually exclusive, which is worth more than the finding it was attached to.

**Two fixes that actually work, in increasing order of effort.**

*Firewall scope.* Concourse's garden containers arrive from the Docker bridge
subnets, not from the LAN. On this host those are `172.17.0.0/16` (bridge),
`172.19.0.0/16` (concourse), and `172.18/20/21/22/24.0.0/16` for the
application stacks. A host rule permitting 5000 from `172.16.0.0/12` and
loopback and denying it elsewhere closes LAN access with the build path intact.
It is one rule and it changes no configuration any service reads.

*Authentication.* `registry:2` takes `REGISTRY_AUTH=htpasswd`, which is the
defence-in-depth version and survives a machine moving networks. It costs
credentials in two more places: kaniko's `--destination` push, and the host's
`docker login` before it pulls. Both can resolve from Vault, which already
holds every other credential this pipeline uses.

**Acceptance criteria**

- `GET /v2/_catalog` from another host on the network fails, **and** a `build`
  job still pushes successfully. Both, or the change is not done.
- Whichever route is taken, the compose comment stops saying the exposure is
  required, because after the firewall rule it is required only from 172.16/12.
- A decision is recorded either way: a registry deliberately open on a trusted
  LAN is a defensible position, it is just not one anybody has stated.

**Provenance:** DevSecOps assessment, 2026-09-03 (second sweep), from an nmap
service scan of 192.168.0.14 run at the operator's request. Recorded as a
declared surface on `mykronos` with the catalog response as its evidence.

---

### B-055 — The promotion gate was fixed in one repository and applied from another — **half done**

**Size:** M **State:** open **Verified:** 2026-09-04

**The applied pipeline let a failed security scan promote to production, and had
done since #55167 was "fixed".**

Three copies of TheHub's pipeline existed and two of them disagreed:

| copy | `insider.passed` | gates prod on the scans? |
|---|---|---|
| TheHub `main` (`7197a028`) | `[api-inventory, dast-demo, oracle-gate]` | yes |
| TheHub `develop` | `[oracle-gate]` | **no — regressed** |
| **this repo's copy, which is what gets applied** | `[oracle-gate]` | **no** |
| live, from `fly get-pipeline` | `[oracle-gate]` | **no** |

So the #55167 fix landed in TheHub's repository and **never reached the pipeline
that runs**. `api-inventory`, `dast-demo` and `functional-dast` hung off
`deploy-demo` as siblings of the gate rather than parts of it, and a commit whose
demo DAST failed stayed eligible for `deploy-prod`. That is the 2026-08-20 state
the guard test names — api-inventory failed builds #14-#19 while oracle-gate #20
went green — still live on 2026-09-04. This is D-081 with a security
consequence: the applied pipeline is the one that governs, and nothing compared
it to the repository that fixed it.

**Fixed and applied 2026-09-04.** This repo's copy now reads
`passed: [oracle-gate, api-inventory, dast-demo]`, verified live:

    LIVE insider.passed = ['api-inventory', 'dast-demo', 'oracle-gate']
    LIVE gate (13 jobs): api-inventory, build, containers, dast-demo,
      dependencies, deploy-demo, iac, insider, oracle-gate, prompt-evals,
      sast, secrets, unit

`functional-dast` is deliberately excluded and the reason is now in the file, as
the guard test requires: it is **paused** under D-053, and a `passed:` on a
paused job can never be satisfied — listing it would close promotion
permanently rather than tighten it.

All six of `test_pipeline_promotion_gate.py`'s gate assertions were replayed
against this copy and pass.

**What is left, and it is not this repository's to fix.**

1. **TheHub's `develop` still carries the regression.** Its twelve red tests are
   the guard working exactly as designed — catching a regression before it
   reaches `main`. The fix is the same one-line change in
   `concourse/pipelines/thehub.yml` there.
2. **Until those twelve are green, `develop` cannot be scanned at all**, because
   every scan lane carries `passed: [unit]`. That half of this entry stands: a
   branch with a red suite receives zero security scanning, silently, and it is
   why the one-off `develop` scan on 2026-09-03 produced a single run — unit,
   failed, 0 findings. B-045's fix therefore still waits on this.
3. **Nothing reconciles the two copies.** `scripts/check_applied_pipelines.py`
   (D-081) compares the applied pipeline to *this* repository's file; it cannot
   see that TheHub's own copy has moved ahead. That gap is what let a fix exist
   and not take effect for two weeks.

**Acceptance criteria**

- ~~`api-inventory` and `dast-demo` are upstream of `deploy-prod` in the applied
  pipeline.~~ Done 2026-09-04.
- TheHub's `develop` copy matches, and its twelve promotion-gate tests pass.
- A check compares TheHub's copy against this repository's, not just the applied
  pipeline against this one — the direction that was missing.
- A scan lane that cannot run because an upstream job failed is distinguishable
  in the briefing from one that is merely silent.

**Provenance:** DevSecOps assessment, 2026-09-03 (second sweep); corrected and
half-closed 2026-09-04. The first version of this entry said the gate had never
been wired; it had, on TheHub's `main`, and the real defect was that the applied
copy never received it.

---

### B-056 — A lane is a repository and a capability, with no room for a branch

**Size:** M **State:** open **Verified:** 2026-09-04

Lane health groups by capability alone (`dashboard.py:2124`):

    SELECT capability, max(coalesce(completed_at, started_at))
    FROM scan_runs
    WHERE repo_full_name = ?  GROUP BY capability

`scan_runs` carries a `branch` column and nothing reads it here. So a
repository cannot have two branches scanned under one capability: both write to
the same lane, and since closure requires two consecutive successful scans that
no longer observe a finding (spec 05 §5), alternating branches flip findings
between open and fixed depending on which tree ran last. That is B-048's defect
— two producers, one lane — arrived from a different direction.

**It forces an either/or that is not a real one.** TheHub's pipeline both
*scans* and *gates*: `deploy-demo` requires
`passed: [secrets, sast, dependencies, containers, prompt-evals, iac]`, and
Concourse's `passed:` constrains versions of the resource being fetched, so a
job cannot be gated on `unit`-of-main while fetching `develop`. Scanning
therefore follows whichever branch the deploy path follows.

The right answer — **scan `develop` because that is where the code is, gate
deploys on `main` because that is what ships** — needs a second scan lane, and a
second scan lane on the same capability is the collision above. So the 2026-08-18
directive was not a preference; it was the only expressible option.

**What was chosen instead, on 2026-09-04:** point the whole pipeline at
`develop`. One producer per lane, no collision, and scanning follows the code.
The cost is the one the directive named — `deploy-demo` now auto-deploys
`develop` to the demo environment and can race `deploy.sh`. Production is
unaffected: `deploy-prod` carries no `trigger:` and still waits for a person.

**Acceptance criteria**

- Lane health, and the two-consecutive-scans closure rule, are evaluated per
  `(repo, capability, branch)` rather than per `(repo, capability)`.
- A repository can declare which branch a capability's lane is *expected* on, so
  a scan of another branch is recorded without disturbing that lane's health.
- With that in place, TheHub can scan `develop` and gate `main` at once, and the
  either/or above stops being one.
- B-048 is re-read against this: mykronos's duplicate IaC findings are the same
  defect with two CIs instead of two branches.

**Provenance:** DevSecOps assessment, 2026-09-04. Found while trying to
implement "scan develop, deploy from main" and discovering the platform cannot
express it.

---

### B-057 — A pin guarded by a comment, raised anyway — **done upstream**

**Size:** S **Verified:** 2026-09-04 **Closed:** 2026-09-04 (TheHub #281)

`thehub/unit` #85, the first build after the pipeline moved to `develop`, failed
in 4m34s without running a single test:

    ImportError while loading conftest '.../backend/tests/conftest.py'
    anthropic/_base_client.py:1686: in __init__
    TypeError: Invalid `http_client` argument; Expected an instance of
      `httpx2.AsyncClient` but got <class 'httpx.AsyncClient'>

**The cause was not a loose range.** `backend/requirements.txt` pinned
`anthropic>=0.40.0,<1.0` under eleven lines of comment explaining why the bound
must not move on its own, ending "Raise a bound only together with the matching
call site in services/ai/." Dependabot #267 raised it to `>=1.0.0,<2.0` and the
PR merged. **The comment survived; the pin it was guarding did not** — and this
was the second occurrence of the same failure.

**1.x breaks two things, and the first diagnosis here found only one.** Measured
upstream against anthropic 1.3.0 rather than assumed:

    AsyncAnthropic(http_client=httpx.AsyncClient(...))   -> TypeError, at import
    messages.create(..., temperature=0.3)                -> unexpected kwarg,
                                                            on all four call sites

The first is what #85 hit; the second would not have surfaced until a Claude
call ran. A fix addressing only the first — passing `timeout=` and letting the
SDK own its client — was drafted here and **abandoned**, because it would have
made collection succeed while every Claude call failed at runtime. A green build
over a broken service is worse than the red build it replaces.

**Fixed upstream by TheHub #281**: revert the pin to `<1.0`, and turn the guard
comment into `backend/tests/unit/test_sdk_pins_match_their_call_sites.py`, which
asserts the coupling in both directions — move the pin without migrating the
call sites and it fails; migrate the call sites and it tells you the pin may
move. Their reasoning is the durable part: *a comment cannot fail a build.*

**What still stands from the original entry.** The blast radius was real: every
scan lane carries `passed: [unit]`, so while this held, TheHub was not scanned at
all — the third distinct cause in two weeks, after the ingestion token (B-024)
and the promotion-gate regression (B-055), none of them a scanner problem. And
moving to `develop` did not break this: `main` last passed `unit` on 2026-08-27
and had never met the SDK, so the branch change revealed a break that was
already there with nothing running to notice it (B-046).

**What does not stand.** The original entry blamed a wide range plus B-050's
missing dependabot `cooldown`. A cooldown would have delayed this, not prevented
it — the range was *narrow* and correct, and the bot widened it. B-050's
cooldown point is still worth doing and is not the mechanism here.

**One note for the history.** The upstream entry records the bad pin as merging
"in PR #276..#279". **#279 is this assessment's own re-export PR.** It did not
introduce the pin, but it merged inside that window, so a reader bisecting the
range will land on it.

**Provenance:** DevSecOps assessment, 2026-09-04, from the first build after
B-045 closed. Found because the reporting refactor landed the same day: this was
the first failed Concourse run TheHub has ever recorded — `Reported
integration_tests=failed` — where before, a failed lane said nothing at all.
Corrected the same day after finding #281 had already landed a better fix.

---

### B-058 — `not_applicable` is a status nothing ever sets, so a repo is failed for lacking what it does not have

**Size:** M **State:** open **Verified:** 2026-09-04

`ssdf.summarise` counts four statuses — `met`, `partial`, `not_evidenced`,
`not_applicable` — and across all five onboarded repositories the fourth is
**zero**. Nothing sets it. A practice a repository cannot possibly evidence and
one it simply has not done are the same row.

That understates two repositories badly, and on a compliance view an
understatement is not the safe direction to be wrong in — it is the one that
gets somebody told to build what they do not need.

| repo | met | measured contents |
|---|---|---|
| `keel` | 2/13 | 0 Dockerfiles, 0 `.tf`, 0 web entrypoints, 10 workflows |
| `personal-soc` | 0/13 | 0 Dockerfiles, 0 `.tf`, 0 web entrypoints, 0 tests, 2 workflows |

So `keel` is marked down on **PW.4** ("run the dependency and container lanes")
for having no containers, on **PW.8** ("run the test lanes") for having almost
no tests, and on **RV.1** for not running `dast` on a schedule against an
application that does not exist. `personal-soc` is 100% PowerShell with no
build artifact at all. Neither is failing; neither has the thing.

**The pressure this creates is the actual risk.** The obvious way to move those
numbers is to enable `containers`, `dast` and `unit` anyway. Each would produce
a lane that runs, finds nothing because there is nothing, and reports
`success` — a green lane over an empty target, which is exactly what the
maturity model refuses when it separates `reporting_capabilities` from
`enabled_capabilities` so a repository cannot "claim coverage by flipping a
toggle". The SSDF view has no such guard: a practice moves to `met` on a lane
reporting, and a lane over nothing reports.

**What was done instead, 2026-09-04.** Only `iac` was enabled on either, because
it is the one that genuinely applies — checkov reads GitHub Actions workflows
(`CKV_GHA_*`, which is where mykronos's own IaC findings come from), and keel
has ten and personal-soc two. Install PRs: keel #77, personal-soc #6. Nothing
else was enabled, so their scores stay low and honest rather than rising on
lanes scanning nothing.

**Acceptance criteria**

- A practice whose capabilities have nothing to act on in this repository
  reports `not_applicable`, with the reason — "no container image is built
  here" reads differently from "the container lane has never run".
- The determination is evidenced rather than declared: the SBOM, the presence
  of a Dockerfile, a build artifact — something observable — not a per-repo
  checkbox, which is a toggle again wearing a different hat.
- `keel` and `personal-soc` stop being marked down for PW.4, PW.8 and RV.1.
- The counts distinguish "12 of 13, one not applicable" from "12 of 13, one
  outstanding". They are different sentences.

**Provenance:** DevSecOps assessment, 2026-09-04, from working the two lowest
scoring repositories and finding most of their gaps were not gaps. Related to
B-051: the same two repositories are also the ones whose languages no
configured analyser can read.

---

### B-059 — The pipeline standard covers two pipelines of four, and the two it skips would fail it

**Size:** M **State:** open **Verified:** 2026-09-04

`scripts/check_pipeline_conformance.py` enforces the pipeline standard, and its
own list is two entries long:

    PIPELINES = (
        "deploy/concourse/pipelines/mykronos.yml",
        "deploy/concourse/pipelines/thehub.yml",
    )

`personal-soc.yml` and `keel` are not in it. That is not a small exemption:

| pipeline | work tasks | **without a timeout** |
|---|---|---|
| `mykronos.yml` | 28 | **0** |
| `personal-soc.yml` | 12 | **12** |

**Every task in personal-soc's pipeline is uncapped, and the worker is
shared.** PS-7's own rationale, written on the `hub_report` anchor, is that "a
hook that hangs holds the single worker exactly as a scan does". There is one
worker for the whole estate. A hung task in personal-soc holds `mykronos` and
`thehub` behind it — so this is an availability property of the platform, not a
tidiness property of one repository.

The standard is also what asserts a reporting job is cross-checked, which is how
`silent` and `never_reported` become detectable at all (spec 15 §4a.1). Two
pipelines are outside that guarantee.

**Adding them to `PIPELINES` fails immediately**, which is presumably why it was
not done — twelve violations arrive at once and the check goes red on work
nobody scheduled. That is an argument for a migration order, not for the
exemption: the check that would have caught this is the check that was scoped
around it.

**Found by adding a job to it.** `iac` was enabled on `personal-soc` on
2026-09-04 and the new job was written with a `timeout: 15m` — noticed only
because the conformance test was run by hand against a pipeline it does not
cover. Nothing would have objected to a thirteenth uncapped task.

**Acceptance criteria**

- `personal-soc.yml` and keel's pipeline are in `PIPELINES`, or an entry records
  which rules they are exempt from and why, per pipeline rather than by absence.
- Every work task in every listed pipeline carries a timeout. Twelve tasks need
  a measured cap, the way D-051 set the others from observed durations rather
  than from a round number.
- A pipeline added to the repository is covered by the standard by default —
  the current shape means a new pipeline is exempt until somebody remembers.

**Provenance:** DevSecOps assessment, 2026-09-04, while adding the `iac` lane to
`personal-soc`. Related to B-058: the same repository was also the one whose
SSDF gaps were mostly practices it cannot apply.

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
- **Two overdue critical findings on TheHub** — *resolved 2026-09-03.* Both were
  false positives in `concourse/pipelines/thehub.yml`: gitleaks matched the
  Concourse variable placeholder `((anthropic-api-key))` and a line inside an
  escaped YAML flow scalar. Every credential in that file resolves to a Vault
  placeholder and the file holds no literal secret. Dispositioned with reasons.
  Worth keeping because the mechanism worked and the input did not: all four of
  this estate's critical findings were false positives, which is what a critical
  count has to survive to mean anything.

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

### B-040 — Accepted risk is invisible to the risk decision — **done**

**Closed 2026-09-03** by #191. Accepted findings are excluded from every open
count, which is correct — a risk somebody consciously took is not one nobody
has looked at. That exclusion is *earned* by acceptances that are decisions,
and this platform's own definition is "a decision with a premise, and the
premise is the part that expires".

On the live estate, **294 of 294 acceptances had neither**: no grounds
recorded, no review date. A repository could move 294 findings out of its
counts by setting a status once and never being asked about them again.

Oracle now carries two light, capped terms — `accepted.unqualified` and the
heavier `accepted.expired`, because a review date that has passed is worse than
never setting one. An acceptance with grounds and a future date still costs
nothing, which is the whole point: the term punishes the missing premise, not
the decision.

---

### B-038 — Nothing runs before `git push` — **closed as a decision**

**Closed 2026-09-03** by D-101. Asked directly, the operator confirmed the
position: this is a control plane, not a scanner. The entry always said it
needed a decision before it needed code, and that is the decision.

What it costs is written down rather than left implicit — a committed
credential is found after it is committed, so rotation and not removal is the
first step, which is why the remediation guidance says exactly that.

---

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
