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

Seven, from five sweeps: 2026-09-03 (first and second), 2026-09-04,
2026-09-05, and one finding from verifying that day's own work. Every entry here was reproduced against the live system before it
was written; the evidence is in each entry rather than a link to a dashboard
that will have moved on.

**The nine that needed the operator rather than code were decided on
2026-09-05, as D-108 to D-116.** Three stay open as execution and each carries
its decision inline: the registry is closed by network scope rather than by
binding (B-054, D-109); the remaining branch-protection controls, now that
D-110's review half is applied and its status-check half is understood
(B-060); and the notifier's webhook, which needs a credential this repository
must not hold (B-035, D-112). Coverage was the fourth and is closed: its lane
was retired under it (B-042, D-113 corrected by D-117, then D-118), and D-121
gave it a weekly home off the critical path. Five are in Closed: the ranking queue's
disclosure derived from its terms (B-049, D-116, built the same day); B-043,
closed as a decision because free-text Consult stays deferred (D-115); binnacle
granted with its partial coverage recorded (B-052, D-111 — executed on the
5th, undone on the 7th, redone on the 8th); ZAP on 2.17.0 with the resource
read taken on the runner (B-053, D-114, 2026-09-08); and `cloud` disabled on
TheHub (B-018, D-108, executed on the 5th inside B-062's restore and confirmed
on the 9th).

**None of the four is blocked any longer, and none of them was a defect in this
platform's code.** Three are a setting, a credential or a rule outside this
repository; the fourth is a call about this deployment's CI budget. Writing
code against any of them before the decision would have been guessing, which is
why they waited.

**One story keeps arriving from different directions: nothing here checks that a
scan covered anything.** It began as the second 2026-09-03 sweep's four —
B-045 the instance (TheHub scanned on `main` while every commit landed on
`develop`, now closed), B-046 the reason nobody saw it (the stalled-lane
detector measured silence, not coverage — now closed), B-047 the missing exit
for findings a disabled capability strands (closed), B-048 the same blind spot
from the other side — two lanes at different path bases, each supplying the
other's absence evidence (closed).
Every sweep since has added a form of it: B-051, a lane pointed at a language
its analyser cannot read, and the widest gap here — four of the account's eleven
repositories watched at all, two of the four green for that reason. B-053, a
scanner too old to know what to look for, now closed. Three are closed: B-061, `event_driven` calling a capability fine without
checking anything runs it; B-047, the missing exit itself; B-058, a status
nothing set, so a repository was failed for lacking what it cannot have;
B-063, `--no-resolve` assessing the declared floor; and B-056, no branch
dimension on a lane, which is why B-045 was forced rather than chosen.

**Three are live defects rather than reporting gaps.** B-064 — TheHub's most
sensitive table encrypted with unauthenticated CBC. B-054 — the registry the
deploy path pulls from taking anonymous writes from any host on the LAN, which
no scanner in this platform could have found; the rule that closes it is
written and needs one elevated run. B-050 — eight live TheHub findings, read by
hand because B-045 meant no scanner had looked at that code in sixteen days.

**The one that was the platform mis-recording its own state is closed.**
B-062 — enabling one capability silently revoked five others and the audit
said nothing was removed — sprang a second time on binnacle on the 7th and
was built out on the 9th as D-119. Its sibling B-049 — filling in the four risk profiles turned an accurate
disclosure off without changing the rank behind it, found only because the
operator half of B-033 was finally done — was built on 2026-09-05 and is in
Closed.

**B-065 arrived from checking the work rather than from a sweep.** Re-applying
the `mykronos` pipeline for D-113 produced a clean drift report and, in the same
output, three credentials stored inline in the other two applied pipelines. One
is a live model key that is already in Vault and inline only because `thehub` has
not been re-applied since; one is an ingestion token genuinely missing from
Vault; one is a deliberate one-hour token that should stay. The other half of the
entry is that the check flags three more that are empty strings, so a warning
about six names three real problems — and a warning that overstates gets
discounted along with the parts of it that matter.

B-055 is half done. The applied pipeline no longer lets a failed security scan
promote to production; what remains is TheHub's own copy, and a check that
compares the two repositories rather than only the applied pipeline against this
one.

B-038 closed on 2026-09-03 as D-101 — the answer was that the position stands.
The risk gate was asked about at the same time and stays advisory, recorded as
D-102 rather than a backlog entry, because a deliberate posture with the
evidence to defend it is a decision and not outstanding work.

Everything from the 2026-09-01 monitoring sweep, all three gaps that writing
[`finding-lifecycle.md`](finding-lifecycle.md) exposed, and five of the seven
entries the 2026-09-03 DevSecOps assessment produced are in Closed.

**B-032 through B-038 came from a DevSecOps assessment of the workflow on
2026-09-03.** Five landed the same day — the check run now names what a change
introduced (B-036), every finding has an owner (B-034), the queue says what it
could not rank by (B-033), a finding has a record of its own (B-032), and the
current SBOM is reachable without knowing an evidence id (B-037). They shared a
shape worth noticing: almost none of them was a missing feature. The finding
record is an assembly over eleven services that already exist; the risk model is
built and unpopulated; routing is switched on and nothing is routed; the notifier
is configured and addressed to nobody; the check run's introduced-findings query
has existed since D-048 and only the gate reads it. The platform's capabilities
are ahead of its wiring, which is a better problem than the reverse and a
different one from the backlog it usually collects.

B-038 is the exception and the only one that is genuinely absent.

**The sequence below is the 2026-09-03 ordering and is kept as written.** Six of
its seven entries have since closed; it is left here because the reasoning about
what unlocks what is the reusable part, not the list.

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

**B-018** was a decision, not a defect, and it went the way of disabling
(D-108). It was deferred on 2026-09-01 with the capability left enabled and
inert, which the entry itself called the one indefensible state; that hold
lasted four days and is in Closed.

### B-035 — The notifier is configured and addressed to nobody

**Size:** S **State:** open **Verified:** 2026-09-03

`MYKRONOS_SLACK_NOTIFY_MIN_SEVERITY=high` and `MYKRONOS_ROUTING_ENABLED=true`
are both set; `MYKRONOS_SLACK_WEBHOOK_URL` is empty. Everything in the platform
is therefore pull: a new critical, a KEV match, or a lane going silent reaches
somebody only if they remember to look.

**Needs the operator, not code** — the webhook URL is a credential this
repository must not hold.

**Decided 2026-09-05 — D-112: configure the webhook.** Through Vault, like
every other secret. B-034 closing is what unblocked it — before ownership was
real these would have been broadcasts. Three separate multi-day scanning outages
in two weeks (B-024, B-055, B-057), none of which announced itself, are the
argument.

**Acceptance criteria**

- Either a webhook is configured, or the absence is recorded as a decision the
  way D-053 recorded paused DAST, so it stops reading as an oversight.

**Provenance:** DevSecOps assessment, 2026-09-03.

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

### B-051 — SAST is language-blind, and two repositories are green because nothing can read them — **half done**

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

**The detection is built, 2026-09-09.** `analysers.py` declares what each
static analyser implements, `GitHubClient.languages` reads the byte counts, and
the briefing has a section for source no analyser here can read — beside the
stalled lanes, because it is the same failure with the alarm removed. Computed
against the live estate rather than quoted from this entry:

| repository | analyser | unread | what it cannot read | closed by |
|---|---|---:|---|---|
| `personal-soc` | codeql | **100%** | PowerShell | `psscriptanalyzer` |
| `keel` | codeql | **70%** | Shell | `shellcheck` |
| `binnacle` | codeql | **68%** | Shell | `shellcheck` |
| `mykronos` | codeql | 4% | PowerShell | `psscriptanalyzer` |
| `TheHub` | codeql | 0% | — | — |

Every row's gap now has a tool that closes it, measured rather than assumed:
`codeql` + `shellcheck` leaves keel and binnacle at nothing, `codeql` +
`psscriptanalyzer` leaves personal-soc and mykronos at nothing.

**Run against the live lake on 2026-09-09, and the estate corrected the table
in two ways.**

`mykronos` and `TheHub` do not run CodeQL alone — the lake holds successful
`sast` runs from **`codeql` and `semgrep`** for both, which is why the tool set
is read from what has reported rather than from the one name in the config.
With semgrep counted, `TheHub` is 2.7% unread rather than 0%, and what is left
is the finding worth having:

| repository | analysers reporting | unread | what |
|---|---|---:|---|
| `TheHub` | codeql + semgrep | 2.7% | **664 KB of PLpgSQL**, 49 KB of PowerShell |
| `mykronos` | codeql + semgrep | 4.4% | 197 KB of PowerShell |

**664 KB of stored procedures on the only internet-facing repository in the
estate, read by nothing.** Neither analyser configured here implements
PLpgSQL. That is a bigger unread surface than anything the entry started
with — keel's 219 KB of shell was the headline — and it was invisible until
something measured it. It needs its own answer and is not covered by either
analyser added today; `SAST_LANGUAGES` has no tool for it to name.

`mykronos`'s 197 KB of PowerShell is its own operations scripts, and the
`sast-powershell` lane built today closes it the moment it is enabled here.

**And the first live run found a false positive in the check itself.** 7 KB of
`Rich Text Format` counted against TheHub as unread source. `NOT_SOURCE` now
excludes documents and markup alongside the configuration languages other
capabilities own — the two have different reasons and the same consequence.
Reporting a document as unanalysed code is exactly the page-of-gaps failure
this was written to avoid, arriving on its first day.

**mykronos's own 4% was not in this entry**, and it is the same defect: its
PowerShell operations scripts are read by nothing. Small, real, and found by
the check rather than by a person.

**Four judgements are in the code rather than in this file**, because each one
decides whether the section is worth reading. Configuration languages —
Dockerfile, HCL, Jinja, CSS — are not counted as unread source: they are read
by `containers` and `iac`, and reporting them would produce a page of gaps
nobody should act on. Only `sast` is asked the question, because `secrets`
greps content, `atlas` reads manifests and `containers` reads an image. *Any*
unread source is reported rather than a threshold, since a percentage invites
an argument about where the line goes. And an unknown tool reads nothing:
a tool with no language list here says so rather than being assumed
comprehensive.

**No re-run button, deliberately.** Running the lane again reads the same
bytes with the same tool and reports success again. The action names the
languages and points at the lane's CI view; choosing a second analyser is a
decision about the repository, not a request this platform can make.

**The readability question is asked of every analyser reporting, not of the
configured one.** A repository running two lanes has two tool names in its
scan runs and one `enabled_tool` in its config, so reading the config would
report keel as 70% unread on the day it stopped being. It reads the distinct
`tool_name` of successful `sast` runs from the lake instead — evidence over
intent, the rule the SSDF view already holds itself to.

**Three things the tests caught, all of them mine.** The workflow blanket-
ignored ShellCheck's exit code, which the pipeline standard forbids and which
would have reported a clean scan for a scan that broke. Registering the
Actions workflow's filename stem in `CAPABILITY_BY_JOB` put it in
`jobs_for_capability("sast")`, where the "scan now" button tried to trigger a
Concourse job that does not exist. And `test_every_uploading_template_has_an_
adapter` assumed a template's key is the capability it reports — true until
now, and it reads the rendered workflow instead.

**Acceptance criteria**

- ~~A repository's languages are compared against what its configured
  capabilities can analyse, and a gap is reported where the briefing already
  reports silent lanes — naming the share of the codebase nothing reads.~~
- `keel` and `binnacle` gain a shell analyser alongside CodeQL. **Built
  2026-09-09 and not yet enabled on either.** ShellCheck is a registered
  `sast` tool with its own adapter, and `sast-shell` is a workflow template
  that runs it. Measured: `codeql` alone leaves keel 70% unread, `shellcheck`
  alone leaves it 30%, and the two together leave **nothing** — which is why
  this is *alongside* rather than *instead of*, and why swapping the tool
  would have traded one blind spot for another.

  **Two lanes on one capability**, which is how "alongside" is expressed here.
  Both upload `sast`; `_base.yml.j2` gained an `upload_capability` block so a
  template's own name can stay distinct — the workflow, job and concurrency
  group must not collide — while what it *reports* is shared. A repository
  does not gain a new thing to enable by adding an analyser.

  **ShellCheck's levels are about correctness, so nothing maps above
  `medium`.** `error` means the shell will not do what the author wrote, which
  is not a statement that an attacker can do anything; a linter that can reach
  `high` competes with the dependency scanner for the top of a queue it has no
  business being at the top of. The 2026-09-03 hand pass over keel found 27
  findings, none above `info`, and that is the baseline this lane should
  reproduce — on every push rather than once an afternoon.

  **`personal-soc` gained one that reads PowerShell**, also 2026-09-09 and
  also not yet enabled. PSScriptAnalyzer is a registered `sast` tool with its
  own adapter and a `sast-powershell` template, and it takes that repository
  from **100% unread to nothing**. It runs on the runner's own `pwsh` rather
  than in a container, with the module version pinned: an analyser that
  silently changes its rule set changes what "clean" means without anybody
  deciding to.

  **Its severity is an integer, and that was the trap worth writing down.**
  `Invoke-ScriptAnalyzer | ConvertTo-Json` serialises the .NET enum as its
  ordinal — `0` Information, `1` Warning, `2` Error, `3` ParseError — so a
  reader expecting `"Warning"` gets `1`. A mapping that only understood the
  names would have filed every finding at the default severity while looking
  like it worked. Both forms are read, because `-EnumsAsStrings` exists.

  Two more shapes that would have been quiet failures: `ConvertTo-Json`
  unwraps a single-element array into a bare object, so a repository with
  exactly one problem would have reported a clean scan; and `ScriptPath` is
  absolute on the runner, so without the workspace strip every finding's
  identity would move with the checkout layout.

  Neither analyser is enabled anywhere yet. Enabling them is a capability
  change per repository, and the numbers above say what each would close.
- ~~`binnacle` is onboarded, or a decision is recorded that it will not be.~~
  Onboarded 2026-09-04, granted on the 5th, and `secrets` restored on the 8th
  (B-052, D-111). It is `active` with `sast` enabled — over a repository
  CodeQL reads 32% of, which D-111 recorded at the time as a qualified green
  and which this check now measures on every render.
- ~~The estate view states how many repositories exist versus how many are
  watched.~~ **Decided and built 2026-09-09.** The operator widened the App
  installation to all repositories, so the question is answerable from the
  App's own scope rather than from a person reading the account. The portfolio
  carries an `estate` block: how many the installation can see, how many are
  onboarded, and **the names of the ones that are not** — a number says there
  is a gap, a name says which repository to go and look at.

  Read live once the listing worked: the installation sees **11**, five are
  onboarded, and six are not — `configFiles`,
  `ccfr-security-web-app-automation`, `concourse-maven-spring-boot`,
  `terraform-project`, `apc` and `blog.toddbenson.net`. Those are the six the
  2026-09-03 pass examined by hand and judged not urgent; the difference is
  that the platform now names them on every render rather than waiting for
  somebody to ask.

  Two things it refuses to do. `visible` stays `null` when the listing cannot
  be read, because "the App could not tell us" and "the account has no other
  repositories" are different facts and only one is good news. And the
  response carries a sentence saying the count is only as wide as the grant —
  an installation scoped to five would report five of five, which is true
  about itself and says nothing about the account.

**Provenance:** DevSecOps assessment, 2026-09-03 (second sweep), from the
question "what about the other repositories" — which the platform could not
answer because it only knows the ones it was told about.

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

**Decided 2026-09-05 — D-109: close it by network scope.** A host rule
permitting 5000 from `172.16.0.0/12` and loopback, denying it elsewhere.
`REGISTRY_AUTH=htpasswd` from Vault is recorded as the follow-up rather than the
first move, because scope is a property of where this machine sits and
authentication survives it moving.

**Written 2026-09-09 as `deploy/concourse/Set-RegistryScope.ps1`, and D-109's
own wording would have taken the build down.** Implemented literally — allow
`172.16/12` and loopback, block `Any` — the block wins: Windows Defender
Firewall evaluates **block rules ahead of allow rules**, so a block on `Any`
beats the allow beside it and kaniko's push dies along with the LAN access.
That is the same trap the loopback correction above describes, one layer down,
and it was caught by checking the precedence rather than by trying it.

The intent has to be expressed as what is *denied*, so the script installs one
inbound block rule scoped to this host's LAN prefix (`192.168.0.0/24`,
computed from the host's own non-Docker addresses rather than hard-coded).
Evidence that this leaves the build alone: every write in the registry's log
arrived from `172.19.0.1`, the Concourse bridge gateway, and Windows does not
filter loopback at all, so `localhost:5000` pulls are untouched either way.
`-WhatIf` runs unelevated and prints the plan; `-Remove` undoes it.

**What is left is one elevated command and two readings.** A firewall rule
needs an administrator prompt this session does not have, and the acceptance
criteria are deliberately both-or-nothing:

    .\deploy\concourse\Set-RegistryScope.ps1 -WhatIf   # read the plan
    .\deploy\concourse\Set-RegistryScope.ps1           # elevated

then `curl http://192.168.0.14:5000/v2/_catalog` from another LAN host must
fail, **and** a Concourse `build` job must still push. Either alone is a false
pass: a registry nobody can reach is not the goal.

The compose comment no longer claims the exposure is required, which was the
third criterion, and it now records why the obvious rule shape is wrong.

**Acceptance criteria**

- `GET /v2/_catalog` from another host on the network fails, **and** a `build`
  job still pushes successfully. Both, or the change is not done. **Waiting on
  the elevated run.**
- ~~Whichever route is taken, the compose comment stops saying the exposure is
  required.~~ Done 2026-09-09: it names the bridge gateway every push has
  actually come from, and why "block everything else" is the wrong rule.
- ~~A decision is recorded either way.~~ D-109, amended 2026-09-09 with the
  block-precedence correction.

**Provenance:** DevSecOps assessment, 2026-09-03 (second sweep), from an nmap
service scan of 192.168.0.14 run at the operator's request. Recorded as a
declared surface on `mykronos` with the catalog response as its evidence.

---

### B-060 — Branch protection, read for the first time, against CIS §1.1

**Size:** M **State:** open **Verified:** 2026-09-04

`administration: read` was granted on 2026-09-04 (B-044), so this is the first
time the estate's change-governance posture has been readable at all. Every
number below is a live read, not an assumption, and the CIS column is the
Software Supply Chain Security Benchmark v1.0 §1.1 recommendation each control
speaks to.

| control | CIS | TheHub | binnacle | keel | mykronos | personal-soc |
|---|---|---|---|---|---|---|
| `pull_request_required` | 1.1.3, 1.1.15 | on | **off** | on | on | on |
| `approving_reviews_required` | 1.1.3 | partial | **off** | **off** | **off** | **off** |
| `dismiss_stale_reviews` | 1.1.4 | **off** | **off** | on | on | on |
| `codeowner_review_required` | 1.1.7 | **off** | **off** | **off** | **off** | **off** |
| `codeowners_coverage` | 1.1.6 | unknown | on | on | unknown | unknown |
| `enforced_for_admins` | 1.1.14 | **off** | **off** | on | on | on |
| `signed_commits_required` | 1.1.12 | **off** | **off** | **off** | **off** | **off** |
| `required_status_checks` | 1.1.9 | **off** | **off** | **off** | **off** | **off** |
| `force_push_blocked` | 1.1.16 | on | **off** | on | on | on |
| `linear_history_required` | 1.1.13 | on | **off** | on | on | on |
| `branch_deletion_blocked` | 1.1.17 | on | **off** | on | on | on |
| `conversation_resolution_required` | 1.1.11 | **off** | **off** | on | on | on |
| `branch_up_to_date_required` | 1.1.10 | **off** | **off** | **off** | **off** | **off** |
| `review_dismissal_restricted` | 1.1.5 | **off** | **off** | **off** | **off** | **off** |
| **governance score, 9 controls** | | **33** | **11** | **57** | **52** | **52** |
| **governance score, 14 controls** | | **30** | **8** | **53** | **49** | **49** |

**Read again on 2026-09-09, and D-110 cannot be executed as written.**
`approving_reviews_required` deadlocks any repository where admin enforcement
is on — GitHub refuses a self-approval and the bypass is off, so `keel`,
`mykronos` and `personal-soc` would take the first pull request after the
change and never merge it. `required_status_checks` has nothing to satisfy it
on `mykronos`, because D-118 retired that repository's eleven Actions lanes
hours after D-110 named it as the safe early case for exactly the opposite
reason. The amendment on D-110 carries the live table and the three choices;
no setting was changed, because branch protection is outward-facing and this
is a decision rather than an execution.

**Three gaps are estate-wide**, and they are the ones that matter most:

- **No repository requires an approving review (1.1.3).** TheHub asks for one,
  which this platform scores `partial` on purpose — one approval on a
  repository with no CODEOWNERS is one rubber stamp from a self-merge, and
  calling that `on` would say something untrue. Everywhere else the answer is
  none.
- **No repository requires status checks to pass before merge (1.1.9).** Every
  scan lane in this estate is therefore advisory at the repository boundary. A
  red `sast` does not stop a merge anywhere, which is the same shape as B-055's
  promotion gate one layer up: the checks run, and nothing is downstream of
  them.
- **No repository requires signed commits (1.1.12).**

**`binnacle` is at 11 and that is expected rather than alarming** — it was
onboarded on 2026-09-04 (B-052) and has had no hardening pass at all. It is the
clean case for doing this in the right order rather than retrofitting.

**TheHub is the outlier worth reading twice.** It is the only internet-facing
repository in the estate and scores lowest of the four established ones, at 33.
`enforced_for_admins` off means the rules it does have are advisory for the
account that owns it, and `force_push_blocked` is the one thing standing
between its history and a rewrite.

**What this does not say.** Fourteen settings reach fourteen of §1.1's
nineteen recommendations; the response carries the other five with what each
would need, and no score is computed across the subset.

*Updated 2026-09-05, after the deploy.* This paragraph said nine settings and
ten recommendations, which was true when written and stopped being true in the
same pull request: the five controls named as "already in the branch-protection
payload and simply not read yet" were then read. They were the cheapest
coverage available and they landed first, as the story asked. Verified live —
14 covered plus 5 uncovered is 19, which is every recommendation in §1.1 and
none counted twice.

**Four of the five were already on and nobody knew.** `linear_history_required`
and `branch_deletion_blocked` read `on` for TheHub, keel, mykronos and
personal-soc; `conversation_resolution_required` is `on` for three. That is
real coverage this estate already had and could not see, which is worth
separating from the coverage it does not have.

**Sequencing matters more than the list.** Requiring pull requests and status
checks changes how work reaches `main`, and two repositories cannot absorb that
today: TheHub's `unit` lane is red (B-057's successor failures), so requiring
status checks there would stop every merge until those five tests pass; and
`main` is what TheHub's production deploy gates from. Order:

1. `binnacle` and `keel` first — no deploy path depends on either, so a mistake
   costs a re-push rather than an outage.
2. `mykronos` next. Its lanes are green, so `required_status_checks` is
   immediately meaningful rather than immediately blocking.
3. `personal-soc` — Concourse-scanned with Actions disabled, so
   `required_status_checks` needs the Concourse checks wired to the commit
   status first, or it will block on checks that never arrive.
4. `TheHub` last, and not before its `unit` lane is green.

**Decided 2026-09-05 — D-110: two of the three, in this entry's order.**
`approving_reviews_required` and `required_status_checks` are being turned on
binnacle-and-keel first, then mykronos, then personal-soc, then TheHub.
`signed_commits_required` is deliberately deferred and recorded as such: on a
single-operator estate an unsigned commit from a forgotten path becomes an
unmergeable one, which fails at the moment somebody is shipping a fix.

**Executed 2026-09-09 (D-110, amended).** Every repository now requires one
approving review with admin enforcement off, and `binnacle` gained branch
protection for the first time. Read back from GitHub afterwards rather than
assumed:

| repository | admins before | admins after | reviews before | reviews after | score |
|---|---|---|---:|---:|---|
| `binnacle` | unprotected | off | — | 1 | 8 → **48** |
| `keel` | on | off | 0 | 1 | 53 → 48 |
| `mykronos` | on | off | 0 | 1 | 49 → 43 |
| `personal-soc` | on | off | 0 | 1 | 49 → 43 |
| `TheHub` | off | off | 1 | 1 | 30 → 30 |

Three scores fell, because `enforced_for_admins` was passing and is not any
more, and CIS weighs it the same as the control gained. That trade was made
deliberately: a review requirement nobody can satisfy is worth less than one
that is advisory and recorded, and on a single-operator estate the alternative
was a deadlock — GitHub refuses a self-approval, and admin enforcement removes
the bypass. The platform scores the new state `partial`, which is the honest
reading.

**Acceptance criteria**

- ~~`approving_reviews_required` is `on` for every repository, or a decision is
  recorded per repository for why not.~~ `partial` everywhere, with D-110
  carrying why. `required_status_checks` and `signed_commits_required` remain
  open: signing is deferred by D-110, and checks are executable on `keel` and
  `binnacle` only because nothing reports on a `mykronos` or `personal-soc`
  pull request.
- `force_push_blocked` is now `on` for `binnacle`, along with linear history,
  deletion blocking and conversation resolution, which it had none of.
  `enforced_for_admins` is now `off` estate-wide by decision rather than by
  omission — the opposite of what this criterion asked for, and the trade
  recorded above.
- A CODEOWNERS file exists where `codeowners_coverage` reads `unknown`, so
  `codeowner_review_required` becomes meaningful rather than decorative.
- 1.1.13 and 1.1.17 are read and reported, closing two of the nine gaps for the
  cost of two field reads.
- The governance scores are re-read afterwards and recorded here, so the change
  is evidenced rather than asserted.

**Scores fell when coverage grew, and that is the reading working.** Every
score dropped 3-4 points on 2026-09-05 because five more controls now count and
three of them are off everywhere. Nothing was turned off; the denominator got
honest. A governance score that only ever rises as the audit widens would be
measuring the audit rather than the estate.

**Provenance:** DevSecOps assessment, 2026-09-04, from the first readable
governance pass after B-044. The read also exposed the defect that had hidden
this: the SSDF assessment compared `state == "pass"` against a module that
emits `on`/`off`/`partial`/`unknown`, so every readable control reported as "not
enforced" including the ones that were on.

---

### B-064 — TheHub encrypts its most sensitive table with unauthenticated CBC

**Size:** M **State:** open **Verified:** 2026-09-05

`backend/services/intimacy_service.py` encrypts with AES-256-CBC and no
authentication:

```python
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
encryptor = cipher.encryptor()
ciphertext = encryptor.update(padded) + encryptor.finalize()
```

CBC provides confidentiality and nothing else. Nothing in the record proves the
ciphertext is the one the service wrote, so an attacker with write access to
the row — a SQL-injection foothold, a stolen database credential, a backup
restored from the wrong place, a compromised backup job — can modify stored
ciphertext and the service will decrypt whatever comes back. PKCS7 unpadding on
attacker-modified input is also the classic padding-oracle shape: decryption
raises on a bad pad and succeeds on a good one, and that difference is enough
to recover plaintext a byte at a time if it is observable in a response or a
log.

**`_hash_data` is not a fix for this and is not intended as one.** It is
SHA-256 over the *plaintext*, for deduplication, stored beside the row. It
authenticates nothing about the ciphertext, and an attacker who can rewrite the
ciphertext can rewrite that column too.

**This is the one finding in TheHub's SAST backlog that is real.** The other
sixteen HIGH findings resolved as follows on 2026-09-05: twelve
`avoid-sqlalchemy-text` are false positives (every caller-supplied value is a
bound parameter; every interpolation is a module constant or an uncalled
maintenance helper) and are dispositioned with the call path recorded per site;
two `run-shell-injection` were real and are fixed in TheHub#291. These two are
what is left, and they are on the table the application treats as its most
sensitive.

**The fix TheHub already has.** `backend/utils/token_crypto.py` uses Fernet,
which is AES-128-CBC with an HMAC-SHA256 over the ciphertext, and it carries a
`fernet1:` version prefix precisely so stored values can be migrated in place.
The same prefix pattern applies here. AES-GCM is the other option and is
stronger per byte; Fernet is the one this repository already operates, tests
and understands.

**Why this is filed rather than fixed in passing.** Changing the encryption of
existing personal data is a migration, not an edit: every stored row has to be
read under CBC and rewritten under the new scheme, the read path has to accept
both during the transition, and getting it wrong destroys data that by
definition cannot be regenerated. `token_crypto.backfill_plaintext` is the
shape to copy — it verifies every row by decrypting the new value back and
comparing before it commits, and aborts the whole batch on a mismatch. That is
the standard this migration should meet, and it is more work than a scan
finding should be closed with.

**Acceptance criteria**

- New writes use an authenticated construction (Fernet, or AES-GCM), with a
  version prefix on the stored value.
- The read path accepts both schemes for as long as unmigrated rows exist, and
  a check reports how many remain rather than assuming zero.
- A backfill migrates existing rows, verifying each by decrypting the rewritten
  value and comparing before commit, aborting the batch on any mismatch.
- Decryption failure is handled without a distinguishable padding error
  reaching a response or a log line, so the migration does not leave a padding
  oracle behind while it runs.
- The two semgrep findings close on their own once the mode changes, which is
  the check that this was fixed rather than dispositioned.

**Provenance:** DevSecOps assessment, 2026-09-05, reading all 16 of TheHub's
HIGH SAST findings by hand after the container backlog was dispositioned and
stopped hiding them. Worth noting the order: these two were reachable only
after 271 unfixable OS-package findings were accepted and twelve false
positives were cleared. A backlog that is 93% noise does not hide its signal
politely — it hides it completely.

---

### B-065 — Two applied pipelines carry live credentials that `fly get-pipeline` hands back — **half done**

**Size:** S **State:** open **Verified:** 2026-09-05

PS-9 says a credential belongs in the credential manager rather than in a
`((vars))` file, because Concourse stores pipeline configuration verbatim and
anyone who can run `fly get-pipeline` reads it back. It was done for `mykronos`
(D-079) and never for the other two. Read out of the live configs on 2026-09-05,
after re-applying `mykronos`:

| pipeline | credential | in the applied config |
|---|---|---|
| `thehub` | `anthropic-api-key` | **literal, 76 chars, twice** |
| `thehub` | `github-token` | **literal, 383 chars** |
| `personal-soc` | `personal-soc-ingestion-token` | **literal, 43 chars, three times** |
| `mykronos` | everything | placeholder — resolves at egress |

Only presence and length were read; no value was printed or copied anywhere.

**The Anthropic key is a stale apply, not a missing secret, and that is the
cheapest fix in this file.** `concourse/main/anthropic-api-key` is in Vault
today, and `set-thehub-pipeline.ps1`'s own probe finds it — reproduced with the
same `CONCOURSE_VAULT_TOKEN` the script uses:

    absent : concourse/main/thehub/anthropic-api-key
    PRESENT: concourse/main/anthropic-api-key

Concourse looks up pipeline scope then team scope, `Test-VaultSecret` probes
those two paths in that order, and the second hits. So a re-apply of `thehub`
today removes two inline copies of a live model key with no other change. The
config is carrying a literal because it has not been applied since the key
reached Vault.

**The ingestion token is genuinely absent from Vault** — neither
`concourse/main/personal-soc/personal-soc-ingestion-token` nor
`concourse/main/personal-soc-ingestion-token` exists — so that one needs
`Import-EnvSecretsToVault.ps1 -Pipeline personal-soc` first, then a re-apply.
It is the one credential here that is inline *and* current: `personal-soc` was
applied on 2026-09-05.

**`github-token` is deliberate and stays.** `set-thehub-pipeline.ps1:301` records
why: it is a GitHub App installation token minted fresh per run and dead in an
hour (CNC-2), and a stale secret resolving in place of a live one is worse than a
config holding something already expiring. Worth naming here so the next reader
does not "fix" it. The residual exposure is real but bounded — one hour, and only
to somebody who can already reach this Concourse.

**Three of the six the drift check flags have nothing in them, and the check
cannot tell.** `check_applied_pipelines.py` classifies a var as `CREDENTIALS
INLINE` when it is not resolved from Vault, which is the right question for
configuration and the wrong one for exposure. Read back:

- `thehub`: `azure-client-secret`, and `azure-client-id`, `azure-tenant-id`,
  `azure-subscription-id` — **all four empty.**
- `personal-soc`: `anthropic-api-key` and `hibp-api-key` — **both empty.**

So the warning names six credentials where three are real, one of those three is
a deliberate one-hour token, and two of the empties are empty for reasons already
recorded (D-108 for Azure; the paused `breach-check` for HIBP). A warning that
overstates gets discounted, and then the two entries in it that matter get
discounted with it.

**This independently confirms D-108.** B-018 concluded that TheHub's Azure
principal is unset from `deploy/concourse/.env`; the applied pipeline agrees —
all four Azure variables are empty strings in the running config. `cloud` could
not have reported no matter what was enabled.

**The check stopped overstating, 2026-09-09.** It asked whether a variable
resolved from Vault, which is the right question for configuration and the
wrong one for exposure. It now reads what the applied config actually holds
where the file holds a reference, and reports an empty string as its own
answer. `github-token` is named with its reason rather than listed beside the
accidental ones.

Only when the file's value is *exactly* the reference: a variable interpolated
into a longer string cannot be isolated from the text around it, and guessing
there would be the same overstatement in the other direction.

**Re-read against the live pipelines on 2026-09-09, and the estate had moved
since the entry was written:**

| pipeline | resolved from Vault | supplied but empty | inline on purpose | real exposure |
|---|---:|---|---|---|
| `mykronos` | 6 | — | — | **none** |
| `thehub` | 8 | `anthropic-api-key`, four `azure-*` | `github-token` | **none** |
| `personal-soc` | 5 | `anthropic-api-key`, `hibp-api-key`, `monitor-emails` | — | **`personal-soc-ingestion-token`** |

So the six-credential warning is one credential, and it is the one this entry
said was genuinely absent from Vault. `thehub`'s Anthropic key is no longer a
76-character literal — it is an empty string, so the exposure is gone and the
key is *not* resolving from Vault either. **Worth a look rather than an
alarm:** TheHub's `ai` lane has succeeded four times since 2026-09-01, most
recently 16:10 today, so whatever it needs it is getting; that a lane can
succeed with an empty model key is a question this entry is not the place to
answer.

**Acceptance criteria**

- `thehub` re-applied, and `((anthropic-api-key))` intact in the applied
  config. **Half:** the literal is gone, and it resolves to an empty string
  rather than from Vault.
- `personal-soc-ingestion-token` in Vault, `personal-soc` re-applied, and its
  three `MYKRONOS_TOKEN` assignments reading as placeholders. **Not done**, and
  it is now the estate's only inline credential with a value in it.
- ~~`check_applied_pipelines.py` distinguishes an inline credential with a
  value from an inline empty string, and says which.~~
- ~~`github-token`'s exclusion is recorded where the check reports it.~~
- The two keys that were inline are treated as exposed and rotated. **Not
  done.** Every apply between 2026-09-05 and whenever `thehub` was re-applied
  stored the Anthropic key somewhere readable, and the ingestion token is
  still there now.

**Provenance:** found on 2026-09-05 while verifying that D-113's coverage flag
had reached the running `mykronos` pipeline. `check_applied_pipelines.py`
reported no drift and, in the same output, three `CREDENTIALS INLINE` lines that
nothing in `docs/` tracked — PS-9 appears nowhere in this file. The
empty-versus-real split was found by reading the applied configs rather than by
trusting the label.

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
- **The `sast` template's CodeQL pin loses to dependabot on every resync.**
  `workflow-templates/sast.yml.j2` pins `codeql-action` at v3.37.6; dependabot
  raised binnacle's generated copy to v3.37.9 on 2026-09-07 (binnacle #6), and
  the next install PR (binnacle #8, 2026-09-08) put it back, because a
  generated file is overwritten on resync by design (spec 03 §6). Two writers
  own one line, so it cannot hold. Harmless today — a patch version either
  way — and it will recur on every repository with dependabot and a Mykronos
  workflow. The fix is the template following upstream, on a cadence, rather
  than dependabot being told to ignore generated files; not filed until the
  drift is more than a patch version.

---

## Closed

Fifty-two entries. The count below was stale at "nineteen": it covered
the 2026-08-31 and 2026-09-01 sweeps only, and never the seven pre-08-31
entries (B-001 to B-007) or the seven that closed on 2026-09-03.

**2026-09-09 — twelve.** B-059, which had eleven uncapped tasks sharing the
estate's single worker and a conformance check scoped around the pipeline that
needed it most: coverage is discovered now, every cap is measured, and the
remaining gaps are recorded with reasons rather than excused by absence. Then
B-056, which had no room for a branch in a lane: a
finding now closes on evidence from the tree it was found in, and lane health
comes from the branch the lane is about rather than from whichever scan ran
last. Then B-063, so a finding says whether its version is one
this repository runs: a lock file names what is installed, an open-bounded
requirement names what is permitted, and the two were the same row until now.
Labelled rather than discounted (D-120), because a floor is a real thing to
assess. Then B-048, whose duplicate had already stopped when D-118
retired the second CI, leaving the defect that caused it: checkov was being
pointed at a mount whose basename it prefixed onto every path, so two live
repositories carried open findings naming files that do not exist. Then B-058,
which was making two repositories look
negligent for lacking things they have no reason to have: applicability is now
read from the repository's own file listing, and `keel` gains three met
practices while `personal-soc` gains three that do not apply. Then B-046, the
entry the whole coverage theme is named
after: the briefing measured silence and nothing measured whether a scan
covered anything, so a lane pinned to a stale tree stayed green forever. Two
of its bugs were found by the tests rather than by reading — a pinned lane
nominating itself as the repository's head, and a cadence-scaled grace that
made the worst lanes unreportable. Then B-061 and B-047, both filed against instances that had
quietly resolved themselves while the defect behind them stayed: oracle now has
a lane in all three pipelines and TheHub's `dast` was re-granted, so what was
built is the mechanism rather than the repair. `event_driven` now checks that a
lane exists before calling a gate healthy, and a capability that loses its
grant records what that did to its findings instead of leaving them open
forever. Then B-055, whose last three criteria closed together:
TheHub's `develop` already agreed about the gate and its suite had been green
since the 6th, neither of which anybody had written down; a check now compares
the owning repository's copy to ours, which is the direction that let a fix
exist for two weeks without taking effect; and a lane quiet because an upstream
it gates on is red reads `blocked` rather than `silent`, with the upstream's
button instead of its own. Then B-062, the trap that sprang twice: the ledger is
authoritative (D-119), a PATCH refuses to narrow ingestion it was not told
about, `reconcile-grants` widens and never revokes, the cross-check sees a job
for a capability nobody enabled, and a refused upload notifies. Then two on
paper: B-044 and B-018 had both been done since the 4th and 5th — governance
readable with five rows and the SSDF count at 11 of 13, and `cloud` off TheHub
inside B-062's restore — and neither had been confirmed against its own
criteria. Read, confirmed, closed.

**2026-09-08 — two.** The two XS entries, both decided on the 5th. B-053: ZAP
2.17.0 in the demo compose, with the first resource reading ever taken on a
runner (ZAP peaked at 312% CPU and 0.76 GiB, passive), and the two "ZAP is out
of date" findings gone from the report. B-052: binnacle's `secrets` lane, which
had been granted on the 5th and switched off again on the 7th with nothing
recorded as to why, re-enabled and uploading before the install PR was merged.

**2026-09-06 — one.** B-066, the only outage in this set rather than a gap: a
stale copy of the tunnel's own ingress had stopped `keel` and `binnacle`
reporting for twenty hours while the briefing read healthy. Found by checking
whether the previous day's work had produced a figure.

**2026-09-04 and 09-05 — four.** B-049 built the day it was decided (D-116):
the queue's disclosure is derived from `RANK_INPUTS` rather than restated, so it
survives the profiles being filled in. B-043 closed as a decision (D-115), the
same disposition B-038 got. B-045, which took three applies to hold
because the decision lived in a flag rather than in the script's default,
and B-057, fixed upstream by TheHub #281 with a better fix than the one
drafted here — a test that asserts a pin against its call sites, because a
comment cannot fail a build.

**2026-09-03 — seven.** B-032, B-033 (the code half), B-034, B-036, B-037,
B-040, and B-038 closed as a decision (D-101).

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

### B-059 — The pipeline standard covers two pipelines of four, and the two it skips would fail it — **done**

**Size:** M **Verified:** 2026-09-04 **Closed:** 2026-09-09

**Coverage is now the default and exemption is the thing you have to write
down.** `check_pipeline_conformance.py` discovers every pipeline in
`deploy/concourse/pipelines/` instead of reading a two-entry tuple, so a
pipeline added to this repository is covered without anybody remembering — the
failure mode that produced this entry in the first place.

**Every uncapped task now carries a measured cap.** Eleven tasks in
`personal-soc.yml` had no timeout, on an estate with one Concourse worker,
where PS-7's own rationale is that "a hook that hangs holds the single worker
exactly as a scan does". Each cap is read off that job's own observed
durations rather than picked as a round number, and the evidence is written
beside it in the pipeline:

| job | runs observed | median | slowest | cap |
|---|---:|---:|---:|---|
| `lint` | 5 | 35s | 48s | 10m |
| `skill-integrity` | 6 | 36s | 56s | 10m |
| `doc-drift` | 5 | 57s | 136s | 10m |
| `functional` | 5 | 69s | 86s | 10m |
| `secrets` | 6 | 78s | 169s | 10m |
| `guard` | 6 | 101s | 146s | 10m |
| `netassess-ingest` | 1 | 33s | 33s | 15m |
| `external-exposure` | 4 | 95s | 207s | 15m |
| `netassess-freshness` | 4 | 95s | 228s | 15m |
| `package` | 5 | 212s | 504s | 30m |
| `breach-check` | 0 | — | — | 15m |

`package` gets 30m because it polls for the host's install acknowledgement and
B-017 records that budget as eight minutes on its own; `netassess-ingest` has
one sample, so its headroom is deliberately wide; `breach-check` is paused, so
its cap is the estate's default for a lane calling one external API rather
than a measurement. Saying which of the three is which is the point.

**The other nine violations are recorded rather than fixed or excused.**
`KNOWN_GAPS` maps `pipeline:job RULE` to why it is still there, and anything
not in it fails the check — so a *new* violation of the same rule in a new job
still fails, which is the property the check exists for. The report prints them
on every run, because a baseline nobody sees is a baseline that grows, and a
test asserts every recorded gap still reproduces: an entry that no longer fires
is a line that will outlive the problem and start excusing a future one.

What is recorded: three lanes reporting to Mykronos with no preflight probe
(PS-2), two whose upload is skipped by their own scanner's exit code (PS-3),
one commit-triggered job with no quality gate (PS-4), one task naming `main`
literally (PS-6) — the assumption B-045 cost sixteen days of scanning — five
downloads with no checksum (PS-8), and all thirteen jobs in no group, so
Concourse hides the whole pipeline from its own UI.

**A test caught the first draft of that baseline being a pardon.** Three of the
nine reasons read "as above", so `test_every_recorded_gap_says_why` — written
in the same commit — failed until they said something. An exemption with no
reason is exemption by absence wearing a dictionary.

- ~~`personal-soc.yml` and keel's pipeline are in `PIPELINES`, or an entry
  records which rules they are exempt from and why, per pipeline rather than
  by absence.~~ Discovered, not listed, with nine reasoned entries. **keel has
  no pipeline in this repository** — it is Actions-scanned, so there was
  nothing to add; the entry assumed one.
- ~~Every work task in every listed pipeline carries a timeout.~~ Eleven caps,
  each from that job's own runs.
- ~~A pipeline added to the repository is covered by the standard by
  default.~~

**Checked:** 2727 backend tests pass, five new — every pipeline conforming,
every recorded gap still reproducing, every recorded gap carrying a reason, a
new pipeline covered without being listed, and no task anywhere running
uncapped, which is stated as its own test because it is an availability
property of the estate rather than of one repository.

**Provenance:** DevSecOps assessment, 2026-09-04, while adding the `iac` lane
to `personal-soc` — noticed only because the conformance test was run by hand
against a pipeline it did not cover. Related to B-058: the same repository was
also the one whose SSDF gaps were mostly practices it cannot apply.

---

### B-042 — Coverage is plumbed end to end and no pipeline writes it — **done**

**Size:** S **Verified:** 2026-09-03 **Closed:** 2026-09-09 (D-121)

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

**Decided 2026-09-05 — D-113: add it, and measure the cost.** On the
pull-request unit lane rather than a nightly one, because coverage that lags the
branch cannot show a regression at review time. If the measured CI time is
unacceptable, the decision to stop rests on that figure rather than on an
assumption — the standard D-053 set for ZAP.

**Built 2026-09-05, and the cost turned out to be nothing measurable.**
`pytest-cov>=6.0` in the `dev` extra, and `--cov=mykronos --cov-branch
--cov-report=xml:.../coverage.xml` on *both* mykronos unit lanes — this entry
quoted the Actions one, but `deploy/concourse/pipelines/mykronos.yml` runs the
same suite and uploads into the same lake, and instrumenting one of two leaves
`line_coverage` alternating between a figure and NULL.

Three full runs of the 2592-test suite at `-n auto` on the development host, all
green: 179.07s with no coverage, 173.90s with `--cov`, 173.24s with
`--cov --cov-branch`. Both coverage runs were *faster* than the baseline, so the
overhead is below this host's ~3% run-to-run variance. **This entry's stated
reason for deferring — that coverage under `pytest-xdist` costs real time — does
not hold here.** Neither runner's own number is in hand until the lanes run.

**The plumbing was right, and it was proved rather than asserted.** The real pair
of files a lane writes was normalised through `normalize_results`: one merged
result, `line_coverage=0.883`, `branch_coverage=0.799`, `success`, zero findings,
zero warnings. No platform code was touched to get that.

**`--cov` alone would have published a number nobody measured**, and this is the
part worth keeping. Cobertura writes `branch-rate="0"` whether or not branch data
was collected; `_rate` reads it as `0.0` rather than `None`; `dashboard.py:2281`
surfaces it. The first version of this change would have put a measured 0% branch
coverage on the Harness tab for a measurement that never happened — B-046,
B-051, B-058 and B-061's own failure, arriving inside the fix for a fifth entry.
`--cov-branch` is on both lanes for that reason.

**The lane ran, and the local measurement did not survive it (D-117).**
Concourse `unit` #226 with `--cov --cov-branch`: **540.81s**, against 218.61s
(#224) and 238.16s (#223) clean. **+322s, about 2.5x**, on a lane carrying
`trigger: true` with seven jobs gating on `passed: [unit, ...]`. The worker
prints the reason on every build — `Performance budgets scaled x3 for this
worker` — and coverage tracing is CPU-bound, so what disappeared into fixture
setup on a fast host does not disappear on `-n 6` at a third of the speed.

**Coverage went to the Actions lane, and then that lane was retired (D-118).**
The Actions unit lane was one of eleven duplicating Concourse, so mykronos is now
`scanned_by=concourse` and those eleven are gone. Coverage therefore has no free
home: it is Concourse at the +322s D-117 rejected, or unmeasured. `pytest-cov`
stays in the `dev` extra either way — it costs nothing installed, and the local
runs above used it.

**The ingest path was proved before the flag came off.** #226 succeeded, wrote
`coverage.xml` beside `unit.xml`, POSTed both to `/api/ingest/raw`, and the
adapter merged them — `0 finding(s) from 2 file(s)`, `line_coverage=0.883`,
`branch_coverage=0.799`, no platform code touched. The plumbing claim in this
entry was correct.

**Decided and built 2026-09-09 — D-121: a weekly lane, off the critical
path.** A `coverage` job runs the same suite with `--cov --cov-branch` on a
Sunday clock and gates nothing. It pays D-117's +322s where nothing waits for
it, and uploads as `unit` so the figure lands on the lane a person reads it
against — the uploader merges `coverage.xml` and `unit.xml` into one run, which
is the plumbing this entry proved on 2026-09-05 with no platform change.

Both of the things left are now settled:

1. ~~Nothing measures coverage right now.~~ The weekly lane does, once the
   pipeline is applied.
2. ~~The figure has to come from a lane rather than from a laptop.~~ It does.
   The number can be up to seven days old, which is the trade D-121 states: a
   stale figure that keeps arriving beats a gate 2.5x slower on every push, and
   beats the blank that "record that we do not measure it" would have left.

**Two details carried into the job rather than left to be rediscovered.**
`--cov-branch` is there because Cobertura writes `branch-rate="0"` whether or
not branch data was collected, so `--cov` alone would publish a measured 0%
nobody measured. And the clock triggers it, not `source`: a `trigger: true` on
the repository would make this the thing it was written to avoid.

**Not yet applied.** The job is in `deploy/concourse/pipelines/mykronos.yml`
and reaches the worker on the next `set-pipeline`. The conformance check
covers it — it is in the `quality` group, carries a timeout, and probes
Mykronos before reporting.

**Two things left this list on 2026-09-05.** The generated-file problem — that
`_test_lane.yml.j2` takes the command from the repo's `unit` capability config,
so a resync would drop `--cov` — went away with D-118: mykronos is
`scanned_by=concourse` and spec 03 §3a means an install has no workflows to
write. And the tunnel route, still broken, is no longer this entry's blocker; it
belongs to `keel` and `binnacle`, which are Actions-scanned and cannot report
without it (B-066).

**Acceptance criteria**

- `pytest-cov` in the `dev` extra and `--cov=mykronos
  --cov-report=xml:$MYKRONOS_RESULTS/coverage.xml` on the unit lane command.
- A figure appears on the Harness tab without any platform change, which is
  the proof that the plumbing was always right.
- The added CI time is measured and recorded, not assumed.

---

### B-056 — A lane is a repository and a capability, with no room for a branch — **done**

**Size:** M **Verified:** 2026-09-04 **Closed:** 2026-09-09

A lane is a repository, a capability **and a branch**. `scan_runs` has always
carried the branch; nothing read it, so every branch of a repository wrote to
one lane.

**Measured before anything was changed, not predicted.**

| repository | shape |
|---|---|
| `ToddGBenson/TheHub` | 404 runs on `develop` and 86 on `main`, both across nine capabilities, both current |
| `TheHub` `dast` | 61 findings last seen on `main`, 109 fixed and 37 open last seen on `develop` |
| every repository | runs from the `mykronos/enable-workflows-*` branches the installer itself opens |

**Closure, first.** `reconcile_absences` partitions recent runs by `(repo,
capability, branch)` and matches each finding to the branch of the run that
last saw it — where the platform observed it, not where somebody expected it.
Before this, two consecutive `main` scans could confirm the absence of a
finding that only ever existed on `develop`, and the next `develop` scan
reopened it: the exact flapping the two-scan rule exists to prevent, arriving
through the dimension the rule did not have. The install pull requests make
that true of all four repositories, not only the one scanned on two branches.

**Then health.** `scan_health` takes the branch each capability's lane is
expected on. Runs elsewhere are counted as `off_lane_runs` rather than
dropped — a scan of another branch is a real scan of a real tree whose
findings close on their own evidence; it simply does not answer for this lane.
Freshness, failure rate and the coverage figure all come from the lane now, so
a pull-request scan can no longer make a lane look fresh, and its failures no
longer count against a branch nobody deploys. The SSDF `reporting` set reads
the same lane, because evidencing a practice from a tree nobody ships is the
same error one surface further on.

**The expected branch defaults to the repository's, which is what makes it
useful with nothing configured.** `lane_branch` in a capability's config names
another where one is wanted, and it refuses a glob: a lane expected on several
branches has no single health, which is the thing the field exists to give it.
A repository with no default branch recorded declares nothing rather than
excluding every run, because an unknown expected branch must not report a
working lane as never having scanned.

**With that, "scan `develop`, gate `main`" is expressible**, and the either/or
the 2026-08-18 directive faced stops being one. Whether TheHub is rearranged
that way is a pipeline decision and not this entry's.

**Two things the tests caught.** The waiting-lane report fired per branch, so a
lane closing findings on `develop` also announced itself short of history
because a pull-request branch was scanned once — true, useless, and how a
report stops being read; it now fires only when no branch has looked enough.
And the branch filter was inlined into seven aggregates while its parameters
were supplied once, which DuckDB reports only at query time; it is computed
once in a CTE.

- ~~Lane health, and the two-consecutive-scans closure rule, are evaluated per
  `(repo, capability, branch)`.~~
- ~~A repository can declare which branch a capability's lane is expected on,
  so a scan of another branch is recorded without disturbing that lane's
  health.~~ `lane_branch`, defaulting to the repository's default branch.
- ~~TheHub can scan `develop` and gate `main` at once.~~ Expressible now.
- ~~B-048 is re-read against this.~~ Closed 2026-09-09; it was the same defect
  with two CIs instead of two branches.

**Checked:** 2722 backend tests pass, eighteen new — eight on closure
(another branch closing nothing, its own branch still closing, an install
pull request closing nothing on the default, interleaved branches keeping
separate histories, the same defect on two branches closing separately, the
failed-scan rule still independent) and ten on health, including that a
capability declaring a branch does not narrow one that did not.

**Provenance:** DevSecOps assessment, 2026-09-04, found while trying to
implement "scan develop, deploy from main" and discovering the platform could
not express it. Closure landed 2026-09-09; health the same day.

---

### B-063 — `--no-resolve` assesses the declared floor, so findings describe a version nobody runs — **done**

**Size:** M **Verified:** 2026-09-05 **Closed:** 2026-09-09 (D-120)

A finding now carries `version_basis`, and the three answers are different
claims: `resolved` came from a lock file and names what gets installed;
`declared_floor` came from an open-bounded requirement and names the oldest
version the repository permits; `declared_pin` came from an exact requirement,
which is a resolved version by another route. `None` is its own answer and the
most important one — nothing established it, so nothing is inferred.

**Read from the scanner's own output rather than from a flag.** The source
file settles it: a lock file pins by definition, so that answer needs neither
the package name nor the checkout. A manifest is a declaration, and the
adapter reads the requirement line out of the workspace to tell a pin from a
floor. It declines wherever the answer is not established — an unrecognised
file, a manifest with no source on disk, a package whose line is not found —
because a wrong `resolved` would say a finding describes running software when
it does not, which is the reading the entry exists to prevent.

**The npm case was wrong first, and the test is why it is not.** The first
version scanned the requirement *line* for an exact version, which is correct
for `requirements.txt` and wrong for `package.json`: a one-line manifest let
`left-pad`'s exact pin decide `lodash`'s answer. It now reads the value for
that package's own key.

**The scan says it too, not just the finding.** A dependency scan that
produced floor findings warns with the count and the sentence that matters —
raising the floor closes them and changes no running byte. The first reading of
these was wrong in exactly the way a per-finding label does not prevent: they
were reported here and in mykronos#216 as four live HIGH vulnerabilities on an
internet-facing application, and corrected only after somebody read
`cryptography.__version__` inside the running containers.

**The estate has none today, which is the sweep working rather than the check
failing.** All four open `atlas` findings are from `frontend/package-lock.json`
and read `resolved`. mykronos's floors were raised on 2026-09-05 (0 of 20 now
carry an advisory) and TheHub's in TheHub#290. What is built here is what makes
the next one legible.

- ~~A finding derived from an unresolved requirement says so.~~
- ~~The dashboard can tell the two apart.~~ `version_basis` on the finding
  models and a `declared floor` marker beside the version on the Findings tab,
  where the version is the thing being misread.
- ~~Either the Oracle weights floor findings differently, or the decision to
  weight them identically is recorded with a reason.~~ **D-120: labelled, not
  discounted.** A floor is a real thing to assess and a rebuild can install
  it, so the risk is not smaller — what was wrong was the claim, and the fix
  for a mislabelled fact is the label.
- ~~The estate is swept for the same shape.~~ Done 2026-09-05, both
  repositories.
- Revisiting `--no-resolve` is still the real fix and is still open: a lock
  file would make every finding resolved and retire the distinction. D-120
  records why that is not this change.

**Checked:** 2704 backend tests pass, twenty-two new — every ecosystem's lock
file, an open bound, an extras marker, a bare requirement, an exact pin, a
commented-out line, the npm neighbour bug, and each of the five ways the
answer is declined.

**Provenance:** DevSecOps assessment, 2026-09-05, immediately after repairing
the lane in B-062's commit; built 2026-09-09.

---

### B-048 — Two lanes record every IaC finding twice, and `parity` says retire the wrong one — **done**

**Size:** S **Verified:** 2026-09-03 **Closed:** 2026-09-09

**The path base was fixed at its source, and the source was ours.** Checkov
prefixes every SARIF path with the basename of the directory it is pointed at,
so `iac.yml.j2` running `--directory /repo` emitted
`repo/.github/workflows/release.yml` — a path that exists nowhere in the
repository. Verified rather than reasoned about: checkov 3.2.334 run both ways
against the same tree emits `repo/.github/workflows/promote.yml` with
`--directory /repo` and `.github/workflows/promote.yml` with `-w /repo
--directory .`. The template now does the second, at version 1.3.0.

That makes the Actions lane agree with the Concourse one, which already
emitted repo-root-relative paths, so the duplicate cannot recur — and it fixes
a live defect the entry did not mention. Read on 2026-09-09:

| repository | scanned by | IaC path base | status |
|---|---|---|---|
| `keel` | Actions | `repo/...` | **open** |
| `binnacle` | Actions | `repo/...` | **open** |
| `mykronos` | Concourse | root-relative | current |
| `mykronos` | Actions, retired | `repo/...` | stale, dispositioned |

The two open findings name files that cannot be opened from the finding and
match nothing anybody greps for. A finding's identity derives from its path
(spec 05 §5), so correcting it means the next scan files the same defect under
a new id and the old one closes after two absences. That churn is unavoidable
in either direction — normalising at ingest would change the same input to the
hash — and it is one-time and self-healing, which the alternative of leaving
unusable paths in place is not.

**The duplication itself had already stopped, for a different reason.** D-118
retired mykronos's eleven Actions lanes on 2026-09-05, so only one CI writes
`iac` there now. What was left was the defect that produced it.

**`parity` no longer recommends the wrong retirement.** `NOT_COMPARABLE` names
`dast` and `functional` with the sentence that says why, `Parity.verdict`
returns `not comparable` *before* it can return `improved`, and `mykronos
parity` prints the reason in its verdict rather than a footnote — including
after "No capability is worse under Actions", which was the line that read as
permission. Only those two are marked: `sast`, `secrets` and `iac` read a
checkout, and a checkout is the same everywhere, so marking them would make the
check refuse to answer anything.

**The `dast` and `functional` "failures" are explained rather than fixed, and
that is the honest disposition.** The Concourse `demo-and-dast` job is paused
under D-053 and its work is done by the hand-written `demo-and-dast.yml`, which
D-118 kept for exactly that reason. A paused job reads as `failed` to a check
that asks whether a lane reported; that is the same conflation B-061 fixed for
gates, arriving in the parity table, and it is now covered by the verdict
rather than by a diagnosis of a job nobody intends to run.

- ~~The path base is normalised so both lanes produce one finding.~~
- ~~`parity` distinguishes a capability whose lanes reach different targets.~~
- ~~A decision recorded that Concourse is retained for internal-target
  scanning.~~ D-118, amended.
- ~~The Concourse `dast` and `functional` failures are diagnosed.~~ Paused
  under D-053, replaced by `demo-and-dast.yml`.

**Checked:** 2682 backend tests pass, eight new — the 2026-09-03 reading
refused, an ordinary capability still improving, a regression still outranking
everything, and only the two deployment-reaching capabilities marked.

**Provenance:** DevSecOps assessment, 2026-09-03 (second sweep); the
retirement recommendation was corrected by the operator the same day. Built
2026-09-09, and the template defect behind it was found by running the scanner
rather than by reading the template.

---

### B-058 — `not_applicable` is a status nothing ever sets, so a repo is failed for lacking what it does not have — **done**

**Size:** M **Verified:** 2026-09-04 **Closed:** 2026-09-09

`ssdf.summarise` counted four statuses and the fourth was zero across all five
repositories, because nothing set it. A practice a repository cannot possibly
evidence and one it simply has not done were the same row.

**The determination is read from the repository, never declared.**
`composition.py` takes the file listing from `GitHubClient.list_tree` and
answers what has nothing to act on here: no Dockerfile means no container
image is built, no manifest means no dependencies are declared, no test file
means no test suite. `ssdf.assess` takes that map, and a capability in it
contributes neither evidence nor a gap — so a practice covered by two lanes
where one reports and the other cannot apply is **met**, and one whose every
lane cannot apply is **not_applicable** with the observation attached.

**Every inference runs one way only.** An absence of Dockerfiles is strong
evidence that no image is built; their presence proves nothing about anything
else. A tree that could not be read, or that GitHub truncated, is `unknown`
and yields nothing at all — so a failed listing understates adherence rather
than inflating it. That direction is deliberate: on a compliance view a wrong
`not_applicable` converts "we did not look" into "this does not apply to us",
which is the one transformation `ssdf.py`'s own header refuses to make. A lane
that is actually reporting also beats the inference, because an observation
outranks a guess about a file listing.

**Measured against both repositories, with the same inputs run twice so the
change is isolated from everything else on the page:**

| repository | before | after |
|---|---|---|
| `keel` | 5 met, 4 partial, 4 not evidenced | **8 met**, 1 partial, 4 not evidenced |
| `personal-soc` | 3 met, 3 partial, 7 not evidenced | 3 met, 3 partial, 4 not evidenced, **3 not applicable** |

Exactly six practices moved and no others. `keel`: PO.3, PW.4 and RV.1 go
partial to met, each of whose shortfall named containers it does not build or
DAST against an application that does not exist. `personal-soc`: PS.3, PW.4
and PW.8 become not applicable rather than unmet.

**`keel` keeps PW.8, and that is the check working rather than a miss.** The
entry expected it to stop being marked down there for having "almost no
tests". It has two — `test/dashboard.test.py` and
`test/selfreview-check.test.js` — so the practice applies and the repository
is under-tested, which is a real finding. "Almost none" is not none, and the
generous test matcher is deliberate: claiming a repository has no tests is the
inference most likely to be wrong, and being wrong tells a team their tests do
not count.

**The pressure this removes is the point.** The obvious way to move those
numbers was to enable `containers`, `dast` and `unit` anyway — each producing
a lane that runs, finds nothing because there is nothing, and reports success.
A green lane over an empty target is what the maturity model refuses when it
separates `reporting_capabilities` from `enabled_capabilities`, and the SSDF
view had no such guard.

- ~~A practice whose capabilities have nothing to act on reports
  `not_applicable`, with the reason.~~ `not_applicable_because`, its own field
  and its own tone on the Adherence tab, because "we observed something that
  meets this" and "we observed that this cannot apply" are different claims.
  `how_to_evidence` is now hidden on an inapplicable practice too — it was
  advice to build something the repository has no reason to have.
- ~~Evidenced rather than declared.~~ The file listing, not a per-repo
  checkbox, which would be a toggle wearing a different hat.
- ~~`keel` and `personal-soc` stop being marked down for PW.4, PW.8 and
  RV.1.~~ All but `keel`'s PW.8, which is genuinely applicable.
- ~~The counts distinguish the two sentences.~~ `not_applicable` is reported
  beside the rest rather than removed from the denominator.

**Checked:** 2674 backend tests pass, eighteen new — the one-way inferences,
the generous test matcher, unknown claiming nothing, a reporting lane beating
the inference, a merely-not-enabled lane still being a gap, and the two
end-to-end shapes from `keel` and `personal-soc`.

**Provenance:** DevSecOps assessment, 2026-09-04, from working the two lowest
scoring repositories and finding most of their gaps were not gaps; built
2026-09-09. Related to B-051: the same two repositories are also the ones
whose languages no configured analyser can read.

---

### B-046 — A lane pinned to a stale commit reports as healthy — **done**

**Size:** M **Verified:** 2026-09-03 **Closed:** 2026-09-09

The briefing led with lanes that cannot close findings, and measured
wall-clock silence to find them. A lane pinned to a branch that has stopped
moving succeeds on schedule forever and never appears there at all. TheHub's
lanes surfaced only because they *also* went quiet for two days; at their
ten-hour cadence, 330 findings would have been frozen against a stale tree
with every indicator green.

`briefing.stale_lanes` is the second question, and it has its own section in
the terminal briefing, its own list on the briefing API, `not_covering` on
each capability in `scan-health`, and its own block on the Remediate page.

**The check is not "consecutive runs share a commit", and writing it that way
would have been worse than the gap.** A lane scanning a repository nobody has
pushed to shares a commit with itself forever and is covering it correctly.
Every quiet repository in the estate would have lit up, and the section would
have stopped being read by the second week. What is wrong is a lane whose
commit *the repository has already moved off* — established from the lake, by
the newest commit any lane on that repository has reported.

**Two things the tests caught that reading the code did not.**

The first: the repository's newest commit cannot be read off the most recent
run. A pinned lane re-scanning an old tree today *is* the most recent run, so
that definition let the stale lane nominate itself as current and the check
could never fire. It is now the commit that **appeared** most recently, by
first-seen time, which is the one case where the two differ and the only case
that matters.

The second: the first version scaled the grace period by the lane's own
cadence, copying `SILENCE_MULTIPLE` from the silence check next to it. That is
right for silence — a weekly lane quiet for five days is fine — and wrong
here. Once a lane has actually run, how often it usually runs says nothing
about whether it should have picked up the newer commit; scaling by cadence
made a lane that runs every nine days unreportable until the new commit was
nine days old, which is the lane most worth reporting. `STALE_FLOOR_DAYS` is
now a flat day, and its only job is absorbing the build race where a slow lane
on commit N finishes after a fast lane on N+1 started.

**Branch drift reads the ledger, not the lake.** `default_branch` comes from
the onboarding record, because the lake only knows what a lane happened to
scan — and a lane on the wrong branch would otherwise define the branch it is
wrong about as correct. A repository with no default branch recorded produces
no claim rather than a guess.

**No re-run button, and that is the point.** Every other lane row on the
Remediate page offers a dispatch, because for a stalled lane that is the fix.
This lane is already running and already succeeding, so a re-run produces one
more clean scan of the same stale tree and closes nothing. The row links to
the lane's CI view and names what to change.

**The estate is clean today, and the check was verified against it rather
than assumed.** Run over the live lake — 759 scan-run files, five
repositories, 103 commits on TheHub and 340 on mykronos — it reports **0
stale lanes**. Six lanes are behind their repository's head and every one of
them last ran *before* that commit existed, which is a lane waiting its turn
and not a lane that stopped following. That distinction is the whole check,
and reading it against real data is what showed it working rather than merely
returning an empty list.

- ~~The briefing and `scan-health` report a lane whose successful runs share
  one commit, naming the commit and the date it stuck.~~ Both, with `since`
  and `runs`.
- ~~Branch drift against `default_branch` is surfaced per repository.~~
- ~~TheHub reproduces both today.~~ **No longer true, and that is B-045
  landing rather than this entry being wrong.** TheHub scans `develop`, which
  is its recorded default, and its lanes follow the commits. The check was
  proved against fourteen synthetic cases instead — six that must fire and
  eight that must not, including the quiet repository, the build race, the
  lane simply waiting its turn, and the repository with a single lane.

**Provenance:** DevSecOps assessment, 2026-09-03 (second sweep); built
2026-09-09.

---

### B-061 — `event_driven` says a capability is fine without checking that anything runs it — **done**

**Size:** S **Verified:** 2026-09-04 **Closed:** 2026-09-09

`NON_SCANNING` conflated two different claims — "produces no scan run" and
"needs no job" — and the exemption was unconditional, so a capability nobody
had written a lane for reported `event_driven, problem: false`.

The split is now explicit. `GATE_JOBS` names the jobs that run a gate-driven
capability, and `coverage()` takes the CI system's job names so it can ask
whether a *lane* exists rather than whether a *run* exists. Oracle with a lane
stays `event_driven`; oracle with no lane is `no_job` and a problem. Aegis and
patchwork keep the unconditional exemption, and the reason is in the code
rather than only here: both are driven from inside Mykronos — aegis by webhooks
as reviews arrive, patchwork by a timer — so neither needs a pipeline job for
the capability to be working.

**Why the job names live in their own table rather than in
`CAPABILITY_BY_JOB`.** That table maps a job to the capability whose *scan
runs* it produces, and an oracle gate produces none. Registering it there would
fix this reading by telling a lie in the other direction: the lane would then
be expected to upload, and read as `never_reported` forever. A test asserts the
two tables stay disjoint.

**The instance had been fixed and the class had not.** This entry was filed
because `personal-soc` had oracle granted with no oracle job. Read on
2026-09-09, all three applied pipelines now have one — `oracle` on
`personal-soc`, `oracle-gate` on `mykronos` and `thehub` — so somebody wrote
the lane at some point in the five days since, and nothing recorded that
either. Checked against the applied configs rather than the files, which is
B-055's lesson:

| pipeline | oracle reads | with its oracle lane removed |
|---|---|---|
| `personal-soc` | `event_driven` | `no_job`, problem |
| `thehub` | `event_driven` | `no_job`, problem |
| `mykronos` | `event_driven` | `no_job`, problem |

The right answer today, and a red light the day any of them loses it. That is
the difference between a green that was checked and a green that was exempt.

**Checked:** five new tests — a capability driven from inside Mykronos is still
not a gap, a gate with a lane is fine with no scan run, the personal-soc shape
is a problem, either job name counts, and the two tables stay disjoint.

**Provenance:** DevSecOps assessment, 2026-09-04, while enabling oracle across
the estate; built 2026-09-09.

---

### B-047 — Disabling a capability strands its findings open forever — **done**

**Size:** S **Verified:** 2026-09-03 **Closed:** 2026-09-09

A finding closes only after two consecutive successful scans no longer observe
it (spec 05 §5). A capability that cannot upload will never produce one, so
its open findings could never close by any path the platform offered — not
because anything was unfixed, but because the only mechanism that could close
them had been removed.

**The closure rule is right and is not relaxed.** What changes is that the
removal says what it did. `FindingStatus.STRANDED` is platform-owned, absent
from `HUMAN_DISPOSITIONS`, and deliberately not `fixed`: it is a statement
about the pipeline, not a judgement about the risk, which may well still be
live. It sits in `TERMINAL_STATUSES` beside `superseded` — nothing can act on
it, and it is not a resolution either — so a disabled lane stops being reported
as holding N findings open, and the findings are still there to be found under
their own filter on the Findings tab.

**Restoring the grant reopens them**, back to `open` rather than to `fixed`,
because nothing has observed their absence and the next two successful scans
are what decide. Without that, re-enabling a capability would leave its history
in a state no scan can revisit, which is the same defect one step later.

**Keyed on the grant, not the ledger.** The grant is what ingestion enforces
(D-119), and `installer.apply` syncs grants immediately, decoupled from the
install pull request (spec 03 §5) — so for an Actions repository the uploads
stop before the PR merges, and the findings follow the moment they stop. A
finding somebody has already dispositioned is left alone: stranding is about
findings with no exit, and one that has been judged has an exit.

**The instance resolved itself, and the class did not.** This was filed
against TheHub's 32 `dast` findings with `dast` switched off. `dast` was
re-granted on 2026-09-05 inside B-062's restore, and that lane has been
reporting since — 156 fixed and 40 open today, which is what a working lane
looks like. So the 32 reached a recorded state by the capability coming back
rather than by anything here. The mechanism is what stops the next one.

**Checked:** twelve new tests, including the end-to-end shape — a capability
switched off while holding open findings, the response saying so, the audit
carrying the counts, re-enabling reopening them, and an ordinary capability
change saying nothing about findings at all, because a sentence reporting "0
stranded" every time is what gets the message skipped on the day it is not
zero.

**Provenance:** DevSecOps assessment, 2026-09-03 (second sweep); built
2026-09-09.

---

### B-055 — The promotion gate was fixed in one repository and applied from another — **done**

**Size:** M **Verified:** 2026-09-04 **Closed:** 2026-09-09

Four acceptance criteria. The first closed on 2026-09-04; the other three are
closed here, and two of them turned out to be already true.

- ~~`api-inventory` and `dast-demo` upstream of `deploy-prod`.~~ 2026-09-04.
- **TheHub's `develop` copy matches, and its tests pass.** Read on
  2026-09-09: `insider` on `develop` carries
  `passed: [oracle-gate, api-inventory, dast-demo]`, the same three this
  repository applies. The twelve promotion-gate tests are part of TheHub's
  `unit` suite, and that suite has been green on `develop` since 2026-09-06 —
  three successful runs since, the most recent at 12:10Z. Neither fact was
  recorded anywhere, which is the whole argument for the check below.
- **A check compares TheHub's copy against ours.**
  `scripts/check_pipeline_gates.py`, the direction `check_applied_pipelines.py`
  (D-081) never looked in.
- **A blocked lane is distinguishable from a silent one in the briefing.**
  `reason="blocked"`, with the upstream named.

**What the new check compares, and what it deliberately does not.** Every job
name, and every `passed:` constraint on every `get:` in it, nested steps
included. Not the whole file: ours is 4,100 lines and TheHub's `develop` is
7,900, mostly inline task scripts, and a diff of that would report hundreds of
differences nobody should act on — which is how a check stops being read. What
must agree is what governs promotion, and that is exactly what regressed.

**Only one branch fails it, and choosing which mattered.** `develop` decides,
because every commit lands there and the pipeline is scanned there (B-045).
`main` is read and reported and never fails the check: it lags `develop` by
design — it is missing `dast-staging` today — and a check that goes red for an
expected lag is one nobody reads. The first run found exactly that and nothing
else, which is the right answer on an estate where the gate currently agrees.

**The briefing half was a button that did nothing.** Every scan lane on a
Concourse-scanned repository carries `passed: [unit, ...]`, so while TheHub's
`develop` suite was red, Concourse scheduled none of them — and the briefing
called all of them `silent` and offered "Re-run this lane", which Concourse
would refuse. A lane that is quiet while an upstream it gates on has failed
*since that lane last ran* now reads `blocked`, names the upstream, and offers
the upstream's re-run instead. The ordering is load-bearing: an upstream that
broke *before* this lane last ran did not stop it, and blaming a red suite for
silence it could not have caused is the same overstatement B-065 complains
about from the other direction.

**Checked:** 2626 backend tests pass, thirteen new. Six on the briefing —
blocked behind a red upstream, the button pointing upstream, a green upstream
leaving silence as silence, an upstream that failed too early not blocking, the
upstream never blocking itself, and the rendered line. Seven on the gate check
— the constraint read flat, nested in `in_parallel` (both spellings) and in
`do`, the 2026-08-20 regression caught, ours-stricter reported, and each
missing-job direction named separately. mypy over 123 files, ruff, tsc and
eslint clean.

**What is not closed by this, and belongs to B-050.** TheHub's `develop`
carried a red suite for days and the only reason anybody noticed was that
somebody looked. The briefing now says `blocked` rather than `silent`, which
makes the *reading* honest; it does not make anybody read it. That is B-035's
webhook, which is still open.

**Provenance:** DevSecOps assessment, 2026-09-03 (second sweep); corrected and
half-closed 2026-09-04; finished 2026-09-09.

---

### B-062 — Enabling one capability silently revoked five others, and the audit said nothing was removed — **done**

**Size:** M **Verified:** 2026-09-05 **Closed:** 2026-09-09 (D-119)

Five acceptance criteria, five changes, one decision.

- **The audit records what was done.** Landed on 2026-09-05 inside the
  restore: `added` and `removed` come from `sync_grants`' return values, and
  the ledger diff is kept beside them as `ledger_added` / `ledger_removed`,
  because the two disagreeing is the signal. The binnacle row on the 7th —
  `removed: ["secrets"]` on a call that had never listed it — is this
  criterion working before the rest existed.
- **The ledger is authoritative, and the two are reconcilable (D-119).**
  `mykronos reconcile-grants` reads both sides for every repository and says
  where they differ; `--apply` widens each to their union and never revokes.
  Run against the estate on 2026-09-09: **0 repositories with drift**, which
  is the 2026-09-05 alignment still holding.
- **A PATCH that would revoke a grant not in the ledger refuses.** 409,
  naming the grants and both ways out: include them, or send
  `revoke_unlisted: true`. The ledger plus `pending_capabilities` is what a
  caller could have seen, so withdrawing a capability before its PR merges is
  still one call. The frontend proxy passes the flag through, off by default,
  and the button renders the 409's text.
- **The coverage cross-check sees the other direction.** A `Reporting` row for
  a capability outside the enabled set is `job_not_enabled` — `enabled:
  false`, `problem: true`, red on the Harness tab and on the capability
  button, with an explanation and an "enable it" action in place of "disable
  anyway". `not_enabled` still means what it meant when no job exists.
- **A 403 from ingestion reaches a person.** Every door — findings, raw, Aegis,
  Oracle, Patchwork — raises `CapabilityRefusedError`, and one handler turns it
  into the same 403 body as before plus a notification naming the repository,
  the capability, what is granted, and the `mykronos grant` that fixes it.
  Once per (repository, capability) per hour, so a scheduled lane that has
  lost its grant does not become a channel somebody mutes.

**What was checked rather than assumed.** 2607 backend tests pass, thirteen
new: the 2026-09-05 call reproduced and refused; the same call with the flag,
revoking and auditing `removed: ["dast"]` against `ledger_removed: []`; the
Actions path guarded the same way; a pending capability withdrawn without a
409; drift read in both directions and reconciled to the union with nothing
revoked; the new coverage state, and Oracle never reading as a stray job; the
refusal's 403 byte-for-byte as before, its notification, the quiet window
holding for the same pair and not for a different one, and expiring. mypy over
123 files, ruff, tsc and eslint clean; `api-types.d.ts` regenerated for the
new request field.

**Left where it was.** The two tables are not merged (D-119 says why), and the
2026-09-05 restore's own numbers stand as the record of what the defect cost.

**Provenance:** DevSecOps assessment, 2026-09-05, found while working out why
TheHub's `iac` lane was failing; sprang a second time on binnacle on the 7th
(B-052); built 2026-09-09.

---

### B-044 — One App permission is holding four features shut — **done**

**Size:** S **Verified:** 2026-09-03 **Closed:** 2026-09-09 (confirmed; granted 2026-09-04)

Granted on 2026-09-04 and closed here only because the confirmation was
never written down. Read on 2026-09-09, against the acceptance criteria:

- `repo_governance` carries a row per repository: five rows, thirteen
  controls read on each. Four read from branch protection; binnacle reads
  `none` with a score of 0, which is B-060's finding about that repository
  and not a read failure.
- The SSDF count moved. `mykronos` reads **11 of 13 met**, from 9 before the
  grant. The two left are PS.2, not evidenced because signed commits are not
  required — deferred deliberately in D-110 — and PW.7, partial because
  approving and codeowner reviews are not enforced, which is D-110's
  remaining execution under B-060.
- The drift sweep runs and has recorded something: two rows, both on
  2026-09-05 at 15:20Z, `codeowners_coverage` going `on -> unknown` on `keel`
  and `binnacle`. The first sweep after the grant recorded nothing, as the
  entry said it should; a later one saw a real transition. What that
  transition was is B-060's question — `unknown` is a control the platform
  could not read, and both repositories are the Actions-scanned pair that
  lost the tunnel that day (B-066).

The governance endpoint returns `readable: True` with fourteen controls. The
defect the grant exposed — the SSDF assessment comparing `state == "pass"`
against a module emitting `on`/`off`/`partial`/`unknown` — was fixed on
2026-09-04 and is what the count above depends on.

**Provenance:** DevSecOps assessment, 2026-09-03; granted 2026-09-04; the
entry's own text said it stayed open "only until the SSDF count is confirmed
to have moved and the first drift sweep is recorded", and both had happened
by the 5th.

---

### B-018 — `cloud` is enabled on a repository and its lane cannot run — **done**

**Size:** S **Verified:** 2026-09-01 **Closed:** 2026-09-09 (confirmed; executed 2026-09-05, D-108)

`cloud` is disabled on `ToddGBenson/TheHub`. The dashboard reads it as
`enabled: false`, never scanned, no findings — a capability that is absent
rather than a green one that cannot report, which is the state D-108 asked
for and the one this entry called the only defensible alternative to
restoring the principal.

The toggle happened inside B-062's restore on 2026-09-05 at 07:18Z: the
PATCH that re-granted TheHub's five deleted capabilities sent the set without
`cloud` (and without `functional`, for the same reason — `cloud-posture` and
`functional-dast` are both paused, so enabling either would be an enabled
capability with no lane feeding it, B-061's failure). D-108 records the
decision and the reversibility: the day an Azure principal exists, the
capability is one PATCH from being back.

Distinct from B-015, and it stayed distinct: there is no zero to misread
because there is no capability to read.

**Provenance:** 2026-09-01 monitoring sweep; decided 2026-09-05 as D-108;
executed the same morning as a side effect of B-062's restore, which is why
nobody closed it.

---

### B-053 — The DAST scanner is seventeen months old and says so itself — **done**

**Size:** XS **Verified:** 2026-09-03 **Closed:** 2026-09-08 (52bc141, run 34303749573)

`deploy/demo/docker-compose.yml` pins `ghcr.io/zaproxy/zaproxy:2.17.0`, still
exact. 2.17.0 is the current stable on the day of the change; the weekly
`w2026-09-08` tag is newer and floats, which D-114 ruled out.

**The measurement, taken on the runner as D-114 asked.** `demo-and-dast.yml`
now samples `docker stats` for every demo container from `up -d` to teardown
and writes peaks into the job summary; this is the first reading, from a
dispatched run on the branch with active scanning off:

| container | peak CPU | p95 CPU | mean CPU | peak memory |
|---|---:|---:|---:|---:|
| `zap` (2.17.0, passive) | 312% | 230% | 84% | 0.76 GiB |
| `backend` | 113% | 111% | 62% | 0.16 GiB |
| `frontend` | 39% | 35% | 11% | 0.15 GiB |

69 samples over 101s, on a 4-vCPU hosted runner. The whole job ran in 3m08s;
the functional suite passed 26 of 26 through the proxy and the spider reached
134 URLs from 29 seeded, inside its budget. D-053's figure was 548% and 7 GiB
for ZAP alone, on the shared host, with active scanning on — so this is not a
before-and-after on the same lane, and nobody took a 2.16.1 reading on a runner
to compare against. What it does establish is that the passive lane on 2.17.0
peaks at three cores for seconds and stays under a gigabyte, on a machine that
exists for ninety seconds and shares nothing. The posture question — whether
active scanning can come back *on the runner* — now has a baseline to be
answered against and is spec 32 §11.4's, not this entry's.

**The two findings closed themselves, as the acceptance criteria said they
would.** The previous `main` run uploaded 27 DAST findings; this one uploaded
25. `ZAP-10116-CWE-1104` is the difference. Two remain open in the lake against
`mykronos` until two consecutive successful scans record the absence
(`reconcile.REQUIRED_ABSENCES`), which the next two `main` deliveries provide.

**Two more are open against TheHub, and this did not touch them.**
`deploy/concourse/pipelines/thehub.yml` pins `2.16.1` twice — the
`dast-staging` image and a `ZAP_VERSION` — and that lane runs on the Concourse
worker on the LAN host, which is exactly the machine D-053 measured. Moving
that pin needs its own reading, taken there, and the runner figure above is
not it. Left in place deliberately; it is B-055's neighbour rather than this
entry's remainder.

**Provenance:** DevSecOps assessment, 2026-09-03 (second sweep); decided as
D-114 on 2026-09-05; built and measured 2026-09-08.

---

### B-052 — binnacle is onboarded and one repository grant short of being scanned — **done**

**Size:** XS **Verified:** 2026-09-03 **Closed:** 2026-09-08 (binnacle #8)

The grant happened on 2026-09-05, the day D-111 was recorded, and went one
capability further than the decision asked for: `atlas`, `iac`, `sast` and
`secrets` (binnacle #4, 01:10Z), then `oracle` (binnacle #5, 03:45Z). Both
merged within the hour, and every one of the five scanned and reported.
binnacle was `active` by 04:10Z on the 5th.

**Then `secrets` was switched off again, and nothing recorded why.** On
2026-09-07 at 22:43Z an admin PATCH sent the set without it — binnacle #7,
"Disable `secrets`", merged three minutes later. The audit row is honest
(`removed: ["secrets"]`, which is B-062's fix doing its job), but there is no
commit, retro or decision from that day that mentions binnacle, and the lane it
removed had scanned successfully thirteen hours earlier. The likeliest cause is
a PATCH built from a list that did not include it — the same routine call that
sprung B-062 on TheHub — and that reading is a guess. D-111 stands: `secrets`
is language-blind, it is one of the two capabilities that report truthfully
over a repository CodeQL cannot read, and keel, which binnacle is a fork of,
has it.

Re-enabled 2026-09-08 with the full current set (`atlas`, `iac`, `oracle`,
`sast`, `secrets`), read from the record first so nothing else was dropped.
That opened binnacle #8. The ingestion grant was live from the PATCH and the
pull-request trigger proved it before anybody merged anything:

    secrets/gitleaks: 0 finding(s) from 1 file(s)
    POST /api/ingest/findings  200 OK
    Uploaded 0 finding(s) for scan run d8ab488e (success)

**What #8 also does, which is worth knowing before the next one.** The
resync it carries moves binnacle's `mykronos-sast.yml` CodeQL pin from
v3.37.9 back to v3.37.6, because the `sast` template pins v3.37.6 and
dependabot had raised the generated file past it on 2026-09-07 (binnacle #6).
A generated file is overwritten on resync by design (spec 03 §6), so this
will happen on every install PR until the template's pin moves. It is a
three-line template bump and the same shape as B-057's "a comment cannot fail
a build": here it is a pin that cannot hold, because two writers own it.
Not fixed here; filed in Watching.

**Still true, and now visible:** CodeQL reads 33% of binnacle. `atlas` and
`secrets` cover the rest truthfully, and shell analysis is B-051's work. The
green is qualified, as D-111 said it had to be.

**Provenance:** DevSecOps assessment, 2026-09-03 (second sweep); decided as
D-111 on 2026-09-05; executed on the 5th, undone on the 7th, redone on the 8th.

---

### B-066 — The tunnel's service copy is stale, so two repositories cannot report at all — **done**

**Size:** XS **Verified:** 2026-09-05 **Closed:** 2026-09-06

`keel` and `binnacle` are both `scanned_by=github_actions`, and
`https://mykronos.toddbenson.net/api/ingest/` is their only path into the lake.
It has been returning 502 since about 08:40 on 2026-09-05.

The failure is in the upload, not the scan. From a runner:

    POST https://mykronos.toddbenson.net/api/ingest/scan-run -> 502  (x6)
    ERROR /api/ingest/scan-run failed after 6 attempts — HTTP 502
      Findings were NOT recorded; this step fails deliberately rather than
      letting the scan look clean (spec 01 §6)

**The tunnel is up and serving everything else**, which is what makes this
diagnosable in one step: `hub.toddbenson.net` answers 200 through the same
tunnel, `cloudflared` is running as a service, and `~/.cloudflared/config.yml`
correctly routes the mykronos API paths to `127.0.0.1:8100`.

**So the user config is right and the service is not reading it.**
`scripts/install-tunnel-route.ps1` documents exactly this: the service runs as
LocalSystem and keeps its own copy at
`C:\Windows\System32\config\systemprofile\.cloudflared\config.yml`, made when
the service was installed, so editing the profile copy "changes nothing until it
is copied across, which is why a new hostname resolves, reaches the tunnel, and
then falls through". The fix is that script, run elevated. It backs the service
copy up, shows what it replaces, restarts, and verifies.

**Two things to know before running it.** It restarts the tunnel, which briefly
drops `hub`, `blog` and `demo` — seconds, but not zero, and its own notes say
so. And its default `-VerifyUrl` is `https://mykronos.toddbenson.net/healthz`,
which is the right probe here: `/healthz` is the one path exempt from the
perimeter gate, so a 200 proves the route end to end without a credential.

**What is not wrong.** Not the ingestion tokens (B-024's failure, and these are
502s from Cloudflare's edge rather than 401s from the API), not the backend
(`127.0.0.1:8100/healthz` answers 200), not Vault, and not the perimeter gate —
`/api/ingest/*` is exempt from it by design.

**This is B-046 from the outside.** Two repositories stopped reporting twelve
hours ago and the platform's own briefing measures silence rather than coverage,
so the estate reads as four watched repositories when two of them have been
unable to file anything since morning. `keel` has 135 runs across four
capabilities and `binnacle`'s first ever scans landed that morning, hours before
this started.

**Closed 2026-09-06.** `install-tunnel-route.ps1` run elevated by the operator.
Verified against the public edge rather than from this host, which matters — see
below:

| path | before | after |
|---|---|---|
| `/healthz` | 502 | **200** |
| `/api/ingest/health` | 502 | **401**, the ingestion token being demanded |
| `/api/dashboard/portfolio` | 502 | **401**, the perimeter gate |

`hub`, `blog` and `demo` all still answer 200, which is the check the script's
`-MustStayUp` exists for.

**And a real run filed, which is the criterion that mattered.** `Mykronos atlas`
dispatched by hand on `keel`, success in 33s, and the row is present:

    ToddGBenson/keel | atlas | success | 2026-09-06T04:06:51 | main

It did not appear in `scan_runs` at first because a run lands in
`_buffer/scan_runs/*.jsonl` and reaches Parquet only at compaction — the same
buffering that makes an un-compacted read of a risk decision look stale.
`ToddGBenson/TheHub | dast | success | develop` was in the same buffer, so the
Concourse path is reporting too.

**The gap is accepted rather than replayed.** `keel` and `binnacle` missed their
scheduled passes between 08:40 on 2026-09-05 and the repair, roughly twenty
hours. Their next scheduled runs cover the same trees, and nothing was pushed to
either repository in the window, so a replay would re-scan identical commits and
produce identical findings. Recorded here so the hole is a decision rather than
something the next sweep rediscovers as unexplained silence.

**One correction worth carrying forward, because it would mislead the next
reader.** The original entry said the hostname "does not answer" from this host
while `hub.toddbenson.net` returned 200 through the same tunnel, and offered that
contrast as evidence. It was not evidence: this machine pins
`mykronos.toddbenson.net` to `127.0.0.1` in
`C:\Windows\System32\drivers\etc\hosts`, added 2026-09-03 when the dashboard
went LAN-only, so a local `curl` was failing to reach `127.0.0.1:443` and never
touched Cloudflare at all. The real evidence was always the runner's 502 from the
public internet. To check the edge from this host, bypass the override:

    curl --resolve mykronos.toddbenson.net:443:104.21.6.227 \
      https://mykronos.toddbenson.net/healthz

The conclusion happened to be right and the reasoning was not, which is the
worse of the two failure modes because it survives review.

**Acceptance criteria**

- `scripts/install-tunnel-route.ps1` run elevated, and
  `https://mykronos.toddbenson.net/healthz` answering 200 from off-host.
- A `keel` and a `binnacle` scan run recorded with a `started_at` after the fix.
- `hub`, `blog` and `demo` still answering afterwards, which the script checks.
- The gap is not silently absorbed: the runs missed between 08:40 and the fix
  are a coverage hole in two repositories, and whether they are re-run or
  accepted is recorded rather than left to the next sweep to rediscover.

**Provenance:** found on 2026-09-05 while checking whether D-113's coverage flag
had produced a figure on the Actions unit lane. The lane had failed, and it had
failed on the upload rather than the tests — which is only visible by reading the
log, because the run reports as a failed suite.

---

### B-049 — Filling in a risk profile silences the disclosure without changing the rank — **done**

**Size:** S **Verified:** 2026-09-03 **Closed:** 2026-09-05 (D-116)

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

**Decided 2026-09-05 — D-116: fix the disclosure now, rank terms separately.**
`not_consulted` reports business context whenever it is not a term, and
`consulted` is derived from the terms the rank can produce rather than restated
as a literal. Adding the three profile fields to `rank_terms` reorders every
queue on the estate and needs stated weights, so it gets its own decision rather
than riding in on a fix for an inaccurate warning.

**Acceptance criteria**

- Either the rank gains terms for the three profile fields, or `not_consulted`
  reports business context whenever it is not a term — regardless of whether a
  profile exists.
- `consulted` is derived from the terms the rank can actually produce rather
  than restated as a literal.
- With all four profiles set, the queue's claim about its own inputs is true.

**Closed 2026-09-05.** The second branch of the first criterion, per D-116.
Business context is now named whenever it is not a term and only the *reason*
moves with profile coverage — "unset anyway on <repos>" while profiles are
missing, "recorded on every risk profile and read by the portfolio decision, but
not a term in this rank" once they exist.

**`consulted` is derived, and the literal turned out to be wrong as well as
un-derived.** It listed four inputs; the rank also produces `repo_is_no_go`,
`orphaned` and `fixable`, and none of the three was disclosed. `RANK_INPUTS` is
now the single declaration — term key to the input it speaks for — and
`rank_terms`'s `add()` raises on a key that is not in it. A term cannot be added
to the rank without saying what input it discloses, which is the same move
TheHub #281 made for the SDK pin in B-057: a comment cannot fail a build, and a
hand-maintained list cannot stay true.

Four tests, and each one fails against the old code: the disclosure survives the
profiles being filled in; `consulted` equals what `RANK_INPUTS` declares; every
term the rank can produce is declared and nothing declared is unreachable; and an
undeclared term raises rather than ranking silently. The empty-portfolio case now
discloses too — the disclosure describes the rank, not the estate.

**Not done, deliberately:** the three profile fields are still not rank terms.
That reorders every queue on the estate and needs stated weights, so it is its
own decision rather than something smuggled in behind a fix for an inaccurate
warning (D-116).

**Provenance:** DevSecOps assessment, 2026-09-03 (second sweep).

---

### B-043 — Free-text questions need a model credential this repo must not hold — **closed as a decision** (D-115)

**Size:** M **Verified:** 2026-09-03 **Closed:** 2026-09-05 (D-115)

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

**Deferred 2026-09-05 — D-115.** The answer is that D-104's position stands:
grounding before phrasing, and the refusal list is what makes the fixed answers
trustworthy. Not blocked by anything and blocking nothing — and six open entries
(B-046, B-051, B-056, B-058, B-061, B-063) say the platform cannot yet vouch for
what a scan covered, which is the worst possible substrate for a fluent answer.
The credential is deliberately not provisioned early: the blocker was never the
key. The criteria below stand as the shape of the work whenever it is scheduled.

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

### B-045 — TheHub is scanned on a branch nobody merges to — **done**

**Size:** S **Verified:** 2026-09-03 **Closed:** 2026-09-04, re-opened and
re-closed 2026-09-05

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

**Re-opened and re-closed on 2026-09-05.** It did not hold for a day.

The close put the decision in `-Branch develop` at apply time and left
`set-thehub-pipeline.ps1`'s default at `main`. Re-applying the pipeline on
2026-09-05 for an unrelated fix printed `Delivering branch 'main'` and moved
TheHub back, silently — the third occurrence of the sentence this entry already
quotes from that script's own comment, this time with the script saying `main`
and the platform saying `develop`.

The default is now `develop`, so the decision lives in the repository rather
than in whoever remembers the flag, and `-Branch main` is the one-off. A
decision recorded only as an argument is a decision that reverts on the next
routine apply.

**Provenance:** DevSecOps assessment, 2026-09-03 (second sweep).

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
