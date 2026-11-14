# Operator tasks

Ten things this platform cannot do for itself. Each needs a credential this
repository must not hold, or a decision only the operator can make.

They are not defects and not unfinished work. Every one of them is a built
feature waiting on an input, and each reports honestly that it cannot see
rather than fabricating a value — which is also the proof that it was built
right.

Ordered by payoff for effort. **B-044 first**: it is five minutes and it lights
four features.

Tokens referenced below live in `backend/.env`: `MYKRONOS_GATE_TOKEN` (`$GATE`),
`MYKRONOS_VIEWER_TOKEN` (`$VIEWER`), `MYKRONOS_ADMIN_TOKEN` (`$ADMIN`). The
PowerShell scripts need a real PowerShell prompt — pasting them after `!` in
Claude Code runs bash and eats the backslashes.

`mykronos`'s onboarding id, used in the examples:
`c4d9eff7-7ce6-4d39-89e1-49ff9d7ae774`. Get others from
`GET /api/dashboard/portfolio`.

---

## 1 · B-044 — grant `administration: read`

**Effort:** ~5 minutes. **Unblocks:** four features.

`repo_governance` holds zero rows — not stale ones, none ever. The App cannot
read branch protection, so the governance panel, three SSDF practices, Oracle's
governance term and the whole control-drift sweep are all inert.

D-097 keeps this permission *optional* deliberately: requiring it would fail the
spec 02 §8 permission smoke test for every installation that already exists.
Optional means somebody has to grant it.

### Steps

1. Open the App's permissions page. App ID is `4551328`; the slug is
   `mykronos-platform` (confirm against your key filename in
   `MYKRONOS_GITHUB_APP_PRIVATE_KEY_PATH`):

       https://github.com/settings/apps/mykronos-platform/permissions

2. Under **Repository permissions**, set **Administration** to **Read-only**.
   Save.

3. **The step people miss.** A permission change is *requested*, not applied.
   GitHub emails the installation owner and the install sits pending until
   somebody accepts. Go to <https://github.com/settings/installations>, click
   **Configure** on the Mykronos install, and accept the request at the top.

4. Verify. No restart needed — the installation token is minted per request:

       curl -s -H "X-Hub-Token: $GATE" -H "Authorization: Bearer $VIEWER" \
         "http://127.0.0.1:8100/api/dashboard/repos/c4d9eff7-7ce6-4d39-89e1-49ff9d7ae774/governance" \
         | python -c "import json,sys; d=json.load(sys.stdin); print(d['readable'], len(d.get('controls') or []))"

   Expect `True 9`.

### What should change

- Governance panel renders nine controls instead of an unreadable notice.
- SSDF count moves above 9/13 on the Adherence tab (PS.1, PS.2, part of PW.7).
- Oracle's governance term goes `available: True` at the next portfolio scoring.
- The control-drift sweep starts having something to compare.

### Expected, and not a bug

The **first** sweep after the grant produces no drift rows. A first reading has
nothing to compare against, and treating every control as having moved from
`unknown` would file nine security regressions for a repository that has done
nothing (D-105).

---

## 2 · B-035 — the Slack bot (D-112 as amended, D-137)

**Effort:** ~5 minutes. **Unblocks:** every notification path.

The notifier is built, configured and addressed to nobody. There is deliberately
no default endpoint — a deployment that changed no configuration must not be
posting its findings to a chat service.

Nothing is pasted any more. `deploy/mykronos/deploy.ps1` reads the host's Slack
bot token and alert channel from Vault (`concourse/main/slack-bot-token`,
`concourse/main/slack-alert-channel`) — the same two values the Concourse
pipeline alerts post with — and hands them to compose. Leave
`MYKRONOS_SLACK_WEBHOOK_URL`, `MYKRONOS_SLACK_BOT_TOKEN` and
`MYKRONOS_SLACK_CHANNEL` empty in `backend/.env`.

### Steps

1. Make sure Vault is unsealed: `deploy\concourse\vault-unseal.ps1`.

2. Deploy a sha that carries this change:

       .\deploy\mykronos\deploy.ps1 -Tag <sha>

   It prints `Slack bot token and channel resolve from Vault (concourse/main).`
   A yellow line naming a variable means Vault could not be read for it.

3. Confirm the backend picked the transport up:

       docker logs mykronos-backend 2>&1 | Select-String "Slack notification"

   Expect `Slack notification is enabled (bot).`

4. Post one test message from the running backend and check the channel:

       docker exec mykronos-backend python -c "import asyncio; from mykronos.config import Settings; from mykronos.notify import Notification, SlackNotifier; s = Settings(); print(asyncio.run(SlackNotifier(s.slack_webhook_url, bot_token=s.slack_bot_token, channel=s.slack_channel).send(Notification(title='Mykronos notifier test', detail='B-035: posted by the running backend.', repo_full_name='ToddGBenson/mykronos', level='info'))))"

   `True` means Slack accepted it. `False` is followed by a warning carrying
   Slack's own error, for example `not_in_channel` (invite the bot).

5. Optionally enable the weekly digest, which is off by default because it
   messages people. Add this to `backend/.env` and redeploy (step 2):

       MYKRONOS_DIGEST_ENABLED=true

   Until #60754 the compose file did not pass this setting, so it had no
   effect on the deployed backend. Confirm it landed:

       docker exec mykronos-backend printenv MYKRONOS_DIGEST_ENABLED

### Choosing the threshold

Start at `high`. If it proves noisy, move to `critical`. The failure mode of an
alert channel is that people stop reading it, which costs more than it saves.
Messages are one summary per ingested batch, not one per finding: a scan
uploading four hundred criticals is one event a person needs to know about.

---

## 3 · B-042 — coverage

**Effort:** ~15 minutes, plus a CI-time decision. **Unblocks:** a real number on
the Harness tab.

Coverage is plumbed end to end and no pipeline writes a coverage document. The
JUnit adapter parses Cobertura `line-rate` and JaCoCo `LINE`, the registry
merges the columns, the lake stores them, `scan_health` already prefers the last
run that *reported* coverage over the last run, and the uploader rglobs and
merges every `*.xml` under `$MYKRONOS_RESULTS`.

Drop a `coverage.xml` beside `unit.xml` and the number appears with no platform
change.

### The decision, first

Coverage collection under `pytest-xdist` adds roughly 20–30% to a 14-minute
suite that runs on every pull request — about 3–4 minutes per run. If that is
not worth it, **skip this**. The Harness tab currently says "never measured",
which is true; a fabricated zero would be worse than a blank.

### Steps

1. Add to `backend/pyproject.toml`, under `[project.optional-dependencies]`
   `dev`:

       "pytest-cov>=6.0",

2. Update the stored lane command. There is no UI for capability config, so this
   is an API call. Current value:

       python -m pytest -q -n auto --junitxml="$MYKRONOS_RESULTS/unit.xml"

   Target value adds coverage output into the same results directory:

       python -m pytest -q -n auto \
         --cov=mykronos --cov-report=xml:"$MYKRONOS_RESULTS/coverage.xml" \
         --junitxml="$MYKRONOS_RESULTS/unit.xml"

   `PATCH /api/repos/{repo_id}/capabilities` sets the **whole** capability set,
   so send the current list along with the config:

       curl -X PATCH "http://127.0.0.1:8100/api/repos/c4d9eff7-7ce6-4d39-89e1-49ff9d7ae774/capabilities" \
         -H "X-Hub-Token: $GATE" -H "Authorization: Bearer $ADMIN" \
         -H "Content-Type: application/json" \
         -d @coverage-patch.json

   Read the current set first with `GET /api/repos/{repo_id}` so nothing is
   dropped. Since D-119 a set that would revoke a grant the dashboard never
   showed is refused with a 409 naming it; `mykronos reconcile-grants` lists
   every repository where the ledger and the grant table disagree.

3. Merge the workflow-install PR that the PATCH opens.

4. Let one unit run finish, then open the Harness tab. A percentage appears with
   no platform change — which is the proof the plumbing was always right.

5. **Record the measured CI cost in this file and in B-042.** The acceptance
   criteria say measured, not assumed.

---

## 4 · B-018 — the Azure decision

**Effort:** a decision, then ~10 minutes either way. **Unblocks:** honesty about
`cloud`.

`cloud` is enabled on `ToddGBenson/TheHub` and has produced zero scan runs ever.
`thehub`'s `cloud-posture` job is paused because `deploy/concourse/.env` carries
no Azure service principal.

**This needs a decision before code.** Only the operator knows whether the
principal was lost with the rest of `.env` on 2026-08-23 or deliberately never
set. Both answers are defensible. Leaving it enabled and inert is the one state
that is not.

### If restoring it

1. Add four keys to `deploy/concourse/.env`:

       AZURE_CLIENT_ID=...
       AZURE_CLIENT_SECRET=...
       AZURE_TENANT_ID=...
       AZURE_SUBSCRIPTION_ID=...

2. Re-apply the pipeline from a PowerShell prompt:

       .\deploy\concourse\set-thehub-pipeline.ps1

   The script refuses to apply without the principal unless `-AllowMissingAzure`
   is passed, so a clean run without that flag means it took.

### If not restoring it

1. Disable the capability so it stops reading as available: untick `cloud` in
   TheHub's capability settings on the dashboard, which sends
   `PATCH /api/repos/{repo_id}/capabilities` without it. TheHub is scanned by
   Concourse, so that moves the enabled set at once, revokes the `cloud` grant
   and opens no pull request (spec 03 §3a).

   Do not use `mykronos disable-workflow`. It switches an installed GitHub
   Actions workflow, and it refuses any repository whose `scanned_by` is not
   `github_actions`, so for TheHub it exits 1 and changes nothing.

2. Write it up as a decision, the way D-053 did for DAST. A capability that is
   off for a stated reason is a posture; one that is on and cannot run is a
   claim the platform cannot support.

---

## 5 · B-043 — the model credential

**Effort:** ~30 minutes to supply, then implementation. **Unblocks:** free-text
questions in Consult.

Optional. The Consult tab answers its fixed question set from records today and
cites the tab each answer came from; a model adds free text over the same
`consult.Facts`.

### Steps

1. Get a key: <https://console.anthropic.com/settings/keys>.

2. Put it in **Vault, not `.env`** — spec 12 §2 keeps model credentials out of
   the repository tier. If the host has rebooted, unseal first:

       .\deploy\concourse\vault-unseal.ps1
       .\deploy\concourse\Import-EnvSecretsToVault.ps1

3. Then the implementation, whose acceptance criteria are already written in
   B-043:

   - Free text answered **only** from `consult.Facts` and what the caller is
     already authorised to read. No repository source, no lake queries the asker
     could not run themselves.
   - Every sentence carries the same tab citation the fixed answers carry. An
     answer that cannot cite is not shown.
   - It still cannot act: no dispositions, no acceptances, no scans, no pull
     requests.
   - A question on the `consult.UNANSWERABLE` list is refused with its stated
     reason rather than attempted.

The refusals are not a placeholder for the model. They stay when it arrives — a
model that answers them anyway is worse than the list, because the list is what
makes the rest trustworthy (D-104).

---

## 6 · #452 — let the deployment probe read the running revision

**Effort:** ~10 minutes. **Unblocks:** "production is N commits behind" in
the briefing, and the `prod N behind` badge on the portfolio and the
Product Owner delivery view.

The deployment probe reads `build.sha` from each repository's
`deployment_probe_url`. Since D-157, mykronos's `/healthz` and TheHub's
`/health` only serve that sha to a caller presenting their perimeter token.
Without a token the probe reads `unparsed`, and the briefing says production
lag is unknown and why. D-165 records the design.

### Steps

1. Set each repository's probe URL as the backend container reaches it
   (admin token):

       curl -s -X PUT -H "X-Hub-Token: $GATE" -H "Authorization: Bearer $ADMIN"          -H "Content-Type: application/json"          -d '{"probe_url": "http://127.0.0.1:8100/healthz"}'          "http://127.0.0.1:8100/api/repos/c4d9eff7-7ce6-4d39-89e1-49ff9d7ae774/deployment-probe"

   For TheHub, use its `/health` URL as seen from inside `mykronos-backend`,
   e.g. `http://host.docker.internal:8000/health`.

2. Tell the probe which token to present to each origin. Add this to
   `backend/.env` and redeploy:

       MYKRONOS_DEPLOYMENT_PROBE_TOKENS={"http://127.0.0.1:8100": "@gate", "http://host.docker.internal:8000": "@hub"}

   `@gate` is `MYKRONOS_GATE_TOKEN` and `@hub` is `MYKRONOS_HUB_API_TOKEN`,
   so neither secret is written down twice. Any other value is used as the
   token itself. Keys are origins (`scheme://host[:port]`), and an origin
   not listed gets no token. That is deliberate, because a probe URL can be
   edited and the two hosts' tokens differ (D-131).

3. Wait for the `deployment-probe` job, which runs every
   `MYKRONOS_DEPLOYMENT_PROBE_INTERVAL_SECONDS` (default 30 minutes), then
   check:

       curl -s -H "X-Hub-Token: $GATE" -H "Authorization: Bearer $VIEWER"          http://127.0.0.1:8100/api/dashboard/deployments          | python -c "import json,sys; [print(r['repo_full_name'], r['status'], r['lag']) for r in json.load(sys.stdin)['repos'] if r['probe_url']]"

   Expect `ok` and a lag of `behind`, `at_head` or `diverged`. A lag of
   `unknown` comes with a `detail` saying what is missing: a token for the
   origin, a wrong token (the endpoint answers 200 either way), or an image
   built without `MYKRONOS_BUILD_SHA`.

---

## 7 · #60834 — schedule the host and LAN collectors

**Effort:** ~15 minutes. **Unblocks:** environmental CVSS lowerings that stay
applied. An observation lowers a score only while it is no older than 14 days
(`control_observations.FRESH_DAYS`). A collector nobody runs is a lowering that
quietly lapses two weeks later. D-166 records the design.

What runs today:

| Vantage | Collector | Schedule |
|---|---|---|
| `internet` | `exposure` job in the backend | every 6 h (`MYKRONOS_EXPOSURE_PROBE_INTERVAL_SECONDS`), already running. It records observations only for endpoints registered with a `repo_full_name` (step 4). |
| `host` | `Publish-ControlObservations.ps1` | nothing until step 3 |
| `lan` | `python -m mykronos.lan_scan` | nothing until step 3, and only if you pass a range and an authorization |

The tasks read the tokens from `backend\.env` each time they fire:
`MYKRONOS_CONCOURSE_TOKEN` for mykronos, `MYKRONOS_THEHUB_CONCOURSE_TOKEN` for
TheHub, and `MYKRONOS_GATE_TOKEN`. The task definition holds the key names,
never the values. `repair-ingestion-token.ps1` writes a rotated token to the
same keys, so a rotation does not mean registering again.

### Steps

1. Give each repository's token the `network` grant. Without it ingest answers
   403, because an observation can lower a score:

       docker exec mykronos-backend mykronos grant ToddGBenson/mykronos network

   Add `ToddGBenson/TheHub` too if you want a TheHub host task (step 3).

2. See what would be registered. The script checks every input and prints the
   task arguments. It registers nothing and prints no token:

       pwsh -File deploy\concourse\Register-ControlObservationTasks.ps1 -WhatIf -Verbose

   A `refused:` line names what is missing: a key in `backend\.env`, nmap, or
   `backend\.venv` for the LAN scan.

3. Register the tasks in your own (non-elevated) PowerShell:

       pwsh -File deploy\concourse\Register-ControlObservationTasks.ps1

   This registers `Mykronos Observations (host, ToddGBenson_mykronos)` daily
   at 05:00. Options:

   - Add TheHub with `-HostRepo ToddGBenson/mykronos,ToddGBenson/TheHub`. Its
     containers are matched by `thehub*`. Check that with `docker ps` first.
   - Add the LAN scan with both of the following. With only one, the script
     refuses (spec 14 §3). There is no default range.

         -LanCidr 192.168.0.14/32,192.168.0.20/32 `
         -LanAuthorizationReference "CHG-nn: Todd authorises a daily scan of his own hosts, 2026-10-20"

     It runs at 05:30 and files under `-LanRepo` (default mykronos). Write the
     authorization as a standing one. It goes into the audit log on every run.

   The tasks run as you, only while you are logged on. Docker Desktop runs only
   then too, and no Windows password is stored. A run missed while logged off
   or asleep happens at the next logon (StartWhenAvailable).

4. Check that the internet collector has something to probe. If a public
   endpoint has no repository, its answers are never filed:

       curl -s -H "X-Hub-Token: $GATE" -H "Authorization: Bearer $VIEWER" \
         http://127.0.0.1:8100/api/exposure

   If an endpoint lacks `repo_full_name`, delete it and register it again
   (`POST /api/exposure/endpoints` with `url`, `repo_full_name` and optionally
   `surface_id`, admin token).

5. Run each task once and look at the result:

       Start-ScheduledTask -TaskName 'Mykronos Observations (host, ToddGBenson_mykronos)'
       Get-Content "$env:LOCALAPPDATA\mykronos-observations\last-host-ToddGBenson_mykronos.log"

   Expect `result: ok`. Last Run Result `2` means refused (the log says why),
   and `1` means the post failed. Then
   `GET /api/dashboard/repos/{repo_id}/control-observations` lists `host`
   rows with `fresh: true`.

### Expected, and not a bug

There is no in-app warning yet when host or LAN observations stop arriving. A
lapsed lowering shows only as `stale: last observed N days ago` on the
environmental view. A briefing line for "no `host` observation in 3 days" is
the follow-up.

---

## 8 · TheHub #60855 — grant `Dependabot secrets: Read and write`

**Effort:** ~5 minutes. **Unblocks:** every Dependabot pull request's lanes.

A Dependabot-triggered Actions run reads a repository's *Dependabot* secrets,
a store separate from the Actions secrets the platform has always written. So
`MYKRONOS_INGESTION_TOKEN` was delivered to one store and not the other, and
every Dependabot pull request's upload and risk-decision steps failed closed
with a blank token. Nobody could paste the value by hand: only its SHA-256 is
stored.

The platform now seals the token into both stores wherever it seals one. The
Dependabot write needs a permission the App did not hold, so until it is
granted each repository records the refusal on its token and the work queue,
the briefing and the platform-health page show it as `dependabot_unsynced`
with the reason. Like `administration: read`, it is *optional* on purpose:
requiring it would fail the spec 02 §8 smoke test for every installation that
already exists.

### Steps

1. Open the App's permissions page (the same page as task 1).

2. Under **Repository permissions**, set **Dependabot secrets** to
   **Read and write**. Save.

3. Accept the permission update on the installation: **Configure** on the
   Mykronos install at <https://github.com/settings/installations>, then the
   request at the top.

4. Let the next rotation sweep run, or force one with `mykronos rotate-due`.
   For each repository whose Actions secret is delivered it reads the
   installation's grant and requires `dependabot_secrets: write`; only then
   does it rotate the token once and write both stores (it does not ask for
   the Dependabot public key first: a Read-only grant can read that key). Until
   the grant is held the sweep rotates nothing and prints
   `NO DEPENDABOT SECRET <repo>: <reason>` per repository, with the owner and
   the next step for that reason.

   If the reason says the write *failed under a held grant*, the sweep skips
   that repository until its next due rotation, so a plain re-run retries
   nothing. Fix the cause (the repository's Dependabot settings, or the GitHub-side
   refusal named in the recorded reason), then either wait for the next due
   rotation, or retry now with `mykronos rotate-token <owner/repo>` followed
   by `mykronos rotate-due`. The token `rotate-token` prints is discarded: it
   only makes a fresh token with no recorded blocker, and the sweep then
   issues and delivers its own to both stores, so do not paste the printed
   value. The cost is one extra rotation (two tokens burned).

5. Verify, per repository:

       gh secret list --app dependabot -R <owner>/<repo>

   Expect `MYKRONOS_INGESTION_TOKEN` listed. Then re-run `risk-decision` on an
   open Dependabot pull request: it records a decision instead of exiting with
   "No ingestion token".

### Expected, and not a bug

A repository scanned by Concourse records nothing here: the sweep writes no
secret to a repository it does not drive (D-086), Dependabot included. A
repository with both an Actions lane and a Concourse pipeline records the
refusal with a hand-rotation instruction, because rotating it from here is
what D-097 forbids.

---

## 9 · TheHub #61615 — switch the Dependabot autopilot to `live`

**Effort:** one line, after reading one listing. **Unblocks:** green
minor/patch dependency groups merging without the feature train.

The `dependabot-autopilot` job walks every open pull request opened by
`dependabot[bot]` on an onboarded repository every fifteen minutes. A pull
request goes ahead only when it is in a minor/patch group
(`pip-minor-patch`, `npm-minor-patch`), changes nothing but that group's
manifests and lockfiles, carries no major bump (a `0.x` minor counts as one)
and no security advisory above moderate, and has every required check of its
base branch plus `library-allowlist` green on its current head. Everything
else is skipped with the reason.

It ships in `dry-run`: each Dependabot pull request appears in the agent work
queue (`GET /api/agent/work`, `waiting`, kind `dependabot_autopilot`)
with what the job would do — `would_request`, `awaiting_approval`,
`would_merge` — or why it skipped it. Nothing is requested or merged.

### Steps

1. Read the listing once and check that every `skipped` reason and every
   `would_request` is what you expect.
2. In `backend/.env` set `MYKRONOS_DEPENDABOT_AUTOPILOT_MODE=live` and
   redeploy the backend.

In `live` the job requests `pull_request_merge` approval for each green head
through the same path as `POST /api/approvals/pull-requests` (an existing
request counts as requested), and once a request is approved and
`independent-review` is green on that head, the GitHub App squash-merges at
exactly that sha, at most five per run. The squash commit carries
`Approval-Request: <id>`. `off` stops the job.

### Expected, and not a bug

A single-dependency or lockfile-only Dependabot pull request (Dependabot opens
these outside the groups) is skipped: it is not a group update, and a person
reviews it as before. A push after the approval moves the head; the old
approval is never merged, and the new head is judged from scratch.

---

## 10 · TheHub #61610 — let MyKronos deploy itself after promote

**Effort:** ~5 minutes now, a day of reading, then one command. **Unblocks:**
production keeping up with main without a hand run.

**The hand deploy is now the exception.** Concourse's `promote` job proves a
commit (it runs only after `oracle-gate`), and then nothing happened until a
person ran `deploy.ps1`, so production drifted days behind main. The
scheduled task "MyKronos Auto Deploy" closes that gap: every 10 minutes
`deploy/mykronos/Watch-AutoDeploy.ps1` decides whether to deploy, and in Live
mode runs `deploy.ps1 -Tag <full sha> -Registry localhost:5000` itself.

It deploys only when **all** of these hold, and otherwise logs every rule that
failed:

| Rule | Skip reason |
|---|---|
| a `promote` build succeeded, and its sha is main's head (a newer main head means wait for its promote) | `no_promoted_build`, `main_unread`, `main_ahead_of_promote` |
| production does not already run it, and the running sha can be read (it is the rollback target) | `already_running`, `running_unread` |
| the images of the sha production runs now are on this host and in the registry, so a failed deploy has a way back | `rollback_unavailable` |
| it was never attempted: **one attempt per sha**. Only a run that moved the stack, or died after it started, counts (see the carve-out below) | `already_attempted` |
| no MyKronos deploy holds the lock, and no TheHub deploy holds its own | `lock_held`, `thehub_deploy_running` |
| Vault is unsealed | `vault_sealed`, `vault_unread` |
| the Docker VM has at least 4096 MB available, Windows at least 1536 MB free | `vm_memory_low`, `windows_memory_low`, `*_unread` |
| it is not 22:00–07:00 Arizona time | `quiet_hours` |

"Could not read" is always a skip, never a pass.

**A skip that does not end is reported once.** When the same blocking reason
(a held lock, a sealed Vault, low memory, an unreadable source, no way back)
is the headline for 6 ticks in a row (an hour), the watcher writes one
`stuck` line to the JSONL and, in Live, sends one failed host-job run and
opens one Hub incident (`source_ref mykronos-auto-deploy:stuck:<reason>`).
Waiting states are never reported: quiet hours, already running, already
attempted, waiting for promote. The usual cause is a lock left by a run that
was killed; check nothing is running and remove the lock directory.

### Steps

1. From a PowerShell 7 prompt in the production checkout, on a current main:

       .\deploy\mykronos\Register-AutoDeploy.ps1 -DryRun

   It registers the task to **decide and log only**. Nothing is deployed in
   this mode, the Hub is not written to, and the attempts memo is untouched.
   `-DryRun -WhatIf` shows what it would register without registering it.

2. Optional, for the Hub record and incidents: put an agent Hub credential
   (never the admin token) in `$HOME\.mykronos-agents\mykronos-auto-deploy-hub.token`.
   Without it, Live runs still deploy and log; they are just not reported to
   the Hub. The story-lifecycle record of a deploy is `deploy.ps1`'s own
   recorder (`MYKRONOS_DEPLOY_RECORDER` in `backend/.env`, task from
   TheHub #61046), which runs on any confirmed deploy, hand or scheduled.

3. Read 24 hours of decisions. One JSON line per tick, in
   `%LOCALAPPDATA%\mykronos\auto-deploy\decisions.jsonl`:

       Get-Content "$env:LOCALAPPDATA\mykronos\auto-deploy\decisions.jsonl" -Tail 200 |
           ForEach-Object { $_ | ConvertFrom-Json } |
           Format-Table at, mode, action, reason, sha

   `event` is `decision` on every tick, and `deploy_start` / `deploy` on a Live
   attempt. `reason` is the headline, `reasons` every failing rule, `checks`
   every rule that passed, and `inputs` the raw values it decided on (shas,
   lock, seal, memory). A `deploy` line carries `result`, `exit`, the health it
   saw afterwards, `rollback`, timings and the paths of the deploy logs.
   Expect `quiet_hours` overnight, `already_running` most of the day and
   `action: Deploy` on the first tick after a promote. If every line is
   `*_unread`, the task cannot reach Docker or Concourse under its logon:
   re-register with `-UsePassword`.

4. Flip it to Live:

       .\deploy\mykronos\Register-AutoDeploy.ps1 -Live

   The same command replaces the task. Check the first real deploy: a
   `deploy` line with `result: success`, and
   `(Get-ScheduledTaskInfo -TaskName 'MyKronos Auto Deploy').LastTaskResult`
   is `0` (`3` skip, `1` failed, `75` lost the lock, `124` still running).

### Stopping it

    Disable-ScheduledTask -TaskName 'MyKronos Auto Deploy'                       # pause
    Unregister-ScheduledTask -TaskName 'MyKronos Auto Deploy' -Confirm:$false    # remove
    .\deploy\mykronos\Register-AutoDeploy.ps1 -DryRun                            # back to decide-and-log

A hand `deploy.ps1` run is still fine and needs no disarming: it takes the same
lock (`%LOCALAPPDATA%\Temp\mykronos-deploy.lock`), so the two cannot overlap,
and a second one exits 75 with nothing pulled.

### When a deploy fails

The watcher judges the result itself: both containers healthy and the
backend's `MYKRONOS_BUILD_SHA` equal to the sha it asked for. If the stack
changed and is not healthy on the new sha, it **rolls back** by running
`deploy.ps1` again with the sha that was running before (recorded before the
attempt), with `-GateWaitMinutes 0`, and opens one Hub incident (room devops,
`source_ref mykronos-auto-deploy:<sha>`). If `deploy.ps1` refused before it
changed anything (the risk gate, a failed pull), production is untouched and
there is nothing to roll back; the incident still opens. The rollback goes
through the risk gate like any deploy and is not forced, so a previous sha the
gate never scored is refused and the incident says `rollback_failed`.

The failed sha is **not retried**. A new promoted main head re-arms the
watcher. To retry the same sha after fixing the cause, remove its entry from
`%LOCALAPPDATA%\mykronos\auto-deploy\attempts.json`.

**Pre-move refusal vs attempt: a deploy that changed nothing is not an
attempt.** `deploy.ps1` says so itself (TheHub #61644). Every stop before it
changes the host (the risk gate refused the sha or never scored it within its
wait, another deploy held the lock, a pull failed, an override could not be
recorded, `backend/.env` is missing) prints one line,
`DEPLOY-PRE-MOVE-REFUSAL kind=<kind>`, then fails as before (exit 1; 75 for
the lock). Both images are pulled before either is retagged, so a failed pull
moves nothing either. The watcher needs the failing exit and the line
together; the memo then
records `result: not_attempted`, `attempted: false` and `reason: <kind>`
(`risk_refused`, `risk_not_judged`, `lock_held`, `pull_failed`,
`override_unrecorded`, `env_missing`, `usage`), the Hub run summary carries
`attempted` and `reason`, the decision ignores that entry, and the next tick
that passes every rule tries the same head again. No hand edit is needed.
Anything else is an attempt: once `deploy.ps1` is past those checks, a
failure spends the sha's one attempt even if the old containers still answer.
The watcher's own checks (lock, Vault, both memory floors) skip before
`deploy.ps1` is called at all, and the forward deploy is always passed the
full 40-character sha. The incident still opens, once per sha while
it stays open. The retries are capped: after 3 `not_attempted` runs of one sha
within 24 hours of the first, the watcher skips it with `retry_cap` (a blocking
reason, so the stuck alert fires once) until that window ends or a new head is
promoted.

If `deploy.ps1` exits non-zero but both containers are healthy on the new
sha (the briefing or the recorder failed after the deploy), the result is
`success_with_warning` and nothing is rolled back.

Before it deploys, the watcher checks that both images of the running sha
are still on this host and in the registry (`rollback_unavailable` if not).
`deploy.ps1` has no option to protect a sha from registry retention, so do not
run `deploy\concourse\Invoke-RegistryRetention.ps1 -Apply` while a deploy is
running, and always pass it `-KeepShas` with the running sha.

A `deploy.ps1` still running after 90 minutes is left running, not killed,
and the lock stays held: every later tick says `lock_held` until a person
checks and removes the lock directory.

### Expected, and not a bug

- The task's run limit is 4 hours. A deploy waits up to 90 minutes and a
  rollback another 90, so the limit never stops a run part way.
- The Hub answers 422 for the host job `mykronos-auto-deploy` until TheHub
  allow-lists it (a one-line TheHub change). The watcher logs this and
  carries on, and `decisions.jsonl` keeps the record.
- `running_unread` while the backend container is down: with no running sha
  there is nothing to roll back to, so the watcher will not deploy over it.
  Deploy by hand.
- A hand rollback is not undone: the rolled-back-from sha was attempted, and
  the watcher waits for a newer promote.

---

## Why none of these was done for you

Writing code against any of them would be guessing. B-018 is a decision, B-042
is a call about this repository's CI budget, and B-035, B-043 and B-044 each
need a credential or grant this repository must not hold.

The shape they share is worth noticing: the platform's capabilities are ahead of
its wiring, which is a better problem than the reverse. Every one of these is a
built thing waiting for an input, and not one of them fabricates a value while
it waits.
