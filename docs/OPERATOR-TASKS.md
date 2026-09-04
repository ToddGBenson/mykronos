# Operator tasks

Five things this platform cannot do for itself. Each needs a credential this
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

## 2 · B-035 — the Slack webhook

**Effort:** ~10 minutes. **Unblocks:** every notification path.

The notifier is built, configured and addressed to nobody. There is deliberately
no default endpoint — a deployment that changed no configuration must not be
posting its findings to a chat service.

### Steps

1. Create an incoming webhook: <https://api.slack.com/apps> → your app →
   **Incoming Webhooks** → **Add New Webhook to Workspace**. Pick a channel,
   copy the URL.

2. Add to `backend/.env`:

       MYKRONOS_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
       MYKRONOS_SLACK_NOTIFY_MIN_SEVERITY=high

3. Optionally enable the weekly digest, which is off by default because it
   messages people:

       MYKRONOS_DIGEST_ENABLED=true

4. Restart the stack. Use the sha-tag deploy, not `deploy.ps1` — that pulls a
   GHCR `:latest` promote has never moved.

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
   dropped.

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

1. Disable the capability so it stops reading as available:

       docker exec mykronos-backend mykronos disable-workflow ToddGBenson/TheHub cloud

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

## Why none of these was done for you

Writing code against any of them would be guessing. B-018 is a decision, B-042
is a call about this repository's CI budget, and B-035, B-043 and B-044 each
need a credential or grant this repository must not hold.

The shape they share is worth noticing: the platform's capabilities are ahead of
its wiring, which is a better problem than the reverse. Every one of these is a
built thing waiting for an input, and not one of them fabricates a value while
it waits.
