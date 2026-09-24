# Vault — credential manager, and personal secret store

Added 2026-08-13. Runs as the `vault` service in `docker-compose.yml`.

## Why

Concourse stores pipeline configuration **verbatim**. A secret passed with
`fly set-pipeline -l vars.yml` is readable afterwards by anyone who can run
`fly get-pipeline`. That is the difference this closes: a pipeline now
*references* a secret instead of *containing* one.

Every pipeline on this host benefits, not just `keel` — `personal-soc` and
`thehub` can move their credentials in the same way.

## Two mounts, deliberately different

| Mount | KV | For | Path layout |
|---|---|---|---|
| `concourse/` | **v1** | Read by Concourse | `concourse/<team>/<pipeline>/<name>` then `concourse/<team>/<name>` |
| `personal/` | **v2** | Everything else on this host | `personal/<anything>` |

`concourse/` is **v1 on purpose**. KV v2 inserts a `data/` segment into the API
path and wraps values in a metadata envelope; Concourse's default lookup
templates expect a flat read. `personal/` is v2 because version history is the
point there — overwriting a secret does not destroy the previous value.

Concourse reads with a token scoped to `concourse/*`, **read and list only**. It
cannot see `personal/`, and it cannot write anywhere. Verified at bootstrap by
attempting a read of `personal/` with that token and confirming it is denied.

## Daily use

```powershell
# Personal secrets — API keys, licence keys, recovery codes
.\vault-secret.ps1 set  openai/api-key          # prompts; never echoed, never in history
.\vault-secret.ps1 get  openai/api-key -Reveal
.\vault-secret.ps1 list
.\vault-secret.ps1 undo openai/api-key          # roll back to the previous version

# A credential for one pipeline
.\vault-secret.ps1 set github_token -Scope pipeline -Pipeline keel
#   ...the pipeline then refers to it as ((github_token))

# Shared across every pipeline in the team
.\vault-secret.ps1 set slack_webhook_url -Scope team
```

Values are prompted with `Read-Host -AsSecureString` and piped on **stdin**, so
they never reach shell history and never appear in the container's process list.
`get` prints only a length unless you pass `-Reveal`.

## After a reboot — or a recreate: unseal

```powershell
.\vault-unseal.ps1
```

Vault uses file storage rather than `-dev` mode, so its data survives a restart —
and so it comes back **sealed**. Until it is unsealed, Concourse cannot resolve
`((vars))`.

Not only a reboot. It seals on any recreate of the container, which on this host
is the more common event: Docker Desktop recreates containers when the engine or
WSL restarts under a session that stays logged in. The tell in `docker inspect`
is `ExitCode 0` + `RestartCount 0` + a fresh `StartedAt` — a recreate, not a
crash.

The failure mode is worth recognising: jobs do **not** hang. They fail with a
credential-resolution error naming the variable. After a reboot, that error means
"run vault-unseal", not "the pipeline is broken".

### It now runs itself, and a seal now shows up

Two things, installed once, from #60474:

```powershell
.\Install-VaultUnsealTask.ps1        # -IntervalMinutes 5 by default
```

- **The Scheduled Task** runs `vault-unseal.ps1` at logon and every five minutes
  thereafter. The repeating trigger is the one that matters: a recreate is not a
  boot, so a start-only trigger would have missed every occurrence so far.
  `vault-unseal.ps1` is idempotent — already unsealed, or no container running,
  both exit 0 immediately — so re-checking costs one `docker inspect` and one
  `vault status`. It appends one line per run to `vault-unseal.log` beside the
  script, which is gitignored and contains no key material.
- **The compose healthcheck** reports a sealed Vault **unhealthy**, within about
  2.5 minutes. It used to pass `sealedcode=200&uninitcode=200`, which instructs
  Vault to answer HTTP 200 in exactly the states where it can serve nothing. On
  2026-09-19 it sealed at a recreate and `docker inspect` said `health=healthy`,
  `failingStreak=0` for **four days**, while 20 of keel's 26 jobs errored in
  three seconds each and `thehub` and `personal-soc` resolved nothing either.

The order was deliberate: the probe first, the automation second. Automating the
unseal alone would have removed the likeliest trigger while leaving the
instrument lying — and the next failure that was not sealing would still have
read healthy.

## The unseal key and root token

`vault/init.json` — gitignored, and the ignore rule was added *before* the file
was created.

**Put a copy in a password manager.** There is no recovery path by design: lose
this file and every secret in the store is unrecoverable.

One key share, threshold one. Splitting the seal across five shares only protects
you if five different *people* hold them; here every share would live in the same
file on the same disk, so shares would be ceremony impersonating a control.

## What this setup is not

- **No TLS.** The listener is reachable only from the `concourse` compose network
  and from `127.0.0.1`. The plaintext hop is container-to-container inside one
  machine. This stops being defensible the moment Vault is reachable off-box —
  including through the Cloudflare tunnel that fronts Concourse. Terminate TLS in
  front of it, or enable it here, before that happens.
- **No Vault auto-unseal.** Vault's own auto-unseal means a transit seal or a
  cloud KMS holding the key — a second trust root this host does not have, and
  that is still true. What #60474 added is not that: it is *automated invocation
  of the manual unseal*, using the key that already sits in `vault/init.json` on
  this disk. It adds no exposure that does not already exist — the file is the
  exposure, and it predates the decision. What it removes is the requirement
  that a human be watching. The seal is still a real seal; nobody is holding the
  key but this machine.
- **Root token on disk.** Acceptable for a single-operator host, and the reason
  Concourse gets its own scoped token instead. For anything shared, use AppRole
  and stop writing the root token down.

## Rollback

```powershell
docker compose stop vault
Copy-Item docker-compose.yml.bak-preVault docker-compose.yml -Force
docker compose up -d --force-recreate concourse
```

Then put the secrets back in a `-l` vars file. The `vault-data` volume is left
alone by that, so re-enabling later loses nothing.
