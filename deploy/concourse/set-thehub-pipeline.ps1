<#
.SYNOPSIS
    Apply TheHub delivery pipeline: scan, gate, demo, DAST, and prod on a click.

.DESCRIPTION
    Spec 16. This was a scanning-only pipeline and is now the whole path to
    production, so it needs materially more than the three variables it used
    to: two deploy keys, a pinned host key, the two environment URLs, and the
    Azure service principal the cloud-posture job authenticates with.

    Where each value comes from:

      backend\.env              the ingestion token and the Oracle gate token
      deploy\concourse\.env     the Concourse login and the Azure principal
      deploy\concourse\keys\    the two deploy keys and the pinned host key

    All three are gitignored. Nothing this script writes survives it: the vars
    file is created in the temp directory and deleted in a finally block, which
    is the existing pattern across the three set-pipeline scripts and is kept
    deliberately so there is one way to do this rather than three.

    The git credential is a GitHub App installation token minted fresh by
    `mykronos github-token`. It lasts an hour: long enough to scan a branch,
    not long enough for a pipeline left running. Re-run this to refresh it.
    That limitation is CNC-2's problem to solve properly.

    Run Install-DeployKey.ps1 (in deploy\thehub) once per environment before
    this. Without the keys the deploy jobs cannot authenticate, and this script
    refuses to apply a pipeline whose deploy half is guaranteed to fail.

.PARAMETER AllowMissingAzure
    Apply the pipeline without an Azure service principal. The delivery jobs
    all work and cloud-posture is paused, because a job that cannot run should
    be visibly off rather than red every morning. That is the right failure
    isolation - a missing backup-subscription credential should not block
    deploying TheHub - and it stays opt-in, because the quiet version of this
    is a cloud scan nobody notices never ran.

.NOTES
    ASCII only - see setup.ps1.
#>

[CmdletBinding()]
param(
    [string]$Target = "mykronos",
    [string]$Pipeline = "thehub",
    # main, not develop: the delivery flow is PR -> merge to main -> this
    # pipeline runs. develop is TheHub's direct-push integration branch, and
    # watching it made every working commit race the local deploy.sh path -
    # the dual-trigger confusion SDLC-7 #49216 flagged. Operator directive
    # 2026-08-18.
    #
    # This lived only in the deployment checkout's working tree until now,
    # which meant the repository said `develop` while the applied pipeline
    # watched `main`, and nothing anywhere reconciled the two. Pass
    # `-Branch develop` explicitly for a one-off scan of the integration
    # branch.
    [string]$Branch = "main",
    # On by default again (D-083). It was "false" from 2026-08-18 because the
    # gate blocked on the composite score and so refused every commit; it now
    # blocks on what a commit introduced, which does not drift as the backlog
    # grows. Pass "false" for a deliberate, loudly-announced override.
    [ValidateSet("true", "false")]
    [string]$OracleBlocking = "true",
    [string]$Concourse = "http://localhost:8080",

    # The host both environments run on, reached by IP for the same reason
    # every other address in these pipelines is: garden task containers resolve
    # through public DNS and have never heard of `host.docker.internal`.
    # 8002, not 8200: docker-compose.demo.yml publishes "8002:8000" and that is
    # what thehub-demo-backend is bound to. The host IP rather than localhost
    # because a garden task container's localhost is its own, not this machine's.
    [string]$DemoUrl = "http://192.168.0.14:8002",
    [string]$ProdUrl = "http://192.168.0.14:8000",
    [string]$ReleaseBucket = "thehub-releases",

    # TheHub's own API, for reporting pipeline stages into its DevSecOps and
    # story-lifecycle processes. The prod backend, by host IP for the same
    # reason as everything else here: a garden task container's localhost is
    # its own.
    [string]$TheHubUrl = "http://192.168.0.14:8000",
    # TheHub's .env, which holds OPS_DEPLOY_TOKEN - the shared secret its
    # scripts/deploy.sh already presents to the same endpoint. Read rather
    # than duplicated, so rotating it there rotates it here.
    [string]$TheHubEnvPath = "C:\Users\tgb_\Documents\Projects\TheHub-main\.env",
    # How long a deploy job waits for the host to report the SHA back. Long
    # enough for an image pull and a container restart on a busy host; short
    # enough that a poller which is not running is a failed build rather than
    # an hour of a worker doing nothing.
    #
    # 15 was set when a deploy was a pull and a restart. Demo is now rebuilt
    # from empty volumes on every run, and the budget has to cover the whole
    # chain, not just the part Concourse can see:
    #
    #   up to 5 min   the agent's poll interval before it notices the request
    #   ~1 min        wipe and recreate the stack
    #   ~7-9 min      init_db, 273 migrations, four workers, first health
    #   ~1-2 min      seed_demo.py
    #   ---------
    #   up to ~17 min, against a 15 minute budget
    #
    # So the job failed intermittently while the deploy underneath it was
    # succeeding -- the worst kind of red, because the thing it names is fine
    # and the thing at fault is a number nobody looks at. The agent's poll
    # interval is separately cut to 1 minute; this is the headroom over what
    # remains.
    [int]$DeployTimeoutMinutes = 25,

    [string]$Registry = "192.168.0.14:5000",
    [string]$ProwlerVersion = "5.5.0",
    [string]$TimeZone = "America/Phoenix",

    [switch]$AllowMissingAzure,
    [switch]$Pause
)

$ErrorActionPreference = "Stop"
$fly = Join-Path $PSScriptRoot "bin\fly.exe"
$backend = Join-Path $PSScriptRoot "..\..\backend"

function Read-EnvValue {
    param([string]$Path, [string]$Key, [switch]$Optional)
    $line = Select-String -Path $Path -Pattern "^$Key=" -ErrorAction SilentlyContinue
    if (-not $line) {
        if ($Optional) { return "" }
        throw "$Key is not set in $Path"
    }
    return $line.Line.Split('=', 2)[1].Trim()
}

$stackEnv = Join-Path $PSScriptRoot ".env"
$backendEnv = Join-Path $backend ".env"
foreach ($file in @($stackEnv, $backendEnv)) {
    if (-not (Test-Path $file)) { throw "Missing $file" }
}

# No deploy keys are read any more, and no host key is pinned, because nothing
# here connects to the deploy host. The deploy jobs write a SHA to MinIO and
# the host pulls it - see the header of pipelines/thehub.yml. What used to be
# checked here is now a fact about the *host*: whether the Scheduled Task that
# polls for the pointer is running. This script cannot see that, so the deploy
# job reports it instead, by timing out with the task's name in the message.

# Optional, and deliberately so: see -AllowMissingAzure.
$azureClientId = Read-EnvValue $stackEnv "AZURE_CLIENT_ID" -Optional
$azureClientSecret = Read-EnvValue $stackEnv "AZURE_CLIENT_SECRET" -Optional
$azureTenantId = Read-EnvValue $stackEnv "AZURE_TENANT_ID" -Optional
$azureSubscriptionId = Read-EnvValue $stackEnv "AZURE_SUBSCRIPTION_ID" -Optional

if (-not $azureClientId -or -not $azureSubscriptionId) {
    if (-not $AllowMissingAzure) {
        throw "No Azure service principal in $stackEnv. Set AZURE_CLIENT_ID, " +
              "AZURE_CLIENT_SECRET, AZURE_TENANT_ID and AZURE_SUBSCRIPTION_ID, " +
              "or pass -AllowMissingAzure to apply the pipeline with the " +
              "cloud-posture job left unable to run."
    }
    Write-Host "No Azure principal: cloud-posture will be paused below." -ForegroundColor Yellow
}

# Reporting into TheHub is optional. Absent, the report task says it is
# skipping and exits 0 - which is the right failure mode for telemetry, and
# the wrong one to discover silently, so it is announced here too.
$hubAnthropicKey = ""
if (Test-Path $TheHubEnvPath) {
    $hubAnthropicKey = Read-EnvValue $TheHubEnvPath "ANTHROPIC_API_KEY" -Optional
}
if (-not $hubAnthropicKey) {
    Write-Host "No Claude key: prompt evals will run the deterministic graders only." -ForegroundColor DarkGray
}

# Slack is a bot token plus a channel rather than an incoming webhook.
# TheHub's webhook is bound to the channel its app posts to, so borrowing it
# would interleave pipeline alerts with messages meant for people. A bot token
# names the channel explicitly - #alerts - and authenticates with a header.
#
# Neither value is read here any more, and that is the change: both now live
# in Vault at `concourse/main/slack-bot-token` and
# `concourse/main/slack-alert-channel`, which is team scope, so this pipeline
# and personal-soc resolve the same credential and neither config contains it.
#
# The header/URL distinction is exactly what made that possible. Vault
# substitutes a `((var))` wherever it appears, so a token in an
# `Authorization:` header moves cleanly; a webhook's secret sits in the URL
# path of the endpoint being called, so the pipeline would still have had to
# hold it. Switching to chat.postMessage was a prerequisite for this, not a
# separate tidy-up.
#
# Only presence is checked, so applying the pipeline still tells you whether
# alerts will work.
$slackReady = $false
try {
    $probe = docker exec -e VAULT_ADDR=http://127.0.0.1:8200 `
        -e "VAULT_TOKEN=$(Read-EnvValue $stackEnv 'CONCOURSE_VAULT_TOKEN')" `
        mykronos-vault vault read -format=json concourse/main/slack-bot-token 2>$null
    if ($LASTEXITCODE -eq 0 -and $probe) { $slackReady = $true }
} catch { }
if ($slackReady) {
    Write-Host "Slack alerts resolve from Vault (concourse/main/slack-bot-token)." -ForegroundColor DarkGray
} else {
    Write-Host "Slack credential not readable in Vault: every notifier will skip." -ForegroundColor Yellow
    Write-Host "  Is Vault sealed? .\vault-unseal.ps1" -ForegroundColor DarkGray
}

$hubDeployToken = ""
if (Test-Path $TheHubEnvPath) {
    $hubDeployToken = Read-EnvValue $TheHubEnvPath "OPS_DEPLOY_TOKEN" -Optional
}
if ($hubDeployToken) {
    Write-Host "Pipeline stages will report to TheHub at $TheHubUrl." -ForegroundColor DarkGray
} else {
    Write-Host "No OPS_DEPLOY_TOKEN found: TheHub's lifecycle will not hear about this pipeline." -ForegroundColor Yellow
}

Write-Host "Minting a GitHub App installation token (valid one hour)..." -ForegroundColor Cyan

# Two places this can be minted from, tried in that order, because the CLI
# needs the operational database and there is more than one copy of it.
#
# The host venv is tried first: that is how this has always worked, and on a
# machine where the backend runs locally it is the right answer.
#
# It stopped being the right answer here. The deployed backend keeps its
# database in a Docker *named volume* (`mykronos_mykronos-data`), so a host
# CLI run from this checkout opens an empty SQLite file, reports "TheHub is
# not onboarded", and this script threw -- pointing at backend/.env, which was
# not the problem. Meanwhile the pipeline was still being applied from a
# sibling checkout that happened to hold a populated database from 2026-08-19,
# which is why TheHub's `mykronos-ref` sat at v4.1 while every other pipeline
# moved to v5 and then v6: the two copies had quietly diverged and nothing
# compared them.
#
# The container is the database of record because it is the one serving
# traffic. Falling back to it makes this script work from any checkout and
# removes the dependency on a stale sibling nobody remembers is load-bearing.
$ghToken = ""
Push-Location $backend
try {
    if (Test-Path ".\.venv\Scripts\python.exe") {
        $ghToken = (& ".\.venv\Scripts\python.exe" -m mykronos.cli github-token ToddGBenson/TheHub 2>$null | Select-Object -Last 1)
        if ($ghToken) { $ghToken = $ghToken.Trim() }
    }
} finally {
    Pop-Location
}

if (-not $ghToken -or -not $ghToken.StartsWith("ghs_")) {
    Write-Host "  host CLI has no onboarding for TheHub; asking the running backend." -ForegroundColor DarkGray
    $ghToken = (& docker exec mykronos-backend python -m mykronos.cli github-token ToddGBenson/TheHub 2>$null | Select-Object -Last 1)
    if ($ghToken) { $ghToken = $ghToken.Trim() }
}

if (-not $ghToken -or -not $ghToken.StartsWith("ghs_")) {
    throw "Did not get an installation token from the host CLI or from the " +
          "mykronos-backend container. Check the GitHub App in backend/.env, " +
          "and that TheHub is onboarded in whichever database you expect the " +
          "CLI to read."
}

& $fly --target $Target login --concourse-url $Concourse `
    --username (Read-EnvValue $stackEnv "CONCOURSE_LOCAL_USER") `
    --password (Read-EnvValue $stackEnv "CONCOURSE_LOCAL_PASSWORD") `
    --team-name main | Out-Null
if ($LASTEXITCODE -ne 0) { throw "fly login failed" }

# -- PS-9: a credential manager, not ((vars)) in a file (spec 15 section 6) --
#
# Concourse stores pipeline configuration verbatim, so every secret written to
# the vars file below is readable afterwards by anyone who can run
# `fly get-pipeline`. set-pipeline.ps1 has probed Vault per credential since
# 2026-08-20 and this script did not, so `fly get-pipeline -p thehub` returned
# live values for the ingestion token, the gate token, both MinIO keys and the
# deploy token - checked, and it did: zero unresolved references for all four.
#
# Each credential is probed first. Present means it is left out of the vars
# file entirely and Concourse resolves it at egress; absent means it falls back
# to the file and this script names it. Moving one is then a single
# Import-EnvSecretsToVault.ps1 run and a re-apply, with no edit here.
#
# github-token is deliberately NOT a candidate: it is a GitHub App installation
# token minted fresh on every run and dead in an hour (CNC-2). Putting a value
# with that lifetime in Vault would mean a stale secret resolving in place of a
# live one, which is worse than the config holding something already expiring.
$vaultToken = Read-EnvValue $stackEnv "CONCOURSE_VAULT_TOKEN" -Optional

function Test-VaultSecret {
    param([string]$Name, [string]$SecretScope = "pipeline")
    if (-not $vaultToken) { return $false }
    # `concourse/<team>/<pipeline>/<name>` then `concourse/<team>/<name>` is
    # Concourse's own lookup order, so probing the same two paths is the only
    # honest way to answer "will the ((var)) resolve".
    $paths = if ($SecretScope -eq "team") {
        @("concourse/main/$Name")
    } else {
        @("concourse/main/$Pipeline/$Name", "concourse/main/$Name")
    }
    foreach ($p in $paths) {
        # Only presence is read; the value never leaves the container.
        docker exec -e VAULT_ADDR=http://127.0.0.1:8200 -e "VAULT_TOKEN=$vaultToken" `
            mykronos-vault vault read -format=json $p 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) { return $true }
    }
    return $false
}

$fromVault = @()
$fromFile = @()
$secretVars = @()

function Add-Secret {
    param([string]$Name, [scriptblock]$Fallback, [string]$SecretScope = "pipeline")
    if (Test-VaultSecret -Name $Name -SecretScope $SecretScope) {
        $script:fromVault += $Name
        return
    }
    $script:fromFile += $Name
    $script:secretVars += ("{0}: '{1}'" -f $Name, (& $Fallback))
}

# The MinIO pair is team-scoped: all three pipelines use the same credential,
# and three copies of one secret is three things to rotate.
Add-Secret -Name "thehub-ingestion-token" -Fallback { Read-EnvValue $backendEnv 'MYKRONOS_THEHUB_CONCOURSE_TOKEN' }
Add-Secret -Name "mykronos-gate-token"    -Fallback { Read-EnvValue $backendEnv 'MYKRONOS_GATE_TOKEN' }
Add-Secret -Name "hub-deploy-token"       -Fallback { $hubDeployToken }
Add-Secret -Name "anthropic-api-key"      -Fallback { $hubAnthropicKey }
Add-Secret -Name "minio-access-key" -SecretScope team -Fallback { Read-EnvValue $stackEnv 'MINIO_ROOT_USER' }
Add-Secret -Name "minio-secret-key" -SecretScope team -Fallback { Read-EnvValue $stackEnv 'MINIO_ROOT_PASSWORD' }

if ($fromVault) {
    Write-Host "Resolving from Vault: $($fromVault -join ', ')" -ForegroundColor DarkGray
}
if ($fromFile) {
    Write-Host "NOT in Vault, so written into the pipeline config where" -ForegroundColor Yellow
    Write-Host "``fly get-pipeline`` can read them back: $($fromFile -join ', ')" -ForegroundColor Yellow
    Write-Host "  Move them:  .\Import-EnvSecretsToVault.ps1 -Pipeline $Pipeline" -ForegroundColor DarkGray
}

$varsFile = Join-Path ([System.IO.Path]::GetTempPath()) "thehub-vars-$(Get-Random).yml"
try {
    $vars = @(
        "mykronos-url: http://192.168.0.14:8100",
        # v4, cut for the pipeline standard (D-078), and the first bump made
        # *before* anything broke: pin-check named `mykronos.junit_stage` as
        # missing the moment the lanes started calling it. The two before it
        # were found by a human noticing a lane behaving oddly days later
        # (D-051 at 53 commits, D-074 at 61), which is what that check exists
        # to replace.
        #
        # Still a chosen commit rather than a floating tag: pinning is what
        # makes a scan reproducible, and the cost of pinning is remembering to
        # move it. v3 is untouched and stays where it is.
        #
        # `pin-check` in the mykronos pipeline is what remembers now — it
        # installs this exact ref and fails if the runner modules and CLI
        # flags the pipelines pass are not in it. When it fails, cut the next tag here.
        #
        # Held at v5 on 2026-08-25: v6 sends `cwe_ids` (spec 28 §1) and the
        # deployed backend forbids extra keys, so uploads 422'd. See the
        # longer note in set-pipeline.ps1. Still a move forward for TheHub,
        # which had been stranded on v4.1 by the stale-checkout problem this
        # script's token-minting comment describes.
        "mykronos-ref: v5",
        "thehub-branch: $Branch",
        # Whether Oracle's no_go stops the deploy.
        #
        # "false" since 2026-08-18, on the operator's explicit instruction. The
        # gate was blocking correctly on a real finding rather than
        # malfunctioning - score 100/100, 21 open critical findings - and
        # TheHub still needed to ship. Until now this was a commented-out
        # `exit 1` in the deployment checkout's working tree, so the repository
        # said the gate blocked while the applied pipeline let every no_go
        # through. A control that is switched off invisibly is worse than one
        # switched off loudly.
        #
        # Restored to "true" on 2026-08-20 (D-083). The condition written here
        # - "once the critical backlog is dispositioned" - was met: all 21 of
        # TheHub's open criticals were dispositioned, 16 as accepted risks
        # with no upstream fix and 5 as verified false positives.
        #
        # That alone would not have been enough, and is not why the gate is
        # back on. The score is still 100/no_go on 77 open highs, and would
        # have refused every commit exactly as before. What makes it safe to
        # enable is that the gate no longer decides on the score.
        #
        # The job announces the override on every blocked commit either way.
        "thehub-oracle-blocking: '$OracleBlocking'",
        "github-token: $ghToken",
        "registry: $Registry",
        "prowler-version: $ProwlerVersion",
        "scan-timezone: $TimeZone",
        "thehub-demo-url: $DemoUrl",
        "thehub-prod-url: $ProdUrl",
        "thehub-release-bucket: $ReleaseBucket",
        "deploy-timeout-minutes: $DeployTimeoutMinutes",
        # Where this pipeline reports its stages back to, so TheHub's own
        # DevSecOps and story-lifecycle processes advance on what Concourse
        # actually did rather than only on what its local deploy.sh did.
        # Same endpoint and same shared secret deploy.sh already uses, so
        # nothing in TheHub changes to receive it.
        #
        # Optional: with no token the report task prints that it is skipping
        # and exits 0. A lifecycle that did not hear about a deploy is a
        # reporting problem, and turning it into a failed deploy would be a
        # worse one.
        "thehub-url: $TheHubUrl",
        # Host IP, not a Docker name: garden task containers resolve through the
        # public servers set in compose and have never heard of `minio`. Same
        # address, and the same reason, as the other two set-pipeline scripts.
        "minio-endpoint: http://192.168.0.14:9000",
        "azure-client-id: $azureClientId",
        "azure-client-secret: $azureClientSecret",
        "azure-tenant-id: $azureTenantId",
        "azure-subscription-id: $azureSubscriptionId",
        # slack-bot-token and slack-alert-channel used to be written here. They
        # are not any more: both resolve through Vault at team scope, so the
        # value never enters this config and `fly get-pipeline` has nothing to
        # print. Every job's notifier still checks for empty and skips, so a
        # sealed Vault degrades to "no notification" rather than to a second
        # failure on top of the one it was trying to report.
        # Optional, and the prompt-eval gate is designed around its absence:
        # without a key the rubric fixtures report as skipped and the
        # deterministic graders still gate every commit, for free. Supplying
        # one turns the judged fixtures on and starts costing money per
        # changed prompt - which is why it is opt-in rather than assumed.
        #
        # Read from TheHub's own .env so there is one copy of the key on this
        # machine rather than two.
        "anthropic-api-key: '$hubAnthropicKey'"
    )

    $vars = $vars + $secretVars
    $vars | Set-Content -Path $varsFile -Encoding UTF8

    # Output discarded, and this is not tidiness. `fly set-pipeline` prints the
    # *resolved* configuration as a diff, with every `((var))` already
    # substituted - so an ordinary run of this script scrolls the ingestion
    # token, the gate token and any deploy key across the terminal, into the
    # scrollback, and into whatever is recording the session.
    #
    # Spec 15 section 6 and spec 16 section 11 both say no credential appears
    # in pipeline YAML or in build logs. Neither covered set-pipeline's own
    # output, which is the one place they were all visible at once.
    #
    # Errors still surface: fly writes those to stderr, and $LASTEXITCODE is
    # checked below either way. The real fix is a credential manager, so that
    # the config never contains a secret to print (spec 15 section 6) - this
    # closes the hole in the meantime.
    & $fly --target $Target set-pipeline --pipeline $Pipeline `
        --config (Join-Path $PSScriptRoot "pipelines\thehub.yml") `
        --load-vars-from $varsFile --non-interactive | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "fly set-pipeline failed" }
} finally {
    if (Test-Path $varsFile) { Remove-Item $varsFile -Force }
}

if ($Pause) {
    & $fly --target $Target pause-pipeline --pipeline $Pipeline
    Write-Host "`nPipeline applied and left paused." -ForegroundColor Yellow
} else {
    & $fly --target $Target unpause-pipeline --pipeline $Pipeline
}

# cloud-posture is paused when there is nothing for it to scan.
#
# It runs on a daily timer, and with no Azure principal it failed every night
# -- after spending thirteen minutes pulling the Prowler image to discover it
# had no credentials. A job that is red every morning for a reason nobody
# intends to fix this week is a job people learn to scroll past, which costs
# more than the scan it was not doing.
#
# Paused is the honest state: visibly off in the UI rather than visibly broken,
# and the same call personal-soc.yml makes for its network scan. Configure the
# principal in deploy\concourse\.env and re-run this; it unpauses itself.
if ($azureClientId -and $azureSubscriptionId) {
    & $fly --target $Target unpause-job --job "$Pipeline/cloud-posture" | Out-Null
    Write-Host "cloud-posture is enabled (Azure principal configured)." -ForegroundColor DarkGray
} else {
    & $fly --target $Target pause-job --job "$Pipeline/cloud-posture" | Out-Null
    Write-Host "cloud-posture paused: no Azure principal, so it has nothing to scan." -ForegroundColor Yellow
}

# functional-dast is paused until the scan has a resource budget it can live
# within (D-053). ZAP's active scan was measured at 548% CPU / 7 GiB on the
# host that also runs production; while it scanned, production timed out.
# Enforced here, not just by hand: a fly pause is state, and state that only
# an operator remembers gets undone by the next re-apply - which is exactly
# what happened on 2026-08-15, when a re-apply for a token rotation quietly
# rescheduled a queued DAST build. Remove this block when D-053 is closed.
& $fly --target $Target pause-job --job "$Pipeline/functional-dast" | Out-Null
Write-Host "functional-dast paused: D-053, no resource budget for the scan yet." -ForegroundColor Yellow

Write-Host "`nDelivering branch '$Branch'." -ForegroundColor Green
Write-Host "  demo: $DemoUrl (automatic, once Oracle clears it)"
Write-Host "  prod: $ProdUrl (waits for you to trigger deploy-prod)"
Write-Host "  $Concourse/teams/main/pipelines/$Pipeline"
