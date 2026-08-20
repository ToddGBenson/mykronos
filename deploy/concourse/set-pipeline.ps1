<#
.SYNOPSIS
    Log in to the local Concourse and apply the Mykronos pipeline.

.DESCRIPTION
    Reads credentials from .env (this stack) and from ../../backend/.env (the
    Mykronos ingestion and gate tokens), writes a vars file for the duration of
    the call, and deletes it afterwards. No secret is printed, and none is
    written anywhere git can see.

.NOTES
    ASCII only - see setup.ps1 for why.
#>

[CmdletBinding()]
param(
    [string]$Target = "mykronos",
    [string]$Pipeline = "mykronos",
    [string]$Concourse = "http://localhost:8080",
    [switch]$Pause
)

$ErrorActionPreference = "Stop"
$fly = Join-Path $PSScriptRoot "bin\fly.exe"
if (-not (Test-Path $fly)) {
    throw "fly is missing. Fetch it: curl -sSfL -o bin/fly.exe '$Concourse/api/v1/cli?arch=amd64&platform=windows'"
}

function Read-EnvValue {
    param([string]$Path, [string]$Key, [switch]$Optional)
    $line = Select-String -Path $Path -Pattern "^$Key=" -ErrorAction SilentlyContinue
    if (-not $line) {
        # Absent is a valid answer for a setting whose feature is off, and an
        # error for one the pipeline cannot run without. The caller says which.
        if ($Optional) { return "" }
        throw "$Key is not set in $Path"
    }
    return $line.Line.Split('=', 2)[1].Trim()
}

$stackEnv = Join-Path $PSScriptRoot ".env"
$backendEnv = Join-Path $PSScriptRoot "..\..\backend\.env"
foreach ($file in @($stackEnv, $backendEnv)) {
    if (-not (Test-Path $file)) { throw "Missing $file" }
}

# -- PS-9: a credential manager, not ((vars)) in a file (spec 15 section 6) --
#
# Concourse stores pipeline configuration verbatim, so every secret written to
# the vars file below is readable afterwards by anyone who can run
# `fly get-pipeline`. Vault has been wired into this Concourse since
# 2026-08-13 (CONCOURSE_VAULT_URL in docker-compose.yml) and thehub already
# resolves two credentials through it; this pipeline resolved none, so its
# ingestion token, its gate token and the MinIO keys were all in the config.
#
# Each credential is now probed in Vault first. Present means it is left out
# of the vars file entirely and Concourse resolves it at egress; absent means
# it falls back to the file and the script says so by name. That way moving a
# credential is one `vault-secret.ps1 set` and a re-apply, with no edit here
# and no window where the pipeline cannot be applied.
$vaultToken = Read-EnvValue $stackEnv "CONCOURSE_VAULT_TOKEN" -Optional
function Test-VaultSecret {
    param([string]$Name, [string]$Scope = "pipeline")
    if (-not $vaultToken) { return $false }
    # `concourse/<team>/<pipeline>/<name>` then `concourse/<team>/<name>` is
    # Concourse's own lookup order, so probing the same two paths is the only
    # honest way to answer "will the ((var)) resolve".
    $paths = if ($Scope -eq "team") {
        @("concourse/main/$Name")
    } else {
        @("concourse/main/$Pipeline/$Name", "concourse/main/$Name")
    }
    foreach ($path in $paths) {
        # Only presence is read. The value never leaves the container, never
        # reaches this process, and therefore never reaches the terminal.
        docker exec -e VAULT_ADDR=http://127.0.0.1:8200 -e "VAULT_TOKEN=$vaultToken" `
            mykronos-vault vault read -format=json $path 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) { return $true }
    }
    return $false
}

# name -> how to produce it if Vault does not have it. Every one of these is a
# secret; anything non-secret stays an ordinary line in the vars file below.
$fallbacks = [ordered]@{
    "mykronos-ingestion-token" = { Read-EnvValue $backendEnv "MYKRONOS_CONCOURSE_TOKEN" }
    "mykronos-gate-token"      = { Read-EnvValue $backendEnv "MYKRONOS_GATE_TOKEN" }
    "minio-access-key"         = { Read-EnvValue $stackEnv "MINIO_ROOT_USER" }
    "minio-secret-key"         = { Read-EnvValue $stackEnv "MINIO_ROOT_PASSWORD" }
}

$fromVault = @()
$fromFile = @()
$secretVars = @()
foreach ($name in $fallbacks.Keys) {
    if (Test-VaultSecret -Name $name) {
        $fromVault += $name
    } else {
        $fromFile += $name
        $secretVars += "${name}: $(& $fallbacks[$name])"
    }
}

if ($fromVault) {
    Write-Host "Resolving from Vault: $($fromVault -join ', ')" -ForegroundColor DarkGray
}
if ($fromFile) {
    Write-Host "NOT in Vault, so written into the pipeline config where" -ForegroundColor Yellow
    Write-Host "``fly get-pipeline`` can read them back: $($fromFile -join ', ')" -ForegroundColor Yellow
    Write-Host "  Move one:  .\vault-secret.ps1 set <name> -Scope pipeline -Pipeline $Pipeline" -ForegroundColor DarkGray
    Write-Host "  Sealed?    .\vault-unseal.ps1" -ForegroundColor DarkGray
}

# Slack is a bot token plus a channel at team scope, resolved from Vault the
# way thehub and personal-soc already resolve them - so this host has one
# Slack identity and no config contains its credential. The notifier checks
# for empty and skips, so a sealed Vault degrades to "no notification" rather
# than to a second failure on top of the one it was reporting.
if (Test-VaultSecret -Name "slack-bot-token" -Scope "team") {
    Write-Host "Slack alerts resolve from Vault (concourse/main/slack-bot-token)." -ForegroundColor DarkGray
} else {
    Write-Host "Slack credential not readable in Vault: every notifier will skip." -ForegroundColor Yellow
}

$user = Read-EnvValue $stackEnv "CONCOURSE_LOCAL_USER"
$password = Read-EnvValue $stackEnv "CONCOURSE_LOCAL_PASSWORD"

Write-Host "Logging in to $Concourse as $user..." -ForegroundColor Cyan
& $fly --target $Target login --concourse-url $Concourse `
    --username $user --password $password --team-name main | Out-Null
if ($LASTEXITCODE -ne 0) { throw "fly login failed" }

# The ingestion token is minted per repository by Mykronos and rotates on a
# 90-day cycle (spec 12 section 2). This reads whichever is current rather
# than keeping a second copy that would silently go stale.
$varsFile = Join-Path ([System.IO.Path]::GetTempPath()) "mykronos-pipeline-vars-$(Get-Random).yml"
try {
    @(
        # Host IP, not a Docker name: garden task containers resolve through
        # the public servers set in compose and have never heard of
        # `host.docker.internal` or `minio`. An IP needs no resolver.
        "mykronos-url: http://192.168.0.14:8100",
        # v3 cut deliberately, the second time this pin has gone stale in a
        # way that mattered (D-051 at 53 commits, D-074 at 61). Still a chosen
        # commit rather than a floating tag: pinning is what makes a scan
        # reproducible, and the cost of pinning is remembering to move it.
        #
        # `pin-check` in the mykronos pipeline is what remembers now — it
        # installs this exact ref and fails if the runner modules and CLI
        # flags the pipelines pass are not in it. When it fails, cut v4 here.
        "mykronos-ref: v3",
        # The branch the pipeline scans, which every upload now reports rather
        # than each one naming the default branch as a literal (PS-6). One
        # place to change if this pipeline is ever pointed somewhere else.
        "scanned-branch: main",
        # MinIO is on the compose network, so the task container reaches it by
        # service name rather than through the host.
        "minio-endpoint: http://192.168.0.14:9000",
        # Host IP for the same reason MinIO uses one: garden task containers
        # cannot resolve Docker service names.
        "registry: 192.168.0.14:5000",
        # The demo environment, rebuilt on the host by
        # deploy/demo/Invoke-DemoRebuild.ps1 because dockerd will not start
        # inside a task on this worker. Reached by host IP for the same
        # reason MinIO and the registry are: a garden task container cannot
        # resolve a Docker service name.
        "demo-host: 192.168.0.14"
        # slack-webhook-url used to be written here. It is not any more: the
        # notifier posts through chat.postMessage with a bot token in an
        # Authorization header, which Vault can substitute, where a webhook's
        # secret sits in the URL path and cannot be (PS-9). Both values resolve
        # at team scope, shared with thehub and personal-soc.
        #
        # Concourse alerts on jobs that failed before they could report; the
        # alerting that matters -- Oracle refusing a commit, a scan recorded as
        # failed, a batch of criticals -- comes from Mykronos itself, which is
        # the only place that can see it whichever CI produced it (spec 16 §14).
    ) + $secretVars | Set-Content -Path $varsFile -Encoding UTF8

    Write-Host "Applying the pipeline..." -ForegroundColor Cyan
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
        --config (Join-Path $PSScriptRoot "pipelines\mykronos.yml") `
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
    Write-Host "`nPipeline applied and unpaused." -ForegroundColor Green
}

# demo-and-dast is paused until the scan has a resource budget it can live
# within (D-053). Enforced here rather than by a fly pause an operator has to
# remember: a re-apply on 2026-08-15 quietly rescheduled a queued DAST build
# in TheHub's pipeline the same way. Remove this block when D-053 is closed.
& $fly --target $Target pause-job --job "$Pipeline/demo-and-dast" | Out-Null
Write-Host "demo-and-dast paused: D-053, no resource budget for the scan yet." -ForegroundColor Yellow

Write-Host "  $Concourse/teams/main/pipelines/$Pipeline"
