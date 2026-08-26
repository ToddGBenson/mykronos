<#
.SYNOPSIS
    Apply the personal-soc pipeline, running that repo's PowerShell helpers here.

.DESCRIPTION
    personal-soc is public, so there is no installation token to mint and
    nothing in this pipeline expires - unlike set-thehub-pipeline.ps1, which
    has to be re-run every hour. The only credential read is the local
    Concourse login from .env.

    The variables supplied are facts about this house rather than about the
    pipeline - the timezone the weekly triggers fire in, the MinIO bucket the
    Windows scan publishes into, and how stale a scan may get before that is
    itself a finding. The default for each matches this host.

.NOTES
    ASCII only - see setup.ps1 for why.

    This pipeline does not scan the network. Invoke-WeeklyNetworkScan needs
    the Windows ARP table and netsh, and a Concourse task on the Linux worker
    has neither - an nmap sweep from there reports all 256 addresses of the
    /24 as up. The scan stays in its Scheduled Task; publish-netassess-run.ps1
    hands the result to MinIO, and netassess-ingest is what judges it.

    So -LanCidr is gone: nothing here scans a CIDR any more.
#>

[CmdletBinding()]
param(
    [string]$Target = "mykronos",
    [string]$Pipeline = "personal-soc",
    [string]$Concourse = "http://localhost:8080",
    [string]$TimeZone = "America/Phoenix",
    [string]$NetassessBucket = "netassess-runs",
    [string]$MonitorBucket = "personal-monitor-runs",
    [string]$SkillsBucket = "personal-soc-releases",
    # Five, not the fifteen TheHub allows: this unpacks a zip rather than
    # pulling an image and restarting a stack, and the installer polls every
    # five minutes, so a run that has not landed inside this window is a
    # poller that is not running rather than one that is being slow.
    [int]$SkillsInstallTimeoutMinutes = 8,
    # Ten, not seven: a weekly scan that slips a day or reboots mid-window is
    # not a dead one, and a check that cries wolf on the normal case is a
    # check that gets muted.
    [int]$MaxScanAgeDays = 10,
    [switch]$Pause
)

$ErrorActionPreference = "Stop"
$fly = Join-Path $PSScriptRoot "bin\fly.exe"
if (-not (Test-Path $fly)) {
    throw "fly is missing. Fetch it: curl -sSfL -o bin/fly.exe '$Concourse/api/v1/cli?arch=amd64&platform=windows'"
}

function Read-EnvValue {
    param([string]$Path, [string]$Key)
    $line = Select-String -Path $Path -Pattern "^$Key=" -ErrorAction SilentlyContinue
    if (-not $line) { throw "$Key is not set in $Path" }
    return $line.Line.Split('=', 2)[1].Trim()
}

# Absent is allowed, and the pipeline says so at build time rather than here.
# Throwing would mean nobody can apply the pipeline until they have bought a
# HIBP key - which would block the four jobs that do not need one.
function Read-EnvValueOptional {
    param([string]$Path, [string]$Key)
    $line = Select-String -Path $Path -Pattern "^$Key=" -ErrorAction SilentlyContinue
    if (-not $line) { return "" }
    return $line.Line.Split('=', 2)[1].Trim()
}

$stackEnv = Join-Path $PSScriptRoot ".env"
if (-not (Test-Path $stackEnv)) { throw "Missing $stackEnv" }

$user = Read-EnvValue $stackEnv "CONCOURSE_LOCAL_USER"
$password = Read-EnvValue $stackEnv "CONCOURSE_LOCAL_PASSWORD"

Write-Host "Logging in to $Concourse as $user..." -ForegroundColor Cyan
& $fly --target $Target login --concourse-url $Concourse `
    --username $user --password $password --team-name main | Out-Null
if ($LASTEXITCODE -ne 0) { throw "fly login failed" }

# Written to a temp file and deleted afterwards, matching the other two
# set-pipeline scripts. Neither value here is secret; the shape is kept the
# same so there is one way to do this rather than two.
# -- PS-9: a credential manager, not ((vars)) in a file (spec 15 section 6) --
#
# Concourse stores pipeline configuration verbatim, so a secret written to the
# vars file below is readable afterwards by anyone who can run
# `fly get-pipeline`. This pipeline holds only the MinIO pair, and they are
# team-scoped in Vault because all three pipelines use the same credential -
# three copies of one secret is three things to rotate.
$vaultToken = Read-EnvValue $stackEnv "CONCOURSE_VAULT_TOKEN" -Optional

function Test-VaultSecret {
    param([string]$Name, [string]$SecretScope = "pipeline")
    if (-not $vaultToken) { return $false }
    # Concourse's own lookup order: pipeline scope, then team scope.
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

Add-Secret -Name "minio-access-key" -SecretScope team -Fallback { Read-EnvValue $stackEnv 'MINIO_ROOT_USER' }
Add-Secret -Name "minio-secret-key" -SecretScope team -Fallback { Read-EnvValue $stackEnv 'MINIO_ROOT_PASSWORD' }

if ($fromVault) {
    Write-Host "Resolving from Vault: $($fromVault -join ', ')" -ForegroundColor DarkGray
}
if ($fromFile) {
    Write-Host "NOT in Vault, so written into the pipeline config where" -ForegroundColor Yellow
    Write-Host "``fly get-pipeline`` can read them back: $($fromFile -join ', ')" -ForegroundColor Yellow
}

$varsFile = Join-Path ([System.IO.Path]::GetTempPath()) "personal-soc-vars-$(Get-Random).yml"
try {
    @(
        "scan-timezone: $TimeZone",
        # Host IP, not a Docker name: garden task containers resolve through
        # the public servers set in compose and have never heard of `minio`.
        # Same reasoning, and the same address, as set-pipeline.ps1.
        "minio-endpoint: http://192.168.0.14:9000",
        "netassess-bucket: $NetassessBucket",
        "netassess-max-age-days: $MaxScanAgeDays",
        "monitor-bucket: $MonitorBucket",
        "skills-release-bucket: $SkillsBucket",
        "skills-install-timeout-minutes: $SkillsInstallTimeoutMinutes",
        # Both may be empty; breach-check is the only job that reads them and
        # it fails with an explanation rather than a stack trace when they are.
        # Quoted because an address list is a plain scalar full of punctuation
        # and an empty value must parse as a string, not as YAML null.
        "hibp-api-key: '$(Read-EnvValueOptional $stackEnv 'HIBP_API_KEY')'",
        "monitor-emails: '$(Read-EnvValueOptional $stackEnv 'MONITOR_EMAILS')'",

        # Reporting. Same host address as the MinIO endpoint above and for the
        # same reason: a garden task container has never heard of `mykronos`.
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
        # longer note in set-pipeline.ps1. Move to v6 once the backend
        # serving `/api/ingest` accepts the field.
        "mykronos-ref: v5",
        # personal-soc is granted exactly one capability - secrets - so the
        # secrets job is the only lane with anywhere to report. Empty is
        # allowed: the scan still runs and still gates, and says loudly in the
        # build log that nothing was filed. Mint one with
        # `mykronos rotate-token ToddGBenson/personal-soc`.
        "personal-soc-ingestion-token: '$(Read-EnvValueOptional $stackEnv 'PERSONAL_SOC_INGESTION_TOKEN')'",
        # Optional. Without it skill-integrity inventories the model IDs it
        # finds and states plainly that it validated none of them.
        "anthropic-api-key: '$(Read-EnvValueOptional $stackEnv 'ANTHROPIC_API_KEY')'"

        # slack-bot-token and slack-alert-channel are deliberately NOT here.
        # They resolve through the Vault credential manager at team scope
        # (`concourse/main/<name>`), which is the difference between a pipeline
        # that *references* a secret and one that *contains* it - `fly
        # get-pipeline` prints this config back to anyone on the team, and
        # everything written to $varsFile ends up in it.
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
        --config (Join-Path $PSScriptRoot "pipelines\personal-soc.yml") `
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

# breach-check is paused when there is no key for it to check with.
#
# Same call set-thehub-pipeline.ps1 makes for cloud-posture without an Azure
# principal, and the same lesson L0001 recorded for the osv lane: a job that is
# red forever for a reason nobody intends to fix this week is a job people
# learn to scroll past, which costs more than the check it was not doing. The
# in-job error message stays -- it is what greets whoever unpauses it early --
# but the resting state is visibly off, not visibly broken.
#
# Put HIBP_API_KEY (and MONITOR_EMAILS) in deploy\concourse\.env and re-run
# this; it unpauses itself.
$hibpKey = Read-EnvValueOptional $stackEnv 'HIBP_API_KEY'
if ($hibpKey) {
    & $fly --target $Target unpause-job --job "$Pipeline/breach-check" | Out-Null
    Write-Host "breach-check is enabled (HIBP key configured)." -ForegroundColor DarkGray
} else {
    & $fly --target $Target pause-job --job "$Pipeline/breach-check" | Out-Null
    Write-Host "breach-check paused: no HIBP API key (~`$4/mo, haveibeenpwned.com/API/Key)." -ForegroundColor Yellow
}

Write-Host "  Weekly triggers in $TimeZone; scans read from '$NetassessBucket', stale after $MaxScanAgeDays days"
Write-Host "  $Concourse/teams/main/pipelines/$Pipeline"
