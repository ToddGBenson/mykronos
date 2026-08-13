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
$varsFile = Join-Path ([System.IO.Path]::GetTempPath()) "personal-soc-vars-$(Get-Random).yml"
try {
    @(
        "scan-timezone: $TimeZone",
        # Host IP, not a Docker name: garden task containers resolve through
        # the public servers set in compose and have never heard of `minio`.
        # Same reasoning, and the same address, as set-pipeline.ps1.
        "minio-endpoint: http://192.168.0.14:9000",
        "minio-access-key: $(Read-EnvValue $stackEnv 'MINIO_ROOT_USER')",
        "minio-secret-key: $(Read-EnvValue $stackEnv 'MINIO_ROOT_PASSWORD')",
        "netassess-bucket: $NetassessBucket",
        "netassess-max-age-days: $MaxScanAgeDays",
        "monitor-bucket: $MonitorBucket",
        # Both may be empty; breach-check is the only job that reads them and
        # it fails with an explanation rather than a stack trace when they are.
        # Quoted because an address list is a plain scalar full of punctuation
        # and an empty value must parse as a string, not as YAML null.
        "hibp-api-key: '$(Read-EnvValueOptional $stackEnv 'HIBP_API_KEY')'",
        "monitor-emails: '$(Read-EnvValueOptional $stackEnv 'MONITOR_EMAILS')'"
    ) | Set-Content -Path $varsFile -Encoding UTF8

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

Write-Host "  Weekly triggers in $TimeZone; scans read from '$NetassessBucket', stale after $MaxScanAgeDays days"
Write-Host "  $Concourse/teams/main/pipelines/$Pipeline"
