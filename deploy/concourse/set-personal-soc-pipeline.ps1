<#
.SYNOPSIS
    Apply the personal-soc pipeline, running that repo's PowerShell helpers here.

.DESCRIPTION
    personal-soc is public, so there is no installation token to mint and
    nothing in this pipeline expires - unlike set-thehub-pipeline.ps1, which
    has to be re-run every hour. The only credential read is the local
    Concourse login from .env.

    Two variables are supplied rather than hard-coded in the pipeline: the
    LAN range the network scan is pointed at, and the timezone the weekly
    trigger fires in. Both are facts about this house rather than about the
    pipeline, and the default for each matches this host.

.NOTES
    ASCII only - see setup.ps1 for why.

    The weekly-network-scan job is expected to fail on the Linux worker: the
    script it runs enumerates hosts through Windows-only cmdlets. The job
    reports that rather than publishing an empty scan. Use -PauseNetworkScan
    to apply the pipeline without it reporting weekly, or read the comments
    on that job in pipelines/personal-soc.yml for the two real fixes.
#>

[CmdletBinding()]
param(
    [string]$Target = "mykronos",
    [string]$Pipeline = "personal-soc",
    [string]$Concourse = "http://localhost:8080",
    [string]$LanCidr = "192.168.0.0/24",
    [string]$TimeZone = "America/Phoenix",
    [switch]$PauseNetworkScan,
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
        "lan-cidr: $LanCidr",
        "scan-timezone: $TimeZone"
    ) | Set-Content -Path $varsFile -Encoding UTF8

    Write-Host "Applying the pipeline..." -ForegroundColor Cyan
    & $fly --target $Target set-pipeline --pipeline $Pipeline `
        --config (Join-Path $PSScriptRoot "pipelines\personal-soc.yml") `
        --load-vars-from $varsFile --non-interactive
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

if ($PauseNetworkScan) {
    & $fly --target $Target pause-job --job "$Pipeline/weekly-network-scan"
    Write-Host "weekly-network-scan is paused - it cannot enumerate hosts from a Linux worker." -ForegroundColor Yellow
}

Write-Host "  Scanning $LanCidr, weekly trigger in $TimeZone"
Write-Host "  $Concourse/teams/main/pipelines/$Pipeline"
