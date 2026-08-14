<#
.SYNOPSIS
    Destroy and rebuild the demo environment from IaC, then seed it.

.DESCRIPTION
    The host half of PIP-4. It runs here rather than inside a Concourse task
    because dockerd will not start in a task on this worker - the same
    constraint that moved image builds to kaniko. A design that stood the
    environment up in-task failed twice before this replaced it.

    Rebuild, never restart. `down -v` first, every time: an active scan
    submits forms and creates records, so a scan of an environment the last
    scan modified is a scan of the wreckage rather than of the application.
    State is tmpfs, so nothing survives the teardown even by accident - the
    `down -v` is belt and braces.

    Nothing about this script can reach production. It composes a separate
    project name, publishes different ports, and the images it runs hold
    synthetic data, no GitHub App key and no production credential.

.NOTES
    ASCII only - see deploy/concourse/setup.ps1.
#>

[CmdletBinding()]
param(
    [string]$Registry = "localhost:5000",
    [switch]$SkipSeed,
    [switch]$Down
)

$ErrorActionPreference = "Stop"

# PowerShell 7.4 turns a native command's stderr into a terminating error when
# $ErrorActionPreference is Stop. `docker compose pull` writes its progress to
# stderr, so the script died on a successful pull. Exit codes are checked
# explicitly below, which is the honest signal from a native command anyway.
$PSNativeCommandUseErrorActionPreference = $false

$here = $PSScriptRoot
$compose = Join-Path $here "docker-compose.yml"

$env:MYKRONOS_IMAGE_BACKEND = "$Registry/mykronos-backend:latest"
$env:MYKRONOS_IMAGE_FRONTEND = "$Registry/mykronos-frontend:latest"

function Invoke-Compose {
    param([string[]]$Arguments)
    & docker compose -f $compose @Arguments
}

Write-Host "Tearing down any previous demo environment..." -ForegroundColor Cyan
Invoke-Compose @("down", "-v", "--remove-orphans") 2>&1 | Out-Null

if ($Down) {
    Write-Host "Demo environment removed." -ForegroundColor Green
    return
}

Write-Host "Pulling the published images..." -ForegroundColor Cyan
Invoke-Compose @("pull", "--quiet") 2>&1 | Out-Null

Write-Host "Building the demo environment from IaC..." -ForegroundColor Cyan
Invoke-Compose @("up", "-d")
if ($LASTEXITCODE -ne 0) { throw "docker compose up failed" }

# Healthy, not merely started. A functional suite that races the application
# reports the race rather than the application.
Write-Host "Waiting for health..." -ForegroundColor Cyan
$deadline = (Get-Date).AddMinutes(5)
do {
    Start-Sleep -Seconds 5
    $states = @("backend", "frontend", "zap") | ForEach-Object {
        docker inspect -f '{{.State.Health.Status}}' "mykronos-demo-$_-1" 2>$null
    }
    Write-Host "  $($states -join ' ')"
    $healthy = @($states | Where-Object { $_ -eq "healthy" }).Count
} while (((Get-Date) -lt $deadline) -and ($healthy -lt 3))

if ($healthy -lt 3) {
    Invoke-Compose @("logs", "--tail", "40")
    throw "The demo environment never became healthy."
}

if ($SkipSeed) {
    Write-Host "Skipping the seed." -ForegroundColor Yellow
    return
}

# Seeded through the container rather than over the published port, because
# minting an ingestion token has no HTTP route - a token is shown once and
# only its hash is stored (spec 12 section 2), so the seeder has to run where
# the database is.
Write-Host "Seeding (PIP-5)..." -ForegroundColor Cyan
$backend = (Invoke-Compose @("ps", "-q", "backend"))
docker cp (Join-Path $here "seed.py") "${backend}:/tmp/seed.py"
docker exec $backend python /tmp/seed.py --url http://localhost:8100
if ($LASTEXITCODE -ne 0) { throw "Seeding failed; the environment is up but empty." }

Write-Host ""
Write-Host "Demo environment ready." -ForegroundColor Green
Write-Host "  dashboard : http://localhost:3200"
Write-Host "  api       : http://localhost:8201"
Write-Host "  zap proxy : http://localhost:8290"
