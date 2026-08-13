<#
.SYNOPSIS
    Apply the TheHub security pipeline, scanning a branch without Actions minutes.

.DESCRIPTION
    TheHub is private and out of GitHub Actions allowance, so its workflows
    fail instantly with no logs. This runs the same scanners in Concourse and
    reports into Mykronos through the same Ingestion API.

    The git credential is a GitHub App installation token minted fresh by
    `mykronos github-token`. It lasts an hour: long enough to scan a branch,
    not long enough for a pipeline left running. Re-run this to refresh it.
    That limitation is CNC-2's problem to solve properly.

.NOTES
    ASCII only - see setup.ps1.
#>

[CmdletBinding()]
param(
    [string]$Target = "mykronos",
    [string]$Pipeline = "thehub",
    [string]$Branch = "develop",
    [string]$Concourse = "http://localhost:8080"
)

$ErrorActionPreference = "Stop"
$fly = Join-Path $PSScriptRoot "bin\fly.exe"
$backend = Join-Path $PSScriptRoot "..\..\backend"

function Read-EnvValue {
    param([string]$Path, [string]$Key)
    $line = Select-String -Path $Path -Pattern "^$Key=" -ErrorAction SilentlyContinue
    if (-not $line) { throw "$Key is not set in $Path" }
    return $line.Line.Split('=', 2)[1].Trim()
}

$stackEnv = Join-Path $PSScriptRoot ".env"
$backendEnv = Join-Path $backend ".env"

Write-Host "Minting a GitHub App installation token (valid one hour)..." -ForegroundColor Cyan
Push-Location $backend
try {
    $ghToken = (& ".\.venv\Scripts\python.exe" -m mykronos.cli github-token ToddGBenson/TheHub 2>$null | Select-Object -Last 1).Trim()
} finally {
    Pop-Location
}
if (-not $ghToken -or -not $ghToken.StartsWith("ghs_")) {
    throw "Did not get an installation token. Is the GitHub App configured in backend/.env?"
}

& $fly --target $Target login --concourse-url $Concourse `
    --username (Read-EnvValue $stackEnv "CONCOURSE_LOCAL_USER") `
    --password (Read-EnvValue $stackEnv "CONCOURSE_LOCAL_PASSWORD") `
    --team-name main | Out-Null
if ($LASTEXITCODE -ne 0) { throw "fly login failed" }

$varsFile = Join-Path ([System.IO.Path]::GetTempPath()) "thehub-vars-$(Get-Random).yml"
try {
    @(
        "mykronos-url: http://192.168.0.14:8100",
        "mykronos-ref: v1",
        "thehub-branch: $Branch",
        "github-token: $ghToken",
        "thehub-ingestion-token: $(Read-EnvValue $backendEnv 'MYKRONOS_THEHUB_CONCOURSE_TOKEN')"
    ) | Set-Content -Path $varsFile -Encoding UTF8

    & $fly --target $Target set-pipeline --pipeline $Pipeline `
        --config (Join-Path $PSScriptRoot "pipelines\thehub.yml") `
        --load-vars-from $varsFile --non-interactive
    if ($LASTEXITCODE -ne 0) { throw "fly set-pipeline failed" }
} finally {
    if (Test-Path $varsFile) { Remove-Item $varsFile -Force }
}

& $fly --target $Target unpause-pipeline --pipeline $Pipeline
Write-Host "`nScanning branch '$Branch'." -ForegroundColor Green
Write-Host "  $Concourse/teams/main/pipelines/$Pipeline"
