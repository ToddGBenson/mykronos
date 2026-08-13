<#
.SYNOPSIS
    Pull the images the pipeline published and bring the Mykronos stack up.

.DESCRIPTION
    The host half of the deploy (spec 15 §3, D-038). Concourse builds images
    and pushes them to the registry; this pulls and restarts. Nothing in the
    pipeline can run this, deliberately: a Concourse task with the host's
    Docker socket could restart anything on this machine, which is the risk
    §7 raises about a worker sitting inside the LAN. A registry is a one-way
    handoff.

    Pulls from localhost:5000 rather than the host IP the pipeline pushes to.
    Docker treats localhost as an insecure registry by default, so no daemon
    configuration is needed here.

.PARAMETER MigrateFrom
    Copy an existing lake and operational database into the volume before
    starting. Do this once, on the first cutover from host processes: without
    it the containers start on an empty volume and every finding, decision
    and archived scan stays behind on the host.

.NOTES
    ASCII only - see deploy/concourse/setup.ps1.
#>

[CmdletBinding()]
param(
    [string]$Registry = "localhost:5000",
    [string]$MigrateFrom,
    [switch]$NoStart
)

$ErrorActionPreference = "Stop"
$here = $PSScriptRoot
$backendEnv = Join-Path $here "..\..\backend\.env"
if (-not (Test-Path $backendEnv)) { throw "Missing $backendEnv" }

function Read-EnvValue {
    param([string]$Path, [string]$Key)
    $line = Select-String -Path $Path -Pattern "^$Key=" -ErrorAction SilentlyContinue
    if (-not $line) { return $null }
    return $line.Line.Split('=', 2)[1].Trim()
}

Write-Host "Pulling images from $Registry..." -ForegroundColor Cyan
foreach ($name in @("mykronos-backend", "mykronos-frontend")) {
    docker pull "$Registry/$name`:latest"
    if ($LASTEXITCODE -ne 0) { throw "Could not pull $name. Has the pipeline published it?" }
    docker tag "$Registry/$name`:latest" "$name`:latest"
}

# The App private key stays on the host and is bind-mounted read-only. Spec 12
# section 2 keeps it out of repositories and out of image layers, and an image
# layer is something people pull.
$keyPath = Read-EnvValue $backendEnv "MYKRONOS_GITHUB_APP_PRIVATE_KEY_PATH"
if ($keyPath -and (Test-Path $keyPath)) {
    $env:MYKRONOS_GITHUB_APP_KEY_HOST_PATH = (Resolve-Path $keyPath).Path
    Write-Host "GitHub App key will be mounted read-only." -ForegroundColor DarkGray
} else {
    Write-Host "No GitHub App key found; the stack will run without it." -ForegroundColor Yellow
}

if ($MigrateFrom) {
    if (-not (Test-Path $MigrateFrom)) { throw "No such directory: $MigrateFrom" }
    Write-Host "`nMigrating existing data into the volume..." -ForegroundColor Cyan
    docker volume create mykronos_mykronos-data | Out-Null
    # Through a helper container: the volume is not reachable from the host
    # filesystem on Docker Desktop.
    $src = (Resolve-Path $MigrateFrom).Path
    docker run --rm -v "${src}:/from:ro" -v "mykronos_mykronos-data:/data" `
        alpine:3.19 sh -c "cp -a /from/datalake /data/ 2>/dev/null; cp -a /from/mykronos.db /data/ 2>/dev/null; ls -la /data"
    if ($LASTEXITCODE -ne 0) { throw "Migration failed; not starting." }
}

if ($NoStart) { return }

Push-Location $here
try {
    docker compose --env-file $backendEnv up -d
    if ($LASTEXITCODE -ne 0) { throw "docker compose up failed" }

    Write-Host "`nWaiting for health..." -ForegroundColor Cyan
    $deadline = (Get-Date).AddMinutes(3)
    do {
        Start-Sleep -Seconds 10
        $backend = (docker inspect -f '{{.State.Health.Status}}' mykronos-backend 2>$null)
        $frontend = (docker inspect -f '{{.State.Health.Status}}' mykronos-frontend 2>$null)
        Write-Host "  backend=$backend frontend=$frontend"
    } while (((Get-Date) -lt $deadline) -and (($backend -ne "healthy") -or ($frontend -ne "healthy")))

    if ($backend -ne "healthy") { throw "Backend did not become healthy: docker compose logs backend" }
    Write-Host "`nDeployed. http://localhost:3100 and http://localhost:8100" -ForegroundColor Green
} finally {
    Pop-Location
}
