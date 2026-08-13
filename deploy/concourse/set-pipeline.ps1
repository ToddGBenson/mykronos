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
    param([string]$Path, [string]$Key)
    $line = Select-String -Path $Path -Pattern "^$Key=" -ErrorAction SilentlyContinue
    if (-not $line) { throw "$Key is not set in $Path" }
    return $line.Line.Split('=', 2)[1].Trim()
}

$stackEnv = Join-Path $PSScriptRoot ".env"
$backendEnv = Join-Path $PSScriptRoot "..\..\backend\.env"
foreach ($file in @($stackEnv, $backendEnv)) {
    if (-not (Test-Path $file)) { throw "Missing $file" }
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
        "mykronos-ref: v1",
        "mykronos-ingestion-token: $(Read-EnvValue $backendEnv 'MYKRONOS_CONCOURSE_TOKEN')",
        "mykronos-gate-token: $(Read-EnvValue $backendEnv 'MYKRONOS_GATE_TOKEN')",
        # MinIO is on the compose network, so the task container reaches it by
        # service name rather than through the host.
        "minio-endpoint: http://192.168.0.14:9000",
        "minio-access-key: $(Read-EnvValue $stackEnv 'MINIO_ROOT_USER')",
        "minio-secret-key: $(Read-EnvValue $stackEnv 'MINIO_ROOT_PASSWORD')",
        # Host IP for the same reason MinIO uses one: garden task containers
        # cannot resolve Docker service names.
        "registry: 192.168.0.14:5000"
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

Write-Host "  $Concourse/teams/main/pipelines/$Pipeline"
