#Requires -Version 7
# ^ pwsh only. These scripts build their docker invocation with
# ProcessStartInfo.ArgumentList, which .NET Framework 4.x (Windows
# PowerShell 5.1) does not have - there it is $null and .Add() fails with
# "You cannot call a method on a null-valued expression", naming neither
# the shell nor the cause. ArgumentList keeps each argument separate, and
# the single-string alternative would put a Vault token on the command
# line, so this requires the newer shell rather than working around it.
#
# Run with:  pwsh -File .\<script>.ps1 ...
<#
.SYNOPSIS
    Move the credentials that are still written into pipeline config into Vault.

.DESCRIPTION
    PS-9 (docs/pipeline-standard.md): "Concourse pipeline YAML is committed.
    Nothing sensitive may appear in it." Concourse stores pipeline configuration
    verbatim, so a secret passed with `--load-vars-from` is readable afterwards
    by anyone who can run `fly get-pipeline`.

    set-pipeline.ps1 probes Vault for each credential and only falls back to the
    vars file when Vault does not have it, naming what fell back. This is the
    other half: it takes the values that are already sitting in .env on this host
    and puts them where the pipeline can resolve them without holding them.

    vault-secret.ps1 remains the way to set a secret you are typing — it prompts
    with Read-Host -AsSecureString on purpose, so a value never reaches shell
    history. This exists for the values that are already in a file, where a
    prompt buys nothing and invites a copy-paste error instead.

    Values are never printed and never passed as arguments. Same mechanism as
    vault-secret.ps1: piped on stdin as `value=-`, written through .NET rather
    than the PowerShell pipeline, because the pipeline appends CRLF and a
    trailing "\r\n" inside an `Authorization: Bearer` header is a 401 that
    nothing in the logs explains.

.EXAMPLE
    .\Import-EnvSecretsToVault.ps1                 # show what would move
    .\Import-EnvSecretsToVault.ps1 -Apply          # move it

.NOTES
    ASCII only - see setup.ps1 for why.
#>
[CmdletBinding()]
param(
    [switch]$Apply,
    [string]$Pipeline = "mykronos",
    [string]$Team = "main",
    [string]$Container = "mykronos-vault"
)

$ErrorActionPreference = "Stop"

$stackEnv = Join-Path $PSScriptRoot ".env"
$backendEnv = Join-Path $PSScriptRoot "..\..\backend\.env"
foreach ($file in @($stackEnv, $backendEnv)) {
    if (-not (Test-Path $file)) { throw "Missing $file" }
}

# Vault name -> which file and key holds it, per pipeline. Keyed on the
# pipeline because the first version was not: it hardcoded the mykronos set,
# so `-Pipeline thehub` cheerfully wrote *mykronos's* ingestion token to
# `concourse/main/thehub/mykronos-ingestion-token` - a credential in a scope
# that must never resolve it, created by the tool meant to reduce exposure.
#
# `Scope = "team"` for anything more than one pipeline uses. Three copies of
# one secret is three things to rotate and two chances to miss one.
$catalogue = @{
    "mykronos" = @(
        @{ Name = "mykronos-ingestion-token"; File = $backendEnv; Key = "MYKRONOS_CONCOURSE_TOKEN" }
        @{ Name = "mykronos-gate-token";      File = $backendEnv; Key = "MYKRONOS_GATE_TOKEN"; Scope = "team" }
        @{ Name = "minio-access-key";         File = $stackEnv;   Key = "MINIO_ROOT_USER"; Scope = "team" }
        @{ Name = "minio-secret-key";         File = $stackEnv;   Key = "MINIO_ROOT_PASSWORD"; Scope = "team" }
    )
    "thehub" = @(
        @{ Name = "thehub-ingestion-token"; File = $backendEnv; Key = "MYKRONOS_THEHUB_CONCOURSE_TOKEN" }
        @{ Name = "mykronos-gate-token";    File = $backendEnv; Key = "MYKRONOS_GATE_TOKEN"; Scope = "team" }
        @{ Name = "minio-access-key";       File = $stackEnv;   Key = "MINIO_ROOT_USER"; Scope = "team" }
        @{ Name = "minio-secret-key";       File = $stackEnv;   Key = "MINIO_ROOT_PASSWORD"; Scope = "team" }
    )
    "personal-soc" = @(
        @{ Name = "minio-access-key"; File = $stackEnv; Key = "MINIO_ROOT_USER"; Scope = "team" }
        @{ Name = "minio-secret-key"; File = $stackEnv; Key = "MINIO_ROOT_PASSWORD"; Scope = "team" }
    )
}

if (-not $catalogue.ContainsKey($Pipeline)) {
    throw "No secret catalogue for pipeline '$Pipeline'. Known: $($catalogue.Keys -join ', ')"
}
$moves = $catalogue[$Pipeline]

function Read-EnvValue {
    param([string]$Path, [string]$Key)
    $line = Select-String -Path $Path -Pattern "^$Key=" -ErrorAction SilentlyContinue
    if (-not $line) { return $null }
    return $line.Line.Split('=', 2)[1].Trim()
}

# CONCOURSE_VAULT_TOKEN is deliberately read-and-list only (VAULT.md), so it
# cannot be used here - writing with it returns 403, which is the policy
# working. The root token from `vault operator init` is what writes, read out
# of the same gitignored file vault-unseal.ps1 reads its unseal keys from.
#
# Read into a variable and never printed, never passed as a command-line
# argument where the container's process list would show it: it goes in as an
# environment variable on the docker exec, the same way vault-unseal.ps1 hands
# over an unseal key.
$initFile = Join-Path $PSScriptRoot "vault\init.json"
if (-not (Test-Path $initFile)) {
    throw "Missing $initFile - that is where the root token lives. Vault cannot be written without it."
}
$token = (Get-Content $initFile -Raw | ConvertFrom-Json).root_token
if (-not $token) { throw "No root_token in $initFile." }

function Write-VaultValue {
    param([string]$Path, [string]$Value)
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = 'docker'
    foreach ($a in @('exec', '-e', 'VAULT_ADDR=http://127.0.0.1:8200',
                     '-e', "VAULT_TOKEN=$token",
                     '-i', $Container, 'vault', 'kv', 'put', $Path, 'value=-')) {
        $psi.ArgumentList.Add($a)
    }
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false

    $proc = [System.Diagnostics.Process]::Start($psi)
    $proc.StandardInput.Write($Value)
    $proc.StandardInput.Close()
    $null = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()
    if ($proc.ExitCode -ne 0) {
        if ($stderr -match 'Vault is sealed') { throw "Vault is sealed. Run .\vault-unseal.ps1 first." }
        throw "write failed for ${Path}: $stderr"
    }
}

function Get-VaultLength {
    param([string]$Path)
    $json = docker exec -e VAULT_ADDR=http://127.0.0.1:8200 -e "VAULT_TOKEN=$token" `
        $Container vault kv get -format=json $Path 2>$null
    if ($LASTEXITCODE -ne 0) { return $null }
    return ($json | ConvertFrom-Json).data.value.Length
}

if (-not $Apply) {
    Write-Host "Dry run. Pass -Apply to write. Nothing is printed but names and lengths." -ForegroundColor Yellow
    Write-Host ""
}

foreach ($move in $moves) {
    $scope = if ($move.Scope) { $move.Scope } else { "pipeline" }
    $path = if ($scope -eq "team") {
        "concourse/$Team/$($move.Name)"
    } else {
        "concourse/$Team/$Pipeline/$($move.Name)"
    }
    $value = Read-EnvValue $move.File $move.Key

    if (-not $value) {
        Write-Host ("{0,-28} SKIP  {1} is not in {2}" -f $move.Name, $move.Key, (Split-Path $move.File -Leaf)) -ForegroundColor Yellow
        continue
    }

    $existing = Get-VaultLength $path
    if ($null -ne $existing) {
        # Already there. Overwriting a live credential with whatever happens to
        # be in .env is not a no-op if the two have drifted, so it is refused
        # rather than assumed.
        Write-Host ("{0,-28} PRESENT  already in Vault ({1} chars); leaving it" -f $move.Name, $existing) -ForegroundColor DarkGray
        continue
    }

    if (-not $Apply) {
        Write-Host ("{0,-28} WOULD MOVE  {1} chars -> {2}" -f $move.Name, $value.Length, $path)
        continue
    }

    Write-VaultValue -Path $path -Value $value
    $stored = Get-VaultLength $path

    # Read the length back rather than assume it. A secret stored two bytes
    # longer than it should be is the exact failure the stdin handling above
    # exists to prevent, and the length is safe to print.
    if ($stored -ne $value.Length) {
        throw "$($move.Name): wrote $($value.Length) chars, Vault read back $stored"
    }
    Write-Host ("{0,-28} MOVED  {1} chars -> {2}" -f $move.Name, $stored, $path) -ForegroundColor Green
}

Write-Host ""
if ($Apply) {
    Write-Host "Re-apply the pipeline so it resolves them from Vault:" -ForegroundColor Cyan
    Write-Host "  .\set-pipeline.ps1"
    Write-Host ""
    Write-Host "The values are still in .env, which is correct - that is where" -ForegroundColor DarkGray
    Write-Host "set-pipeline.ps1 falls back from if Vault is ever sealed. They are" -ForegroundColor DarkGray
    Write-Host "also still in the CURRENTLY APPLIED pipeline config until you" -ForegroundColor DarkGray
    Write-Host "re-apply, and readable by anyone who can run fly get-pipeline" -ForegroundColor DarkGray
    Write-Host "until they are rotated. Moving them protects the future, not the past." -ForegroundColor DarkGray
}
