<#
.SYNOPSIS
    Rotate a repository's ingestion token and deliver it to EVERY reader.

.DESCRIPTION
    D-097, four times over. A repository's ingestion token can be read from
    three places - a GitHub Actions secret, a Vault path Concourse resolves
    `((vars))` from, and a key in `deploy/concourse/.env` - and the automatic
    rotation job can only write the first. Rotating and delivering to one is
    not a partial success. It is an outage for the others, and it has now
    happened to mykronos, to the `.env` copy, to keel, and to TheHub.

    TheHub is the instructive one. Its token rotated on 2026-08-31, the
    Actions secret was updated, and the Vault copy was left behind. TheHub is
    `scanned_by=concourse`, so the *only* reader that mattered was the broken
    one: every Concourse job failed its preflight with a bare 401, nothing
    scanned, and 316 findings froze open because a finding closes only after
    two consecutive successful scans. The guard that prevents this was written
    on 2026-09-01, a day too late for that rotation.

    THE ORDER IS THE DESIGN, and none of it is optional:

      1. Prove every reader named is WRITABLE first. Nothing is rotated until
         all of them are reachable. A check that runs after the rotation is
         not a check, it is a post-mortem.
      2. Rotate once.
      3. Deliver to every reader.
      4. Mark synced, so the unsynced sweep does not rotate it again.
      5. Re-apply the pipeline, so Concourse resolves the new value.

    If a delivery fails, the previous token is still valid for its overlap
    window, so the failure is recoverable by re-running rather than an outage.
    That property is the whole reason the rotation precedes the writes.

    NO TRAILING NEWLINE INTO VAULT. A CRLF inside an `Authorization: Bearer`
    header is a 401 that nothing in the logs explains, and it has cost a day
    here before. The Vault write below pipes the value with none.

.PARAMETER Repo
    owner/repo. Its readers are looked up below; add new ones to $READERS.

.PARAMETER WhatIf
    Run every reachability check and report. Rotates nothing. Do this first.

.EXAMPLE
    .\repair-ingestion-token.ps1 -Repo ToddGBenson/TheHub -WhatIf
    .\repair-ingestion-token.ps1 -Repo ToddGBenson/TheHub

.NOTES
    ASCII only - see deploy/concourse/setup.ps1.
    Vault must be unsealed: .\vault-unseal.ps1
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$Repo,
    [string]$Container = "mykronos-backend",
    [string]$VaultContainer = "mykronos-vault",
    [switch]$NoApply
)

$ErrorActionPreference = "Stop"
$here = $PSScriptRoot
$stackEnv = Join-Path $here ".env"
$backendEnv = Join-Path $here "..\..\backend\.env"

# Who reads each repository's token. This table is the point of the script:
# it is the thing that was implicit, and being implicit is what broke four
# lanes. `Apply` names the pipeline script to re-run, or $null for none.
$READERS = @{
    "ToddGBenson/TheHub"       = @{
        Secret    = "MYKRONOS_INGESTION_TOKEN"
        VaultPath = "concourse/main/thehub/thehub-ingestion-token"
        EnvFile   = $backendEnv
        EnvKey    = "MYKRONOS_THEHUB_CONCOURSE_TOKEN"
        Apply     = "set-thehub-pipeline.ps1"
    }
    "ToddGBenson/personal-soc" = @{
        Secret    = "MYKRONOS_INGESTION_TOKEN"
        VaultPath = $null
        EnvFile   = $stackEnv
        EnvKey    = "PERSONAL_SOC_INGESTION_TOKEN"
        Apply     = "set-personal-soc-pipeline.ps1"
    }
    "ToddGBenson/mykronos"     = @{
        Secret    = "MYKRONOS_INGESTION_TOKEN"
        VaultPath = "concourse/main/mykronos/mykronos-ingestion-token"
        EnvFile   = $backendEnv
        EnvKey    = "MYKRONOS_CONCOURSE_TOKEN"
        Apply     = "set-pipeline.ps1"
    }
    "ToddGBenson/keel"         = @{
        Secret    = "MYKRONOS_INGESTION_TOKEN"
        VaultPath = "concourse/main/keel/mykronos_ingestion_token"
        EnvFile   = $null
        EnvKey    = $null
        Apply     = $null
    }
}

if (-not $READERS.ContainsKey($Repo)) {
    throw ("No reader map for $Repo. Add one to `$READERS rather than " +
           "rotating blind - that is exactly how D-097 happened.")
}
$reader = $READERS[$Repo]

function Write-Step { param([string]$Text) Write-Host "`n$Text" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Text) Write-Host "  OK   $Text" -ForegroundColor Green }
function Write-Bad  { param([string]$Text) Write-Host "  FAIL $Text" -ForegroundColor Red }

function Get-VaultToken {
    $initFile = Join-Path $here "vault\init.json"
    if (-not (Test-Path $initFile)) { return $null }
    return (Get-Content $initFile -Raw | ConvertFrom-Json).root_token
}

# ---------------------------------------------------------------------------
# 1. Every named reader must be writable BEFORE anything is rotated.
# ---------------------------------------------------------------------------
Write-Step "Checking every reader of $Repo before touching the token..."
$problems = @()

if (-not ((docker ps --format '{{.Names}}' 2>$null) -contains $Container)) {
    $problems += "Container $Container is not running - cannot mint a token."
} else { Write-Ok "$Container is running." }

$ghUser = (gh api user --jq .login 2>$null)
if ($LASTEXITCODE -ne 0) {
    $problems += "gh is not authenticated - run: gh auth login"
} else {
    gh api "repos/$Repo" --jq .full_name *> $null
    if ($LASTEXITCODE -ne 0) { $problems += "Cannot reach $Repo through gh." }
    else { Write-Ok "GitHub reader reachable ($($reader.Secret) on $Repo)." }
}

$vaultToken = $null
if ($reader.VaultPath) {
    $vaultToken = Get-VaultToken
    if (-not $vaultToken) {
        $problems += "No vault/init.json - cannot write $($reader.VaultPath)."
    } else {
        # Sealed Vault answers every read with an error that reads like a
        # credentials bug. Better to say so here than after the rotation.
        $sealed = docker exec $VaultContainer sh -c 'vault status -format=json 2>/dev/null' |
            ConvertFrom-Json
        if ($sealed.sealed) {
            $problems += "Vault is sealed. Run .\vault-unseal.ps1 first."
        } else { Write-Ok "Vault reader reachable ($($reader.VaultPath))." }
    }
}

if ($reader.EnvFile) {
    if (-not (Test-Path $reader.EnvFile)) {
        $problems += "Missing $($reader.EnvFile) - the .env reader has nowhere to go."
    } else {
        try {
            $fs = [System.IO.File]::Open($reader.EnvFile, 'Open', 'ReadWrite', 'None')
            $fs.Close()
            Write-Ok "File reader writable ($($reader.EnvKey) in $($reader.EnvFile))."
        } catch { $problems += "$($reader.EnvFile) is not writable: $($_.Exception.Message)" }
    }
}

if ($problems.Count -gt 0) {
    Write-Host ""
    foreach ($p in $problems) { Write-Bad $p }
    throw "Not rotating. Every reader must be writable first (D-097)."
}

if ($WhatIfPreference) {
    Write-Host "`nAll readers reachable. With -WhatIf nothing was rotated." -ForegroundColor Yellow
    return
}

# ---------------------------------------------------------------------------
# 2. Rotate once.
# ---------------------------------------------------------------------------
Write-Step "Rotating $Repo..."
$output = docker exec $Container mykronos rotate-token $Repo 2>&1
if ($LASTEXITCODE -ne 0) { throw "Rotation failed:`n$output" }
$token = ($output | Select-String -Pattern '^New token\s*:\s*(.+)$').Matches.Groups[1].Value.Trim()
if (-not $token) { throw "Could not read the new token out of:`n$output" }
Write-Ok "Rotated. The previous token stays valid for the overlap window."

# ---------------------------------------------------------------------------
# 3. Deliver to every reader. None of them is optional.
# ---------------------------------------------------------------------------
Write-Step "Delivering to every reader..."

$token | gh secret set $reader.Secret --repo $Repo --body -
if ($LASTEXITCODE -ne 0) {
    throw ("Rotated, but the GitHub secret write FAILED. The previous token is " +
           "still valid for the overlap window - re-run this script.")
}
Write-Ok "GitHub Actions secret $($reader.Secret) set."

if ($reader.VaultPath) {
    # `printf %s` and `value=-` on stdin: NO trailing newline. A CRLF inside
    # an Authorization header is a 401 nothing in the logs explains.
    $write = "printf %s '$token' | vault write $($reader.VaultPath) value=-"
    docker exec -e VAULT_TOKEN=$vaultToken $VaultContainer sh -c $write | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Rotated, but the Vault write FAILED. Re-run this script." }

    $readBack = docker exec -e VAULT_TOKEN=$vaultToken $VaultContainer `
        sh -c "vault read -field=value $($reader.VaultPath)"
    if ($readBack -ne $token) {
        throw "Vault read-back does not match what was written - suspect a stray newline."
    }
    Write-Ok "Vault $($reader.VaultPath) set and read back byte-identical."
}

if ($reader.EnvFile) {
    $lines = @(Get-Content $reader.EnvFile)
    $pattern = "^$([regex]::Escape($reader.EnvKey))="
    if ($lines -match $pattern) {
        $lines = $lines | ForEach-Object {
            if ($_ -match $pattern) { "$($reader.EnvKey)=$token" } else { $_ }
        }
    } else { $lines += "$($reader.EnvKey)=$token" }
    Set-Content -Path $reader.EnvFile -Value $lines -Encoding ascii
    Write-Ok "$($reader.EnvKey) written to $($reader.EnvFile)."
}

# ---------------------------------------------------------------------------
# 4. Record it, so the unsynced sweep does not rotate again.
# ---------------------------------------------------------------------------
Write-Step "Marking the token synced..."
$py = "from mykronos.config import get_settings; from mykronos.db import Database; " +
      "from mykronos.auth import TokenRegistry; " +
      "db=Database(get_settings().database_url); s=db.session().__enter__(); " +
      "TokenRegistry(s).mark_secret_synced('$Repo'); s.commit(); print('synced')"
$synced = docker exec $Container python -c $py 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "  WARN could not mark synced: $synced" -ForegroundColor Yellow
} else { Write-Ok "Marked synced." }

# ---------------------------------------------------------------------------
# 5. Re-apply, so Concourse resolves the new value.
# ---------------------------------------------------------------------------
if ($reader.Apply -and -not $NoApply) {
    Write-Step "Re-applying $($reader.Apply)..."
    & (Join-Path $here $reader.Apply)
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  WARN the pipeline did not apply. The token is delivered; apply by hand." -ForegroundColor Yellow
    } else { Write-Ok "Pipeline applied." }
}

Write-Host "`nDone. Trigger a job and confirm its preflight passes." -ForegroundColor Green
