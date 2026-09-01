<#
.SYNOPSIS
    Restore personal-soc's ingestion token to both of its readers (B-016).

.DESCRIPTION
    personal-soc has an active token whose plaintext survives only inside the
    GitHub Actions secret, which is write-only. `deploy/concourse/.env` has no
    `PERSONAL_SOC_INGESTION_TOKEN`, so the applied Concourse pipeline carries
    `MYKRONOS_TOKEN: ""` and files nothing. The repository's newest scan run is
    2026-08-12.

    Recovering the existing value is impossible by design, so the repair is a
    rotation. That is the dangerous part, and it is why this is a script rather
    than four commands in a runbook.

    D-097, THREE TIMES OVER. A repository read by both GitHub Actions and
    Concourse must have its token delivered to BOTH readers in one operation.
    Rotating and delivering to one is not a partial success - it is an outage
    for the other, and it has happened here three times: mykronos, then the
    `.env` copy, then keel. The automatic rotation job now defers a repo like
    this rather than half-fixing it, which is correct and also means
    personal-soc will never be repaired automatically. Hence this.

    So the order below is deliberate and the checks are not optional:

      1. Prove every reader is WRITABLE first. Nothing is rotated until the
         GitHub App can be reached, the repo secret is writable, and the .env
         file exists and is not read-only. A check that runs after the
         rotation is not a check, it is a post-mortem.
      2. Rotate once.
      3. Deliver to both readers.
      4. Mark the token synced, so the unsynced sweep does not rotate it again.
      5. Re-apply the pipeline so Concourse picks the value up.

    If step 3 fails at either reader, the previous token is still valid for the
    overlap window - so the failure is recoverable by re-running this script,
    not an outage. That property is the reason the rotation happens before the
    writes rather than after.

.PARAMETER WhatIf
    Run every reachability check and report what would happen. Rotates
    nothing, writes nothing. Do this first.

.NOTES
    ASCII only - see deploy/concourse/setup.ps1.
    Run from the repository, with Docker up and Vault unsealed.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$Repo = "ToddGBenson/personal-soc",
    [string]$EnvKey = "PERSONAL_SOC_INGESTION_TOKEN",
    [string]$SecretName = "MYKRONOS_INGESTION_TOKEN",
    [string]$Container = "mykronos-backend",
    # Skip the pipeline re-apply. The token is still delivered; Concourse just
    # keeps the old empty value until somebody applies.
    [switch]$NoApply
)

$ErrorActionPreference = "Stop"
$here = $PSScriptRoot
$stackEnv = Join-Path $here ".env"

function Write-Step { param([string]$Text) Write-Host "`n$Text" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Text) Write-Host "  OK   $Text" -ForegroundColor Green }
function Write-Bad  { param([string]$Text) Write-Host "  FAIL $Text" -ForegroundColor Red }

# ---------------------------------------------------------------------------
# 1. Every reader must be writable BEFORE anything is rotated.
# ---------------------------------------------------------------------------
Write-Step "Checking both readers before touching the token..."
$problems = @()

if (-not (Test-Path $stackEnv)) {
    $problems += "Missing $stackEnv - the Concourse reader has nowhere to be written."
} else {
    # Read-only or locked by an editor would fail *after* the rotation, which
    # is the failure mode this whole ordering exists to avoid.
    try {
        $fs = [System.IO.File]::Open($stackEnv, 'Open', 'ReadWrite', 'None')
        $fs.Close()
        Write-Ok "$stackEnv is writable."
    } catch {
        $problems += "$stackEnv is not writable: $($_.Exception.Message)"
    }
}

$docker = (docker ps --format '{{.Names}}' 2>$null) -contains $Container
if (-not $docker) {
    $problems += "Container $Container is not running - cannot mint a token."
} else {
    Write-Ok "$Container is running."
}

# The GitHub half. `gh` is what the operator already uses here, and it fails
# loudly on a missing scope rather than writing a secret nobody can read.
$ghUser = (gh api user --jq .login 2>$null)
if ($LASTEXITCODE -ne 0) {
    $problems += "gh is not authenticated - run: gh auth login"
} else {
    Write-Ok "gh authenticated as $ghUser."
    gh api "repos/$Repo" --jq .full_name *> $null
    if ($LASTEXITCODE -ne 0) {
        $problems += "Cannot read $Repo through gh - check the token's repo scope."
    } else {
        Write-Ok "$Repo is reachable."
    }
}

if ($problems.Count -gt 0) {
    Write-Host ""
    foreach ($p in $problems) { Write-Bad $p }
    throw "Not rotating. Every reader must be writable first (D-097)."
}

if ($WhatIfPreference) {
    Write-Host "`nAll checks passed. With -WhatIf nothing was rotated." -ForegroundColor Yellow
    Write-Host "Re-run without -WhatIf to perform the repair." -ForegroundColor Yellow
    return
}

# ---------------------------------------------------------------------------
# 2. Rotate once. The previous token stays valid for the overlap window, so a
#    delivery failure below is recoverable rather than an outage.
# ---------------------------------------------------------------------------
Write-Step "Rotating $Repo..."
$output = docker exec $Container mykronos rotate-token $Repo 2>&1
if ($LASTEXITCODE -ne 0) { throw "Rotation failed:`n$output" }

$token = ($output | Select-String -Pattern '^New token\s*:\s*(.+)$').Matches.Groups[1].Value.Trim()
if (-not $token) { throw "Could not read the new token out of:`n$output" }
Write-Ok "Rotated. The previous token stays valid for the overlap window."

# ---------------------------------------------------------------------------
# 3. Deliver to BOTH readers. Neither is optional.
# ---------------------------------------------------------------------------
Write-Step "Delivering to both readers..."

# Reader 1: the GitHub Actions secret.
$token | gh secret set $SecretName --repo $Repo --body -
if ($LASTEXITCODE -ne 0) {
    throw ("Rotated, but the GitHub secret write FAILED. The previous token " +
           "is still valid for the overlap window - re-run this script.")
}
Write-Ok "GitHub Actions secret $SecretName set on $Repo."

# Reader 2: deploy/concourse/.env. Replace in place if the key is present,
# append if not, and keep the rest of the file byte-for-byte.
$lines = @(Get-Content $stackEnv)
$pattern = "^$([regex]::Escape($EnvKey))="
if ($lines -match $pattern) {
    $lines = $lines | ForEach-Object { if ($_ -match $pattern) { "$EnvKey=$token" } else { $_ } }
} else {
    $lines += "$EnvKey=$token"
}
Set-Content -Path $stackEnv -Value $lines -Encoding ascii
Write-Ok "$EnvKey written to $stackEnv."

# ---------------------------------------------------------------------------
# 4. Record the delivery, so the unsynced sweep does not rotate it again.
# ---------------------------------------------------------------------------
Write-Step "Marking the token synced..."
$py = "from mykronos.config import get_settings; from mykronos.db import Database; " +
      "from mykronos.auth import TokenRegistry; " +
      "db=Database(get_settings().database_url); s=db.session().__enter__(); " +
      "TokenRegistry(s).mark_secret_synced('$Repo'); s.commit(); print('synced')"
$synced = docker exec $Container python -c $py 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "  WARN could not mark synced; the sweep may rotate again: $synced" -ForegroundColor Yellow
} else {
    Write-Ok "Marked synced."
}

# ---------------------------------------------------------------------------
# 5. Re-apply, so Concourse actually reads the new value.
# ---------------------------------------------------------------------------
if (-not $NoApply) {
    Write-Step "Re-applying the personal-soc pipeline..."
    & (Join-Path $here "set-personal-soc-pipeline.ps1")
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  WARN the pipeline did not apply. The token is delivered; apply by hand." -ForegroundColor Yellow
    } else {
        Write-Ok "Pipeline applied."
    }
}

Write-Host "`nDone. personal-soc should file scan results on its next run." -ForegroundColor Green
# Single-quoted: PowerShell escapes with a backtick, not a backslash, so a
# double-quoted string containing \" terminates early and the remainder is
# parsed as commands. That is exactly what happened on the first real run.
$check = 'SELECT max(started_at) FROM scan_runs WHERE repo_full_name=''{0}''' -f $Repo
Write-Host ("Check with: docker exec {0} mykronos query ""{1}""" -f $Container, $check) -ForegroundColor DarkGray
