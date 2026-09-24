<#
.SYNOPSIS
    Install the Scheduled Task that unseals Vault after a restart or recreate.

.DESCRIPTION
    Vault uses the file storage backend, so it comes back SEALED every time
    its container is recreated, and Concourse then resolves no ((vars)) at all.
    vault-unseal.ps1 fixes that in a second. Until this task existed, nothing
    ran it: somebody had to notice first.

    On 2026-09-19 the Docker engine recreated the container (ExitCode 0,
    RestartCount 0, fresh StartedAt - a recreate, not a crash) and nobody
    noticed for FOUR DAYS. 20 of keel's 26 jobs errored in three seconds each,
    `thehub` and `personal-soc` resolved nothing, and the container reported
    healthy throughout because the healthcheck had been told to answer 200
    while sealed. #59083's 2026-09-07 incident was the same cause. This is at
    least the third occurrence.

    #60474 fixes both halves and in this order: the healthcheck first, so a
    seal is VISIBLE within minutes, then this, so it usually reopens itself
    before anyone has to look. The order matters - auto-unseal alone would
    have removed the likeliest trigger while leaving the instrument lying,
    and any future failure that was not sealing would still read healthy.

    THIS IS NOT VAULT AUTO-UNSEAL. Vault's own auto-unseal means a transit
    seal or a cloud KMS holding the key - a second trust root this host does
    not have. This is automated invocation of the MANUAL unseal, using the key
    that already sits in vault/init.json on this disk. It adds no exposure
    that does not already exist: the file is the exposure, and it predates
    this decision. What it removes is the requirement for a human to be
    watching.

.PARAMETER IntervalMinutes
    How often to re-check. 5 by default, which bounds a sealed window at about
    five minutes. The compose healthcheck needs 2.5 minutes (interval 15s x
    retries 10) to report unhealthy, so a seal this task recovers from may
    still flicker in `docker inspect`. That is the right way round: the alarm
    is allowed to be faster than the repair.

.PARAMETER AsSystem
    Register under SYSTEM instead of the calling account, and trigger at boot
    rather than at logon. Needs an elevated session.

    Not the default, and this is the one genuinely uncertain choice here.
    Docker Desktop on this host is login-scoped - the engine is not running
    before somebody logs in - so a SYSTEM task firing at boot has nothing to
    talk to, and the current user is the account that demonstrably can reach
    the engine. If SYSTEM can reach the pipe on your machine, this switch is
    strictly better: it covers a reboot with no login. Verify rather than
    assume, which is what the first run below is for.

.NOTES
    ASCII only - see setup.ps1. Windows PowerShell 5.1 reads a BOM-less file
    as CP1252, so a UTF-8 dash becomes three characters and the parser
    reports errors on lines that are not the problem.
#>

[CmdletBinding()]
param(
    [int]$IntervalMinutes = 5,
    [switch]$AsSystem,
    [string]$TaskName = "Mykronos Vault Unseal",

    # Passed through rather than left to the script's default, so the task and
    # anyone reading the log cannot disagree about where it is.
    [string]$LogFile = (Join-Path $PSScriptRoot "vault-unseal.log")
)

$ErrorActionPreference = "Stop"

$unsealer = Join-Path $PSScriptRoot "vault-unseal.ps1"
if (-not (Test-Path $unsealer)) {
    throw "vault-unseal.ps1 not found next to this script: $unsealer"
}

# Fail early and clearly. Register-ScheduledTask's own error for this is
# "Access is denied", which sends people to file permissions rather than to
# the elevation they actually need.
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = ([Security.Principal.WindowsPrincipal]$identity).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if ($AsSystem -and -not $isAdmin) {
    Write-Host "Registering a SYSTEM task needs an elevated session." -ForegroundColor Red
    Write-Host "  Either: start PowerShell with 'Run as Administrator' and re-run this," -ForegroundColor Yellow
    Write-Host "  or:     drop -AsSystem and it registers under $($identity.Name)." -ForegroundColor Yellow
    exit 1
}

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Write-Host "Replacing the existing '$TaskName' task." -ForegroundColor DarkGray
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument ('-NoProfile -ExecutionPolicy Bypass -File "{0}" -LogFile "{1}"' -f $unsealer, $LogFile)

# TWO triggers, and the repeating one is the one that matters.
#
# A boot or logon trigger alone would not have caught this incident at all.
# The 2026-09-19 seal was a Docker-engine recreate under a session that stayed
# logged in - the host never rebooted, so a start trigger would never have
# fired. A recreate is not a boot, and recreates are the routine event here.
#
# vault-unseal.ps1 is idempotent and exits 0 the moment it sees an unsealed
# Vault or no container, so re-checking costs one `docker inspect` and one
# `vault status` per run.
$startup = if ($AsSystem) {
    New-ScheduledTaskTrigger -AtStartup
} else {
    New-ScheduledTaskTrigger -AtLogOn -User $identity.Name
}
# Docker takes a while to be ready. An unseal attempt against an engine that
# is still starting exits 0 with "nothing to unseal" and would otherwise be
# the only attempt until the repetition caught up.
$startup.Delay = "PT2M"

$repeating = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
    -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)

# IgnoreNew so a hung `docker exec` cannot stack instances. StartWhenAvailable
# so a run missed on a sleeping machine is picked up rather than skipped
# silently - a machine waking from sleep with a recreated engine is exactly
# the case this exists for.
#
# AllowStartIfOnBatteries / DontStopIfGoingOnBatteries because Windows
# defaults both the other way: a task registered without them refuses to run
# on battery and returns 0x800710E0, "the operator or administrator has
# refused the request" - a message that sends you looking for a permissions
# problem that does not exist.
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -StartWhenAvailable `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

if ($AsSystem) {
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $who = "SYSTEM (elevated)"
} else {
    $principal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Limited
    $who = $identity.Name
}

Register-ScheduledTask -TaskName $TaskName -Action $action `
    -Trigger @($startup, $repeating) -Settings $settings -Principal $principal `
    -Description ("Runs deploy/concourse/vault-unseal.ps1 so a sealed Vault reopens itself. " +
                  "A file-storage Vault seals on every container recreate and Concourse then " +
                  "resolves no ((vars)) in any pipeline. #60474.") | Out-Null

Write-Host "Registered '$TaskName' as $who, every $IntervalMinutes minutes." -ForegroundColor Green

# Run it once now rather than leaving the operator to wonder whether the
# principal can actually reach the Docker engine - which is the one thing
# about this task that cannot be settled by reading it.
Write-Host "Running it once now..." -ForegroundColor Cyan

while ((Get-ScheduledTask -TaskName $TaskName).State -eq "Running") {
    Write-Host "  waiting for the instance already running..." -ForegroundColor DarkGray
    Start-Sleep -Seconds 5
}

# Watch the artefact, not only the exit code. The log line says WHICH of the
# three zero-exit outcomes happened, and "already unsealed" versus "no
# container running" is the whole difference between a working task and one
# that will sit at exit 0 forever without ever reaching Vault.
$before = if (Test-Path $LogFile) { (Get-Item $LogFile).Length } else { -1 }

Start-ScheduledTask -TaskName $TaskName

$deadline = (Get-Date).AddMinutes(2)
do {
    Start-Sleep -Seconds 5
    $state = (Get-ScheduledTask -TaskName $TaskName).State
    $after = if (Test-Path $LogFile) { (Get-Item $LogFile).Length } else { -1 }
} while ($state -eq "Running" -and $after -eq $before -and (Get-Date) -lt $deadline)

$info = Get-ScheduledTaskInfo -TaskName $TaskName

if ($after -ne $before) {
    $line = (Get-Content $LogFile -Tail 1)
    Write-Host "First run logged: $line" -ForegroundColor Green
    if ($line -match "nothing to unseal") {
        Write-Host "  Vault is not running, so this run proves the task fires but not" -ForegroundColor Yellow
        Write-Host "  that it can reach Vault. Re-run once the stack is up." -ForegroundColor Yellow
    }
} elseif ($info.LastTaskResult -eq 0) {
    Write-Host "Task completed but wrote nothing to $LogFile." -ForegroundColor Yellow
    Write-Host "  Run the unsealer by hand to see why:" -ForegroundColor Yellow
    Write-Host "  powershell -NoProfile -ExecutionPolicy Bypass -File `"$unsealer`"" -ForegroundColor Yellow
} else {
    Write-Host "First run returned $($info.LastTaskResult) and logged nothing." -ForegroundColor Red
    Write-Host "  If this is a SYSTEM task, the likeliest cause is that SYSTEM cannot" -ForegroundColor Yellow
    Write-Host "  reach the Docker Desktop pipe. Re-run without -AsSystem." -ForegroundColor Yellow
}
