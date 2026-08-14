<#
.SYNOPSIS
    Install the Scheduled Task that collects endpoint posture for The Hub.

.DESCRIPTION
    Collect-EndpointPosture.ps1 writes data/endpoint-posture.json; something
    has to run it on a cycle. This registers that task.

    In a file rather than a block of commands to paste, because the task
    definition is configuration and configuration belongs in the repository --
    and because pasting eight lines of PowerShell into a shell that turns out
    to be bash produces a confusing detour through winget rather than an error.

.PARAMETER IntervalMinutes
    How often to collect. 15 by default; the capability treats a reading older
    than two hours as stale.

.PARAMETER AsCurrentUser
    Register under the calling account instead of SYSTEM. Works without
    elevation, and BitLocker and Secure Boot stay unreadable -- both need an
    elevated collector and return "Access denied" without one. Everything else
    collects normally.

.NOTES
    ASCII only - see deploy\concourse\setup.ps1.

    Registering a SYSTEM task needs an elevated session. Run this from a
    PowerShell started with "Run as Administrator", or pass -AsCurrentUser and
    accept two unknown probes.
#>

[CmdletBinding()]
param(
    [int]$IntervalMinutes = 15,
    [switch]$AsCurrentUser,
    [string]$TaskName = "TheHub Endpoint Posture"
)

$ErrorActionPreference = "Stop"

$collector = Join-Path $PSScriptRoot "Collect-EndpointPosture.ps1"
if (-not (Test-Path $collector)) {
    throw "Collector not found next to this script: $collector"
}

# Fail early and clearly. Register-ScheduledTask's own error for this is
# "Access is denied", which sends people to file permissions rather than to
# the elevation they actually need.
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = ([Security.Principal.WindowsPrincipal]$identity).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $AsCurrentUser -and -not $isAdmin) {
    Write-Host "Registering a SYSTEM task needs an elevated session." -ForegroundColor Red
    Write-Host "  Either: start PowerShell with 'Run as Administrator' and re-run this," -ForegroundColor Yellow
    Write-Host "  or:     re-run with -AsCurrentUser (BitLocker and Secure Boot stay unknown)." -ForegroundColor Yellow
    exit 1
}

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Write-Host "Replacing the existing '$TaskName' task." -ForegroundColor DarkGray
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument ('-NoProfile -ExecutionPolicy Bypass -File "{0}" -Once' -f $collector)

# Repeating one-time trigger rather than a daily schedule: posture that is
# only true once a day is posture nobody can act on.
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
    -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)

# IgnoreNew so a slow collection cannot stack instances -- the deploy agent
# was found wedged in exactly that state earlier. StartWhenAvailable so a
# missed run on a sleeping machine is picked up rather than skipped silently.
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -StartWhenAvailable

if ($AsCurrentUser) {
    $principal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Limited
    $who = $identity.Name
} else {
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $who = "SYSTEM (elevated)"
}

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Settings $settings -Principal $principal `
    -Description ("Collects Windows endpoint security posture for The Hub SOC dashboard. " +
                  "Writes data/endpoint-posture.json, which the container reads via the ./data bind mount.") | Out-Null

Write-Host "Registered '$TaskName' as $who, every $IntervalMinutes minutes." -ForegroundColor Green

# Run it once now rather than leaving the operator to wonder whether it works.
Write-Host "Running it once now..." -ForegroundColor Cyan
Start-ScheduledTask -TaskName $TaskName

$deadline = (Get-Date).AddSeconds(90)
do {
    Start-Sleep -Seconds 5
    $info = Get-ScheduledTaskInfo -TaskName $TaskName
    $state = (Get-ScheduledTask -TaskName $TaskName).State
} while ($state -eq "Running" -and (Get-Date) -lt $deadline)

if ($info.LastTaskResult -eq 0) {
    Write-Host "First run succeeded." -ForegroundColor Green
} else {
    Write-Host "First run returned $($info.LastTaskResult). Check the collector by hand:" -ForegroundColor Yellow
    Write-Host "  powershell -NoProfile -ExecutionPolicy Bypass -File `"$collector`" -Once" -ForegroundColor Yellow
}
