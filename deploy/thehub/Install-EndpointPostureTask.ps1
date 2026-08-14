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
    [string]$TaskName = "TheHub Endpoint Posture",

    # Where the collector writes, and therefore where this looks to confirm a
    # run actually produced something. Passed through to the collector rather
    # than left to its own default, so the two cannot disagree about the path
    # and report a working collection as a silent one.
    [string]$DataDir = "C:\Users\tgb_\Documents\Projects\TheHub-main\data"
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
    -Argument ('-NoProfile -ExecutionPolicy Bypass -File "{0}" -Once -DataDir "{1}"' -f $collector, $DataDir)

# Repeating one-time trigger rather than a daily schedule: posture that is
# only true once a day is posture nobody can act on.
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
    -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)

# IgnoreNew so a slow collection cannot stack instances -- the deploy agent
# was found wedged in exactly that state earlier. StartWhenAvailable so a
# missed run on a sleeping machine is picked up rather than skipped silently.
#
# AllowStartIfOnBatteries / DontStopIfGoingOnBatteries because Windows
# defaults both the other way: a task registered without them refuses to run
# on battery and returns 0x800710E0, "the operator or administrator has
# refused the request" -- a message that sends you looking for a permissions
# problem that does not exist. Observed on the first run here.
#
# For a security posture collector those defaults are exactly wrong. A laptop
# on battery is not a laptop that has stopped needing Defender to be on, and a
# collector that quietly stops is worse than one that never started: the
# widget keeps showing the last reading, which ages into a confident lie. The
# capability reports staleness past two hours, but only if something is still
# collecting to compare against.
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -StartWhenAvailable `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

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
#
# Wait for any in-flight instance to finish first. Registering and immediately
# starting, twice in quick succession, left two collectors running and
# MultipleInstances=IgnoreNew refused the third with 0x800710E0 -- reported
# here as "first run returned 2147946720", which reads as a permissions
# failure and is really "it is already doing what you asked".
Write-Host "Running it once now..." -ForegroundColor Cyan

while ((Get-ScheduledTask -TaskName $TaskName).State -eq "Running") {
    Write-Host "  waiting for the instance already running..." -ForegroundColor DarkGray
    Start-Sleep -Seconds 10
}

# Watch the artefact, not the exit code. The question is whether posture got
# collected, and the file answers it directly.
$posture = Join-Path $DataDir "endpoint-posture.json"
$before = if (Test-Path $posture) { (Get-Item $posture).LastWriteTime } else { [datetime]::MinValue }

Start-ScheduledTask -TaskName $TaskName

# Four minutes, not ninety seconds. A full collection measured ~80s on the
# machine this was written for -- Get-HotFix and the WMI probes dominate -- so
# a 90s deadline was a coin toss that reported a working task as broken.
$deadline = (Get-Date).AddMinutes(4)
do {
    Start-Sleep -Seconds 10
    $state = (Get-ScheduledTask -TaskName $TaskName).State
    $after = if (Test-Path $posture) { (Get-Item $posture).LastWriteTime } else { [datetime]::MinValue }
} while ($state -eq "Running" -and $after -eq $before -and (Get-Date) -lt $deadline)

$info = Get-ScheduledTaskInfo -TaskName $TaskName

if ($after -ne $before) {
    Write-Host "First run collected posture at $after." -ForegroundColor Green
} elseif ($info.LastTaskResult -eq 0) {
    Write-Host "Task completed but wrote nothing to $posture." -ForegroundColor Yellow
    Write-Host "  Run the collector by hand to see why:" -ForegroundColor Yellow
    Write-Host "  powershell -NoProfile -ExecutionPolicy Bypass -File `"$collector`" -Once" -ForegroundColor Yellow
} else {
    Write-Host "First run returned $($info.LastTaskResult) and collected nothing." -ForegroundColor Yellow
    Write-Host "  powershell -NoProfile -ExecutionPolicy Bypass -File `"$collector`" -Once" -ForegroundColor Yellow
}
