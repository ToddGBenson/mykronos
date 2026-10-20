#Requires -Version 7.2
<#
.SYNOPSIS
    Register the daily tasks that keep host and LAN control observations fresh
    (TheHub #60834).

.DESCRIPTION
    Run by the operator, once, in their own PowerShell prompt. Nothing runs this
    for you. Re-running it replaces the tasks (idempotent).

    An observation lowers an environmental CVSS score only while it is no older
    than 14 days (control_observations.FRESH_DAYS). The internet collector runs
    inside the backend (the `exposure` job, every 6 hours). The host and LAN
    collectors run on this Windows host, so they need a Scheduled Task each:

      "Mykronos Observations (host, <owner/repo>)"   daily 05:00
          Publish-ControlObservations.ps1, one task per -HostRepo.
      "Mykronos Observations (LAN, <owner/repo>)"    daily 05:30
          python -m mykronos.lan_scan. Registered ONLY when -LanCidr and
          -LanAuthorizationReference are both given: there is no default
          range and no scan without an authorization (spec 14 section 3).

    Both run Invoke-ControlObservationCollector.ps1, which reads the ingestion
    and gate tokens from backend\.env when the task fires. The task definition
    names the .env KEY, never the value, so no token is written into Task
    Scheduler. backend\.env is where repair-ingestion-token.ps1 delivers a
    rotated token, so a rotation needs no re-registration.

    DAILY, because 14 days is the window: a daily run survives thirteen missed
    days (a powered-off week, Docker Desktop down) before any lowering lapses,
    and the host's ports and tunnel change on deploys, not by the hour.
    05:00/05:30 is after the backup create (03:00) and verify (04:00).

    LogonType Interactive, not Password: the host collector reads Docker
    Desktop, which runs only while this user is logged on, and nothing here
    needs a stored Windows password (unlike the backup tasks, which need DPAPI).
    StartWhenAvailable picks up a run missed while logged off at the next
    logon. MultipleInstances IgnoreNew; a 15-minute limit on host, 90 on LAN
    (lan_scan's own nmap timeout is 60).

    Before registering, each task's inputs are checked with the collector's
    -DryRun; a missing token key or nmap is a warning here and a refusal (exit
    2, in Last Run Result and the log) when the task fires.

    Supports -WhatIf.

.EXAMPLE
    pwsh -File deploy/concourse/Register-ControlObservationTasks.ps1 -WhatIf
    pwsh -File deploy/concourse/Register-ControlObservationTasks.ps1
    pwsh -File deploy/concourse/Register-ControlObservationTasks.ps1 -LanCidr 192.168.0.14/32,192.168.0.20/32 -LanAuthorizationReference "CHG-17: Todd authorised a daily scan of his own hosts, 2026-10-20"

.NOTES
    ASCII only -- see setup.ps1.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string[]] $HostRepo = @('ToddGBenson/mykronos'),
    [string] $HostAt = '05:00',
    [string[]] $LanCidr = @(),
    [string] $LanAuthorizationReference = '',
    [string] $LanRepo = 'ToddGBenson/mykronos',
    [string] $LanAt = '05:30',
    [string] $MykronosUrl = 'http://127.0.0.1:8100',
    [string] $EnvFile = (Join-Path $PSScriptRoot '..\..\backend\.env'),
    [string] $Python = (Join-Path $PSScriptRoot '..\..\backend\.venv\Scripts\python.exe'),
    [string] $Nmap = $(if (Test-Path 'C:\Program Files (x86)\Nmap\nmap.exe') { 'C:\Program Files (x86)\Nmap\nmap.exe' } else { 'nmap' }),
    [string] $TaskPrefix = 'Mykronos Observations'
)

$ErrorActionPreference = 'Stop'

# Which backend\.env key holds each repository's ingestion token, and which
# containers are that repository's. Token keys mirror the EnvKey column of
# repair-ingestion-token.ps1's $READERS: that script is what writes them.
$REPOS = @{
    'ToddGBenson/mykronos' = @{ TokenKey = 'MYKRONOS_CONCOURSE_TOKEN'; ContainerFilter = 'mykronos-*' }
    'ToddGBenson/TheHub'   = @{ TokenKey = 'MYKRONOS_THEHUB_CONCOURSE_TOKEN'; ContainerFilter = 'thehub*' }
}

function Get-RepoEntry {
    param([string] $Repo)
    foreach ($k in $REPOS.Keys) { if ($k -ieq $Repo) { return $REPOS[$k] } }
    throw "No token key for $Repo. Add it to `$REPOS (and to repair-ingestion-token.ps1's `$READERS) rather than guessing."
}

if (($LanCidr.Count -gt 0) -xor [bool]$LanAuthorizationReference.Trim()) {
    throw 'The LAN task needs both -LanCidr and -LanAuthorizationReference (spec 14 section 3), or neither.'
}

$EnvFile = [IO.Path]::GetFullPath($EnvFile)
$Python = [IO.Path]::GetFullPath($Python)
$invoke = Join-Path $PSScriptRoot 'Invoke-ControlObservationCollector.ps1'
$pwsh = (Get-Command pwsh -ErrorAction Stop).Source

function Format-Arg {
    # One argument for the task's command line, double-quoted. Nothing passed
    # here is a secret: the tokens are read from -EnvFile at run time.
    param([string] $Value)
    return '"' + ($Value -replace '"', '\"') + '"'
}

$tasks = @()
foreach ($repo in $HostRepo) {
    $entry = Get-RepoEntry -Repo $repo
    $tasks += [pscustomobject]@{
        Name   = "$TaskPrefix (host, $repo)"
        At     = $HostAt
        Limit  = New-TimeSpan -Minutes 15
        Params = [ordered]@{ Collector = 'host'; Repo = $repo; TokenKey = $entry.TokenKey
            ContainerFilter = $entry.ContainerFilter; EnvFile = $EnvFile; MykronosUrl = $MykronosUrl }
    }
}
if ($LanCidr.Count -gt 0) {
    $entry = Get-RepoEntry -Repo $LanRepo
    $tasks += [pscustomobject]@{
        Name   = "$TaskPrefix (LAN, $LanRepo)"
        At     = $LanAt
        Limit  = New-TimeSpan -Minutes 90
        Params = [ordered]@{ Collector = 'lan'; Repo = $LanRepo; TokenKey = $entry.TokenKey
            EnvFile = $EnvFile; MykronosUrl = $MykronosUrl; Python = $Python; Nmap = $Nmap
            AuthorizationReference = $LanAuthorizationReference; Cidr = ($LanCidr -join ',') }
    }
} else {
    [Console]::Out.WriteLine('LAN task: not registered (no -LanCidr / -LanAuthorizationReference).')
}

$user = "$env:USERDOMAIN\$env:USERNAME"
foreach ($t in $tasks) {
    # Check the inputs the way the task will see them. A warning, not a stop:
    # the operator may be registering before granting `network` or installing nmap.
    $splat = @{}
    foreach ($k in $t.Params.Keys) { $splat[$k] = $t.Params[$k] }
    $null = & $invoke @splat -DryRun
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "$($t.Name): the dry run refused (see above). The task will exit 2 until that is fixed."
    }

    $argLine = '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File ' + (Format-Arg $invoke)
    foreach ($k in $t.Params.Keys) { $argLine += " -$k " + (Format-Arg $t.Params[$k]) }
    Write-Verbose "$($t.Name) arguments: $argLine"
    $action = New-ScheduledTaskAction -Execute $pwsh -Argument $argLine
    $trigger = New-ScheduledTaskTrigger -Daily -At $t.At
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew `
        -ExecutionTimeLimit $t.Limit -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
    if ($PSCmdlet.ShouldProcess($t.Name, "register daily at $($t.At) as $user")) {
        $null = Register-ScheduledTask -TaskName $t.Name -Action $action -Trigger $trigger -Settings $settings `
            -Principal $principal -Force `
            -Description 'Posts control observations to Mykronos so environmental CVSS lowerings stay within their 14-day freshness (TheHub #60834).'
        [Console]::Out.WriteLine("registered: '$($t.Name)' daily at $($t.At)")
    }
}

exit 0
