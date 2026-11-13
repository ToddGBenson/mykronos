#Requires -Version 7.0
<#
.SYNOPSIS
    Create or update the "MyKronos Auto Deploy" scheduled task (TheHub #61610).

.DESCRIPTION
    RUN THIS YOURSELF, from a PowerShell 7 prompt in the production checkout,
    after the PR is merged and the checkout is on that main. Nothing in the
    repository registers it.

        # see what it would register, touching nothing:
        .\deploy\mykronos\Register-AutoDeploy.ps1 -DryRun -WhatIf

        # FIRST: decide and log every 10 minutes, never deploy
        .\deploy\mykronos\Register-AutoDeploy.ps1 -DryRun

        # after reading a day of decisions.jsonl: deploy for real
        .\deploy\mykronos\Register-AutoDeploy.ps1 -Live

    Re-running it replaces the task, so switching mode is the same command.

    WHAT IT REGISTERS
      Name       MyKronos Auto Deploy
      Every      10 minutes, indefinitely, starting a minute from now
      Runs       pwsh -NoProfile -NonInteractive -File Watch-AutoDeploy.ps1 -Mode <DryRun|Live>
      As         you, S4U (runs whether or not you are logged on, stores no
                 password), limited rights: nothing here needs elevation.
                 -UsePassword stores your password instead, if S4U cannot
                 reach Docker on this host.
      Instances  IgnoreNew: a tick that fires during a deploy is dropped,
                 never queued and never run beside it
      Limit      3 hours per run

    STOP IT
      Disable-ScheduledTask -TaskName 'MyKronos Auto Deploy'     # pause
      Unregister-ScheduledTask -TaskName 'MyKronos Auto Deploy' -Confirm:$false   # remove
      .\deploy\mykronos\Register-AutoDeploy.ps1 -DryRun          # back to decide-and-log
#>
[CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'DryRun')]
param(
    [Parameter(ParameterSetName = 'DryRun', Mandatory = $true)][switch]$DryRun,
    [Parameter(ParameterSetName = 'Live', Mandatory = $true)][switch]$Live,
    [string]$TaskName = 'MyKronos Auto Deploy',
    [ValidateRange(5, 120)][int]$IntervalMin = 10,
    [switch]$UsePassword
)

$ErrorActionPreference = 'Stop'
$watcher = Join-Path $PSScriptRoot 'Watch-AutoDeploy.ps1'
foreach ($f in @($watcher, (Join-Path $PSScriptRoot 'AutoDeploy.ps1'), (Join-Path $PSScriptRoot 'DeployLock.ps1'))) {
    if (-not (Test-Path -LiteralPath $f)) { throw "not found: $f (is this checkout on a main that has TheHub #61610?)" }
}
$pwsh = (Get-Command pwsh.exe -ErrorAction SilentlyContinue).Source
if (-not $pwsh) { throw 'pwsh.exe (PowerShell 7) is not on PATH; the watcher needs it.' }
$tokenFile = Join-Path $HOME '.mykronos-agents\mykronos-auto-deploy-hub.token'
if (-not (Test-Path -LiteralPath $tokenFile)) {
    Write-Warning "No Hub token at $tokenFile. Decisions are still logged; Live runs will not be reported to the Hub and incidents will not be opened until it exists."
}

$mode = $(if ($Live) { 'Live' } else { 'DryRun' })
$argLine = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Mode {1}' -f $watcher, $mode
$action = New-ScheduledTaskAction -Execute $pwsh -Argument $argLine -WorkingDirectory $PSScriptRoot
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes $IntervalMin)
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 3)
$user = "$env:USERDOMAIN\$env:USERNAME"
$logon = $(if ($UsePassword) { 'Password' } else { 'S4U' })
$stateDir = Join-Path $env:LOCALAPPDATA 'mykronos\auto-deploy'

Write-Host "Task   : $TaskName"
Write-Host "Every  : $IntervalMin minutes (IgnoreNew, 3 h limit)"
Write-Host "Runs   : $pwsh $argLine"
Write-Host "As     : $user ($logon, limited)"
if ($Live) {
    Write-Host 'Mode   : LIVE - a promoted main head is deployed by the next tick that passes every rule' -ForegroundColor Yellow
} else {
    Write-Host 'Mode   : DRY RUN - decides and logs only; nothing is deployed'
}

if ($PSCmdlet.ShouldProcess($TaskName, "register every $IntervalMin minutes, mode $mode")) {
    if ($UsePassword) {
        $cred = Get-Credential -UserName $user -Message "Password for the '$TaskName' task"
        $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Password -RunLevel Limited
    } else {
        $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType S4U -RunLevel Limited
    }
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Write-Host 'Existing task found; replacing it.'
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
    $taskArgs = @{
        TaskName    = $TaskName
        Action      = $action
        Trigger     = $trigger
        Settings    = $settings
        Principal   = $principal
        Description = "MyKronos deploys itself after Concourse promote (TheHub #61610). Mode $mode. Stop: Disable-ScheduledTask -TaskName '$TaskName'."
    }
    if ($UsePassword) { $taskArgs['User'] = $user; $taskArgs['Password'] = $cred.GetNetworkCredential().Password }
    Register-ScheduledTask @taskArgs | Out-Null
    Write-Host "Registered '$TaskName' ($mode). First run in about a minute."
}

Write-Host ''
Write-Host 'Read it:'
Write-Host "  (Get-ScheduledTaskInfo -TaskName '$TaskName').LastTaskResult    # 0 deploy/would, 3 skip, 1 failed, 75 lock, 124 still running"
Write-Host "  Get-Content '$stateDir\decisions.jsonl' -Tail 20 | ForEach-Object { `$_ | ConvertFrom-Json } | Format-Table at,mode,action,reason,sha"
Write-Host 'Stop it:'
Write-Host "  Disable-ScheduledTask -TaskName '$TaskName'"
Write-Host "  Unregister-ScheduledTask -TaskName '$TaskName' -Confirm:`$false"
