#Requires -Version 7.0
<#
.SYNOPSIS
    MyKronos deploys itself after promote (TheHub #61610). One tick of the
    "MyKronos Auto Deploy" scheduled task (Register-AutoDeploy.ps1).

.DESCRIPTION
    Every ten minutes:

      1. Reads, without changing anything: the newest succeeded build of
         Concourse mykronos/promote and its input sha (anonymous), main's
         head (git ls-remote), the sha the running backend reports, the
         deploy lock and TheHub's, Vault's seal, MemAvailable in the Docker
         VM, free memory on Windows, the clock, and the attempts memo.
      2. Decides with Get-AutoDeployDecision (AutoDeploy.ps1), a pure
         function with Pester tests. Deploy only when the promoted sha is
         main's head, is not already running, was never attempted, the lock
         is free, Vault is unsealed, both memory floors hold and it is
         outside quiet hours.
      3. Appends the decision to decisions.jsonl in -StateDir. Always.

    -Mode DryRun (THE DEFAULT) stops there: nothing is run, nothing is
    written to the Hub, the attempts memo is not touched.

    -Mode Live, on Deploy:
      - takes the deploy lock (DeployLock.ps1, shared with deploy.ps1) for
        the whole attempt, and records the sha in attempts.json as
        'started' BEFORE anything runs: one attempt per sha, whatever the
        result, so a failure is never retried in a loop and a success is
        never re-run over a hand rollback;
      - runs `deploy.ps1 -Tag <full sha> -Registry localhost:5000` in a
        child pwsh -NonInteractive (a prompt fails instead of hanging), its
        output to deploy-<sha12>-<stamp>.log. deploy.ps1 asks the risk gate,
        pulls, brings compose up, waits for health and, when it confirms the
        sha, runs the Hub deploy recorder named in backend/.env;
      - judges it afterwards on its own: both containers healthy and the
        backend reporting the sha;
      - on a failure that left the stack changed, ROLLS BACK by running
        deploy.ps1 again with the sha that was running before (deploy.ps1's
        documented rollback: "the same command with the previous sha"),
        with -GateWaitMinutes 0;
      - reports the run to the Hub host job and, on anything but success,
        opens one Hub incident (room devops).

.PARAMETER Mode
    DryRun (default) or Live.

.PARAMETER SimulateFailedHealth
    Live only. Treat the post-deploy check as failed even when it passed, so
    the rollback path runs for real (story acceptance criterion 3). Never
    set by the scheduled task.

.NOTES
    Exit codes, so LastTaskResult means something:
      0   deployed and confirmed (DryRun: would deploy)
      3   skipped; the reason is in decisions.jsonl
      1   the deploy failed (rolled back or not: see the JSONL and the incident)
      75  lost the lock to another deploy between deciding and starting
      124 deploy.ps1 still running after -DeployTimeoutMin; left running,
          the lock left held for a person
    ASCII only.
#>
[CmdletBinding()]
param(
    [ValidateSet('DryRun', 'Live')]
    [string]$Mode = 'DryRun',
    [string]$StateDir = '',
    [string]$ConcourseUrl = 'http://127.0.0.1:8080',
    [string]$HubUrl = 'http://127.0.0.1:8000',
    [string]$HubTokenFile = '',
    [string]$Registry = 'localhost:5000',
    [ValidateRange(10, 600)][int]$DeployTimeoutMin = 90,
    [string]$TheHubLockDir = '',
    [switch]$SimulateFailedHealth
)

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
. (Join-Path $here 'AutoDeploy.ps1')
. (Join-Path $here 'DeployLock.ps1')

if (-not $StateDir) { $StateDir = Join-Path $env:LOCALAPPDATA 'mykronos\auto-deploy' }
if (-not $HubTokenFile) { $HubTokenFile = Join-Path $HOME '.mykronos-agents\mykronos-auto-deploy-hub.token' }
if (-not $TheHubLockDir) { $TheHubLockDir = Join-Path $env:LOCALAPPDATA 'Temp\thehub-deploy.lock' }
if (-not (Test-Path -LiteralPath $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }

$jsonl = Join-Path $StateDir 'decisions.jsonl'
$attemptsFile = Join-Path $StateDir 'attempts.json'
$deployScript = Join-Path $here 'deploy.ps1'
$repoRoot = (Resolve-Path (Join-Path $here '..\..')).Path
$pwshPath = (Get-Process -Id $PID).Path
$hostJob = 'mykronos-auto-deploy'

function Get-Short([string]$Sha) { if ($Sha -and $Sha.Length -gt 12) { return $Sha.Substring(0, 12) } return $Sha }

function Invoke-Hub {
    # The agent credential in -HubTokenFile, never the admin token. Absent,
    # the Hub is simply not told; decisions.jsonl is the durable record.
    param([string]$Method, [string]$Path, $Body)
    if (-not (Test-Path -LiteralPath $HubTokenFile)) { throw "no Hub token at $HubTokenFile" }
    $token = ([IO.File]::ReadAllText($HubTokenFile)).Trim()
    if (-not $token) { throw "empty Hub token file $HubTokenFile" }
    $a = @{ Method = $Method; Uri = ($HubUrl.TrimEnd('/') + $Path); TimeoutSec = 30
        Headers = @{ 'X-Hub-Token' = $token } }
    if ($null -ne $Body) {
        $a.Body = [Text.Encoding]::UTF8.GetBytes(($Body | ConvertTo-Json -Depth 8 -Compress))
        $a.ContentType = 'application/json; charset=utf-8'
    }
    $r = Invoke-RestMethod @a
    return $r
}

function Send-HostJobRun([bool]$Ok, [string]$ErrorText, [hashtable]$Summary, [int]$DurationMs) {
    $body = @{ ok = $Ok; duration_ms = $DurationMs; summary = $Summary }
    if ($ErrorText) { $body.error = $ErrorText }
    try {
        Invoke-Hub 'POST' "/api/ops/host-jobs/$hostJob/run" $body | Out-Null
        return 'recorded'
    } catch {
        $m = $_.Exception.Message
        if ($m -match '422') { $m = "the Hub has no '$hostJob' host job allow-listed yet" }
        Write-Host "WARN run not recorded in the Hub: $m" -ForegroundColor Yellow
        return "not recorded: $m"
    }
}

function Open-DeployIncident([string]$Sha, [string]$Result, [string]$Detail) {
    $ref = "mykronos-auto-deploy:$Sha"
    try {
        $open = @(Invoke-Hub 'GET' '/api/ops/devops/incidents?limit=100' $null)
        $already = $open | Where-Object {
            ([string]$_.source_ref) -eq $ref -and ([string]$_.status) -notin @('resolved', 'closed')
        } | Select-Object -First 1
        if ($already) { return "already open: #$($already.id)" }
    } catch {
        Write-Host "WARN could not list incidents: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    $s12 = Get-Short $Sha
    $body = @{
        room = 'devops'; severity = 'error'; priority = 'high'
        title = "MyKronos auto-deploy of $s12 $Result"
        impact = ("mykronos auto-deploy $s12 $Result").Substring(0, [Math]::Min(64, ("mykronos auto-deploy $s12 $Result").Length))
        detail = ($Detail + " The watcher will not retry $s12 (one attempt per sha); a new promoted main head re-arms it, " +
            "or remove $s12 from attempts.json in the state dir. Stop it: Disable-ScheduledTask -TaskName 'MyKronos Auto Deploy'.")
        source_capability = 'auto_deploy'
        source_ref = $ref
        tags = @('auto-deploy', 'deploy', 'mykronos')
    }
    try {
        $inc = Invoke-Hub 'POST' '/api/incidents' $body
        return "opened: #$($inc.id)"
    } catch {
        Write-Host "ERROR incident NOT opened: $($_.Exception.Message)" -ForegroundColor Red
        return "not opened: $($_.Exception.Message)"
    }
}

function Invoke-DeployScript {
    # deploy.ps1 in a child pwsh. -NonInteractive: if anything in it ever
    # prompts, the child fails instead of waiting for a keyboard nobody is at.
    param([string]$Tag, [string]$LogPath, [string[]]$Extra = @())
    $argList = @('-NoProfile', '-NonInteractive', '-File', ('"{0}"' -f $deployScript),
        '-Tag', $Tag, '-Registry', $Registry) + $Extra
    $errPath = [IO.Path]::ChangeExtension($LogPath, '.err.log')
    $proc = Start-Process -FilePath $pwshPath -ArgumentList $argList -WorkingDirectory $here `
        -NoNewWindow -PassThru -RedirectStandardOutput $LogPath -RedirectStandardError $errPath
    $null = $proc.Handle
    if (-not $proc.WaitForExit($DeployTimeoutMin * 60 * 1000)) {
        # Not killed: a deploy.ps1 killed between compose down and up leaves
        # less running than either version. A person decides.
        return 124
    }
    $proc.WaitForExit()
    return $proc.ExitCode
}

# ---------------------------------------------------------------- collect

$tickStart = [DateTime]::UtcNow
$promote = Get-PromotedSha -ConcourseUrl $ConcourseUrl
$mainHead = Get-MainHead -RepoRoot $repoRoot
$running = Get-RunningSha
$lockPath = Get-MykronosDeployLockPath
$lockHeld = Test-Path -LiteralPath $lockPath
$otherHeld = Test-Path -LiteralPath $TheHubLockDir
$sealed = Get-VaultSealed
$vmFree = Get-VmFreeMB
$winFree = Get-WindowsFreeMB
try {
    $attempts = @(Read-AutoDeployAttemptList -Path $attemptsFile)
} catch {
    # Fail closed: an attempts memo that cannot be read must not read as
    # "never attempted".
    Write-AutoDeployJsonl -Path $jsonl -Entry @{ event = 'decision'; mode = $Mode; action = 'Skip';
        reason = 'attempts_unread'; detail = "attempts.json could not be parsed: $($_.Exception.Message)" }
    Write-Host "SKIP attempts_unread: $attemptsFile could not be parsed" -ForegroundColor Yellow
    exit 3
}
$attemptedShas = @($attempts | ForEach-Object { [string]$_.sha })

$decision = Get-AutoDeployDecision -PromotedSha $promote.Sha -MainHead $mainHead -RunningSha $running `
    -LockHeld $lockHeld -OtherDeployRunning $otherHeld -VaultSealed $sealed -VmFreeMB $vmFree `
    -WindowsFreeMB $winFree -NowUtc $tickStart -AttemptedShas $attemptedShas -Mode $Mode

$inputs = [ordered]@{
    promoted_sha = $promote.Sha; promote_build = $promote.Build; main_head = $mainHead; running_sha = $running
    lock_held = $lockHeld; thehub_lock_held = $otherHeld; vault_sealed = $sealed
    vm_free_mb = $vmFree; windows_free_mb = $winFree
}
Write-AutoDeployJsonl -Path $jsonl -Entry @{
    event = 'decision'; mode = $Mode; action = $decision.Action; reason = $decision.Reason
    detail = $decision.Detail; reasons = @($decision.Reasons | ForEach-Object { $_.Code })
    checks = @($decision.Checks); sha = $decision.Sha; inputs = $inputs
}
$prefix = $(if ($Mode -eq 'DryRun') { 'DRYRUN ' } else { '' })
foreach ($r in $decision.Reasons) { Write-Host "${prefix}skip $($r.Code): $($r.Detail)" }
Write-Host "${prefix}decision=$($decision.Action) reason=$($decision.Reason) sha=$(Get-Short $decision.Sha)"

if ($decision.Action -ne 'Deploy') { exit 3 }
if (-not $decision.Execute) { exit 0 }

# ---------------------------------------------------------------- deploy (Live)

$sha = $decision.Sha
$s12 = Get-Short $sha
$previous = $running
$lock = Enter-MykronosDeployLock -Holder "Watch-AutoDeploy.ps1 $s12"
if (-not $lock.Acquired) {
    Write-AutoDeployJsonl -Path $jsonl -Entry @{ event = 'deploy'; mode = $Mode; sha = $sha; result = 'lost_lock'
        detail = ('lock taken between deciding and starting by ' + (Format-MykronosDeployLockOwner $lock.Owner)) }
    exit 75
}

$exitCode = 1
$timedOut = $false
try {
    $env:MYKRONOS_DEPLOY_LOCK_TOKEN = $lock.Token
    Save-AutoDeployAttempt -Path $attemptsFile -Sha $sha -Result 'started' -Extra @{ previous = $previous }
    $startUtc = [DateTime]::UtcNow
    $stamp = $startUtc.ToString('yyyyMMddTHHmmssZ')
    $deployLog = Join-Path $StateDir "deploy-$s12-$stamp.log"
    Write-AutoDeployJsonl -Path $jsonl -Entry @{ event = 'deploy_start'; mode = $Mode; sha = $sha
        previous = $previous; log = $deployLog }
    Send-HostJobRun $true $null @{ phase = 'start'; sha = $s12; previous = (Get-Short $previous) } 0 | Out-Null
    Write-Host "DEPLOY $s12 (previous $(Get-Short $previous)): deploy.ps1 -Tag $sha -Registry $Registry; output $deployLog"

    # The remote-tracking ref only; the working tree does not move. deploy.ps1
    # reads commits in this checkout (the nearest-scored walk, the Hub
    # recorder's since..sha range), and a checkout that never fetched H
    # would read none of them.
    & git -C $repoRoot fetch --quiet origin '+refs/heads/main:refs/remotes/origin/main' 2>$null
    if ($LASTEXITCODE -ne 0) { Write-Host "WARN git fetch origin main exit $LASTEXITCODE; deploying anyway" -ForegroundColor Yellow }

    $code = Invoke-DeployScript -Tag $sha -LogPath $deployLog
    $deployEnd = [DateTime]::UtcNow
    $after = Get-StackState
    $healthy = Test-StackOn $after $sha
    if ($SimulateFailedHealth) {
        Write-Host 'SimulateFailedHealth: treating the post-deploy check as failed.' -ForegroundColor Yellow
        $healthy = $false
    }

    $result = 'success'
    $rollback = 'not-needed'
    $rollbackCode = $null
    $rollbackLog = $null
    if ($code -eq 124) {
        $result = 'timeout'
        $timedOut = $true
        $rollback = 'not-attempted (deploy.ps1 still running)'
    } elseif ($code -eq 0 -and $healthy) {
        $result = 'success'
    } elseif ((-not $SimulateFailedHealth) -and (Test-StackOn $after $previous)) {
        # deploy.ps1 stopped before it changed anything (the risk gate
        # refused, a pull failed): production is still the previous sha and
        # healthy, so there is nothing to roll back.
        $result = 'failed_unchanged'
    } elseif (-not $previous) {
        $result = 'failed'
        $rollback = 'impossible (no previous sha was recorded)'
    } else {
        $result = 'failed'
        Write-Host "Health check failed for $s12 (backend=$($after.Backend) frontend=$($after.Frontend) sha=$(Get-Short $after.Sha)); rolling back to $(Get-Short $previous)." -ForegroundColor Red
        $rollbackLog = Join-Path $StateDir "rollback-$s12-to-$(Get-Short $previous)-$stamp.log"
        $rollbackCode = Invoke-DeployScript -Tag $previous -LogPath $rollbackLog -Extra @('-GateWaitMinutes', '0')
        $restored = Get-StackState
        if ($rollbackCode -eq 0 -and (Test-StackOn $restored $previous)) {
            $result = 'rolled_back'
            $rollback = "ok to $(Get-Short $previous)"
        } else {
            $result = 'rollback_failed'
            $rollback = "failed to $(Get-Short $previous): exit $rollbackCode, backend=$($restored.Backend) frontend=$($restored.Frontend) sha=$(Get-Short $restored.Sha)"
            if ($rollbackCode -eq 124) { $timedOut = $true }
        }
    }
    $endUtc = [DateTime]::UtcNow
    $durationMs = [int]($endUtc - $startUtc).TotalMilliseconds

    Save-AutoDeployAttempt -Path $attemptsFile -Sha $sha -Result $result -Extra @{ previous = $previous; exit = $code }
    $hub = Send-HostJobRun ($result -eq 'success') $(if ($result -ne 'success') { "deploy $s12 $result exit $code; rollback $rollback" } else { $null }) @{
        phase = 'end'; sha = $s12; previous = (Get-Short $previous); result = $result; exit = $code
        rollback = $rollback; started_at = $startUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
        deploy_finished_at = $deployEnd.ToString('yyyy-MM-ddTHH:mm:ssZ'); finished_at = $endUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
        simulated_failure = [bool]$SimulateFailedHealth
    } $durationMs
    $incident = $null
    if ($result -ne 'success') {
        $incident = Open-DeployIncident $sha $result ("Watch-AutoDeploy.ps1 ran deploy.ps1 -Tag $sha -Registry $Registry. " +
            "result=$result exit=$code backend=$($after.Backend) frontend=$($after.Frontend) running=$(Get-Short $after.Sha) " +
            "rollback=$rollback. Output: $deployLog" + $(if ($rollbackLog) { "; rollback output: $rollbackLog." } else { '.' }))
    }
    Write-AutoDeployJsonl -Path $jsonl -Entry @{
        event = 'deploy'; mode = $Mode; sha = $sha; previous = $previous; result = $result; exit = $code
        healthy_after = [bool]$healthy; backend = $after.Backend; frontend = $after.Frontend; running_after = $after.Sha
        rollback = $rollback; rollback_exit = $rollbackCode; simulated_failure = [bool]$SimulateFailedHealth
        started_at = $startUtc.ToString('yyyy-MM-ddTHH:mm:ssZ'); finished_at = $endUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
        duration_ms = $durationMs; log = $deployLog; rollback_log = $rollbackLog; hub = $hub; incident = $incident
    }
    Write-Host "RESULT $s12 $result exit=$code rollback=$rollback ($([int]($durationMs / 1000)) s)"
    $exitCode = $(if ($result -eq 'success') { 0 } elseif ($timedOut) { 124 } else { 1 })
} finally {
    Remove-Item Env:\MYKRONOS_DEPLOY_LOCK_TOKEN -ErrorAction SilentlyContinue
    # A deploy.ps1 still running keeps the lock: releasing it would let the
    # next tick, or a hand deploy, start beside it.
    if (-not $timedOut) { Exit-MykronosDeployLock $lock }
}
exit $exitCode
