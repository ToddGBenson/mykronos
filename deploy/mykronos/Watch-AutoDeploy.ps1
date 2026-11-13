#Requires -Version 7.0
<#
.SYNOPSIS
    MyKronos deploys itself after promote (TheHub #61610). One tick of the
    "MyKronos Auto Deploy" scheduled task (Register-AutoDeploy.ps1).

.DESCRIPTION
    Every ten minutes:

      1. Reads, without changing anything: the newest succeeded build of
         Concourse mykronos/promote and its input sha (anonymous), main's
         head (git ls-remote), the sha the running backend reports and
         whether its images can be pulled back (the rollback supply), the
         deploy lock and TheHub's, Vault's seal, MemAvailable in the Docker
         VM, free memory on Windows, the clock, and the attempts memo.
      2. Decides with Get-AutoDeployDecision (AutoDeploy.ps1), a pure
         function with Pester tests. Deploy only when the promoted sha is
         main's head, is not already running, was never attempted, there is
         a way back, the lock is free, Vault is unsealed, both memory floors
         hold and it is outside quiet hours.
      3. Appends the decision to decisions.jsonl in -StateDir. Always.
      4. Counts how many ticks in a row the same BLOCKING reason has been
         the headline (streak.json). At 6 (an hour) it says so once: a
         `stuck` line in the JSONL and, in Live, one failed host-job run and
         one Hub incident. A lock left by a killed run, a sealed Vault or an
         unreadable Docker is then not a silent skip forever.

    -Mode DryRun (THE DEFAULT) stops after the decision: nothing is run,
    nothing is written to the Hub, the attempts memo is not touched.

    -Mode Live, on Deploy:
      - takes the deploy lock (DeployLock.ps1, shared with deploy.ps1) for
        the whole attempt, and records the sha in attempts.json as
        'started' BEFORE anything runs, so a watcher that dies mid-deploy
        has spent the attempt and the next tick does not stack a second run;
      - runs `deploy.ps1 -Tag <full sha> -Registry localhost:5000` in a
        child pwsh -NonInteractive (a prompt fails instead of hanging), its
        output to deploy-<sha12>-<stamp>.log. deploy.ps1 asks the risk gate,
        pulls, brings compose up, waits for health and, when it confirms the
        sha, runs the Hub deploy recorder named in backend/.env;
      - judges it afterwards with Get-AutoDeployOutcome (pure, tested):
          success               healthy on the new sha, exit 0
          success_with_warning  healthy on the new sha, non-zero exit: no
                                rollback of a healthy, correct stack
          not_attempted         deploy.ps1 stopped before changing the stack
                                (the gate refused or never answered, a pull
                                failed, exit 75): production is unchanged,
                                and the sha's one attempt is NOT spent
          failed                the stack changed and is not healthy on the
                                new sha: ROLL BACK
          timeout               still running at -DeployTimeoutMin
      - rolls back by running deploy.ps1 again with the tag of the sha that
        ran before (deploy.ps1's documented rollback: "the same command
        with the previous sha"), with -GateWaitMinutes 0;
      - reports ONE host-job run at the end (actor Watch-AutoDeploy, kind
        deploy; no "started ok" run that could read as a success) and, on
        anything but success, one Hub incident (room devops).

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
      1   the deploy failed (rolled back or not), or deploy.ps1 stopped
          before changing anything (not_attempted: retried next tick)
      75  another deploy held the lock (between deciding and starting, or
          inside deploy.ps1)
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
    [ValidateRange(2, 1000)][int]$StuckTicks = 6,
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
$streakFile = Join-Path $StateDir 'streak.json'
$deployScript = Join-Path $here 'deploy.ps1'
$repoRoot = (Resolve-Path (Join-Path $here '..\..')).Path
$pwshPath = (Get-Process -Id $PID).Path
$hostJob = 'mykronos-auto-deploy'
$actor = 'Watch-AutoDeploy'

function Get-Short([string]$Sha) { if ($Sha -and $Sha.Length -gt 12) { return $Sha.Substring(0, 12) } return $Sha }
function Get-Stamp([DateTime]$At) { return $At.ToString('yyyy-MM-ddTHH:mm:ssZ') }

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

function Send-HostJobRun {
    # One run per attempt, at the end, naming who ran it and what kind of
    # job it was. There is deliberately no "started, ok" run: a watcher
    # that dies mid-deploy must never leave a success behind it.
    param([bool]$Ok, [string]$ErrorText, [hashtable]$Summary, [int]$DurationMs = 0)
    $s = @{ actor = $actor; kind = 'deploy' }
    foreach ($k in $Summary.Keys) { $s[$k] = $Summary[$k] }
    $body = @{ ok = $Ok; duration_ms = $DurationMs; summary = $s }
    if ($ErrorText) { $body.error = $ErrorText }
    try {
        Invoke-Hub -Method 'POST' -Path "/api/ops/host-jobs/$hostJob/run" -Body $body | Out-Null
        return 'recorded'
    } catch {
        $m = $_.Exception.Message
        if ($m -match '422') { $m = "the Hub has no '$hostJob' host job allow-listed yet" }
        Write-Host "WARN run not recorded in the Hub: $m" -ForegroundColor Yellow
        return "not recorded: $m"
    }
}

function Open-DeployIncident {
    # One open incident per source_ref: a sha's deploy, or a stuck reason.
    param([string]$Ref, [string]$Title, [string]$Detail, [string]$Severity = 'error')
    try {
        $open = @(Invoke-Hub -Method 'GET' -Path '/api/ops/devops/incidents?limit=100' -Body $null)
        $already = $open | Where-Object {
            ([string]$_.source_ref) -eq $Ref -and ([string]$_.status) -notin @('resolved', 'closed')
        } | Select-Object -First 1
        if ($already) { return "already open: #$($already.id)" }
    } catch {
        Write-Host "WARN could not list incidents: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    $body = @{
        room = 'devops'; severity = $Severity; priority = $(if ($Severity -eq 'error') { 'high' } else { 'medium' })
        title = $Title
        impact = $Title.Substring(0, [Math]::Min(64, $Title.Length))
        detail = ($Detail + " Stop it: Disable-ScheduledTask -TaskName 'MyKronos Auto Deploy'.")
        source_capability = 'auto_deploy'
        source_ref = $Ref
        tags = @('auto-deploy', 'deploy', 'mykronos')
    }
    try {
        $inc = Invoke-Hub -Method 'POST' -Path '/api/incidents' -Body $body
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

function Invoke-StreakTick([string]$Reason, [string]$Detail, [string]$Sha) {
    # Reads streak.json, counts this tick, and on the tick the same blocking
    # reason reaches -StuckTicks says so once (JSONL always; the Hub in Live).
    $prev = $null
    try {
        if (Test-Path -LiteralPath $streakFile) { $prev = Get-Content -LiteralPath $streakFile -Raw | ConvertFrom-Json }
    } catch { $prev = $null }
    $streak = Step-AutoDeployStreak -Previous $prev -Reason $Reason -Threshold $StuckTicks
    try {
        Set-Content -LiteralPath $streakFile -Encoding ascii -Value (
            [ordered]@{ Reason = $streak.Reason; Count = $streak.Count; Alerted = $streak.Alerted } | ConvertTo-Json -Compress)
    } catch { Write-Host "WARN streak.json not written: $($_.Exception.Message)" -ForegroundColor Yellow }
    if (-not $streak.Alert) { return }
    $minutes = $streak.Count * 10
    $text = "MyKronos auto-deploy stuck: $Reason for $($streak.Count) ticks (~$minutes min)"
    $hub = 'not sent (DryRun)'
    $incident = $null
    if ($Mode -eq 'Live') {
        $hub = Send-HostJobRun -Ok $false -ErrorText "$text. $Detail" -Summary @{ phase = 'stuck'; reason = $Reason; ticks = $streak.Count; sha = (Get-Short $Sha) }
        $incident = Open-DeployIncident -Ref "mykronos-auto-deploy:stuck:$Reason" -Title $text -Detail (
            "Every tick for about $minutes minutes has skipped with '$Reason': $Detail " +
            "The watcher keeps skipping until the cause is cleared. Read decisions.jsonl in $StateDir.")
    }
    Write-AutoDeployJsonl -Path $jsonl -Entry @{ event = 'stuck'; mode = $Mode; reason = $Reason; sha = $Sha
        ticks = $streak.Count; detail = $Detail; hub = $hub; incident = $incident }
    Write-Host "STUCK $Reason for $($streak.Count) ticks" -ForegroundColor Red
}

# ---------------------------------------------------------------- collect

$tickStart = [DateTime]::UtcNow
$promote = Get-PromotedSha -ConcourseUrl $ConcourseUrl
$mainHead = Get-MainHead -RepoRoot $repoRoot
$running = Get-RunningSha
$rollbackSupply = Get-RollbackImage -Sha $running -Registry $Registry
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
    $why = "attempts.json could not be parsed: $($_.Exception.Message)"
    Write-AutoDeployJsonl -Path $jsonl -Entry @{ event = 'decision'; mode = $Mode; action = 'Skip';
        reason = 'attempts_unread'; detail = $why }
    Write-Host "SKIP attempts_unread: $attemptsFile could not be parsed" -ForegroundColor Yellow
    Invoke-StreakTick -Reason 'attempts_unread' -Detail $why -Sha $promote.Sha
    exit 3
}

$decision = Get-AutoDeployDecision -PromotedSha $promote.Sha -MainHead $mainHead -RunningSha $running `
    -LockHeld $lockHeld -OtherDeployRunning $otherHeld -VaultSealed $sealed -VmFreeMB $vmFree `
    -WindowsFreeMB $winFree -NowUtc $tickStart -Attempts $attempts -RollbackAvailable $rollbackSupply.Available `
    -Mode $Mode

$inputs = [ordered]@{
    promoted_sha = $promote.Sha; promote_build = $promote.Build; main_head = $mainHead; running_sha = $running
    rollback_available = $rollbackSupply.Available; rollback_tag = $rollbackSupply.Tag; rollback_detail = $rollbackSupply.Detail
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
Invoke-StreakTick -Reason $decision.Reason -Detail $decision.Detail -Sha $decision.Sha

if ($decision.Action -ne 'Deploy') { exit 3 }
if (-not $decision.Execute) { exit 0 }

# ---------------------------------------------------------------- deploy (Live)

$sha = $decision.Sha
$s12 = Get-Short $sha
$previous = $running
$previousTag = $rollbackSupply.Tag
$lock = Enter-MykronosDeployLock -Holder "Watch-AutoDeploy.ps1 $s12"
if (-not $lock.Acquired) {
    $owner = Format-MykronosDeployLockOwner $lock.Owner
    $hub = Send-HostJobRun -Ok $false -ErrorText "lost the deploy lock to $owner before starting $s12" -Summary @{
        phase = 'end'; sha = $s12; result = 'lost_lock'; exit = 75 }
    Write-AutoDeployJsonl -Path $jsonl -Entry @{ event = 'deploy'; mode = $Mode; sha = $sha; result = 'lost_lock'; exit = 75
        detail = "lock taken between deciding and starting by $owner"; hub = $hub }
    exit 75
}

$exitCode = 1
$timedOut = $false
try {
    $env:MYKRONOS_DEPLOY_LOCK_TOKEN = $lock.Token
    Save-AutoDeployAttempt -Path $attemptsFile -Sha $sha -Result 'started' -Extra @{ previous = $previous; previous_tag = $previousTag }
    $startUtc = [DateTime]::UtcNow
    $stamp = $startUtc.ToString('yyyyMMddTHHmmssZ')
    $deployLog = Join-Path $StateDir "deploy-$s12-$stamp.log"
    Write-AutoDeployJsonl -Path $jsonl -Entry @{ event = 'deploy_start'; mode = $Mode; sha = $sha
        previous = $previous; previous_tag = $previousTag; log = $deployLog }
    Write-Host "DEPLOY $s12 (previous $(Get-Short $previous), rollback tag $previousTag): deploy.ps1 -Tag $sha -Registry $Registry; output $deployLog"

    # The remote-tracking ref only; the working tree does not move. deploy.ps1
    # reads commits in this checkout (the nearest-scored walk, the Hub
    # recorder's since..sha range), and a checkout that never fetched H
    # would read none of them.
    & git -C $repoRoot fetch --quiet origin '+refs/heads/main:refs/remotes/origin/main' 2>$null
    if ($LASTEXITCODE -ne 0) { Write-Host "WARN git fetch origin main exit $LASTEXITCODE; deploying anyway" -ForegroundColor Yellow }

    $code = Invoke-DeployScript -Tag $sha -LogPath $deployLog
    $deployEnd = [DateTime]::UtcNow
    $after = Get-StackState
    if ($SimulateFailedHealth) { Write-Host 'SimulateFailedHealth: treating the post-deploy check as failed.' -ForegroundColor Yellow }
    $outcome = Get-AutoDeployOutcome -Code $code -HealthyOnNew (Test-StackOn $after $sha) `
        -HealthyOnPrevious ([bool]$previous -and (Test-StackOn $after $previous)) `
        -PreviousKnown ([bool]$previousTag) -Simulate ([bool]$SimulateFailedHealth)
    $result = $outcome.Result
    $rollback = 'not-needed'
    $rollbackCode = $null
    $rollbackLog = $null
    if ($result -eq 'timeout') {
        $timedOut = $true
        $rollback = 'not-attempted (deploy.ps1 still running)'
    } elseif ($result -eq 'failed' -and -not $outcome.Rollback) {
        $rollback = 'impossible (no previous tag was recorded)'
    } elseif ($outcome.Rollback) {
        Write-Host "Health check failed for $s12 (backend=$($after.Backend) frontend=$($after.Frontend) sha=$(Get-Short $after.Sha)); rolling back to $previousTag." -ForegroundColor Red
        $rollbackLog = Join-Path $StateDir "rollback-$s12-to-$(Get-Short $previousTag)-$stamp.log"
        $rollbackCode = Invoke-DeployScript -Tag $previousTag -LogPath $rollbackLog -Extra @('-GateWaitMinutes', '0')
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

    # not_attempted gives the sha back: the next tick may try it again.
    Save-AutoDeployAttempt -Path $attemptsFile -Sha $sha -Result $result -Extra @{
        previous = $previous; previous_tag = $previousTag; exit = $code; why = $outcome.Why }
    $ok = ($result -in @('success', 'success_with_warning'))
    $hub = Send-HostJobRun -Ok $ok -ErrorText $(if (-not $ok) { "deploy $s12 $result exit ${code}: $($outcome.Why); rollback $rollback" } else { $null }) -Summary @{
        phase = 'end'; sha = $s12; previous = (Get-Short $previous); result = $result; exit = $code
        rollback = $rollback; started_at = (Get-Stamp $startUtc); deploy_finished_at = (Get-Stamp $deployEnd)
        finished_at = (Get-Stamp $endUtc); simulated_failure = [bool]$SimulateFailedHealth
    } -DurationMs $durationMs
    $incident = $null
    if ($result -ne 'success') {
        $retry = $(if ($outcome.Counted) {
                "The watcher will not retry $s12 (one attempt per sha); a new promoted main head re-arms it, or remove $s12 from attempts.json in $StateDir."
            } else {
                "Nothing changed, so $s12 is not counted as attempted and the next tick that passes every rule tries it again."
            })
        # success_with_warning: the deploy succeeded (healthy on H) and a
        # later step failed. Said as a warning, not an error.
        $sev = $(if ($result -eq 'success_with_warning') { 'warn' } else { 'error' })
        $title = $(if ($result -eq 'success_with_warning') {
                "MyKronos auto-deploy of $s12 succeeded with a warning (exit $code)"
            } else { "MyKronos auto-deploy of $s12 $result" })
        $incident = Open-DeployIncident -Ref "mykronos-auto-deploy:$sha" -Title $title -Severity $sev -Detail (
            "Watch-AutoDeploy.ps1 ran deploy.ps1 -Tag $sha -Registry $Registry. result=$result exit=$code ($($outcome.Why)) " +
            "backend=$($after.Backend) frontend=$($after.Frontend) running=$(Get-Short $after.Sha) rollback=$rollback. " +
            "Output: $deployLog" + $(if ($rollbackLog) { "; rollback output: $rollbackLog." } else { '.' }) + " $retry")
    }
    Write-AutoDeployJsonl -Path $jsonl -Entry @{
        event = 'deploy'; mode = $Mode; sha = $sha; previous = $previous; previous_tag = $previousTag; result = $result
        exit = $code; why = $outcome.Why; counted = $outcome.Counted
        backend = $after.Backend; frontend = $after.Frontend; running_after = $after.Sha
        rollback = $rollback; rollback_exit = $rollbackCode; simulated_failure = [bool]$SimulateFailedHealth
        started_at = (Get-Stamp $startUtc); finished_at = (Get-Stamp $endUtc)
        duration_ms = $durationMs; log = $deployLog; rollback_log = $rollbackLog; hub = $hub; incident = $incident
    }
    Write-Host "RESULT $s12 $result exit=$code rollback=$rollback ($([int]($durationMs / 1000)) s)"
    $exitCode = $(if ($ok) { 0 } elseif ($timedOut) { 124 } elseif ($code -eq 75) { 75 } else { 1 })
} finally {
    Remove-Item Env:\MYKRONOS_DEPLOY_LOCK_TOKEN -ErrorAction SilentlyContinue
    # A deploy.ps1 still running keeps the lock: releasing it would let the
    # next tick, or a hand deploy, start beside it.
    if (-not $timedOut) { Exit-MykronosDeployLock $lock }
}
exit $exitCode
