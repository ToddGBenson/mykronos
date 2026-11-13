<#
.SYNOPSIS
    The decision and the collectors behind MyKronos's scheduled deploy
    (TheHub #61610). Dot-sourced by Watch-AutoDeploy.ps1 and by the Pester
    tests in tests/.

.DESCRIPTION
    Two halves, kept apart on purpose:

    Get-AutoDeployDecision is PURE. It takes plain values (two shas, two
    booleans, two numbers, a clock, a list) and returns Deploy or Skip with
    every reason. It reads nothing and writes nothing, so every rule is
    tested without Docker, Concourse or a network (tests/AutoDeploy.Tests.ps1).

    The Get-* collectors below it are the only code that touches the host.
    Each returns a value or $null; $null means "could not ask", and the
    decision treats "could not ask" as a skip with its own reason, never as
    a pass. An unread host is not a quiet one.

    The rules, in the order the headline is chosen (every failing rule is
    reported, the first one is the headline):

      no_promoted_build     Concourse has no succeeded `promote` build to read
      main_unread           the main head could not be read
      main_ahead_of_promote main has a newer commit than the last promote:
                            wait for that commit's promote, do not ship the
                            older one over it
      running_unread        the running image's sha could not be read, so
                            there would be nothing to roll back to
      already_running       production already runs the promoted sha
      rollback_unavailable  the images of the sha production runs now are
                            not on this host and in the registry, so a
                            failed deploy would have no way back
      already_attempted     this sha was attempted before: one attempt per
                            sha. Only a run that moved the stack (or died
                            after it started) counts; a deploy.ps1 that
                            stopped before changing anything (the risk gate
                            refused or never answered, a pull failed, the
                            lock was taken: result `not_attempted`) does not
      lock_held             a MyKronos deploy holds the lock
      thehub_deploy_running TheHub's deploy holds its lock (one deploy on the
                            host at a time; they share the memory)
      vault_unread          Vault's seal state could not be read
      vault_sealed          Vault is sealed: a deploy would start half-blind,
                            so it is a skip, not a half deploy
      vm_memory_unread      the Docker VM's MemAvailable could not be read
      vm_memory_low         below the VM floor (4096 MB)
      windows_memory_unread
      windows_memory_low    below the Windows floor (1536 MB)
      quiet_hours           22:00-07:00 America/Phoenix (UTC-7 all year)

    ASCII only.
#>

# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

function Test-ShaMatch {
    # Two shas name the same commit when both are hex and one is a prefix of
    # the other, at 7 characters or more. The running image may carry a full
    # sha while a log line carries 12, and either way round is the same
    # commit.
    param([string]$A, [string]$B)
    if (-not $A -or -not $B) { return $false }
    $a = $A.Trim().ToLowerInvariant()
    $b = $B.Trim().ToLowerInvariant()
    if ($a -notmatch '^[0-9a-f]{7,40}$' -or $b -notmatch '^[0-9a-f]{7,40}$') { return $false }
    return ($a.StartsWith($b) -or $b.StartsWith($a))
}

function Test-QuietHour {
    # True when the clock, moved to the operator's zone, is inside
    # [StartHour, EndHour). A window that wraps midnight (22 -> 7) is the
    # normal case. Arizona keeps UTC-7 all year, so a fixed offset is exact.
    param(
        [Parameter(Mandatory = $true)][DateTime]$NowUtc,
        [int]$StartHour = 22,
        [int]$EndHour = 7,
        [int]$UtcOffsetHours = -7
    )
    if ($StartHour -eq $EndHour) { return $false }
    $hour = $NowUtc.AddHours($UtcOffsetHours).Hour
    if ($StartHour -lt $EndHour) { return ($hour -ge $StartHour -and $hour -lt $EndHour) }
    return ($hour -ge $StartHour -or $hour -lt $EndHour)
}

function Test-AutoDeployAttempted {
    # PURE. True when the memo holds an entry for Sha that counts as the one
    # attempt: anything but 'not_attempted'. A bare string is a sha that
    # counts.
    param([AllowNull()][object[]]$Attempts, [string]$Sha)
    foreach ($a in @($Attempts)) {
        if ($null -eq $a) { continue }
        if ($a -is [string]) { $aSha = $a; $aResult = 'started' }
        else { $aSha = [string]$a.sha; $aResult = [string]$a.result }
        if ($aResult -eq 'not_attempted') { continue }
        if (Test-ShaMatch $Sha $aSha) { return $true }
    }
    return $false
}

function ConvertTo-UtcTime {
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    if ($Value -is [DateTime]) { return $Value.ToUniversalTime() }
    return [DateTime]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal)
}

function Get-AutoDeployRetryCap {
    <#
        PURE. A not_attempted run spends nothing, so without a cap a head
        the gate keeps refusing (or never scores) is retried every tick, and
        an unjudged one holds the lock ~45 of every ~55 minutes. The memo
        entry for a sha carries not_attempted_count and the first and last
        times; Capped is true when Cap or more fell inside the window that
        started at the first. A new sha has its own entry, so it starts at 0.
        Returns $null when the memo has no not_attempted entry for Sha.
    #>
    param(
        [AllowNull()][object[]]$Attempts,
        [string]$Sha,
        [Parameter(Mandatory = $true)][DateTime]$NowUtc,
        [int]$Cap = 3,
        [int]$WindowHours = 24
    )
    foreach ($a in @($Attempts)) {
        if ($null -eq $a -or $a -is [string]) { continue }
        if (-not (Test-ShaMatch $Sha ([string]$a.sha))) { continue }
        if ([string]$a.result -ne 'not_attempted') { continue }
        $count = 0
        if ($null -ne $a.not_attempted_count) { $count = [int]$a.not_attempted_count }
        $first = ConvertTo-UtcTime $a.not_attempted_first
        if (-not $first) { $first = ConvertTo-UtcTime $a.at }
        if (-not $first) { $first = $NowUtc }
        $until = $first.AddHours($WindowHours)
        $capped = ($count -ge $Cap -and $NowUtc -lt $until)
        return [pscustomobject]@{
            Capped = $capped; Count = $count
            First = $first.ToString('yyyy-MM-ddTHH:mm:ssZ'); Until = $until.ToString('yyyy-MM-ddTHH:mm:ssZ')
        }
    }
    return $null
}

function Get-NotAttemptedTally {
    <#
        PURE. The not_attempted counters for Sha after one more such run at
        NowUtc, from the sha's previous memo entry (or $null). A run whose
        window (WindowHours from the first) has passed starts a new window
        at 1.
    #>
    param(
        [AllowNull()][object]$Previous,
        [Parameter(Mandatory = $true)][DateTime]$NowUtc,
        [int]$WindowHours = 24
    )
    $count = 0
    $first = $null
    if ($Previous -and $null -ne $Previous.not_attempted_count) {
        $count = [int]$Previous.not_attempted_count
        $first = ConvertTo-UtcTime $Previous.not_attempted_first
    }
    if (-not $first -or $NowUtc -ge $first.AddHours($WindowHours)) {
        $count = 0
        $first = $NowUtc
    }
    $stamp = $NowUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
    return [ordered]@{
        not_attempted_count = $count + 1
        not_attempted_first = $first.ToString('yyyy-MM-ddTHH:mm:ssZ')
        not_attempted_last  = $stamp
    }
}

function Get-AutoDeployOutcome {
    <#
        PURE. What a finished deploy.ps1 run amounts to, from what the
        watcher saw afterwards:
          Code              deploy.ps1's exit code (124 = still running)
          HealthyOnNew      both containers healthy and the backend on H
          HealthyOnPrevious both healthy and the backend still on the sha
                            that ran before
          PreviousKnown     a rollback target was recorded
          Simulate          -SimulateFailedHealth: treat the new stack as
                            failed whatever it reports
        Returns Result, Counted (does this spend the sha's one attempt),
        Rollback (should the watcher roll back) and Why.
    #>
    param(
        [int]$Code,
        [bool]$HealthyOnNew,
        [bool]$HealthyOnPrevious,
        [bool]$PreviousKnown,
        [bool]$Simulate = $false
    )
    function Format-Outcome([string]$Result, [bool]$Counted, [bool]$Rollback, [string]$Why) {
        return [pscustomobject]@{ Result = $Result; Counted = $Counted; Rollback = $Rollback; Why = $Why }
    }
    if ($Code -eq 124) {
        return (Format-Outcome 'timeout' $true $false 'deploy.ps1 still running; left running, lock held')
    }
    if ($HealthyOnNew -and -not $Simulate) {
        if ($Code -eq 0) { return (Format-Outcome 'success' $true $false 'healthy on the new sha') }
        # The deploy's intent was met; something after it (the briefing,
        # the recorder) exited non-zero. Rolling back a healthy, correct
        # stack would be the worse outcome.
        return (Format-Outcome 'success_with_warning' $true $false "deploy.ps1 exited $Code but both containers are healthy on the new sha")
    }
    if ($HealthyOnPrevious -and -not $Simulate) {
        # deploy.ps1 stopped before it changed the stack: the risk gate
        # refused or never answered, a pull failed, the lock was taken (75).
        # Nothing moved, so the sha's one attempt is not spent.
        return (Format-Outcome 'not_attempted' $false $false "deploy.ps1 exited $Code before changing the stack; production is unchanged and healthy")
    }
    if (-not $PreviousKnown) {
        return (Format-Outcome 'failed' $true $false 'no previous sha was recorded; rollback impossible')
    }
    return (Format-Outcome 'failed' $true $true 'the stack changed and is not healthy on the new sha')
}

function Step-AutoDeployStreak {
    <#
        PURE. Counts consecutive ticks whose headline is the same blocking
        reason, so a watcher that is stuck (a lock left by a killed run, a
        sealed Vault, an unreadable Docker) says so once instead of skipping
        silently forever. Waiting states are not blocking: ready, quiet
        hours, already running, already attempted, waiting for promote.
        Returns the new streak (Reason, Count, Alerted) and Alert: $true on
        exactly the tick the count reaches Threshold, once per streak.
    #>
    param(
        [AllowNull()][object]$Previous,
        [AllowNull()][string]$Reason,
        [int]$Threshold = 6
    )
    $waiting = @('ready', 'quiet_hours', 'already_running', 'already_attempted', 'main_ahead_of_promote')
    if (-not $Reason -or $waiting -contains $Reason) {
        return [pscustomobject]@{ Reason = $Reason; Count = 0; Alerted = $false; Alert = $false }
    }
    $count = 1
    $alerted = $false
    if ($Previous -and ([string]$Previous.Reason) -eq $Reason) {
        $count = [int]$Previous.Count + 1
        $alerted = [bool]$Previous.Alerted
    }
    $alert = ($count -ge $Threshold -and -not $alerted)
    if ($alert) { $alerted = $true }
    return [pscustomobject]@{ Reason = $Reason; Count = $count; Alerted = $alerted; Alert = $alert }
}

function Get-AutoDeployDecision {
    <#
        PURE. Returns:
          Action   'Deploy' or 'Skip'
          Reason   the headline code ('ready' on Deploy)
          Detail   one sentence for the headline
          Reasons  every failing rule, headline first: @{ Code; Detail }
          Checks   every rule that passed, by name
          Sha      the promoted sha (the one a deploy would ship)
          Mode     'DryRun' or 'Live'
          Execute  $true only for Deploy in Live mode: DryRun never runs
                   anything, whatever the decision
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyString()][string]$PromotedSha,
        [AllowNull()][AllowEmptyString()][string]$MainHead,
        [AllowNull()][AllowEmptyString()][string]$RunningSha,
        [bool]$LockHeld = $false,
        [bool]$OtherDeployRunning = $false,
        # $true sealed, $false unsealed, $null could not ask.
        [AllowNull()][object]$VaultSealed = $null,
        [AllowNull()][object]$VmFreeMB = $null,
        [AllowNull()][object]$WindowsFreeMB = $null,
        [Parameter(Mandatory = $true)][DateTime]$NowUtc,
        # The attempts memo: objects with .sha and .result, or bare shas.
        # An entry whose result is 'not_attempted' is ignored.
        [AllowNull()][object[]]$Attempts = @(),
        # $true when the running sha's images can be pulled back; $false or
        # $null (could not ask) is a skip: no deploy without a way back.
        [AllowNull()][object]$RollbackAvailable = $null,
        # not_attempted runs of one sha allowed per window before retry_cap.
        [int]$RetryCap = 3,
        [int]$RetryWindowHours = 24,
        [ValidateSet('DryRun', 'Live')][string]$Mode = 'DryRun',
        [int]$VmFloorMB = 4096,
        [int]$WindowsFloorMB = 1536,
        [int]$QuietStartHour = 22,
        [int]$QuietEndHour = 7,
        [int]$UtcOffsetHours = -7
    )

    $reasons = New-Object System.Collections.Generic.List[object]
    $checks = New-Object System.Collections.Generic.List[string]
    function Add-Reason([string]$Code, [string]$Detail) {
        $reasons.Add([pscustomobject]@{ Code = $Code; Detail = $Detail })
    }
    function Get-Short([string]$Sha) {
        if (-not $Sha) { return '(none)' }
        if ($Sha.Length -gt 12) { return $Sha.Substring(0, 12) }
        return $Sha
    }

    $promoted = $(if ($PromotedSha) { $PromotedSha.Trim().ToLowerInvariant() } else { '' })
    $promotedOk = $promoted -match '^[0-9a-f]{40}$'

    # 1. What would ship, and is it the newest thing on main.
    if (-not $promotedOk) {
        Add-Reason 'no_promoted_build' 'no succeeded promote build with a full source sha was read from Concourse'
    } else {
        $checks.Add('promoted')
    }
    if (-not $MainHead -or $MainHead.Trim() -notmatch '^[0-9a-fA-F]{40}$') {
        Add-Reason 'main_unread' 'the head of main could not be read (git ls-remote origin main)'
    } elseif ($promotedOk -and -not (Test-ShaMatch $promoted $MainHead)) {
        Add-Reason 'main_ahead_of_promote' ("main is at $(Get-Short $MainHead) and the last promote is " +
            "$(Get-Short $promoted): wait for the newer commit's promote")
    } elseif ($promotedOk) {
        $checks.Add('promoted_is_main_head')
    }

    # 2. Is it already there, and was it tried.
    if (-not $RunningSha) {
        Add-Reason 'running_unread' 'the running mykronos-backend reports no MYKRONOS_BUILD_SHA, so there is nothing to roll back to'
    } elseif ($promotedOk -and (Test-ShaMatch $promoted $RunningSha)) {
        Add-Reason 'already_running' "production already runs $(Get-Short $promoted)"
    } else {
        $checks.Add('production_behind')
        if ($RollbackAvailable -eq $true) {
            $checks.Add('rollback_available')
        } else {
            Add-Reason 'rollback_unavailable' ("the images of $(Get-Short $RunningSha), which production runs now, " +
                'could not be found on this host and in the registry: a failed deploy would have no way back')
        }
    }
    $tried = $false
    if ($promotedOk -and (Test-AutoDeployAttempted -Attempts $Attempts -Sha $promoted)) { $tried = $true }
    if ($tried) {
        Add-Reason 'already_attempted' "$(Get-Short $promoted) was attempted before; one attempt per sha (remove it from attempts.json to retry)"
    } else {
        $checks.Add('not_attempted')
    }
    $cap = $null
    if ($promotedOk -and -not $tried) {
        $cap = Get-AutoDeployRetryCap -Attempts $Attempts -Sha $promoted -NowUtc $NowUtc `
            -Cap $RetryCap -WindowHours $RetryWindowHours
    }
    if ($cap -and $cap.Capped) {
        Add-Reason 'retry_cap' ("$(Get-Short $promoted) stopped before changing anything $($cap.Count) times since " +
            "$($cap.First) (the gate refused or never answered, a pull failed, the lock was taken); " +
            "no more tries until $($cap.Until) or a new promoted head")
    } elseif ($cap) {
        $checks.Add('under_retry_cap')
    }

    # 3. Is the host free and fit.
    if ($LockHeld) { Add-Reason 'lock_held' 'another MyKronos deploy holds the deploy lock' } else { $checks.Add('lock_free') }
    if ($OtherDeployRunning) { Add-Reason 'thehub_deploy_running' 'TheHub deploy.sh holds its lock; one deploy on the host at a time' } else { $checks.Add('no_thehub_deploy') }

    if ($null -eq $VaultSealed) {
        Add-Reason 'vault_unread' 'vault status could not be read from mykronos-vault'
    } elseif ([bool]$VaultSealed) {
        Add-Reason 'vault_sealed' 'Vault is sealed: run deploy/concourse/vault-unseal.ps1; a sealed Vault is a skip, not a half deploy'
    } else {
        $checks.Add('vault_unsealed')
    }

    if ($null -eq $VmFreeMB) {
        Add-Reason 'vm_memory_unread' 'MemAvailable in the Docker VM could not be read'
    } elseif ([int]$VmFreeMB -lt $VmFloorMB) {
        Add-Reason 'vm_memory_low' "Docker VM has $([int]$VmFreeMB) MB available, below the $VmFloorMB MB floor"
    } else {
        $checks.Add('vm_memory')
    }
    if ($null -eq $WindowsFreeMB) {
        Add-Reason 'windows_memory_unread' 'free physical memory on Windows could not be read'
    } elseif ([int]$WindowsFreeMB -lt $WindowsFloorMB) {
        Add-Reason 'windows_memory_low' "Windows has $([int]$WindowsFreeMB) MB free, below the $WindowsFloorMB MB floor"
    } else {
        $checks.Add('windows_memory')
    }

    if (Test-QuietHour -NowUtc $NowUtc -StartHour $QuietStartHour -EndHour $QuietEndHour -UtcOffsetHours $UtcOffsetHours) {
        $local = $NowUtc.AddHours($UtcOffsetHours).ToString('HH:mm')
        Add-Reason 'quiet_hours' ("$local America/Phoenix (UTC$UtcOffsetHours); quiet " +
            ('{0:00}:00-{1:00}:00' -f $QuietStartHour, $QuietEndHour))
    } else {
        $checks.Add('outside_quiet_hours')
    }

    if ($reasons.Count -gt 0) {
        $head = $reasons[0]
        return [pscustomobject]@{
            Action  = 'Skip'
            Reason  = $head.Code
            Detail  = $head.Detail
            Reasons = $reasons.ToArray()
            Checks  = $checks.ToArray()
            Sha     = $(if ($promotedOk) { $promoted } else { $null })
            Mode    = $Mode
            Execute = $false
        }
    }
    $detail = "promote succeeded for main's head $(Get-Short $promoted), production runs $(Get-Short $RunningSha)"
    if ($Mode -eq 'DryRun') { $detail = "DRY RUN, nothing runs: would deploy. $detail" }
    return [pscustomobject]@{
        Action  = 'Deploy'
        Reason  = 'ready'
        Detail  = $detail
        Reasons = @()
        Checks  = $checks.ToArray()
        Sha     = $promoted
        Mode    = $Mode
        Execute = ($Mode -eq 'Live')
    }
}

# ---------------------------------------------------------------------------
# The attempt memo: one attempt per sha
# ---------------------------------------------------------------------------

function Read-AutoDeployAttemptList {
    # Every sha this watcher started, newest last. A missing file is "none";
    # an unreadable one is an exception, because silently forgetting every
    # attempt would let a failed sha be retried every ten minutes.
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    $raw = Get-Content -LiteralPath $Path -Raw
    if (-not $raw -or -not $raw.Trim()) { return @() }
    $parsed = $raw | ConvertFrom-Json
    return @($parsed)
}

function Save-AutoDeployAttempt {
    # Replaces the entry for Sha (a 'started' becomes its result) and keeps
    # the newest 100.
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Sha,
        [Parameter(Mandatory = $true)][string]$Result,
        [hashtable]$Extra = @{}
    )
    $now = (Get-Date).ToUniversalTime()
    $all0 = @(Read-AutoDeployAttemptList -Path $Path)
    $prior = $all0 | Where-Object { $_.sha -eq $Sha } | Select-Object -Last 1
    $existing = @($all0 | Where-Object { $_.sha -ne $Sha })
    $entry = [ordered]@{ sha = $Sha; result = $Result; at = $now.ToString('yyyy-MM-ddTHH:mm:ssZ') }
    foreach ($k in $Extra.Keys) { $entry[$k] = $Extra[$k] }
    # The retry tally survives the 'started' that precedes every run, and
    # grows on each not_attempted (Get-AutoDeployRetryCap reads it).
    if ($Result -eq 'not_attempted') {
        $tally = Get-NotAttemptedTally -Previous $prior -NowUtc $now
        foreach ($k in $tally.Keys) { $entry[$k] = $tally[$k] }
    } elseif ($prior -and $null -ne $prior.not_attempted_count) {
        foreach ($k in @('not_attempted_count', 'not_attempted_first', 'not_attempted_last')) { $entry[$k] = $prior.$k }
    }
    $all = @($existing) + @([pscustomobject]$entry)
    if ($all.Count -gt 100) { $all = $all[($all.Count - 100)..($all.Count - 1)] }
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    # -InputObject, not the pipeline: a one-element array must stay an array.
    Set-Content -LiteralPath $Path -Encoding ascii -Value (ConvertTo-Json -InputObject @($all) -Depth 5)
}

function Write-AutoDeployJsonl {
    # One line per tick, decision or outcome. The durable record: the
    # console of a scheduled task is read by nobody.
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][hashtable]$Entry)
    # The keys a reader scans for first, then the rest in a stable order.
    $line = [ordered]@{ at = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    $lead = @('event', 'mode', 'action', 'reason', 'result', 'sha', 'detail')
    foreach ($k in $lead) { if ($Entry.ContainsKey($k)) { $line[$k] = $Entry[$k] } }
    foreach ($k in @($Entry.Keys | Sort-Object)) { if ($lead -notcontains $k) { $line[$k] = $Entry[$k] } }
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Add-Content -LiteralPath $Path -Encoding ascii -Value ($line | ConvertTo-Json -Compress -Depth 6)
}

# ---------------------------------------------------------------------------
# Collectors: the only code here that touches the host. $null = could not ask.
# ---------------------------------------------------------------------------

function Get-PromotedSha {
    # The input commit of the newest SUCCEEDED build of mykronos/promote,
    # read anonymously (the job is public). promote passes only after
    # oracle-gate, so its sha has a risk decision by the time it is here.
    param([string]$ConcourseUrl = 'http://127.0.0.1:8080', [string]$Pipeline = 'mykronos',
        [string]$Job = 'promote', [int]$TimeoutSec = 20)
    try {
        # Assigned first, then piped: Invoke-RestMethod hands back a JSON
        # array as ONE object, and @() around the call would wrap it again.
        $builds = Invoke-RestMethod -TimeoutSec $TimeoutSec `
            -Uri "$ConcourseUrl/api/v1/teams/main/pipelines/$Pipeline/jobs/$Job/builds?limit=25"
        $ok = $builds | Where-Object { $_.status -eq 'succeeded' } | Select-Object -First 1
        if (-not $ok) { return $null }
        $res = Invoke-RestMethod -TimeoutSec $TimeoutSec -Uri "$ConcourseUrl/api/v1/builds/$($ok.id)/resources"
        $src = @($res.inputs) | Where-Object { $_.name -eq 'source' } | Select-Object -First 1
        $sha = [string]$src.version.ref
        if ($sha -notmatch '^[0-9a-f]{40}$') { return $null }
        return [pscustomobject]@{ Sha = $sha; Build = [string]$ok.name; BuildId = $ok.id }
    } catch {
        return $null
    }
}

function Get-MainHead {
    # main as GitHub has it now, not as this checkout last fetched it. The
    # repository is public, so this needs no credential.
    param([string]$RepoRoot)
    try {
        $out = & git -C $RepoRoot ls-remote origin refs/heads/main 2>$null
        if ($LASTEXITCODE -ne 0) { return $null }
        $first = (@($out) | Select-Object -First 1)
        if (-not $first) { return $null }
        $sha = ($first -split '\s+')[0]
        if ($sha -notmatch '^[0-9a-f]{40}$') { return $null }
        return $sha
    } catch {
        return $null
    }
}

function Get-RunningSha {
    # The same stamp deploy.ps1 confirms a deploy by: the image's own
    # MYKRONOS_BUILD_SHA. Only that one variable is matched; the rest of the
    # container's environment is never kept or printed.
    param([string]$Container = 'mykronos-backend')
    try {
        $lines = docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' $Container 2>$null
        if ($LASTEXITCODE -ne 0) { return $null }
        foreach ($line in $lines) {
            if ($line -match '^MYKRONOS_BUILD_SHA=([0-9a-f]{7,40})\s*$') { return $Matches[1] }
        }
    } catch {
        Write-Verbose 'docker inspect failed'
    }
    return $null
}

function Get-VaultSealed {
    # $true / $false, or $null when Vault did not answer. `vault status`
    # exits 2 when sealed and still prints the JSON, so the exit code is not
    # the answer; the field is.
    param([string]$Container = 'mykronos-vault')
    try {
        $out = docker exec -e VAULT_ADDR=http://127.0.0.1:8200 $Container vault status -format=json 2>$null
        if (-not $out) { return $null }
        $status = ($out -join "`n") | ConvertFrom-Json
        if ($null -eq $status.sealed) { return $null }
        return [bool]$status.sealed
    } catch {
        return $null
    }
}

function Get-VmFreeMB {
    # MemAvailable of the Docker VM. /proc/meminfo is not namespaced, so any
    # running container reads the VM's figure; no container is started to
    # measure it. The first container that answers wins.
    param([string[]]$Containers = @('mykronos-backend', 'mykronos-vault'))
    foreach ($c in $Containers) {
        try {
            $out = docker exec $c cat /proc/meminfo 2>$null
            if ($LASTEXITCODE -ne 0) { continue }
            foreach ($line in $out) {
                if ($line -match '^MemAvailable:\s+(\d+)\s+kB') { return [int]([int64]$Matches[1] / 1024) }
            }
        } catch {
            continue
        }
    }
    return $null
}

function Get-WindowsFreeMB {
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        return [int]([int64]$os.FreePhysicalMemory / 1024)
    } catch {
        return $null
    }
}

function Get-RollbackImage {
    <#
        Can the sha production runs now be deployed again? deploy.ps1 pulls
        "$Registry/<image>:<tag>" for the backend and the frontend, so both
        must be in the registry; they are checked on this host too (docker
        image inspect). The tag may be the full sha or a prefix a hand
        deploy used, so the local tags are searched for either.
        Returns Available ($true, $false, $null = could not ask), Tag, Detail.
    #>
    param(
        [string]$Sha,
        [string]$Registry = 'localhost:5000',
        [string[]]$Images = @('mykronos-backend', 'mykronos-frontend')
    )
    function Format-Answer($Available, [string]$Tag, [string]$Detail) {
        return [pscustomobject]@{ Available = $Available; Tag = $Tag; Detail = $Detail }
    }
    if (-not $Sha) { return (Format-Answer $null $null 'no running sha') }
    # ::1 resets on this host; the registry answers on 127.0.0.1.
    $api = 'http://' + ($Registry -replace '^localhost', '127.0.0.1')
    $accept = 'application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, ' +
        'application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json'
    $tag = $null
    foreach ($name in $Images) {
        try {
            $local = @(docker images --format '{{.Tag}}' "$Registry/$name" 2>$null)
            if ($LASTEXITCODE -ne 0) { return (Format-Answer $null $null 'docker images failed') }
        } catch {
            return (Format-Answer $null $null 'docker images failed')
        }
        if ($tag -and ($local -contains $tag)) {
            $t = $tag
        } else {
            $match = @($local | Where-Object { Test-ShaMatch $_ $Sha } | Sort-Object Length -Descending)
            if ($match.Count -eq 0) { return (Format-Answer $false $null "no local $Registry/$name tag for $Sha") }
            $t = [string]$match[0]
        }
        docker image inspect "$Registry/${name}:$t" 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) { return (Format-Answer $false $null "docker image inspect $Registry/${name}:$t failed") }
        try {
            Invoke-WebRequest -Method Head -Uri "$api/v2/$name/manifests/$t" -Headers @{ Accept = $accept } `
                -TimeoutSec 15 -ErrorAction Stop | Out-Null
        } catch {
            $status = $null
            try { $status = [int]$_.Exception.Response.StatusCode } catch { $status = $null }
            if ($status -eq 404) { return (Format-Answer $false $null "the registry has no ${name}:$t (retention?)") }
            return (Format-Answer $null $null "the registry did not answer for ${name}:$t")
        }
        if (-not $tag) { $tag = $t }
    }
    return (Format-Answer $true $tag "both images present as :$tag")
}

function Get-StackState {
    # What the deploy is judged by afterwards: both containers healthy and
    # the backend running the sha that was asked for.
    param([string]$Backend = 'mykronos-backend', [string]$Frontend = 'mykronos-frontend')
    $b = (docker inspect -f '{{.State.Health.Status}}' $Backend 2>$null)
    $f = (docker inspect -f '{{.State.Health.Status}}' $Frontend 2>$null)
    return [pscustomobject]@{
        Backend  = $(if ($b) { [string]$b } else { 'missing' })
        Frontend = $(if ($f) { [string]$f } else { 'missing' })
        Sha      = (Get-RunningSha -Container $Backend)
    }
}

function Test-StackOn {
    param($State, [string]$Sha)
    return ($State.Backend -eq 'healthy' -and $State.Frontend -eq 'healthy' -and (Test-ShaMatch $State.Sha $Sha))
}
