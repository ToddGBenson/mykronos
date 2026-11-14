# TheHub #61610. The decision is pure, so every rule is tested here with plain
# values: no Docker, no Concourse, no network. Run from the repository root:
#   pwsh -NoProfile -c "Invoke-Pester deploy/mykronos/tests"

BeforeAll {
    . (Join-Path $PSScriptRoot '..\AutoDeploy.ps1')
    . (Join-Path $PSScriptRoot '..\DeployLock.ps1')

    $script:H = 'fcdfff150ad0ad8dd16d43be60b70a04982fab3c'      # promoted and main head
    $script:Newer = '362d21d0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'  # a later main head
    $script:Prev = '11c9b4a4bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'   # what production runs
    # 2026-11-13 17:00Z is 10:00 in Arizona: outside quiet hours.
    $script:Noon = [DateTime]::SpecifyKind([DateTime]'2026-11-13T17:00:00', 'Utc')

    function Get-GreenInput {
        # Every rule passes. Each test changes one input from here.
        return @{
            PromotedSha   = $script:H
            MainHead      = $script:H
            RunningSha    = $script:Prev
            LockHeld      = $false
            OtherDeployRunning = $false
            VaultSealed   = $false
            VmFreeMB      = 5000
            WindowsFreeMB = 4000
            NowUtc        = $script:Noon
            Attempts      = @()
            RollbackAvailable = $true
            Mode          = 'Live'
        }
    }
}

Describe 'Get-AutoDeployDecision' {

    It 'deploys a promoted main head that is not running (Live executes)' {
        $g = Get-GreenInput; $d = Get-AutoDeployDecision @g
        $d.Action | Should -Be 'Deploy'
        $d.Reason | Should -Be 'ready'
        $d.Sha | Should -Be $script:H
        $d.Execute | Should -BeTrue
        $d.Reasons.Count | Should -Be 0
    }

    It 'decides Deploy but executes nothing in DryRun' {
        $in = Get-GreenInput; $in.Mode = 'DryRun'
        $d = Get-AutoDeployDecision @in
        $d.Action | Should -Be 'Deploy'
        $d.Execute | Should -BeFalse
        $d.Detail | Should -Match 'DRY RUN'
    }

    It 'defaults to DryRun when no mode is given' {
        $in = Get-GreenInput; $in.Remove('Mode')
        $d = Get-AutoDeployDecision @in
        $d.Mode | Should -Be 'DryRun'
        $d.Execute | Should -BeFalse
    }

    It 'skips when nothing was promoted' {
        $in = Get-GreenInput; $in.PromotedSha = $null
        $d = Get-AutoDeployDecision @in
        $d.Action | Should -Be 'Skip'
        $d.Reason | Should -Be 'no_promoted_build'
        $d.Execute | Should -BeFalse
    }

    It 'skips a promoted sha that is not a full sha' {
        $in = Get-GreenInput; $in.PromotedSha = 'fcdfff15'
        (Get-AutoDeployDecision @in).Reason | Should -Be 'no_promoted_build'
    }

    It 'waits when main has a newer commit than the last promote' {
        $in = Get-GreenInput; $in.MainHead = $script:Newer
        $d = Get-AutoDeployDecision @in
        $d.Action | Should -Be 'Skip'
        $d.Reason | Should -Be 'main_ahead_of_promote'
        $d.Detail | Should -Match '362d21d0aaaa'
    }

    It 'skips when main could not be read' {
        $in = Get-GreenInput; $in.MainHead = ''
        (Get-AutoDeployDecision @in).Reason | Should -Be 'main_unread'
    }

    It 'skips a sha production already runs, short or full' {
        $in = Get-GreenInput; $in.RunningSha = $script:H
        (Get-AutoDeployDecision @in).Reason | Should -Be 'already_running'
        $in.RunningSha = $script:H.Substring(0, 12)
        (Get-AutoDeployDecision @in).Reason | Should -Be 'already_running'
    }

    It 'skips when the running sha cannot be read (nothing to roll back to)' {
        $in = Get-GreenInput; $in.RunningSha = $null
        (Get-AutoDeployDecision @in).Reason | Should -Be 'running_unread'
    }

    It 'makes one attempt per sha' {
        $in = Get-GreenInput; $in.Attempts = @($script:Prev, $script:H)
        $d = Get-AutoDeployDecision @in
        $d.Action | Should -Be 'Skip'
        $d.Reason | Should -Be 'already_attempted'
    }

    It 'is not blocked by an attempt of a different sha' {
        $in = Get-GreenInput; $in.Attempts = @($script:Prev)
        (Get-AutoDeployDecision @in).Action | Should -Be 'Deploy'
    }

    It 'skips while the deploy lock is held' {
        $in = Get-GreenInput; $in.LockHeld = $true
        (Get-AutoDeployDecision @in).Reason | Should -Be 'lock_held'
    }

    It 'skips while TheHub is deploying' {
        $in = Get-GreenInput; $in.OtherDeployRunning = $true
        (Get-AutoDeployDecision @in).Reason | Should -Be 'thehub_deploy_running'
    }

    It 'skips while Vault is sealed' {
        $in = Get-GreenInput; $in.VaultSealed = $true
        $d = Get-AutoDeployDecision @in
        $d.Reason | Should -Be 'vault_sealed'
        $d.Detail | Should -Match 'vault-unseal'
    }

    It 'treats an unreadable Vault as a skip, not a pass' {
        $in = Get-GreenInput; $in.VaultSealed = $null
        (Get-AutoDeployDecision @in).Reason | Should -Be 'vault_unread'
    }

    It 'skips when the Docker VM is below 4096 MB' {
        $in = Get-GreenInput; $in.VmFreeMB = 4095
        $d = Get-AutoDeployDecision @in
        $d.Reason | Should -Be 'vm_memory_low'
        $d.Detail | Should -Match '4095'
        $in.VmFreeMB = 4096
        (Get-AutoDeployDecision @in).Action | Should -Be 'Deploy'
    }

    It 'treats an unmeasured VM as a skip' {
        $in = Get-GreenInput; $in.VmFreeMB = $null
        (Get-AutoDeployDecision @in).Reason | Should -Be 'vm_memory_unread'
    }

    It 'skips when Windows is below 1536 MB' {
        $in = Get-GreenInput; $in.WindowsFreeMB = 1535
        (Get-AutoDeployDecision @in).Reason | Should -Be 'windows_memory_low'
        $in.WindowsFreeMB = 1536
        (Get-AutoDeployDecision @in).Action | Should -Be 'Deploy'
    }

    It 'treats unmeasured Windows memory as a skip' {
        $in = Get-GreenInput; $in.WindowsFreeMB = $null
        (Get-AutoDeployDecision @in).Reason | Should -Be 'windows_memory_unread'
    }

    It 'skips in quiet hours (23:30 Arizona)' {
        $in = Get-GreenInput; $in.NowUtc = [DateTime]::SpecifyKind([DateTime]'2026-11-14T06:30:00', 'Utc')
        $d = Get-AutoDeployDecision @in
        $d.Reason | Should -Be 'quiet_hours'
        $d.Detail | Should -Match '23:30'
    }

    It 'reports every failing rule with the identity rule as the headline' {
        $in = Get-GreenInput
        $in.MainHead = $script:Newer; $in.VaultSealed = $true; $in.VmFreeMB = 100; $in.LockHeld = $true
        $d = Get-AutoDeployDecision @in
        $d.Reason | Should -Be 'main_ahead_of_promote'
        @($d.Reasons | ForEach-Object { $_.Code }) |
            Should -Be @('main_ahead_of_promote', 'lock_held', 'vault_sealed', 'vm_memory_low')
    }

    It 'lists the checks that passed' {
        $g = Get-GreenInput; $d = Get-AutoDeployDecision @g
        $d.Checks | Should -Contain 'promoted_is_main_head'
        $d.Checks | Should -Contain 'vault_unsealed'
        $d.Checks | Should -Contain 'outside_quiet_hours'
    }
}

Describe 'one attempt per sha, counting only runs that moved the stack (61644)' {
    It 'counts a memo entry that moved the stack or died after starting' {
        foreach ($r in @('started', 'success', 'failed', 'rolled_back', 'rollback_failed', 'timeout')) {
            $in = Get-GreenInput; $in.Attempts = @([pscustomobject]@{ sha = $script:H; result = $r })
            (Get-AutoDeployDecision @in).Reason | Should -Be 'already_attempted' -Because $r
        }
    }
    It 'ignores a not_attempted entry, so the head is retried without editing the memo' {
        $in = Get-GreenInput; $in.Attempts = @([pscustomobject]@{ sha = $script:H; result = 'not_attempted' })
        $d = Get-AutoDeployDecision @in
        $d.Action | Should -Be 'Deploy'
        $d.Checks | Should -Contain 'not_attempted'
    }
    It 'round-trips through the memo file' {
        $p = Join-Path $TestDrive 'attempts-61644.json'
        Save-AutoDeployAttempt -Path $p -Sha $script:H -Result 'started'
        Save-AutoDeployAttempt -Path $p -Sha $script:H -Result 'not_attempted' -Extra @{ why = 'gate refused' }
        $in = Get-GreenInput; $in.Attempts = @(Read-AutoDeployAttemptList -Path $p)
        (Get-AutoDeployDecision @in).Action | Should -Be 'Deploy'
    }
}

Describe 'a pre-move refusal is not an attempt; a post-move failure is (61644)' {
    BeforeAll {
        $script:DeployPs1 = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\deploy.ps1') -Raw
        $script:WatchPs1 = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\Watch-AutoDeploy.ps1') -Raw
        function Get-RefusalLog([string]$Kind) {
            return @('Risk gate: asked.',
                "DEPLOY-PRE-MOVE-REFUSAL kind=$Kind (nothing was pulled or changed)",
                'The risk gate refused it. Nothing has been pulled.')
        }
    }

    It 'reads the refusal kind from deploy.ps1''s failing exit and marker line' {
        Get-PreMoveRefusal -Code 1 -Lines (Get-RefusalLog 'risk_refused') | Should -Be 'risk_refused'
        Get-PreMoveRefusal -Code 1 -Lines (Get-RefusalLog 'risk_not_judged') | Should -Be 'risk_not_judged'
        Get-PreMoveRefusal -Code 75 -Lines (Get-RefusalLog 'lock_held') | Should -Be 'lock_held'
    }
    It 'treats exit 75 as the lock even without the line (deploy.ps1''s documented code)' {
        Get-PreMoveRefusal -Code 75 -Lines @('Another MyKronos deploy holds the lock.') | Should -Be 'lock_held'
    }
    It 'needs both: a marker with exit 0 or 124, or a failure without a marker, is not a refusal' {
        Get-PreMoveRefusal -Code 0 -Lines (Get-RefusalLog 'pull_failed') | Should -BeNullOrEmpty
        Get-PreMoveRefusal -Code 124 -Lines (Get-RefusalLog 'risk_refused') | Should -BeNullOrEmpty
        Get-PreMoveRefusal -Code 1 -Lines @('Backend did not become healthy') | Should -BeNullOrEmpty
        Get-PreMoveRefusal -Code 1 -Lines @() | Should -BeNullOrEmpty
        Get-PreMoveRefusal -Code 1 -Lines @('  see DEPLOY-PRE-MOVE-REFUSAL kind=x in the docs') | Should -BeNullOrEmpty
    }

    It 'every kind deploy.ps1 emits is read back by the watcher' {
        $kinds = @([regex]::Matches($script:DeployPs1, 'Stop-BeforeMove -Kind "([a-z_]+)"') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
        $kinds | Should -Contain 'risk_refused'
        $kinds | Should -Contain 'risk_not_judged'
        $kinds | Should -Contain 'lock_held'
        $kinds | Should -Contain 'pull_failed'
        foreach ($k in $kinds) {
            $code = $(if ($k -eq 'lock_held') { 75 } else { 1 })
            Get-PreMoveRefusal -Code $code -Lines (Get-RefusalLog $k) | Should -Be $k -Because $k
        }
        $script:DeployPs1 | Should -Match 'Write-Host "DEPLOY-PRE-MOVE-REFUSAL kind=\$Kind \(nothing'
        $script:DeployPs1 | Should -Match 'Stop-BeforeMove -Kind "lock_held" -ExitCode 75'
    }
    It 'deploy.ps1 run as a child prints the marker and fails on a missing backend/.env' {
        $tree = Join-Path $TestDrive 'tree61644'
        New-Item -ItemType Directory -Path (Join-Path $tree 'deploy\mykronos') -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot '..\deploy.ps1') -Destination (Join-Path $tree 'deploy\mykronos\deploy.ps1')
        $log = Join-Path $TestDrive 'child61644.log'
        $pw = (Get-Process -Id $PID).Path
        & $pw -NoProfile -NonInteractive -File (Join-Path $tree 'deploy\mykronos\deploy.ps1') -Tag $script:H *> $log
        $code = $LASTEXITCODE
        $code | Should -Not -Be 0
        Get-PreMoveRefusal -Code $code -Lines @(Get-Content -LiteralPath $log) | Should -Be 'env_missing'
    }
    It 'deploy.ps1 refuses only before compose up, and pulls both images before retagging either' {
        $up = $script:DeployPs1.IndexOf('docker compose --env-file $backendEnv up -d')
        $up | Should -BeGreaterThan 0
        $last = $script:DeployPs1.LastIndexOf('Stop-BeforeMove -Kind')
        $last | Should -BeLessThan $up
        $script:DeployPs1.IndexOf('Stop-BeforeMove -Kind "pull_failed"') |
            Should -BeLessThan $script:DeployPs1.IndexOf('docker tag "$Registry/$name`:$Tag"')
        # The risk gate refusals go through the marker, not a bare throw.
        $script:DeployPs1 | Should -Not -Match 'Out-Null\s+throw \(\$lines'
    }

    It 'a pre-move refusal is not attempted even when the stack it left was not healthy' {
        $o = Get-AutoDeployOutcome -Code 1 -PreMoveRefusal 'risk_refused' -HealthyOnNew $false `
            -HealthyOnPrevious $false -PreviousKnown $true
        $o.Result | Should -Be 'not_attempted'
        $o.Counted | Should -BeFalse
        $o.Rollback | Should -BeFalse -Because 'nothing moved, so there is nothing to roll back'
        $o.Reason | Should -Be 'risk_refused'
    }
    It 'a post-move failure is one attempt even when the old stack still answers' {
        $o = Get-AutoDeployOutcome -Code 1 -HealthyOnNew $false -HealthyOnPrevious $true -PreviousKnown $true
        $o.Result | Should -Be 'failed'
        $o.Counted | Should -BeTrue
        $o.Rollback | Should -BeFalse
        $o.Reason | Should -BeNullOrEmpty
        $o = Get-AutoDeployOutcome -Code 1 -HealthyOnNew $false -HealthyOnPrevious $false -PreviousKnown $true
        $o.Counted | Should -BeTrue; $o.Rollback | Should -BeTrue
    }

    It 'records attempted: false with the reason, and the next tick retries the same sha' {
        $p = Join-Path $TestDrive 'attempts-premove.json'
        Save-AutoDeployAttempt -Path $p -Sha $script:H -Result 'started'
        $o = Get-AutoDeployOutcome -Code 1 -PreMoveRefusal (Get-PreMoveRefusal -Code 1 -Lines (Get-RefusalLog 'risk_refused')) `
            -HealthyOnNew $false -HealthyOnPrevious $true -PreviousKnown $true
        Save-AutoDeployAttempt -Path $p -Sha $script:H -Result $o.Result -Extra @{ attempted = $o.Counted; reason = $o.Reason }
        $e = @(Read-AutoDeployAttemptList -Path $p)[0]
        $e.attempted | Should -BeFalse
        $e.reason | Should -Be 'risk_refused'
        $e.result | Should -Be 'not_attempted'
        $in = Get-GreenInput; $in.Attempts = @(Read-AutoDeployAttemptList -Path $p)
        $d = Get-AutoDeployDecision @in
        $d.Action | Should -Be 'Deploy'
        $d.Sha | Should -Be $script:H
    }
    It 'records a post-move failure as attempted, and the next tick skips the sha' {
        $p = Join-Path $TestDrive 'attempts-postmove.json'
        Save-AutoDeployAttempt -Path $p -Sha $script:H -Result 'started'
        (@(Read-AutoDeployAttemptList -Path $p)[0]).attempted | Should -BeTrue
        $o = Get-AutoDeployOutcome -Code 1 -PreMoveRefusal (Get-PreMoveRefusal -Code 1 -Lines @('Backend did not become healthy')) `
            -HealthyOnNew $false -HealthyOnPrevious $false -PreviousKnown $true
        Save-AutoDeployAttempt -Path $p -Sha $script:H -Result 'rolled_back' -Extra @{ attempted = $o.Counted; reason = $o.Reason }
        $e = @(Read-AutoDeployAttemptList -Path $p)[0]
        $e.attempted | Should -BeTrue
        $e.reason | Should -BeNullOrEmpty
        $in = Get-GreenInput; $in.Attempts = @(Read-AutoDeployAttemptList -Path $p)
        (Get-AutoDeployDecision @in).Reason | Should -Be 'already_attempted'
    }
    It 'cannot be talked out of an attempt by an attempted: false on a result that moved' {
        $p = Join-Path $TestDrive 'attempts-lie.json'
        Save-AutoDeployAttempt -Path $p -Sha $script:H -Result 'failed' -Extra @{ attempted = $false }
        (@(Read-AutoDeployAttemptList -Path $p)[0]).attempted | Should -BeTrue
    }

    It 'the watcher carries attempted and the reason into the memo, the Hub run and the JSONL' {
        $script:WatchPs1 | Should -Match '\$preMove = Get-PreMoveRefusal -Code \$code -Lines \$deployLines'
        $script:WatchPs1 | Should -Match 'Get-AutoDeployOutcome -Code \$code -PreMoveRefusal \$preMove'
        $script:WatchPs1 | Should -Match 'attempted = \$outcome\.Counted; reason = \$outcome\.Reason'
        ([regex]::Matches($script:WatchPs1, 'reason = \$outcome\.Reason')).Count | Should -BeGreaterOrEqual 3
    }
}

Describe 'the watcher passes the decision''s full sha (61644)' {
    It 'decides on a 40-character lowercase sha, whatever case Concourse gave' {
        $in = Get-GreenInput; $in.PromotedSha = $script:H.ToUpperInvariant(); $in.MainHead = $script:H
        $d = Get-AutoDeployDecision @in
        $d.Action | Should -Be 'Deploy'
        $d.Sha | Should -MatchExactly '^[0-9a-f]{40}$'
    }
    It 'hands deploy.ps1 exactly that sha as -Tag' {
        $g = Get-GreenInput; $d = Get-AutoDeployDecision @g
        $a = Get-DeployScriptArgumentList -ScriptPath 'deploy.ps1' -Tag $d.Sha -Registry 'localhost:5000' -RequireFullSha
        $i = [array]::IndexOf($a, '-Tag')
        $a[$i + 1] | Should -MatchExactly '^[0-9a-f]{40}$'
        $a[$i + 1] | Should -BeExactly $script:H
        $a | Should -Contain '-NonInteractive'
    }
    It 'refuses a 12-character or uppercase sha for the forward deploy' {
        { Get-DeployScriptArgumentList -ScriptPath 'deploy.ps1' -Tag $script:H.Substring(0, 12) -Registry 'r' -RequireFullSha } |
            Should -Throw '*full 40-character lowercase*'
        { Get-DeployScriptArgumentList -ScriptPath 'deploy.ps1' -Tag $script:H.ToUpperInvariant() -Registry 'r' -RequireFullSha } |
            Should -Throw
    }
    It 'lets a rollback pass the running images'' shorter tag' {
        $a = Get-DeployScriptArgumentList -ScriptPath 'deploy.ps1' -Tag $script:Prev.Substring(0, 12) -Registry 'r' -Extra @('-GateWaitMinutes', '0')
        $a[-2] | Should -Be '-GateWaitMinutes'
    }
    It 'the watcher''s forward deploy asks for the full sha' {
        $w = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\Watch-AutoDeploy.ps1') -Raw
        $w | Should -Match 'Invoke-DeployScript -Tag \$sha -LogPath \$deployLog -RequireFullSha'
        $w | Should -Match 'Get-DeployScriptArgumentList -ScriptPath \$deployScript'
    }
}

Describe 'the retry cap on not_attempted' {
    BeforeAll {
        function Get-NaEntry([int]$Count, [string]$First) {
            return [pscustomobject]@{ sha = $script:H; result = 'not_attempted'; at = $First
                not_attempted_count = $Count; not_attempted_first = $First; not_attempted_last = $First }
        }
    }
    It 'allows three not_attempted runs, then skips with retry_cap' {
        foreach ($c in 1..2) {
            $in = Get-GreenInput; $in.Attempts = @(Get-NaEntry $c '2026-11-13T12:00:00Z')
            (Get-AutoDeployDecision @in).Action | Should -Be 'Deploy' -Because "count $c"
        }
        $in = Get-GreenInput; $in.Attempts = @(Get-NaEntry 3 '2026-11-13T12:00:00Z')
        $d = Get-AutoDeployDecision @in
        $d.Action | Should -Be 'Skip'
        $d.Reason | Should -Be 'retry_cap'
    }
    It 'lifts the cap 24 h after the first not_attempted run' {
        $in = Get-GreenInput; $in.Attempts = @(Get-NaEntry 3 '2026-11-12T17:00:01Z')
        (Get-AutoDeployDecision @in).Reason | Should -Be 'retry_cap'
        $in.Attempts = @(Get-NaEntry 3 '2026-11-12T17:00:00Z')
        (Get-AutoDeployDecision @in).Action | Should -Be 'Deploy'
    }
    It 'counts up, survives a started entry and rolls over after 24 h in the memo' {
        $p = Join-Path $TestDrive 'attempts-cap.json'
        foreach ($i in 1..3) {
            Save-AutoDeployAttempt -Path $p -Sha $script:H -Result 'started'
            Save-AutoDeployAttempt -Path $p -Sha $script:H -Result 'not_attempted'
        }
        $e = @(Read-AutoDeployAttemptList -Path $p)[0]
        $e.not_attempted_count | Should -Be 3
        $in = Get-GreenInput; $in.Attempts = @(Read-AutoDeployAttemptList -Path $p); $in.NowUtc = [DateTime]::UtcNow
        (Get-AutoDeployDecision @in).Reason | Should -Be 'retry_cap'
        $old = [pscustomobject]@{ sha = $script:H; result = 'not_attempted'; not_attempted_count = 3
            not_attempted_first = '2026-11-01T00:00:00Z' }
        $t = Get-NotAttemptedTally -Previous $old -NowUtc ([DateTime]::SpecifyKind([DateTime]'2026-11-13T17:00:00', 'Utc'))
        $t.not_attempted_count | Should -Be 1
        $t.not_attempted_first | Should -Be '2026-11-13T17:00:00Z'
    }
    It 'starts a new sha at zero' {
        $in = Get-GreenInput
        $in.Attempts = @([pscustomobject]@{ sha = $script:Prev; result = 'not_attempted'; not_attempted_count = 9
                not_attempted_first = '2026-11-13T12:00:00Z' })
        (Get-AutoDeployDecision @in).Action | Should -Be 'Deploy'
    }
    It 'is a blocking reason: the stuck streak alerts once on it' {
        $s = $null; $alerts = 0
        foreach ($i in 1..8) { $s = Step-AutoDeployStreak -Previous $s -Reason 'retry_cap'; if ($s.Alert) { $alerts++ } }
        $alerts | Should -Be 1
    }
}

Describe 'the rollback supply' {
    It 'skips when the running sha''s images are gone' {
        $in = Get-GreenInput; $in.RollbackAvailable = $false
        $d = Get-AutoDeployDecision @in
        $d.Action | Should -Be 'Skip'
        $d.Reason | Should -Be 'rollback_unavailable'
    }
    It 'skips when the supply could not be checked' {
        $in = Get-GreenInput; $in.RollbackAvailable = $null
        (Get-AutoDeployDecision @in).Reason | Should -Be 'rollback_unavailable'
    }
    It 'does not ask for a way back when production already runs the sha' {
        $in = Get-GreenInput; $in.RunningSha = $script:H; $in.RollbackAvailable = $false
        (Get-AutoDeployDecision @in).Reason | Should -Be 'already_running'
    }
}

Describe 'Get-AutoDeployOutcome' {
    It 'is success on exit 0 healthy on the new sha' {
        $o = Get-AutoDeployOutcome -Code 0 -HealthyOnNew $true -HealthyOnPrevious $false -PreviousKnown $true
        $o.Result | Should -Be 'success'; $o.Counted | Should -BeTrue; $o.Rollback | Should -BeFalse
    }
    It 'does not roll back a non-zero exit that left both containers healthy on the new sha' {
        $o = Get-AutoDeployOutcome -Code 1 -HealthyOnNew $true -HealthyOnPrevious $false -PreviousKnown $true
        $o.Result | Should -Be 'success_with_warning'; $o.Rollback | Should -BeFalse; $o.Counted | Should -BeTrue
    }
    It 'gives the attempt back when deploy.ps1 refused before anything moved (gate, pull, lock)' {
        foreach ($c in @(@(1, 'risk_refused'), @(1, 'pull_failed'), @(75, 'lock_held'))) {
            $o = Get-AutoDeployOutcome -Code $c[0] -PreMoveRefusal $c[1] -HealthyOnNew $false -HealthyOnPrevious $true -PreviousKnown $true
            $o.Result | Should -Be 'not_attempted'; $o.Counted | Should -BeFalse; $o.Rollback | Should -BeFalse
            $o.Reason | Should -Be $c[1]
        }
    }
    It 'rolls back a changed, unhealthy stack' {
        $o = Get-AutoDeployOutcome -Code 1 -HealthyOnNew $false -HealthyOnPrevious $false -PreviousKnown $true
        $o.Result | Should -Be 'failed'; $o.Rollback | Should -BeTrue; $o.Counted | Should -BeTrue
    }
    It 'rolls back on exit 0 when the new stack is not healthy' {
        (Get-AutoDeployOutcome -Code 0 -HealthyOnNew $false -HealthyOnPrevious $false -PreviousKnown $true).Rollback | Should -BeTrue
    }
    It 'cannot roll back without a previous tag' {
        $o = Get-AutoDeployOutcome -Code 1 -HealthyOnNew $false -HealthyOnPrevious $false -PreviousKnown $false
        $o.Result | Should -Be 'failed'; $o.Rollback | Should -BeFalse
    }
    It 'leaves a timed-out deploy alone' {
        $o = Get-AutoDeployOutcome -Code 124 -HealthyOnNew $false -HealthyOnPrevious $false -PreviousKnown $true
        $o.Result | Should -Be 'timeout'; $o.Rollback | Should -BeFalse; $o.Counted | Should -BeTrue
    }
    It 'rolls back a healthy stack under -SimulateFailedHealth' {
        $o = Get-AutoDeployOutcome -Code 0 -HealthyOnNew $true -HealthyOnPrevious $false -PreviousKnown $true -Simulate $true
        $o.Result | Should -Be 'failed'; $o.Rollback | Should -BeTrue
    }
}

Describe 'Step-AutoDeployStreak' {
    It 'alerts once, on the sixth tick of the same blocking reason' {
        $s = $null; $alerts = 0
        foreach ($i in 1..10) {
            $s = Step-AutoDeployStreak -Previous $s -Reason 'lock_held'
            if ($s.Alert) { $alerts++; $s.Count | Should -Be 6 }
        }
        $alerts | Should -Be 1
        $s.Count | Should -Be 10
    }
    It 'restarts the count when the reason changes' {
        $s = $null
        foreach ($i in 1..5) { $s = Step-AutoDeployStreak -Previous $s -Reason 'lock_held' }
        $s = Step-AutoDeployStreak -Previous $s -Reason 'vault_sealed'
        $s.Count | Should -Be 1
        $s.Alert | Should -BeFalse
    }
    It 'never counts waiting states' {
        foreach ($r in @('ready', 'quiet_hours', 'already_running', 'already_attempted', 'main_ahead_of_promote')) {
            $s = $null
            foreach ($i in 1..8) { $s = Step-AutoDeployStreak -Previous $s -Reason $r; $s.Alert | Should -BeFalse }
        }
    }
    It 're-arms after the streak breaks' {
        $s = $null
        foreach ($i in 1..6) { $s = Step-AutoDeployStreak -Previous $s -Reason 'lock_held' }
        $s = Step-AutoDeployStreak -Previous $s -Reason 'already_running'
        $hit = $false
        foreach ($i in 1..6) { $s = Step-AutoDeployStreak -Previous $s -Reason 'lock_held'; if ($s.Alert) { $hit = $true } }
        $hit | Should -BeTrue
    }
}

Describe 'Test-QuietHour' {
    It 'is quiet from 22:00 Arizona' {
        Test-QuietHour -NowUtc ([DateTime]::SpecifyKind([DateTime]'2026-11-14T05:00:00', 'Utc')) | Should -BeTrue
        Test-QuietHour -NowUtc ([DateTime]::SpecifyKind([DateTime]'2026-11-14T04:59:00', 'Utc')) | Should -BeFalse
    }
    It 'is open again at 07:00 Arizona' {
        Test-QuietHour -NowUtc ([DateTime]::SpecifyKind([DateTime]'2026-11-13T13:59:00', 'Utc')) | Should -BeTrue
        Test-QuietHour -NowUtc ([DateTime]::SpecifyKind([DateTime]'2026-11-13T14:00:00', 'Utc')) | Should -BeFalse
    }
    It 'handles a window that does not wrap midnight' {
        $t = [DateTime]::SpecifyKind([DateTime]'2026-11-13T20:00:00', 'Utc')   # 13:00 AZ
        Test-QuietHour -NowUtc $t -StartHour 12 -EndHour 14 | Should -BeTrue
        Test-QuietHour -NowUtc $t -StartHour 14 -EndHour 16 | Should -BeFalse
    }
}

Describe 'Test-ShaMatch' {
    It 'matches a prefix either way round and refuses junk' {
        Test-ShaMatch 'fcdfff150ad0' 'fcdfff150ad0ad8dd16d43be60b70a04982fab3c' | Should -BeTrue
        Test-ShaMatch 'FCDFFF150AD0AD8DD16D43BE60B70A04982FAB3C' 'fcdfff150ad0' | Should -BeTrue
        Test-ShaMatch 'fcdfff1' '362d21d0aaaa' | Should -BeFalse
        Test-ShaMatch 'fcd' 'fcdfff150ad0' | Should -BeFalse
        Test-ShaMatch '' 'fcdfff150ad0' | Should -BeFalse
    }
}

Describe 'the attempts memo' {
    It 'records a start, replaces it with the result, and reads it back' {
        $p = Join-Path $TestDrive 'attempts.json'
        Read-AutoDeployAttemptList -Path $p | Should -BeNullOrEmpty
        Save-AutoDeployAttempt -Path $p -Sha $script:H -Result 'started'
        Save-AutoDeployAttempt -Path $p -Sha $script:H -Result 'rolled_back'
        $all = @(Read-AutoDeployAttemptList -Path $p)
        $all.Count | Should -Be 1
        $all[0].result | Should -Be 'rolled_back'
    }
    It 'throws on a corrupt memo rather than forgetting every attempt' {
        $p = Join-Path $TestDrive 'bad.json'
        Set-Content -LiteralPath $p -Value '{not json'
        { Read-AutoDeployAttemptList -Path $p } | Should -Throw
    }
}

Describe 'the deploy lock' {
    BeforeEach {
        $env:MYKRONOS_DEPLOY_LOCK_DIR = Join-Path $TestDrive ("lock-" + [guid]::NewGuid().ToString('N'))
        Remove-Item Env:\MYKRONOS_DEPLOY_LOCK_TOKEN -ErrorAction SilentlyContinue
    }
    AfterEach {
        Remove-Item Env:\MYKRONOS_DEPLOY_LOCK_DIR -ErrorAction SilentlyContinue
        Remove-Item Env:\MYKRONOS_DEPLOY_LOCK_TOKEN -ErrorAction SilentlyContinue
    }
    It 'refuses a second holder and frees on release' {
        $a = Enter-MykronosDeployLock -Holder 'first'
        $a.Acquired | Should -BeTrue
        $a.Owned | Should -BeTrue
        $b = Enter-MykronosDeployLock -Holder 'second'
        $b.Acquired | Should -BeFalse
        $b.Owner.holder | Should -Be 'first'
        Exit-MykronosDeployLock $a
        (Enter-MykronosDeployLock -Holder 'third').Acquired | Should -BeTrue
    }
    It 'lets the holder''s child proceed without releasing the lock' {
        $parent = Enter-MykronosDeployLock -Holder 'watcher'
        $env:MYKRONOS_DEPLOY_LOCK_TOKEN = $parent.Token
        $child = Enter-MykronosDeployLock -Holder 'deploy.ps1'
        $child.Acquired | Should -BeTrue
        $child.Owned | Should -BeFalse
        Exit-MykronosDeployLock $child
        Test-Path -LiteralPath $parent.Path | Should -BeTrue
        Exit-MykronosDeployLock $parent
        Test-Path -LiteralPath $parent.Path | Should -BeFalse
    }
    It 'does not let a wrong token in' {
        $parent = Enter-MykronosDeployLock -Holder 'watcher'
        $env:MYKRONOS_DEPLOY_LOCK_TOKEN = 'not-the-token'
        (Enter-MykronosDeployLock -Holder 'deploy.ps1').Acquired | Should -BeFalse
        Exit-MykronosDeployLock $parent
    }
}
