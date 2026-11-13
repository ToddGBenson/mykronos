<#
.SYNOPSIS
    The one lock a MyKronos production deploy runs under (TheHub #61610).

.DESCRIPTION
    Dot-sourced by deploy.ps1 and by Watch-AutoDeploy.ps1, so a hand deploy
    and the scheduled one can never run beside each other.

    A directory, created with mkdir, because creating a directory either
    succeeds or fails atomically: two processes cannot both create it. That
    is the same rule TheHub's deploy.sh uses for
    %LOCALAPPDATA%\Temp\thehub-deploy.lock, and the test-container lock.

    RE-ENTRANT FOR ONE CHILD. The watcher takes the lock for the whole
    attempt (the deploy, the health check and a rollback), then runs
    deploy.ps1 as a child process. The child would find the lock held and
    refuse. So the holder writes a random token into owner.json and passes
    it in MYKRONOS_DEPLOY_LOCK_TOKEN; a deploy.ps1 that carries the matching
    token proceeds under its parent's lock and leaves it for the parent to
    release. The token is a local nonce, not a credential.

    A LOCK LEFT BEHIND IS NOT CLEARED HERE. A killed run can leave the
    directory, and every later deploy then refuses until a person checks
    that nothing is running and removes it. Guessing that a lock is stale is
    how two deploys end up overlapping.

    Windows PowerShell 5.1 compatible and ASCII only: deploy.ps1 still runs
    under whichever PowerShell the operator opens.
#>

function Get-MykronosDeployLockPath {
    if ($env:MYKRONOS_DEPLOY_LOCK_DIR) { return $env:MYKRONOS_DEPLOY_LOCK_DIR }
    return (Join-Path $env:LOCALAPPDATA 'Temp\mykronos-deploy.lock')
}

function Read-MykronosDeployLockOwner {
    param([string]$Path = (Get-MykronosDeployLockPath))
    $ownerFile = Join-Path $Path 'owner.json'
    if (-not (Test-Path -LiteralPath $ownerFile)) { return $null }
    try {
        return (Get-Content -LiteralPath $ownerFile -Raw | ConvertFrom-Json)
    } catch {
        return $null
    }
}

function Enter-MykronosDeployLock {
    <#
        Returns a hashtable:
          Acquired  $true when the caller may deploy
          Owned     $true when the caller created the lock and must release it
          Path      the lock directory
          Token     the nonce a child needs (only when Owned)
          Owner     who holds it (only when not Acquired), or $null
    #>
    param(
        [string]$Holder = 'unknown',
        [string]$Path = (Get-MykronosDeployLockPath)
    )
    if (Test-Path -LiteralPath $Path) {
        $owner = Read-MykronosDeployLockOwner -Path $Path
        $inherited = $env:MYKRONOS_DEPLOY_LOCK_TOKEN
        if ($inherited -and $owner -and ([string]$owner.token) -eq $inherited) {
            return @{ Acquired = $true; Owned = $false; Path = $Path; Token = $null; Owner = $owner }
        }
        return @{ Acquired = $false; Owned = $false; Path = $Path; Token = $null; Owner = $owner }
    }
    try {
        # No -Force: on an existing directory this throws, which is the lock.
        New-Item -ItemType Directory -Path $Path -ErrorAction Stop | Out-Null
    } catch {
        return @{ Acquired = $false; Owned = $false; Path = $Path; Token = $null;
            Owner = (Read-MykronosDeployLockOwner -Path $Path) }
    }
    $token = [guid]::NewGuid().ToString('N')
    $owner = [ordered]@{
        pid        = $PID
        holder     = $Holder
        started_at = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        token      = $token
    }
    try {
        Set-Content -LiteralPath (Join-Path $Path 'owner.json') -Encoding ascii `
            -Value ($owner | ConvertTo-Json -Compress)
    } catch {
        # The lock is held whether or not the owner file was written; an
        # unnamed owner only makes the "held by" message less useful.
        Write-Verbose "lock owner not written: $($_.Exception.Message)"
    }
    return @{ Acquired = $true; Owned = $true; Path = $Path; Token = $token; Owner = $null }
}

function Exit-MykronosDeployLock {
    param([hashtable]$Lock)
    if ($null -eq $Lock -or -not $Lock.Owned) { return }
    Remove-Item -LiteralPath $Lock.Path -Recurse -Force -ErrorAction SilentlyContinue
}

function Format-MykronosDeployLockOwner {
    param($Owner)
    if ($null -eq $Owner) { return 'an unnamed holder (no owner.json)' }
    return ('pid {0}, {1}, since {2}' -f $Owner.pid, $Owner.holder, $Owner.started_at)
}
