<#
.SYNOPSIS
    Poll MinIO for a release pointer and deploy the image it names.

.DESCRIPTION
    The host side of the pull-based deploy. Concourse never connects here and
    this machine runs no listener for it to connect to: the pipeline writes a
    commit SHA to `<environment>.requested` in the release bucket, this script
    notices, and Invoke-TheHubDeploy.ps1 pulls that image by SHA and restarts
    the stack.

    Spec 16 section 7 originally answered "how does Concourse restart a
    service" with a forced-command SSH key per environment. That works, and it
    needs sshd listening on a machine inside the LAN. This gets the same
    result the way docker-compose.yml already argued for over mounting the
    Docker socket - "a registry is a one-way handoff: Concourse can publish an
    image, and nothing it does can restart a service" - by making the
    instruction one-way too.

    What it costs, said plainly: sshd enforced environment separation against
    the key that authenticated, so a demo key could not reach production. Here
    the separation is by object name. This script deploys `demo.requested` to
    demo and `prod.requested` to prod and cannot confuse the two, but anything
    holding the MinIO credentials can write either pointer.

    After a successful deploy it writes `<environment>.deployed` back. That is
    not bookkeeping: the pipeline blocks on it, so `passed: [deploy-demo]`
    means demo is serving that commit rather than that a request was filed.

.PARAMETER Environments
    Which pointers to check. Both by default.

.PARAMETER Once
    Check once and exit. This is how the Scheduled Task runs it; the polling
    loop is for running it by hand while watching.

.NOTES
    ASCII only - see deploy\concourse\setup.ps1.

    Credentials come from deploy\concourse\.env and are passed to mc through
    MC_HOST_<alias> rather than `mc alias set`, which would write them to
    %USERPROFILE%\mc\config.json and leave a second copy on disk.
#>

[CmdletBinding()]
param(
    [ValidateSet("demo", "prod")]
    [string[]]$Environments = @("demo", "prod"),
    [string]$Endpoint = "http://localhost:9000",
    [string]$Bucket = "thehub-releases",
    [switch]$Once,
    [int]$IntervalSeconds = 60
)

$ErrorActionPreference = "Stop"
$here = $PSScriptRoot
$deployScript = Join-Path $here "Invoke-TheHubDeploy.ps1"
if (-not (Test-Path $deployScript)) { throw "Missing $deployScript" }

$stackEnv = Join-Path $here "..\concourse\.env"
if (-not (Test-Path $stackEnv)) { throw "Missing $stackEnv" }

function Read-EnvValue {
    param([string]$Path, [string]$Key)
    $line = Select-String -Path $Path -Pattern "^$Key=" -ErrorAction SilentlyContinue
    if (-not $line) { throw "$Key is not set in $Path" }
    return $line.Line.Split('=', 2)[1].Trim()
}

$mc = Join-Path $here "..\concourse\bin\mc.exe"
if (-not (Test-Path $mc)) {
    Write-Host "Fetching mc.exe..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri "https://dl.min.io/client/mc/release/windows-amd64/mc.exe" `
        -OutFile $mc -UseBasicParsing
}

$uri = [System.Uri]$Endpoint
$creds = "{0}:{1}" -f
    [System.Uri]::EscapeDataString((Read-EnvValue $stackEnv "MINIO_ROOT_USER")),
    [System.Uri]::EscapeDataString((Read-EnvValue $stackEnv "MINIO_ROOT_PASSWORD"))
$env:MC_HOST_thehub = "{0}://{1}@{2}" -f $uri.Scheme, $creds, $uri.Authority

function Get-Pointer {
    param([string]$Name)
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) "thehub-$Name-$(Get-Random)"

    # ErrorActionPreference is Stop for this script, and under Windows
    # PowerShell anything a native command writes to stderr becomes a
    # NativeCommandError -- which Stop makes terminating. `mc` writes
    # "Object does not exist" to stderr on the ordinary "nothing published
    # yet" path, so this function threw instead of returning $null and took
    # the whole run with it. `2>$null` discards the text but not the error
    # record, which is why it looked handled.
    #
    # A missing pointer is the normal state of this bucket most of the time,
    # so it is relaxed here and only here.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & $mc --quiet cp "thehub/$Bucket/$Name" $tmp 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $tmp)) { return $null }
        return (Get-Content $tmp -Raw).Trim()
    } finally {
        $ErrorActionPreference = $previous
        if (Test-Path $tmp) { Remove-Item $tmp -Force }
    }
}

$script:failures = 0

function Invoke-Cycle {
    foreach ($environment in $Environments) {
        $requested = Get-Pointer "$environment.requested"
        if (-not $requested) { continue }

        # Validated here as well as in Invoke-TheHubDeploy. The pointer is
        # read from object storage, and "whatever was in the bucket" reaching
        # a command line is exactly the shape of input that deserves checking
        # twice rather than trusting the writer.
        if ($requested -notmatch '^[0-9a-f]{40}$') {
            Write-Host "$environment.requested is not a commit SHA ('$requested') - ignoring." -ForegroundColor Red
            $script:failures++
            continue
        }

        # The deploy script's own state file is the authority on what is
        # running. Reading MinIO's `.deployed` instead would let a failed
        # write-back cause an endless redeploy of a commit already live.
        $stateFile = Join-Path $here ".deployed-$environment"
        $current = if (Test-Path $stateFile) { (Get-Content $stateFile -Raw).Trim() } else { "" }

        if ($current -eq $requested) {
            Write-Verbose "$environment is already at $requested"
            continue
        }

        # A pointer this host has already failed on is not retried. Without
        # this the loop is genuinely harmful rather than merely useless: a
        # SHA that cannot deploy - because the compose file is not wired to
        # THEHUB_IMAGE, or because its fixed container_name collides with a
        # container another project already owns - is retried every interval
        # forever, and each attempt runs `docker compose up`, which rebuilds
        # the image from source before failing. That is a build loop on a
        # machine nobody is watching.
        #
        # The marker is cleared by a *different* SHA arriving, so a fix
        # deploys immediately without anyone clearing state by hand.
        $failedFile = Join-Path $here ".failed-$environment"
        $failed = if (Test-Path $failedFile) { (Get-Content $failedFile -Raw).Trim() } else { "" }
        if ($failed -eq $requested) {
            Write-Verbose "$environment already failed on $requested - not retrying"
            continue
        }

        Write-Host "$environment : $current -> $requested" -ForegroundColor Cyan

        # Invoke-TheHubDeploy reports every real failure with `throw`, not an
        # exit code - "Could not pull", "docker compose up failed", "Nothing
        # in $project is running $ImageRef". With ErrorActionPreference Stop
        # those propagate straight through this call, so the whole block
        # below used to be unreachable for exactly the failures it was written
        # for: no marker was recorded, the no-retry protection never engaged,
        # and the run died before the other environment was even looked at.
        #
        # TimeoutMinutes is raised from the script's default of 5 because a
        # first boot into an empty environment measured ~6m47s to answer
        # /health - so the default failed a deploy that was working, and left
        # a .failed marker that would have stopped it being retried. 12 keeps
        # room under the pipeline's own 15-minute wait for the acknowledgement.
        #
        # Demo is rebuilt from scratch on every deploy: volumes destroyed,
        # stack recreated from the compose file, migrations and seed_demo.py
        # run. That is what lets the functional suite and DAST downstream mean
        # something - both run against the same dataset every time, so a test
        # that changes verdict did so because the code changed and not because
        # the last eight runs left rows behind.
        #
        # Prod is never rebuilt. The switch is passed only for demo here, and
        # Invoke-TheHubDeploy refuses it for any other environment at the point
        # where the volumes would actually be deleted.
        $rebuild = @{}
        if ($environment -eq "demo") { $rebuild["Rebuild"] = $true }

        $deployError = $null
        try {
            & $deployScript -Environment $environment -Sha $requested -TimeoutMinutes 12 @rebuild
            $deployExit = $LASTEXITCODE
        } catch {
            $deployError = $_.Exception.Message
            $deployExit = 1
        }

        if ($deployExit -ne 0) {
            # Not acknowledged. The pipeline is waiting on that value and a
            # timeout there is the correct outcome - reporting a SHA that did
            # not deploy would let DAST probe the previous build and attribute
            # the result to this commit.
            Set-Content -Path $failedFile -Value $requested -NoNewline -Encoding ASCII
            Write-Host "$environment deploy failed (exit $deployExit)." -ForegroundColor Red
            if ($deployError) { Write-Host "  $deployError" -ForegroundColor Red }
            Write-Host "  Pointer left unacknowledged and recorded in $(Split-Path $failedFile -Leaf)." -ForegroundColor Red
            Write-Host "  This SHA will not be retried; publishing a different one clears it." -ForegroundColor Red
            $script:failures++
            continue
        }

        # A success supersedes any earlier failure, including one on this same
        # SHA from before whatever was wrong got fixed.
        if (Test-Path $failedFile) { Remove-Item $failedFile -Force -EA SilentlyContinue }

        $ack = Join-Path ([System.IO.Path]::GetTempPath()) "ack-$environment-$(Get-Random)"
        try {
            [System.IO.File]::WriteAllText($ack, $requested)
            & $mc --quiet cp $ack "thehub/$Bucket/$environment.deployed" | Out-Null
            Write-Host "$environment deployed and acknowledged at $requested" -ForegroundColor Green
        } finally {
            if (Test-Path $ack) { Remove-Item $ack -Force }
        }
    }
}

try {
    if ($Once) {
        Invoke-Cycle
        # Explicit, because `mc` leaves a non-zero $LASTEXITCODE behind on the
        # perfectly normal "no pointer published yet" path. Without this the
        # Scheduled Task records every quiet run as a failure, and a task that
        # is always red is a task nobody looks at.
        exit $(if ($script:failures -gt 0) { 1 } else { 0 })
    } else {
        Write-Host "Polling $Endpoint/$Bucket every $IntervalSeconds s. Ctrl-C to stop." -ForegroundColor DarkGray
        while ($true) {
            try { Invoke-Cycle } catch { Write-Host "Cycle failed: $($_.Exception.Message)" -ForegroundColor Red }
            Start-Sleep -Seconds $IntervalSeconds
        }
    }
} finally {
    Remove-Item Env:\MC_HOST_thehub -ErrorAction SilentlyContinue
}
