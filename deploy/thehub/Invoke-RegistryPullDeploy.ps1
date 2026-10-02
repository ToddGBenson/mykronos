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

    THE TASK'S REPETITION INTERVAL IS PART OF THE DEPLOY BUDGET.

    The pipeline's deploy job publishes a pointer and then waits
    deploy-timeout-minutes for the acknowledgement. Everything between those
    two moments has to fit, and this task's interval is dead time at the front
    of it: at PT5M the agent could sit for five minutes before it even looked.

    Against a demo rebuild that now runs init_db, 273 migrations, four workers
    and a seed, five minutes of polling latency was enough to fail the job
    while the deploy underneath it was succeeding. Set to PT1M:

      Set-ScheduledTask -TaskName "TheHub Registry Pull Deploy" -Trigger $t

    A quiet cycle is one `mc cp` that finds nothing, so a one-minute interval
    costs almost nothing. If you lengthen it, lengthen the pipeline's
    deploy-timeout-minutes to match.

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

# [#60517] The release pointer is read over MinIO's own S3 HTTP API, signed with
# AWS SigV4, from this process. No binary inside the storage container, and
# nothing downloaded.
#
# HISTORY, because both previous forms broke for the same underlying reason --
# depending on a binary this script does not own:
#
#   Originally a local mc.exe, fetched from
#   https://dl.min.io/client/mc/release/windows-amd64/mc.exe on first use. That
#   URL, and every dl.min.io path tried alongside it, now returns HTTP 410 Gone.
#   With $ErrorActionPreference = "Stop" the failed fetch threw and the script
#   exited 1 before doing anything, every five minutes.
#
#   Then (2026-09-14) `docker exec mykronos-minio mc --quiet cat`, using the
#   binary already inside the running container. mykronos 5b61ff6 (2026-09-25)
#   moved artifact storage to pgsty/silo:...-distroless, whose own compose
#   comment says "Distroless has no shell and no mc" -- and accounted for it
#   only in the healthcheck. So:
#
#       docker exec mykronos-minio mc --version
#         -> exec: "mc": executable file not found in $PATH
#
#   The demo sat 12 commits behind from 2026-09-26 02:21Z while the agent
#   reported success.
#
# A SIDECAR WOULD REINTRODUCE THE SAME COUPLING and break on the next image
# change. The S3 API is the storage service's actual contract, so this depends on
# that instead. Roughly forty lines of HMAC, no dependency, and it cannot be
# removed by someone swapping the image.

# 127.0.0.1, NOT localhost. On this host `localhost` resolves to ::1 first, where
# wslrelay holds the port and never answers -- so the request HANGS rather than
# being refused, and a hung five-minute agent looks exactly like a quiet one.
# A healthy MinIO would read as dead.
if ($Endpoint -match '^(https?)://localhost(:|/|$)') {
    $Endpoint = $Endpoint -replace '://localhost', '://127.0.0.1'
    Write-Host "Endpoint rewritten to $Endpoint (localhost resolves to a squatted ::1 on this host)." -ForegroundColor DarkGray
}

$uri = [System.Uri]$Endpoint
$S3AccessKey = Read-EnvValue $stackEnv "MINIO_ROOT_USER"
$S3SecretKey = Read-EnvValue $stackEnv "MINIO_ROOT_PASSWORD"
$S3Region = "us-east-1"   # MinIO's default; it is signed, not resolved.

function Get-Sha256Hex {
    param([byte[]]$Bytes)

    # THREE POWERSHELL TRAPS IN FOUR LINES, all hit while writing this and all
    # worth naming so the next edit does not re-introduce them:
    #
    #  1. An EMPTY byte[] -- which a GET's body is -- makes PowerShell unable to
    #     choose between ComputeHash(byte[]) and ComputeHash(Stream):
    #     "Multiple ambiguous overloads found for ComputeHash". Hence the cast at
    #     each call below rather than one shared variable.
    #  2. `$payload = if (...) { [byte[]]::new(0) } else { $Bytes }` yields $null,
    #     because assigning an expression whose value is an empty collection
    #     UNROLLS it to nothing. That produced "Value cannot be null (Parameter
    #     'buffer')". So the branches call ComputeHash directly and nothing
    #     holds an empty array.
    #  3. The obvious name for that variable, $input, is an AUTOMATIC variable
    #     holding the pipeline enumerator. Assigning to it fails quietly.
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        if ($null -eq $Bytes -or $Bytes.Length -eq 0) {
            $hash = $sha.ComputeHash([byte[]]::new(0))
        } else {
            $hash = $sha.ComputeHash([byte[]]$Bytes)
        }
        return -join ($hash | ForEach-Object { $_.ToString("x2") })
    } finally { $sha.Dispose() }
}


function Get-HmacSha256 {
    param([byte[]]$Key, [string]$Message)
    $h = New-Object System.Security.Cryptography.HMACSHA256
    try {
        $h.Key = $Key
        return $h.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Message))
    } finally { $h.Dispose() }
}

# One signed request. Returns a result object rather than throwing, because the
# CALLER has to tell "nothing published yet" (404, normal) from "could not read"
# (anything else, a failure) -- collapsing those two is the defect #60517 fixes.
function Invoke-S3Request {
    param(
        [ValidateSet("GET", "PUT")][string]$Method,
        [string]$Key,
        [string]$Body = ""
    )

    $now = [DateTime]::UtcNow
    $amzDate = $now.ToString("yyyyMMddTHHmmssZ")
    $dateStamp = $now.ToString("yyyyMMdd")

    $bodyBytes = if ($Body) { [System.Text.Encoding]::UTF8.GetBytes($Body) } else { [byte[]]::new(0) }

    # The payload IS signed. Getting here took two wrong turns worth recording,
    # because both had the same root cause in opposite directions.
    #
    # Passing `-Body $bodyBytes` (a byte[]) made Invoke-WebRequest STRINGIFY the
    # array: the 40-character SHA went on the wire as "50 98 50 49 50 53 ...",
    # its own decimal code points, space separated. So MinIO hashed 126 bytes of
    # digits while this process hashed 40 bytes of hex, and every write failed
    # with XAmzContentSHA256Mismatch. The first fix reached for UNSIGNED-PAYLOAD,
    # which made the write SUCCEED and stored the digits -- a green acknowledgement
    # carrying nonsense, which is worse than the failure it replaced. The read
    # side had the mirror-image bug (`| Out-String` on a byte[]).
    #
    # The body is now sent as the STRING and signed properly, so the signature
    # covers it and a corrupted body is rejected rather than stored.
    $payloadHash = Get-Sha256Hex -Bytes $bodyBytes

    # Each path segment is escaped, but the separators are not: S3 signs the
    # canonical URI with '/' intact.
    #
    # The join is a SEPARATE statement on purpose. Written as
    #     "/" + (($Key -split '/') | ForEach-Object { ... }) -join '/'
    # PowerShell precedence makes it ("/" + $array) -join '/', and a string plus
    # an array is STRING CONCATENATION with the array flattened on spaces. The
    # request went out as /thehub-releases demo.requested and MinIO answered
    # InvalidBucketName -- which named the symptom precisely and took a round trip
    # to see.
    $segments = ($Key -split '/') | ForEach-Object { [System.Uri]::EscapeDataString($_) }
    $canonicalUri = '/' + ($segments -join '/')

    $canonicalHeaders = "host:$($uri.Authority)`nx-amz-content-sha256:$payloadHash`nx-amz-date:$amzDate`n"
    $signedHeaders = "host;x-amz-content-sha256;x-amz-date"
    $canonicalRequest = "$Method`n$canonicalUri`n`n$canonicalHeaders`n$signedHeaders`n$payloadHash"

    $scope = "$dateStamp/$S3Region/s3/aws4_request"
    $stringToSign = "AWS4-HMAC-SHA256`n$amzDate`n$scope`n" +
        (Get-Sha256Hex -Bytes ([System.Text.Encoding]::UTF8.GetBytes($canonicalRequest)))

    $kSecret = [System.Text.Encoding]::UTF8.GetBytes("AWS4$S3SecretKey")
    $kDate = Get-HmacSha256 -Key $kSecret -Message $dateStamp
    $kRegion = Get-HmacSha256 -Key $kDate -Message $S3Region
    $kService = Get-HmacSha256 -Key $kRegion -Message "s3"
    $kSigning = Get-HmacSha256 -Key $kService -Message "aws4_request"
    $signature = -join ((Get-HmacSha256 -Key $kSigning -Message $stringToSign) |
        ForEach-Object { $_.ToString("x2") })

    $headers = @{
        "x-amz-date"           = $amzDate
        "x-amz-content-sha256" = $payloadHash
        "Authorization"        = "AWS4-HMAC-SHA256 Credential=$S3AccessKey/$scope, SignedHeaders=$signedHeaders, Signature=$signature"
    }

    $target = "$($uri.Scheme)://$($uri.Authority)$canonicalUri"
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $params = @{
            Uri = $target; Method = $Method; Headers = $headers
            UseBasicParsing = $true; TimeoutSec = 20
            # .NET parses Authorization strictly and rejects SigV4's
            # "Scheme Credential=..., SignedHeaders=..., Signature=..." form
            # outright: "The format of value 'AWS4-HMAC-SHA256 Credential=...'
            # is invalid." The header is well-formed for S3; it is the client
            # that is wrong about it, so validation is skipped for this call
            # only. PowerShell 7 required -- which the Scheduled Task already
            # uses (pwsh.exe, not powershell.exe).
            SkipHeaderValidation = $true
        }
        if ($Method -eq "PUT") {
            # THE STRING, NOT $bodyBytes. A byte[] body is stringified by
            # Invoke-WebRequest into its decimal code points -- see the note on
            # $payloadHash above. The string is UTF8-encoded on the wire, which is
            # exactly what $bodyBytes was hashed from, so the signature matches.
            $params["Body"] = $Body
            $params["ContentType"] = "text/plain; charset=utf-8"
        }
        $response = Invoke-WebRequest @params

        # DECODE, do not stringify. With -UseBasicParsing, Invoke-WebRequest
        # hands back a byte[] for a response S3 serves as
        # application/octet-stream, and `| Out-String` on a byte[] renders the
        # DECIMAL CODE POINTS one per line: a 40-character SHA came out as
        # "50`n98`n50`n49..." and tripped the SHA validation with a number.
        $raw = $response.Content
        $text = if ($raw -is [byte[]]) {
            [System.Text.Encoding]::UTF8.GetString($raw)
        } else {
            [string]$raw
        }
        return [pscustomobject]@{
            Status = "ok"; Code = [int]$response.StatusCode
            Content = $text; Error = $null
        }
    } catch {
        $code = 0
        try { $code = [int]$_.Exception.Response.StatusCode } catch { $code = 0 }
        if ($code -eq 404) {
            # Nothing published yet. The normal state of this bucket most of the
            # time, and NOT a failure.
            return [pscustomobject]@{ Status = "absent"; Code = 404; Content = $null; Error = $null }
        }
        # S3 says WHY in the response body, and without it "400 Bad Request" is
        # unactionable -- it covers a clock skew, a wrong region, a malformed
        # canonical request and a bad key with one sentence.
        $detail = ""
        try {
            $stream = $_.Exception.Response.GetResponseStream()
            if ($stream) {
                $reader = New-Object System.IO.StreamReader($stream)
                try { $detail = $reader.ReadToEnd() } finally { $reader.Dispose() }
            }
        } catch { $detail = "" }
        if (-not $detail) {
            try { $detail = [string]$_.ErrorDetails.Message } catch { $detail = "" }
        }
        return [pscustomobject]@{
            Status = "unreadable"; Code = $code; Content = $null
            Error = if ($detail) {
                "{0} | {1}" -f $_.Exception.Message, ($detail -replace '\s+', ' ')
            } else { $_.Exception.Message }
        }
    } finally {
        $ErrorActionPreference = $previous
    }
}

function Get-Pointer {
    param([string]$Name)

    # [#60517] THREE OUTCOMES, NOT TWO. This is the half that mattered.
    #
    # This returned $null for BOTH "nothing published yet" and "could not read
    # the pointer at all", and `Invoke-Cycle` answered both with a bare
    # `continue`. So when mc vanished from the distroless storage image on
    # 2026-09-25 the agent skipped silently every five minutes: no log line, no
    # failure count, LastTaskResult 0, NumberOfMissedRuns 0 -- and the demo sat
    # 12 commits behind for two days while the task reported success.
    #
    # Reading the pointer is no longer a native command, so the old
    # NativeCommandError dance is gone with it: Invoke-S3Request returns a
    # status instead of throwing.
    $result = Invoke-S3Request -Method GET -Key "$Bucket/$Name"

    if ($result.Status -eq "absent") {
        # The normal state of this bucket most of the time.
        return [pscustomobject]@{ Status = "absent"; Value = $null; Detail = $null }
    }
    if ($result.Status -ne "ok") {
        return [pscustomobject]@{
            Status = "unreadable"; Value = $null
            Detail = "HTTP $($result.Code): $($result.Error)"
        }
    }

    $content = ($result.Content | Out-String).Trim()
    if (-not $content) {
        # Present but EMPTY. Not absent -- somebody wrote a zero-length pointer,
        # which is a real fault and used to read as "nothing published".
        return [pscustomobject]@{
            Status = "unreadable"; Value = $null
            Detail = "the object exists but is empty"
        }
    }
    return [pscustomobject]@{ Status = "found"; Value = $content; Detail = $null }
}


# Writes a pointer back. Returns $true on success so a failed acknowledgement is
# visible to the caller instead of vanishing into Out-Null.
function Set-Pointer {
    param([string]$Name, [string]$Content)
    $result = Invoke-S3Request -Method PUT -Key "$Bucket/$Name" -Body $Content
    if ($result.Status -ne "ok") {
        Write-Host ("Could not write {0}: HTTP {1} {2}" -f $Name, $result.Code, $result.Error) -ForegroundColor Red
        return $false
    }
    return $true
}

$script:failures = 0

function Invoke-Cycle {
    foreach ($environment in $Environments) {
        $pointer = Get-Pointer "$environment.requested"

        # [#60517] A pointer that CANNOT BE READ is a failure, not a quiet skip.
        # `if (-not $requested) { continue }` answered "nothing published" and
        # "storage is unreachable" identically, which is how this agent ran green
        # for two days while deploying nothing.
        if ($pointer.Status -eq "unreadable") {
            Write-Host ("Could not read {0}.requested - {1}" -f $environment, $pointer.Detail) -ForegroundColor Red
            $script:failures++
            continue
        }
        if ($pointer.Status -eq "absent") { continue }
        $requested = $pointer.Value

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
            # Already there -- but the pipeline does not know that until the
            # acknowledgement says so. This branch used to `continue` without
            # writing one, which stranded exactly the runs where nothing was
            # wrong: a deploy-demo retriggered for a SHA that already deployed,
            # or a first attempt whose deploy landed and whose ack write
            # failed, sat out the pipeline's full wait and went red with the
            # environment serving the right commit underneath it.
            #
            # The state file stays the authority on what is RUNNING (see
            # above); MinIO's `.deployed` is only the messenger, and a
            # messenger may repeat itself. Re-writing an ack that already
            # matches is a no-op.
            $ack = Get-Pointer "$environment.deployed"
            if ($ack.Status -eq "unreadable") {
                Write-Host ("Could not read {0}.deployed - {1}" -f $environment, $ack.Detail) -ForegroundColor Red
                $script:failures++
                continue
            }
            $known = $ack.Value
            if ($known -ne $requested) {
                Write-Host "$environment already at $requested - writing the missing acknowledgement." -ForegroundColor Cyan
                if (-not (Set-Pointer -Name "$environment.deployed" -Content $requested)) {
                    $script:failures++
                }
            } else {
                Write-Verbose "$environment is already at $requested"
            }
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

        # A deploy that landed and could not say so strands the pipeline on its
        # full wait, so the write is checked rather than fired and forgotten.
        if (Set-Pointer -Name "$environment.deployed" -Content $requested) {
            Write-Host "$environment deployed and acknowledged at $requested" -ForegroundColor Green
        } else {
            # [#60517] This printed "deployed and acknowledged" UNCONDITIONALLY,
            # on the line after the write that had just failed. The deploy really
            # did land, so saying nothing would be wrong too -- they are two
            # separate facts and both get said.
            $script:failures++
            Write-Host ("$environment IS serving $requested, but the " +
                "acknowledgement could not be written - the pipeline will wait " +
                "out its deploy timeout and go red over a deploy that worked") -ForegroundColor Yellow
        }
    }
}

try {
    if ($Once) {
        # Under the Scheduled Task, stdout goes nowhere. The 2026-08-15 demo
        # failure was diagnosed by re-running the deploy by hand because the
        # task's two failed attempts left no record of *why* - this log makes
        # the next one legible. All streams, so the deploy script's own output
        # and native-command stderr land too. A quiet cycle appends nothing,
        # and the size cap keeps an unattended task from growing it unbounded.
        $log = Join-Path $here "registry-pull-deploy.log"
        if ((Test-Path $log) -and (Get-Item $log).Length -gt 256KB) {
            Remove-Item $log -Force -ErrorAction SilentlyContinue
        }
        $stamp = "==== cycle $(Get-Date -Format o) ===="
        $lines = & { Invoke-Cycle } *>&1 | ForEach-Object { "$_" }
        if ($lines) {
            Add-Content -Path $log -Value (@($stamp) + $lines) -Encoding UTF8
            # Run by hand with -Once, the capture above would otherwise eat
            # the output entirely.
            $lines | ForEach-Object { Write-Host $_ }
        } else {
            # [#60517] AN HOURLY HEARTBEAT, so a quiet agent is distinguishable
            # from a stopped one.
            #
            # A quiet cycle appended nothing, which is right for volume and wrong
            # for diagnosis: registry-pull-deploy.log last wrote 2026-09-25 12:39
            # and that told nobody whether the agent was idle, hung, or gone. An
            # empty log and a dead task looked identical for two days.
            #
            # Once an hour, not every cycle: at a one-minute interval a per-cycle
            # marker is 1440 lines a day for no added information, and the 256KB
            # cap above would start rotating away the lines that matter.
            $heartbeat = Join-Path $here ".pull-deploy-heartbeat"
            $last = if (Test-Path $heartbeat) {
                try { [DateTime]::Parse((Get-Content $heartbeat -Raw).Trim()) } catch { [DateTime]::MinValue }
            } else { [DateTime]::MinValue }
            if (([DateTime]::UtcNow - $last).TotalMinutes -ge 60) {
                Add-Content -Path $log -Value (
                    "$stamp quiet - no pointer published for: $($Environments -join ', ') " +
                    "(endpoint reachable, nothing to do)"
                ) -Encoding UTF8
                Set-Content -Path $heartbeat -Value ([DateTime]::UtcNow.ToString("o")) -Encoding UTF8
            }
        }
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
    # [#60517] MC_HOST_thehub is no longer set -- the pointer is read over the S3
    # HTTP API and the credential never enters the environment. Kept as a cleanup
    # for a process that still has one from an older run of this script in the
    # same session; harmless when absent.
    Remove-Item Env:\MC_HOST_thehub -ErrorAction SilentlyContinue
}
