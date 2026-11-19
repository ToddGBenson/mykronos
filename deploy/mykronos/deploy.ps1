<#
.SYNOPSIS
    Pull the images the pipeline published and bring the Mykronos stack up.

.DESCRIPTION
    The host half of the deploy (spec 15 §3, D-038). CI builds images and
    pushes them to a registry; this pulls and restarts. Nothing in the
    pipeline can run this, deliberately: a CI task with the host's Docker
    socket could restart anything on this machine, which is the risk spec 15
    §7 raises about a worker sitting inside the LAN. A registry is a one-way
    handoff, and that property is what survived the move to Actions unchanged.

    Pulls from GHCR since spec 32 §4.1. It used to pull `localhost:5000` - a
    registry with no TLS and no authentication, reachable only from this LAN
    and therefore unreachable from a GitHub-hosted runner. GHCR is reachable
    from both ends, and authenticates, which the LAN registry never did.

    Two things that can go wrong here and did not before, both handled below:

    A GHCR package is **private by default even in a public repository**.
    Publishing from Actions does not make it public; that is a separate switch
    in the package's settings. A private package needs `docker login ghcr.io`
    on this host with a token carrying `read:packages`.

    THERE IS NO `:latest` ANY MORE (D-125). `delivery.yml` publishes `:${SHA}`
    on every push and that is the whole tagging model. The `promote` workflow
    that used to move `:latest` behind a production approval has been retired:
    it never once ran in its entire history - 99 runs, 99 cancelled, zero
    completions - and left `:latest` pointing at an image OLDER than the last
    production deploy. A default that ships something older than what is
    already running is worse than having no default.

    So the sha is mandatory. That is not a new burden: every real deploy for
    months already passed `-Tag <sha>`, because `:latest` could not be
    trusted. D-125 makes the practice the contract.

    WHERE THE HUMAN GATE WENT. It did not disappear - it was never anywhere
    else. Running this script is the deploy decision, and it has always been a
    manual action on this host. The promote approval was a second gate layered
    on top, and it was the one that never worked.

    THE MACHINE SAYS NO AGAIN (#60487, D-126). Retiring the tag left nothing
    mechanical between a `no_go` and production - the exact hole D-047 existed
    to close. This script now asks the platform what the risk gate decided
    about the sha before it pulls anything, and REFUSES a commit the gate
    refused unless -Force is passed with a reason that is recorded.

    THE RATCHET, AND IT FAILS CLOSED (D-183, operator decision 2026-11-15).
    Since D-183 the question is not "what did the gate decide about this sha"
    but "may this sha replace the one running", asked of
    GET /api/oracle/deploy-gate with the running image's MYKRONOS_BUILD_SHA as
    the baseline. The platform refuses a deploy that raises the risk score
    beyond a 0.5 tolerance or brings an open critical or high the running
    commit lacks; once the repository has been below No-Go it refuses any
    No-Go; and it allows a fix that lowers the score while still No-Go. Both
    scores are measured over one findings snapshot, so a CVE published since
    the running commit was scanned moves both equally and refuses nothing.

    It supersedes D-126's fail-open posture and D-159's "only the floor
    refuses". Everything that is not an explicit `allow` stops before
    anything is pulled: a refusal, a sha nothing has scored, and a platform
    this host could not ask (unreachable, no token, an answer that is not a
    ratchet verdict). The cost D-126 named is real - a sealed Vault or a
    down backend now blocks the deploy that would fix it - and the answer to
    it is -Force with a recorded reason, which is the operator's alone.
    Agents never pass -Force.

    THE OUTCOMES DO NOT LOOK ALIKE. An allow is ONE quiet line; every refusal
    names its codes and scores, and every run's verdict is repeated as the
    last line on the screen and appended to `deploy-risk-log.jsonl` beside
    this script, refusals and overrides included.

    AND IT WAITS FOR THE ANSWER (#735). The gate is not part of Delivery: it
    runs in Concourse after every scan lane for the commit has finished,
    which on 2026-09-29 was 29 and 32 minutes after Delivery went green. So
    when the ratchet answers only `no_decision` this script polls, for
    -GateWaitMinutes (45 by default), and then refuses as NOT JUDGED, naming
    the nearest ancestor the gate did score.

    SCOPE. D-125 retired the GHCR `:latest`, which is what this script pulls by
    default. A SECOND promote exists in the Concourse `mykronos.yml` pipeline
    and still retags `:latest` on the LAN registry (192.168.0.14:5000). If you
    pass `-Registry localhost:5000` you are on that path, and a `:latest` may
    still exist there. `-Tag` is mandatory either way.

.PARAMETER Tag
    REQUIRED. The commit sha to deploy - 7 to 40 hex characters, validated.

    Rollback is the same command with the previous sha, plus -Restore when
    the ratchet cannot be asked (the failed deploy took the backend down):
    see .PARAMETER Restore. The deploy reads
    the running container's `MYKRONOS_BUILD_SHA` afterwards and says whether
    the running commit is the one requested, because "healthy" and "running what you asked for" are different
    facts and only the second one is the deploy's job.

.PARAMETER PlatformUrl
    Where to ask the ratchet. The local production backend, and ONLY that:
    http://127.0.0.1:8100 is the one value accepted (D-183). Since the gate
    fails closed, the address it asks is the gate - a listener elsewhere
    that answers {"allow": true} would otherwise ship anything with no
    -Force and no override in the ledger. The parameter stays so the value is
    visible and recorded (`asked` on every ledger line), not so it can move.

.PARAMETER GateWaitMinutes
    How long to wait for the risk gate to score the sha when it has not yet
    (#735). Default 45: the gate has answered about 30 minutes after Delivery.
    0 asks once and does not wait - the old behaviour, for an emergency
    deploy where the ledger's NOT JUDGED line is the accepted cost.

.PARAMETER Force
    OPERATOR ONLY; agents never pass it. Deploy a sha the ratchet did not
    allow: refused, never scored, or not asked at all.
    Requires -ForceReason, and the reason
    is written to a ledger beside this script before anything is pulled. An
    override nobody can find afterwards is not an override, it is an
    unrecorded exception.

.PARAMETER Restore
    Redeploy the sha that was running before the most recent deploy, WITHOUT
    asking the ratchet (D-183, operator decision 2026-11-15: "Allow restore
    of the prior sha"). It exists for the rollback after a failed deploy,
    when the backend that answers the ratchet is the thing that failed.

    The sha is not the caller's word. Before every pull, deploy.ps1 writes
    an `event=deploying` line with the running build stamp it replaces
    (`previous`) and an HMAC of it keyed with this host's platform token. A
    restore is accepted only when -Tag is that recorded sha (or a prefix of
    it, the tag a hand deploy may have pulled) for the MOST RECENT
    `deploying` line, and that line verifies. Anything else refuses before
    anything moves (`restore_refused`): a different sha, no ledger, an
    unreadable or edited ledger, a deploy that recorded no running sha, or
    no token to verify with. The restore is recorded as `event=restore`
    before the pull (`restore_unrecorded` if it cannot be). A restore writes
    no `deploying` line, so it can never make the failed sha restorable.
    Cannot be combined with -Force.

.PARAMETER ForceReason
    Why this refused or unjudged sha ships anyway. Recorded, not just printed.

.PARAMETER MigrateFrom
    Copy an existing lake and operational database into the volume before
    starting. Do this once, on the first cutover from host processes: without
    it the containers start on an empty volume and every finding, decision
    and archived scan stays behind on the host.

.NOTES
    ASCII only - see deploy/concourse/setup.ps1.
#>

[CmdletBinding()]
param(
    # `ghcr.io/<owner>` - the owner segment is part of the path, so the
    # `$Registry/$name` join below is unchanged. Pass `localhost:5000` to pull
    # from the old LAN registry while both are still publishing.
    [string]$Registry = "ghcr.io/toddgbenson",
    # Which published image to deploy. REQUIRED, and a commit sha (D-125).
    #
    # There is no default and `latest` is no longer a thing to pass. `:latest`
    # was retired because the gate that owned it never once ran: 99 promote
    # runs, 99 cancelled, zero completions, and the tag left pointing at an
    # image OLDER than the last production deploy. A default that ships
    # something older than what is already running is worse than no default.
    #
    # Naming the sha is now the deploy decision. It was always the real one --
    # every deploy for months passed `-Tag <sha>` because `:latest` could not
    # be trusted -- and D-125 makes the practice the contract.
    #
    # Rollback is the same command with the previous sha; -Restore ships that
    # sha without asking the ratchet (D-183), and only that sha.
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{7,40}$')]
    [string]$Tag,
    # Where to ask what the risk gate decided about $Tag (#60487). The same
    # backend this script already deploys and checks, so the new dependency
    # is a route, not a machine. Pinned (D-183): see .PARAMETER PlatformUrl.
    # A throw rather than ValidateScript's ErrorMessage, which Windows
    # PowerShell 5.1 does not parse.
    [ValidateScript({
        if ($_ -ceq 'http://127.0.0.1:8100') { $true }
        else { throw "-PlatformUrl must be http://127.0.0.1:8100, the production backend this script deploys (D-183). The ratchet's answer is the gate; it is not asked anywhere else." }
    })]
    [string]$PlatformUrl = "http://127.0.0.1:8100",
    # How long to wait for the gate to answer about $Tag (#735). 0 = ask once.
    [ValidateRange(0, 180)]
    [int]$GateWaitMinutes = 45,
    # Ship a sha the gate refused or never scored. Needs -ForceReason; see the banner it
    # prints and the ledger it writes.
    [switch]$Force,
    [string]$ForceReason,
    # Redeploy the sha the most recent deploy replaced, without asking the
    # ratchet; only that sha, read from the ledger. See .PARAMETER Restore.
    [switch]$Restore,
    [string]$MigrateFrom,
    [switch]$NoStart
)

$ErrorActionPreference = "Stop"
$here = $PSScriptRoot
# The repository the ratchet judges $Tag in (D-183). Not a parameter: this
# script deploys MyKronos and nothing else, and for this platform's own
# repository the backend compares the running sha this script sends with its
# own build stamp and refuses a disagreement.
$Repo = "ToddGBenson/mykronos"

# [TheHub #61644] A PRE-MOVE REFUSAL IS NOT AN ATTEMPT. Every stop before the
# first change to the host (the risk gate refused or never scored the sha, the
# lock is held, a pull failed, an override could not be recorded, the env file
# is missing) ends here: ONE machine-readable line,
#   DEPLOY-PRE-MOVE-REFUSAL kind=<kind>
# then the same throw as before (a non-zero exit; 75 for the lock, as
# before). Watch-AutoDeploy.ps1 reads the line with the non-zero exit and
# records the sha as NOT attempted, so it retries once the blocker clears;
# anything that fails after this point prints no such line, is an attempt
# and is not retried. Keep the kinds in step with Get-PreMoveRefusal
# (AutoDeploy.ps1).
function Stop-BeforeMove {
    param(
        [Parameter(Mandatory = $true)][string]$Kind,
        [string]$Message,
        # Set only for the lock: an exit with this code instead of a throw.
        [int]$ExitCode = 0
    )
    Write-Host "DEPLOY-PRE-MOVE-REFUSAL kind=$Kind (nothing was pulled or changed)"
    if ($ExitCode -ne 0) { exit $ExitCode }
    throw $Message
}

$backendEnv = Join-Path $here "..\..\backend\.env"
if (-not (Test-Path $backendEnv)) { Stop-BeforeMove -Kind "env_missing" -Message "Missing $backendEnv" }

function Read-EnvValue {
    param([string]$Path, [string]$Key)
    $line = Select-String -Path $Path -Pattern "^$Key=" -ErrorAction SilentlyContinue
    if (-not $line) { return $null }
    return $line.Line.Split('=', 2)[1].Trim()
}

function Get-RunningBuildSha {
    # The commit mykronos-backend is running, from the image's own
    # MYKRONOS_BUILD_SHA stamp, or $null. Read twice (TheHub #61046): before
    # the pull, for what this deploy replaces, and after it, to confirm what
    # it delivered. See the confirmation step below for why the stamp and
    # not /healthz.
    param([switch]$Quiet)
    try {
        $stamp = docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' mykronos-backend 2>$null
        if ($LASTEXITCODE -ne 0) { throw "docker inspect failed" }
        $found = $null
        foreach ($line in $stamp) {
            if ($line -match '^MYKRONOS_BUILD_SHA=(.*)$') { $found = $Matches[1].Trim() }
        }
        if ($found) { return $found }
    } catch {
        if (-not $Quiet) {
            Write-Host "Could not read MYKRONOS_BUILD_SHA from mykronos-backend to confirm the running commit." -ForegroundColor Yellow
        }
    }
    return $null
}

function Invoke-DeployRecorder {
    # TheHub #61046. Tell the backlog which stories this deploy put live.
    #
    # Nothing a deploy here did reached the Hub's story lifecycle, so a story
    # whose code was running sat at "tested" until someone moved it by hand:
    # 53 stall reports were open on 2026-10-27 and 16 stories had been moved
    # by hand in 30 days. The recorder reads the commits between the previous
    # and the new running commit in this checkout and posts the stories they
    # name.
    #
    # The recorder is NAMED IN backend/.env, not here: it lives outside this
    # repository and carries its own credential, so this script holds neither
    # an address nor a secret for it. A .py path runs under python; anything
    # else is invoked directly. Absent, misnamed or failing, it warns and the
    # deploy stands: the deploy happened whatever the record says.
    param([string]$Sha, [string]$PreviousSha)
    $recorder = Read-EnvValue $backendEnv "MYKRONOS_DEPLOY_RECORDER"
    if (-not $recorder) {
        Write-Host "No MYKRONOS_DEPLOY_RECORDER in backend/.env: the stories this deploy shipped stay at their gate until moved by hand." -ForegroundColor DarkGray
        return
    }
    if (-not (Test-Path $recorder)) {
        Write-Host "MYKRONOS_DEPLOY_RECORDER names $recorder, which does not exist; this deploy was not recorded." -ForegroundColor Yellow
        return
    }
    $checkout = (Resolve-Path (Join-Path $here "..\..")).Path
    $recorderArgs = @("--repo", "mykronos", "--sha", $Sha, "--checkout", $checkout)
    if ($PreviousSha) { $recorderArgs += @("--since", $PreviousSha) }
    try {
        if ($recorder -like "*.py") {
            & python $recorder @recorderArgs
        } else {
            & $recorder @recorderArgs
        }
        if ($LASTEXITCODE -ne 0) {
            Write-Host "The deploy recorder exited $LASTEXITCODE. The deploy is fine; its stories were not recorded." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "The deploy recorder could not run: $($_.Exception.Message). The deploy is fine; its stories were not recorded." -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# THE RISK GATE (#60487, D-183). Runs before anything is pulled, so a refusal
# costs nothing and leaves the host exactly as it was.
# ---------------------------------------------------------------------------

$riskLedger = Join-Path $here "deploy-risk-log.jsonl"

function Write-RiskBanner {
    <#
        Deliberately loud, and deliberately NOT what a normal run looks like.
        The clean path prints one grey line; only the two cases that mean "no
        gate ran" get this. If banners start appearing on every deploy,
        something is broken - that is the point.
    #>
    param([string]$Heading, [string[]]$Lines, [string]$Color)
    $rule = "=" * 74
    Write-Host ""
    Write-Host $rule -ForegroundColor $Color
    Write-Host "  $Heading" -ForegroundColor $Color
    Write-Host $rule -ForegroundColor $Color
    foreach ($line in $Lines) { Write-Host "  $line" -ForegroundColor $Color }
    Write-Host $rule -ForegroundColor $Color
    Write-Host ""
}

function Write-RiskLedger {
    <#
        The durable half. A printed warning dies with the console buffer, and
        the whole complaint in #60487 is that a warn-and-proceed path leaves
        no trace anybody can go back to. Every run appends one line - not only
        the overrides - because "could not ask" needs a record at least as
        much as "asked and was refused" does.

        Returns $true only if the line is on disk. Callers that are recording
        an override treat $false as fatal: the record is the price of the
        override, so an override that cannot be recorded does not happen.
    #>
    param([hashtable]$Entry)
    try {
        $Entry["at"] = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        $Entry["user"] = $env:USERNAME
        $Entry["host"] = $env:COMPUTERNAME
        # Which platform answered (or was asked), on every line (D-183).
        $Entry["asked"] = $PlatformUrl
        Add-Content -Path $riskLedger -Value ($Entry | ConvertTo-Json -Compress -Depth 8)
        return $true
    } catch {
        Write-Host "Could not write $riskLedger : $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Get-LedgerMac {
    # HMAC-SHA256 of a ledger line's load-bearing fields, keyed with this
    # host's platform token (D-183 restore). Lower-case hex.
    param([string]$Key, [string]$Text)
    $hmac = [System.Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($Key))
    try {
        $bytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text))
        return ([BitConverter]::ToString($bytes) -replace '-', '').ToLowerInvariant()
    } finally {
        $hmac.Dispose()
    }
}

function Get-DeployingMacText {
    # A random nonce, not the time: ConvertFrom-Json turns an ISO time back
    # into a DateTime, and its string is then not the one that was signed.
    param([string]$DeployTag, [string]$Previous, [string]$Nonce)
    return "deploying|$DeployTag|$Previous|$Nonce"
}

function Get-RestoreTarget {
    <#
        Whether -Tag is the sha the most recent deploy replaced, from the
        ledger alone. Fails closed: any doubt is a refusal with a reason.
        Returns @{ Ok; Sha; Deploy; Reason }.
    #>
    param([string]$Tag, [string]$Key, [string]$Running)
    $no = { param($why) @{ Ok = $false; Sha = $null; Deploy = $null; Reason = $why } }
    if (-not $Key) { return (& $no "there is no platform token in backend/.env to verify the ledger with") }
    if (-not (Test-Path -LiteralPath $riskLedger -PathType Leaf)) {
        return (& $no "there is no deploy ledger ($riskLedger), so no deploy recorded what it replaced")
    }
    try {
        $lines = @(Get-Content -LiteralPath $riskLedger -ErrorAction Stop)
    } catch {
        return (& $no "the deploy ledger could not be read: $($_.Exception.Message)")
    }
    # One pass (TheHub #61730): the ledger only grows, and appending to a
    # PowerShell array copies it, so collecting every entry first and then
    # walking them again was quadratic in the ledger's length. Each nonce's
    # first position is all the replay check below needs.
    $last = $null
    $lastIndex = -1
    $index = -1
    $firstNonce = [System.Collections.Generic.Dictionary[string, int]]::new([StringComparer]::Ordinal)
    foreach ($line in $lines) {
        if (-not "$line".Trim()) { continue }
        try {
            $entry = $line | ConvertFrom-Json -ErrorAction Stop
        } catch {
            return (& $no "a deploy ledger line is not JSON, so the ledger was edited or damaged")
        }
        $index++
        if ($entry -and $entry.PSObject.Properties.Name -contains "nonce") {
            $nonce = [string]$entry.nonce
            if (-not $firstNonce.ContainsKey($nonce)) { $firstNonce[$nonce] = $index }
        }
        if ($entry -and $entry.PSObject.Properties.Name -contains "event" -and $entry.event -eq "deploying") {
            $last = $entry
            $lastIndex = $index
        }
    }
    if (-not $last) { return (& $no "the ledger records no deploy, so there is no prior sha to restore") }
    # A replayed copy of a genuine older line carries that line's nonce, which
    # every deploy draws fresh: the latest deploying line's nonce on any
    # earlier line means the line is a replay, whatever the running stamp says.
    $lastNonce = [string]$last.nonce
    if ($lastNonce -and $firstNonce.ContainsKey($lastNonce) -and $firstNonce[$lastNonce] -lt $lastIndex) {
        return (& $no "the most recent deploy line repeats an earlier line's nonce, so it is a replayed copy")
    }
    $previous = [string]$last.previous
    if ($previous -cnotmatch '^[0-9a-f]{40}$') {
        return (& $no "the most recent deploy ($([string]$last.tag)) recorded no running sha")
    }
    $expected = Get-LedgerMac -Key $Key -Text (Get-DeployingMacText -DeployTag ([string]$last.tag) -Previous $previous -Nonce ([string]$last.nonce))
    if ($expected -cne [string]$last.mac) {
        return (& $no "the most recent deploy line does not verify (edited, or written with another token)")
    }
    # Bound to what runs now, so a replayed older line or a truncated ledger
    # cannot re-target the restore: after the failed deploy the unhealthy
    # container still reports the failed deploy's sha. Unreadable is allowed
    # (the backend container may be gone altogether).
    $lastTag = ([string]$last.tag).ToLowerInvariant()
    if ($Running -and -not $Running.ToLowerInvariant().StartsWith($lastTag)) {
        return (& $no "the running build is $($Running.Substring(0, [Math]::Min(12, $Running.Length))), not $lastTag, the most recent recorded deploy; a restore undoes only that deploy")
    }
    $want = $Tag.ToLowerInvariant()
    if ($want.Length -lt 7 -or -not $previous.StartsWith($want)) {
        return (& $no "$Tag is not $($previous.Substring(0, 12)), the sha that ran before the most recent deploy ($([string]$last.tag))")
    }
    return @{ Ok = $true; Sha = $previous; Deploy = [string]$last.tag; Reason = $null }
}

function Get-RiskVerdict {
    <#
        Since D-183 this reads `/decisions/by-commit` only for
        Find-NearestScored's hint; the deploy decision is Get-RatchetVerdict.
        Four outcomes, and the caller must be able to tell all four apart:
          clean    - asked, and the answer permits a deploy
          refused  - asked, and the commit INTRODUCED an open critical or
                     high (`introduced_blocking`, D-048) - the gate's floor
          backlog  - asked, and the recommendation is no_go but the commit
                     introduced nothing blocking. Warns, proceeds (D-159)
          unjudged - asked, and NOTHING has ever scored this commit.
                     Refuses unless -Force
          unasked  - could not ask at all. Warns, proceeds (D-126)

        `unjudged` and `unasked` are separate states because they have
        different causes, different fixes and different outcomes: one means
        the gate did not score this commit (most often because a lane was
        red, so Concourse never reached the gate), the other means this host
        could not reach the platform.
    #>
    param([string]$Sha, [string]$BaseUrl, [string]$Token)

    if (-not $Token) {
        return @{
            State = "unasked"
            Reason = "backend/.env carries neither MYKRONOS_ADMIN_TOKEN nor MYKRONOS_VIEWER_TOKEN, so there was no credential to ask with."
        }
    }

    try {
        $answer = Invoke-RestMethod `
            -Uri "$BaseUrl/api/oracle/decisions/by-commit/$Sha" `
            -Headers @{ Authorization = "Bearer $Token" } `
            -TimeoutSec 10
    } catch {
        return @{
            State = "unasked"
            Reason = "$BaseUrl did not answer: $($_.Exception.Message)"
        }
    }

    # A backend too old to have the route, or a proxy that rewrote the path,
    # can answer 200 with something else entirely. Treated as "could not ask"
    # rather than parsed optimistically, because the optimistic reading of a
    # response with no verdict in it is a clean bill of health.
    if ($null -eq $answer -or -not ($answer.PSObject.Properties.Name -contains "found")) {
        return @{
            State = "unasked"
            Reason = "$BaseUrl answered, but not with a risk decision. Is this backend new enough to serve /api/oracle/decisions/by-commit?"
        }
    }

    if (-not $answer.found) { return @{ State = "unjudged"; Decision = $answer } }
    # The floor the gate job actually refuses on (#735, D-048), and the ONLY
    # refusal here (D-159). Only an explicit true counts. A recorded override
    # on the decision is the human call, and clears it - which is what -Force
    # records below.
    if ($answer.introduced_blocking -eq $true -and -not $answer.overridden) {
        return @{ State = "refused"; Decision = $answer; Floor = $true }
    }
    # The backlog, not this change. The gate job warns on it and passes, so
    # this script does the same: a refusal the gate never made would make
    # -Force routine, and a routine override records nothing worth reading.
    if ($answer.effective_recommendation -eq "no_go") {
        return @{ State = "backlog"; Decision = $answer }
    }
    # An allow-list, not "anything that is not no_go". A verdict this script
    # does not recognise - a null, an empty string, a word a later policy
    # introduces - must not fall through to a pass. Under a fail-open gate the
    # default branch is the one that lets things through, so the default
    # branch has to be the one that says it could not tell.
    if ($answer.effective_recommendation -in @("go", "review_recommended")) {
        return @{ State = "clean"; Decision = $answer }
    }
    return @{
        State = "unasked"
        Reason = "$BaseUrl returned a verdict this script does not recognise: '$($answer.effective_recommendation)'."
    }
}

function Format-Short {
    param([string]$Sha)
    if (-not $Sha) { return "(unknown)" }
    if ($Sha.Length -gt 12) { return $Sha.Substring(0, 12) }
    return $Sha
}

function Get-RatchetVerdict {
    <#
        THE DEPLOY RATCHET (D-183). Asks GET /api/oracle/deploy-gate whether
        $Sha may replace $Deployed, and returns one of four states:
          allow    - the platform answered allow: true, verdict "allow"
          refused  - it answered, and refused (score raised, an introduced
                     critical or high, a latched No-Go, a disputed baseline)
          unjudged - it answered no_decision and nothing else: the gate has
                     not scored $Sha yet, so the caller may wait for it
          unasked  - it could not be asked, or answered something that is not
                     a ratchet verdict
        Only `allow` lets a deploy through. `unasked` used to warn and proceed
        (D-126); it is a refusal now, because the operator decided the gate
        fails closed. An answer is read as allow only when BOTH `allow` is
        the boolean true and `verdict` is "allow": a proxy that rewrote the
        body, or a backend too old to have the route, must not read as a pass.
    #>
    param([string]$Sha, [string]$Deployed, [string]$Repo, [string]$BaseUrl, [string]$Token)

    if (-not $Token) {
        return @{
            State = "unasked"
            Reason = "backend/.env carries neither MYKRONOS_ADMIN_TOKEN nor MYKRONOS_VIEWER_TOKEN, so there was no credential to ask with."
        }
    }
    $query = "repo=$([uri]::EscapeDataString($Repo))&commit=$Sha"
    if ($Deployed) { $query += "&deployed=$Deployed" }
    try {
        $answer = Invoke-RestMethod `
            -Uri "$BaseUrl/api/oracle/deploy-gate?$query" `
            -Headers @{ Authorization = "Bearer $Token" } `
            -TimeoutSec 60
    } catch {
        return @{ State = "unasked"; Reason = "$BaseUrl did not answer: $($_.Exception.Message)" }
    }
    if ($null -eq $answer -or -not ($answer.PSObject.Properties.Name -contains "allow") -or
        -not ($answer.PSObject.Properties.Name -contains "reasons")) {
        return @{
            State = "unasked"
            Reason = "$BaseUrl answered, but not with a ratchet verdict. Is this backend new enough to serve /api/oracle/deploy-gate?"
        }
    }
    if ($answer.allow -is [bool] -and $answer.allow -and $answer.verdict -eq "allow") {
        return @{ State = "allow"; Answer = $answer }
    }
    $codes = @($answer.reasons | ForEach-Object { $_.code })
    if ($codes.Count -eq 1 -and $codes[0] -eq "no_decision") {
        return @{ State = "unjudged"; Answer = $answer; Reason = "the gate has never scored $Sha" }
    }
    return @{ State = "refused"; Answer = $answer; Reason = ($codes -join ", ") }
}

function Find-NearestScored {
    <#
        The nearest ancestor of an unjudged sha that the gate DID score, and
        what it said (#60731). Concourse scores only the newest commit that
        passed every lane, so a sha it skipped is unjudged even when main is
        green. "Nothing scored this" is then less useful than "the commit two
        before it scored go". That is the newest judgement of code this deploy
        contains. It says nothing about the commits after it, and the banner
        says so.

        Walks `git rev-list` in the checkout this script sits in and asks the
        same by-commit route for each ancestor. Stops at the first answer, and
        at the first "could not ask", because that will not get better one
        commit further back. Never throws: this only adds to a message, and a
        failure here must not change what the deploy decides.
    #>
    param([string]$Sha, [string]$BaseUrl, [string]$Token, [string]$RepoPath, [int]$Depth = 25)
    try {
        $ancestors = @(git -C $RepoPath rev-list --max-count=$($Depth + 1) $Sha 2>$null)
        $listed = ($LASTEXITCODE -eq 0)
    } catch {
        $listed = $false
    }
    if (-not $listed -or $ancestors.Count -eq 0) {
        return @{ Found = $false; Reason = "$Sha is not in the checkout at $RepoPath (git fetch?), so its ancestors could not be listed." }
    }
    $asked = 0
    foreach ($ancestor in @($ancestors | Select-Object -Skip 1)) {
        $asked++
        $answer = Get-RiskVerdict -Sha $ancestor -BaseUrl $BaseUrl -Token $Token
        if ($answer.State -eq "unasked") {
            return @{ Found = $false; Reason = "stopped asking at $($ancestor.Substring(0, 12)): $($answer.Reason)" }
        }
        if ($answer.State -eq "unjudged") { continue }
        $said = "$($answer.Decision.effective_recommendation)"
        if ($answer.State -eq "refused") { $said = "refused (it introduced an open critical or high)" }
        if ($answer.State -eq "backlog") { $said = "no_go on the backlog, nothing blocking introduced" }
        return @{ Found = $true; Sha = $ancestor; Distance = $asked; Verdict = $said;
            Score = $answer.Decision.overall_risk_score }
    }
    return @{ Found = $false; Reason = "none of the $asked commit(s) before $Sha has a risk decision." }
}

function Format-NearestScored {
    param([hashtable]$Nearest, [string]$Sha)
    if (-not $Nearest.Found) { return "Nearest scored commit: none found - $($Nearest.Reason)" }
    $short = $Nearest.Sha.Substring(0, 12)
    return ("Nearest scored commit: $short, $($Nearest.Distance) commit(s) before ${Sha}: " +
        "$($Nearest.Verdict) (score $($Nearest.Score)). It does not cover the " +
        "$($Nearest.Distance) commit(s) after it.")
}

if ($Force -and -not $ForceReason) {
    Stop-BeforeMove -Kind "usage" -Message "-Force needs -ForceReason. Overriding a refusal without recording why is the thing #60487 exists to prevent."
}
if ($ForceReason -and $ForceReason.Trim().Length -lt 10) {
    Stop-BeforeMove -Kind "usage" -Message "-ForceReason is too short to be a reason. Write the sentence someone reading the ledger in six months needs."
}
if ($Restore -and $Force) {
    Stop-BeforeMove -Kind "usage" -Message "-Restore and -Force do not combine. A restore ships only the sha the last deploy replaced, without -Force; anything else is a normal deploy."
}
if ($ForceReason -and -not $Force) {
    Write-Host "-ForceReason was given without -Force; it will only be recorded if the gate actually refuses." -ForegroundColor DarkGray
}

$riskToken = Read-EnvValue $backendEnv "MYKRONOS_ADMIN_TOKEN"
$riskTokenIsAdmin = [bool]$riskToken
if (-not $riskToken) { $riskToken = Read-EnvValue $backendEnv "MYKRONOS_VIEWER_TOKEN" }
# The perimeter gate's token. Only the by-commit lookup is exempt from the
# gate; recording an override is not, and without this header it answered
# 401 - so every -Force since the gate was switched on landed in the local
# ledger only, while the decision still read as un-overridden.
$gateToken = Read-EnvValue $backendEnv "MYKRONOS_GATE_TOKEN"

# [TheHub #61046] What this deploy replaces, read before anything changes, so
# the recorder can name the range of commits it shipped - and, since D-183,
# so the ratchet can judge $Tag against what is running. Null on a first
# deploy or an image too old to carry the stamp; the recorder then reads the
# tip commit alone, and the ratchet uses the backend's own build stamp (it
# is the deployment) or refuses with baseline_unknown.
$previousSha = Get-RunningBuildSha -Quiet
if ($previousSha -notmatch '^[0-9a-f]{7,40}$') { $previousSha = $null }

# Repeated as the very last line of the run. The banner below scrolls away
# behind a pull, a health wait and a briefing; this does not.
$riskSummary = ""

if ($Restore) {
    # D-183, operator decision 2026-11-15: "Allow restore of the prior sha".
    # The ratchet is not asked: the backend that answers it may be the thing
    # that just failed. Only the sha the ledger says the last deploy replaced.
    $target = Get-RestoreTarget -Tag $Tag -Key $riskToken -Running $previousSha
    if (-not $target.Ok) {
        Write-RiskLedger @{ event = "refused"; tag = $Tag; state = "restore"; kind = "restore_refused";
            reason = $target.Reason; deployed = $previousSha } | Out-Null
        Stop-BeforeMove -Kind "restore_refused" -Message ("RESTORE REFUSED - $($target.Reason). " +
            "A restore ships only the sha the most recent deploy replaced, as its ledger line recorded it. " +
            "Nothing has been pulled.")
    }
    $recorded = Write-RiskLedger @{ event = "restore"; tag = $Tag; restores = $target.Sha;
        failed_deploy = $target.Deploy; deployed = $previousSha }
    if (-not $recorded) {
        Stop-BeforeMove -Kind "restore_unrecorded" -Message "The restore could not be recorded, so it does not happen. Fix $riskLedger and re-run."
    }
    $riskSummary = ("Risk gate: not asked - RESTORE of $(Format-Short $target.Sha), the sha the deploy of " +
        "$(Format-Short $target.Deploy) replaced (D-183, operator decision 2026-11-15).")
    Write-Host $riskSummary -ForegroundColor Yellow
} else {

$verdict = Get-RatchetVerdict -Sha $Tag -Deployed $previousSha -Repo $Repo -BaseUrl $PlatformUrl -Token $riskToken

# #735: "no decision yet" is usually "the gate has not run yet". Wait for it,
# bounded, and say so - a silent 30-minute pause reads as a hang.
if ($verdict.State -eq "unjudged" -and $GateWaitMinutes -gt 0) {
    Write-Host ("No risk decision for $Tag yet. The gate runs after every scan lane, " +
        "about 30 minutes after Delivery. Waiting up to $GateWaitMinutes minutes " +
        "(-GateWaitMinutes 0 skips; Ctrl+C stops with nothing pulled).") -ForegroundColor Yellow
    $waitStart = Get-Date
    $deadline = $waitStart.AddMinutes($GateWaitMinutes)
    $lastReport = 0
    $missed = 0
    # "unasked" here is one poll that went unanswered, not an unreachable
    # platform: the first ask, above, was answered. On 2026-10-15 a single poll
    # 40 minutes into the wait took longer than its 10 s timeout, the loop
    # ended on it, and 9a2eec4 shipped as COULD NOT ASK while its gate was
    # minutes from deciding. A miss keeps waiting; a deadline that passes on
    # a miss is "could not ask", which is a refusal since D-183.
    while ($verdict.State -in @("unjudged", "unasked") -and (Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 30
        $verdict = Get-RatchetVerdict -Sha $Tag -Deployed $previousSha -Repo $Repo -BaseUrl $PlatformUrl -Token $riskToken
        if ($verdict.State -eq "unasked") {
            $missed++
            if ($missed -eq 1 -or $missed % 10 -eq 0) {
                Write-Host "  a poll went unanswered ($missed so far): $($verdict.Reason) Still waiting." -ForegroundColor DarkYellow
            }
            continue
        }
        $waitedMinutes = [int][math]::Floor(((Get-Date) - $waitStart).TotalMinutes)
        if ($verdict.State -eq "unjudged" -and $waitedMinutes -ge $lastReport + 5) {
            $lastReport = $waitedMinutes
            Write-Host "  still waiting for the gate: $waitedMinutes of $GateWaitMinutes minutes" -ForegroundColor DarkGray
        }
    }
}
$answer = $verdict.Answer

if ($verdict.State -eq "allow") {
    # One line. No banner, no pause. The quiet path has to be quiet, or the
    # loud paths stop meaning anything.
    $note = ("Risk gate: allow for $Tag over $(Format-Short $answer.deployed_sha) " +
        "(score $($answer.baseline_score) -> $($answer.candidate_score), " +
        "$(@($answer.reasons | ForEach-Object { $_.code }) -join ', '), " +
        "latched $($answer.latch.latched), policy $($answer.policy_version), asked $PlatformUrl).")
    # Fixes the scans already show but reconciliation has not closed (two
    # missed scans) are not credited yet; said so nobody re-deploys to chase it.
    if ($answer.PSObject.Properties.Name -contains "fix_credit_pending" -and [int]$answer.fix_credit_pending -gt 0) {
        $note += " Fix credit pending: $($answer.fix_credit_pending) finding(s) close on their second missed scan; no need to re-deploy for it."
    }
    $color = if ([double]$answer.candidate_score -lt [double]$answer.no_go_threshold) { "DarkGray" } else { "Yellow" }
    Write-Host $note -ForegroundColor $color
    $riskSummary = $note
    Write-RiskLedger @{ event = "checked"; tag = $Tag; state = "allow"; deployed = $answer.deployed_sha;
        candidate_score = $answer.candidate_score; baseline_score = $answer.baseline_score;
        codes = @($answer.reasons | ForEach-Object { $_.code }); latched = $answer.latch.latched } | Out-Null
    if ($Force) {
        Write-Host "-Force was passed but the ratchet did not refuse $Tag; there was nothing to override." -ForegroundColor DarkGray
    }
} else {
    # Everything that is not an explicit allow refuses (D-183 (c)): a refusal,
    # a commit nothing scored, and a platform that could not be asked.
    $lines = @()
    $kind = "risk_refused"
    $heading = "REFUSED"
    switch ($verdict.State) {
        "unjudged" {
            $kind = "risk_not_judged"
            $heading = "NOT JUDGED"
            $nearest = Find-NearestScored -Sha $Tag -BaseUrl $PlatformUrl -Token $riskToken `
                -RepoPath (Join-Path $here "..\..")
            $waited = $(if ($GateWaitMinutes -gt 0) { "Waited $GateWaitMinutes minutes for the gate to answer." } else { "Did not wait for the gate (-GateWaitMinutes 0)." })
            $lines = @(
                "NOT JUDGED - the risk gate has never scored $Tag.",
                $waited,
                "",
                "Concourse scores only a commit that passed every lane, so the usual cause",
                "is a red lane (unit, lint-and-types) for this sha.",
                "",
                (Format-NearestScored -Nearest $nearest -Sha $Tag),
                "",
                "What to do:",
                "  * Wait. The gate answers about 30 minutes after Delivery goes",
                "    green; re-run, or pass a larger -GateWaitMinutes.",
                "  * Or deploy the last green sha - the newest one the gate DID score:",
                $(if ($nearest.Found) { "      .\deploy.ps1 -Tag $($nearest.Sha.Substring(0, 12))   ($($nearest.Verdict))" } else { "      (none found above; check the lanes for the newest green head)" })
            )
        }
        "unasked" {
            $kind = "risk_unasked"
            $heading = "COULD NOT ASK"
            $lines = @(
                "COULD NOT ASK - the deploy ratchet did not answer for $Tag.",
                $verdict.Reason,
                "",
                "No risk decision was consulted, and since D-183 that is a refusal, not a",
                "pass: the gate fails closed. If the platform itself is what is broken",
                "(Vault sealed, the backend down), fix it, or deploy the fix with",
                "-Force and a reason; the override is recorded before anything is pulled."
            )
        }
        default {
            $lines = @("REFUSED - the deploy ratchet refused $Tag over $(Format-Short $answer.deployed_sha) (D-183).") +
                @($answer.reasons | ForEach-Object { "  [$($_.code)] $($_.message)" }) + @(
                "",
                "Score $($answer.baseline_score) running -> $($answer.candidate_score) for $Tag (tolerance $($answer.tolerance) in total, already spent $($answer.accepted_creep), No-Go $($answer.no_go_threshold)), latched $($answer.latch.latched).",
                "Introduced: $(($answer.introduced | ConvertTo-Json -Compress)); fixed: $(($answer.fixed | ConvertTo-Json -Compress)).",
                "Repository $($answer.repo_full_name), policy $($answer.policy_version), range of $(@($answer.range_commits).Count) commit(s)."
            )
        }
    }
    $codes = @()
    if ($answer) { $codes = @($answer.reasons | ForEach-Object { $_.code }) }
    $decisionId = $(if ($answer -and $answer.candidate_decision) { $answer.candidate_decision.decision_id } else { $null })

    if (-not $Force) {
        $refusal = $lines + @(
            "",
            "Nothing has been pulled.",
            "",
            "To deploy it anyway (the operator only - agents never pass -Force):",
            "  .\deploy.ps1 -Tag $Tag -Force -ForceReason ""<why this ships despite the refusal>""",
            "",
            "The reason is written to deploy-risk-log.jsonl and, with an admin token,",
            "recorded against the decision itself."
        )
        # A refusal is recorded too. The ledger is meant to answer "what did
        # this host do about risk", and a refusal followed minutes later by a
        # -Force is the pattern worth being able to see.
        Write-RiskLedger @{ event = "refused"; tag = $Tag; state = $verdict.State; kind = $kind;
            codes = $codes; reason = $verdict.Reason; deployed = $previousSha;
            candidate_score = $(if ($answer) { $answer.candidate_score } else { $null });
            baseline_score = $(if ($answer) { $answer.baseline_score } else { $null });
            decision_id = $decisionId } | Out-Null
        Stop-BeforeMove -Kind $kind -Message ($refusal -join [Environment]::NewLine)
    }

    Write-RiskBanner -Color Red -Heading "OVERRIDDEN - SHIPPING A SHA THE RATCHET DID NOT ALLOW ($heading)" `
        -Lines ($lines + @("", "Reason given: $ForceReason"))

    # Recorded BEFORE the pull. If this cannot be written the deploy does not
    # happen: an override whose reason exists only in a console buffer is an
    # unrecorded exception wearing the word "recorded".
    $recorded = Write-RiskLedger @{ event = "override"; tag = $Tag; state = $verdict.State; kind = $kind;
        codes = $codes; deployed = $previousSha; decision_id = $decisionId; reason = $ForceReason }
    if (-not $recorded) {
        Stop-BeforeMove -Kind "override_unrecorded" -Message "The override could not be recorded, so it is not an override. Fix $riskLedger and re-run."
    }
    Write-Host "Override recorded in $riskLedger" -ForegroundColor Yellow

    # Best effort, and said out loud either way. The platform is the right
    # home for this record, but it is also the thing most likely to be down
    # during the deploy that needed forcing - which is exactly why the local
    # ledger above is the one the deploy depends on.
    $pushed = "not attempted (no decision to record it against)"
    if ($riskTokenIsAdmin -and $decisionId) {
        try {
            Invoke-RestMethod -Method Post `
                -Uri "$PlatformUrl/api/oracle/decisions/$decisionId/override" `
                -Headers $(if ($gateToken) {
                    @{ Authorization = "Bearer $riskToken"; "X-Hub-Token" = $gateToken }
                } else {
                    @{ Authorization = "Bearer $riskToken" }
                }) `
                -ContentType "application/json" `
                -Body (@{ reason = "Deployed by deploy.ps1 -Force over the deploy ratchet ($(($codes + @($verdict.State)) -join ', ')): $ForceReason"; accepted_recommendation = "go" } | ConvertTo-Json) `
                -TimeoutSec 10 | Out-Null
            $pushed = "recorded on the platform"
            Write-Host "Override also recorded against decision $decisionId." -ForegroundColor Yellow
        } catch {
            $pushed = "local ledger only ($($_.Exception.Message))"
            Write-Host "Could not record the override on the platform: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    } elseif ($decisionId) {
        $pushed = "local ledger only (no admin token on this host)"
    }
    $riskSummary = "Risk gate: OVERRIDDEN - $Tag was $heading ($(($codes + @($verdict.Reason)) -join ', ')) and shipped with -Force ($pushed). Reason: $ForceReason"
    Start-Sleep -Seconds 5
}
}  # end of: not a restore

# [TheHub #61610] ONE DEPLOY AT A TIME. Taken here, after the risk gate and
# before the first pull: the gate is read-only and can wait 45 minutes, and
# everything from the pull on changes the host. A hand deploy and the
# scheduled one (Watch-AutoDeploy.ps1) share this lock; the watcher holds it
# for its whole attempt and passes its token down, so this run proceeds under
# it. Exit 75 is "another deploy holds the lock", the same code TheHub's
# deploy.sh uses. Nothing has been pulled when it fires.
. (Join-Path $here "DeployLock.ps1")
$deployLock = Enter-MykronosDeployLock -Holder "deploy.ps1 -Tag $Tag"
if (-not $deployLock.Acquired) {
    Write-Host ("Another MyKronos deploy holds $($deployLock.Path) (" +
        (Format-MykronosDeployLockOwner $deployLock.Owner) + "). Nothing has been pulled.") -ForegroundColor Red
    Write-Host "If nothing is running, remove that directory and re-run." -ForegroundColor Red
    Stop-BeforeMove -Kind "lock_held" -ExitCode 75
}
# The rest of the script runs inside this try, unindented to keep the diff
# readable; the matching finally is the last line of the file.
try {

# What this deploy replaces, recorded BEFORE the pull and signed, so a
# rollback can restore exactly that sha without asking the ratchet (D-183,
# -Restore). A restore writes none: it must never make the failed sha
# restorable. If the line cannot be written the deploy does not happen, for
# the same reason an override that cannot be recorded does not: an
# unattended deploy that then fails health could not be rolled back.
if (-not $Restore) {
    $deployingNonce = [guid]::NewGuid().ToString("N")
    $deployingMac = $null
    if (-not $riskToken) {
        Write-Host ("No platform token in backend/.env: this deploy's ledger line cannot be signed, " +
            "so it cannot be restored with -Restore if it fails; a rollback will need -Force.") -ForegroundColor Yellow
    } else {
        $deployingMac = Get-LedgerMac -Key $riskToken -Text (Get-DeployingMacText -DeployTag $Tag -Previous ([string]$previousSha) -Nonce $deployingNonce)
    }
    $recorded = Write-RiskLedger @{ event = "deploying"; tag = $Tag; previous = $previousSha;
        nonce = $deployingNonce; mac = $deployingMac }
    if (-not $recorded) {
        Stop-BeforeMove -Kind "deploy_unrecorded" -Message "The deploy could not record what it replaces, so it could not be restored if it fails. Fix $riskLedger and re-run."
    }
}

Write-Host "Pulling images from $Registry at tag $Tag..." -ForegroundColor Cyan
# [TheHub #61644] Both are pulled before either is retagged, so a failed pull
# leaves even the local `:latest` pointers where they were: a pre-move refusal.
foreach ($name in @("mykronos-backend", "mykronos-frontend")) {
    docker pull "$Registry/$name`:$Tag"
    if ($LASTEXITCODE -ne 0) {
        # Named causes rather than "could not pull". Each of these fails the
        # same way at the daemon and needs a different thing done about it,
        # and the first cutover to GHCR is exactly when somebody will meet
        # one of them for the first time.
        $lines = @(
            "Could not pull $Registry/$name`:$Tag.",
            ""
        )
        $lines += @(
            "  * Is that a commit the pipeline built? Only commits whose",
            "    publish-backend job succeeded have an image. A merged",
            "    commit whose build failed or never ran has no tag.",
            "  * Is the package public? A GHCR package is private by default",
            "    even in a public repository. Either make it public in the",
            "    package settings, or run: docker login ghcr.io",
            "    with a token carrying read:packages.",
            "  * Still on the old registry? Pass -Registry localhost:5000."
        )
        Stop-BeforeMove -Kind "pull_failed" -Message ($lines -join [Environment]::NewLine)
    }
}
foreach ($name in @("mykronos-backend", "mykronos-frontend")) {
    # Retagged to `:latest` locally because compose defaults to
    # `mykronos-backend:latest` and takes no tag of its own. The local tag is
    # the deploy's own pointer, not the registry's -- which is the whole reason
    # this works without touching the compose file or the env file.
    docker tag "$Registry/$name`:$Tag" "$name`:latest"
}

# The App private key stays on the host and is bind-mounted read-only. Spec 12
# section 2 keeps it out of repositories and out of image layers, and an image
# layer is something people pull.
$keyPath = Read-EnvValue $backendEnv "MYKRONOS_GITHUB_APP_PRIVATE_KEY_PATH"
if ($keyPath -and (Test-Path $keyPath)) {
    $env:MYKRONOS_GITHUB_APP_KEY_HOST_PATH = (Resolve-Path $keyPath).Path
    Write-Host "GitHub App key will be mounted read-only." -ForegroundColor DarkGray
} else {
    Write-Host "No GitHub App key found; compose refuses to start without it. Set MYKRONOS_GITHUB_APP_PRIVATE_KEY_PATH in backend/.env." -ForegroundColor Yellow
}

if ($MigrateFrom) {
    if (-not (Test-Path $MigrateFrom)) { throw "No such directory: $MigrateFrom" }
    Write-Host "`nMigrating existing data into the volume..." -ForegroundColor Cyan
    docker volume create mykronos_mykronos-data | Out-Null
    # Through a helper container: the volume is not reachable from the host
    # filesystem on Docker Desktop.
    # Three things this has to get right, each of which failed on the first
    # attempt and each of which failed *quietly*:
    #
    # 1. The SQLite write-ahead log. Copying mykronos.db alone leaves every
    #    write since the last checkpoint behind - 1.8MB of it, including every
    #    onboarded repository. The database opens cleanly and reports nothing.
    # 2. The lake's _manifest.duckdb persists views naming the host's paths.
    #    Carried across, the catalog reads 93 Parquet files as zero rows.
    #    Deleting it makes the catalog rebuild the views where the data now is.
    # 3. Ownership. `cp -a` preserves the host's, the container runs as uid
    #    10001, and SQLite then fails with "attempt to write a readonly
    #    database" - which surfaces as an unhealthy container.
    #
    # All three produce a platform that starts, answers, and is empty. That is
    # the worst possible outcome for a migration, so each is handled here and
    # the row counts are checked afterwards rather than assumed.
    $src = (Resolve-Path $MigrateFrom).Path
    # One line, not a here-string: PowerShell here-strings emit CRLF, and
    # `sh -c` reads the carriage returns as part of each command. The first
    # attempt failed with nothing useful in the output.
    $script = "set -e; " +
        "cp -a /from/datalake /data/; " +
        "cp -a /from/mykronos.db /data/; " +
        "cp -a /from/mykronos.db-wal /data/ 2>/dev/null || true; " +
        "cp -a /from/mykronos.db-shm /data/ 2>/dev/null || true; " +
        "rm -f /data/datalake/_manifest.duckdb; " +
        "chown -R 10001:10001 /data; ls -la /data"
    docker run --rm -v "${src}:/from:ro" -v "mykronos_mykronos-data:/data" alpine:3.19 sh -c $script
    if ($LASTEXITCODE -ne 0) { throw "Migration failed; not starting." }
}

function Write-RiskSummaryLine {
    <#
        The last thing on the screen, every run. The banner above is separated
        from here by a pull, a three-minute health wait and a full briefing -
        long enough for "could not ask" to have scrolled out of sight before
        the operator looks up. So the verdict is stated again at the end,
        where the eye lands.
    #>
    if (-not $riskSummary) { return }
    $color = if ($riskSummary.StartsWith("Risk gate: allow")) {
        "DarkGray"
    } elseif ($riskSummary.StartsWith("Risk gate: OVERRIDDEN") -or $riskSummary.StartsWith("Risk gate: not asked - RESTORE")) {
        "Red"
    } else {
        "Yellow"
    }
    Write-Host $riskSummary -ForegroundColor $color
}

if ($NoStart) {
    Write-RiskSummaryLine
    return
}

# Slack (B-035, D-112 as amended, D-137). The notifier posts as this host's one
# Slack bot - the identity the Concourse pipelines already post as - to the
# channel their alerts go to. Both are read from Vault at team scope with the
# read-only Concourse token, the same two paths the pipelines resolve
# `((slack-bot-token))` and `((slack-alert-channel))` from, and are handed to
# compose through this process's environment, which compose prefers over
# --env-file. So the token is never pasted into backend/.env and never
# printed: only which names resolved is said.
#
# Fails open, like the risk gate. A sealed Vault leaves whatever backend/.env
# says (normally empty), and the backend's own startup warning then reports a
# notifier addressed to nobody - a deploy is not blocked by a chat service.
$slackFromVault = [ordered]@{
    "MYKRONOS_SLACK_BOT_TOKEN" = "concourse/main/slack-bot-token"
    "MYKRONOS_SLACK_CHANNEL"   = "concourse/main/slack-alert-channel"
}
$concourseEnv = Join-Path $here "..\concourse\.env"
$vaultToken = if (Test-Path $concourseEnv) { Read-EnvValue $concourseEnv "CONCOURSE_VAULT_TOKEN" } else { $null }
$slackResolved = @()
if ($vaultToken) {
    # `-e VAULT_TOKEN` with no value forwards it from this process's
    # environment, so the token is never in docker's command line.
    $prior = $env:VAULT_TOKEN
    $env:VAULT_TOKEN = $vaultToken
    foreach ($name in $slackFromVault.Keys) {
        try {
            $value = docker exec -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN `
                mykronos-vault vault read -field=value $slackFromVault[$name] 2>$null
            if ($LASTEXITCODE -eq 0 -and $value) {
                Set-Item -Path "env:$name" -Value (($value -join "").Trim())
                $slackResolved += $name
            }
        } catch {
            # Unresolved names are reported as missing just below; Slack is
            # optional for a deploy. The exception text is not echoed: this
            # block runs with a Vault token in the environment.
            Write-Verbose "Slack: could not read $name from Vault."
        }
        $value = $null
    }
    $env:VAULT_TOKEN = $prior
}
if ($slackResolved.Count -eq $slackFromVault.Count) {
    Write-Host "Slack bot token and channel resolve from Vault (concourse/main)." -ForegroundColor DarkGray
} else {
    $missing = @($slackFromVault.Keys | Where-Object { $slackResolved -notcontains $_ }) -join ", "
    Write-Host "Slack: $missing not readable from Vault; backend/.env decides, and is normally empty." -ForegroundColor Yellow
    Write-Host "  Is Vault sealed? ..\concourse\vault-unseal.ps1" -ForegroundColor DarkGray
}

Push-Location $here
try {
    docker compose --env-file $backendEnv up -d
    if ($LASTEXITCODE -ne 0) { throw "docker compose up failed" }
    # Out of this session's environment as soon as compose has read them, so
    # a deploy run from an interactive shell does not leave the token behind.
    foreach ($name in $slackResolved) { Remove-Item -Path "env:$name" -ErrorAction SilentlyContinue }

    Write-Host "`nWaiting for health..." -ForegroundColor Cyan
    $deadline = (Get-Date).AddMinutes(3)
    do {
        Start-Sleep -Seconds 10
        $backend = (docker inspect -f '{{.State.Health.Status}}' mykronos-backend 2>$null)
        $frontend = (docker inspect -f '{{.State.Health.Status}}' mykronos-frontend 2>$null)
        Write-Host "  backend=$backend frontend=$frontend"
    } while (((Get-Date) -lt $deadline) -and (($backend -ne "healthy") -or ($frontend -ne "healthy")))

    if ($backend -ne "healthy") { throw "Backend did not become healthy: docker compose logs backend" }
    # The frontend is checked as well, not only waited for. On 2026-10-22
    # compose left mykronos-frontend in `created`, never started; the loop
    # above ran out its three minutes, this script said "Deployed", and the
    # dashboard answered 502 until someone noticed. A container that was
    # created and not started is started once here; anything else stops.
    if ($frontend -ne "healthy") {
        $state = (docker inspect -f '{{.State.Status}}' mykronos-frontend 2>$null)
        if ($state -eq "created") {
            Write-Host "  frontend was created but never started; starting it" -ForegroundColor Yellow
            docker start mykronos-frontend | Out-Null
            $deadline = (Get-Date).AddMinutes(2)
            do {
                Start-Sleep -Seconds 5
                $frontend = (docker inspect -f '{{.State.Health.Status}}' mykronos-frontend 2>$null)
            } while (((Get-Date) -lt $deadline) -and ($frontend -ne "healthy"))
        }
        if ($frontend -ne "healthy") {
            throw "Frontend did not become healthy (state: $state, health: $frontend): docker compose logs frontend"
        }
    }

    # Healthy is not the same fact as "running what you asked for". A stale
    # image answers /healthz perfectly well, which is how production came to be
    # eight days old behind entirely green indicators (#361). The image carries
    # its commit (#363), so the deploy can check its own work rather than
    # report success and leave the question open.
    #
    # Never fatal when it cannot be answered: an older image that predates
    # MYKRONOS_BUILD_SHA reports no sha, and refusing to finish a deploy over a
    # missing field would be worse than saying so.
    # [D-125] No longer conditional on the tag not being `latest`: every deploy
    # now names a sha, so "healthy" and "running what you asked for" can always
    # be told apart. That is the whole reason the sha is mandatory.
    # [D-157, TheHub #60722] Read from the container's own stamp, not from
    # /healthz. The public /healthz no longer carries the sha (it told the
    # internet which commit to diff), and the stamp needs no token. It is the
    # same MYKRONOS_BUILD_SHA the backend serves as `build.sha`: the image's
    # ENV, which compose does not override.
    $running = Get-RunningBuildSha
    # A restore may pull a short tag; what it must run is exactly the full
    # sha the ledger recorded, so a colliding prefix cannot pass as one.
    $restoreMismatch = $false
    $tookTag = $false
    if ($running) {
        if ($Restore) {
            $tookTag = ($running.ToLowerInvariant() -ceq $target.Sha)
            $restoreMismatch = -not $tookTag
        } else {
            $tookTag = ($running -eq $Tag -or $Tag.StartsWith($running) -or $running.StartsWith($Tag))
        }
    }
    if (-not $running) {
        Write-Host "The running image does not report a build sha; cannot confirm the tag took." -ForegroundColor Yellow
    } elseif ($tookTag) {
        Write-Host "Confirmed: the backend is running $Tag." -ForegroundColor Green
        # [TheHub #61046] Only a confirmed deploy is recorded: on a mismatch
        # the stories in the range are not what is running.
        Invoke-DeployRecorder -Sha $running -PreviousSha $previousSha
    } else {
        # Not a throw. The stack is up and healthy; what failed is the
        # deploy's intent, and the operator needs both facts.
        Write-Host "MISMATCH: asked for $Tag, the container reports $running." -ForegroundColor Red
        Write-Host "          The stack is healthy but it is not the artifact you asked for." -ForegroundColor Red
    }

    Write-Host "`nDeployed. http://localhost:3100 and http://localhost:8100" -ForegroundColor Green

    # The briefing, every time, because "it deployed" is not the same fact as
    # "the backlog is moving". Its first section reports lanes whose scans are
    # failing — and a finding closes only after two consecutive *successful*
    # scans see it gone, so a broken lane freezes its findings open however
    # well the code was fixed. On 2026-09-01 that was 115 DAST findings
    # against security headers that had already shipped and were being served
    # on the wire, and nothing anywhere said so.
    #
    # Never fatal. A deploy that worked did work, and a briefing that cannot
    # read the lake must not retract that.
    Write-Host ""
    docker exec mykronos-backend mykronos briefing
    if ($LASTEXITCODE -ne 0) {
        Write-Host "The briefing did not run. The deploy itself is fine; run 'docker exec mykronos-backend mykronos briefing' to see why." -ForegroundColor Yellow
    }

    Write-Host ""
    Write-RiskSummaryLine
    if ($restoreMismatch) {
        throw "RESTORE MISMATCH: the restore was of $($target.Sha), and the backend reports $running."
    }
} finally {
    foreach ($name in $slackResolved) { Remove-Item -Path "env:$name" -ErrorAction SilentlyContinue }
    Pop-Location
}

} finally {
    # [TheHub #61610] Released only by the run that took it: a run under the
    # watcher's token leaves the lock for the watcher's rollback step.
    Exit-MykronosDeployLock $deployLock
}
