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
    about the sha before it pulls anything, and REFUSES a `no_go` unless
    -Force is passed with a reason that is recorded.

    IT FAILS OPEN, DELIBERATELY. If the platform cannot be reached it warns
    and proceeds. That is never worse than the state it replaces: with no
    check at all, an unreachable platform already meant no gate. Fail closed
    was rejected on a measured case, not a hypothetical one - Vault was sealed
    for four days in September 2026 and the whole Concourse estate was down
    (#60474); a fail-closed gate would have blocked every deploy that could
    have fixed it, including the unseal.

    AND THE COST OF FAILING OPEN IS THAT A WARNING CAN GO INVISIBLE. A
    warn-and-proceed path that prints on every routine command stops being
    read, which is the failure mode this estate keeps meeting. So the four
    outcomes do not look alike: a clean answer is ONE quiet line, while
    "could not ask" and "nothing ever scored this" are banners with a pause,
    and every run's verdict is repeated as the last line on the screen and
    appended to `deploy-risk-log.jsonl` beside this script. "Could not ask"
    is not "asked and it was fine", and the operator must never have to infer
    which one happened from the absence of something.

    SCOPE. D-125 retired the GHCR `:latest`, which is what this script pulls by
    default. A SECOND promote exists in the Concourse `mykronos.yml` pipeline
    and still retags `:latest` on the LAN registry (192.168.0.14:5000). If you
    pass `-Registry localhost:5000` you are on that path, and a `:latest` may
    still exist there. `-Tag` is mandatory either way.

.PARAMETER Tag
    REQUIRED. The commit sha to deploy - 7 to 40 hex characters, validated.

    Rollback is the same command with the previous sha. The deploy reads
    `/healthz` afterwards and says whether the running commit is the one
    requested, because "healthy" and "running what you asked for" are different
    facts and only the second one is the deploy's job.

.PARAMETER PlatformUrl
    Where to ask for the sha's risk decision. The local backend by default -
    the same address this script already reads `/healthz` from, so it adds no
    new host, no new port and no new credential store.

.PARAMETER Force
    Deploy a sha the risk gate refused. Requires -ForceReason, and the reason
    is written to a ledger beside this script before anything is pulled. An
    override nobody can find afterwards is not an override, it is an
    unrecorded exception.

.PARAMETER ForceReason
    Why this `no_go` ships anyway. Recorded, not just printed.

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
    # Rollback is unchanged and is still the whole procedure: the same command
    # with the previous sha.
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{7,40}$')]
    [string]$Tag,
    # Where to ask what the risk gate decided about $Tag (#60487). The same
    # backend this script already reads /healthz from, so the new dependency
    # is a route, not a machine.
    [string]$PlatformUrl = "http://127.0.0.1:8100",
    # Ship a sha the gate refused. Needs -ForceReason; see the banner it
    # prints and the ledger it writes.
    [switch]$Force,
    [string]$ForceReason,
    [string]$MigrateFrom,
    [switch]$NoStart
)

$ErrorActionPreference = "Stop"
$here = $PSScriptRoot
$backendEnv = Join-Path $here "..\..\backend\.env"
if (-not (Test-Path $backendEnv)) { throw "Missing $backendEnv" }

function Read-EnvValue {
    param([string]$Path, [string]$Key)
    $line = Select-String -Path $Path -Pattern "^$Key=" -ErrorAction SilentlyContinue
    if (-not $line) { return $null }
    return $line.Line.Split('=', 2)[1].Trim()
}

# ---------------------------------------------------------------------------
# THE RISK GATE (#60487, D-126). Runs before anything is pulled, so a refusal
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
        Add-Content -Path $riskLedger -Value ($Entry | ConvertTo-Json -Compress -Depth 8)
        return $true
    } catch {
        Write-Host "Could not write $riskLedger : $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Get-RiskVerdict {
    <#
        Four outcomes, and the caller must be able to tell all four apart:
          clean    - asked, and the answer permits a deploy
          refused  - asked, and the answer is no_go
          unjudged - asked, and NOTHING has ever scored this commit
          unasked  - could not ask at all

        `unjudged` and `unasked` both end in "deploy proceeds", which is
        exactly why they are separate states rather than one "warn" branch.
        They have different causes and different fixes: one means the gate
        workflow did not run for this commit, the other means this host could
        not reach the platform.
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
    if ($answer.effective_recommendation -eq "no_go") {
        return @{ State = "refused"; Decision = $answer }
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

if ($Force -and -not $ForceReason) {
    throw "-Force needs -ForceReason. Overriding a no_go without recording why is the thing #60487 exists to prevent."
}
if ($ForceReason -and $ForceReason.Trim().Length -lt 10) {
    throw "-ForceReason is too short to be a reason. Write the sentence someone reading the ledger in six months needs."
}
if ($ForceReason -and -not $Force) {
    Write-Host "-ForceReason was given without -Force; it will only be recorded if the gate actually refuses." -ForegroundColor DarkGray
}

$riskToken = Read-EnvValue $backendEnv "MYKRONOS_ADMIN_TOKEN"
$riskTokenIsAdmin = [bool]$riskToken
if (-not $riskToken) { $riskToken = Read-EnvValue $backendEnv "MYKRONOS_VIEWER_TOKEN" }

$verdict = Get-RiskVerdict -Sha $Tag -BaseUrl $PlatformUrl -Token $riskToken
$decision = $verdict.Decision

# Repeated as the very last line of the run. The banner above scrolls away
# behind a pull, a health wait and a briefing; this does not.
$riskSummary = ""

switch ($verdict.State) {

    "clean" {
        # One line. No banner, no pause. The quiet path has to be quiet, or
        # the loud paths stop meaning anything.
        $note = "Risk gate: $($decision.effective_recommendation) for $Tag (score $($decision.overall_risk_score), policy $($decision.policy_version), asked $PlatformUrl)."
        if ($decision.overridden) {
            $note += " Recorded override: $($decision.recommendation) -> $($decision.effective_recommendation)."
        }
        $color = if ($decision.effective_recommendation -eq "go") { "DarkGray" } else { "Yellow" }
        Write-Host $note -ForegroundColor $color
        $riskSummary = $note
        Write-RiskLedger @{ event = "checked"; tag = $Tag; state = "clean";
            recommendation = $decision.recommendation;
            effective = $decision.effective_recommendation;
            decision_id = $decision.decision_id; score = $decision.overall_risk_score } | Out-Null
    }

    "unjudged" {
        Write-RiskBanner -Color Yellow `
            -Heading "NOT JUDGED - NO RISK DECISION EXISTS FOR $Tag" `
            -Lines @(
                "The platform was reached and asked. It has never scored this commit.",
                "",
                "THAT IS NOT A PASS. It is the absence of one, and it is a different",
                "fact from 'asked, and it was fine'. Most likely the oracle gate did",
                "not run for this commit, or its decision never reached the lake.",
                "",
                "Proceeding: the decided posture is fail open (#60487, D-126). A check",
                "that cannot answer must not be worse than the no check before it."
            )
        $riskSummary = "Risk gate: NOT JUDGED - nothing has ever scored $Tag. It shipped unassessed."
        Write-RiskLedger @{ event = "checked"; tag = $Tag; state = "unjudged" } | Out-Null
        Start-Sleep -Seconds 5
    }

    "unasked" {
        Write-RiskBanner -Color Red `
            -Heading "COULD NOT ASK - THE RISK GATE DID NOT RUN FOR $Tag" `
            -Lines @(
                $verdict.Reason,
                "",
                "No risk decision was consulted. Whatever the platform thinks of this",
                "commit, this deploy did not hear it - and that is NOT the same thing",
                "as being told the commit is fine.",
                "",
                "Proceeding: the decided posture is fail open (#60487, D-126). Vault",
                "was sealed four days in September 2026 and the estate was down",
                "(#60474); a fail-closed gate would have blocked the deploy that",
                "fixed it."
            )
        $riskSummary = "Risk gate: COULD NOT ASK - $($verdict.Reason) $Tag shipped unchecked."
        Write-RiskLedger @{ event = "checked"; tag = $Tag; state = "unasked"; reason = $verdict.Reason } | Out-Null
        Start-Sleep -Seconds 5
    }

    "refused" {
        $detail = @(
            "Score $($decision.overall_risk_score), policy $($decision.policy_version), decided $($decision.evaluated_at).",
            "Repository $($decision.repo_full_name), decision $($decision.decision_id).",
            "Reasoning: $($decision.reasoning)"
        )

        if (-not $Force) {
            $lines = @("The risk gate scored $Tag no_go. Nothing has been pulled.") + $detail + @(
                "",
                "To deploy it anyway:",
                "  .\deploy.ps1 -Tag $Tag -Force -ForceReason ""<why this ships despite no_go>""",
                "",
                "The reason is written to deploy-risk-log.jsonl and, with an admin",
                "token, recorded against the decision itself so the override is",
                "visible to everyone and not only to whoever was at this keyboard."
            )
            # A refusal is recorded too. The ledger is meant to answer "what
            # did this host do about risk", and a run that was stopped is part
            # of that answer -- not least because a refusal followed minutes
            # later by a -Force is the pattern worth being able to see.
            Write-RiskLedger @{ event = "refused"; tag = $Tag; state = "refused";
                recommendation = $decision.recommendation;
                effective = $decision.effective_recommendation;
                decision_id = $decision.decision_id; score = $decision.overall_risk_score;
                repo = $decision.repo_full_name } | Out-Null
            throw ($lines -join [Environment]::NewLine)
        }

        Write-RiskBanner -Color Red `
            -Heading "OVERRIDDEN - SHIPPING A no_go SHA" `
            -Lines (@("$Tag was refused by the risk gate and is being deployed anyway.") + $detail + @(
                "",
                "Reason given: $ForceReason"
            ))

        # Recorded BEFORE the pull. If this cannot be written the deploy does
        # not happen: an override whose reason exists only in a console buffer
        # is an unrecorded exception wearing the word "recorded".
        $recorded = Write-RiskLedger @{ event = "override"; tag = $Tag; state = "refused";
            recommendation = $decision.recommendation;
            effective = $decision.effective_recommendation;
            decision_id = $decision.decision_id; score = $decision.overall_risk_score;
            repo = $decision.repo_full_name; reason = $ForceReason }
        if (-not $recorded) {
            throw "The override could not be recorded, so it is not an override. Fix $riskLedger and re-run."
        }
        Write-Host "Override recorded in $riskLedger" -ForegroundColor Yellow

        # Best effort, and said out loud either way. The platform is the right
        # home for this record, but it is also the thing most likely to be
        # down during the deploy that needed forcing - which is exactly why
        # the local ledger above is the one the deploy depends on.
        $pushed = "not attempted"
        if ($riskTokenIsAdmin -and $decision.decision_id) {
            try {
                Invoke-RestMethod -Method Post `
                    -Uri "$PlatformUrl/api/oracle/decisions/$($decision.decision_id)/override" `
                    -Headers @{ Authorization = "Bearer $riskToken" } `
                    -ContentType "application/json" `
                    -Body (@{ reason = "Deployed by deploy.ps1 -Force: $ForceReason"; accepted_recommendation = "go" } | ConvertTo-Json) `
                    -TimeoutSec 10 | Out-Null
                $pushed = "recorded on the platform"
                Write-Host "Override also recorded against decision $($decision.decision_id)." -ForegroundColor Yellow
            } catch {
                $pushed = "local ledger only ($($_.Exception.Message))"
                Write-Host "Could not record the override on the platform: $($_.Exception.Message)" -ForegroundColor Yellow
                Write-Host "The local ledger still holds it." -ForegroundColor Yellow
            }
        } elseif (-not $riskTokenIsAdmin) {
            $pushed = "local ledger only (no admin token on this host)"
            Write-Host "No MYKRONOS_ADMIN_TOKEN here, so the override is in the local ledger only." -ForegroundColor Yellow
        }

        $riskSummary = "Risk gate: OVERRIDDEN - $Tag was no_go and shipped with -Force ($pushed). Reason: $ForceReason"
        Start-Sleep -Seconds 5
    }
}

if ($Force -and $verdict.State -ne "refused") {
    Write-Host "-Force was passed but the gate did not refuse $Tag; there was nothing to override." -ForegroundColor DarkGray
}

Write-Host "Pulling images from $Registry at tag $Tag..." -ForegroundColor Cyan
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
        throw ($lines -join [Environment]::NewLine)
    }
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
    Write-Host "No GitHub App key found; the stack will run without it." -ForegroundColor Yellow
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
    $color = if ($riskSummary.StartsWith("Risk gate: go") -or $riskSummary.StartsWith("Risk gate: review")) {
        "DarkGray"
    } elseif ($riskSummary.StartsWith("Risk gate: OVERRIDDEN") -or $riskSummary.StartsWith("Risk gate: COULD NOT ASK")) {
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

Push-Location $here
try {
    docker compose --env-file $backendEnv up -d
    if ($LASTEXITCODE -ne 0) { throw "docker compose up failed" }

    Write-Host "`nWaiting for health..." -ForegroundColor Cyan
    $deadline = (Get-Date).AddMinutes(3)
    do {
        Start-Sleep -Seconds 10
        $backend = (docker inspect -f '{{.State.Health.Status}}' mykronos-backend 2>$null)
        $frontend = (docker inspect -f '{{.State.Health.Status}}' mykronos-frontend 2>$null)
        Write-Host "  backend=$backend frontend=$frontend"
    } while (((Get-Date) -lt $deadline) -and (($backend -ne "healthy") -or ($frontend -ne "healthy")))

    if ($backend -ne "healthy") { throw "Backend did not become healthy: docker compose logs backend" }

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
    $running = $null
    try {
        $running = (Invoke-RestMethod -Uri "http://127.0.0.1:8100/healthz" -TimeoutSec 15).build.sha
    } catch {
        Write-Host "Could not read /healthz to confirm the running commit." -ForegroundColor Yellow
    }
    if (-not $running) {
        Write-Host "The running image does not report a build sha; cannot confirm the tag took." -ForegroundColor Yellow
    } elseif ($running -eq $Tag -or $Tag.StartsWith($running) -or $running.StartsWith($Tag)) {
        Write-Host "Confirmed: the backend is running $Tag." -ForegroundColor Green
    } else {
        # Not a throw. The stack is up and healthy; what failed is the
        # deploy's intent, and the operator needs both facts.
        Write-Host "MISMATCH: asked for $Tag, /healthz reports $running." -ForegroundColor Red
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
} finally {
    Pop-Location
}
