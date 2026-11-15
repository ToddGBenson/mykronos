#Requires -Version 7
# ^ pwsh only: [RandomNumberGenerator]::Fill does not exist in Windows
# PowerShell 5.1, and 5.1 turns fly's stderr into a terminating error under
# $ErrorActionPreference = "Stop" exactly when the token has expired.
<#
.SYNOPSIS
    Log fly target `mykronos-agent` in to the local Concourse as the agents'
    user, so an agent can refresh its own token.

.DESCRIPTION
    D-182. The main team has two local users (docker-compose.yml): the
    operator, who is owner, and the agents' user, who holds the Concourse
    `pipeline-operator` role and nothing more. Every fly token lasts 24 hours
    (Concourse's --auth-duration default), so a login that only the operator
    could perform lapsed every day. This one reads the agents' password from
    .env and logs in again without anyone at the keyboard.

    What pipeline-operator can do on the main team (atc/api/accessor/roles.go,
    Concourse 8.3): trigger a job, rerun and abort a build, comment on a
    build, check a resource, pin and unpin a resource version and comment on
    the pin, disable and enable a resource version, clear the task and
    resource caches, and pause and unpause a job or a pipeline. What it
    cannot: set or delete a pipeline, archive or expose one, hijack a
    container, run `fly execute`, or change the team.

    AGENTS NEVER PAUSE. The role allows more than agents may use; the
    standing rule is narrower. Agents never pause, pin, unpin or disable a
    resource version, and never clear a cache; they abort only builds they
    started themselves. Each of those stops a lane in a way that reads as
    "nothing to report" rather than as "stopped": a paused pipeline, a
    resource pinned to an old version, a version hidden from the pipeline.
    Trigger, rerun, check and abort-your-own only; the rest is the operator's.

    This is a guard against accident, not a security boundary: agents run as
    the operator's OS user and can read the owner's password in .env and the
    owner's `mykronos` target in ~/.flyrc (D-182).

    Without -Force, a target whose token is still valid is left alone, so
    this can run before every fly call. After a login it checks the role
    Concourse actually granted (`fly userinfo`) and fails if it is anything
    but pipeline-operator on main - an agent login holding owner is the
    failure this design exists to prevent, and it would otherwise work
    silently.

    -Provision is the operator's one-time step: it adds CONCOURSE_AGENT_USER
    and a generated CONCOURSE_AGENT_PASSWORD to .env when they are absent,
    and never replaces a value that is there. It refuses an agent name that
    is not lowercase letters, digits, '-' and '_' (starting with a letter or
    digit), and one equal to CONCOURSE_LOCAL_USER, before writing anything.
    It never calls docker compose. The web node reads the values only when
    it is recreated: docker compose up -d --no-deps concourse.

    Nothing here prints the password or the token. The password reaches fly
    as ONE argument, "--password=<value>": fly parses flags with go-flags,
    which refuses a separate value that starts with '-' and repeats it in
    the error on stderr. New-Secret also never returns a value that starts
    with '-'. fly 8 takes the password grant only with both -u and -p, so the
    password is in fly.exe's argv for the second the login takes.

    Run from a worktree it still finds the stack's .env and bin\fly.exe: both
    are gitignored and live only in the main checkout, which it locates
    through git's common directory.

.EXAMPLE
    .\Connect-AgentFly.ps1
    fly -t mykronos-agent trigger-job -j mykronos/backend-tests

.EXAMPLE
    .\Connect-AgentFly.ps1 -Provision
    (operator, once) then: docker compose up -d --no-deps concourse

.NOTES
    PowerShell 7 (pwsh). ASCII only - see setup.ps1 for why.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Target = "mykronos-agent",
    [string]$Concourse = "http://localhost:8080",
    [string]$Team = "main",
    [string]$EnvFile = "",
    [string]$AgentUser = "mykronos-agent",
    [switch]$Provision,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

# The stack's directory in the main checkout. .env and bin\ are gitignored,
# so a worktree has neither; git's common directory is the main checkout's
# .git whichever worktree this runs from.
function Get-StackDirectory {
    if (Test-Path (Join-Path $PSScriptRoot ".env")) { return $PSScriptRoot }
    $common = git -C $PSScriptRoot rev-parse --path-format=absolute --git-common-dir 2>$null
    if ($LASTEXITCODE -eq 0 -and $common) {
        $main = Join-Path (Split-Path -Parent $common) "deploy\concourse"
        if (Test-Path (Join-Path $main ".env")) { return $main }
    }
    return $PSScriptRoot
}

function New-Secret {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pure generator: returns a random string and changes no state. Writing .env is the caller''s job, guarded by ShouldProcess.')]
    param([int]$Bytes = 24)
    $buffer = New-Object byte[] $Bytes
    # URL-safe, as setup.ps1's: no comma, which CONCOURSE_ADD_LOCAL_USER
    # splits on, and no colon, which separates the user from the password.
    # Never a leading '-', which a flag parser reads as an option.
    do {
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($buffer)
        $secret = [Convert]::ToBase64String($buffer).Replace('+', '-').Replace('/', '_').TrimEnd('=')
    } while ($secret.StartsWith('-'))
    $secret
}

function Read-EnvValue {
    param([string]$Path, [string]$Key)
    $line = Select-String -Path $Path -Pattern "^$Key=" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $line) { return "" }
    return $line.Line.Split('=', 2)[1].Trim()
}

$stack = Get-StackDirectory
if (-not $EnvFile) { $EnvFile = Join-Path $stack ".env" }
if (-not (Test-Path $EnvFile)) { throw "$EnvFile is missing: run setup.ps1 first." }

# -- -Provision: the operator's one-time .env step ---------------------------
if ($Provision) {
    # The name goes into CONCOURSE_ADD_LOCAL_USER's USER:PASSWORD list and
    # into a quoted YAML list in the team config, so only characters that
    # break neither. Checked before anything is written.
    $agentName = Read-EnvValue $EnvFile "CONCOURSE_AGENT_USER"
    if (-not $agentName) { $agentName = $AgentUser }
    if ($agentName -cnotmatch '^[a-z0-9][a-z0-9_-]*$') {
        throw "Agent user '$agentName' is not lowercase letters, digits, '-' and '_' starting with a letter or digit. Nothing was written."
    }
    $ownerName = Read-EnvValue $EnvFile "CONCOURSE_LOCAL_USER"
    if ($ownerName -and ($ownerName.ToLowerInvariant() -eq $agentName.ToLowerInvariant())) {
        throw "Agent user '$agentName' is the owner (CONCOURSE_LOCAL_USER). The agents' login must be a user of its own, or it holds owner. Nothing was written."
    }
    $envLines = @(Get-Content $EnvFile)
    $add = @()
    if (-not (Read-EnvValue $EnvFile "CONCOURSE_AGENT_USER")) {
        $add += "CONCOURSE_AGENT_USER=$AgentUser"
    }
    if (-not (Read-EnvValue $EnvFile "CONCOURSE_AGENT_PASSWORD")) {
        $add += "CONCOURSE_AGENT_PASSWORD=$(New-Secret)"
    }
    if (-not $add) {
        Write-Host "env         : CONCOURSE_AGENT_USER and CONCOURSE_AGENT_PASSWORD already set" -ForegroundColor DarkGray
    } elseif ($PSCmdlet.ShouldProcess($EnvFile, "Add $(($add | ForEach-Object { $_.Split('=')[0] }) -join ' and ')")) {
        $envLines += @('', "# The agents' Concourse login: pipeline-operator on main (Connect-AgentFly.ps1, D-182).") + $add
        Set-Content -Path $EnvFile -Value $envLines -Encoding UTF8
        Write-Host "env         : wrote $(($add | ForEach-Object { $_.Split('=')[0] }) -join ' and ') (value not printed)" -ForegroundColor Green
        Write-Host "Next: docker compose up -d --no-deps concourse   (in $stack)" -ForegroundColor Cyan
        Write-Host "Then: .\Connect-AgentFly.ps1" -ForegroundColor Cyan
    }
    return
}

$user = Read-EnvValue $EnvFile "CONCOURSE_AGENT_USER"
$password = Read-EnvValue $EnvFile "CONCOURSE_AGENT_PASSWORD"
if (-not $user -or -not $password) {
    throw "CONCOURSE_AGENT_USER and CONCOURSE_AGENT_PASSWORD are not both set in $EnvFile. The operator adds them once: .\Connect-AgentFly.ps1 -Provision"
}
# Concourse lowercases local user names, so these compare the way it does.
$owner = Read-EnvValue $EnvFile "CONCOURSE_LOCAL_USER"
if ($owner -and ($owner.ToLowerInvariant() -eq $user.ToLowerInvariant())) {
    throw "CONCOURSE_AGENT_USER names the owner ($owner). The agents' login must be a user of its own, or it holds owner."
}

$fly = Join-Path $stack "bin\fly.exe"
if (-not (Test-Path $fly)) {
    $onPath = Get-Command fly -ErrorAction SilentlyContinue
    if (-not $onPath) {
        throw "fly is missing. Fetch it: curl -sSfL -o bin/fly.exe '$Concourse/api/v1/cli?arch=amd64&platform=windows'"
    }
    $fly = $onPath.Source
}

if (-not $Force) {
    & $fly --target $Target status *> $null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "fly target $Target is logged in and its token is valid (-Force logs in again)." -ForegroundColor DarkGray
        return
    }
}

Write-Host "Logging fly target $Target in to $Concourse as $user (team $Team)..." -ForegroundColor Cyan
# "--password=..." as one argument: as two, a value starting with '-' is
# refused by fly's flag parser and printed back in its error (stderr).
& $fly --target $Target login --concourse-url $Concourse `
    --username $user "--password=$password" --team-name $Team | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "fly login failed. If the web node predates D-182, recreate it: docker compose up -d --no-deps concourse"
}
Remove-Variable password

# The role Concourse granted, not the one this script assumes.
$raw = & $fly --target $Target userinfo --json
if ($LASTEXITCODE -ne 0 -or -not $raw) { throw "fly userinfo failed after a successful login" }
$info = ($raw -join "`n") | ConvertFrom-Json
$roles = @($info.teams.$Team)
if ($info.is_admin -or ($roles.Count -ne 1) -or ($roles[0] -ne "pipeline-operator")) {
    & $fly --target $Target logout *> $null
    throw "Concourse granted $user [$($roles -join ', ')] on $Team (admin: $($info.is_admin)), not pipeline-operator alone. Logged out; check the team config in docker-compose.yml."
}

Write-Host "fly target $Target : $user, pipeline-operator on $Team. Token valid for 24h; re-run to refresh." -ForegroundColor Green
Write-Host "Trigger, rerun, check and abort your own builds only - agents never pause, pin, unpin, disable a version or clear a cache." -ForegroundColor Yellow
