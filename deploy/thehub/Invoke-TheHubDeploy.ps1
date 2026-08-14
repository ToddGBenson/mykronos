<#
.SYNOPSIS
    Deploy one TheHub environment to a given commit. The far end of the
    pipeline's SSH deploy (spec 16 section 7).

.DESCRIPTION
    This is not a script anybody runs by hand often, and it is not a script the
    pipeline gets to choose the arguments of. It is the forced command on a
    deploy key:

      command="pwsh -NoProfile -File C:\...\Invoke-TheHubDeploy.ps1 -Environment demo",
        no-agent-forwarding,no-port-forwarding,no-pty,no-X11-forwarding ssh-ed25519 AAAA...

    sshd ignores whatever the client asked to run and starts this instead,
    passing the client's command line through as SSH_ORIGINAL_COMMAND. Exactly
    one thing is read out of it - a 40-character hexadecimal commit SHA - and
    it is validated before it reaches a command line.

    That is the whole security argument for letting a pipeline deploy at all.
    Spec 15 section 7 and D-038 refuse a Docker socket in a Concourse task
    because it would let every task in every pipeline drive this host's daemon.
    A key that can do one thing to one environment is a much smaller grant:
    compromising a pipeline task yields the ability to deploy a commit that is
    already in the registry, not the ability to run a command.

    -Environment comes from the authorized_keys line and never from the
    network. The demo key cannot deploy to production because sshd starts a
    different process for it, not because this script checked something.

.PARAMETER Environment
    demo or prod. Supplied by the forced command, not by the caller.

.PARAMETER Sha
    Normally read from SSH_ORIGINAL_COMMAND. Accepted as a parameter so this
    can be run and tested locally without an SSH session.

.PARAMETER TimeoutMinutes
    How long the stack has to report healthy before this rolls back.

.NOTES
    ASCII only - see deploy\concourse\setup.ps1.

    Configuration lives in deploy\thehub\.env, which is gitignored:

      THEHUB_REGISTRY=localhost:5000
      THEHUB_DEMO_COMPOSE=C:\path\to\TheHub\docker-compose.demo.yml
      THEHUB_DEMO_PROJECT=thehub-demo
      THEHUB_DEMO_URL=http://localhost:8200
      THEHUB_PROD_COMPOSE=C:\path\to\TheHub\docker-compose.yml
      THEHUB_PROD_PROJECT=thehub-prod
      THEHUB_PROD_URL=http://localhost:8000

    TheHub's compose files must take their image from ${THEHUB_IMAGE}. That is
    the one change this deploy model asks of TheHub itself, and it is what
    makes "deploy" mean "run exactly this commit" rather than "rebuild and
    hope".

    Pulls from localhost:5000 rather than the host IP the pipeline pushes to.
    Docker treats localhost as an insecure registry by default, so no daemon
    configuration is needed here.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("demo", "prod")]
    [string]$Environment,

    [string]$Sha,
    [int]$TimeoutMinutes = 5,

    # Destroy the volumes and reseed, so the environment is rebuilt from the
    # compose file and seed_demo.py rather than inherited from the last run.
    # Demo only, and refused for prod at the point of destruction rather than
    # only here.
    [switch]$Rebuild
)

$ErrorActionPreference = "Stop"
$here = $PSScriptRoot

function Read-EnvValue {
    param([string]$Path, [string]$Key, [switch]$Optional)
    $line = Select-String -Path $Path -Pattern "^$Key=" -ErrorAction SilentlyContinue
    if (-not $line) {
        if ($Optional) { return $null }
        throw "$Key is not set in $Path"
    }
    return $line.Line.Split('=', 2)[1].Trim()
}

# -- The one untrusted input ------------------------------------------------
#
# SSH_ORIGINAL_COMMAND is whatever the client sent. It is matched against a
# whole-string anchored pattern rather than searched: `-match "[0-9a-f]{40}"`
# would happily accept "rm -rf / <sha>" because it only asks whether a SHA is
# in there somewhere.

if (-not $Sha) { $Sha = $env:SSH_ORIGINAL_COMMAND }
if ($null -eq $Sha) { $Sha = "" }
$Sha = $Sha.Trim()

if ($Sha -notmatch '^[0-9a-f]{40}$') {
    Write-Error ("Expected a 40-character commit SHA, got '{0}'. This key " +
                 "deploys a commit; it does not run commands." -f $Sha)
    exit 64
}

$envFile = Join-Path $here ".env"
if (-not (Test-Path $envFile)) { throw "Missing $envFile" }

$prefix = "THEHUB_" + $Environment.ToUpper()
$registry = Read-EnvValue $envFile "THEHUB_REGISTRY"
$composeFile = Read-EnvValue $envFile "${prefix}_COMPOSE"
$project = Read-EnvValue $envFile "${prefix}_PROJECT"
$healthUrl = Read-EnvValue $envFile "${prefix}_URL"

if (-not (Test-Path $composeFile)) { throw "No compose file at $composeFile" }

$image = "${registry}/thehub:${Sha}"
$stateFile = Join-Path $here ".deployed-$Environment"

# -- One deployer at a time --------------------------------------------------
#
# Two deploys of the same project will interleave destructively. Found the
# obvious way: a manual run and the Scheduled Task both reached this script for
# demo at once, one called `docker compose down -v` while the other was
# bringing the stack up, and postgres died with exit 137 -- which reads as an
# out-of-memory kill and sends you to look at Docker's memory limits.
#
# MultipleInstances=IgnoreNew on the task only stops the task racing itself.
# Nothing stopped an operator, or another tool, running this alongside it.
#
# An exclusive file handle rather than a lock file with a PID in it: if this
# process dies the OS closes the handle, so the lock cannot outlive its owner
# and there is no stale-lock heuristic to get wrong.
$lockPath = Join-Path $here ".deploy-lock-$Environment"
try {
    $lock = [System.IO.File]::Open(
        $lockPath,
        [System.IO.FileMode]::OpenOrCreate,
        [System.IO.FileAccess]::ReadWrite,
        [System.IO.FileShare]::None
    )
} catch {
    Write-Host "Another deploy of '$Environment' is already running." -ForegroundColor Red
    Write-Host "  Lock held on $lockPath" -ForegroundColor Yellow
    Write-Host "  Refusing rather than interleaving: two `docker compose` runs on one" -ForegroundColor Yellow
    Write-Host "  project take each other's containers down mid-start." -ForegroundColor Yellow
    exit 3
}

# Stamped both to say who holds it and to keep a live reference to $lock, so
# the handle is not finalised early by the garbage collector. Never explicitly
# released: every exit path from here ends the process, and the OS closes the
# handle then. That is the point of doing it this way.
$stamp = [System.Text.Encoding]::ASCII.GetBytes(
    "pid=$PID env=$Environment sha=$Sha at=$((Get-Date).ToUniversalTime().ToString('s'))Z"
)
$lock.SetLength(0)
$lock.Write($stamp, 0, $stamp.Length)
$lock.Flush()

Write-Host "Deploying $image to $Environment ($project)" -ForegroundColor Cyan

# What is running now, so there is something to go back to. Recorded before
# anything changes: a rollback target captured after the failure is a rollback
# target that may already be the broken one.
$previous = if (Test-Path $stateFile) { (Get-Content $stateFile -Raw).Trim() } else { $null }
if ($previous) { Write-Host "  current: $previous" -ForegroundColor DarkGray }

# -- The check that makes "deploy" mean what it says -------------------------
#
# Pulling the image proves it exists in the registry. It does not prove the
# stack will run it, and those are not the same claim.
#
# A compose service that declares `build:` and no `image:` rebuilds from
# whatever source is on disk and ignores THEHUB_IMAGE completely. Every step
# still succeeds: the pull works, `up` works, the containers come up healthy,
# the health URL answers, and the deploy reports that the environment is
# serving a SHA it has never run. That is the exact failure the gate upstream
# exists to prevent - a commit reaching an environment without having been
# scanned - reintroduced at the last step by a compose file nobody changed.
#
# So the image ID is captured from the pull and compared against what is
# actually running. Cheap, and it fails loudly on the one mistake that would
# otherwise be invisible.
function Assert-RunningImage {
    param([string]$Expected, [string]$ImageRef)

    $ids = docker compose --project-name $project --file $composeFile ps --quiet
    if ($LASTEXITCODE -ne 0 -or -not $ids) {
        throw "No containers are running for $project after docker compose up."
    }

    $running = foreach ($id in $ids) {
        if ($id) { docker inspect --format '{{.Image}}' $id 2>$null }
    }

    if ($running -contains $Expected) {
        Write-Host "  verified: a container is running $ImageRef" -ForegroundColor DarkGray
        return
    }

    throw ("Nothing in $project is running $ImageRef. docker pull fetched it and " +
           "docker compose up did not use it, which means $composeFile builds its " +
           "services instead of taking them from image: THEHUB_IMAGE. The stack is " +
           "running something this deploy did not choose and nothing scanned. Wire " +
           "THEHUB_IMAGE into that compose file before deploying again.")
}

# -- Immutability ------------------------------------------------------------
#
# `docker compose down -v` destroys the volumes, so the stack comes back with
# an empty database that migrations and seed_demo.py then fill. That is what
# makes the environment immutable in the sense that matters here: every run
# starts from the same known dataset, so a functional test that passes today
# and fails tomorrow has changed because the code changed, not because eight
# earlier test runs left rows behind. DAST gets the same guarantee - findings
# stop depending on what a previous scan happened to create.
#
# Guarded to demo. Running this against prod would delete production data, and
# a flag that can do that by typo should not exist. The caller cannot pass it
# for prod either (see the parameter block), but the check is repeated at the
# point of destruction because that is where being wrong is unrecoverable.
function Invoke-Wipe {
    if ($Environment -ne "demo") {
        throw "Refusing to wipe volumes for '$Environment'. This is demo-only."
    }

    Write-Host "  wiping $project (down -v): volumes are destroyed" -ForegroundColor Yellow
    docker compose --project-name $project --file $composeFile down -v --remove-orphans
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose down -v failed for $project; refusing to seed on top of an unknown state."
    }
}

# Seed the freshly-built environment.
#
# Migrations are NOT run here. entrypoint.sh already runs
# `run_migrations_auto()` before it starts uvicorn, so by the time the stack
# reports healthy the schema is done. Calling run_migrations.py again on top
# of that is redundant, and it failed: the second pass tripped over
# `pg_type_typname_nsp_index` -- a duplicate in Postgres's type catalogue,
# which is what re-creating an already-created table looks like.
#
# One owner for the schema. The entrypoint has it.
function Invoke-Seed {
    Write-Host "Seeding $Environment with the demo dataset..." -ForegroundColor Cyan

    # Trust, but check. If the entrypoint's auto-migration hit a database that
    # was not ready it returns silently ("Skipping auto-migration"), which
    # would leave an empty schema for seed_demo.py to fail against in a much
    # more confusing way. An empty history table is that failure, named.
    # to_regclass first: when the auto-migration skipped entirely the history
    # table does not exist, and querying it raises a SQLAlchemy traceback that
    # buries the actual answer. This reports 0 instead, so the clear message
    # below is what an operator sees.
    $probe = "from run_migrations import engine; from sqlalchemy import text; c = engine.connect(); " +
             "print(0 if c.execute(text(`"select to_regclass('_hub_migration_history')`")).scalar() is None " +
             "else c.execute(text('select count(*) from _hub_migration_history')).scalar())"

    $applied = docker compose --project-name $project --file $composeFile `
        exec -T demo-backend python -c $probe
    if ($LASTEXITCODE -ne 0) {
        throw "Could not reach the database in $project to check the migration history."
    }

    $count = 0
    [void][int]::TryParse(($applied | Select-Object -Last 1).ToString().Trim(), [ref]$count)
    if ($count -lt 1) {
        throw "No migrations are recorded in $project. entrypoint.sh skipped them, so there is no schema to seed."
    }
    Write-Host "  schema: $count migration(s) applied by the entrypoint" -ForegroundColor DarkGray

    docker compose --project-name $project --file $composeFile exec -T demo-backend python scripts/seed_demo.py
    if ($LASTEXITCODE -ne 0) { throw "seed_demo.py failed in $project." }

    Write-Host "  seeded" -ForegroundColor DarkGray
}

function Invoke-ComposeUp {
    param([string]$ImageRef)

    docker pull $ImageRef
    if ($LASTEXITCODE -ne 0) {
        throw "Could not pull $ImageRef. Has the pipeline published it?"
    }

    $expected = docker image inspect --format '{{.Id}}' $ImageRef 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $expected) {
        throw "Pulled $ImageRef but could not read its image ID."
    }

    $env:THEHUB_IMAGE = $ImageRef
    docker compose --project-name $project --file $composeFile up -d --remove-orphans
    if ($LASTEXITCODE -ne 0) { throw "docker compose up failed for $project" }

    Assert-RunningImage -Expected $expected -ImageRef $ImageRef
}

function Test-Healthy {
    # Two questions, because they fail separately and mean different things.
    #
    #   1. Does every container with a healthcheck report healthy? A container
    #      that is `running` and unhealthy is a deploy that half-landed.
    #   2. Does the environment answer over HTTP? A stack of healthy containers
    #      behind a service that is not listening is still down to a user.
    $ids = docker compose --project-name $project --file $composeFile ps --quiet
    if ($LASTEXITCODE -ne 0 -or -not $ids) { return $false }

    foreach ($id in $ids) {
        if (-not $id) { continue }
        $state = docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' $id 2>$null
        if ($state -ne "healthy" -and $state -ne "running") {
            Write-Host "  $($id.Substring(0, 12)) is $state" -ForegroundColor DarkGray
            return $false
        }
    }

    try {
        Invoke-WebRequest -Uri $healthUrl -UseBasicParsing -TimeoutSec 10 | Out-Null
        return $true
    } catch {
        Write-Host "  $healthUrl is not answering yet" -ForegroundColor DarkGray
        return $false
    }
}

if ($Rebuild) { Invoke-Wipe }

Invoke-ComposeUp -ImageRef $image

Write-Host "Waiting for $Environment to become healthy..." -ForegroundColor Cyan
$deadline = (Get-Date).AddMinutes($TimeoutMinutes)
$healthy = $false
do {
    Start-Sleep -Seconds 10
    $healthy = Test-Healthy
} while (-not $healthy -and (Get-Date) -lt $deadline)

if ($healthy) {
    # Seeded only after the stack is healthy, because both steps run through
    # `compose exec` into a container that has to be up to receive them.
    #
    # And before the state file is written: a rebuilt environment that is
    # running but empty is not a deploy anyone asked for. Reporting it as one
    # would send functional tests and DAST at a database with no rows, where
    # every test fails for the same uninteresting reason and the scan finds
    # nothing because there is nothing to find.
    if ($Rebuild) {
        try {
            Invoke-Seed
        } catch {
            Write-Host "SEED FAILED: $_" -ForegroundColor Red
            Write-Host "$Environment is up and running $Sha but has no data." -ForegroundColor Red
            Write-Host "Not acknowledged - testing an empty environment proves nothing." -ForegroundColor Red
            exit 1
        }
    }

    Set-Content -Path $stateFile -Value $Sha -Encoding ASCII
    Write-Host "$Environment is serving $Sha" -ForegroundColor Green
    exit 0
}

# -- Rollback ---------------------------------------------------------------
#
# A deploy that half-lands and reports success is worse than one that fails:
# the pipeline goes green, DAST probes whatever is up, and the environment is
# left in a state nobody chose.

Write-Host "$Environment did not become healthy within $TimeoutMinutes minutes." -ForegroundColor Red

if (-not $previous) {
    Write-Host "No previous deployment recorded, so there is nothing to roll back to." -ForegroundColor Yellow
    Write-Host "The stack is left up for inspection: docker compose -p $project logs" -ForegroundColor Yellow
    exit 1
}

# Rolling back a rebuild does not restore the data. `down -v` already deleted
# the volumes, so the previous image comes back onto an empty database. Said
# plainly rather than discovered: the rollback restores the *service*, and the
# dataset has to be reseeded.
if ($Rebuild) {
    Write-Host "This was a rebuild, so the old data is already gone." -ForegroundColor Yellow
    Write-Host "Rolling back restores the previous image on an empty database." -ForegroundColor Yellow
}

Write-Host "Rolling back to $previous..." -ForegroundColor Yellow
try {
    Invoke-ComposeUp -ImageRef "${registry}/thehub:${previous}"
} catch {
    # Both the deploy and the rollback failed. Say so precisely - "rollback
    # failed" and "deploy failed" send somebody to two different places.
    Write-Host "ROLLBACK FAILED: $_" -ForegroundColor Red
    Write-Host "$Environment is down and neither image is running cleanly." -ForegroundColor Red
    exit 2
}

Write-Host "Rolled back. $Environment is serving $previous; $Sha was not deployed." -ForegroundColor Yellow
exit 1
