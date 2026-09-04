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

    And `:latest` only exists once `promote` has run. `delivery.yml` publishes
    `:${SHA}` on every push and moves `:latest` only after the production
    environment's approval, which is D-047's rule that the gate holds the tag
    rather than the artifact. A first deploy after the cutover therefore has
    nothing to pull until a promote has happened - which reads as a broken
    script unless it says so.

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

Write-Host "Pulling images from $Registry..." -ForegroundColor Cyan
foreach ($name in @("mykronos-backend", "mykronos-frontend")) {
    docker pull "$Registry/$name`:latest"
    if ($LASTEXITCODE -ne 0) {
        # Named causes rather than "could not pull". Each of these fails the
        # same way at the daemon and needs a different thing done about it,
        # and the first cutover to GHCR is exactly when somebody will meet
        # one of them for the first time.
        $lines = @(
            "Could not pull $Registry/$name`:latest.",
            "",
            "  * Has delivery.yml promoted yet? It publishes :<sha> on every",
            "    push and moves :latest only after the production",
            "    environment's approval (D-047). Before the first promote",
            "    there is no :latest to pull.",
            "  * Is the package public? A GHCR package is private by default",
            "    even in a public repository. Either make it public in the",
            "    package settings, or run: docker login ghcr.io",
            "    with a token carrying read:packages.",
            "  * Still on the old registry? Pass -Registry localhost:5000."
        )
        throw ($lines -join [Environment]::NewLine)
    }
    docker tag "$Registry/$name`:latest" "$name`:latest"
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

if ($NoStart) { return }

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
} finally {
    Pop-Location
}
