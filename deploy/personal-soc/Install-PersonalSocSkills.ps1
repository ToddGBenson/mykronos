<#
.SYNOPSIS
    Install the skill bundle the pipeline published into ~/.claude/skills.

.DESCRIPTION
    The execution half of personal-soc runs the *installed* skills - the
    weekly network scan and the threat monitor both invoke
    ~/.claude/skills/... from a Scheduled Task. The pipeline scans the
    *repository*. Nothing kept the two the same, so a fix committed to
    personal-soc reached the thing that actually runs on Sunday morning only
    if somebody remembered to copy it across.

    This closes that. The `package` job publishes skills-<sha>.zip and moves
    a pointer; this polls the pointer, fetches the bundle and installs it.
    Concourse never writes here - it has no path into ~/.claude and is not
    given one.

.NOTES
    ASCII only - see deploy\concourse\setup.ps1.

    MERGE, NEVER MIRROR. This is the whole reason the install is a script
    rather than an Expand-Archive one-liner.

    ~/.claude/skills/personal-threat-monitor/references/ holds profile.md and
    identifiers.md - the filled identity profile and the identifier ledger.
    They are gitignored, so they are not in the repository and cannot be in
    the bundle. A "wipe the directory and unpack" install would therefore
    delete them, and the skill would come back up with the example templates
    and no memory of who it is monitoring. Files are copied over the top and
    nothing is deleted.

    The cost of that choice, stated so it is not a surprise: a file deleted
    from the repository is not deleted from the install. A stale reference
    lingers until somebody removes it by hand. That is the right way round -
    a leftover file is a nuisance, and a deleted ledger is a loss.
#>

[CmdletBinding()]
param(
    [string]$Endpoint = "http://localhost:9000",
    [string]$Bucket = "personal-soc-releases",
    [string]$SkillRoot = (Join-Path $env:USERPROFILE ".claude\skills"),
    [switch]$Once,
    [int]$IntervalSeconds = 300
)

$ErrorActionPreference = "Stop"
$here = $PSScriptRoot
$stackEnv = Join-Path $here "..\concourse\.env"
if (-not (Test-Path $stackEnv)) { throw "Missing $stackEnv" }

# Names that must never arrive from a bundle, checked here as well as in the
# pipeline. This is the machine that holds the real ones; it is the last place
# that can refuse, and the only one that pays if it does not.
$Confidential = @("profile.md", "identifiers.md")

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
$env:MC_HOST_psoc = "{0}://{1}@{2}" -f $uri.Scheme, $creds, $uri.Authority

$stateFile = Join-Path $here ".installed-skills"
$script:failures = 0

function Get-Pointer {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) "psoc-ptr-$(Get-Random)"
    try {
        & $mc --quiet cp "psoc/$Bucket/skills.requested" $tmp 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $tmp)) { return $null }
        return (Get-Content $tmp -Raw).Trim()
    } finally { if (Test-Path $tmp) { Remove-Item $tmp -Force } }
}

function Invoke-Cycle {
    $requested = Get-Pointer
    if (-not $requested) { return }

    if ($requested -notmatch '^[0-9a-f]{40}$') {
        Write-Host "skills.requested is not a commit SHA ('$requested') - ignoring." -ForegroundColor Red
        $script:failures++
        return
    }

    $current = if (Test-Path $stateFile) { (Get-Content $stateFile -Raw).Trim() } else { "" }
    if ($current -eq $requested) { Write-Verbose "skills already at $requested"; return }

    Write-Host "skills: $current -> $requested" -ForegroundColor Cyan

    $work = Join-Path ([System.IO.Path]::GetTempPath()) "psoc-install-$(Get-Random)"
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    try {
        $zip = Join-Path $work "skills.zip"
        & $mc --quiet cp "psoc/$Bucket/skills-$requested.zip" $zip | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $zip)) {
            Write-Host "Could not fetch skills-$requested.zip - pointer left unacknowledged." -ForegroundColor Red
            $script:failures++
            return
        }

        $extract = Join-Path $work "x"
        Expand-Archive -Path $zip -DestinationPath $extract -Force

        $staged = Join-Path $extract "skills"
        if (-not (Test-Path $staged)) {
            Write-Host "Bundle has no skills/ directory - refusing to install." -ForegroundColor Red
            $script:failures++
            return
        }

        # Third check, on the machine that would pay for the mistake.
        $bad = Get-ChildItem $staged -Recurse -File |
            Where-Object { $Confidential -contains $_.Name }
        if ($bad) {
            Write-Host "Bundle contains confidential files - refusing to install:" -ForegroundColor Red
            $bad | ForEach-Object { Write-Host "  $($_.FullName.Substring($staged.Length))" -ForegroundColor Red }
            $script:failures++
            return
        }

        New-Item -ItemType Directory -Force -Path $SkillRoot | Out-Null

        # Copy over the top. No Remove-Item on the target, ever - see the
        # note in the header about what lives in references/.
        $before = @(Get-ChildItem $SkillRoot -Recurse -File -EA SilentlyContinue).Count
        Copy-Item -Path (Join-Path $staged "*") -Destination $SkillRoot -Recurse -Force
        $after = @(Get-ChildItem $SkillRoot -Recurse -File -EA SilentlyContinue).Count

        # Proof the merge preserved them, rather than an assurance that it did.
        $survived = foreach ($n in $Confidential) {
            Get-ChildItem $SkillRoot -Recurse -File -Filter $n -EA SilentlyContinue
        }
        Write-Host ("  installed into {0} ({1} -> {2} files)" -f $SkillRoot, $before, $after)
        if ($survived) {
            $survived | ForEach-Object { Write-Host "  preserved $($_.Name) in $($_.Directory.Name)" -ForegroundColor DarkGray }
        }

        Set-Content -Path $stateFile -Value $requested -NoNewline -Encoding ASCII

        $ack = Join-Path $work "ack"
        [System.IO.File]::WriteAllText($ack, $requested)
        & $mc --quiet cp $ack "psoc/$Bucket/skills.installed" | Out-Null
        Write-Host "skills installed and acknowledged at $requested" -ForegroundColor Green
    } finally {
        if (Test-Path $work) { Remove-Item $work -Recurse -Force -EA SilentlyContinue }
    }
}

try {
    if ($Once) {
        Invoke-Cycle
        # Explicit: mc leaves a non-zero exit code behind on the ordinary
        # "nothing published yet" path, and a Scheduled Task that reports
        # failure every five minutes is one nobody reads.
        exit $(if ($script:failures -gt 0) { 1 } else { 0 })
    } else {
        Write-Host "Polling $Endpoint/$Bucket every $IntervalSeconds s. Ctrl-C to stop." -ForegroundColor DarkGray
        while ($true) {
            try { Invoke-Cycle } catch { Write-Host "Cycle failed: $($_.Exception.Message)" -ForegroundColor Red }
            Start-Sleep -Seconds $IntervalSeconds
        }
    }
} finally {
    Remove-Item Env:\MC_HOST_psoc -ErrorAction SilentlyContinue
}
