<#
.SYNOPSIS
    Unattended weekly run of the personal-threat-monitor skill (OSINT + threat brief).

.DESCRIPTION
    This one cannot be a Concourse job, and not because of the Linux worker.

    Both checks are driven by references/profile.md and references/identifiers.md
    - the confidential identifier ledger. The skill's own instruction is to keep
    those "out of any git repo or synced/shared location", so they are not in the
    personal-soc checkout a pipeline would clone, and putting them somewhere a
    pipeline could reach would break the rule that makes the skill safe.

    A cloud-scheduled agent has the same problem for the same reason. So this
    runs locally, against the installed skill at ~/.claude/skills, on the machine
    that already holds the ledger.

    breach-check, the paid HIBP job that used to run in Concourse, was retired
    2026-09-23 (#60004). Its replacement is the key-free breach watch,
    Get-NewBreaches.ps1 from the installed skill: it needs no API key, only the
    git-ignored references/account-domains.local.txt, so it can only run here,
    beside the rest of the weekly monitor. This script runs it first and puts
    its verdict at the top of the digest: exit 1 names the new breaches, exit 2
    is reported as unknown and never as clean, and a missing domains file is
    reported once as "breach watch not configured". None of those fails the
    run. What the model does is the part that is judgement rather than a query.

.PARAMETER BreachScript
    The installed skill's Get-NewBreaches.ps1.

.PARAMETER AllowBash
    Adds Bash to the tool allowlist. Off by default: this runs unattended with
    edits auto-accepted, and Bash plus auto-accept is broad authority over this
    desktop for a job nobody is watching. Turn it on only if a run stalls
    waiting for it - the skill is documented read-only, so it should not need it.

.NOTES
    ASCII only, matching the other scripts here.

    Run this once by hand before scheduling it. Claude Code asks about trusting
    a directory the first time it works in one, and a trust prompt in a
    scheduled task is a hang, not an error.
#>

[CmdletBinding()]
param(
    [string]$Repo = (Join-Path $HOME 'personal-soc'),
    [string]$Claude = (Join-Path $HOME '.local\bin\claude.exe'),
    [string]$BreachScript = (Join-Path $HOME '.claude\skills\personal-threat-monitor\scripts\Get-NewBreaches.ps1'),
    [switch]$AllowBash
)

$ErrorActionPreference = "Stop"

# Runs the key-free breach watch and turns its exit code into a verdict. Exit
# 0 is clean, 1 is new breaches, 2 is unknown. Anything else, a missing script
# or a throw is unknown too: it must never read as clean. Returns Code
# (0, 1 or 2), State, and Text for the digest.
function Invoke-BreachWatch {
    param(
        [Parameter(Mandatory)][string]$Script,
        [Parameter(Mandatory)][string]$OutDir,
        [string]$Shell = (Get-Process -Id $PID).Path
    )
    if (-not (Test-Path -LiteralPath $Script -PathType Leaf)) {
        return [pscustomobject]@{ Code = 2; State = 'unknown'
            Text = "Breach watch UNKNOWN: Get-NewBreaches.ps1 not found at $Script. Install the current skills. This is not a pass." }
    }
    # Join-Path segments, not a backslash string: this also runs under pwsh on Linux in CI.
    $skillRoot = Split-Path -Parent (Split-Path -Parent $Script)
    $domains = Join-Path (Join-Path $skillRoot 'references') 'account-domains.local.txt'
    if (-not (Test-Path -LiteralPath $domains -PathType Leaf)) {
        return [pscustomobject]@{ Code = 2; State = 'not-configured'
            Text = 'Breach watch not configured: references/account-domains.local.txt is missing, so no breach signal this run. This is not a pass.' }
    }
    $log = Join-Path $OutDir 'breach-watch.log'
    $file = Join-Path $OutDir 'new-breaches.json'
    # A file left by an earlier run must never be read as this run's answer.
    Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $file) {
        return [pscustomobject]@{ Code = 2; State = 'unknown'
            Text = 'Breach watch UNKNOWN: could not clear the previous new-breaches.json. No breach signal this run; this is not a pass.' }
    }
    $code = 2
    $old = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & $Shell -NoProfile -ExecutionPolicy Bypass -File $Script -OutDir $OutDir *> $log
        $code = $LASTEXITCODE
    } catch {
        $code = 2
    } finally {
        $ErrorActionPreference = $old
    }
    if ($code -eq 0) {
        return [pscustomobject]@{ Code = 0; State = 'clean'
            Text = 'Breach watch: no newly added breach matches an account domain.' }
    }
    if ($code -eq 1) {
        # Exit 1 is also what pwsh -File returns when the script throws outside
        # its own Exit-Unknown. It is a breach only if this run wrote a
        # non-empty array.
        $names = @()
        try {
            $names = @(Get-Content -LiteralPath $file -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop |
                ForEach-Object { "$($_.name) ($($_.domain))" })
        } catch { }
        if ($names.Count) {
            return [pscustomobject]@{ Code = 1; State = 'new-breaches'
                Text = "Breach watch: NEW breach at a service you use: $($names -join ', '). Change those passwords and check for reuse." }
        }
        return [pscustomobject]@{ Code = 2; State = 'unknown'
            Text = 'Breach watch UNKNOWN: Get-NewBreaches.ps1 exited 1 without writing a new-breaches.json for this run, so it probably crashed (see breach-watch.log). No breach signal this run; this is not a pass.' }
    }
    return [pscustomobject]@{ Code = 2; State = 'unknown'
        Text = "Breach watch UNKNOWN: Get-NewBreaches.ps1 exited $code (see breach-watch.log). No breach signal this run; this is not a pass." }
}

# Dot-sourced by the tests to reach the functions without running the job.
# Set and not dot-sourced is an error, never a silent exit.
if ($env:MYKRONOS_TEST_LOAD_ONLY) {
    if ($MyInvocation.InvocationName -eq '.') { return }
    throw 'MYKRONOS_TEST_LOAD_ONLY is set but the script was not dot-sourced; refusing to run the job.'
}

if (-not (Test-Path $Claude)) { throw "claude CLI not found at $Claude" }
if (-not (Test-Path $Repo))   { throw "personal-soc checkout not found at $Repo" }

$today = Get-Date -Format 'yyyy-MM-dd'
$outDir = Join-Path $Repo "personal-monitor\$today"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$breach = Invoke-BreachWatch -Script $BreachScript -OutDir $outDir
Set-Content -LiteralPath (Join-Path $outDir 'breach-watch.md') -Value $breach.Text -Encoding ASCII
$colour = if ($breach.Code -eq 0) { 'Green' } else { 'Yellow' }
Write-Host $breach.Text -ForegroundColor $colour

# No connected-account access. Check A can read the owner's inbox "with
# consent" - but consent is a moment, and there is nobody here to give it.
# Asking for it unattended would either hang or, worse, proceed as though
# silence were agreement.
$prompt = @"
Run the personal-threat-monitor skill for this week, both checks:
  Check A - OSINT self-assessment (digital footprint)
  Check B - personalized threat intelligence brief

This is an UNATTENDED scheduled run. Nobody is available to answer questions:
  - Do not read connected accounts (Gmail, Calendar, Drive). The inbox review
    needs consent given in the moment, and there is none. Note in the run log
    that it was skipped for that reason rather than omitting it silently.
  - Do not ask clarifying questions. Where a judgement is needed, make it and
    record the reasoning.
  - Public sources and the local ledger only.

Follow the skill's guardrails exactly, including the [S]/[D]/[M] handling
classes in references/identifiers.md. Never search an [M] identifier.

Breach watch (key-free, already run before you started; do not re-run it):
  $($breach.Text)
Put that line at the top of security-digest.md. Never describe an unknown
result as clean.

Write into: $outDir
  footprint.json      - Check A findings, machine-readable
  threat-brief.md     - Check B, per references/brief-template.md
  security-digest.md  - the combined weekly digest
  run-log.md          - what ran, what was skipped and why, sources consulted

Diff Check A against the most recent previous personal-monitor/<date>/footprint.json
and surface NEW exposures prominently at the top of security-digest.md. If there
is no previous run, say so rather than implying nothing changed.

Report only what sources actually returned. Mark each finding confirmed,
inferred, or ambiguous. Do not fabricate findings to fill a section.
"@

$tools = @('Read', 'Write', 'Edit', 'Glob', 'Grep', 'WebSearch', 'WebFetch', 'Skill', 'TodoWrite')
if ($AllowBash) { $tools += 'Bash' }

Write-Host "Running personal-threat-monitor into $outDir" -ForegroundColor Cyan
Write-Host "  tools: $($tools -join ', ')" -ForegroundColor DarkGray

Push-Location $Repo
try {
    # acceptEdits, not bypassPermissions: file writes go through without a
    # prompt, and anything outside the allowlist still stops rather than
    # proceeding unsupervised.
    & $Claude --print $prompt `
        --permission-mode acceptEdits `
        --allowedTools $tools 2>&1 | Tee-Object -FilePath (Join-Path $outDir 'claude-run.log')
    $code = $LASTEXITCODE
} finally {
    Pop-Location
}

# A zero exit with no output is the failure mode worth catching: the model
# can end a turn having written nothing, and an empty folder is
# indistinguishable from "nothing to report" unless it is checked for.
$expected = @('threat-brief.md', 'security-digest.md')
$missing = $expected | Where-Object { -not (Test-Path (Join-Path $outDir $_)) }

# The digest carries the breach verdict even if the model dropped it.
$digest = Join-Path $outDir 'security-digest.md'
if ((Test-Path $digest) -and -not (Select-String -LiteralPath $digest -SimpleMatch -Pattern 'Breach watch' -Quiet)) {
    Add-Content -LiteralPath $digest -Value "`n## Breach watch`n`n$($breach.Text)`n"
}
if ($breach.Code -ne 0) {
    Write-Host "`nBreach watch: $($breach.State). See breach-watch.md." -ForegroundColor Yellow
}

if ($code -ne 0) {
    Write-Host "`nclaude exited $code." -ForegroundColor Red
    exit $code
}
if ($missing) {
    Write-Host "`nRun produced no $($missing -join ', ') - treating as a failed run." -ForegroundColor Red
    exit 1
}

Write-Host "`nWrote:" -ForegroundColor Green
Get-ChildItem $outDir | ForEach-Object { "  $($_.Name)  ($($_.Length) bytes)" }
