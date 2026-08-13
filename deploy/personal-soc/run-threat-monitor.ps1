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

    The other half of the split is breach-check, a Concourse job: HIBP is a
    script and needs no ledger beyond a list of addresses. What is left here is
    the part that is judgement rather than a query, which is exactly the part
    that needs a model.

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
    [string]$Repo = (Join-Path $env:USERPROFILE 'personal-soc'),
    [string]$Claude = (Join-Path $env:USERPROFILE '.local\bin\claude.exe'),
    [switch]$AllowBash
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $Claude)) { throw "claude CLI not found at $Claude" }
if (-not (Test-Path $Repo))   { throw "personal-soc checkout not found at $Repo" }

$today = Get-Date -Format 'yyyy-MM-dd'
$outDir = Join-Path $Repo "personal-monitor\$today"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

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
