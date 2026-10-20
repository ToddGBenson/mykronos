#Requires -Version 7.2
<#
.SYNOPSIS
    Run one control-observation collector for one repository: what the
    scheduled tasks call (TheHub #60834).

.DESCRIPTION
    The environmental CVSS resolver lowers a score only on an observation no
    older than 14 days (control_observations.FRESH_DAYS). A collector nobody
    runs is a lowering that silently expires. Register-ControlObservationTasks.ps1
    registers a daily task per collector; each task runs this script, which:

      -Collector host   runs Publish-ControlObservations.ps1 (vantage `host`):
                        docker published ports, cloudflared ingress, firewall
                        evidence, posted as mykronos.host-observations/1.
      -Collector lan    runs `python -m mykronos.lan_scan` (vantage `lan`):
                        nmap -sV --top-ports 1000 against exactly -Cidr, under
                        -AuthorizationReference (spec 14 section 3).

    THE TOKENS ARE READ AT RUN TIME, NEVER PASSED IN. The task definition holds
    the NAME of the .env key (-TokenKey), not its value. The repository's
    ingestion token and the perimeter gate token are read from -EnvFile
    (backend\.env) when the task fires and handed to the collector through this
    process's environment, so neither appears in the task's arguments, in a
    command line, or in the log. backend\.env is where repair-ingestion-token.ps1
    delivers a rotated token (MYKRONOS_CONCOURSE_TOKEN for mykronos,
    MYKRONOS_THEHUB_CONCOURSE_TOKEN for TheHub), so a rotation reaches these
    tasks without anyone re-registering them. A copy kept anywhere else would
    break 24 hours after the next rotation, at the end of the overlap window.

    The token must hold the `network` grant (`mykronos grant <repo> network`);
    without it the server answers 403, and this exits non-zero so the task's
    Last Run Result says so.

    Each run writes %LOCALAPPDATA%\mykronos-observations\last-<collector>-<repo>.log,
    replacing the previous one. Exit 0 on success, 1 on failure, 2 on a refusal
    (missing input; nothing was collected).

.PARAMETER DryRun
    Resolve every input and print the plan. Reads the .env file only to check
    the keys are present; collects nothing, posts nothing, prints no token.

.EXAMPLE
    pwsh -File deploy/concourse/Invoke-ControlObservationCollector.ps1 -Collector host -Repo ToddGBenson/mykronos -TokenKey MYKRONOS_CONCOURSE_TOKEN -ContainerFilter 'mykronos-*' -DryRun

.NOTES
    ASCII only -- see setup.ps1.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('host', 'lan')][string] $Collector,
    [Parameter(Mandatory)][string] $Repo,
    [Parameter(Mandatory)][string] $TokenKey,
    [string] $GateTokenKey = 'MYKRONOS_GATE_TOKEN',
    [string] $EnvFile = (Join-Path $PSScriptRoot '..\..\backend\.env'),
    [string] $MykronosUrl = 'http://127.0.0.1:8100',
    # host
    [string] $ContainerFilter = '*',
    # lan
    [string[]] $Cidr = @(),
    [string] $AuthorizationReference = '',
    [string] $Python = (Join-Path $PSScriptRoot '..\..\backend\.venv\Scripts\python.exe'),
    [string] $Nmap = 'nmap',
    [string] $LogDir = (Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)) 'mykronos-observations'),
    [switch] $DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# A scheduled task passes -Cidr as one comma-separated argument.
$Cidr = @($Cidr | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })

$EXIT_OK = 0
$EXIT_FAILED = 1
$EXIT_REFUSED = 2

function Read-EnvValue {
    # Same reader as deploy.ps1 and set-pipeline.ps1: the first KEY= line.
    param([string]$Path, [string]$Key)
    $line = Select-String -LiteralPath $Path -Pattern "^$([regex]::Escape($Key))=" -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if (-not $line) { return '' }
    return $line.Line.Split('=', 2)[1].Trim().Trim('"').Trim("'")
}

$slug = ($Repo -replace '[^A-Za-z0-9._-]', '_')
$logPath = Join-Path $LogDir "last-$Collector-$slug.log"
$lines = [System.Collections.Generic.List[string]]::new()

function Write-Line {
    param([string] $Text)
    $lines.Add($Text)
    [Console]::Out.WriteLine($Text)
}

function Save-Log {
    if ($DryRun) { return }
    try {
        New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
        Set-Content -LiteralPath $logPath -Value $lines -Encoding ascii
    } catch {
        Write-Warning "could not write $logPath : $($_.Exception.Message)"
    }
}

function Exit-Run {
    param([int] $Code, [string] $Why)
    Write-Line "result: $(@{0='ok';1='failed';2='refused'}[$Code]) - $Why"
    Save-Log
    exit $Code
}

Write-Line "collector: $Collector  repo: $Repo  at: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))  dry-run: $([bool]$DryRun)"

# -- inputs: refuse before collecting anything ------------------------------
$problems = @()
if (-not (Test-Path -LiteralPath $EnvFile)) {
    $problems += "no env file at $EnvFile"
    $token = ''
    $gate = ''
} else {
    $token = Read-EnvValue -Path $EnvFile -Key $TokenKey
    $gate = if ($GateTokenKey) { Read-EnvValue -Path $EnvFile -Key $GateTokenKey } else { '' }
    if (-not $token) { $problems += "$TokenKey is not set in $EnvFile" }
    if ($GateTokenKey -and -not $gate) { $problems += "$GateTokenKey is not set in $EnvFile" }
}

if ($Collector -eq 'lan') {
    # spec 14 section 3: no default range, no scan without an authorization.
    if ($Cidr.Count -eq 0) { $problems += 'no -Cidr: the LAN collector scans only ranges it is given' }
    if (-not $AuthorizationReference.Trim()) { $problems += 'no -AuthorizationReference (spec 14 section 3)' }
    if (-not (Test-Path -LiteralPath $Python)) { $problems += "no python at $Python" }
    if (-not (Get-Command $Nmap -ErrorAction SilentlyContinue)) { $problems += "nmap not found: $Nmap" }
} else {
    $publisher = Join-Path $PSScriptRoot 'Publish-ControlObservations.ps1'
    if (-not (Test-Path -LiteralPath $publisher)) { $problems += "no publisher at $publisher" }
}

Write-Line "env file: $EnvFile  token key: $TokenKey ($(if ($token) { 'present' } else { 'missing' }))  gate key: $GateTokenKey ($(if ($gate) { 'present' } else { 'missing' }))"
if ($Collector -eq 'lan') {
    Write-Line "would scan: $($Cidr -join ', ')  authorization: $AuthorizationReference"
    Write-Line "python: $Python  nmap: $Nmap"
} else {
    Write-Line "containers: $ContainerFilter"
}
Write-Line "post to: $MykronosUrl"

if ($problems.Count -gt 0) {
    foreach ($p in $problems) { Write-Line "refused: $p" }
    Exit-Run -Code $EXIT_REFUSED -Why 'nothing collected'
}
if ($DryRun) {
    Exit-Run -Code $EXIT_OK -Why 'dry run: inputs resolve; nothing collected or posted'
}

# -- run: tokens travel in this process's environment only ------------------
$env:MYKRONOS_INGESTION_TOKEN = $token
$env:MYKRONOS_GATE_TOKEN = $gate
$env:MYKRONOS_URL = $MykronosUrl
try {
    if ($Collector -eq 'host') {
        $out = & $publisher -MykronosUrl $MykronosUrl -ContainerFilter $ContainerFilter 2>&1 | Out-String
        foreach ($l in ($out -split "`r?`n")) { if ($l.Trim()) { Write-Line $l } }
        Exit-Run -Code $EXIT_OK -Why 'host observations posted'
    }

    $pyArgs = @('-m', 'mykronos.lan_scan', '--repo', $Repo, '--authorization-reference', $AuthorizationReference,
        '--ingestion-url', $MykronosUrl, '--nmap', $Nmap)
    foreach ($c in $Cidr) { $pyArgs += @('--cidr', $c) }
    $env:PYTHONPATH = (Resolve-Path (Join-Path $PSScriptRoot '..\..\backend')).Path
    $out = & $Python @pyArgs 2>&1 | Out-String
    $code = $LASTEXITCODE
    foreach ($l in ($out -split "`r?`n")) { if ($l.Trim()) { Write-Line $l } }
    if ($code -ne 0) { Exit-Run -Code $EXIT_FAILED -Why "lan_scan exited $code" }
    Exit-Run -Code $EXIT_OK -Why 'LAN observations posted'
} catch {
    # The exception text is the server's answer or a local error; the token is
    # only ever in a header, never in a message.
    Exit-Run -Code $EXIT_FAILED -Why $_.Exception.Message
} finally {
    Remove-Item Env:MYKRONOS_INGESTION_TOKEN, Env:MYKRONOS_GATE_TOKEN -ErrorAction SilentlyContinue
}
