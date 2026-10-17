#Requires -Version 7
<#
.SYNOPSIS
  Operator-run: everything waiting for your decision, one item at a time,
  each with a recommendation and its reason. You answer agree or not.

.DESCRIPTION
  Covers every pending approval request, not only pull requests: risk
  acceptances, delegations and anything else the engine holds. For each one
  it shows:

    - what it is, from the platform's evidence (the requester's statement is
      shown too, labelled as a claim, never as evidence);
    - for a PR: the files and their classes, and every check on the head;
      for a risk acceptance: what it covers, the residual risk, the end date,
      the justification, premises, controls and milestones;
    - the independent reviewer's shadow verdict and reason, as advice;
    - a recommendation: AGREE, CHECK (one named thing to read first) or WAIT
      (a check is red or still running, so not decidable yet).

  You answer y (agree), n (disagree: you give the reason, and the request is
  rejected), s (skip; it stays open) or d (the full diff or text). Agreeing
  posts an approval with a rationale built from the evidence; you can type
  your own instead.

  It does not offer what cannot be decided: a request for a head the PR has
  moved past, a closed PR, or a request you opened yourself. Those are listed
  with the reason. It also tells you which risk acceptances end within 14
  days or have ended, and how many sampled agent decisions wait for a
  spot-check.

  Approved PRs are then handed to approval-queue.ps1, which waits for
  `independent-review` to go green on the head and squash-merges them in
  order (-NoMerge skips that).

  The recommendation logic is in review_inbox.py beside this script, where
  tests pin it. Tokens are read from MyKronos's backend\.env and never
  printed. Every answer is written to a log under -LogDir.

.EXAMPLE
  .\review-inbox.ps1
.EXAMPLE
  .\review-inbox.ps1 -DryRun        # read-only: show the inbox, decide nothing
.EXAMPLE
  .\review-inbox.ps1 -NoMerge       # decide, but merge nothing
#>
[CmdletBinding()]
param(
  [switch] $DryRun,
  [switch] $NoMerge,
  [string] $Repo = 'ToddGBenson/mykronos',
  [string] $RepoPath = 'C:\Users\tgb_\Documents\Projects\mykronos',
  [string] $Api = 'http://127.0.0.1:8100',
  [string] $AdminIdentity = 'admin',
  [string] $Python = '',
  [string] $LogDir = (Join-Path $HOME 'approval-queue-logs')
)
$ErrorActionPreference = 'Stop'

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$script:LogFile = Join-Path $LogDir ("review-inbox-{0:yyyyMMdd-HHmmss}.log" -f (Get-Date))
function Log([string] $Message, [string] $Color = 'Gray') {
  Add-Content -LiteralPath $script:LogFile -Value ("{0:yyyy-MM-ddTHH:mm:ssK} {1}" -f (Get-Date), $Message) -Encoding utf8
  Write-Host $Message -ForegroundColor $Color
}

# -- Credentials (never printed) ---------------------------------------------------
$envFile = Join-Path $RepoPath 'backend\.env'
function Read-EnvValue([string] $name) {
  $l = Select-String -LiteralPath $envFile -Pattern "^$name=" | Select-Object -First 1
  if (-not $l) { throw "$name not found in $envFile" }
  return $l.Line.Substring($name.Length + 1).Trim().Trim('"')
}
$script:H = @{
  Authorization = "Bearer $(Read-EnvValue 'MYKRONOS_ADMIN_TOKEN')"
  'X-Hub-Token' = (Read-EnvValue 'MYKRONOS_GATE_TOKEN')
}

$script:Helper = Join-Path $PSScriptRoot 'review_inbox.py'
if (-not (Test-Path -LiteralPath $script:Helper)) { throw "review_inbox.py not found beside this script" }
if (-not $Python) {
  $venv = Join-Path $RepoPath 'backend\.venv\Scripts\python.exe'
  $Python = if (Test-Path -LiteralPath $venv) { $venv } else { 'python' }
}

function Invoke-Api([string] $Path, [string] $Method = 'Get', $Body = $null) {
  $p = @{ Method = $Method; Uri = "$Api$Path"; Headers = $script:H }
  if ($null -ne $Body) { $p.ContentType = 'application/json'; $p.Body = (ConvertTo-Json -InputObject $Body -Depth 8) }
  try {
    $r = Invoke-RestMethod @p
    return $r
  } catch {
    $detail = $null
    try { $detail = ($_.ErrorDetails.Message | ConvertFrom-Json).detail } catch { $detail = $null }
    if (-not $detail) { $detail = $_.Exception.Message }
    if ($detail -isnot [string]) { $detail = ConvertTo-Json -InputObject $detail -Depth 6 -Compress }
    throw "MyKronos: $detail"
  }
}

# -- Gather ------------------------------------------------------------------------
Write-Host 'Reading the inbox...' -ForegroundColor DarkGray
$pending = @(Invoke-Api '/api/approvals?state=pending')
$requests = foreach ($r in $pending) {
  $ev = Invoke-Api "/api/approvals/$($r.id)/evidence"
  @{ request = $r; evidence = $ev.evidence; evidence_digest = $ev.evidence_digest }
}
$shadow = @()
try { $shadow = @((Invoke-Api '/api/approvals/shadow-reviews').reviews) } catch { Log "  could not read the reviewer's verdicts: $_" 'Yellow' }
$acceptances = @()
try { $acceptances = @(Invoke-Api '/api/risk-acceptances?status_filter=active') } catch { Log "  could not read risk acceptances: $_" 'Yellow' }
$samples = 0
try { $samples = @(Invoke-Api '/api/approvals/samples').Count } catch { $samples = 0 }

$prs = @{}
foreach ($r in $pending | Where-Object { $_.duty -eq 'pull_request_merge' }) {
  if ($r.subject_ref -match '#(\d+)@') {
    $n = $Matches[1]
    if (-not $prs.ContainsKey($n)) {
      $j = gh pr view $n --repo $Repo --json number,title,state,headRefOid,statusCheckRollup 2>$null
      if ($LASTEXITCODE -eq 0) { $prs[$n] = (($j -join "`n") | ConvertFrom-Json) }
    }
  }
}

$bundle = @{
  operator = $AdminIdentity; now = (Get-Date).ToUniversalTime().ToString('o')
  requests = @($requests); shadow = $shadow; prs = $prs; acceptances = $acceptances; samples = $samples
}
$in = New-TemporaryFile
try {
  ConvertTo-Json -InputObject $bundle -Depth 20 | Set-Content -LiteralPath $in.FullName -Encoding utf8NoBOM
  $out = & $Python $script:Helper build $in.FullName
  if ($LASTEXITCODE -ne 0) { throw "review_inbox.py exited $LASTEXITCODE" }
} finally { Remove-Item -LiteralPath $in.FullName -Force -ErrorAction SilentlyContinue }
$inbox = ($out -join "`n") | ConvertFrom-Json -Depth 20

# -- Inform ------------------------------------------------------------------------
Log "`n=== Review inbox: $(@($inbox.offered).Count) to decide ===" 'Cyan'
foreach ($n in @($inbox.notices)) { Log "  ! $n" 'Yellow' }
if (@($inbox.skipped).Count) {
  Log "`nNot offered (nothing for you to decide):" 'DarkGray'
  foreach ($s in @($inbox.skipped)) { Log "  - $($s.title): $($s.why_not)" 'DarkGray' }
}
if ($DryRun) {
  foreach ($i in @($inbox.offered)) {
    Write-Host "`n[$($i.recommendation)] $($i.title)" -ForegroundColor Cyan
    Write-Host "  why: $($i.why)"
    $i.lines | ForEach-Object { Write-Host $_ }
  }
  Log "`nDry run: nothing decided." 'Cyan'
  return
}

# -- Decide ------------------------------------------------------------------------
$colors = @{ AGREE = 'Green'; CHECK = 'Yellow'; WAIT = 'DarkYellow' }
$approvedPrs = [System.Collections.Generic.List[int]]::new()
$tally = [ordered]@{ agreed = 0; disagreed = 0; skipped = 0; refused = 0 }
$k = 0
foreach ($i in @($inbox.offered)) {
  $k++
  Write-Host ("`n----- {0} of {1} -------------------------------------------" -f $k, @($inbox.offered).Count) -ForegroundColor DarkGray
  Write-Host "[$($i.recommendation)] $($i.title)" -ForegroundColor $colors[$i.recommendation]
  Write-Host "  recommendation: $($i.recommendation) - $($i.why)" -ForegroundColor $colors[$i.recommendation]
  $i.lines | ForEach-Object { Write-Host $_ }
  if ($i.requester_statement) { Write-Host "  requester's claim (not evidence): $($i.requester_statement)" -ForegroundColor DarkGray }
  Write-Host "  requested by $($i.requested_by); the request expires $($i.expires_at)" -ForegroundColor DarkGray

  do {
    $ans = (Read-Host 'Agree? y = yes, n = no, s = skip, d = details').Trim().ToLower()
    if ($ans -eq 'd') {
      if ($i.diff) { foreach ($f in @($i.diff)) { Write-Host "`n=== $($f.path) [$($f.class)]" -ForegroundColor Cyan; Write-Host $f.patch } }
      elseif ($i.full_text) { Write-Host $i.full_text }
    }
  } while ($ans -notin @('y', 'n', 's'))

  if ($ans -eq 's') { $tally.skipped++; Log "  $($i.title): skipped; it stays open" 'DarkGray'; continue }
  if ($ans -eq 'y') {
    $verdict = 'approve'
    Write-Host "  rationale: $($i.approve_rationale)" -ForegroundColor DarkGray
    $rat = Read-Host 'Enter keeps that rationale, or type what you checked (20+ characters)'
    if ($rat.Trim().Length -lt 20) { $rat = $i.approve_rationale }
  } else {
    $verdict = 'reject'
    do { $rat = Read-Host 'Why not? (20+ characters; the requester and the reviewer are measured on it)' } while ($rat.Trim().Length -lt 20)
  }
  try {
    $dec = Invoke-Api -Path "/api/approvals/$($i.request_id)/decisions" -Method 'Post' -Body @{ verdict = $verdict; rationale = $rat; evidence_digest = $i.evidence_digest }
    Add-Content -LiteralPath $script:LogFile -Value "      $verdict, rationale: $rat" -Encoding utf8
    if ($verdict -eq 'approve') {
      $tally.agreed++
      Log "  $($i.title): you agreed; the request is $($dec.state)" $(if ($dec.state -eq 'approved') { 'Green' } else { 'Yellow' })
      if ($dec.state -eq 'approved' -and $i.duty -eq 'pull_request_merge') { $approvedPrs.Add([int] $i.pr_number) }
    } else {
      $tally.disagreed++
      Log "  $($i.title): you disagreed; the request is $($dec.state)" 'Yellow'
    }
  } catch {
    $tally.refused++
    Log "  $($i.title): MyKronos refused the decision: $_" 'Red'
  }
}

Log ("`n=== Done: {0} agreed, {1} disagreed, {2} skipped, {3} refused ===" -f $tally.agreed, $tally.disagreed, $tally.skipped, $tally.refused) 'Cyan'

# -- Merge what you approved ----------------------------------------------------------
if ($approvedPrs.Count -gt 0) {
  if ($NoMerge) {
    Log "Approved, not merged (-NoMerge): $(($approvedPrs | ForEach-Object { "#$_" }) -join ' '). approval-queue.ps1 $($approvedPrs -join ' ') merges them." 'Cyan'
  } else {
    Log "Merging what you approved: $(($approvedPrs | ForEach-Object { "#$_" }) -join ' ')" 'Cyan'
    & (Join-Path $PSScriptRoot 'approval-queue.ps1') @($approvedPrs) -NoSamples -Repo $Repo -RepoPath $RepoPath -Api $Api -AdminIdentity $AdminIdentity -LogDir $LogDir
  }
}
Log "Log: $script:LogFile" 'DarkGray'
