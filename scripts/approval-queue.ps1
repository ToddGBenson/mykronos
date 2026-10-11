#Requires -Version 7
<#
.SYNOPSIS
  Operator-run: take mykronos pull requests through independent approval and
  squash-merge them, one command for the whole queue (D-149).

.DESCRIPTION
  Replaces approve-pr.ps1. The queue does the waiting, the rebasing and the
  merging; it never approves anything as an agent. Who approves comes from the
  platform (spec 34, approval-policy-v1.yaml):

    governance          you, in ONE batch prompt per round: every governance
                        request waiting is shown with its evidence, and you
                        answer y or n for each in a single pass.
    production/routine  the platform-started reviewer, when it is live and an
                        active delegation covers the tier: the queue asks the
                        platform to start it (POST /{id}/independent-review),
                        the platform picks the model and the evidence, and the
                        decision goes through the engine like anyone's.
                        Otherwise these join your batch too.

  It works in rounds. Each round:
    1. brings every remaining PR up to date: a PR that conflicts with main is
       merged with origin/main in a temp worktree (main's side first, so
       docs/DECISIONS.md is merged by `merge=union` with main's entries on
       top), the merged log is checked (main's entries intact, no number taken
       twice, the branch's after them), the repo's decision-log test is run,
       and it is pushed with --force-with-lease (a fast-forward: the merge
       descends from the PR head). Not a rebase - see Update-Branch for why.
       A PR that is only behind is left alone: main does not require
       branches to be up to date, and a new head would cost a new request.
    2. waits, polling, for the platform's pending request on each current head
       (job:pull-request-requests opens one ~10 minutes after first seeing it).
    3. decides: reviewer runs first, then your one batch prompt.
    4. merges approved PRs in order once `independent-review` is green on the
       head, with `gh pr merge --squash --match-head-commit`, and
       fast-forwards local main. A PR the previous merge made conflict goes to
       the next round.

  Anything that fails - a conflict outside the decision log, a failed check,
  a test, a refusal from the engine - skips that PR with the engine's own
  message and the queue carries on. At the end it offers you the sampled
  agent decisions waiting for your spot-check (spec 34 sec. 5.2): samples left
  unreviewed for 14 days suspend the delegation.

  Tokens are read from MyKronos's backend\.env and never printed. Every step
  is written to a log file under -LogDir.

.EXAMPLE
  .\approval-queue.ps1 772 770 773 774
.EXAMPLE
  .\approval-queue.ps1 -All
.EXAMPLE
  .\approval-queue.ps1 -All -DryRun        # the plan and the routing, nothing changed
.EXAMPLE
  .\approval-queue.ps1 -SamplesOnly        # just the spot-check queue
#>
[CmdletBinding()]
param(
  [Parameter(Position = 0, ValueFromRemainingArguments = $true)] [int[]] $Pr,
  [switch] $All,
  [switch] $DryRun,
  [switch] $SamplesOnly,
  [switch] $NoSamples,
  [string] $Repo = 'ToddGBenson/mykronos',
  [string] $RepoPath = 'C:\Users\tgb_\Documents\Projects\mykronos',
  [string] $Api = 'http://127.0.0.1:8100',
  [string] $AdminIdentity = 'admin',
  [int] $RequestTimeoutMinutes = 30,
  [int] $CheckTimeoutMinutes = 10,
  [int] $PollSeconds = 30,
  [int] $MaxRounds = 0,
  [string] $Python = '',
  [string] $LogDir = (Join-Path $HOME 'approval-queue-logs')
)
$ErrorActionPreference = 'Stop'

# -- Logging ----------------------------------------------------------------------
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$script:LogFile = Join-Path $LogDir ("approval-queue-{0:yyyyMMdd-HHmmss}.log" -f (Get-Date))
function Log([string] $Message, [string] $Color = 'Gray') {
  $line = "{0:yyyy-MM-ddTHH:mm:ssK} {1}" -f (Get-Date), $Message
  Add-Content -LiteralPath $script:LogFile -Value $line -Encoding utf8
  Write-Host $Message -ForegroundColor $Color
}
Log "approval-queue: log at $script:LogFile" 'DarkGray'

# -- Credentials (never printed) ------------------------------------------------------
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

# -- The pure logic lives in approval_queue.py, beside this script ------------------------
$script:Helper = Join-Path $PSScriptRoot 'approval_queue.py'
if (-not (Test-Path -LiteralPath $script:Helper)) {
  $script:Helper = Join-Path $RepoPath 'scripts\approval_queue.py'
}
if (-not (Test-Path -LiteralPath $script:Helper)) { throw "approval_queue.py not found beside this script or in $RepoPath\scripts" }
if (-not $Python) {
  $venv = Join-Path $RepoPath 'backend\.venv\Scripts\python.exe'
  $Python = if (Test-Path -LiteralPath $venv) { $venv } else { 'python' }
}

function Invoke-Helper([string] $Command, $InputObject) {
  $in = New-TemporaryFile
  try {
    ConvertTo-Json -InputObject $InputObject -Depth 12 | Set-Content -LiteralPath $in.FullName -Encoding utf8NoBOM
    $out = & $Python $script:Helper $Command $in.FullName
    if ($LASTEXITCODE -ne 0) { throw "approval_queue.py $Command exited $LASTEXITCODE" }
    return (($out -join "`n") | ConvertFrom-Json -Depth 12)
  } finally { Remove-Item -LiteralPath $in.FullName -Force -ErrorAction SilentlyContinue }
}

# -- The platform's API -----------------------------------------------------------------
class ApiError : System.Exception {
  [int] $Status
  ApiError([int] $status, [string] $message) : base($message) { $this.Status = $status }
}
function Invoke-Api([string] $Path, [string] $Method = 'Get', $Body = $null) {
  $p = @{ Method = $Method; Uri = "$Api$Path"; Headers = $script:H }
  if ($null -ne $Body) { $p.ContentType = 'application/json'; $p.Body = (ConvertTo-Json -InputObject $Body -Depth 8) }
  try {
    # Assign first: a JSON array comes back as ONE object, and returning the
    # variable is what unrolls it (approve-pr.ps1's lesson).
    $r = Invoke-RestMethod @p
    return $r
  } catch {
    $status = 0
    try { $status = [int] $_.Exception.Response.StatusCode } catch { $status = 0 }
    $detail = $null
    try { $detail = ($_.ErrorDetails.Message | ConvertFrom-Json).detail } catch { $detail = $null }
    if (-not $detail) { $detail = if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message } }
    if ($detail -isnot [string]) { $detail = ConvertTo-Json -InputObject $detail -Depth 6 -Compress }
    throw [ApiError]::new($status, [string] $detail)
  }
}

# -- GitHub and git ----------------------------------------------------------------------
$PrFields = 'number,title,state,isDraft,headRefName,headRefOid,baseRefName,isCrossRepository,createdAt'
function Get-Pr([int] $n) {
  $j = gh pr view $n --repo $Repo --json $PrFields
  if ($LASTEXITCODE -ne 0) { return $null }
  return (($j -join "`n") | ConvertFrom-Json)
}
function Invoke-Git([string[]] $GitArgs, [string] $Dir = $RepoPath) {
  $out = & git -C $Dir @GitArgs 2>&1
  $code = $LASTEXITCODE
  Add-Content -LiteralPath $script:LogFile -Value ("    git {0} -> {1}" -f ($GitArgs -join ' '), $code) -Encoding utf8
  return [pscustomobject]@{ Code = $code; Out = (($out | ForEach-Object { "$_" }) -join "`n") }
}
function Sync-Origin([string[]] $Branches) {
  $refs = @('+refs/heads/main:refs/remotes/origin/main') + @($Branches | ForEach-Object { "+refs/heads/${_}:refs/remotes/origin/$_" })
  $r = Invoke-Git (@('fetch', '--quiet', 'origin') + $refs)
  if ($r.Code -ne 0) { throw "git fetch failed: $($r.Out)" }
}
# GitHub's merge button runs no merge drivers, so the conflict test must not
# either: once main's .gitattributes says `merge=union`, a plain merge-tree
# would call a decision-log conflict clean that GitHub still refuses.
# --attr-source (the empty tree) replaces the in-tree attributes and an empty
# core.attributesFile the global ones.
$script:NoAttrs = Join-Path ([IO.Path]::GetTempPath()) 'mykronos-approval-queue.noattributes'
Set-Content -LiteralPath $script:NoAttrs -Value '' -Encoding ascii
$EmptyTree = '4b825dc642cb6eb9a060e54bf8d69288fbee4904'
function Test-Conflict([string] $Branch) {
  # Merged as GitHub would merge it, without a working tree: exit 1 = conflict.
  $r = Invoke-Git @('-c', "core.attributesFile=$script:NoAttrs", "--attr-source=$EmptyTree", 'merge-tree', '--write-tree', '--name-only', 'origin/main', "origin/$Branch")
  if ($r.Code -gt 1) { throw "git merge-tree failed for ${Branch}: $($r.Out)" }
  return ($r.Code -eq 1)
}
function Get-Deferred([int[]] $Numbers, $Prs) {
  <# Which PRs to leave for the next round, so a decision is never spent on a
     head the round's own merges will replace. The round's squash merges are
     simulated in queue order, as GitHub will make them and without merge
     drivers: each clean merge-tree result becomes a dangling commit on top of
     the last, and the next PR is merged against that. A PR that conflicts
     there would be re-headed after the merge before it - two PRs that both
     append to docs/DECISIONS.md always do - so it waits. #>
  $tip = (Invoke-Git @('rev-parse', 'origin/main')).Out.Trim()
  $deferred = @{}
  foreach ($n in $Numbers) {
    $r = Invoke-Git @('-c', "core.attributesFile=$script:NoAttrs", "--attr-source=$EmptyTree", 'merge-tree', '--write-tree', $tip, "origin/$($Prs[$n].headRefName)")
    if ($r.Code -ne 0) { $deferred[$n] = $true; continue }
    $tree = ($r.Out -split "`n")[0].Trim()
    $c = Invoke-Git @('commit-tree', $tree, '-p', $tip, '-m', 'approval-queue: simulated squash merge')
    if ($c.Code -ne 0) { $deferred[$n] = $true; continue }
    $tip = $c.Out.Trim()
  }
  return $deferred
}

# The union driver, supplied for the queue's own merge even before main's
# .gitattributes carries it: core.attributesFile is the lowest-priority
# attributes source, so the in-tree line wins once it exists and says the same.
$script:Attrs = Join-Path ([IO.Path]::GetTempPath()) 'mykronos-approval-queue.gitattributes'
Set-Content -LiteralPath $script:Attrs -Value 'docs/DECISIONS.md merge=union' -Encoding ascii

function Update-Branch($p) {
  <# Bring a conflicting PR up to date with origin/main and push it. Returns
     $null on success, or the reason it could not.

     A merge, not a rebase, and made FROM main's side. Measured on #770 and
     #773 (2026-10-11): a rebase replays the branch one commit at a time, so a
     branch that appended D-136 and later renamed it D-137 came out with BOTH
     headings - union kept the intermediate line. One merge of the final trees
     applies union once. With main as "ours", union writes main's lines first
     and the branch's after them, which is what an append-only log needs. The
     merge commit descends from the branch tip, so the push is a fast-forward,
     and GitHub squashes it away at merge. #>
  $branch = $p.headRefName
  $old = $p.headRefOid
  if ($branch -in @('main', 'master') -or $branch -eq $p.baseRefName) { return "refusing to rewrite '$branch'" }
  $wt = Join-Path ([IO.Path]::GetTempPath()) ("mk-queue-{0}-{1}" -f $p.number, ([guid]::NewGuid().ToString('N').Substring(0, 8)))
  $r = Invoke-Git @('worktree', 'add', '--detach', $wt, 'origin/main')
  if ($r.Code -ne 0) { return "could not create a worktree: $($r.Out)" }
  try {
    $msg = "Merge main into $branch (approval-queue: docs/DECISIONS.md merged by union, D-149)"
    $r = Invoke-Git @('-c', "core.attributesFile=$script:Attrs", 'merge', '--no-ff', '-m', $msg, "origin/$branch") $wt
    if ($r.Code -ne 0) {
      $files = (Invoke-Git @('diff', '--name-only', '--diff-filter=U') $wt).Out -split "`n" | Where-Object { $_ }
      Invoke-Git @('merge', '--abort') $wt | Out-Null
      return "conflicts with main outside what the queue can merge: $($files -join ', ')"
    }
    if ((Invoke-Git @('merge-base', '--is-ancestor', $old, 'HEAD') $wt).Code -ne 0) { return "the merge does not descend from the PR head $old" }
    # The decision index (D-149) is generated, so it is regenerated rather than
    # trusted to union: two PRs that each add a decision file both add a line
    # at its end. Folded into the merge commit, which only this run has seen.
    $indexer = Join-Path $wt 'scripts\decisions_index.py'
    if (Test-Path -LiteralPath $indexer) {
      & $Python $indexer --check --root $wt 2>$null | Out-Null
      if ($LASTEXITCODE -ne 0) {
        $w = & $Python $indexer --root $wt 2>&1
        if ($LASTEXITCODE -ne 0) { return "the decision index could not be regenerated: $(($w | ForEach-Object { "$_" }) -join ' ')" }
        Invoke-Git @('add', 'docs/DECISIONS.md') $wt | Out-Null
        $r = Invoke-Git @('commit', '--quiet', '--amend', '--no-edit') $wt
        if ($r.Code -ne 0) { return "could not fold the regenerated index into the merge: $($r.Out)" }
        Log "  #$($p.number): regenerated the decision index after the merge" 'DarkGray'
      }
    }
    $log = Join-Path $wt 'docs\DECISIONS.md'
    if (Test-Path -LiteralPath $log) {
      # Python reads main's log from git as bytes: PowerShell would decode
      # git's stdout with the console code page and could mangle the em dash
      # every heading carries, and a log with no readable headings checks clean.
      $out = & $Python $script:Helper 'check-decisions-git' $RepoPath $log
      if ($LASTEXITCODE -ne 0) { return "the decision-log check could not run (exit $LASTEXITCODE)" }
      $problems = @((($out -join "`n") | ConvertFrom-Json).problems)
      if ($problems.Count -gt 0) { return "the union-merged decision log is wrong: $($problems -join ' ')" }
      Push-Location (Join-Path $wt 'backend')
      try {
        $t = & $Python -m pytest tests/test_decisions_log.py -q -p no:cacheprovider 2>&1
        $code = $LASTEXITCODE
        Add-Content -LiteralPath $script:LogFile -Value (($t | ForEach-Object { "      $_" }) -join "`n") -Encoding utf8
        if ($code -ne 0) { return "test_decisions_log.py fails after the merge: $(($t | Select-Object -Last 3) -join ' ')" }
      } finally { Pop-Location }
    }
    $new = (Invoke-Git @('rev-parse', 'HEAD') $wt).Out.Trim()
    if ($new -eq $old) { return $null }
    $r = Invoke-Git @('push', '--quiet', "--force-with-lease=refs/heads/${branch}:$old", 'origin', "HEAD:refs/heads/$branch") $wt
    if ($r.Code -ne 0) { return "push refused (someone else pushed to $branch?): $($r.Out)" }
    Log ("  #{0}: merged main in, {1} -> {2}, pushed; the platform opens a request for the new head in ~10 min" -f $p.number, $old.Substring(0, 8), $new.Substring(0, 8)) 'Cyan'
    return $null
  } finally {
    Invoke-Git @('worktree', 'remove', '--force', $wt) | Out-Null
  }
}

function Get-ApprovalRequest([string] $State) {
  return @(Invoke-Api "/api/approvals?state=$State&duty=pull_request_merge")
}
function Wait-IndependentReview([string] $Sha) {
  <# The latest `independent-review` run on the sha: 'success', 'failure:<why>' or 'timeout'. #>
  $deadline = (Get-Date).AddMinutes($CheckTimeoutMinutes)
  do {
    $j = gh api "repos/$Repo/commits/$Sha/check-runs?check_name=independent-review&per_page=100"
    if ($LASTEXITCODE -eq 0) {
      $runs = @((($j -join "`n") | ConvertFrom-Json).check_runs | Sort-Object id)
      if ($runs.Count -gt 0) {
        $last = $runs[-1]
        if ($last.status -eq 'completed') {
          if ($last.conclusion -eq 'success') { return 'success' }
          return "failure:$($last.conclusion)"
        }
      }
    }
    Start-Sleep -Seconds 10
  } while ((Get-Date) -lt $deadline)
  return 'timeout'
}
function Update-LocalMain {
  Sync-Origin @()
  $current = (Invoke-Git @('rev-parse', '--abbrev-ref', 'HEAD')).Out.Trim()
  if ($current -eq 'main') {
    $r = Invoke-Git @('merge', '--ff-only', 'origin/main')
  } else {
    $r = Invoke-Git @('fetch', '--quiet', 'origin', 'main:main')
  }
  if ($r.Code -eq 0) { Log '  local main fast-forwarded' 'DarkGray' } else { Log "  local main NOT fast-forwarded (checkout is on '$current'): $($r.Out)" 'Yellow' }
}

# -- Spot-checks (spec 34 sec. 5.2) -----------------------------------------------------------
function Invoke-SampleReview {
  $samples = @(Invoke-Api '/api/approvals/samples')
  if ($samples.Count -eq 0) { Log 'No sampled agent decisions are waiting for your spot-check.' 'DarkGray'; return }
  Log "`n$($samples.Count) sampled agent decision(s) wait for your spot-check. Unreviewed for 14 days, they suspend the delegation." 'Yellow'
  foreach ($s in $samples) {
    Write-Host "`n$($s.subject_ref)  tier $($s.tier)  $($s.verdict) by $($s.approver) ($($s.family)) at $($s.decided_at)" -ForegroundColor Cyan
    Write-Host $s.rationale
    $a = Read-Host 'Agree with this decision? a = agree, d = disagree, anything else = later'
    if ($a -notin @('a', 'd')) { Log "  sample $($s.decision_id): left for later"; continue }
    $note = ''
    if ($a -eq 'd') {
      do { $note = Read-Host 'Why you disagree (required; the approver is measured on it)' } while (-not $note.Trim())
    }
    try {
      $r = Invoke-Api "/api/approvals/samples/$($s.decision_id)" 'Post' @{ verdict = $(if ($a -eq 'a') { 'agree' } else { 'disagree' }); note = $note }
      Log ("  sample {0}: {1}; agreement {2}/{3}{4}" -f $s.decision_id, $r.verdict, $r.agreement.agreed, $r.agreement.reviewed, $(if ($r.delegation_suspended) { ' - DELEGATION SUSPENDED' } else { '' })) $(if ($r.delegation_suspended) { 'Red' } else { 'Green' })
    } catch [ApiError] { Log "  sample $($s.decision_id): MyKronos refused: $($_.Exception.Message)" 'Red' }
  }
}

if ($SamplesOnly) { Invoke-SampleReview; return }

# -- The queue -------------------------------------------------------------------------------
if (-not $All -and -not $Pr) { throw 'Name the PRs in order (approval-queue.ps1 770 773 774), or pass -All.' }
$open = gh pr list --repo $Repo --state open --limit 100 --json $PrFields
if ($LASTEXITCODE -ne 0) { throw 'gh pr list failed' }
$plan = Invoke-Helper 'order' @{ prs = @(($open -join "`n") | ConvertFrom-Json); numbers = $(if ($All) { @() } else { @($Pr) }) }
$results = [ordered]@{}
foreach ($s in @($plan.skipped)) { $results["#$($s.number)"] = "skipped: $($s.reason)"; Log "#$($s.number): skipped - $($s.reason)" 'Yellow' }
$remaining = [System.Collections.Generic.List[int]]::new()
foreach ($n in @($plan.queue)) { $remaining.Add([int] $n) }
if ($remaining.Count -eq 0) { Log 'Nothing to do.'; return }
Log ("Queue: {0}" -f (($remaining | ForEach-Object { "#$_" }) -join ' ')) 'Cyan'
if ($MaxRounds -le 0) { $MaxRounds = $remaining.Count + 1 }

function Drop([int] $n, [string] $why, [string] $color = 'Red') {
  $script:results["#$n"] = $why
  [void] $script:remaining.Remove($n)
  Log "#${n}: $why" $color
}

$round = 0
while ($remaining.Count -gt 0 -and $round -lt $MaxRounds) {
  $round++
  Log "`n=== Round ${round}: $(($remaining | ForEach-Object { "#$_" }) -join ' ') ===" 'Cyan'

  # 1. Bring each PR up to date - only where it actually conflicts.
  $prs = @{}
  foreach ($n in @($remaining)) {
    $p = Get-Pr $n
    if (-not $p) { Drop $n 'skipped: gh could not read it'; continue }
    if ($p.state -ne 'OPEN') { Drop $n "skipped: it is $($p.state.ToLower())" 'Yellow'; continue }
    $why = (Invoke-Helper 'order' @{ prs = @($p); numbers = @($n) }).skipped
    if (@($why).Count -gt 0) { Drop $n "skipped: $(@($why)[0].reason)" 'Yellow'; continue }
    $prs[$n] = $p
  }
  if ($prs.Count -eq 0) { break }
  Sync-Origin @($prs.Values | ForEach-Object { $_.headRefName })
  foreach ($n in @($remaining)) {
    $p = $prs[$n]
    if (Test-Conflict $p.headRefName) {
      if ($DryRun) { Log "  #${n}: conflicts with main - would merge main in (dry run)" 'Yellow'; continue }
      $err = Update-Branch $p
      if ($err) { Drop $n "skipped: $err"; continue }
      $prs[$n] = Get-Pr $n
    } else {
      Log "  #${n}: merges cleanly into main at $($p.headRefOid.Substring(0, 8))" 'DarkGray'
    }
  }

  # 1b. Of those, which can merge this round once the ones before them have.
  $active = @($remaining)
  if (-not $DryRun) {
    Sync-Origin @($prs.Values | ForEach-Object { $_.headRefName })
    $deferred = Get-Deferred @($remaining) $prs
    foreach ($n in @($remaining)) {
      if ($deferred.ContainsKey($n)) { Log "  #${n}: would conflict once the PRs before it merge; it is decided next round, after main is merged into it" 'DarkGray' }
    }
    $active = @($remaining | Where-Object { -not $deferred.ContainsKey($_) })
  }

  # 2. Wait for the platform's request on each current head.
  $reqs = @{}
  $deadline = (Get-Date).AddMinutes($RequestTimeoutMinutes)
  $announced = $false
  while ($true) {
    $pending = Get-ApprovalRequest 'pending'
    $approved = Get-ApprovalRequest 'approved'
    foreach ($n in $active) {
      if ($reqs.ContainsKey($n)) { continue }
      $ref = "$Repo#$n@$($prs[$n].headRefOid)"
      $a = $approved | Where-Object { $_.subject_ref -eq $ref } | Select-Object -First 1
      if ($a) { $reqs[$n] = $a; continue }
      $mine = @($pending | Where-Object { $_.subject_ref -eq $ref })
      $other = $mine | Where-Object { $_.requested_by -ne $AdminIdentity } | Select-Object -First 1
      if ($other) { $reqs[$n] = $other } elseif ($mine.Count -gt 0) { $reqs[$n] = $mine[0] }
    }
    $missing = @($active | Where-Object { -not $reqs.ContainsKey($_) })
    if ($missing.Count -eq 0 -or $DryRun) { break }
    if ((Get-Date) -ge $deadline) {
      foreach ($n in $missing) { Drop $n "skipped: no approval request for head $($prs[$n].headRefOid.Substring(0, 8)) after $RequestTimeoutMinutes min. job:pull-request-requests opens one ~10 min after it first sees a head." }
      break
    }
    if (-not $announced) { Log ("  waiting for the platform's request on {0} (polling every {1}s)" -f (($missing | ForEach-Object { "#$_" }) -join ' '), $PollSeconds) 'DarkGray'; $announced = $true }
    Start-Sleep -Seconds $PollSeconds
  }

  # 3. Decide. Routing needs the reviewer's mode and the delegations.
  $mode = 'unknown'
  try { $mode = (Invoke-Api '/api/approvals/shadow-reviews').mode } catch [ApiError] { Log "  could not read the reviewer mode: $($_.Exception.Message)" 'Yellow' }
  $delegations = @()
  try { $delegations = @(Invoke-Api '/api/approvals/delegations') } catch [ApiError] { Log "  could not read delegations: $($_.Exception.Message)" 'Yellow' }

  $batch = [System.Collections.Generic.List[object]]::new()
  foreach ($n in $active) {
    if (-not $reqs.ContainsKey($n)) {
      if ($DryRun) { Log "  #${n}: no request yet for head $($prs[$n].headRefOid.Substring(0, 8))" 'Yellow' }
      continue
    }
    $req = $reqs[$n]
    if ($req.state -eq 'approved') { Log "  #${n}: already approved ($($req.id))" 'Green'; continue }
    $r = Invoke-Helper 'route' @{ tier = $req.tier; reviewer_mode = $mode; delegations = $delegations }
    Log "  #${n}: request $($req.id), tier $($req.tier), opened by $($req.requested_by) -> $($r.route) ($($r.reason))"
    if ($DryRun) { continue }
    $agentNote = $null
    if ($r.route -eq 'agent') {
      try {
        $o = Invoke-Api "/api/approvals/$($req.id)/independent-review" 'Post'
        Log ("  #{0}: reviewer {1} ({2}) said {3}; request is {4}" -f $n, $o.reviewer, $o.model, $o.verdict, $o.state) $(if ($o.state -eq 'approved') { 'Green' } else { 'Yellow' })
        Add-Content -LiteralPath $script:LogFile -Value "      rationale: $($o.rationale)" -Encoding utf8
        if ($o.state -eq 'approved') { $reqs[$n] = Invoke-Api "/api/approvals/$($req.id)"; continue }
        if ($o.state -eq 'rejected') { Drop $n "rejected by the reviewer: $($o.rationale)"; continue }
        $agentNote = "The reviewer answered '$($o.verdict)': $($o.rationale)"
      } catch [ApiError] {
        $agentNote = "The reviewer did not decide ($($_.Exception.Status)): $($_.Exception.Message)"
        Log "  #${n}: $agentNote - falling back to you" 'Yellow'
      }
    }
    if ($req.requested_by -eq $AdminIdentity) {
      Drop $n "skipped: the only pending request for this head was opened under YOUR identity, so you cannot also approve it. A new head commit lets MyKronos open one you can approve."
      continue
    }
    $batch.Add([pscustomobject]@{ Number = $n; Request = $req; AgentNote = $agentNote })
  }
  if ($DryRun) { Log "`nDry run: nothing was pushed, decided or merged." 'Cyan'; break }

  if ($batch.Count -gt 0) {
    Log "`n--- $($batch.Count) request(s) for you to decide ---" 'Yellow'
    foreach ($b in $batch) {
      $ev = Invoke-Api "/api/approvals/$($b.Request.id)/evidence"
      $b | Add-Member -NotePropertyName Evidence -NotePropertyValue $ev
      $b | Add-Member -NotePropertyName Summary -NotePropertyValue (Invoke-Helper 'summary' @{ request = $b.Request; evidence = $ev.evidence })
      Write-Host ''
      $b.Summary.lines | ForEach-Object { Write-Host $_ }
      if ($ev.requester_statement) { Write-Host "  requester's claim (not evidence): $($ev.requester_statement)" -ForegroundColor DarkGray }
      if ($b.AgentNote) { Write-Host "  $($b.AgentNote)" -ForegroundColor DarkYellow }
    }
    Write-Host ''
    foreach ($b in $batch) {
      $n = $b.Number
      do {
        $ans = Read-Host "Approve #$n ($($b.Request.tier))? y = approve, n = not now, d = show the diff"
        if ($ans -eq 'd') {
          foreach ($f in @($b.Evidence.evidence.files)) { Write-Host "`n=== $($f.path) [$($f.class)]" -ForegroundColor Cyan; Write-Host $f.patch }
        }
      } while ($ans -eq 'd')
      if ($ans -ne 'y') { Drop $n 'not approved by you; the request stays open' 'Yellow'; continue }
      Write-Host "Default rationale: $($b.Summary.default_rationale)" -ForegroundColor DarkGray
      do {
        $rat = Read-Host 'Rationale (Enter accepts the default above; or type what you checked, 20+ characters)'
        if (-not $rat.Trim()) { $rat = $b.Summary.default_rationale }
        if ($rat.Trim().Length -lt 20) { Write-Host 'Too short: MyKronos needs at least 20 characters.' -ForegroundColor Yellow }
      } while ($rat.Trim().Length -lt 20)
      try {
        $dec = Invoke-Api "/api/approvals/$($b.Request.id)/decisions" 'Post' @{ verdict = 'approve'; rationale = $rat; evidence_digest = $b.Evidence.evidence_digest }
        Add-Content -LiteralPath $script:LogFile -Value "      rationale: $rat" -Encoding utf8
        if ($dec.state -ne 'approved') { Drop $n "your approval was recorded but the request is '$($dec.state)', not approved" 'Yellow'; continue }
        Log "  #${n}: approved by you" 'Green'
        $reqs[$n] = $dec
      } catch [ApiError] { Drop $n "MyKronos REFUSED the approval: $($_.Exception.Message)" }
    }
  }

  # 4. Merge, in queue order, whatever is approved and still clean.
  foreach ($n in $active) {
    if (-not $reqs.ContainsKey($n) -or $reqs[$n].state -ne 'approved') { continue }
    $p = Get-Pr $n
    if (-not $p -or $p.state -ne 'OPEN') { Drop $n "skipped: it is no longer open" 'Yellow'; continue }
    $sha = $p.headRefOid
    if ("$Repo#$n@$sha" -ne $reqs[$n].subject_ref) { Log "  #${n}: head moved since its approval; next round" 'Yellow'; continue }
    Sync-Origin @($p.headRefName)
    if (Test-Conflict $p.headRefName) { Log "  #${n}: the merge before it made it conflict; main is merged into it next round" 'Yellow'; continue }
    $c = Wait-IndependentReview $sha
    if ($c -ne 'success') { Drop $n "skipped: independent-review on $($sha.Substring(0, 8)) is $c"; continue }
    $out = gh pr merge $n --repo $Repo --squash --match-head-commit $sha 2>&1
    if ($LASTEXITCODE -ne 0) { Drop $n "skipped: gh pr merge failed: $(($out | ForEach-Object { "$_" }) -join ' ')"; continue }
    $results["#$n"] = "merged at $($sha.Substring(0, 8))"
    [void] $remaining.Remove($n)
    Log "  #${n}: squash-merged" 'Green'
    Update-LocalMain
  }
}
foreach ($n in @($remaining)) { $results["#$n"] = "not finished after $MaxRounds round(s)" }

Log "`n=== Result ===" 'Cyan'
foreach ($k in $results.Keys) { Log ("  {0,-6} {1}" -f $k, $results[$k]) $(if ($results[$k] -like 'merged*') { 'Green' } else { 'Yellow' }) }
if (-not $DryRun -and -not $NoSamples) { Invoke-SampleReview }
Log "Log: $script:LogFile" 'DarkGray'
