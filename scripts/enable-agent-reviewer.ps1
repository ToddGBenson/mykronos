#Requires -Version 7
<#
.SYNOPSIS
  Operator-run: let the platform-started reviewer approve production and
  routine pull requests (spec 34 sec. 5, D-149). Never governance.

.DESCRIPTION
  Three things have to be true before an agent's approval counts, and this
  script does each one, in order, and prints what it did:

    1. The reviewer can run. MYKRONOS_REVIEWER_API_KEY must be set in
       backend\.env AND passed by deploy\mykronos\docker-compose.yml (D-149
       added it there; before that, nothing in .env reached the container).
       Without a key, the script stops here: a live reviewer with no key
       answers 503 and every request falls back to you anyway.

    2. A delegation exists. Proposing one is itself a `delegation_grant`
       request (POST /api/approvals/delegations): duty pull_request_merge,
       tiers production + routine, the reviewer's model family, a sampling
       rate, a 30-day expiry. A person approves it after its one-hour
       cooling-off - under single_operator that person may be you, flagged
       same_person. So the FIRST run proposes and stops; run it again an hour
       later and it shows you the proposal and asks you to approve it.

    3. The reviewer is live. MYKRONOS_REVIEWER_MODE=live in backend\.env, and
       the backend container recreated on the image it is already running.
       Only after the delegation is active: switching first would stop the
       shadow reviews with nothing in their place. The recreate passes what
       deploy.ps1 passes besides backend\.env - the GitHub App key path and
       the Slack token and channel from Vault - and stops before touching
       anything if it cannot resolve them.

  How fresh-context independence is proven: the reviewer's credential is
  minted by the platform with `platform_started` set, a flag no API-minted
  credential can carry, and `fresh_context` refuses any agent approver
  without it. The reviewer sees the policy's instructions and the frozen
  evidence bundle only. Nothing here can mint that credential; only the
  platform can.

  Sampling: a share of the reviewer's approvals (-Sampling, default 0.2) is
  queued for your after-the-fact spot-check. Review them with
  `approval-queue.ps1 -SamplesOnly` (the queue also offers them at the end of
  every run). Agreement below 90% of the last 20, or a sample unreviewed for
  14 days, suspends the delegation until you grant it again.

  Revoke at any time: POST /api/approvals/delegations/{id}/revoke.

.EXAMPLE
  .\enable-agent-reviewer.ps1             # run once to propose, again after an hour to approve and go live
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'Api', Justification = 'Used by Invoke-Api, which reads it from script scope; the rule does not follow a script parameter into a nested function.')]
[CmdletBinding()]
param(
  [string] $RepoPath = 'C:\Users\tgb_\Documents\Projects\mykronos',
  [string] $Api = 'http://127.0.0.1:8100',
  [ValidateRange(0.0, 1.0)] [double] $Sampling = 0.2,
  [ValidateRange(1, 90)] [int] $Days = 30,
  [string] $Family = ''
)
$ErrorActionPreference = 'Stop'
$Duty = 'pull_request_merge'
$Tiers = @('production', 'routine')          # sorted, as the engine stores them
$Subject = "delegation:${Duty}:$($Tiers -join ',')"

$envFile = Join-Path $RepoPath 'backend\.env'
$compose = Join-Path $RepoPath 'deploy\mykronos\docker-compose.yml'
function Read-EnvValue([string] $name) {
  $l = Select-String -LiteralPath $envFile -Pattern "^$name=" | Select-Object -First 1
  if (-not $l) { return '' }
  return $l.Line.Substring($name.Length + 1).Trim().Trim('"')
}
$h = @{
  Authorization = "Bearer $(Read-EnvValue 'MYKRONOS_ADMIN_TOKEN')"
  'X-Hub-Token' = (Read-EnvValue 'MYKRONOS_GATE_TOKEN')
}
function Invoke-Api([string] $Path, [string] $Method = 'Get', $Body = $null) {
  $p = @{ Method = $Method; Uri = "$Api$Path"; Headers = $h }
  if ($null -ne $Body) { $p.ContentType = 'application/json'; $p.Body = (ConvertTo-Json -InputObject $Body -Depth 8) }
  try { $r = Invoke-RestMethod @p; return $r }
  catch {
    $msg = try { ($_.ErrorDetails.Message | ConvertFrom-Json).detail } catch { $_.ErrorDetails.Message }
    if (-not $msg) { $msg = $_.Exception.Message }
    throw "MyKronos refused $Method ${Path}: $msg"
  }
}
$did = [System.Collections.Generic.List[string]]::new()
function Done([string] $what) { $did.Add($what); Write-Host "  $what" -ForegroundColor Green }
function Stop-Here {
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Script-internal: prints a reason and what was done, then exits 2. It changes no state; the verb names the script stopping.')]
  param([string] $why)
  Write-Host "`n$why" -ForegroundColor Yellow
  if ($did.Count) { Write-Host "`nDone this run:" -ForegroundColor Cyan; $did | ForEach-Object { Write-Host "  - $_" } }
  exit 2
}

# The family the delegation trusts is the model the reviewer runs: the
# platform records `reviewer_model` as the reviewer's family (config.py).
if (-not $Family) { $Family = Read-EnvValue 'MYKRONOS_REVIEWER_MODEL' }
if (-not $Family) { $Family = 'claude-opus-5-5' }      # config.py's default
Write-Host "Delegating $Duty ($($Tiers -join ', ')) to the platform-started reviewer, family $Family" -ForegroundColor Cyan

# -- 1. Can the reviewer run? -------------------------------------------------------------
$composeText = Get-Content -LiteralPath $compose -Raw
foreach ($name in 'MYKRONOS_REVIEWER_API_KEY', 'MYKRONOS_REVIEWER_MODE', 'MYKRONOS_REVIEWER_MODEL') {
  if ($composeText -notmatch "(?m)^\s+${name}:") {
    Stop-Here "$compose does not pass $name to the container, so setting it in backend\.env does nothing. Merge the D-149 pull request and fast-forward $RepoPath first."
  }
}
if ((Read-EnvValue 'MYKRONOS_REVIEWER_API_KEY').Length -eq 0) {
  Stop-Here @"
The reviewer has no key. Add this line to $envFile (an Anthropic API key; the value is never printed):

  MYKRONOS_REVIEWER_API_KEY=<key>

ANTHROPIC_API_KEY in backend\.env is NOT enough: compose does not pass it to the backend container.
Then run this script again. Nothing was changed.
"@
}
Write-Host '  reviewer key: present in backend\.env (not shown)' -ForegroundColor DarkGray

# The track record the trust rests on: shadow verdicts beside yours.
$shadow = Invoke-Api '/api/approvals/shadow-reviews'
# Only the tiers this script delegates (TheHub #60760): on governance the
# reviewer rejects by rule so a person decides, which says nothing about them.
$agree = 0; $disagree = 0; $undecided = 0
foreach ($t in $Tiers) {
  $row = if ($shadow.by_tier) { $shadow.by_tier."${Duty}:$t" } else { $null }
  if ($row) { $agree += $row.agree; $disagree += $row.disagree; $undecided += $row.undecided }
}
$judged = $agree + $disagree
Write-Host ("  reviewer mode now: {0}; shadow record on {1} {2}: {3} agree, {4} disagree, {5} undecided{6}" -f $shadow.mode, $Duty, ($Tiers -join '+'), $agree, $disagree, $undecided, $(if ($judged) { " (agreement $([math]::Round(100 * $agree / $judged))%)" } else { ' - no judged reviews on these tiers yet' })) -ForegroundColor DarkGray

# -- 2. The delegation ----------------------------------------------------------------------
$active = @(@(Invoke-Api '/api/approvals/delegations') | Where-Object {
  $d = $_
  $d.active -and $d.duty -eq $Duty -and ($Family -in @($d.approver_families)) -and
  (@($Tiers | Where-Object { $_ -notin @($d.tiers) }).Count -eq 0)
})
if ($active.Count -gt 0) {
  $d = $active[0]
  Write-Host "  delegation $($d.id) is already active until $($d.expires_at) (sampling $($d.sampling))" -ForegroundColor DarkGray
} else {
  $pending = @(@(Invoke-Api '/api/approvals?state=pending&duty=delegation_grant') | Where-Object { $_.subject_ref -eq $Subject })
  if ($pending.Count -eq 0) {
    $expires = (Get-Date).ToUniversalTime().AddDays($Days).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $req = Invoke-Api -Path '/api/approvals/delegations' -Method 'Post' -Body @{
      duty = $Duty; tiers = $Tiers; approver_families = @($Family); expires_at = $expires; sampling = $Sampling
      statement = "Operator decision 2026-10-11 (D-149): a platform-started, fresh-context reviewer approves production and routine pull requests; governance stays with a person. $([int](100 * $Sampling))% of its approvals are sampled for spot-check."
    }
    Done "proposed delegation request $($req.id): $Duty, tiers $($Tiers -join '+'), family $Family, sampling $Sampling, expires $expires"
    $ready = ([datetime] $req.created_at).AddHours(1)
    Stop-Here "Its one-hour cooling-off ends at $($ready.ToString('u')) (UTC). Run this script again after that to approve it and switch the reviewer to live."
  }
  $req = $pending[0]
  $ready = ([datetime] $req.created_at).AddHours(1)
  if ((Get-Date).ToUniversalTime() -lt $ready) {
    Stop-Here "Delegation request $($req.id) is in its cooling-off until $($ready.ToString('u')) (UTC). Run this again after that."
  }
  $ev = Invoke-Api "/api/approvals/$($req.id)/evidence"
  $p = $ev.evidence.proposal
  # Approve only what this script proposes: never a wider grant someone else asked for.
  if ($p.duty -ne $Duty -or (@($p.tiers) -join ',') -ne ($Tiers -join ',') -or 'governance' -in @($p.tiers)) {
    Stop-Here "Request $($req.id) proposes duty '$($p.duty)' tiers '$(@($p.tiers) -join ',')', not what this script grants. Decide it yourself."
  }
  Write-Host "`nProposal $($req.id), requested by $($req.requested_by):" -ForegroundColor Cyan
  Write-Host ("  duty {0}; tiers {1}; families {2}; sampling {3}; expires {4}" -f $p.duty, (@($p.tiers) -join ', '), (@($p.approver_families) -join ', '), $p.sampling, $p.expires_at)
  $answer = Read-Host 'Grant it? Type y to approve, anything else to stop'
  if ($answer -ne 'y') { Stop-Here 'Not approved. The request stays open.' }
  $rationale = "Granting $Duty for production and routine only, never governance: the reviewer is platform-started with fresh context, and $($p.sampling) of its approvals come back to me for spot-check; expires $($p.expires_at)."
  $dec = Invoke-Api -Path "/api/approvals/$($req.id)/decisions" -Method 'Post' -Body @{ verdict = 'approve'; rationale = $rationale; evidence_digest = $ev.evidence_digest }
  if ($dec.state -ne 'approved') { Stop-Here "Your decision was recorded but request $($req.id) is '$($dec.state)'." }
  Done "approved delegation request $($req.id) (same_person=$((@($dec.decisions) | Select-Object -Last 1).same_person)); the delegation is active"
}

# -- 3. Live ----------------------------------------------------------------------------------
if ($shadow.mode -eq 'live') {
  Write-Host '  reviewer is already live' -ForegroundColor DarkGray
} else {
  # What deploy.ps1 hands compose besides --env-file, resolved before the mode
  # is written so a refusal leaves backend\.env as it was. Without the App key
  # path compose refuses to start the backend; without the two Slack values it
  # starts and silently stops notifying, because they come from Vault, not
  # from backend\.env. Values are never printed.
  $passed = [ordered]@{}
  $keyPath = Read-EnvValue 'MYKRONOS_GITHUB_APP_PRIVATE_KEY_PATH'
  if (-not ($keyPath -and (Test-Path -LiteralPath $keyPath))) {
    Stop-Here "MYKRONOS_GITHUB_APP_PRIVATE_KEY_PATH in $envFile does not name a file, and compose will not start the backend without it. Nothing was changed."
  }
  $passed['MYKRONOS_GITHUB_APP_KEY_HOST_PATH'] = (Resolve-Path -LiteralPath $keyPath).Path
  $slackFromVault = [ordered]@{
    'MYKRONOS_SLACK_BOT_TOKEN' = 'concourse/main/slack-bot-token'
    'MYKRONOS_SLACK_CHANNEL'   = 'concourse/main/slack-alert-channel'
  }
  $concourseEnv = Join-Path $RepoPath 'deploy\concourse\.env'
  $vaultLine = if (Test-Path -LiteralPath $concourseEnv) { Select-String -LiteralPath $concourseEnv -Pattern '^CONCOURSE_VAULT_TOKEN=' | Select-Object -First 1 }
  $vaultToken = if ($vaultLine) { $vaultLine.Line.Substring('CONCOURSE_VAULT_TOKEN='.Length).Trim().Trim('"') } else { '' }
  foreach ($name in $slackFromVault.Keys) {
    $value = $null
    if ($vaultToken) {
      # `-e VAULT_TOKEN` with no value forwards it from this process's
      # environment, so the token is never in docker's command line.
      $prior = $env:VAULT_TOKEN
      $env:VAULT_TOKEN = $vaultToken
      try {
        $value = docker exec -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN `
          mykronos-vault vault read -field=value $slackFromVault[$name] 2>$null
      } finally { $env:VAULT_TOKEN = $prior }
    }
    if ($LASTEXITCODE -ne 0 -or -not $value) {
      Stop-Here "Could not read $($slackFromVault[$name]) from Vault, and recreating the backend without it would stop Slack notifications. Is Vault sealed? deploy\concourse\vault-unseal.ps1. Nothing was changed."
    }
    $passed[$name] = ($value -join '').Trim()
    $value = $null
  }
  Write-Host '  App key path and Slack token/channel resolved for compose (not shown)' -ForegroundColor DarkGray

  $text = [IO.File]::ReadAllText($envFile)
  $nl = if ($text -match "`r`n") { "`r`n" } else { "`n" }
  if ($text -match '(?m)^MYKRONOS_REVIEWER_MODE=.*$') {
    $text = [regex]::Replace($text, '(?m)^MYKRONOS_REVIEWER_MODE=.*?(?=\r?$)', 'MYKRONOS_REVIEWER_MODE=live')
  } else {
    if (-not $text.EndsWith("`n")) { $text += $nl }
    $text += "# D-149: the platform-started reviewer's verdicts count where a delegation allows.$nl" + "MYKRONOS_REVIEWER_MODE=live$nl"
  }
  [IO.File]::WriteAllText($envFile, $text, [Text.UTF8Encoding]::new($false))
  Done 'set MYKRONOS_REVIEWER_MODE=live in backend\.env'

  # Recreate the backend on the image it already runs: the compose default
  # (:latest) is retired, and a deploy is not what this script is for.
  $image = (docker inspect -f '{{.Config.Image}}' mykronos-backend).Trim()
  if ($LASTEXITCODE -ne 0 -or -not $image) { Stop-Here 'Could not read the running backend image. Redeploy with deploy\mykronos\deploy.ps1 to pick up the new mode.' }
  $passed['MYKRONOS_IMAGE_BACKEND'] = $image
  # Through this process's environment, which compose prefers over
  # --env-file, and out of it as soon as compose has read them.
  foreach ($name in $passed.Keys) { Set-Item -Path "env:$name" -Value $passed[$name] }
  Push-Location (Join-Path $RepoPath 'deploy\mykronos')
  try {
    docker compose --env-file $envFile up -d --no-deps backend
    if ($LASTEXITCODE -ne 0) { throw 'docker compose up failed' }
  } finally {
    Pop-Location
    foreach ($name in $passed.Keys) { Remove-Item -Path "env:$name" -ErrorAction SilentlyContinue }
    $passed.Clear()
  }
  Done "recreated mykronos-backend on $image"

  $deadline = (Get-Date).AddMinutes(3)
  do {
    Start-Sleep -Seconds 5
    $health = (docker inspect -f '{{.State.Health.Status}}' mykronos-backend 2>$null)
  } while ($health -ne 'healthy' -and (Get-Date) -lt $deadline)
  $mode = (Invoke-Api '/api/approvals/shadow-reviews').mode
  if ($mode -ne 'live') { Stop-Here "The backend reports reviewer mode '$mode', not live. Check that the container was recreated (not just restarted)." }
  Done 'verified: the backend reports reviewer mode live'
  # Names only: the same three things a raw compose recreate loses.
  $kept = docker exec mykronos-backend sh -c 'for k in MYKRONOS_SLACK_BOT_TOKEN MYKRONOS_SLACK_CHANNEL; do [ -n "$(printenv $k)" ] || echo "$k"; done; [ -s /secrets/github-app.pem ] || echo github-app.pem'
  if ($kept) { Stop-Here "The backend is live but came up without: $($kept -join ', '). Redeploy with deploy\mykronos\deploy.ps1." }
  Done 'verified: the GitHub App key and the Slack token and channel reached the backend'
}

Write-Host "`nThe reviewer now approves production and routine PRs the delegation covers; governance still comes to you." -ForegroundColor Cyan
Write-Host 'Run approval-queue.ps1 as before: it asks the platform to start the reviewer, and batches only what is left for you.'
Write-Host "Spot-check its sampled decisions with: approval-queue.ps1 -SamplesOnly  (unreviewed for 14 days, they suspend the delegation)"
if ($did.Count) { Write-Host "`nDone this run:" -ForegroundColor Cyan; $did | ForEach-Object { Write-Host "  - $_" } }
