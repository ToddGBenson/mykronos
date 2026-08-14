<#
.SYNOPSIS
  Unseal Vault after a restart.

.DESCRIPTION
  Vault uses the file storage backend rather than `-dev` mode, so its data
  survives a restart — and so it comes back SEALED. Nothing can read a secret
  until it is unsealed, which means Concourse pipelines fail to resolve
  ((vars)) after every reboot of this host until you run this.

  That is the deliberate cost of persistence. The alternative, dev mode, keeps
  everything in memory and loses it on restart, which is fine for a demo and
  useless as somewhere to keep a secret you would be upset to regenerate.

  Failure mode worth recognising: a sealed Vault does NOT make Concourse jobs
  hang. They fail with a credential-resolution error naming the var. If you see
  that after a reboot, this is the fix — not the pipeline.

.EXAMPLE
  .\vault-unseal.ps1
#>
[CmdletBinding()]
param(
  [string] $InitFile = (Join-Path $PSScriptRoot 'vault/init.json'),
  [string] $Container = 'mykronos-vault'
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $InitFile)) {
  Write-Error @"
No init file at $InitFile.

Either Vault has never been initialised on this host, or the unseal material was
lost. If it is lost, the data is unrecoverable — there is no recovery path by
design, which is why the bootstrap tells you to put a copy in a password manager.
"@
}

$init = Get-Content $InitFile -Raw | ConvertFrom-Json

# Is it already open? Unsealing an unsealed Vault is harmless, but saying so is
# more useful than silently doing nothing.
$status = docker exec $Container sh -c 'VAULT_ADDR=http://127.0.0.1:8200 vault status -format=json' 2>$null
if ($LASTEXITCODE -eq 0) {
  $s = $status | ConvertFrom-Json
  if (-not $s.sealed) {
    Write-Host "Vault is already unsealed." -ForegroundColor Green
    exit 0
  }
}

foreach ($key in $init.unseal_keys_b64) {
  $out = docker exec -e VAULT_ADDR=http://127.0.0.1:8200 $Container `
           vault operator unseal $key 2>&1
  if ($LASTEXITCODE -ne 0) { Write-Error "unseal failed: $out" }
}

$final = docker exec $Container sh -c 'VAULT_ADDR=http://127.0.0.1:8200 vault status -format=json' | ConvertFrom-Json
if ($final.sealed) {
  Write-Error "Vault is still sealed after applying every key in $InitFile."
}

Write-Host "Vault unsealed." -ForegroundColor Green
Write-Host "Concourse will resolve ((vars)) again on the next build; jobs that" -ForegroundColor DarkGray
Write-Host "failed while it was sealed need re-triggering, they do not retry." -ForegroundColor DarkGray
