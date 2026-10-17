<#
.SYNOPSIS
  Initialise Vault on a new host and write CONCOURSE_VAULT_TOKEN into .env.
  Safe to re-run: every step checks before it acts.

.DESCRIPTION
  #60753. docker-compose.yml refuses to start Concourse without
  CONCOURSE_VAULT_TOKEN, and its error said "see vault-init" - a script that
  did not exist. setup.ps1 never wrote the token and nothing initialised Vault,
  so the first `up` on a new host failed and sent the operator nowhere. The
  bootstrap VAULT.md describes had been done by hand, once, on this host.

  This is that bootstrap, written down. In order:

    1. Start the vault service if it is not running. Compose interpolates the
       WHOLE file even for `up -d vault`, so the `:?` guard on the very token
       this script exists to mint would refuse the call. A placeholder goes in
       this process's environment for that one command; it is never written
       to .env, and the concourse service is not created by it.
    2. Initialise it - one key share, threshold one (VAULT.md says why) - and
       write vault/init.json. Never over an existing file: that file holds the
       only unseal key, and overwriting it makes the store unrecoverable.
    3. Unseal, through vault-unseal.ps1, which stays the one implementation.
    4. Mount concourse/ as KV v1 and personal/ as KV v2.
    5. Write the `concourse` policy: read and list on concourse/*, nothing else.
    6. Mint a token with only that policy, prove it cannot read personal/, and
       write it to .env as CONCOURSE_VAULT_TOKEN. A token already in .env that
       Vault still accepts is kept.

  No secret is printed or passed as a command-line argument. Tokens reach
  `docker exec` by name (`-e VAULT_TOKEN`) from this process's environment, as
  vault-secret.ps1 and Import-EnvSecretsToVault.ps1 do.

.PARAMETER Container
  The Vault container. Only the default is ever started through compose; any
  other name must already be running, so a test against a scratch container
  cannot start - or recreate - the real one.

.EXAMPLE
  .\vault-init.ps1          # setup.ps1 runs this before it starts the stack

.NOTES
  ASCII only - see setup.ps1. Windows PowerShell 5.1 reads a BOM-less file as
  CP1252, so a UTF-8 dash becomes three characters.

  THE TOKEN'S LIFETIME. A token's TTL is capped by the token store's
  max-lease-ttl, 32 days by default, and a static client token that lapses
  fails every credential lookup with a 403 that reads like a policy problem.
  So the store's cap is raised to ten years and the token minted to it. That
  matches what VAULT.md already accepts for a single-operator host - the root
  token sits on this disk with no TTL at all. Revoke and re-run to rotate:
    vault token revoke <token>; remove the line from .env; .\vault-init.ps1
#>
[CmdletBinding()]
param(
  [string] $EnvFile = (Join-Path $PSScriptRoot '.env'),
  [string] $InitFile = (Join-Path $PSScriptRoot 'vault/init.json'),
  [string] $Container = 'mykronos-vault'
)

$ErrorActionPreference = 'Stop'

$TokenKey = 'CONCOURSE_VAULT_TOKEN'
$TokenTtl = '87600h'
$Policy = @'
# Concourse resolves ((vars)) from here. Read and list only: it cannot write,
# and it cannot see personal/ (VAULT.md).
path "concourse/*" {
  capabilities = ["read", "list"]
}
'@

function Invoke-Vault {
  <#
    Run `vault` inside the container. Output comes back split into stdout and
    stderr, and nothing is ever echoed from here - several of these commands
    print key material, so the caller decides what is safe to show.

    The token, when given, goes on THIS process's environment and is forwarded
    by name. `-e VAULT_TOKEN=<value>` would put it in docker.exe's argv.

    ErrorActionPreference is lowered for the call because, under 'Stop', any
    native stderr line becomes a terminating NativeCommandError (see
    vault-unseal.ps1's Invoke-Docker, where that was found by running it).
  #>
  param(
    [string[]] $Arguments,
    [string] $Token,
    [string] $InputText
  )

  $priorToken = $env:VAULT_TOKEN
  $previous = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    $dockerArgs = @('exec')
    if ($InputText) { $dockerArgs += '-i' }
    $dockerArgs += @('-e', 'VAULT_ADDR=http://127.0.0.1:8200')
    if ($Token) {
      $env:VAULT_TOKEN = $Token
      $dockerArgs += @('-e', 'VAULT_TOKEN')
    }
    $dockerArgs += $Container
    $dockerArgs += 'vault'
    $dockerArgs += $Arguments

    if ($InputText) {
      $output = $InputText | & docker @dockerArgs 2>&1
    } else {
      $output = & docker @dockerArgs 2>&1
    }
    $code = $LASTEXITCODE
  } finally {
    $env:VAULT_TOKEN = $priorToken
    $ErrorActionPreference = $previous
  }

  $stdout = @($output | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] })
  $stderr = @($output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } |
              ForEach-Object { $_.ToString() })
  return [pscustomobject]@{
    Stdout   = ($stdout -join "`n")
    Stderr   = ($stderr -join "`n")
    ExitCode = $code
  }
}

function Read-EnvValue {
  param([string] $Path, [string] $Key)
  if (-not (Test-Path $Path)) { return $null }
  $line = Select-String -Path $Path -Pattern "^$Key=" | Select-Object -First 1
  if (-not $line) { return $null }
  $value = $line.Line.Split('=', 2)[1].Trim().Trim('"')
  if ($value) { return $value } else { return $null }
}

function Set-EnvValue {
  # Replace the key's line, or append one. Every other line is kept as it is.
  param([string] $Path, [string] $Key, [string] $Value)
  $lines = @()
  if (Test-Path $Path) { $lines = @(Get-Content -Path $Path) }
  $found = $false
  $lines = @($lines | ForEach-Object {
    if ($_ -match "^$Key=") { $found = $true; "$Key=$Value" } else { $_ }
  })
  if (-not $found) {
    $lines += ''
    $lines += '# Written by vault-init.ps1: read and list on concourse/* only (VAULT.md).'
    $lines += "$Key=$Value"
  }
  Set-Content -Path $Path -Value $lines -Encoding UTF8
}

function Get-Status {
  # `vault status` exits 0 unsealed, 2 sealed (or uninitialised), 1 on error.
  $r = Invoke-Vault @('status', '-format=json')
  if ($r.ExitCode -eq 1 -or -not $r.Stdout) { return $null }
  return $r.Stdout | ConvertFrom-Json
}

# --- 1. Running? ------------------------------------------------------------
$previous = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$running = (& docker inspect -f '{{.State.Running}}' $Container 2>$null) -eq 'true'
$ErrorActionPreference = $previous

if (-not $running) {
  if ($Container -ne 'mykronos-vault') {
    throw "'$Container' is not running, and only the default container is started from here."
  }
  Write-Host "Starting the vault service..." -ForegroundColor Cyan
  $priorPlaceholder = $env:CONCOURSE_VAULT_TOKEN
  if (-not $priorPlaceholder) {
    # Satisfies the `:?` guard for this one call. Not a credential, never
    # written anywhere, and the concourse service is not started by it.
    $env:CONCOURSE_VAULT_TOKEN = 'placeholder-until-vault-init-mints-one'
  }
  Push-Location $PSScriptRoot
  try {
    docker compose up -d vault
    if ($LASTEXITCODE -ne 0) { throw "docker compose up -d vault failed with $LASTEXITCODE" }
  } finally {
    Pop-Location
    $env:CONCOURSE_VAULT_TOKEN = $priorPlaceholder
  }
}

$status = $null
$deadline = (Get-Date).AddSeconds(60)
while (-not ($status = Get-Status)) {
  if ((Get-Date) -gt $deadline) { throw "Vault in '$Container' did not answer within 60s: docker logs $Container" }
  Start-Sleep -Seconds 2
}

# --- 2. Initialised? --------------------------------------------------------
if (-not $status.initialized) {
  if (Test-Path $InitFile) {
    throw @"
Vault is uninitialised, but $InitFile already exists.

That file belongs to a Vault whose data is gone - most likely a deleted
vault-data volume. Refusing to overwrite it: if the old volume can be restored,
this is its only unseal key. Move the file aside yourself once you are sure,
then re-run.
"@
  }

  Write-Host "Initialising Vault (one key share, threshold one - see VAULT.md)..." -ForegroundColor Cyan
  $init = Invoke-Vault @('operator', 'init', '-key-shares=1', '-key-threshold=1', '-format=json')
  if ($init.ExitCode -ne 0) { throw "vault operator init failed (exit $($init.ExitCode)): $($init.Stderr)" }
  $parsed = $init.Stdout | ConvertFrom-Json
  if (-not $parsed.root_token -or -not $parsed.unseal_keys_b64) {
    throw "vault operator init returned no root token or unseal key; nothing was written."
  }
  New-Item -ItemType Directory -Force -Path (Split-Path $InitFile) | Out-Null
  Set-Content -Path $InitFile -Value $init.Stdout -Encoding ascii
  Write-Host "Wrote $InitFile (gitignored)." -ForegroundColor Green
  Write-Host "  PUT A COPY IN A PASSWORD MANAGER. Lose it and every secret in Vault is gone." -ForegroundColor Yellow
} elseif (-not (Test-Path $InitFile)) {
  throw @"
Vault is initialised, but there is no $InitFile to unseal it or to mint a token.

Restore the file from your password manager and re-run. Without it this script
cannot write the token; with only the root token, set $TokenKey in
$EnvFile by hand to a token holding the 'concourse' policy.
"@
}

# --- 3. Unsealed? -----------------------------------------------------------
& (Join-Path $PSScriptRoot 'vault-unseal.ps1') -InitFile $InitFile -Container $Container
if ($LASTEXITCODE -ne 0) { throw "vault-unseal.ps1 failed (exit $LASTEXITCODE)." }

$root = (Get-Content $InitFile -Raw | ConvertFrom-Json).root_token
if (-not $root) { throw "No root_token in $InitFile." }

# --- 4. Mounts --------------------------------------------------------------
$list = Invoke-Vault @('secrets', 'list', '-format=json') -Token $root
if ($list.ExitCode -ne 0) { throw "vault secrets list failed: $($list.Stderr)" }
$mounts = $list.Stdout | ConvertFrom-Json

# concourse/ is KV v1 on purpose: Concourse's lookup templates expect a flat
# read, and v2 inserts `data/` into the path (VAULT.md).
$existing = $mounts.'concourse/'
if (-not $existing) {
  $r = Invoke-Vault @('secrets', 'enable', '-path=concourse', '-version=1', 'kv') -Token $root
  if ($r.ExitCode -ne 0) { throw "enabling concourse/ failed: $($r.Stderr)" }
  Write-Host "Mounted concourse/ (KV v1)." -ForegroundColor Green
} elseif ($existing.options.version -eq '2') {
  throw "concourse/ is mounted as KV v2. Concourse cannot read it without a data/ path; see VAULT.md."
} else {
  Write-Host "concourse/ is already mounted." -ForegroundColor DarkGray
}

if (-not $mounts.'personal/') {
  $r = Invoke-Vault @('secrets', 'enable', '-path=personal', 'kv-v2') -Token $root
  if ($r.ExitCode -ne 0) { throw "enabling personal/ failed: $($r.Stderr)" }
  Write-Host "Mounted personal/ (KV v2)." -ForegroundColor Green
} else {
  Write-Host "personal/ is already mounted." -ForegroundColor DarkGray
}

# --- 5. Policy --------------------------------------------------------------
# Rewritten every run: it is the definition, and this file is where it lives.
$r = Invoke-Vault @('policy', 'write', 'concourse', '-') -Token $root -InputText $Policy
if ($r.ExitCode -ne 0) { throw "writing the concourse policy failed: $($r.Stderr)" }

# --- 6. Token ---------------------------------------------------------------
$current = Read-EnvValue $EnvFile $TokenKey
if ($current) {
  $lookup = Invoke-Vault @('token', 'lookup', '-format=json') -Token $current
  if ($lookup.ExitCode -eq 0) {
    Write-Host "$TokenKey in $EnvFile is accepted by Vault; leaving it." -ForegroundColor Green
    return
  }
  Write-Host "$TokenKey in $EnvFile is not accepted by Vault; minting a replacement." -ForegroundColor Yellow
}

$r = Invoke-Vault @('auth', 'tune', "-max-lease-ttl=$TokenTtl", 'token/') -Token $root
if ($r.ExitCode -ne 0) { throw "raising the token store's max TTL failed: $($r.Stderr)" }

$r = Invoke-Vault @('token', 'create', '-policy=concourse', '-orphan',
                    '-display-name=concourse', "-ttl=$TokenTtl", '-format=json') -Token $root
if ($r.ExitCode -ne 0) { throw "minting the Concourse token failed: $($r.Stderr)" }
$token = ($r.Stdout | ConvertFrom-Json).auth.client_token
if (-not $token) { throw "vault token create returned no client token." }

# The check VAULT.md says the bootstrap makes: the token Concourse holds must
# be denied personal/. A token that can read it is not the one described.
# A raw read of a v2 path rather than `vault kv`, whose mount preflight fails
# differently; a 403 is the answer either way, and a 404 would mean access.
$probe = Invoke-Vault @('read', 'personal/data/vault-init-probe') -Token $token
if ($probe.ExitCode -eq 0 -or ($probe.Stderr -notmatch 'Code: 403')) {
  throw "The new Concourse token was not denied personal/ - refusing to write it. Check the 'concourse' policy."
}

Set-EnvValue -Path $EnvFile -Key $TokenKey -Value $token
Write-Host "Wrote $TokenKey to $EnvFile (read and list on concourse/* only; denied personal/)." -ForegroundColor Green
