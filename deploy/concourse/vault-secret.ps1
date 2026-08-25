#Requires -Version 7
# ^ pwsh only. These scripts build their docker invocation with
# ProcessStartInfo.ArgumentList, which .NET Framework 4.x (Windows
# PowerShell 5.1) does not have - there it is $null and .Add() fails with
# "You cannot call a method on a null-valued expression", naming neither
# the shell nor the cause. ArgumentList keeps each argument separate, and
# the single-string alternative would put a Vault token on the command
# line, so this requires the newer shell rather than working around it.
#
# Run with:  pwsh -File .\<script>.ps1 ...
<#
.SYNOPSIS
  Read, write and list secrets - for Concourse pipelines and for personal use.

.DESCRIPTION
  Two mounts, deliberately different:

    concourse/   KV v1, read by Concourse. Flat reads, no version history.
                 Path layout is fixed by Concourse's lookup templates:
                   concourse/<team>/<pipeline>/<name>   pipeline-specific
                   concourse/<team>/<name>              shared across a team
                 A pipeline then refers to it as ((name)) and the VALUE NEVER
                 ENTERS the pipeline config - which is the entire point, because
                 `fly get-pipeline` prints config back to anyone on the team.

    personal/    KV v2, for everything else on this host: API keys, licence
                 keys, recovery codes, the things that otherwise end up in a
                 note or a shell profile. v2 keeps version history, so
                 overwriting a secret does not destroy the previous value -
                 `-Undo` brings it back.

  Values are never echoed unless you ask for them with -Reveal, so this is safe
  to run with someone looking over your shoulder or in a shared terminal.

.EXAMPLE
  # Personal secret
  .\vault-secret.ps1 set  openai/api-key
  .\vault-secret.ps1 get  openai/api-key -Reveal
  .\vault-secret.ps1 list
  .\vault-secret.ps1 undo openai/api-key      # roll back to the previous version

.EXAMPLE
  # A credential for one pipeline, in the `main` team
  .\vault-secret.ps1 set github_token -Scope pipeline -Pipeline keel
  # ...then the pipeline refers to it as ((github_token))

.EXAMPLE
  # Shared across every pipeline in the team
  .\vault-secret.ps1 set slack_webhook_url -Scope team
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory, Position = 0)]
  [ValidateSet('get', 'set', 'list', 'delete', 'undo')]
  [string] $Action,

  [Parameter(Position = 1)]
  [string] $Name,

  [ValidateSet('personal', 'team', 'pipeline')]
  [string] $Scope = 'personal',

  [string] $Team = 'main',
  [string] $Pipeline,
  [switch] $Reveal,
  [string] $Container = 'mykronos-vault'
)

$ErrorActionPreference = 'Stop'

function Invoke-Vault {
  param([string[]] $VaultArgs)
  $out = docker exec -e VAULT_ADDR=http://127.0.0.1:8200 -i $Container vault @VaultArgs 2>&1
  if ($LASTEXITCODE -ne 0) {
    if ($out -match 'Vault is sealed') {
      Write-Error "Vault is sealed. Run .\vault-unseal.ps1 first."
    }
    Write-Error ($out | Out-String)
  }
  return $out
}

# Resolve the path. Concourse's layout is not a convention we chose; it is what
# its lookup templates read, so getting it wrong means the pipeline reports a
# missing credential rather than a wrong one.
switch ($Scope) {
  'personal' { $mount = 'personal'; $path = "personal/$Name" }
  'team'     { $mount = 'concourse'; $path = "concourse/$Team/$Name" }
  'pipeline' {
    if (-not $Pipeline) { Write-Error "-Pipeline is required with -Scope pipeline" }
    $mount = 'concourse'; $path = "concourse/$Team/$Pipeline/$Name"
  }
}

switch ($Action) {

  'list' {
    if ($Scope -eq 'personal') {
      Invoke-Vault @('kv', 'list', 'personal/') | Write-Output
    } else {
      $base = if ($Pipeline) { "concourse/$Team/$Pipeline" } else { "concourse/$Team" }
      Invoke-Vault @('kv', 'list', $base) | Write-Output
    }
  }

  'get' {
    $json = Invoke-Vault @('kv', 'get', '-format=json', $path) | Out-String
    $value = ($json | ConvertFrom-Json).data
    if ($Scope -eq 'personal') { $value = $value.data }   # v2 nests under .data.data
    $value = $value.value
    if ($Reveal) {
      Write-Output $value
    } else {
      $len = if ($value) { $value.Length } else { 0 }
      Write-Host "$path exists ($len chars). Pass -Reveal to print it." -ForegroundColor Green
    }
  }

  'set' {
    # Read-Host -AsSecureString so the value never lands in shell history, and
    # never appears on a command line where `ps` could see it.
    $secure = Read-Host -Prompt "Value for $path" -AsSecureString
    $plain = [System.Net.NetworkCredential]::new('', $secure).Password
    if (-not $plain) { Write-Error "Empty value refused - use 'delete' to remove a secret." }

    # Piped on stdin (`value=-`) rather than passed as an argument, for the same
    # reason: an argument is visible in the container's process list.
    #
    # Written through .NET rather than `$plain | docker exec`, because the
    # PowerShell pipeline terminates what it sends with CRLF. That stored a
    # 57-character bot token as 59 bytes, and a trailing "\r\n" inside an
    # `Authorization: Bearer` header is a 401 that nothing in the logs
    # explains - the value looks correct everywhere except on the wire.
    # StandardInput.Write() sends exactly the characters given.
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = 'docker'
    foreach ($a in @('exec', '-e', 'VAULT_ADDR=http://127.0.0.1:8200',
                     '-i', $Container, 'vault', 'kv', 'put', $path, 'value=-')) {
      $psi.ArgumentList.Add($a)
    }
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false

    $proc = [System.Diagnostics.Process]::Start($psi)
    $proc.StandardInput.Write($plain)
    $proc.StandardInput.Close()
    $null = $proc.StandardOutput.ReadToEnd()
    $writeErr = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()
    if ($proc.ExitCode -ne 0) {
      if ($writeErr -match 'Vault is sealed') { Write-Error "Vault is sealed. Run .\vault-unseal.ps1 first." }
      Write-Error "write failed: $writeErr"
    }

    # Read the length back. A secret that stored two bytes longer than it
    # should is exactly the failure this rewrite fixes, so it is worth
    # confirming rather than assuming - and the length is safe to print.
    $check = docker exec -e VAULT_ADDR=http://127.0.0.1:8200 $Container `
      vault read -format=json $path 2>$null | Out-String
    if ($check) {
      $stored = ($check | ConvertFrom-Json).data
      if ($Scope -eq 'personal') { $stored = $stored.data }
      $storedLen = $stored.value.Length
      if ($storedLen -ne $plain.Length) {
        Write-Warning "stored $storedLen chars but $($plain.Length) were given - the value was altered in transit."
      }
    }

    Write-Host "Wrote $path" -ForegroundColor Green
    if ($Scope -ne 'personal') {
      Write-Host "Pipelines in team '$Team' can now use ((${Name}))." -ForegroundColor DarkGray
    }
  }

  'undo' {
    if ($Scope -ne 'personal') {
      Write-Error "undo needs version history, which only the personal/ (KV v2) mount has."
    }
    $meta = Invoke-Vault @('kv', 'metadata', 'get', '-format=json', $path) | Out-String
    $current = ($meta | ConvertFrom-Json).data.current_version
    if ($current -lt 2) { Write-Error "$path has only one version - nothing to roll back to." }
    Invoke-Vault @('kv', 'rollback', "-version=$($current - 1)", $path) | Out-Null
    Write-Host "Rolled $path back to version $($current - 1)." -ForegroundColor Green
  }

  'delete' {
    Invoke-Vault @('kv', 'delete', $path) | Out-Null
    Write-Host "Deleted $path" -ForegroundColor Green
    if ($Scope -eq 'personal') {
      Write-Host "Soft delete - 'undo' can still recover it. Use 'vault kv metadata delete' to destroy." -ForegroundColor DarkGray
    }
  }
}
