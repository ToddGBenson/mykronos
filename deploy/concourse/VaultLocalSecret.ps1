<#
.SYNOPSIS
  Vault's unseal keys and the operator's admin token, read from a file only
  this Windows user can decrypt (TheHub #60836). Dot-source it.

.DESCRIPTION
  vault/init.json holds the unseal key and the root token in plaintext beside
  the compose file. The operator's move writes them to

      %LOCALAPPDATA%\mykronos-vault\vault-local.clixml

  instead: Export-Clixml of a hashtable of SecureStrings, which Windows
  protects with DPAPI for the current user. It is the same pattern as the
  backup chain's secrets.clixml (deploy/backup/MyKronosBackup.psm1).

    UnsealKeys   the base64 unseal keys, one per line
    AdminToken   a token holding the admin policy, minted to replace the root
                 token for day-to-day writes (vault-secret.ps1 and friends)

  Every reader tries that file first and init.json second, so each script
  works before the move, during it (both present) and after init.json is
  deleted. A different location can be given in MYKRONOS_VAULT_LOCAL_SECRET.

  WHAT DPAPI PROTECTS. The file is useless to another Windows account, to a
  copy of the disk or of a backup, and to anyone who has the repository
  checkout. It is NOT protection from code running as this same user, which
  can decrypt it exactly as these scripts do.

  WHO CANNOT READ IT. A task registered with LogonType S4U, or as SYSTEM,
  holds no user password, so DPAPI has no key and the read fails. The unseal
  task that Install-VaultUnsealTask.ps1 registers runs Interactive, which
  can. Read-VaultLocalSecret says so in its error instead of failing vaguely.

.NOTES
  ASCII only, and Windows PowerShell 5.1 compatible: vault-unseal.ps1 is
  started by powershell.exe on this host as well as by pwsh.
#>

function Get-VaultLocalSecretPath {
  if ($env:MYKRONOS_VAULT_LOCAL_SECRET) { return $env:MYKRONOS_VAULT_LOCAL_SECRET }
  $base = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
  return (Join-Path (Join-Path $base 'mykronos-vault') 'vault-local.clixml')
}

function Read-VaultLocalSecret {
  <#
    The named value as plain text; $null when the file or the name is absent.
    Throws when the file exists but cannot be decrypted, because "no file" and
    "a file this logon cannot open" need different repairs.
  #>
  param(
    [Parameter(Mandatory)] [string] $Name,
    [string] $Path
  )
  if (-not $Path) { $Path = Get-VaultLocalSecretPath }
  if (-not (Test-Path -LiteralPath $Path)) { return $null }
  try {
    $raw = Import-Clixml -LiteralPath $Path
  } catch {
    throw ("cannot decrypt $Path as $([Environment]::UserName) ($($_.Exception.GetType().Name)). " +
           "It is DPAPI-protected for that user's own logon: an S4U or SYSTEM task cannot read it.")
  }
  if (-not ($raw -is [hashtable]) -or -not $raw.ContainsKey($Name)) { return $null }
  $value = $raw[$Name]
  if (-not ($value -is [securestring])) {
    throw "$Name in $Path is not a SecureString; refusing a plaintext value."
  }
  return [System.Net.NetworkCredential]::new('', $value).Password
}

function Get-VaultUnsealKey {
  <#
    @{ Keys; Source } from the DPAPI file, else from InitFile; $null when
    neither holds a key. Source names where they came from, for the log.
    A DPAPI file this logon cannot decrypt falls back to InitFile while that
    still exists (the move is in progress), and throws once it does not.
  #>
  param([string] $InitFile)
  $local = $null
  $unreadable = $null
  try { $local = Read-VaultLocalSecret -Name 'UnsealKeys' } catch { $unreadable = $_ }
  if ($local) {
    $keys = @($local -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($keys.Count) {
      return [pscustomobject]@{ Keys = $keys; Source = "the DPAPI file $(Get-VaultLocalSecretPath)" }
    }
  }
  if ($InitFile -and (Test-Path -LiteralPath $InitFile)) {
    $keys = @((Get-Content -LiteralPath $InitFile -Raw | ConvertFrom-Json).unseal_keys_b64 | Where-Object { $_ })
    if ($keys.Count) { return [pscustomobject]@{ Keys = $keys; Source = $InitFile } }
  }
  if ($unreadable) { throw $unreadable }
  return $null
}

function Get-VaultAdminToken {
  <#
    @{ Token; Source } - the admin token from the DPAPI file, else the root
    token from InitFile; $null when there is neither. The value is never
    printed by anything here; callers forward it by name (-e VAULT_TOKEN).
    An unreadable DPAPI file falls back to InitFile, as Get-VaultUnsealKey.
  #>
  param([string] $InitFile)
  $token = $null
  $unreadable = $null
  try { $token = Read-VaultLocalSecret -Name 'AdminToken' } catch { $unreadable = $_ }
  if ($token) {
    return [pscustomobject]@{ Token = $token; Source = "the admin token in $(Get-VaultLocalSecretPath)" }
  }
  if ($InitFile -and (Test-Path -LiteralPath $InitFile)) {
    $token = (Get-Content -LiteralPath $InitFile -Raw | ConvertFrom-Json).root_token
    if ($token) { return [pscustomobject]@{ Token = $token; Source = "the root token in $InitFile" } }
  }
  if ($unreadable) { throw $unreadable }
  return $null
}
