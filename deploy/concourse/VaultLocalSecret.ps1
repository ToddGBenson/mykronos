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

  A different location can be given in MYKRONOS_VAULT_LOCAL_SECRET.

  ONE SOURCE AT A TIME. When the DPAPI file exists it is the only source. A
  file that exists but cannot be used - zero bytes, not XML, the wrong shape,
  a value that is not a SecureString, the name missing, or ciphertext this
  logon cannot decrypt - is refused with an error that says which, and is
  never treated as absent. Falling back to init.json there would hide a
  failed move behind the plaintext root token, and once the root token is
  revoked it would surface as a 403 that points nowhere near this file.
  init.json is read only when there is no DPAPI file at all (a host before
  the move), and then with a warning naming both files, every time.

  WHAT DPAPI PROTECTS. The file is useless to another Windows account, to a
  copy of the disk or of a backup, and to anyone who has the repository
  checkout. It is NOT protection from code running as this same user, which
  can decrypt it exactly as these scripts do.

  WHO CANNOT READ IT. A task registered with LogonType S4U, or as SYSTEM,
  holds no user password, so DPAPI has no key and the read fails. The unseal
  task that Install-VaultUnsealTask.ps1 registers runs Interactive as the
  operator, which can; the installer has no SYSTEM option for that reason.

.NOTES
  ASCII only, and Windows PowerShell 5.1 compatible: vault-unseal.ps1 is
  started by powershell.exe on this host as well as by pwsh.
#>

function Get-VaultLocalSecretPath {
  if ($env:MYKRONOS_VAULT_LOCAL_SECRET) { return $env:MYKRONOS_VAULT_LOCAL_SECRET }
  $base = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
  return (Join-Path (Join-Path $base 'mykronos-vault') 'vault-local.clixml')
}

function Test-CryptographicFailure {
  # True when the error, or anything it wraps, is DPAPI failing to decrypt.
  param($Exception)
  for ($e = $Exception; $e; $e = $e.InnerException) {
    if ($e -is [System.Security.Cryptography.CryptographicException]) { return $true }
  }
  return $false
}

function Read-VaultLocalSecret {
  <#
    The named value as plain text, or $null when there is no DPAPI file.
    Throws when the file exists but cannot be used, naming which of three
    things is wrong, because each needs a different repair:
      cannot decrypt  - this logon is not the one that wrote it (S4U, SYSTEM,
                        another account), or its ciphertext is damaged
      damaged         - zero bytes, or not a clixml file at all
      wrong shape     - it parses, but is not a hashtable of SecureStrings
                        holding this name
  #>
  param(
    [Parameter(Mandatory)] [string] $Name,
    [string] $Path
  )
  if (-not $Path) { $Path = Get-VaultLocalSecretPath }
  if (-not (Test-Path -LiteralPath $Path)) { return $null }
  $tail = 'Not falling back to init.json while this file exists: restore it from the offline backup, or move it aside.'
  if ((Get-Item -LiteralPath $Path -Force).Length -eq 0) {
    throw "the DPAPI file $Path is damaged: it is zero bytes. $tail"
  }
  try {
    $raw = Import-Clixml -LiteralPath $Path
  } catch {
    $kind = $_.Exception.GetType().Name
    if (Test-CryptographicFailure $_.Exception) {
      throw ("cannot decrypt $Path as $([Environment]::UserName) ($kind). It is DPAPI-protected for the " +
             "Windows account and logon that wrote it: an S4U or SYSTEM task, or another account, cannot " +
             "read it. Run this as that user's interactive logon; if that is already the case, the " +
             "ciphertext is damaged. $tail")
    }
    throw "the DPAPI file $Path is damaged: it is not a readable clixml file ($kind). $tail"
  }
  $shape = $null
  if (-not ($raw -is [hashtable])) {
    $type = if ($null -eq $raw) { 'nothing' } else { $raw.GetType().Name }
    $shape = "it holds a $type, not a hashtable"
  } elseif (-not $raw.ContainsKey($Name)) {
    # The move writes UnsealKeys, then AdminToken: a file with one is a move
    # stopped half way, and the repair is to finish it, not to restore.
    $shape = "it has no $Name entry (a move stopped before writing it: finish the move)"
  } elseif (-not ($raw[$Name] -is [securestring])) {
    $shape = "$Name is not a SecureString (refusing a plaintext value)"
  }
  if ($shape) {
    throw ("the DPAPI file $Path has the wrong shape: $shape. Expected Export-Clixml of a hashtable " +
           "of SecureStrings holding UnsealKeys and AdminToken. $tail")
  }
  return [System.Net.NetworkCredential]::new('', $raw[$Name]).Password
}

function Get-InitFileFallbackWarning {
  param([string] $InitFile, [string] $What)
  return ("no DPAPI file at $(Get-VaultLocalSecretPath); using the $What in the plaintext " +
          "$InitFile. Finish the move off init.json (TheHub #60836).")
}

function Get-VaultUnsealKey {
  <#
    @{ Keys; Source; Warning } from the DPAPI file, else - only when there is
    no DPAPI file - from InitFile; $null when neither exists. Source names
    where they came from, for the log. Warning is set, and Write-Warning
    emitted, every time InitFile is used. A DPAPI file that exists but cannot
    be used throws (Read-VaultLocalSecret), whatever InitFile holds.
  #>
  [CmdletBinding()]
  param([string] $InitFile)
  $path = Get-VaultLocalSecretPath
  if (Test-Path -LiteralPath $path) {
    $local = Read-VaultLocalSecret -Name 'UnsealKeys' -Path $path
    $keys = @($local -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if (-not $keys.Count) {
      throw "the DPAPI file $path has the wrong shape: UnsealKeys is empty. Not falling back to init.json while this file exists."
    }
    return [pscustomobject]@{ Keys = $keys; Source = "the DPAPI file $path"; Warning = $null }
  }
  if ($InitFile -and (Test-Path -LiteralPath $InitFile)) {
    $keys = @((Get-Content -LiteralPath $InitFile -Raw | ConvertFrom-Json).unseal_keys_b64 | Where-Object { $_ })
    if ($keys.Count) {
      $warning = Get-InitFileFallbackWarning -InitFile $InitFile -What 'unseal key'
      Write-Warning $warning
      return [pscustomobject]@{ Keys = $keys; Source = $InitFile; Warning = $warning }
    }
  }
  return $null
}

function Get-VaultAdminToken {
  <#
    @{ Token; Source; Warning } - the admin token from the DPAPI file, else -
    only when there is no DPAPI file - the root token from InitFile, with a
    Write-Warning every time; $null when neither exists. A DPAPI file that
    exists but cannot be used throws, as Get-VaultUnsealKey. The value is
    never printed by anything here; callers forward it by name (-e VAULT_TOKEN).
  #>
  [CmdletBinding()]
  param([string] $InitFile)
  $path = Get-VaultLocalSecretPath
  if (Test-Path -LiteralPath $path) {
    $token = Read-VaultLocalSecret -Name 'AdminToken' -Path $path
    if (-not $token) {
      throw "the DPAPI file $path has the wrong shape: AdminToken is empty. Not falling back to init.json while this file exists."
    }
    return [pscustomobject]@{ Token = $token; Source = "the admin token in $path"; Warning = $null }
  }
  if ($InitFile -and (Test-Path -LiteralPath $InitFile)) {
    $token = (Get-Content -LiteralPath $InitFile -Raw | ConvertFrom-Json).root_token
    if ($token) {
      $warning = Get-InitFileFallbackWarning -InitFile $InitFile -What 'root token'
      Write-Warning $warning
      return [pscustomobject]@{ Token = $token; Source = "the root token in $InitFile"; Warning = $warning }
    }
  }
  return $null
}
