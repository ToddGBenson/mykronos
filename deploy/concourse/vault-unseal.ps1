<#
.SYNOPSIS
  Unseal Vault after a restart. Safe to run on a timer.

.DESCRIPTION
  Vault uses the file storage backend rather than `-dev` mode, so its data
  survives a restart - and so it comes back SEALED. Nothing can read a secret
  until it is unsealed, which means Concourse pipelines fail to resolve
  ((vars)) after every restart of this host, and after every Docker-engine
  recreate, until this runs.

  That is the deliberate cost of persistence. The alternative, dev mode, keeps
  everything in memory and loses it on restart, which is fine for a demo and
  useless as somewhere to keep a secret you would be upset to regenerate.

  Failure mode worth recognising: a sealed Vault does NOT make Concourse jobs
  hang. They fail with a credential-resolution error naming the var. If you see
  that after a reboot, this is the fix - not the pipeline.

  #60474: for four days nobody saw it. Install-VaultUnsealTask.ps1 registers a
  Scheduled Task that runs this repeatedly so a recreate reopens itself, and
  the compose healthcheck now reports a sealed Vault UNHEALTHY so a failure of
  that task is visible rather than silent. This script is the single
  implementation of the unseal; the task is only a trigger for it.

.PARAMETER LogFile
  Append a timestamped line per run. A Scheduled Task has no console, so
  without this its only trace is an exit code, and "it has been exit 0 all
  week" does not distinguish "unsealed it twice" from "never ran".

.EXAMPLE
  .\vault-unseal.ps1

.NOTES
  ASCII only - see setup.ps1. Windows PowerShell 5.1 reads a BOM-less file as
  CP1252, so a UTF-8 dash becomes three characters.

  EXIT CODES, because a Scheduled Task is read by exit code:
    0  unsealed now, already unsealed, or no Vault container running
    1  a real failure - keys rejected, still sealed, or no init file to use

  "No container running" is deliberately 0. A task that returns 1 every time
  Docker is down becomes a task whose failures nobody reads, and this host
  already has two of those. Whether Vault should be running at all is the
  compose healthcheck's question, not this script's.
#>
[CmdletBinding()]
param(
  [string] $InitFile = (Join-Path $PSScriptRoot 'vault/init.json'),
  [string] $Container = 'mykronos-vault',
  [string] $LogFile
)

$ErrorActionPreference = 'Stop'

function Write-Step {
  param([string] $Message, [string] $Colour = 'Gray')

  Write-Host $Message -ForegroundColor $Colour
  if ($LogFile) {
    $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ssK')
    Add-Content -Path $LogFile -Value "$stamp  $Message" -Encoding ascii
  }
}

function Stop-With {
  param([string] $Message)

  Write-Step $Message 'Red'
  exit 1
}

function Invoke-Docker {
  <#
    Run docker and hand back its output and exit code, without letting a line
    on stderr become a terminating error.

    `$ErrorActionPreference = 'Stop'` turns ANY native-command stderr output
    into a NativeCommandError, and `2>$null` does not prevent that - it only
    hides the text. So `docker inspect` against a container that does not
    exist threw a PowerShell error, and the "nothing to unseal, exit 0" branch
    below could never be reached: on a host with the stack down this exited 1
    with a stack trace instead. Found by running it, not by reading it.
  #>
  param([string[]] $Arguments)

  $previous = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    $output = & docker @Arguments 2>&1
    return [pscustomobject]@{ Output = $output; ExitCode = $LASTEXITCODE }
  } finally {
    $ErrorActionPreference = $previous
  }
}

# Is there anything to unseal? Ask before reading the key material, so a host
# with Docker stopped neither touches init.json nor reports a failure.
$inspect = Invoke-Docker @('inspect', '-f', '{{.State.Running}}', $Container)
if ($inspect.ExitCode -ne 0) {
  Write-Step "No '$Container' container on this host - nothing to unseal."
  exit 0
}
if (($inspect.Output | Select-Object -Last 1) -ne 'true') {
  Write-Step "'$Container' exists but is not running - nothing to unseal."
  exit 0
}

# Is it already open? Unsealing an unsealed Vault is harmless, but saying so is
# more useful than silently doing nothing - and on a timer this is the answer
# almost every run, so it has to be cheap and quiet.
$status = Invoke-Docker @('exec', $Container, 'sh', '-c',
                          'VAULT_ADDR=http://127.0.0.1:8200 vault status -format=json')
if ($status.ExitCode -eq 0) {
  $s = ($status.Output -join "`n") | ConvertFrom-Json
  if (-not $s.sealed) {
    Write-Step "Vault is already unsealed." 'Green'
    exit 0
  }
}

if (-not (Test-Path $InitFile)) {
  Stop-With @"
Vault is sealed and there is no init file at $InitFile.

Either Vault has never been initialised on this host, or the unseal material was
lost. If it is lost, the data is unrecoverable - there is no recovery path by
design, which is why the bootstrap tells you to put a copy in a password manager.
"@
}

$init = Get-Content $InitFile -Raw | ConvertFrom-Json

foreach ($key in $init.unseal_keys_b64) {
  # The key is passed as an argument here and so is visible in the container's
  # process list for the life of the exec. It is already at rest in $InitFile
  # on this disk; if that ever stops being true, this becomes stdin.
  $unseal = Invoke-Docker @('exec', '-e', 'VAULT_ADDR=http://127.0.0.1:8200',
                            $Container, 'vault', 'operator', 'unseal', $key)
  if ($unseal.ExitCode -ne 0) {
    # Deliberately not echoing docker's output: `vault operator unseal` quotes
    # the rejected key back in its error, and this line can reach a log file.
    Stop-With "unseal failed (exit $($unseal.ExitCode)) applying a key from $InitFile."
  }
}

$final = Invoke-Docker @('exec', $Container, 'sh', '-c',
                         'VAULT_ADDR=http://127.0.0.1:8200 vault status -format=json')
if ($final.ExitCode -ne 0 -or (($final.Output -join "`n") | ConvertFrom-Json).sealed) {
  Stop-With "Vault is still sealed after applying every key in $InitFile."
}

Write-Step "Vault unsealed." 'Green'
Write-Step "Concourse will resolve ((vars)) again on the next build; jobs that" 'DarkGray'
Write-Step "failed while it was sealed need re-triggering, they do not retry." 'DarkGray'
exit 0
