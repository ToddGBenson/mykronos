#Requires -Version 7.2
<#
.SYNOPSIS
    Store the backup secrets for this Windows user and register the two nightly tasks.

.DESCRIPTION
    TheHub #60842. Run by the operator, once, in their own PowerShell prompt.
    Nothing in the backup chain runs this for you.

      -SetSecrets   prompts (masked) for the encryption key, the upload SAS
                    URL and the read SAS URL, and writes them to
                    %LOCALAPPDATA%\mykronos-backup\secrets.clixml with DPAPI
                    (CurrentUser): only this Windows user, on this machine,
                    can read them back. The key is checked for shape before it
                    is saved; it is never printed.

      (default)     registers, for the current user:
                      "Mykronos Backup (create)"  daily 03:00  Backup-MyKronos.ps1
                      "Mykronos Backup (verify)"  daily 04:00  Test-MyKronosRestore.ps1
                    Same hours as TheHub's create/verify. LogonType Password,
                    not S4U: an S4U task cannot decrypt DPAPI secrets and has
                    no network credentials. Docker Desktop must be running for
                    this user when the tasks fire.

    Supports -WhatIf.

.EXAMPLE
    pwsh -File deploy/backup/Register-MyKronosBackupTasks.ps1 -SetSecrets
    pwsh -File deploy/backup/Register-MyKronosBackupTasks.ps1 -WhatIf
    pwsh -File deploy/backup/Register-MyKronosBackupTasks.ps1
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch] $SetSecrets,
    [string] $BackupRoot = (Join-Path $env:USERPROFILE 'Backups\mykronos'),
    [string] $CreateAt = '03:00',
    [string] $VerifyAt = '04:00',
    [string] $CreateTaskName = 'Mykronos Backup (create)',
    [string] $VerifyTaskName = 'Mykronos Backup (verify)',
    [pscredential] $Credential
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'MyKronosBackup.psm1') -Force

function Read-Secret {
    param([string] $Prompt)
    $s = Read-Host -Prompt $Prompt -AsSecureString
    return $s
}

if ($SetSecrets) {
    $path = Get-DefaultSecretPath
    $key = Read-Secret -Prompt 'Backup encryption key (Fernet, url-safe base64 of 32 bytes)'
    $plainKey = ConvertFrom-SecureString -SecureString $key -AsPlainText
    $null = Get-FernetKey -Key $plainKey     # throws, naming the setting only, if malformed
    $write = Read-Secret -Prompt 'Upload SAS URL for the mykronos-backups container (create+write); Enter to skip'
    $read = Read-Secret -Prompt 'Read SAS URL for the same container (read+list); Enter to skip'
    $store = @{ EncryptionKey = $key; WriteSasUrl = $write; ReadSasUrl = $read }
    foreach ($name in @('WriteSasUrl', 'ReadSasUrl')) {
        $v = ConvertFrom-SecureString -SecureString $store[$name] -AsPlainText
        if ($v) {
            $null = Split-SasUrl -SasUrl $v
            $exp = Get-SasExpiry -SasUrl $v
            [Console]::Out.WriteLine(('{0}: {1} expires {2}' -f $name, (Get-SafeContainerUrl -SasUrl $v), $(if ($exp) { $exp.ToString('yyyy-MM-dd') } else { 'unknown (no se=)' })))
        } else {
            [Console]::Out.WriteLine("${name}: not set")
        }
    }
    if ($PSCmdlet.ShouldProcess($path, 'write DPAPI-protected backup secrets')) {
        New-Item -ItemType Directory -Force -Path (Split-Path $path) | Out-Null
        $store | Export-Clixml -LiteralPath $path
        [Console]::Out.WriteLine("saved: $path (key fingerprint $(Get-KeyFingerprint -Key $plainKey))")
    }
    return
}

$pwsh = (Get-Command pwsh -ErrorAction Stop).Source
$tasks = @(
    @{ Name = $CreateTaskName; At = $CreateAt; Script = (Join-Path $PSScriptRoot 'Backup-MyKronos.ps1'); Limit = (New-TimeSpan -Hours 3) }
    @{ Name = $VerifyTaskName; At = $VerifyAt; Script = (Join-Path $PSScriptRoot 'Test-MyKronosRestore.ps1'); Limit = (New-TimeSpan -Hours 2) }
)

if (-not (Test-Path -LiteralPath (Get-DefaultSecretPath))) {
    Write-Warning "no secrets file at $(Get-DefaultSecretPath): the create task will refuse to run until -SetSecrets has been run as this user"
}

if (-not $Credential -and -not $WhatIfPreference) {
    $Credential = Get-Credential -UserName "$env:USERDOMAIN\$env:USERNAME" -Message 'Windows password for the backup tasks (LogonType Password)'
}

foreach ($t in $tasks) {
    $action = New-ScheduledTaskAction -Execute $pwsh -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -BackupRoot "{1}"' -f $t.Script, $BackupRoot)
    $trigger = New-ScheduledTaskTrigger -Daily -At $t.At
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit $t.Limit
    if ($PSCmdlet.ShouldProcess($t.Name, "register daily at $($t.At): $($t.Script)")) {
        $null = Register-ScheduledTask -TaskName $t.Name -Action $action -Trigger $trigger -Settings $settings `
            -User $Credential.UserName -Password $Credential.GetNetworkCredential().Password -RunLevel Limited -Force
        [Console]::Out.WriteLine("registered: '$($t.Name)' daily at $($t.At)")
    }
}
