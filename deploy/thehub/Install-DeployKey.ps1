<#
.SYNOPSIS
    Provision the restricted SSH deploy keys the pipeline uses (spec 16 section 7).

.DESCRIPTION
    Generates one ed25519 keypair per environment, writes the private half
    where set-thehub-pipeline.ps1 will read it, and prints the authorized_keys
    lines to install on this host.

    The authorized_keys entry is the security control, not the key:

      command="pwsh -NoProfile -File <path> -Environment demo",
        no-agent-forwarding,no-port-forwarding,no-pty,no-X11-forwarding <key>

    sshd ignores the client's command and runs that one. So the key cannot open
    a shell, cannot forward a port, and cannot deploy to an environment other
    than the one its own line names - separation is enforced by sshd against
    the key that authenticated, rather than by the pipeline choosing to pass a
    different argument. Spec 15 section 6 asks for deploy credentials scoped to
    the deploy job; this scopes them to the environment, which is stronger.

    It also captures the host's public key into a known_hosts file. The deploy
    tasks run with StrictHostKeyChecking on, because a deploy job that accepts
    any host key is a deploy job that can be pointed at a different host.

    This script does NOT edit authorized_keys itself. Writing to the sshd
    configuration of the machine it is running on, unattended, is the kind of
    convenience that locks somebody out of their own host - and on Windows the
    file for an administrator account is not the one in the user profile. The
    lines are printed for a person to place.

.PARAMETER Environments
    Which environments to generate keys for. Existing keys are left alone
    unless -Force is given: regenerating a key that is already installed
    breaks deploys until the new public half is placed, which is a surprising
    outcome for a script somebody re-ran to check it had worked.

.NOTES
    ASCII only - see deploy\concourse\setup.ps1.

    Requires OpenSSH (ssh-keygen, ssh-keyscan), which ships with Windows 11.
    The deploy account needs the Docker CLI on its PATH and membership of
    docker-users. It does not need to be an administrator - it needs to be able
    to talk to the Docker daemon and nothing else.
#>

[CmdletBinding()]
param(
    [ValidateSet("demo", "prod")]
    [string[]]$Environments = @("demo", "prod"),

    [string]$DeployHost = "192.168.0.14",
    [string]$KeyDirectory = (Join-Path $PSScriptRoot "..\concourse\keys"),
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$keyDir = (New-Item -ItemType Directory -Force -Path $KeyDirectory).FullName
$scriptPath = (Join-Path $PSScriptRoot "Invoke-TheHubDeploy.ps1")
if (-not (Test-Path $scriptPath)) { throw "Missing $scriptPath" }
$scriptPath = (Resolve-Path $scriptPath).Path

foreach ($tool in @("ssh-keygen", "ssh-keyscan")) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "$tool is not on PATH. Install the OpenSSH client feature."
    }
}

$authorizedLines = @()

foreach ($environment in $Environments) {
    $private = Join-Path $keyDir "thehub-$environment-deploy"
    $public = "$private.pub"

    if ((Test-Path $private) -and -not $Force) {
        Write-Host "Keeping the existing $environment key ($private)." -ForegroundColor DarkGray
    } else {
        if (Test-Path $private) { Remove-Item $private, $public -Force -ErrorAction SilentlyContinue }
        Write-Host "Generating the $environment deploy key..." -ForegroundColor Cyan
        # No passphrase: the private half lives in Concourse's credential store
        # and is handed to a task as an environment variable. A passphrase that
        # would have to be stored beside the key it protects is theatre.
        & ssh-keygen -t ed25519 -N '""' -C "concourse-thehub-$environment" -f $private | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "ssh-keygen failed for $environment" }
    }

    $pub = (Get-Content $public -Raw).Trim()
    $command = "pwsh -NoProfile -File `"$scriptPath`" -Environment $environment"
    $authorizedLines += "command=`"$command`",no-agent-forwarding,no-port-forwarding,no-pty,no-X11-forwarding $pub"
}

# The host key, pinned. Captured here rather than accepted at first connection,
# because "trust on first use" from an automated task is trust on every use.
$knownHosts = Join-Path $keyDir "thehub-known_hosts"
Write-Host "Capturing the host key for $DeployHost..." -ForegroundColor Cyan
$scan = & ssh-keyscan -t ed25519,rsa $DeployHost 2>$null | Where-Object { $_ -and -not $_.StartsWith("#") }
if (-not $scan) {
    throw "ssh-keyscan got nothing from $DeployHost. Is the OpenSSH Server service running?"
}
$scan | Set-Content -Path $knownHosts -Encoding ASCII

Write-Host "`nKeys are in $keyDir." -ForegroundColor Green
Write-Host "set-thehub-pipeline.ps1 reads them from there; they are gitignored.`n"

Write-Host "Add these lines to the deploy account's authorized_keys:" -ForegroundColor Yellow
Write-Host "  a normal account:   C:\Users\<deploy-user>\.ssh\authorized_keys"
Write-Host "  an administrator:   C:\ProgramData\ssh\administrators_authorized_keys"
Write-Host "                      (and that file must be owned by Administrators/SYSTEM only)`n"
foreach ($line in $authorizedLines) {
    Write-Host $line
    Write-Host ""
}

Write-Host "Then check it end to end, from a machine that is not this one:" -ForegroundColor Yellow
Write-Host "  ssh -i $keyDir\thehub-demo-deploy <deploy-user>@$DeployHost 0000000000000000000000000000000000000000"
Write-Host "It should refuse that SHA - the image does not exist - and not open a shell."
Write-Host "A shell prompt means the forced command is not in place." -ForegroundColor Yellow
