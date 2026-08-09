<#
.SYNOPSIS
    Publish the updated cloudflared ingress to the service, and restart it.

.DESCRIPTION
    The cloudflared service runs as LocalSystem, which keeps its own config at
    C:\Windows\System32\config\systemprofile\.cloudflared\config.yml — a copy
    made when the service was installed, entirely separate from the one in
    your user profile. Editing ~/.cloudflared/config.yml therefore changes
    nothing until it is copied across, which is why a new hostname resolves,
    reaches the tunnel, and then falls through to the 404 catch-all.

    This backs up the service's copy, shows you what is being replaced, copies
    the user config over it, restarts the service, and verifies.

.NOTES
    Run elevated. Restarting the tunnel briefly drops every hostname it
    serves — hub, blog and demo included. It is seconds, but it is not zero.

    Usage:  Right-click PowerShell -> Run as administrator, then:
              cd C:\Users\tgb_\Documents\Projects\PDSO2
              .\scripts\install-tunnel-route.ps1
#>

[CmdletBinding()]
param(
    [string]$UserConfig    = "$env:USERPROFILE\.cloudflared\config.yml",
    [string]$ServiceConfig = "C:\Windows\System32\config\systemprofile\.cloudflared\config.yml",
    [string]$VerifyUrl     = "https://mykronos.toddbenson.net/healthz",
    [string[]]$MustStayUp  = @("https://hub.toddbenson.net/", "https://blog.toddbenson.net/")
)

$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Not elevated. Re-run this from an administrator PowerShell."
}

if (-not (Test-Path $UserConfig)) { throw "No user config at $UserConfig" }

Write-Host "`n=== Replacing ===" -ForegroundColor Cyan
if (Test-Path $ServiceConfig) {
    Get-Content $ServiceConfig | Write-Host
    $backup = "$ServiceConfig.bak-$(Get-Date -Format yyyyMMdd-HHmmss)"
    Copy-Item $ServiceConfig $backup
    Write-Host "`nBacked up to $backup" -ForegroundColor DarkGray
} else {
    Write-Host "(none — the service config does not exist yet)" -ForegroundColor DarkGray
    New-Item -ItemType Directory -Force -Path (Split-Path $ServiceConfig) | Out-Null
}

Write-Host "`n=== With ===" -ForegroundColor Cyan
Get-Content $UserConfig | Write-Host

Copy-Item $UserConfig $ServiceConfig -Force
Write-Host "`nCopied." -ForegroundColor Green

Write-Host "`nRestarting the tunnel — every hostname drops for a few seconds..." `
    -ForegroundColor Yellow
Restart-Service Cloudflared -Force
Start-Sleep -Seconds 10

Write-Host "`n=== Verifying ===" -ForegroundColor Cyan

# The hostnames that were already working matter more than the new one: a
# config that breaks them is worse than one that never added anything.
foreach ($url in $MustStayUp) {
    try {
        $code = (Invoke-WebRequest $url -Method Head -TimeoutSec 20 `
                    -SkipHttpErrorCheck).StatusCode
    } catch { $code = "unreachable" }
    $colour = if ($code -eq 200) { "Green" } else { "Red" }
    Write-Host ("  {0,-40} {1}" -f $url, $code) -ForegroundColor $colour
}

try {
    $code = (Invoke-WebRequest $VerifyUrl -TimeoutSec 20 -SkipHttpErrorCheck).StatusCode
} catch { $code = "unreachable" }

Write-Host ("  {0,-40} {1}" -f $VerifyUrl, $code)
switch ($code) {
    200 { Write-Host "`nMykronos is reachable." -ForegroundColor Green }
    502 { Write-Host "`nTunnel routes correctly; nothing is listening on 8100 yet. Start the backend." -ForegroundColor Yellow }
    404 { Write-Host "`nStill the catch-all — the ingress rule did not take. If this tunnel's config is managed in the Zero Trust dashboard, add the public hostname there instead." -ForegroundColor Red }
    default { Write-Host "`nUnexpected: $code" -ForegroundColor Red }
}

Write-Host "`nTo roll back: copy the .bak file above over $ServiceConfig and restart Cloudflared.`n"
