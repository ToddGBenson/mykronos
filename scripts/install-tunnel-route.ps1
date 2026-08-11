<#
.SYNOPSIS
    Publish the updated cloudflared ingress to the service, and restart it.

.DESCRIPTION
    The cloudflared service runs as LocalSystem, which keeps its own config at
    C:\Windows\System32\config\systemprofile\.cloudflared\config.yml - a copy
    made when the service was installed, entirely separate from the one in
    your user profile. Editing ~/.cloudflared/config.yml therefore changes
    nothing until it is copied across, which is why a new hostname resolves,
    reaches the tunnel, and then falls through to the 404 catch-all.

    This backs up the service's copy, shows you what is being replaced, copies
    the user config over it, restarts the service, and verifies.

.NOTES
    Run elevated. Restarting the tunnel briefly drops every hostname it
    serves - hub, blog and demo included. It is seconds, but it is not zero.

    Deliberately ASCII-only. Windows PowerShell 5.1 reads a script file with
    no byte-order mark as CP1252, so a UTF-8 em-dash arrives as three
    characters, the last of which is a double quote that closes whatever
    string it sits in. The result is a cascade of parser errors pointing at
    lines that are not the problem. Keeping to ASCII means the file parses
    identically whichever shell and whichever encoding guess it meets.

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

# Works on both Windows PowerShell 5.1 and PowerShell 7. `-SkipHttpErrorCheck`
# would be shorter but is 7-only, and 5.1 is what an elevated Start-menu
# PowerShell usually is - so on the exact shell this script is written for, it
# would throw on any non-2xx response, which includes the 404 we most need to
# report clearly.
function Get-StatusCode {
    param([string]$Url, [switch]$Head)
    # Not $args: that is an automatic variable, and shadowing it is the kind of
    # thing that works until something in the call path expects the real one.
    $request = @{ Uri = $Url; TimeoutSec = 20; UseBasicParsing = $true }
    if ($Head) { $request["Method"] = "Head" }
    try {
        return [int](Invoke-WebRequest @request).StatusCode
    } catch {
        $response = $_.Exception.Response
        if ($response -and $response.StatusCode) { return [int]$response.StatusCode }
        return "unreachable"
    }
}

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
    Write-Host "(none - the service config does not exist yet)" -ForegroundColor DarkGray
    New-Item -ItemType Directory -Force -Path (Split-Path $ServiceConfig) | Out-Null
}

Write-Host "`n=== With ===" -ForegroundColor Cyan
Get-Content $UserConfig | Write-Host

Copy-Item $UserConfig $ServiceConfig -Force
Write-Host "`nCopied." -ForegroundColor Green

Write-Host "`nRestarting the tunnel - every hostname drops for a few seconds..." `
    -ForegroundColor Yellow
Restart-Service Cloudflared -Force
Start-Sleep -Seconds 10

Write-Host "`n=== Verifying ===" -ForegroundColor Cyan

# The hostnames that were already working matter more than the new one: a
# config that breaks them is worse than one that never added anything.
foreach ($url in $MustStayUp) {
    $code = Get-StatusCode -Url $url -Head
    $colour = if ($code -eq 200) { "Green" } else { "Red" }
    Write-Host ("  {0,-40} {1}" -f $url, $code) -ForegroundColor $colour
}

$code = Get-StatusCode -Url $VerifyUrl
Write-Host ("  {0,-40} {1}" -f $VerifyUrl, $code)

switch ($code) {
    200 {
        Write-Host "`nMykronos is reachable." -ForegroundColor Green
    }
    502 {
        Write-Host ("`nTunnel routes correctly; nothing is listening on 8100 yet. " +
            "Start the backend.") -ForegroundColor Yellow
    }
    404 {
        Write-Host ("`nStill the catch-all - the ingress rule did not take. If this " +
            "tunnel is managed in the Zero Trust dashboard, add the public hostname " +
            "there instead; a local config file is ignored in that mode.") -ForegroundColor Red
    }
    default {
        Write-Host "`nUnexpected: $code" -ForegroundColor Red
    }
}

Write-Host "`nTo roll back: copy the .bak file above over $ServiceConfig and restart Cloudflared.`n"
