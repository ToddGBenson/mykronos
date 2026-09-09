<#
.SYNOPSIS
    Close the image registry to the LAN while leaving the build path open (B-054, D-109).

.DESCRIPTION
    `mykronos-registry` (registry:2) listens on 0.0.0.0:5000 over plain HTTP with
    no `auth:` block in its configuration at all. There is no authentication to
    fail. Anonymous read is demonstrable from any host on the network, and
    anonymous *write* lands on tags this host then runs -- `thehub-demo-backend`
    runs an image pulled from here -- which is code execution on this machine
    from any device on the LAN, with no credential involved.

    Binding to 127.0.0.1 was the obvious fix and would take the build down.
    Concourse's kaniko task pushes to $Registry = "192.168.0.14:5000"; garden
    task containers reach this registry by host IP because they cannot resolve
    Docker service names. The proposed fix and the working pipeline were
    mutually exclusive, which is why this closes the exposure by scope.

    ONE INBOUND BLOCK RULE, SCOPED TO THE LAN.

    The tempting shape is "allow 172.16/12 and loopback, block everything
    else", which is how D-109 states the intent -- and implementing it that way
    literally would take the build down. Windows Defender Firewall evaluates
    **block rules before allow rules**, so a block on `-RemoteAddress Any`
    beats the allow beside it and kaniko's push dies with the LAN access. The
    intent has to be expressed as what is denied.

    What is denied is the LAN, because that is what the exposure is. Every
    write this registry has served arrived from 172.19.0.1 -- the Concourse
    bridge network's gateway -- or from loopback, and neither is in 192.168.0/24.
    Windows does not filter loopback at all, so `localhost:5000` pulls are
    unaffected either way.

    `REGISTRY_AUTH=htpasswd` resolved from Vault is the defence-in-depth version
    and the right follow-up if this host ever moves networks: scope is a
    property of where the machine sits, and authentication is not.

.PARAMETER LanPrefix
    The prefixes to deny, defaulting to this host's own non-Docker IPv4
    subnets. Pass explicitly if this machine gains an interface the default
    would miss.

.PARAMETER Remove
    Delete the rule and restore the previous state. For undoing this in a hurry.

.PARAMETER WhatIf
    Print what would change and touch nothing. Works unelevated, which is the
    point: read the plan first, then run it as administrator.

.EXAMPLE
    .\Set-RegistryScope.ps1 -WhatIf
    .\Set-RegistryScope.ps1              # needs an elevated prompt
    .\Set-RegistryScope.ps1 -Remove

.NOTES
    Verify BOTH halves afterwards, because either alone is a false pass:
      1. From another host on the LAN:  curl http://192.168.0.14:5000/v2/_catalog
         must fail or time out.
      2. Trigger a `build` job in Concourse. It must still push.
    A registry nobody can reach is not the goal; a registry only the build can
    reach is.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string[]]$LanPrefix,
    [switch]$Remove
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# The registry's published port. Named once so a change here cannot half-apply.
$Port = 5000

$RuleName = 'Mykronos registry 5000 - deny the LAN'

function Test-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-LanPrefix {
    <#
        This host's real networks, which is everything that is not Docker's,
        not loopback and not APIPA. Computed rather than hard-coded so a
        machine that changes address does not silently stop being covered --
        the rule is only as good as the list it denies.
    #>
    Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object {
            $_.IPAddress -notmatch '^127\.' -and
            $_.IPAddress -notmatch '^169\.254\.' -and
            $_.IPAddress -notmatch '^172\.(1[6-9]|2[0-9]|3[01])\.'
        } |
        ForEach-Object {
            $octets = $_.IPAddress.Split('.')
            # Normalised to the network address so two addresses on one subnet
            # (this host has a wired and a wireless address on 192.168.0/24)
            # produce one prefix rather than two overlapping rules.
            switch ($_.PrefixLength) {
                24 { '{0}.{1}.{2}.0/24' -f $octets[0], $octets[1], $octets[2] }
                16 { '{0}.{1}.0.0/16' -f $octets[0], $octets[1] }
                default { '{0}/{1}' -f $_.IPAddress, $_.PrefixLength }
            }
        } |
        Sort-Object -Unique
}

if ($Remove) {
    if (Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue) {
        if ($PSCmdlet.ShouldProcess($RuleName, 'Remove firewall rule')) {
            Remove-NetFirewallRule -DisplayName $RuleName
            Write-Host "removed: $RuleName"
            Write-Host ''
            Write-Host 'The registry is open to the LAN again (B-054), which is what D-109 closed.'
        }
    }
    else {
        Write-Host "not present: $RuleName"
    }
    return
}

if (-not $LanPrefix) { $LanPrefix = @(Get-LanPrefix) }

if (-not $LanPrefix) {
    Write-Warning 'No LAN prefix found to deny. Pass -LanPrefix explicitly.'
    exit 1
}

Write-Host "Port        : $Port (mykronos-registry, plain HTTP, no auth: block)"
Write-Host "Denying     : $($LanPrefix -join ', ')"
Write-Host 'Still open  : Docker bridges (172.16/12) and loopback -- the build path'
Write-Host ''

if (-not (Test-Elevated) -and -not $WhatIfPreference) {
    Write-Warning 'Firewall rules need an elevated prompt. Re-run this as administrator.'
    Write-Warning 'Run with -WhatIf to see the plan without changing anything.'
    exit 1
}

$existing = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
if ($existing) {
    # Re-scoped rather than skipped: the machine may have changed address since
    # the rule was written, and a rule denying a subnet this host has left is a
    # rule that protects nothing while looking like it does.
    if ($PSCmdlet.ShouldProcess($RuleName, "Update scope to $($LanPrefix -join ', ')")) {
        Set-NetFirewallRule -DisplayName $RuleName -RemoteAddress $LanPrefix
        Write-Host "updated: $RuleName"
    }
}
elseif ($PSCmdlet.ShouldProcess($RuleName, 'Create block rule')) {
    New-NetFirewallRule -DisplayName $RuleName `
        -Direction Inbound -Action Block -Protocol TCP -LocalPort $Port `
        -RemoteAddress $LanPrefix -Profile Any `
        -Description ('The registry takes anonymous writes to tags this host runs. ' +
                      'Docker bridges and loopback still reach it. B-054 / D-109.') | Out-Null
    Write-Host "created: $RuleName"
}

Write-Host ''
Write-Host 'Now verify both halves -- either one alone is a false pass:'
Write-Host '  1. From another LAN host: curl http://192.168.0.14:5000/v2/_catalog  (must fail)'
Write-Host '  2. Trigger a Concourse `build` job                                   (must still push)'
Write-Host ''
Write-Host 'Undo with: .\Set-RegistryScope.ps1 -Remove'
