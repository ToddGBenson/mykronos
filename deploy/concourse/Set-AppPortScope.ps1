<#
.SYNOPSIS
    Close the published application ports to the LAN while leaving the build
    path open. Companion to Set-RegistryScope.ps1, same shape, same reasoning.

.DESCRIPTION
    A network assessment on 2026-09-17 found seven container ports published on
    0.0.0.0 and reachable from the whole flat /24 -- a segment shared with
    consumer IoT devices this host has no reason to trust. Port 5000 was
    already handled by Set-RegistryScope.ps1. These six were not:

        8000  thehub-backend           (prod)
        8002  thehub-demo-backend      (demo)
        8009  thehub-staging-backend   (staging)
        8081  thehub-staging-frontend  (staging nginx)
        8100  mykronos-backend
        9000  mykronos-minio           (S3 API -- console 9001 is already loopback)

    Added 2026-09-30: the mykronos demo stack (deploy/demo), which is meant
    to be destroyed after each DAST run but in practice stays up:

        8201  mykronos-demo-backend    (demo, fixed demo tokens)
        8290  mykronos-demo-zap        (ZAP API with api.disablekey=true)
        3200  mykronos-demo-frontend   (demo)

    8290 is the one that matters: ZAP's API answers without a key, so anyone
    on the segment could drive the scanner.

    They are reachable despite having no allow rule of their own, because
    `Docker Desktop Backend` carries one inbound allow for
    com.docker.backend.exe on ANY port from ANY address. Port 8000 additionally
    has two explicit allow rules ('TheHub Backend', 'TheHub Port 8000'). Neither
    matters here: Windows Defender Firewall evaluates block rules before allow
    rules, so one block wins over all three.

    BINDING THESE TO 127.0.0.1 WOULD TAKE THE PIPELINE DOWN -- as of 2026-09-30.

    UPDATE 2026-10-21: no longer true, and the services have since moved to
    loopback (mykronos #920, TheHub #457). Docker Desktop forwards its host
    gateway (192.168.65.254) to the host's loopback, so a Concourse task or a
    container still reaches a 127.0.0.1-bound port there; probed 2026-10-21
    for both a container's HTTP request and the daemon's localhost push/pull.
    Keep this rule anyway: it is the second layer, and it still covers any
    service that publishes on 0.0.0.0 by mistake. The reasoning below is the
    original, kept for the record.

    That was the obvious fix and it was wrong for exactly the reason the registry
    fix was. Concourse tasks reach these services by host IP, because a garden
    container cannot resolve Docker service names -- see the comment at
    set-pipeline.ps1:182, "`host.docker.internal` or `minio`. An IP needs no
    resolver." The pipeline vars say so directly:

        minio-endpoint:    http://192.168.0.14:9000
        mykronos-url:      http://192.168.0.14:8100
        thehub-demo-url:   http://192.168.0.14:8002
        ProdUrl:           http://192.168.0.14:8000
        StagingUrl:        http://192.168.0.14:8081

    So the exposure is closed by scope, not by binding. Traffic from the
    Concourse bridge gateway (172.19.0.1) and from loopback is untouched --
    neither is in 192.168.0/24, and Windows does not filter loopback at all.

    Per-service authentication is the defence-in-depth version and the right
    follow-up, particularly for MinIO. Scope is a property of where the machine
    sits; authentication is not. When this host moves network segment, revisit
    both.

.PARAMETER LanPrefix
    The prefixes to deny, defaulting to this host's own non-Docker IPv4
    subnets. Pass explicitly if this machine gains an interface the default
    would miss.

.PARAMETER Port
    The ports to scope. Defaults to the nine above.

.PARAMETER Remove
    Delete the rule and restore the previous state. For undoing this in a hurry.

.PARAMETER WhatIf
    Print what would change and touch nothing. Works unelevated, which is the
    point: read the plan first, then run it as administrator.

.EXAMPLE
    .\Set-AppPortScope.ps1 -WhatIf
    .\Set-AppPortScope.ps1              # needs an elevated prompt
    .\Set-AppPortScope.ps1 -Remove

.NOTES
    Verify BOTH halves afterwards, because either alone is a false pass:
      1. From another host on the LAN: curl http://192.168.0.14:8000/
         must fail or time out.
      2. Trigger a Concourse job that hits MinIO or a deploy smoke-check.
         It must still pass.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string[]]$LanPrefix,
    [int[]]$Port = @(8000, 8002, 8009, 8081, 8100, 9000, 8201, 8290, 3200),
    [switch]$Remove
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RuleName = 'Mykronos app ports - deny the LAN'

function Test-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-LanPrefix {
    <#
        This host's real networks -- everything that is not Docker's, not
        loopback and not APIPA. Computed rather than hard-coded so a machine
        that changes address does not silently stop being covered. Identical
        to Set-RegistryScope.ps1 by intent: two rules that disagree about what
        "the LAN" means is a gap waiting to happen.
    #>
    Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object {
            $_.IPAddress -notmatch '^127\.' -and
            $_.IPAddress -notmatch '^169\.254\.' -and
            $_.IPAddress -notmatch '^172\.(1[6-9]|2[0-9]|3[01])\.'
        } |
        ForEach-Object {
            $octets = $_.IPAddress.Split('.')
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
            Write-Host 'The app ports are open to the LAN again. That is finding F-15.'
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

Write-Host "Ports       : $($Port -join ', ')"
Write-Host "Denying     : $($LanPrefix -join ', ')"
Write-Host 'Still open  : Docker bridges (172.16/12) and loopback -- the build path'
Write-Host ''
Write-Host 'Note: block beats allow in Windows Defender Firewall, so this one rule'
Write-Host '      overrides "Docker Desktop Backend" (any port, any address) and the'
Write-Host '      two explicit allow rules on 8000.'
Write-Host ''

if (-not (Test-Elevated) -and -not $WhatIfPreference) {
    Write-Warning 'Firewall rules need an elevated prompt. Re-run this as administrator.'
    Write-Warning 'Run with -WhatIf to see the plan without changing anything.'
    exit 1
}

$existing = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
if ($existing) {
    # Re-scoped rather than skipped, for the same reason as the registry rule:
    # a rule denying a subnet this host has left protects nothing while looking
    # like it does.
    if ($PSCmdlet.ShouldProcess($RuleName, "Update scope to $($LanPrefix -join ', ') on $($Port -join ',')")) {
        Set-NetFirewallRule -DisplayName $RuleName -RemoteAddress $LanPrefix
        Set-NetFirewallRule -DisplayName $RuleName -LocalPort $Port -Protocol TCP
        Write-Host "updated: $RuleName"
    }
}
elseif ($PSCmdlet.ShouldProcess($RuleName, 'Create block rule')) {
    New-NetFirewallRule -DisplayName $RuleName `
        -Direction Inbound -Action Block -Protocol TCP -LocalPort $Port `
        -RemoteAddress $LanPrefix -Profile Any `
        -Description ('App/staging/demo tiers and the MinIO S3 API were reachable from ' +
                      'the whole flat LAN via the Docker Desktop Backend allow rule. ' +
                      'Docker bridges and loopback still reach them, which is the ' +
                      'pipeline path. Assessment 2026-09-17 finding F-15.') | Out-Null
    Write-Host "created: $RuleName"
}

Write-Host ''
Write-Host 'Now verify both halves -- either one alone is a false pass:'
Write-Host '  1. From another LAN host: curl http://192.168.0.14:8000/   (must fail)'
Write-Host '  2. Trigger a Concourse job that reaches MinIO or a deploy smoke-check'
Write-Host '                                                             (must still pass)'
Write-Host ''
Write-Host 'Undo with: .\Set-AppPortScope.ps1 -Remove'
