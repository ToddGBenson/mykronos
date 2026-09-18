<#
.SYNOPSIS
    Collect the evidence that says whether the registry's LAN scope still holds
    (B-054, D-109). Reads only -- changes nothing.

.DESCRIPTION
    `Set-RegistryScope.ps1` applies the control. Nothing re-reads it, and the
    verification its own notes give -- `curl http://192.168.0.14:5000/v2/_catalog`
    -- is the one an operator can actually run only from the wrong machine. Run
    from this host it returns the catalog whether the rule is in force, narrowed,
    disabled or deleted, because Windows Defender Firewall does not filter
    traffic from a host to its own addresses. The script says so itself, in
    passing: "Windows does not filter loopback at all."

    So this collects the rule rather than probing the port:

      * every inbound rule whose port filter names the port, enabled or not,
        with its action, protocol, profiles and remote address ranges;
      * every address this host holds on a real network, with the network
        profile Windows has categorised its interface under -- a rule scoped to
        Private does not apply to the wireless address Windows calls Public;
      * what Docker publishes, so a new 0.0.0.0 binding has something to be
        compared against;
      * whether the registry has gained authentication, which would mean the
        firewall rule has stopped being the only control.

    The output is a JSON document. `mykronos host-controls <file>` judges it --
    the arithmetic on the address ranges is there, in Python, under test,
    because "192.168.0.1-192.168.0.13, 192.168.0.15-192.168.0.254" reads as
    covering the LAN in any listing and leaves this host's own .14 uncovered.

    -IncludeLocalProbe runs the naive check as well. It is collected so the
    report can carry it labelled `not_evidence` beside the real assertions:
    deleting it does not stop anyone running it, and an operator who curls the
    registry from here gets the catalog and a feeling of having checked
    something. Better to print that the feeling is unearned than to leave the
    check to be run somewhere nothing contradicts it.

.PARAMETER Port
    The port the control is about. Defaults to the registry's 5000.

.PARAMETER Path
    Where to write the document. Defaults to host-controls.json beside this
    script. Prints to stdout with -Path '-'.

.PARAMETER IncludeLocalProbe
    Also request the registry from this host, and record the answer as the
    non-evidence it is.

.EXAMPLE
    .\Get-HostControlEvidence.ps1
    .\Get-HostControlEvidence.ps1 -Path - | Out-File evidence.json
    mykronos host-controls .\host-controls.json

.NOTES
    ASCII only -- see deploy\concourse\setup.ps1.

    Needs no elevation: reading firewall rules does not, and nothing here
    writes one. If a section cannot be read it is recorded in `errors` rather
    than omitted, because the judging side treats an unread section as
    `unknown` and fails the run. A collector that silently dropped a section it
    could not read would turn this into another check that cannot fail.
#>

[CmdletBinding()]
param(
    [int]$Port = 5000,
    [string]$Path = (Join-Path $PSScriptRoot 'host-controls.json'),
    [string]$RegistryContainer = 'mykronos-registry',
    [switch]$IncludeLocalProbe
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$errors = [ordered]@{}

# Referenced here as well as inside the collection scriptblock below:
# PSScriptAnalyzer does not see a parameter used only inside a scriptblock and
# reports it unused, which the estate's own psscriptanalyzer adapter would then
# ingest as a finding about a script whose job is to stop false findings.
$container = $RegistryContainer

function Get-Section {
    <#
        Run one collection and never let it take the document down, but never
        let it quietly succeed either. "Could not read" and "read, and the
        answer is no" are different facts and the report must be able to tell
        them apart -- the same rule Collect-EndpointPosture.ps1 states.
    #>
    param([string]$Name, [scriptblock]$Body)

    try {
        return (& $Body)
    } catch {
        $errors[$Name] = $_.Exception.Message
        return $null
    }
}

# -- Firewall rules that could deny this port -------------------------------
#
# Inbound Block rules, enabled or not. Disabled ones are collected on purpose:
# a disabled Block rule is the most useful line in the document when the
# control has gone, because it names what somebody switched off. Allow rules
# are not collected -- Windows evaluates Block before Allow, so what is denied
# is decided by the Block rules alone, and the inbound Allow set on a Windows
# desktop is several hundred rules none of which can answer this question.
$rules = Get-Section 'firewall_rules' {
    $out = @()
    foreach ($rule in (Get-NetFirewallRule -Direction Inbound -Action Block)) {
        $filter = $rule | Get-NetFirewallPortFilter
        $protocol = [string]$filter.Protocol
        if ($protocol -ne 'TCP' -and $protocol -ne 'Any' -and $protocol -ne '6') { continue }

        $ports = @($filter.LocalPort | ForEach-Object { [string]$_ })
        $named = $false
        foreach ($text in $ports) {
            if ($text -eq 'Any' -or $text -eq [string]$Port) { $named = $true; break }
            if ($text -match '^(\d+)-(\d+)$') {
                if ([int]$Matches[1] -le $Port -and $Port -le [int]$Matches[2]) { $named = $true; break }
            }
        }
        if (-not $named) { continue }

        $address = $rule | Get-NetFirewallAddressFilter

        $out += [ordered]@{
            display_name     = [string]$rule.DisplayName
            name             = [string]$rule.Name
            enabled          = [bool]($rule.Enabled.ToString() -eq 'True')
            direction        = $rule.Direction.ToString()
            action           = $rule.Action.ToString()
            protocol         = $protocol
            local_ports      = $ports
            remote_addresses = @($address.RemoteAddress | ForEach-Object { [string]$_ })
            profiles         = @($rule.Profile.ToString())
        }
    }
    # A port nothing names is a legitimate answer (an empty array), not a
    # failure. `errors` is for a read that could not happen.
    ,$out
}

# -- This host's own LAN addresses, with their profiles ----------------------
#
# Docker's bridges, loopback and APIPA are not the LAN and the control is not
# about them -- the same exclusion Set-RegistryScope.ps1's Get-LanPrefix makes,
# for the same reason.
$lan = Get-Section 'lan_addresses' {
    $profiles = @{}
    foreach ($connection in (Get-NetConnectionProfile)) {
        $profiles[[string]$connection.InterfaceAlias] = $connection.NetworkCategory.ToString()
    }

    $out = @()
    foreach ($address in (Get-NetIPAddress -AddressFamily IPv4)) {
        $ip = [string]$address.IPAddress
        if ($ip -match '^127\.' -or $ip -match '^169\.254\.') { continue }
        if ($ip -match '^172\.(1[6-9]|2[0-9]|3[01])\.') { continue }

        $alias = [string]$address.InterfaceAlias
        $category = ''
        if ($profiles.ContainsKey($alias)) { $category = $profiles[$alias] }
        # Windows reports a domain-joined network as DomainAuthenticated; the
        # rule's own profile field calls it Domain.
        if ($category -eq 'DomainAuthenticated') { $category = 'Domain' }

        $octets = $ip.Split('.')
        $prefix = switch ([int]$address.PrefixLength) {
            24 { '{0}.{1}.{2}.0/24' -f $octets[0], $octets[1], $octets[2] }
            16 { '{0}.{1}.0.0/16' -f $octets[0], $octets[1] }
            default { '{0}/{1}' -f $ip, [int]$address.PrefixLength }
        }

        $out += [ordered]@{
            prefix    = $prefix
            address   = $ip
            interface = $alias
            profile   = $category
        }
    }
    ,$out
}

# -- What this host publishes -----------------------------------------------
$published = Get-Section 'published_ports' {
    $lines = & docker ps --format '{{.Names}} {{.Ports}}' 2>&1
    if ($LASTEXITCODE -ne 0) { throw "docker ps exited $LASTEXITCODE : $lines" }
    $out = @()
    foreach ($line in $lines) {
        $text = [string]$line
        if (-not $text.Trim()) { continue }
        $name, $ports = $text.Split(' ', 2)
        if (-not $ports) { continue }
        foreach ($binding in $ports.Split(',')) {
            $trimmed = $binding.Trim()
            # Only bindings that reach an interface. `5432/tcp` with no host
            # side is published to nothing and is not the event this watches.
            if ($trimmed -match '->') { $out += "$name $trimmed" }
        }
    }
    ,(@($out | Sort-Object))
}

# -- Is the firewall rule still the only control -----------------------------
$registryAuth = Get-Section 'registry_auth' {
    $raw = & docker inspect $container 2>&1
    if ($LASTEXITCODE -ne 0) { throw "docker inspect $container exited $LASTEXITCODE" }
    $inspected = ($raw | Out-String | ConvertFrom-Json)[0]

    $authEnv = @($inspected.Config.Env | Where-Object { $_ -like 'REGISTRY_AUTH*' })
    $configMounts = @(
        $inspected.Mounts |
            Where-Object { [string]$_.Destination -like '/etc/docker/registry*' } |
            ForEach-Object { [string]$_.Destination }
    )

    $configured = ($authEnv.Count -gt 0)
    $detail = if ($configured) {
        'REGISTRY_AUTH set: ' + ($authEnv -join ', ')
    } elseif ($configMounts.Count -gt 0) {
        # A mounted config could carry an auth: block this cannot see from
        # outside the container. Not a pass and not a failure: unreadable.
        throw ('A configuration is mounted at ' + ($configMounts -join ', ') +
               ' and may carry an auth: block this cannot read from here.')
    } else {
        'No REGISTRY_AUTH* environment and no configuration mount: the image default ' +
        'config.yml has no auth: block, so there is no authentication to fail.'
    }

    [ordered]@{ configured = $configured; detail = $detail }
}

# -- The check that proves nothing, collected so it can be labelled ----------
$probe = $null
if ($IncludeLocalProbe) {
    $probe = Get-Section 'local_probe' {
        $self = $null
        if ($lan -and @($lan).Count -gt 0) { $self = [string](@($lan)[0].address) }
        if (-not $self) { $self = '127.0.0.1' }
        $url = "http://${self}:${Port}/v2/_catalog"
        try {
            $response = Invoke-WebRequest -Uri $url -TimeoutSec 5 -UseBasicParsing
            [ordered]@{ url = $url; status_code = [int]$response.StatusCode }
        } catch {
            [ordered]@{ url = $url; status_code = $null; detail = $_.Exception.Message }
        }
    }
}

$document = [ordered]@{
    schema           = 'mykronos.host-controls/1'
    collected_at     = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    host             = $env:COMPUTERNAME
    port             = $Port
    lan_addresses    = @($lan)
    firewall_rules   = @($rules)
    published_ports  = @($published)
    registry_auth    = $registryAuth
    local_probe      = $probe
    errors           = $errors
}

$json = $document | ConvertTo-Json -Depth 6

if ($Path -eq '-') {
    $json
} else {
    Set-Content -Path $Path -Value $json -Encoding ascii
    Write-Host "wrote: $Path"
    Write-Host ''
    Write-Host "Judge it with:  mykronos host-controls `"$Path`""
    if ($errors.Count -gt 0) {
        Write-Host ''
        Write-Warning "$($errors.Count) section(s) could not be read. Each one fails the check rather than passing it:"
        foreach ($key in $errors.Keys) { Write-Warning "  $key : $($errors[$key])" }
    }
}
