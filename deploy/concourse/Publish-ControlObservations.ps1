<#
.SYNOPSIS
    Collect what this host publishes and post it to Mykronos as control
    observations (TheHub #60826). Reads only -- changes nothing.

.DESCRIPTION
    The threat model's exposure claims are declarations: a person says the demo
    backend on tcp/8002 is `internal`. This script reads what the host actually
    does, from the host itself (vantage `host`):

      * docker: every running container's published ports and the address each
        is bound to (`docker ps` + `docker inspect`). 0.0.0.0:8002 and
        127.0.0.1:5433 are different facts and both are recorded.
      * cloudflared: the tunnel's ingress rules (config.yml) -- which public
        hostname routes to which local service port. A tunnel publishes a port
        no LAN scan can see; this is the evidence that it does (#348).
      * the firewall: the evidence Get-HostControlEvidence.ps1 collects, so the
        registry's LAN scope is judged by host_controls on the server.

    Like Get-HostControlEvidence.ps1 it does NOT judge. It posts a document
    (`mykronos.host-observations/1`) and the server translates it into
    observations under test (control_observations.from_host_document). A
    section that cannot be read is recorded in `errors` and becomes `unknown`
    on the server; a run that resolves nothing posts `unknown`, never `pass`.

.PARAMETER MykronosUrl
    The Mykronos API, e.g. http://localhost:8180. Defaults to $env:MYKRONOS_URL.

.PARAMETER MykronosToken
    The repository's ingestion token, granted the `network` capability.
    Defaults to $env:MYKRONOS_INGESTION_TOKEN. See NOTES for where it comes from.

.PARAMETER MykronosGateToken
    The perimeter gate token (gate.py), sent as X-Hub-Token when the API is
    reached through the gate. Defaults to $env:MYKRONOS_GATE_TOKEN.

.PARAMETER CloudflaredConfig
    The tunnel config to read. Defaults to %USERPROFILE%\.cloudflared\config.yml.

.PARAMETER ContainerFilter
    Wildcard on container names, for a host that runs several repositories'
    services: post only the ones this token's repository owns.

.PARAMETER RegistryPort
    Passed to Get-HostControlEvidence.ps1 -Port.

.PARAMETER Path
    Write the document here instead of posting it ('-' for stdout). Use it to
    see exactly what would be sent.

.EXAMPLE
    .\Publish-ControlObservations.ps1 -Path -
    $env:MYKRONOS_INGESTION_TOKEN = '<token>'; .\Publish-ControlObservations.ps1 -MykronosUrl http://localhost:8180 -ContainerFilter 'thehub*'

.NOTES
    ASCII only -- see setup.ps1.

    THE TOKEN. A repository's ingestion token: `mykronos mint-token <owner/repo>
    --grant network` issues one (printed once), or an existing token for the
    repository -- deploy\concourse\.env MYKRONOS_INGESTION_TOKEN, or the Vault
    path repair-ingestion-token.ps1 delivers to -- with the grant added by
    `mykronos grant <owner/repo> network`. Without the network grant the server
    answers 403: an observation can lower a finding's environmental score, so
    writing one is a grant, not a side effect of holding a token.

    Observations are filed under the token's repository (spec 05 section 4):
    run once per repository, with -ContainerFilter scoping the containers.
#>

[CmdletBinding()]
param(
    [string]$MykronosUrl = $env:MYKRONOS_URL,
    [string]$MykronosToken = $env:MYKRONOS_INGESTION_TOKEN,
    [string]$MykronosGateToken = $env:MYKRONOS_GATE_TOKEN,
    [string]$CloudflaredConfig = (Join-Path $env:USERPROFILE '.cloudflared\config.yml'),
    [string]$ContainerFilter = '*',
    [int]$RegistryPort = 5000,
    [string]$Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$collectorVersion = '1'
$errors = [ordered]@{}

# Referenced here as well as inside the scriptblocks below, for the reason
# Get-HostControlEvidence.ps1 gives: PSScriptAnalyzer does not see a parameter
# used only inside a scriptblock.
$filter = $ContainerFilter
$configPath = $CloudflaredConfig
$port = $RegistryPort

function Get-Section {
    <#
        Run one collection; record a failure rather than dropping the section.
        "Could not read" and "read, and nothing is there" are different facts.
    #>
    param([string]$Name, [scriptblock]$Body)

    try {
        return (& $Body)
    } catch {
        $errors[$Name] = $_.Exception.Message
        return $null
    }
}

# -- docker: published ports and the address each is bound to ---------------
$docker = Get-Section 'docker' {
    $names = & docker ps --format '{{.Names}}' 2>&1
    if ($LASTEXITCODE -ne 0) { throw "docker ps exited $LASTEXITCODE : $names" }
    $selected = @($names | ForEach-Object { [string]$_ } | Where-Object { $_.Trim() -and $_ -like $filter })

    $containers = @()
    if ($selected.Count -gt 0) {
        $raw = & docker inspect @selected 2>&1
        if ($LASTEXITCODE -ne 0) { throw "docker inspect exited $LASTEXITCODE" }
        foreach ($item in @($raw | Out-String | ConvertFrom-Json)) {
            $ports = [ordered]@{}
            $settings = $item.NetworkSettings
            if ($settings -and $settings.Ports) {
                foreach ($property in $settings.Ports.PSObject.Properties) {
                    $bindings = @()
                    foreach ($binding in @($property.Value)) {
                        if ($null -eq $binding) { continue }
                        $bindings += [ordered]@{
                            HostIp   = [string]$binding.HostIp
                            HostPort = [string]$binding.HostPort
                        }
                    }
                    $ports[$property.Name] = $bindings
                }
            }
            $containers += [ordered]@{
                name  = ([string]$item.Name).TrimStart('/')
                ports = $ports
            }
        }
    }
    [ordered]@{ containers = $containers }
}

# -- cloudflared: which public hostname routes to which local port -----------
#
# The YAML is parsed on the server, under test. An absent or unreadable file
# is an error here and `unknown` there -- never "nothing is published".
$cloudflared = Get-Section 'cloudflared' {
    if (-not (Test-Path -LiteralPath $configPath)) {
        throw "No cloudflared config at $configPath"
    }
    [ordered]@{
        path        = $configPath
        config_text = (Get-Content -LiteralPath $configPath -Raw)
    }
}

# -- the firewall: Get-HostControlEvidence.ps1's document, judged server-side -
$hostControls = Get-Section 'host_controls' {
    $script = Join-Path $PSScriptRoot 'Get-HostControlEvidence.ps1'
    $json = & $script -Port $port -Path '-' | Out-String
    $json | ConvertFrom-Json
}

$document = [ordered]@{
    schema            = 'mykronos.host-observations/1'
    collector_version = $collectorVersion
    collected_at      = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    host              = $env:COMPUTERNAME
    docker            = $docker
    cloudflared       = $cloudflared
    host_controls     = $hostControls
    errors            = $errors
}

foreach ($key in $errors.Keys) {
    Write-Warning "$key could not be read and will be recorded as unknown: $($errors[$key])"
}

if ($Path) {
    $json = $document | ConvertTo-Json -Depth 12
    if ($Path -eq '-') {
        Write-Output $json
    } else {
        Set-Content -LiteralPath $Path -Value $json -Encoding ascii
        Write-Output "wrote: $Path"
    }
    return
}

if (-not $MykronosUrl -or -not $MykronosToken) {
    throw 'Set -MykronosUrl and -MykronosToken (or MYKRONOS_URL / MYKRONOS_INGESTION_TOKEN), or pass -Path to write the document instead.'
}

$body = [ordered]@{
    collector     = "Publish-ControlObservations.ps1@$($env:COMPUTERNAME)"
    host_document = $document
} | ConvertTo-Json -Depth 12

$headers = @{
    'Authorization' = "Bearer $MykronosToken"
    'Content-Type'  = 'application/json'
}
if ($MykronosGateToken) { $headers['X-Hub-Token'] = $MykronosGateToken }

$result = Invoke-RestMethod -Method Post -Uri "$($MykronosUrl.TrimEnd('/'))/api/ingest/control-observations" `
    -Headers $headers -Body $body -TimeoutSec 60
Write-Output $result
