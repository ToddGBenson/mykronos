<#
.SYNOPSIS
    The Windows half of adding a Concourse worker on another host: the
    firewall scope, its key, the TSA on the LAN address and the install bundle.

.DESCRIPTION
    TheHub #61659, D-181. The two workers in docker-compose.yml share one
    Docker VM with production, and their heavy lanes have killed each other
    for memory. A worker on a Linux box takes the compute-only steps off the
    VM. It registers to the same web node over the TSA (SSH, port 2222) with
    a key pair of its own. The steps run in this order, and the order is the
    point: nothing publishes 2222 on the LAN before the LAN is denied it.

      1. Firewall FIRST. A Windows Firewall BLOCK rule must deny TCP 2222 from
         every address of this host's LAN prefix except -LinuxIp. Needed
         because 'Docker Desktop Backend' allows any port from any address,
         and block beats allow (Set-AppPortScope.ps1 has the record). An
         existing enabled block rule that already does this - for example
         'Mykronos app ports - deny the LAN' once it lists 2222 and carves the
         runner out - is detected and reused; no second rule is made. When the
         rule cannot land (not elevated, or -SkipFirewall) the script stops
         here and changes nothing, unless -IUnderstandLanExposure is given.
      2. The worker's key pair is generated with the same `generate-key` the
         other workers' keys came from, straight into the bundle directory.
         Only the .pub is copied to keys\<Name>_key.pub: keys\ is mounted
         read-only into the web node and both compose workers, and the
         private key has no business in any of them.
      3. The .pub is appended to keys\authorized_worker_keys (setup.ps1 keeps
         every *_key.pub there, so a re-run of setup.ps1 no longer drops it).
      4. .env gets CONCOURSE_TSA_BIND_IP (this host's LAN address).
      5. `docker compose up -d concourse` recreates the web node so it
         publishes 2222 there and reads the new authorized key (-SkipCompose:
         a SIGHUP reloads the key list instead and 2222 stays unpublished).
      6. The bundle is completed: the TSA host public key, worker.conf naming
         this host, and the Linux install script beside the private key.
         Copy it to the Linux box, run the script there as root, then delete
         the bundle here.

    Re-running is safe from any partial state: an existing rule, key, list
    entry or .env line is detected and kept. A private key left in keys\ by
    an earlier version of this script is moved into the bundle. -WhatIf
    prints the plan and writes nothing.

    Nothing here prints a key, a token or a line of .env.

    The deny covers this host's on-link prefix only (the interface's own
    address and prefix length), the same "LAN" Set-AppPortScope.ps1 denies.
    A source routed in from another subnet is not in it; on a flat home LAN
    there is none, and the TSA still admits only the listed keys.

.PARAMETER Name
    The worker's name as `fly workers` will show it. Lowercase letters,
    digits and hyphens. Default linux-1.

.PARAMETER LinuxIp
    The Linux box's LAN address: the one address the firewall rule lets
    through to 2222. Required unless -SkipFirewall.

.PARAMETER Tag
    The placement tag the worker carries. Steps that say `tags: [<Tag>]`
    run on it and nothing else does. Default linux. Routing jobs to it is a
    pipeline change of its own (D-181); this script only adds the worker.

.PARAMETER TsaBindIp
    The address the web node publishes 2222 on. Default: this host's LAN
    IPv4 address (the one that is not loopback, APIPA or a Docker/WSL range).

.PARAMETER SkipCompose
    Do not recreate the web node. The authorized keys are reloaded with
    SIGHUP instead; 2222 stays unpublished until a run without this switch.

.PARAMETER SkipFirewall
    Do not look at or touch the firewall. Refused without
    -IUnderstandLanExposure, because the .env line it then writes publishes
    2222 to the whole LAN at the next recreate.

.PARAMETER IUnderstandLanExposure
    Continue when the block rule cannot be put in place in this run (not
    elevated, or -SkipFirewall). 2222 is then reachable from the whole LAN,
    gated only by the TSA's key list, until the rule exists.

.PARAMETER BundleRoot
    Where <Name>-bundle\ is written. Default deploy\concourse\bundles
    (git-ignored, and outside keys\, which containers mount).

.EXAMPLE
    # From an elevated prompt (documentation addresses; use your own):
    .\Add-LinuxWorker.ps1 -LinuxIp 192.0.2.50
    then: scp -r .\bundles\linux-1-bundle user@192.0.2.50:~/
          ssh user@192.0.2.50 'sudo bash ~/linux-1-bundle/install-concourse-worker.sh'
          Remove-Item -Recurse .\bundles\linux-1-bundle
    then: fly -t mykronos workers

.NOTES
    ASCII only (see setup.ps1).
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidatePattern('^[a-z0-9][a-z0-9-]*$')]
    [string]$Name = 'linux-1',

    [ValidatePattern('^(\d{1,3}\.){3}\d{1,3}$')]
    [string]$LinuxIp,

    [ValidatePattern('^[a-z0-9][a-z0-9,-]*$')]
    [string]$Tag = 'linux',

    [ValidatePattern('^(\d{1,3}\.){3}\d{1,3}$')]
    [string]$TsaBindIp,

    [switch]$SkipCompose,
    [switch]$SkipFirewall,
    [switch]$IUnderstandLanExposure,

    [string]$KeyDir = (Join-Path $PSScriptRoot 'keys'),
    [string]$EnvFile = (Join-Path $PSScriptRoot '.env'),
    [string]$ComposeDir = $PSScriptRoot,
    [string]$BundleRoot = (Join-Path $PSScriptRoot 'bundles')
)

$ErrorActionPreference = 'Stop'
$image = 'concourse/concourse:8.3.3'
$ruleName = 'Mykronos Concourse TSA 2222 - deny the LAN except the Linux worker'
$tsaPort = 2222
$installScript = Join-Path $PSScriptRoot 'linux-worker\install-concourse-worker.sh'

function Test-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-LanAddress {
    <#
        This host's real IPv4 interface(s): not loopback, not APIPA, not the
        Docker/WSL 172.16/12 ranges. The same definition Set-AppPortScope.ps1
        uses for "the LAN", so the publish and the deny agree about it.
    #>
    Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object {
            $_.IPAddress -notmatch '^127\.' -and
            $_.IPAddress -notmatch '^169\.254\.' -and
            $_.IPAddress -notmatch '^172\.(1[6-9]|2[0-9]|3[01])\.'
        }
}

function ConvertTo-UInt32 ([string]$ip) {
    $b = [System.Net.IPAddress]::Parse($ip).GetAddressBytes()
    [Array]::Reverse($b)
    [BitConverter]::ToUInt32($b, 0)
}

function ConvertFrom-UInt32 ([uint32]$n) {
    $b = [BitConverter]::GetBytes($n)
    [Array]::Reverse($b)
    ([System.Net.IPAddress]::new($b)).ToString()
}

function Get-PrefixMask ([int]$PrefixLength) {
    if ($PrefixLength -eq 0) { [uint32]0 } else { [uint32]([uint32]::MaxValue -shl (32 - $PrefixLength) -band [uint32]::MaxValue) }
}

function Get-DenyRanges {
    <#
        The on-link LAN prefix (from the interface's address and prefix
        length) with one address cut out, as the `a-b` ranges Windows Firewall
        takes for -RemoteAddress. A block rule cannot say "except", so the
        exception is the gap between two ranges. Addresses outside the prefix
        are not denied; see the header.
    #>
    param([string]$Address, [int]$PrefixLength, [string]$Except)
    $mask = Get-PrefixMask $PrefixLength
    $net = (ConvertTo-UInt32 $Address) -band $mask
    $first = $net + 1
    $last = ($net -bor (-bnot $mask -band [uint32]::MaxValue)) - 1
    $x = ConvertTo-UInt32 $Except
    if ($x -lt $first -or $x -gt $last) {
        throw "-LinuxIp $Except is not inside this host's LAN $Address/$PrefixLength; the rule would deny the worker itself"
    }
    $ranges = @()
    if ($x -gt $first) { $ranges += ('{0}-{1}' -f (ConvertFrom-UInt32 $first), (ConvertFrom-UInt32 ($x - 1))) }
    if ($x -lt $last) { $ranges += ('{0}-{1}' -f (ConvertFrom-UInt32 ($x + 1)), (ConvertFrom-UInt32 $last)) }
    $ranges
}

function ConvertTo-Interval ([string]$Entry) {
    <#
        One firewall address entry as an inclusive [first, last] pair of
        uint64, or $null for what cannot be read as IPv4 (a keyword such as
        LocalSubnet, or IPv6). Windows reports a CIDR entry as a/mask.
    #>
    $ip = '\d{1,3}(?:\.\d{1,3}){3}'
    $e = "$Entry".Trim()
    if ($e -eq 'Any' -or $e -eq '*') { return , @([uint64]0, [uint64][uint32]::MaxValue) }
    if ($e -match "^($ip)-($ip)$") {
        return , @([uint64](ConvertTo-UInt32 $Matches[1]), [uint64](ConvertTo-UInt32 $Matches[2]))
    }
    $mask = $null
    if ($e -match "^($ip)/(\d{1,2})$") { $mask = Get-PrefixMask ([int]$Matches[2]) }
    elseif ($e -match "^($ip)/($ip)$") { $mask = ConvertTo-UInt32 $Matches[2] }
    if ($null -ne $mask) {
        $net = (ConvertTo-UInt32 $Matches[1]) -band $mask
        return , @([uint64]$net, [uint64]($net -bor (-bnot $mask -band [uint32]::MaxValue)))
    }
    if ($e -match "^$ip$") { $n = [uint64](ConvertTo-UInt32 $e); return , @($n, $n) }
    $null
}

function Get-Intervals ([string[]]$Entries) {
    $list = @()
    foreach ($entry in $Entries) {
        $iv = ConvertTo-Interval $entry
        if ($null -ne $iv) { $list += , $iv }
    }
    , $list
}

function Test-RangesCovered {
    <# True when every address of every `a-b` in -Ranges is in -Entries. #>
    param([string[]]$Ranges, [string[]]$Entries)
    $have = Get-Intervals $Entries
    foreach ($range in $Ranges) {
        $want = ConvertTo-Interval $range
        $cursor = $want[0]
        while ($cursor -le $want[1]) {
            $best = $null
            foreach ($iv in $have) {
                if ($iv[0] -le $cursor -and $iv[1] -ge $cursor -and ($null -eq $best -or $iv[1] -gt $best)) { $best = $iv[1] }
            }
            if ($null -eq $best) { return $false }
            $cursor = $best + 1
        }
    }
    $true
}

function Test-AddressInEntries {
    param([string]$Address, [string[]]$Entries)
    $n = [uint64](ConvertTo-UInt32 $Address)
    foreach ($iv in (Get-Intervals $Entries)) {
        if ($iv[0] -le $n -and $n -le $iv[1]) { return $true }
    }
    $false
}

function Test-PortEntriesInclude {
    param([int]$Port, [string[]]$Entries)
    foreach ($e in $Entries) {
        $e = "$e".Trim()
        if ($e -eq 'Any') { return $true }
        if ($e -match '^\d+$' -and [int]$e -eq $Port) { return $true }
        if ($e -match '^(\d+)-(\d+)$' -and [int]$Matches[1] -le $Port -and $Port -le [int]$Matches[2]) { return $true }
    }
    $false
}

function Test-ProfileApplies {
    <# A rule's Profile ("Any", "Private, Public", ...) against the network's category. #>
    param([string]$RuleProfile, [string]$Category)
    if ($RuleProfile -eq 'Any' -or $RuleProfile -eq '0') { return $true }
    if (-not $Category) { return $false }
    $want = if ($Category -eq 'DomainAuthenticated') { 'Domain' } else { $Category }
    @($RuleProfile.Split(',') | ForEach-Object { $_.Trim() }) -contains $want
}

function Get-InboundBlockRule {
    <#
        Every enabled inbound block rule that applies to TCP -Port on
        -LocalIp under -Category, with its remote addresses. Reading rules
        needs no elevation.
    #>
    param([int]$Port, [string]$LocalIp, [string]$Category)
    foreach ($rule in @(Get-NetFirewallRule -Direction Inbound -Action Block -Enabled True -ErrorAction SilentlyContinue)) {
        if (-not (Test-ProfileApplies -RuleProfile "$($rule.Profile)" -Category $Category)) { continue }
        $pf = $rule | Get-NetFirewallPortFilter
        if (@('TCP', 'Any', '6') -notcontains "$($pf.Protocol)") { continue }
        if (-not (Test-PortEntriesInclude -Port $Port -Entries @($pf.LocalPort))) { continue }
        $af = $rule | Get-NetFirewallAddressFilter
        if (-not (Test-AddressInEntries -Address $LocalIp -Entries @($af.LocalAddress))) { continue }
        [pscustomobject]@{ DisplayName = $rule.DisplayName; RemoteAddress = @($af.RemoteAddress) }
    }
}

# -- preconditions ---------------------------------------------------------
if ($SkipFirewall -and -not $IUnderstandLanExposure) {
    throw ('-SkipFirewall leaves 2222 open to the whole LAN once .env names the LAN address. ' +
           'Nothing was changed. Run elevated without it, or add -IUnderstandLanExposure.')
}
if (-not $SkipFirewall -and -not $LinuxIp) {
    throw 'Pass -LinuxIp <the Linux box''s LAN address>: it is the one address the firewall lets through to 2222.'
}
foreach ($required in @('tsa_host_key.pub', 'authorized_worker_keys')) {
    if (-not (Test-Path (Join-Path $KeyDir $required))) {
        throw "$KeyDir\$required is missing: run setup.ps1 first, this adds to a working stack."
    }
}
if (-not (Test-Path $installScript)) { throw "$installScript is missing; this checkout is incomplete." }
if (-not (Test-Path $EnvFile)) { throw "$EnvFile is missing: run setup.ps1 first." }

$lan = @(Get-LanAddress)
if (-not $TsaBindIp) {
    if ($lan.Count -ne 1) {
        throw ("This host has $($lan.Count) LAN addresses ($($lan.IPAddress -join ', ')); pass -TsaBindIp to choose one.")
    }
    $TsaBindIp = $lan[0].IPAddress
}
$lanIf = $lan | Where-Object IPAddress -eq $TsaBindIp | Select-Object -First 1
if (-not $lanIf) { throw "-TsaBindIp $TsaBindIp is not an address of this host." }

$bundle = Join-Path $BundleRoot "$Name-bundle"
Write-Host "Worker      : $Name (tag $Tag)"
Write-Host "TSA         : $TsaBindIp`:$tsaPort (published by the web node)"
Write-Host "Linux box   : $(if ($LinuxIp) { $LinuxIp } else { '(not given; firewall skipped)' })"
Write-Host "Keys        : $KeyDir (public keys only)"
Write-Host "Bundle      : $bundle"
Write-Host ''

# -- 1. the firewall scope, before anything can publish 2222 ---------------
if ($SkipFirewall) {
    Write-Warning 'firewall    : skipped (-SkipFirewall -IUnderstandLanExposure): 2222 will be open to the whole LAN, key-gated only.'
} else {
    $deny = @(Get-DenyRanges -Address $lanIf.IPAddress -PrefixLength $lanIf.PrefixLength -Except $LinuxIp)
    $category = $null
    try { $category = "$((Get-NetConnectionProfile -InterfaceIndex $lanIf.InterfaceIndex -ErrorAction Stop).NetworkCategory)" } catch { $category = $null }
    $rules = @(Get-InboundBlockRule -Port $tsaPort -LocalIp $TsaBindIp -Category $category)
    $others = @($rules | Where-Object DisplayName -ne $ruleName)

    $blocking = @($others | Where-Object { Test-AddressInEntries -Address $LinuxIp -Entries $_.RemoteAddress })
    if ($blocking) {
        throw ("Block rule '$($blocking[0].DisplayName)' denies $tsaPort from $LinuxIp itself, so the worker could never connect. " +
               'Carve that address out of it first. Nothing was changed.')
    }
    foreach ($r in $others) {
        $unread = @($r.RemoteAddress | Where-Object { $null -eq (ConvertTo-Interval $_) })
        if ($unread) { Write-Warning "Block rule '$($r.DisplayName)' on $tsaPort names $($unread -join ', '); if that includes $LinuxIp the worker is refused." }
    }

    $covering = @($rules | Where-Object { Test-RangesCovered -Ranges $deny -Entries $_.RemoteAddress } |
                  Where-Object { -not (Test-AddressInEntries -Address $LinuxIp -Entries $_.RemoteAddress) })
    if ($covering) {
        Write-Host "firewall    : '$($covering[0].DisplayName)' already denies $tsaPort to the LAN but $LinuxIp; no rule added" -ForegroundColor DarkGray
    } else {
        $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        $action = if ($existing) { "Re-scope to deny $($deny -join ', ')" } else { "Create block rule denying $($deny -join ', ')" }
        if (-not (Test-Elevated)) {
            if ($WhatIfPreference) {
                Write-Host "What if: $action on TCP $tsaPort (needs an elevated prompt for the real run)" -ForegroundColor DarkGray
            } elseif ($IUnderstandLanExposure) {
                Write-Warning "firewall    : not elevated, rule not added (-IUnderstandLanExposure): 2222 will be open to the whole LAN, key-gated only."
            } else {
                $again = "$PSCommandPath -Name $Name -LinuxIp $LinuxIp -Tag $Tag" + $(if ($PSBoundParameters.ContainsKey('TsaBindIp')) { " -TsaBindIp $TsaBindIp" } else { '' })
                throw ("The block rule on $tsaPort needs an elevated prompt, and it comes first: nothing was changed. " +
                       "Run this from an elevated prompt: $again")
            }
        } elseif ($PSCmdlet.ShouldProcess($ruleName, $action)) {
            if ($existing) {
                Set-NetFirewallRule -DisplayName $ruleName -RemoteAddress $deny -LocalPort $tsaPort -Protocol TCP -Enabled True
                Write-Host "firewall    : re-scoped '$ruleName' to deny $($deny -join ', ')" -ForegroundColor Green
            } else {
                New-NetFirewallRule -DisplayName $ruleName `
                    -Direction Inbound -Action Block -Protocol TCP -LocalPort 2222 `
                    -RemoteAddress $deny -Profile Any `
                    -Description ("The Concourse TSA is published on the LAN address for a worker on another host " +
                                  "(TheHub #61659, D-181). 'Docker Desktop Backend' allows any port from any address " +
                                  "and block beats allow, so this denies every LAN address but the worker's. " +
                                  "Re-run Add-LinuxWorker.ps1 -LinuxIp to move it.") | Out-Null
                Write-Host "firewall    : created '$ruleName' denying $($deny -join ', ')" -ForegroundColor Green
            }
        }
    }
}

# -- 2. the worker's key pair: private half in the bundle only -------------
$pubPath = Join-Path $KeyDir "${Name}_key.pub"
$bundleKey = Join-Path $bundle 'worker_key'
$legacyKey = Join-Path $KeyDir "${Name}_key"
if (Test-Path $legacyKey) {
    # An earlier version of this script left the private key in keys\, which
    # three containers mount. Move it out.
    if (-not (Test-Path $pubPath) -and -not (Test-Path "$bundleKey.pub")) {
        throw "keys\${Name}_key has no ${Name}_key.pub beside it; delete it and re-run to mint a new pair. Nothing was moved."
    }
    if (Test-Path $bundleKey) {
        if ((Get-FileHash $legacyKey).Hash -ne (Get-FileHash $bundleKey).Hash) {
            throw "Both keys\${Name}_key and the bundle's worker_key exist and differ; remove the one the Linux box does not use."
        }
        if ($PSCmdlet.ShouldProcess($legacyKey, 'Remove (the same key is in the bundle)')) {
            Remove-Item -LiteralPath $legacyKey -Force
            Write-Host "key         : removed the private key from keys\ (it is in the bundle)" -ForegroundColor Green
        }
    } elseif ($PSCmdlet.ShouldProcess($legacyKey, "Move the private key into $bundle")) {
        New-Item -ItemType Directory -Force -Path $bundle | Out-Null
        Move-Item -LiteralPath $legacyKey -Destination $bundleKey
        if ((Test-Path $pubPath) -and -not (Test-Path "$bundleKey.pub")) { Copy-Item $pubPath "$bundleKey.pub" }
        Write-Host "key         : moved the private key from keys\ into the bundle" -ForegroundColor Green
    }
}

if (Test-Path $pubPath) {
    Write-Host "key         : ${Name}_key.pub exists, kept" -ForegroundColor DarkGray
} elseif (Test-Path "$bundleKey.pub") {
    if ($PSCmdlet.ShouldProcess($pubPath, 'Copy the bundle''s worker_key.pub')) {
        Copy-Item "$bundleKey.pub" $pubPath
        Write-Host "key         : restored ${Name}_key.pub from the bundle" -ForegroundColor Green
    }
} elseif (Test-Path $bundleKey) {
    throw "The bundle holds worker_key without its .pub and keys\${Name}_key.pub is missing; delete $bundle and re-run to mint a new pair."
} elseif ($PSCmdlet.ShouldProcess($bundle, "Generate the worker key pair with $image generate-key")) {
    New-Item -ItemType Directory -Force -Path $bundle | Out-Null
    docker run --rm -v "${bundle}:/out" $image generate-key -t ssh -f /out/worker_key | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path "$bundleKey.pub")) { throw 'generate-key failed; is Docker running?' }
    Copy-Item "$bundleKey.pub" $pubPath
    Write-Host "key         : generated worker_key in the bundle; only ${Name}_key.pub is in keys\" -ForegroundColor Green
}

# -- 3. the TSA's list ------------------------------------------------------
$authorized = Join-Path $KeyDir 'authorized_worker_keys'
if (Test-Path $pubPath) {
    $pubLine = (Get-Content $pubPath | Where-Object { $_.Trim() } | Select-Object -First 1).Trim()
    $material = $pubLine.Split(' ')[1]
    $listed = Get-Content $authorized | Where-Object { $_.Split(' ').Count -ge 2 -and $_.Split(' ')[1] -eq $material }
    if ($listed) {
        Write-Host 'authorized  : already listed' -ForegroundColor DarkGray
    } elseif ($PSCmdlet.ShouldProcess('authorized_worker_keys', "Append ${Name}_key.pub")) {
        $lines = @(Get-Content $authorized | Where-Object { $_.Trim() }) + $pubLine
        Set-Content -Path $authorized -Value $lines -Encoding ascii
        Write-Host "authorized  : appended ${Name}_key.pub ($($lines.Count) keys listed)" -ForegroundColor Green
    }
} else {
    Write-Host 'authorized  : (WhatIf) would append the new .pub' -ForegroundColor DarkGray
}

# -- 4. the TSA on the LAN address -----------------------------------------
$envLines = @(Get-Content $EnvFile)
$current = $envLines | Where-Object { $_ -match '^CONCOURSE_TSA_BIND_IP=' } | Select-Object -First 1
$wanted = "CONCOURSE_TSA_BIND_IP=$TsaBindIp"
if ($current -eq $wanted) {
    Write-Host 'env         : CONCOURSE_TSA_BIND_IP already set' -ForegroundColor DarkGray
} elseif ($PSCmdlet.ShouldProcess($EnvFile, 'Set CONCOURSE_TSA_BIND_IP to the LAN address')) {
    if ($current) {
        $envLines = $envLines | ForEach-Object { if ($_ -match '^CONCOURSE_TSA_BIND_IP=') { $wanted } else { $_ } }
    } else {
        $envLines += @('', '# The web node publishes the TSA (2222) here for workers on other hosts (Add-LinuxWorker.ps1).', $wanted)
    }
    Set-Content -Path $EnvFile -Value $envLines -Encoding UTF8
    Write-Host 'env         : wrote CONCOURSE_TSA_BIND_IP' -ForegroundColor Green
}

# -- 5. the web node --------------------------------------------------------
if ($SkipCompose) {
    if ($PSCmdlet.ShouldProcess('mykronos-concourse', 'SIGHUP: reload authorized_worker_keys')) {
        docker kill -s HUP mykronos-concourse | Out-Null
        Write-Host 'web node    : SIGHUP sent; authorized keys reloaded. 2222 is published only after a run without -SkipCompose.' -ForegroundColor Yellow
    }
} else {
    $running = docker inspect -f '{{.Config.Image}}' mykronos-concourse 2>$null
    if ($PSCmdlet.ShouldProcess('mykronos-concourse', "docker compose up -d concourse (recreates the web node; running image $running, compose pins $image)")) {
        Push-Location $ComposeDir
        try {
            docker compose up -d concourse
            if ($LASTEXITCODE -ne 0) { throw "docker compose up -d concourse failed with $LASTEXITCODE" }
        } finally { Pop-Location }
        Write-Host 'web node    : recreated; waiting for healthy...'
        $deadline = (Get-Date).AddMinutes(4)
        do {
            Start-Sleep -Seconds 10
            $state = (docker inspect -f '{{.State.Health.Status}}' mykronos-concourse 2>$null)
            Write-Host "              $state"
            if ($state -eq 'healthy') { break }
        } while ((Get-Date) -lt $deadline)
        if ($state -ne 'healthy') { throw 'The web node did not become healthy. Check: docker compose logs concourse' }
        $ports = docker port mykronos-concourse 2222/tcp
        if ("$ports" -notmatch [regex]::Escape("$TsaBindIp`:2222")) {
            throw "The web node publishes 2222 as '$ports', not on $TsaBindIp. Is .env read from $EnvFile by the compose in $ComposeDir?"
        }
        $probe = Test-NetConnection -ComputerName $TsaBindIp -Port 2222 -WarningAction SilentlyContinue
        if (-not $probe.TcpTestSucceeded) { throw "Nothing answers on $TsaBindIp`:2222 although Docker publishes it." }
        Write-Host "web node    : TSA answers on $TsaBindIp`:2222" -ForegroundColor Green
    }
}

# -- 6. the rest of the bundle ---------------------------------------------
if ($PSCmdlet.ShouldProcess($bundle, 'Write the TSA host .pub, worker.conf and the install script beside the worker key')) {
    New-Item -ItemType Directory -Force -Path $bundle | Out-Null
    Copy-Item (Join-Path $KeyDir 'tsa_host_key.pub') (Join-Path $bundle 'tsa_host_key.pub') -Force
    Copy-Item $installScript (Join-Path $bundle 'install-concourse-worker.sh') -Force
    # LF only: the install script reads this on Linux (it strips CR anyway).
    $conf = "# Written by Add-LinuxWorker.ps1 on $(Get-Date -Format s); read by install-concourse-worker.sh`n" +
            "TSA_HOST=$TsaBindIp`:2222`n" +
            "WORKER_NAME=$Name`n" +
            "TAG=$Tag`n"
    [IO.File]::WriteAllText((Join-Path $bundle 'worker.conf'), $conf, [Text.UTF8Encoding]::new($false))
    if (Test-Path $bundleKey) {
        Write-Host "bundle      : $bundle" -ForegroundColor Green
    } else {
        # The bundle was deleted after an earlier scp, as the README says. The
        # installer reuses /etc/concourse/worker_key on a box that has one.
        Write-Host "bundle      : $bundle (no worker_key: the private key now lives only on the Linux box;" -ForegroundColor Yellow
        Write-Host "              to mint a new pair, delete keys\${Name}_key.pub and its line in authorized_worker_keys, then re-run)" -ForegroundColor Yellow
    }
}

Write-Host ''
Write-Host 'Next, from this prompt (replace user). The bundle holds the worker''s private key: delete it here once copied.' -ForegroundColor Cyan
$target = if ($LinuxIp) { $LinuxIp } else { '<linux-ip>' }
Write-Host "  scp -r `"$bundle`" user@${target}:~/"
Write-Host "  ssh user@$target 'sudo bash ~/$Name-bundle/install-concourse-worker.sh'"
Write-Host "  Remove-Item -Recurse `"$bundle`""
Write-Host 'Then verify:' -ForegroundColor Cyan
Write-Host "  fly -t mykronos workers        # '$Name' with tag '$Tag', state running"
