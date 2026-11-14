<#
.SYNOPSIS
    The Windows half of adding a Concourse worker on another host: its key,
    the TSA on the LAN address, the firewall scope and the install bundle.

.DESCRIPTION
    TheHub #61659, D-178. The two workers in docker-compose.yml share one
    Docker VM with production, and their heavy lanes have killed each other
    for memory. A worker on a Linux box takes the compute-only steps off the
    VM. It registers to the same web node over the TSA (SSH, port 2222) with
    a key pair of its own, so four things change here and nowhere else:

      1. keys\<Name>_key(.pub) is generated with the same `generate-key` the
         other workers' keys came from, and the .pub is appended to
         keys\authorized_worker_keys (setup.ps1 now keeps every *_key.pub
         there, so a re-run of setup.ps1 no longer drops it).
      2. .env gets CONCOURSE_TSA_BIND_IP=<this host's LAN address>, and
         `docker compose up -d concourse` recreates the web node so it
         publishes 2222 there and reads the new authorized key. Nothing else
         in the compose is touched; the two workers reconnect to the new web
         container on their own (same name, same host key).
      3. A Windows Firewall BLOCK rule denies TCP 2222 from every LAN address
         except -LinuxIp. Needed because 'Docker Desktop Backend' allows any
         port from any address, and block beats allow (Set-AppPortScope.ps1
         has the record). Behind it the TSA still admits only listed keys.
      4. keys\<Name>-bundle\ is written: the worker's private key, the TSA
         host public key, worker.conf naming this host, and the Linux install
         script. Copy it to the Linux box and run the script there as root.

    Re-running is safe: every step checks before it changes anything.
    -WhatIf prints the plan. -SkipCompose and -SkipFirewall leave steps 2
    and 3 to a later run (the key is then reloaded with SIGHUP, which the TSA
    honours, so a worker that can already reach 2222 registers at once).

    Nothing here prints a key, a token or a line of .env.

.PARAMETER Name
    The worker's name as `fly workers` will show it. Lowercase letters,
    digits and hyphens. Default linux-1.

.PARAMETER LinuxIp
    The Linux box's LAN address: the one address the firewall rule lets
    through to 2222. Required unless -SkipFirewall.

.PARAMETER Tag
    The placement tag the worker carries. Steps that say `tags: [<Tag>]`
    run on it and nothing else does. Default linux. Routing jobs to it is a
    pipeline change of its own (D-178); this script only adds the worker.

.PARAMETER TsaBindIp
    The address the web node publishes 2222 on. Default: this host's LAN
    IPv4 address (the one that is not loopback, APIPA or a Docker/WSL range).

.PARAMETER SkipCompose
    Do not recreate the web node. The authorized keys are reloaded with
    SIGHUP instead; 2222 stays unpublished until a run without this switch.

.PARAMETER SkipFirewall
    Do not touch the firewall. The rule needs an elevated prompt; without
    one the script prints the exact command to run elevated and continues.

.EXAMPLE
    .\Add-LinuxWorker.ps1 -LinuxIp 192.168.0.50
    then: scp -r .\keys\linux-1-bundle user@192.168.0.50:~/
          ssh user@192.168.0.50 'sudo bash ~/linux-1-bundle/install-concourse-worker.sh'
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

    [string]$KeyDir = (Join-Path $PSScriptRoot 'keys'),
    [string]$EnvFile = (Join-Path $PSScriptRoot '.env'),
    [string]$ComposeDir = $PSScriptRoot
)

$ErrorActionPreference = 'Stop'
$image = 'concourse/concourse:8.3.3'
$ruleName = 'Mykronos Concourse TSA 2222 - deny the LAN except the Linux worker'
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

function Get-DenyRanges {
    <#
        The LAN prefix with one address cut out, as the `a-b` ranges Windows
        Firewall takes for -RemoteAddress. A block rule cannot say "except",
        so the exception is the gap between two ranges.
    #>
    param([string]$Address, [int]$PrefixLength, [string]$Except)
    $mask = if ($PrefixLength -eq 0) { [uint32]0 } else { [uint32]([uint32]::MaxValue -shl (32 - $PrefixLength) -band [uint32]::MaxValue) }
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

# -- preconditions ---------------------------------------------------------
if (-not $SkipFirewall -and -not $LinuxIp) {
    throw 'Pass -LinuxIp <the Linux box''s LAN address>, or -SkipFirewall to leave the rule for later.'
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

Write-Host "Worker      : $Name (tag $Tag)"
Write-Host "TSA         : $TsaBindIp`:2222 (published by the web node)"
Write-Host "Linux box   : $(if ($LinuxIp) { $LinuxIp } else { '(not given; firewall skipped)' })"
Write-Host "Keys        : $KeyDir"
Write-Host ''

# -- 1. the worker's key pair, and the TSA's list --------------------------
$keyPath = Join-Path $KeyDir "${Name}_key"
if (Test-Path $keyPath) {
    Write-Host "key         : ${Name}_key exists, kept" -ForegroundColor DarkGray
} elseif ($PSCmdlet.ShouldProcess("${Name}_key", "Generate the worker key pair with $image generate-key")) {
    docker run --rm -v "${KeyDir}:/keys" $image generate-key -t ssh -f "/keys/${Name}_key" | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path "$keyPath.pub")) { throw 'generate-key failed; is Docker running?' }
    Write-Host "key         : generated ${Name}_key and ${Name}_key.pub" -ForegroundColor Green
}

$authorized = Join-Path $KeyDir 'authorized_worker_keys'
$pubLine = $null
if (Test-Path "$keyPath.pub") {
    $pubLine = (Get-Content "$keyPath.pub" | Where-Object { $_.Trim() } | Select-Object -First 1).Trim()
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

# -- 2. the TSA on the LAN address -----------------------------------------
$envLines = @(Get-Content $EnvFile)
$current = $envLines | Where-Object { $_ -match '^CONCOURSE_TSA_BIND_IP=' } | Select-Object -First 1
$wanted = "CONCOURSE_TSA_BIND_IP=$TsaBindIp"
if ($current -eq $wanted) {
    Write-Host 'env         : CONCOURSE_TSA_BIND_IP already set' -ForegroundColor DarkGray
} elseif ($PSCmdlet.ShouldProcess($EnvFile, "Set $wanted")) {
    if ($current) {
        $envLines = $envLines | ForEach-Object { if ($_ -match '^CONCOURSE_TSA_BIND_IP=') { $wanted } else { $_ } }
    } else {
        $envLines += @('', '# The web node publishes the TSA (2222) here for workers on other hosts (Add-LinuxWorker.ps1).', $wanted)
    }
    Set-Content -Path $EnvFile -Value $envLines -Encoding UTF8
    Write-Host "env         : wrote $wanted" -ForegroundColor Green
}

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

# -- 3. the firewall scope -------------------------------------------------
if ($SkipFirewall) {
    Write-Host 'firewall    : skipped (-SkipFirewall)' -ForegroundColor Yellow
} else {
    $deny = @(Get-DenyRanges -Address $lanIf.IPAddress -PrefixLength $lanIf.PrefixLength -Except $LinuxIp)
    Write-Host "firewall    : deny TCP 2222 from $($deny -join ', ') (so only $LinuxIp reaches it)"
    if (-not (Test-Elevated) -and -not $WhatIfPreference) {
        Write-Warning 'The firewall rule needs an elevated prompt. Everything else is done; run this elevated:'
        Write-Warning "  $PSCommandPath -Name $Name -LinuxIp $LinuxIp -Tag $Tag -SkipCompose"
        Write-Warning '  (-SkipCompose: the web node is already recreated; the run reloads keys and adds the rule)'
    } else {
        $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if ($existing) {
            if ($PSCmdlet.ShouldProcess($ruleName, "Re-scope to $($deny -join ', ')")) {
                Set-NetFirewallRule -DisplayName $ruleName -RemoteAddress $deny -LocalPort 2222 -Protocol TCP
                Write-Host "firewall    : updated '$ruleName'" -ForegroundColor Green
            }
        } elseif ($PSCmdlet.ShouldProcess($ruleName, 'Create block rule')) {
            New-NetFirewallRule -DisplayName $ruleName `
                -Direction Inbound -Action Block -Protocol TCP -LocalPort 2222 `
                -RemoteAddress $deny -Profile Any `
                -Description ("The Concourse TSA is published on the LAN address for a worker on another host " +
                              "(TheHub #61659, D-178). 'Docker Desktop Backend' allows any port from any address " +
                              "and block beats allow, so this denies every LAN address but the worker's. " +
                              "Re-run Add-LinuxWorker.ps1 -LinuxIp to move it.") | Out-Null
            Write-Host "firewall    : created '$ruleName'" -ForegroundColor Green
        }
    }
}

# -- 4. the bundle for the Linux box ---------------------------------------
$bundle = Join-Path $KeyDir "$Name-bundle"
if ($PSCmdlet.ShouldProcess($bundle, 'Write the install bundle (private key, TSA host .pub, worker.conf, install script)')) {
    New-Item -ItemType Directory -Force -Path $bundle | Out-Null
    Copy-Item $keyPath (Join-Path $bundle 'worker_key') -Force
    Copy-Item (Join-Path $KeyDir 'tsa_host_key.pub') (Join-Path $bundle 'tsa_host_key.pub') -Force
    Copy-Item $installScript (Join-Path $bundle 'install-concourse-worker.sh') -Force
    # LF only: the install script reads this on Linux (it strips CR anyway).
    $conf = "# Written by Add-LinuxWorker.ps1 on $(Get-Date -Format s); read by install-concourse-worker.sh`n" +
            "TSA_HOST=$TsaBindIp`:2222`n" +
            "WORKER_NAME=$Name`n" +
            "TAG=$Tag`n"
    [IO.File]::WriteAllText((Join-Path $bundle 'worker.conf'), $conf, [Text.UTF8Encoding]::new($false))
    Write-Host "bundle      : $bundle" -ForegroundColor Green
}

Write-Host ''
Write-Host 'Next, from this prompt (replace user; the bundle holds the worker''s private key, so delete it here afterwards):' -ForegroundColor Cyan
$target = if ($LinuxIp) { $LinuxIp } else { '<linux-ip>' }
Write-Host "  scp -r `"$bundle`" user@${target}:~/"
Write-Host "  ssh user@$target 'sudo bash ~/$Name-bundle/install-concourse-worker.sh'"
Write-Host "  Remove-Item -Recurse `"$bundle`""
Write-Host 'Then verify:' -ForegroundColor Cyan
Write-Host "  fly -t mykronos workers        # '$Name' with tag '$Tag', state running"
