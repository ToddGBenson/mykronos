<#
.SYNOPSIS
    Collect Windows endpoint security posture for The Hub's SOC dashboard.

.DESCRIPTION
    The SOC board's `endpoint_security` widget has always been dark, with the
    reason recorded in the code: "No EDR agents. Host posture from the nmap
    sweep is the substitute once NOC-1 discovery is enabled."

    This is the substitute. The Hub runs in a Linux container and cannot reach
    the Windows host's PowerShell, so the collection happens here and the
    result is written to the bind-mounted data directory the container already
    reads (`./data:/app/data` in docker-compose.yml, commented "Dashboard JSON
    files"). No new endpoint, no credentials, no network hop.

    Pairs with the nmap sweep rather than duplicating it. nmap answers "what is
    reachable from the network"; this answers "what is bound, what is patched,
    what is protecting the box" -- the view from inside. The difference between
    the two is usually the interesting part.

.PARAMETER DataDir
    Where to write. Defaults to TheHub checkout's data/ directory, which is
    what the prod compose file bind-mounts to /app/data.

.PARAMETER Once
    Collect once and exit. This is how the Scheduled Task runs it.

.NOTES
    ASCII only - see deploy\concourse\setup.ps1.

    Reports ONE host: the machine the Hub runs on. That is a real signal and
    better than the nothing the widget shows now, but it is not fleet EDR, and
    the payload names the host so the dashboard cannot imply coverage it does
    not have.

    Every probe is individually guarded. A box without BitLocker, or without
    Defender, or where Get-HotFix is slow, must still produce a document --
    a collector that returns nothing because one cmdlet was unavailable would
    put the widget back where it started.
#>

[CmdletBinding()]
param(
    [string]$DataDir = "C:\Users\tgb_\Documents\Projects\TheHub-main\data",
    [switch]$Once,
    [int]$IntervalSeconds = 900
)

$ErrorActionPreference = "Stop"

function Get-Probe {
    <#
    Run one probe and never let it take the document down.

    Returns a hashtable with either a value or an error string. "Could not
    read" and "read, and the answer is no" are different facts and the
    dashboard must be able to tell them apart -- a missing BitLocker reading
    shown as "not encrypted" is a false alarm, and shown as "encrypted" is a
    dangerous one.
    #>
    param(
        [string]$Name,
        [scriptblock]$Body
    )

    try {
        return @{ ok = $true; value = (& $Body) }
    } catch {
        Write-Verbose "probe '$Name' failed: $($_.Exception.Message)"
        return @{ ok = $false; error = $_.Exception.Message }
    }
}

function Get-EndpointPosture {
    $now = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

    # -- Defender ---------------------------------------------------------
    $defender = Get-Probe "defender" {
        $s = Get-MpComputerStatus
        $sigAge = $null
        if ($s.AntivirusSignatureLastUpdated) {
            $sigAge = [int]((Get-Date) - $s.AntivirusSignatureLastUpdated).TotalDays
        }
        @{
            realtime_protection    = [bool]$s.RealTimeProtectionEnabled
            antivirus_enabled      = [bool]$s.AntivirusEnabled
            antispyware_enabled    = [bool]$s.AntispywareEnabled
            tamper_protection      = [bool]$s.IsTamperProtected
            signature_age_days     = $sigAge
            last_quick_scan        = if ($s.QuickScanEndTime) { $s.QuickScanEndTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") } else { $null }
            last_full_scan         = if ($s.FullScanEndTime)  { $s.FullScanEndTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") } else { $null }
        }
    }

    # -- Host firewall ----------------------------------------------------
    $firewall = Get-Probe "firewall" {
        $profiles = @{}
        foreach ($p in Get-NetFirewallProfile) {
            $profiles[$p.Name.ToString()] = @{
                enabled       = [bool]$p.Enabled
                inbound_action = $p.DefaultInboundAction.ToString()
            }
        }
        $profiles
    }

    # -- Disk encryption --------------------------------------------------
    $bitlocker = Get-Probe "bitlocker" {
        $vols = @()
        foreach ($v in Get-BitLockerVolume) {
            $vols += @{
                mount_point      = $v.MountPoint
                protection_status = $v.ProtectionStatus.ToString()
                encryption_pct   = $v.EncryptionPercentage
            }
        }
        $vols
    }

    # -- Boot integrity ---------------------------------------------------
    $secureBoot = Get-Probe "secure_boot" { [bool](Confirm-SecureBootUEFI) }

    # -- Patch state ------------------------------------------------------
    #
    # Get-HotFix only sees servicing-stack style updates and misses a lot of
    # modern cumulative servicing, so this is a floor on "how long since
    # something was installed", not a patch-compliance verdict. Labelled that
    # way in the payload so nobody reads it as one.
    $patching = Get-Probe "patching" {
        $latest = Get-HotFix | Where-Object { $_.InstalledOn } |
                  Sort-Object InstalledOn -Descending | Select-Object -First 1
        if (-not $latest) { return @{ last_update = $null; days_since = $null; count = 0 } }
        @{
            last_update = $latest.InstalledOn.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            days_since  = [int]((Get-Date) - $latest.InstalledOn).TotalDays
            hotfix_id   = $latest.HotFixID
            count       = (Get-HotFix | Measure-Object).Count
        }
    }

    # -- Privilege drift --------------------------------------------------
    $admins = Get-Probe "local_admins" {
        $names = @()
        foreach ($m in Get-LocalGroupMember -Group "Administrators") {
            $names += $m.Name
        }
        @{ count = $names.Count; members = $names }
    }

    # -- Listening ports, the view nmap cannot get -------------------------
    #
    # nmap sees what answers from the network. This sees what is bound and
    # which process owns it, including loopback-only listeners nmap will never
    # report. Reported as a count plus the distinct owning processes rather
    # than a full socket dump -- the dashboard wants a posture signal, not a
    # netstat paste, and the full list changes every few seconds.
    $listening = Get-Probe "listening" {
        $conns = Get-NetTCPConnection -State Listen
        $byProc = @{}
        foreach ($c in $conns) {
            $name = "unknown"
            try {
                $p = Get-Process -Id $c.OwningProcess -ErrorAction Stop
                $name = $p.ProcessName
            } catch { }
            if (-not $byProc.ContainsKey($name)) { $byProc[$name] = 0 }
            $byProc[$name]++
        }
        $external = @($conns | Where-Object {
            $_.LocalAddress -ne "127.0.0.1" -and $_.LocalAddress -ne "::1"
        })
        @{
            total            = @($conns).Count
            externally_bound = $external.Count
            by_process       = $byProc
        }
    }

    return @{
        schema_version = 1
        collected_at   = $now
        host           = $env:COMPUTERNAME
        os             = (Get-CimInstance Win32_OperatingSystem).Caption
        scope_note     = "One host - the machine The Hub runs on. Not fleet EDR coverage."
        defender       = $defender
        firewall       = $firewall
        bitlocker      = $bitlocker
        secure_boot    = $secureBoot
        patching       = $patching
        local_admins   = $admins
        listening      = $listening
    }
}

function Write-Posture {
    if (-not (Test-Path $DataDir)) {
        throw "Data directory not found: $DataDir. That path is bind-mounted to /app/data; without it the Hub has nowhere to read from."
    }

    $posture = Get-EndpointPosture
    $target = Join-Path $DataDir "endpoint-posture.json"
    $temp = "$target.tmp"

    # WriteAllText, not Set-Content -Encoding UTF8: under Windows PowerShell
    # 5.1 -- which is what the Scheduled Task runs -- that switch writes UTF-8
    # WITH a byte order mark, and Python's json.load rejects it outright
    # ("Unexpected UTF-8 BOM"). The consumer decodes utf-8-sig defensively, but
    # the file should be clean at the source rather than every reader needing
    # to know. Same approach Invoke-RegistryPullDeploy uses for its ack file.
    #
    # Temp file then move, because the container reads this on a schedule and a
    # half-written document parses as a corrupt one.
    [System.IO.File]::WriteAllText($temp, ($posture | ConvertTo-Json -Depth 8))
    Move-Item -Path $temp -Destination $target -Force

    $bits = @()
    if ($posture.defender.ok)  { $bits += "defender_rtp=$($posture.defender.value.realtime_protection)" }
    if ($posture.patching.ok)  { $bits += "days_since_patch=$($posture.patching.value.days_since)" }
    if ($posture.listening.ok) { $bits += "listening=$($posture.listening.value.total)" }
    Write-Host "$($posture.collected_at)  $($posture.host)  $($bits -join '  ')" -ForegroundColor Green
}

if ($Once) {
    Write-Posture
    exit 0
}

Write-Host "Collecting endpoint posture every $IntervalSeconds s into $DataDir. Ctrl-C to stop." -ForegroundColor DarkGray
while ($true) {
    try { Write-Posture } catch { Write-Host "Collection failed: $($_.Exception.Message)" -ForegroundColor Red }
    Start-Sleep -Seconds $IntervalSeconds
}
