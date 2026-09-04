<#
.SYNOPSIS
    Publish a netassess run to MinIO so the personal-soc pipeline can verify it.

.DESCRIPTION
    The scan itself stays on Windows, where it works: the "personal-soc Weekly
    Network Scan" Scheduled Task runs Invoke-WeeklyNetworkScan.ps1 against the
    real adapters and the real ARP table. This script is the handoff - it zips
    the run and puts it in MinIO, where the pipeline picks it up.

    That split is deliberate. A Concourse task on the Linux worker cannot see
    LAN MAC addresses at all: it sits behind Docker Desktop's NAT on a
    different L2 segment, and an nmap sweep from there reports all 256
    addresses of a /24 as "up" - a measured result, not a guess. So Concourse
    does not scan. It verifies, diffs, and complains.

    This script does NOT judge the run it uploads. A hollow scan is published
    exactly like a good one, because deciding which is which is the
    pipeline's job and a publisher that quietly withholds bad runs would make
    the pipeline's silence meaningless.

.PARAMETER Run
    Which run to publish. Defaults to the newest dated folder under -Root.

.EXAMPLE
    .\publish-netassess-run.ps1
    .\publish-netassess-run.ps1 -Run 2026-08-10

.NOTES
    ASCII only - see setup.ps1 for why.

    Credentials come from this stack's .env and are passed to mc through
    MC_HOST_<alias> rather than `mc alias set`, which would write them to
    %USERPROFILE%\mc\config.json and leave a second copy on disk.
#>

[CmdletBinding()]
param(
    [string]$Root = (Join-Path $env:USERPROFILE 'netassess'),
    [string]$Run,
    [string]$Endpoint = "http://localhost:9000",
    [string]$Bucket = "netassess-runs",
    # Spec 32 section 4.4. Where the judgement goes. Empty skips it, which is
    # the right behaviour for a deployment that has no Mykronos rather than an
    # error about one.
    [string]$MykronosUrl = $env:MYKRONOS_URL,
    [string]$MykronosToken = $env:MYKRONOS_INGESTION_TOKEN,
    # The perimeter gate in front of the whole API (gate.py). Separate from
    # the ingestion token: one says which repository is writing, the other
    # says the caller is allowed to reach this host at all.
    [string]$MykronosGateToken = $env:MYKRONOS_GATE_TOKEN
)

$ErrorActionPreference = "Stop"

function Read-EnvValue {
    param([string]$Path, [string]$Key)
    $line = Select-String -Path $Path -Pattern "^$Key=" -ErrorAction SilentlyContinue
    if (-not $line) { throw "$Key is not set in $Path" }
    return $line.Line.Split('=', 2)[1].Trim()
}

$stackEnv = Join-Path $PSScriptRoot ".env"
if (-not (Test-Path $stackEnv)) { throw "Missing $stackEnv" }

# --- pick the run -------------------------------------------------------
if (-not (Test-Path $Root)) { throw "No netassess root at $Root" }

if ($Run) {
    $runDir = Join-Path $Root $Run
    if (-not (Test-Path $runDir)) { throw "No such run: $runDir" }
    $runDir = Get-Item $runDir
} else {
    # Sorted by name, not by LastWriteTime: the folder name is the scan date
    # and a later edit to an older run must not make it look like the newest.
    $runDir = Get-ChildItem $Root -Directory |
        Where-Object { $_.Name -match '^\d{4}-\d{2}-\d{2}' } |
        Sort-Object Name | Select-Object -Last 1
    if (-not $runDir) { throw "No dated run folders under $Root" }
}

# --- version key --------------------------------------------------------
# Concourse's s3 resource orders `regexp` versions as semver, so the key has
# to parse as one. "2026-08-10" does not; "2026.8.10" does. Leading zeros are
# stripped because semver forbids them in numeric identifiers - with them,
# every version compares equal and the pipeline stops seeing new runs.
if ($runDir.Name -notmatch '^(\d{4})-(\d{2})-(\d{2})') {
    throw "Run folder '$($runDir.Name)' is not date-named; cannot derive a version."
}
$version = "{0}.{1}.{2}" -f [int]$Matches[1], [int]$Matches[2], [int]$Matches[3]
$objectName = "netassess-$version.zip"

# --- mc -----------------------------------------------------------------
$mc = Join-Path $PSScriptRoot "bin\mc.exe"
if (-not (Test-Path $mc)) {
    Write-Host "Fetching mc.exe..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri "https://dl.min.io/client/mc/release/windows-amd64/mc.exe" `
        -OutFile $mc -UseBasicParsing
}

$user = Read-EnvValue $stackEnv "MINIO_ROOT_USER"
$password = Read-EnvValue $stackEnv "MINIO_ROOT_PASSWORD"

# Escaped because a generated password may contain characters that are not
# legal unescaped in a URL userinfo field, and mc would read the credential
# as a malformed host rather than reporting a bad password.
$uri = [System.Uri]$Endpoint
$creds = "{0}:{1}" -f [System.Uri]::EscapeDataString($user), [System.Uri]::EscapeDataString($password)
$env:MC_HOST_netassess = "{0}://{1}@{2}" -f $uri.Scheme, $creds, $uri.Authority

try {
    & $mc --quiet mb --ignore-existing "netassess/$Bucket" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "mc mb failed against $Endpoint" }

    $zip = Join-Path ([System.IO.Path]::GetTempPath()) $objectName
    if (Test-Path $zip) { Remove-Item $zip -Force }

    # Contents at the archive root rather than nested under the date, so the
    # pipeline unpacks two runs into two directories of its own choosing and
    # Compare-Assessment sees the layout it expects either way.
    Write-Host "Packing $($runDir.Name)..." -ForegroundColor Cyan
    Compress-Archive -Path (Join-Path $runDir.FullName '*') -DestinationPath $zip

    Write-Host "Uploading $objectName to $Bucket..." -ForegroundColor Cyan
    & $mc --quiet cp $zip "netassess/$Bucket/runs/$objectName"
    if ($LASTEXITCODE -ne 0) { throw "mc cp failed" }

    $size = "{0:N0}" -f (Get-Item $zip).Length
    Write-Host "`nPublished $($runDir.Name) as $objectName ($size bytes)." -ForegroundColor Green

    # --- tell Mykronos ---------------------------------------------------
    #
    # Spec 32 section 4.4. The archive above is the history and stays where it
    # is; this is the judgement, and it is a push rather than a poll because
    # the alternative was giving the backend an S3 client and MinIO
    # credentials it needs for nothing else, to discover an event this script
    # already knows about.
    #
    # Two text files rather than the zip: the judgement reads those two, and
    # unpacking an archive inside the ingestion path would buy nothing.
    #
    # Never fatal. The archive is published either way, and a scan that ran
    # correctly must not be reported as a failure because a web request did
    # not land. This script's whole contract is that it does not judge the run
    # it uploads - reporting a transport failure as a scan failure would be
    # exactly that, by the back door.
    if (-not $MykronosUrl -or -not $MykronosToken) {
        Write-Host "  Mykronos not configured; skipping the judgement push." -ForegroundColor DarkGray
    } else {
        try {
            $inventory = Join-Path $runDir.FullName "inventory.csv"
            $status = Join-Path $runDir.FullName "network-status.md"
            $body = @{
                run_key           = $objectName
                inventory_csv     = if (Test-Path $inventory) { Get-Content $inventory -Raw } else { "" }
                network_status_md = if (Test-Path $status) { Get-Content $status -Raw } else { "" }
            } | ConvertTo-Json -Depth 3

            $headers = @{
                "Authorization" = "Bearer $MykronosToken"
                "Content-Type"  = "application/json"
            }
            if ($MykronosGateToken) { $headers["X-Hub-Token"] = $MykronosGateToken }

            $result = Invoke-RestMethod -Method Post -Uri "$($MykronosUrl.TrimEnd('/'))/api/ingest/netassess" `
                -Headers $headers -Body $body -TimeoutSec 30
            if ($result.believable) {
                Write-Host "  Mykronos accepted the run: $($result.host_count) host(s)." -ForegroundColor Green
            } else {
                Write-Host "  Mykronos judged the run NOT believable:" -ForegroundColor Yellow
                foreach ($p in $result.problems) { Write-Host "    - $p" -ForegroundColor Yellow }
            }
            foreach ($h in $result.hosts_appeared)    { Write-Host "    + new  $h" }
            foreach ($h in $result.hosts_disappeared) { Write-Host "    - gone $h" }
        } catch {
            Write-Host "  Could not report to Mykronos: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Host "  The archive is published; only the judgement did not run." -ForegroundColor DarkGray
        }
    }
} finally {
    Remove-Item Env:\MC_HOST_netassess -ErrorAction SilentlyContinue
    if ($zip -and (Test-Path $zip)) { Remove-Item $zip -Force }
}
