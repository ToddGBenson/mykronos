#Requires -Version 7.2
<#
.SYNOPSIS
    Nightly backup of Mykronos's state: snapshot, encrypt, upload, prune, manifest.

.DESCRIPTION
    TheHub #60842. Until this existed Mykronos had no backup of anything: the
    operational database, the lake, MinIO and Vault's storage each lived in
    exactly one Docker volume on one host.

    WHAT IS BACKED UP (each becomes one HUBENC1-encrypted file in the set)

      operational-db  /data/mykronos.db in mykronos-backend. SQLite in WAL
                      mode, so it is copied with SQLite's online backup API
                      INSIDE the running backend (the process that owns the
                      file), never by copying the file: a file copy of a WAL
                      database taken mid-write is a torn database. The copy
                      is integrity-checked and its per-table row counts are
                      recorded for the restore drill to compare against.
      datalake        /data/datalake from the same volume: Parquet partitions,
                      the compaction buffer, archived raw scan output.
      minio           the whole MinIO data volume (artifacts and SBOMs).
      vault-storage   Vault's file storage, which Vault keeps encrypted under
                      its own barrier. NOT the unseal key or root token -- see
                      the exclusions in MyKronosBackup.psm1 and #60836.

    Each volume is read through a throwaway container with the volume mounted
    READ-ONLY (`docker run --rm --network none -v vol:/src:ro`). Nothing in
    this script writes to a live volume or restarts a live container.

    WHAT IS NOT, and why, is written into every manifest (registry: 83 GB of
    images rebuilt from source; Concourse's database and worker caches:
    regenerated from the repo).

    CONSISTENCY. The database snapshot is transactionally consistent. The
    volume tars are taken live. Lake Parquet files are written to a .tmp and
    renamed (lake/compaction.py), so a tar sees whole files; `.tmp` files are
    excluded; and the compaction buffer is archived FIRST, so a compaction
    that runs mid-tar can duplicate buffered rows into the archive but cannot
    drop them. MinIO objects written during the window can be torn; at 03:00
    that window is normally empty.

    EXIT CODES
      0  every component captured and encrypted, and the offsite copy landed
      1  a component or the offsite upload failed, or the run refused to start
      2  the local set is complete but there is no offsite copy because no SAS
         is configured -- one copy in the same room as its source

    Fails closed on encryption: with no key, or a malformed one, it refuses
    before it snapshots anything and creates no set directory.

.PARAMETER DryRun
    Print the plan -- components, sources, commands, destination, what would
    be pruned -- and the preflight findings, without writing anything.

.EXAMPLE
    pwsh -File deploy/backup/Backup-MyKronos.ps1 -DryRun
#>
[CmdletBinding()]
param(
    [string] $BackupRoot = (Join-Path $env:USERPROFILE 'Backups\mykronos'),
    [string] $BackendContainer = 'mykronos-backend',
    [string] $DataVolume = 'mykronos_mykronos-data',
    [string] $MinioVolume = 'mykronos-concourse_minio-data',
    [string] $VaultVolume = 'mykronos-concourse_vault-data',
    # Image for the throwaway tar containers. Default: whatever image the
    # running backend uses -- already on this host, has sh, GNU tar and
    # python, so nothing is pulled at 03:00.
    [string] $ToolImage = '',
    [int] $RetainDays = 7,
    [int] $MinKeep = 3,
    [int] $MinFreeGB = 20,
    [string] $SecretPath = '',
    [switch] $DryRun
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'MyKronosBackup.psm1') -Force

if (-not $SecretPath) { $SecretPath = Get-DefaultSecretPath }
$script:LogPath = $null

function Say {
    param([string] $Message)
    Write-BackupLog -Message $Message -LogPath $script:LogPath
}

function Invoke-Docker {
    <# Run docker, return its output lines and exit code. Never throws. #>
    param([Parameter(Mandatory)] [string[]] $Arguments, [string] $InputText)
    $global:LASTEXITCODE = 0
    try {
        if ($PSBoundParameters.ContainsKey('InputText')) {
            $out = $InputText.Replace("`r`n", "`n") | docker @Arguments 2>&1
        } else {
            $out = docker @Arguments 2>&1
        }
        $code = $LASTEXITCODE
    } catch {
        $out = @("$_")
        $code = 127
    }
    return [pscustomobject]@{ Lines = @($out | ForEach-Object { "$_" }); ExitCode = $code }
}

# ---------------------------------------------------------------------------
# The plan
# ---------------------------------------------------------------------------

$secrets = Get-BackupSecret -SecretPath $SecretPath
$keyProblem = $null
try { $null = Get-FernetKey -Key $secrets.EncryptionKey } catch { $keyProblem = "$($_.Exception.Message)" }

if (-not $ToolImage) {
    $r = Invoke-Docker -Arguments @('inspect', '--format', '{{.Config.Image}}', $BackendContainer)
    if ($r.ExitCode -eq 0 -and $r.Lines.Count -gt 0) { $ToolImage = $r.Lines[0].Trim() }
}

$tarRun = 'docker run --rm --network none --user 0:0 -v <volume>:/src:ro -v <set>\.staging:/out ' + $ToolImage + ' sh -s'
$components = @(
    [ordered]@{ name = 'operational-db'; file = 'operational-db.sqlite'; source = "${BackendContainer}:/data/mykronos.db (sqlite online backup, in the running container)"; how = "docker exec -i $BackendContainer python - /tmp/<snapshot>.db ; docker cp ; docker exec rm" }
    [ordered]@{ name = 'datalake'; file = 'datalake.tar.gz'; source = "volume $DataVolume, /datalake (read-only)"; how = $tarRun.Replace('<volume>', $DataVolume) + '  (_buffer first, *.tmp excluded)' }
    [ordered]@{ name = 'minio'; file = 'minio.tar.gz'; source = "volume $MinioVolume (read-only)"; how = $tarRun.Replace('<volume>', $MinioVolume) }
    [ordered]@{ name = 'vault-storage'; file = 'vault-storage.tar.gz'; source = "volume $VaultVolume (read-only; Vault's encrypted file storage only)"; how = $tarRun.Replace('<volume>', $VaultVolume) }
)
$offsiteTarget = if ($secrets.WriteSasUrl) { Get-SafeContainerUrl -SasUrl $secrets.WriteSasUrl } else { '' }

# Preflight: read-only checks, run in both modes.
$refusals = New-Object System.Collections.Generic.List[string]
if ($keyProblem) { $refusals.Add($keyProblem) }
$dv = Invoke-Docker -Arguments @('version', '--format', '{{.Server.Version}}')
if ($dv.ExitCode -ne 0) { $refusals.Add('docker is not reachable (is Docker Desktop running for this user?)') }
else {
    $running = Invoke-Docker -Arguments @('inspect', '--format', '{{.State.Running}}', $BackendContainer)
    if ($running.ExitCode -ne 0 -or ($running.Lines -join '').Trim() -ne 'true') { $refusals.Add("container $BackendContainer is not running - the database snapshot needs it") }
    foreach ($v in @($DataVolume, $MinioVolume, $VaultVolume)) {
        $vi = Invoke-Docker -Arguments @('volume', 'inspect', '--format', '{{.Name}}', $v)
        if ($vi.ExitCode -ne 0) { $refusals.Add("volume $v does not exist") }
    }
    if (-not $ToolImage) { $refusals.Add('no tool image: pass -ToolImage, or start the backend so its image can be used') }
}
$qualifier = try { Split-Path -Path $BackupRoot -Qualifier -ErrorAction Stop } catch { $null }
if ($qualifier) {
    $drive = Get-PSDrive -Name $qualifier.TrimEnd(':') -ErrorAction SilentlyContinue
    if ($drive -and $drive.Free -lt ([long]$MinFreeGB * 1GB)) {
        $refusals.Add(('{0} has {1:N1} GB free, below -MinFreeGB {2}' -f $qualifier, ($drive.Free / 1GB), $MinFreeGB))
    }
}

$existing = @(Get-LocalBackupSet -Root $BackupRoot)
$wouldPrune = Select-BackupsToPrune -Sets $existing -RetainDays $RetainDays -MinKeep $MinKeep

if ($DryRun) {
    Say '--- DRY RUN: nothing will be written ---'
    Say "set        : $BackupRoot\$(Get-SetName)"
    foreach ($c in $components) {
        Say ('component  : {0,-15} from {1}' -f $c.name, $c.source)
        Say ('             {0}' -f $c.how)
        Say ('             -> {0}{1} (HUBENC1, key fingerprint {2})' -f $c.file, (Get-EncryptedSuffix), $(if ($keyProblem) { 'n/a' } else { Get-KeyFingerprint -Key $secrets.EncryptionKey }))
    }
    foreach ($x in Get-BackupExclusion) { Say ('excluded   : {0,-15} {1}' -f $x.name, $x.reason) }
    if ($offsiteTarget) { Say "offsite    : $offsiteTarget/<set>/ (block blobs; the SAS signature is never printed)" }
    else { Say 'offsite    : NOT CONFIGURED - the run would exit 2 (local copy only)' }
    Say ("retention  : keep {0} day(s), never fewer than {1} successful set(s); would prune after an ok run: {2}" -f $RetainDays, $MinKeep, $(if ($wouldPrune.Count) { $wouldPrune -join ', ' } else { 'nothing' }))
    if ($refusals.Count) {
        foreach ($m in $refusals) { Say "WOULD REFUSE: $m" }
        Say '--- dry run complete: a real run would refuse ---'
        exit 1
    }
    Say '--- dry run complete: preflight passed ---'
    exit 0
}

# ---------------------------------------------------------------------------
# The run
# ---------------------------------------------------------------------------

# Encryption fails closed BEFORE anything is created: no key, no directory.
if ($keyProblem) {
    Write-BackupLog -Message "REFUSING TO RUN - $keyProblem"
    exit 1
}

New-Item -ItemType Directory -Force -Path (Join-Path $BackupRoot 'logs') | Out-Null
$script:LogPath = Join-Path $BackupRoot ('logs\backup-{0}.log' -f (Get-Date -Format 'yyyy-MM-dd'))

if ($refusals.Count) {
    foreach ($m in $refusals) { Say "REFUSING TO RUN - $m" }
    Say '--- complete, verdict failed (refused) ---'
    exit 1
}

$lockPath = Join-Path $BackupRoot '.lock'
try {
    $lock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
} catch {
    Say 'REFUSING TO RUN - another backup run holds the lock'
    exit 1
}

$createdLocal = Get-Date
$setName = Get-SetName -At $createdLocal
$setDir = Join-Path $BackupRoot $setName
$staging = Join-Path $setDir '.staging'
New-Item -ItemType Directory -Force -Path $staging | Out-Null
$key = $secrets.EncryptionKey

$manifest = [ordered]@{
    schema          = 1
    name            = $setName
    created_utc     = $createdLocal.ToUniversalTime().ToString('o')
    completed_utc   = $null
    host            = $env:COMPUTERNAME
    encryption      = [ordered]@{ format = 'HUBENC1'; key_fingerprint = (Get-KeyFingerprint -Key $key) }
    tool_image      = $ToolImage
    components      = @()
    excluded        = @(Get-BackupExclusion)
    offsite         = [ordered]@{ status = $(if ($secrets.WriteSasUrl) { 'pending' } else { 'not-configured' }); container_url = $offsiteTarget; prefix = $setName; uploaded = @(); failed = @(); sas_expires_utc = $null }
    retention       = [ordered]@{ retain_days = $RetainDays; min_keep = $MinKeep; pruned = @() }
    success         = $false
    verdict         = 'pending'
    errors          = @()
    warnings        = @()
}
if ($secrets.WriteSasUrl) {
    $exp = Get-SasExpiry -SasUrl $secrets.WriteSasUrl
    if ($exp) { $manifest.offsite.sas_expires_utc = $exp.ToString('o') }
}

function Add-EncryptedComponent {
    <# Encrypt a staged plaintext into the set and fill in the record. #>
    param($Record, [string] $PlainPath, [string] $FileName)
    $dest = Join-Path $setDir ($FileName + (Get-EncryptedSuffix))
    try {
        $enc = Protect-BackupFile -Path $PlainPath -Destination $dest -Key $key
    } finally {
        Remove-Item -LiteralPath $PlainPath -Force -ErrorAction SilentlyContinue
    }
    $Record.file = Split-Path -Leaf $dest
    $Record.bytes = (Get-Item -LiteralPath $dest).Length
    $Record.sha256 = Get-FileSha256 -Path $dest
    $Record.plaintext_bytes = $enc.PlaintextBytes
    $Record.plaintext_sha256 = $enc.PlaintextSha256
}

function Get-NewComponentRecord {
    param([string] $Name, [string] $Source)
    return [ordered]@{
        name = $Name; status = 'failed'; source = $Source; file = $null; bytes = 0; sha256 = $null
        plaintext_bytes = 0; plaintext_sha256 = $null; detail = [ordered]@{}; warnings = @(); error = $null; seconds = 0
    }
}

$sqliteSnapshot = @'
import json, sqlite3, sys
from mykronos.config import get_settings
url = get_settings().database_url
if not url.startswith("sqlite:///"):
    print("RESULT " + json.dumps({"error": "database_url is not sqlite (scheme %s); this chain snapshots sqlite only" % url.split(":", 1)[0]}))
    sys.exit(3)
src_path = url[len("sqlite:///"):]
src = sqlite3.connect("file:%s?mode=ro" % src_path, uri=True)
dst = sqlite3.connect(sys.argv[1])
src.backup(dst)
src.close()
dst.execute("PRAGMA journal_mode=DELETE")
ok = dst.execute("PRAGMA integrity_check").fetchone()[0]
names = [r[0] for r in dst.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
counts = {n: dst.execute('SELECT count(*) FROM "%s"' % n.replace('"', '""')).fetchone()[0] for n in names}
dst.close()
print("RESULT " + json.dumps({"source": src_path, "integrity": ok, "tables": counts}))
'@

function Backup-OperationalDb {
    $rec = Get-NewComponentRecord -Name 'operational-db' -Source "${BackendContainer}:/data/mykronos.db"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $inContainer = "/tmp/mykronos-backup-$setName.db"
    try {
        $r = Invoke-Docker -Arguments @('exec', '-i', $BackendContainer, 'python', '-', $inContainer) -InputText $sqliteSnapshot
        $line = $r.Lines | Where-Object { $_.StartsWith('RESULT ') } | Select-Object -Last 1
        if (-not $line) { throw "snapshot produced no result (exit $($r.ExitCode)): $(($r.Lines | Select-Object -Last 3) -join ' | ')" }
        $res = $line.Substring(7) | ConvertFrom-Json
        if ($res.PSObject.Properties['error']) { throw $res.error }
        if ($r.ExitCode -ne 0) { throw "snapshot exited $($r.ExitCode)" }
        if ($res.integrity -ne 'ok') { throw "integrity_check on the snapshot returned '$($res.integrity)'" }
        $rec.source = "${BackendContainer}:$($res.source)"
        $rec.detail = [ordered]@{ integrity = $res.integrity; tables = $res.tables }
        $plain = Join-Path $staging 'operational-db.sqlite'
        $cp = Invoke-Docker -Arguments @('cp', "${BackendContainer}:$inContainer", $plain)
        if ($cp.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $plain)) { throw "docker cp of the snapshot failed (exit $($cp.ExitCode))" }
        Add-EncryptedComponent -Record $rec -PlainPath $plain -FileName 'operational-db.sqlite'
        $rec.status = 'ok'
    } catch {
        $rec.error = "$($_.Exception.Message)"
    } finally {
        $null = Invoke-Docker -Arguments @('exec', $BackendContainer, 'rm', '-f', $inContainer)
        $rec.seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    }
    return $rec
}

function Backup-Volume {
    <#
        tar.gz one volume (or a subdirectory of it) through a throwaway,
        network-less container with the volume mounted read-only.
        GNU tar exit 1 means "a file changed while being read": recorded as a
        warning, not a failure. 2 or more is a failure.
    #>
    param(
        [string] $Name, [string] $Volume, [string] $SubPath = '', [string] $First = '',
        [string[]] $Exclude = @(), [string] $CountPattern = '', [string] $CountLabel = 'entries_matching'
    )
    $src = if ($SubPath) { "/src/$SubPath" } else { '/src' }
    $rec = Get-NewComponentRecord -Name $Name -Source ("volume $Volume" + $(if ($SubPath) { ":/$SubPath" } else { '' }))
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $archive = "$Name.tar.gz"
    $excl = ($Exclude | ForEach-Object { "--exclude='$_'" }) -join ' '
    $countCmd = if ($CountPattern) { "grep -cE '$CountPattern' /tmp/list || true" } else { 'echo 0' }
    $sh = @"
cd '$src' 2>/dev/null || { echo 'RESULT missing-source'; exit 3; }
set --
if [ -n '$First' ] && [ -e '$First' ]; then set -- '$First'; fi
for f in `$(ls -A); do [ "`$f" = '$First' ] || set -- "`$@" "`$f"; done
[ `$# -gt 0 ] || { echo 'RESULT empty-source'; exit 4; }
tar -czf '/out/$archive' $excl "`$@" 2>/tmp/err
rc=`$?
head -n 10 /tmp/err | sed 's/^/TARMSG /'
echo "TAR_RC `$rc"
tar -tzf '/out/$archive' > /tmp/list 2>/dev/null
echo "ENTRIES `$(wc -l < /tmp/list)"
echo "COUNT `$($countCmd)"
"@
    try {
        $r = Invoke-Docker -Arguments @('run', '--rm', '-i', '--network', 'none', '--user', '0:0', '-v', "${Volume}:/src:ro", '-v', "${staging}:/out", $ToolImage, 'sh', '-s') -InputText $sh
        $result = $r.Lines | Where-Object { $_.StartsWith('RESULT ') } | Select-Object -Last 1
        if ($result) { throw "source $($result.Substring(7)) ($src in $Volume)" }
        $rcLine = $r.Lines | Where-Object { $_.StartsWith('TAR_RC ') } | Select-Object -Last 1
        if (-not $rcLine) { throw "tar container produced no result (exit $($r.ExitCode)): $(($r.Lines | Select-Object -Last 3) -join ' | ')" }
        $rc = [int]$rcLine.Substring(7)
        $msgs = @($r.Lines | Where-Object { $_.StartsWith('TARMSG ') } | ForEach-Object { $_.Substring(7) })
        if ($rc -ge 2) { throw "tar exited ${rc}: $($msgs -join ' | ')" }
        if ($rc -eq 1) { $rec.warnings = @("tar: files changed while being read (taken live): $(($msgs | Select-Object -First 3) -join ' | ')") }
        $entries = [long](($r.Lines | Where-Object { $_.StartsWith('ENTRIES ') } | Select-Object -Last 1).Substring(8).Trim())
        $count = [long](($r.Lines | Where-Object { $_.StartsWith('COUNT ') } | Select-Object -Last 1).Substring(6).Trim())
        if ($entries -le 0) { throw 'the archive lists no entries' }
        $rec.detail = [ordered]@{ entries = $entries; $CountLabel = $count }
        $plain = Join-Path $staging $archive
        Add-EncryptedComponent -Record $rec -PlainPath $plain -FileName $archive
        $rec.status = 'ok'
    } catch {
        $rec.error = "$($_.Exception.Message)"
    } finally {
        $rec.seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    }
    return $rec
}

Say "--- mykronos backup start: $setName ---"
$recs = @()
$recs += Backup-OperationalDb
$recs += Backup-Volume -Name 'datalake' -Volume $DataVolume -SubPath 'datalake' -First '_buffer' -Exclude @('*.tmp') -CountPattern '\.parquet$' -CountLabel 'parquet_files'
$recs += Backup-Volume -Name 'minio' -Volume $MinioVolume -CountPattern '/xl\.meta$' -CountLabel 'objects'
$recs += Backup-Volume -Name 'vault-storage' -Volume $VaultVolume -CountPattern '^(core|logical|sys)/$' -CountLabel 'top_level_dirs'
foreach ($rec in $recs) {
    if ($rec.status -eq 'ok') { Say ('ok      {0,-15} {1,14:N0} bytes  {2}  {3}s' -f $rec.name, $rec.bytes, $rec.sha256.Substring(0, 12), $rec.seconds) }
    else { Say ('FAILED  {0,-15} {1}' -f $rec.name, $rec.error) }
    foreach ($w in $rec.warnings) { Say ('warning {0,-15} {1}' -f $rec.name, $w) }
}
$manifest.components = $recs
Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue

# Written now, before the upload, so a crash mid-transfer leaves a readable
# record -- whose offsite status says `pending`, which the verdict treats as a
# failure rather than as "predates offsite tracking".
$manifestPath = Join-Path $setDir 'manifest.json'
Write-ManifestFile -Manifest $manifest -Path $manifestPath

if ($secrets.WriteSasUrl) {
    $uploaded = @(); $failedUploads = @()
    foreach ($rec in @($recs | Where-Object { $_.status -eq 'ok' })) {
        $blob = "$setName/$($rec.file)"
        try {
            Send-BlobFile -SasUrl $secrets.WriteSasUrl -BlobName $blob -Path (Join-Path $setDir $rec.file)
            $uploaded += $rec.file
            Say "offsite ok      $blob"
        } catch {
            $failedUploads += $rec.file
            Say "offsite FAILED  $blob - $($_.Exception.Message)"
        }
    }
    $manifest.offsite.uploaded = $uploaded
    $manifest.offsite.failed = $failedUploads
    $manifest.offsite.status = if ($failedUploads.Count -eq 0 -and $uploaded.Count -gt 0) { 'ok' } else { 'failed' }
} else {
    Say 'offsite NOT CONFIGURED - no upload SAS; this set exists on this host only'
}

$judged = Get-BackupVerdict -Manifest ([pscustomobject]$manifest | ConvertTo-Json -Depth 8 | ConvertFrom-Json)
$manifest.verdict = $judged.Verdict
$manifest.success = ($judged.Verdict -ne 'failed')
$manifest.errors = @($judged.Errors)
$manifest.warnings = @($judged.Warnings)
$manifest.completed_utc = (Get-Date).ToUniversalTime().ToString('o')

# Prune only after a fully good run: a reaper must never outlive its producer.
if ($judged.Verdict -eq 'ok') {
    $sets = @(Get-LocalBackupSet -Root $BackupRoot)
    $toPrune = Select-BackupsToPrune -Sets $sets -RetainDays $RetainDays -MinKeep $MinKeep
    foreach ($n in $toPrune) {
        if ($n -eq $setName) { continue }
        Remove-Item -LiteralPath (Join-Path $BackupRoot $n) -Recurse -Force -ErrorAction SilentlyContinue
        Say "pruned  $n"
    }
    $manifest.retention.pruned = @($toPrune | Where-Object { $_ -ne $setName })
}

Write-ManifestFile -Manifest $manifest -Path $manifestPath
if ($secrets.WriteSasUrl) {
    try { Send-BlobFile -SasUrl $secrets.WriteSasUrl -BlobName "$setName/manifest.json" -Path $manifestPath }
    catch { Say "offsite FAILED  $setName/manifest.json - $($_.Exception.Message)" }
}

Get-ChildItem -LiteralPath (Join-Path $BackupRoot 'logs') -Filter 'backup-*.log' -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } |
    Remove-Item -Force -ErrorAction SilentlyContinue

foreach ($w in $judged.Warnings) { Say "warning $w" }
foreach ($e in $judged.Errors) { Say "error   $e" }
Say "--- complete, verdict $($judged.Verdict) ---"
$lock.Dispose()
Remove-Item -LiteralPath $lockPath -Force -ErrorAction SilentlyContinue
exit (Get-VerdictExitCode -Verdict $judged.Verdict)
