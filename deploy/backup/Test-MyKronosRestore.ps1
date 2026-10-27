#Requires -Version 7.2
<#
.SYNOPSIS
    Restore drill: restore the latest Mykronos backup into throwaway containers and check it.

.DESCRIPTION
    TheHub #60842. A backup that has never been restored is a hypothesis. This
    takes the newest successful set (local by default, or pulled from Azure
    with -Source Azure), and proves each component opens:

      freshness        the newest successful set is under -MaxAgeHours old
      hashes           every file matches the size and SHA-256 in the manifest
      decrypt-*        every file decrypts with this host's key, and the
                       plaintext matches the length and SHA-256 sealed inside
                       the archive (catches truncation, which Fernet alone
                       does not)
      operational-db   the SQLite snapshot passes integrity_check, its row
                       counts equal the ones recorded at backup time, and the
                       key tables are not empty
      datalake         the lake untars into a throwaway volume and DuckDB
                       reads every Parquet file in it; the file count matches
                       the manifest
      minio            untars; .minio.sys/format.json parses; object count
                       matches the manifest
      vault-storage    untars; a throwaway Vault (no network) started on the
                       restored storage reports initialized=true, sealed=true.
                       It is NEVER unsealed: the unseal key is not in the
                       backup and this drill does not go looking for it.
      offsite          (local source, read SAS configured) every file of the
                       set is in Azure at the same size

    Everything it creates is named mykronos-drill-* (volumes, one container,
    a scratch directory under the backup root) and removed at the end. It
    never touches a live container or volume.

    EXIT CODES
      0  pass
      1  fail -- a real defect in the backup, or no usable backup at all
      2  inconclusive -- the drill could not run (Docker unreachable, an image
         missing); says nothing about the backup either way

.PARAMETER DryRun
    Print which set would be drilled and what would be created, without
    writing, creating or downloading anything.

.EXAMPLE
    pwsh -File deploy/backup/Test-MyKronosRestore.ps1
    pwsh -File deploy/backup/Test-MyKronosRestore.ps1 -Source Azure
#>
[CmdletBinding()]
param(
    [string] $BackupRoot = (Join-Path $env:USERPROFILE 'Backups\mykronos'),
    [ValidateSet('Local', 'Azure')] [string] $Source = 'Local',
    [string] $SetName = '',
    [string] $ToolImage = '',
    [string] $VaultImage = '',
    [string] $BackendContainer = 'mykronos-backend',
    [string] $VaultContainer = 'mykronos-vault',
    [string[]] $KeyTables = @('repo_onboardings', 'audit_log', 'capability_configs', 'ingestion_tokens'),
    [int] $MaxAgeHours = 36,
    [string] $SecretPath = '',
    [switch] $KeepScratch,
    [switch] $DryRun
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'MyKronosBackup.psm1') -Force

if (-not $SecretPath) { $SecretPath = Get-DefaultSecretPath }
$script:LogPath = $null
$checks = New-Object System.Collections.Generic.List[object]

function Say {
    param([string] $Message)
    Write-BackupLog -Message $Message -LogPath $script:LogPath
}

function Add-Check {
    param([string] $Name, [ValidateSet('pass', 'fail', 'inconclusive', 'skip')] [string] $Status, [string] $Detail = '')
    $checks.Add([pscustomobject]@{ name = $Name; status = $Status; detail = $Detail })
    Say ('{0,-12} {1,-22} {2}' -f $Status.ToUpperInvariant(), $Name, $Detail)
}

function Invoke-Docker {
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

function Get-ResultJson {
    param($Run)
    $line = $Run.Lines | Where-Object { $_.StartsWith('RESULT ') } | Select-Object -Last 1
    if (-not $line) { return $null }
    return $line.Substring(7) | ConvertFrom-Json
}

function Get-Component {
    param($Manifest, [string] $Name)
    return @($Manifest.components) | Where-Object { $_.name -eq $Name } | Select-Object -First 1
}

$secrets = Get-BackupSecret -SecretPath $SecretPath
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$prefix = "mykronos-drill-$stamp"

foreach ($pair in @(@{ Var = 'ToolImage'; Container = $BackendContainer }, @{ Var = 'VaultImage'; Container = $VaultContainer })) {
    if (-not (Get-Variable -Name $pair.Var -ValueOnly)) {
        $r = Invoke-Docker -Arguments @('inspect', '--format', '{{.Config.Image}}', $pair.Container)
        if ($r.ExitCode -eq 0 -and $r.Lines.Count) { Set-Variable -Name $pair.Var -Value $r.Lines[0].Trim() }
    }
}

# ---------------------------------------------------------------------------
# Which set
# ---------------------------------------------------------------------------

$candidate = $null      # name of the set to drill
$newestName = $null
if ($Source -eq 'Local') {
    $sets = @(Get-LocalBackupSet -Root $BackupRoot)
    if ($sets.Count) { $newestName = $sets[0].Name }
    $good = @($sets | Where-Object { $_.Success })
    if ($SetName) { $good = @($good | Where-Object { $_.Name -eq $SetName }) }
    if ($good.Count) { $candidate = $good[0] }
} else {
    if (-not $secrets.ReadSasUrl) {
        Say 'REFUSING TO RUN - -Source Azure needs a read SAS (MYKRONOS_BACKUP_READ_SAS_URL, or Register-MyKronosBackupTasks.ps1 -SetSecrets)'
        exit 1
    }
    $inventory = Get-BlobInventory -SasUrl $secrets.ReadSasUrl -Prefix 'mykronos_'
    $remoteSets = @($inventory.Keys | Where-Object { $_ -match '^(mykronos_\d{8}_\d{6})/manifest\.json$' } | ForEach-Object { ($_ -split '/')[0] } | Sort-Object -Descending)
    if ($SetName) { $remoteSets = @($remoteSets | Where-Object { $_ -eq $SetName }) }
    if ($remoteSets.Count) { $newestName = $remoteSets[0] }
    $candidate = $remoteSets | ForEach-Object { [pscustomobject]@{ Name = $_; Created = (ConvertFrom-SetName -Name $_) } } | Select-Object -First 1
}

$scratch = Join-Path $BackupRoot ".drill-$stamp"

if ($DryRun) {
    Say '--- DRY RUN: nothing will be written, created or downloaded ---'
    Say "source     : $Source $(if ($Source -eq 'Azure') { Get-SafeContainerUrl -SasUrl $secrets.ReadSasUrl } else { $BackupRoot })"
    Say "set        : $(if ($candidate) { $candidate.Name } else { 'NONE - the drill would fail: no successful backup set found' })"
    if ($newestName -and $candidate -and $newestName -ne $candidate.Name) { Say "note       : the newest set $newestName is not successful; the drill would use the newest one that is" }
    Say "scratch    : $scratch (decrypted plaintext; removed at the end)"
    Say "volumes    : $prefix-lake, $prefix-minio, $prefix-vault (removed at the end)"
    Say "container  : $prefix-vault from $VaultImage, --network none, never unsealed"
    Say "tool image : $ToolImage"
    Say "key tables : $($KeyTables -join ', ')"
    Say "key        : $(if ($secrets.EncryptionKey) { 'present, fingerprint ' + (Get-KeyFingerprint -Key $secrets.EncryptionKey) } else { 'MISSING - the drill would fail' })"
    Say "offsite    : $(if ($Source -eq 'Local' -and $secrets.ReadSasUrl) { 'listing compared against ' + (Get-SafeContainerUrl -SasUrl $secrets.ReadSasUrl) } elseif ($Source -eq 'Local') { 'skipped - no read SAS' } else { 'is the source' })"
    exit 0
}

New-Item -ItemType Directory -Force -Path (Join-Path $BackupRoot 'logs') | Out-Null
$script:LogPath = Join-Path $BackupRoot ('logs\drill-{0}.log' -f (Get-Date -Format 'yyyy-MM-dd'))
Say "--- mykronos restore drill start ($Source) ---"

if (-not $candidate) {
    Add-Check -Name 'select-set' -Status 'fail' -Detail "no successful backup set found ($Source)"
} else {
    $age = ((Get-Date) - $candidate.Created).TotalHours
    if ($age -le $MaxAgeHours) { Add-Check -Name 'freshness' -Status 'pass' -Detail ('{0} is {1:N1} h old' -f $candidate.Name, $age) }
    else { Add-Check -Name 'freshness' -Status 'fail' -Detail ('newest successful set {0} is {1:N1} h old (limit {2})' -f $candidate.Name, $age, $MaxAgeHours) }
    if ($newestName -and $newestName -ne $candidate.Name) {
        Add-Check -Name 'newest-set' -Status 'fail' -Detail "the newest set $newestName did not succeed; drilling $($candidate.Name) instead"
    }
}

$volumes = @()
$vaultName = "$prefix-vault"
$vaultStarted = $false
$manifest = $null

try {
    if (-not $candidate) { throw [System.OperationCanceledException]::new('no set') }
    if (-not $secrets.EncryptionKey) {
        Add-Check -Name 'key' -Status 'fail' -Detail 'MYKRONOS_BACKUP_ENCRYPTION_KEY is not available to this user - the backups cannot be opened here'
        throw [System.OperationCanceledException]::new('no key')
    }
    New-Item -ItemType Directory -Force -Path $scratch | Out-Null

    # -- fetch -------------------------------------------------------------
    if ($Source -eq 'Local') {
        $setDir = $candidate.Path
    } else {
        $setDir = Join-Path $scratch 'download'
        New-Item -ItemType Directory -Force -Path $setDir | Out-Null
        foreach ($blob in @($inventory.Keys | Where-Object { $_.StartsWith("$($candidate.Name)/") })) {
            Get-BlobFile -SasUrl $secrets.ReadSasUrl -BlobName $blob -Destination (Join-Path $setDir ($blob.Substring($candidate.Name.Length + 1)))
        }
    }
    $manifest = Get-Content -Raw -LiteralPath (Join-Path $setDir 'manifest.json') | ConvertFrom-Json
    if (-not $manifest.success) {
        Add-Check -Name 'manifest' -Status 'fail' -Detail "$($candidate.Name) is recorded as a failed backup (verdict $($manifest.verdict))"
    }

    # -- hashes + decrypt --------------------------------------------------
    $plain = @{}
    foreach ($c in @($manifest.components | Where-Object { $_.status -eq 'ok' })) {
        $f = Join-Path $setDir $c.file
        if (-not (Test-Path -LiteralPath $f)) { Add-Check -Name "hash-$($c.name)" -Status 'fail' -Detail "$($c.file) is missing"; continue }
        $len = (Get-Item -LiteralPath $f).Length
        $sha = Get-FileSha256 -Path $f
        if ($len -ne [long]$c.bytes -or $sha -ne $c.sha256) {
            Add-Check -Name "hash-$($c.name)" -Status 'fail' -Detail "$($c.file): $len bytes / $($sha.Substring(0,12)) vs manifest $($c.bytes) / $(([string]$c.sha256).Substring(0,12))"
            continue
        }
        Add-Check -Name "hash-$($c.name)" -Status 'pass' -Detail ('{0:N0} bytes' -f $len)
        $out = Join-Path $scratch ($c.file.Substring(0, $c.file.Length - (Get-EncryptedSuffix).Length))
        try {
            $dec = Unprotect-BackupFile -Path $f -Destination $out -Key $secrets.EncryptionKey
            if ($c.plaintext_sha256 -and $dec.PlaintextSha256 -ne $c.plaintext_sha256) { throw 'plaintext SHA-256 differs from the manifest' }
            Add-Check -Name "decrypt-$($c.name)" -Status 'pass' -Detail ('{0:N0} plaintext bytes' -f $dec.PlaintextBytes)
            $plain[$c.name] = $out
        } catch {
            Add-Check -Name "decrypt-$($c.name)" -Status 'fail' -Detail "$($_.Exception.Message)"
        }
    }

    $dv = Invoke-Docker -Arguments @('version', '--format', '{{.Server.Version}}')
    if ($dv.ExitCode -ne 0) {
        Add-Check -Name 'docker' -Status 'inconclusive' -Detail 'docker is not reachable; the restores could not be attempted'
        throw [System.OperationCanceledException]::new('no docker')
    }

    # -- operational-db ----------------------------------------------------
    $dbc = Get-Component -Manifest $manifest -Name 'operational-db'
    if ($plain.ContainsKey('operational-db')) {
        $py = @'
import json, sqlite3, sys
con = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True)
ok = con.execute("PRAGMA integrity_check").fetchone()[0]
names = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
counts = {n: con.execute('SELECT count(*) FROM "%s"' % n.replace('"', '""')).fetchone()[0] for n in names}
print("RESULT " + json.dumps({"integrity": ok, "tables": counts}))
'@
        $leaf = Split-Path -Leaf $plain['operational-db']
        $r = Invoke-Docker -Arguments @('run', '--rm', '-i', '--network', 'none', '--user', '0:0', '-v', "${scratch}:/r", $ToolImage, 'python', '-', "/r/$leaf") -InputText $py
        $res = Get-ResultJson -Run $r
        if (-not $res) { Add-Check -Name 'operational-db' -Status 'fail' -Detail "the snapshot did not open: $(($r.Lines | Select-Object -Last 2) -join ' | ')" }
        else {
            $problems = @()
            if ($res.integrity -ne 'ok') { $problems += "integrity_check: $($res.integrity)" }
            foreach ($t in $KeyTables) {
                $n = if ($res.tables.PSObject.Properties[$t]) { [long]$res.tables.$t } else { -1 }
                if ($n -lt 0) { $problems += "key table $t is missing" } elseif ($n -eq 0) { $problems += "key table $t is empty" }
            }
            if ($dbc.detail -and $dbc.detail.PSObject.Properties['tables']) {
                foreach ($p in $dbc.detail.tables.PSObject.Properties) {
                    $got = if ($res.tables.PSObject.Properties[$p.Name]) { [long]$res.tables.($p.Name) } else { -1 }
                    if ($got -ne [long]$p.Value) { $problems += "$($p.Name): $got rows, manifest says $($p.Value)" }
                }
            }
            $summary = ($KeyTables | ForEach-Object { "$_=$(if ($res.tables.PSObject.Properties[$_]) { $res.tables.$_ } else { 'missing' })" }) -join ' '
            if ($problems.Count) { Add-Check -Name 'operational-db' -Status 'fail' -Detail ($problems -join '; ') }
            else { Add-Check -Name 'operational-db' -Status 'pass' -Detail "integrity ok; $(@($res.tables.PSObject.Properties).Count) tables match the manifest; $summary" }
        }
    }

    function Expand-ToVolume {
        <# Untar a decrypted archive into a fresh mykronos-drill-* volume. #>
        param([string] $Component, [string] $Suffix)
        $vol = "$prefix-$Suffix"
        if (-not $vol.StartsWith('mykronos-drill-')) { throw "refusing to create a volume outside mykronos-drill-*: $vol" }
        $null = Invoke-Docker -Arguments @('volume', 'create', $vol)
        $script:volumes += $vol
        $leaf = Split-Path -Leaf $plain[$Component]
        # docker cp the archive into the volume, then untar there. Read through the
        # Windows bind mount, tar failed part-way on the 400 MB datalake with the
        # host short of memory ("gzip: stdin: Cannot allocate memory", 2026-10-22).
        $c = Invoke-Docker -Arguments @('create', '-v', "${vol}:/w", $ToolImage)
        if ($c.ExitCode -ne 0) { throw "docker create for the copy-in failed: $(($c.Lines | Select-Object -Last 1))" }
        $cid = ($c.Lines | Select-Object -Last 1).Trim()
        try {
            $cp = Invoke-Docker -Arguments @('cp', $plain[$Component], "${cid}:/w/.drill-archive")
            if ($cp.ExitCode -ne 0) { throw "docker cp of $leaf failed: $(($cp.Lines | Select-Object -Last 1))" }
        } finally {
            $null = Invoke-Docker -Arguments @('rm', '-f', $cid)
        }
        $sh = "tar -xzf /w/.drill-archive -C /w; rc=`$?; rm -f /w/.drill-archive; echo `"RC `$rc`""
        $r = Invoke-Docker -Arguments @('run', '--rm', '-i', '--network', 'none', '--user', '0:0', '-v', "${vol}:/w", $ToolImage, 'sh', '-s') -InputText $sh
        $rc = $r.Lines | Where-Object { $_.StartsWith('RC ') } | Select-Object -Last 1
        if (-not $rc -or $rc -ne 'RC 0') {
            # The first error is the cause; the last lines are tar's generic epilogue.
            $errs = @($r.Lines | Where-Object { $_ -and -not $_.StartsWith('RC ') })
            throw "untar failed: $(($errs | Select-Object -First 1)) ... $(($errs | Select-Object -Last 1))"
        }
        Remove-Item -LiteralPath $plain[$Component] -Force -ErrorAction SilentlyContinue
        return $vol
    }

    # -- datalake ----------------------------------------------------------
    if ($plain.ContainsKey('datalake')) {
        try {
            $vol = Expand-ToVolume -Component 'datalake' -Suffix 'lake'
            $py = @'
import duckdb, json, os
root = "/w"
con = duckdb.connect(":memory:")
res = {"files": 0, "rows": 0, "unreadable": [], "tables": {}}
for d, _, fs in os.walk(root):
    for f in fs:
        if not f.endswith(".parquet"):
            continue
        p = os.path.join(d, f)
        rel = os.path.relpath(p, root)
        table = rel.split(os.sep)[0]
        res["files"] += 1
        try:
            n = con.execute("SELECT count(*) FROM read_parquet(?)", [p]).fetchone()[0]
        except Exception:
            res["unreadable"].append(rel)
            continue
        res["rows"] += n
        t = res["tables"].setdefault(table, {"files": 0, "rows": 0})
        t["files"] += 1
        t["rows"] += n
print("RESULT " + json.dumps(res))
'@
            $r = Invoke-Docker -Arguments @('run', '--rm', '-i', '--network', 'none', '--user', '0:0', '-v', "${vol}:/w:ro", $ToolImage, 'python', '-') -InputText $py
            $res = Get-ResultJson -Run $r
            $lc = Get-Component -Manifest $manifest -Name 'datalake'
            $expected = if ($lc.detail -and $lc.detail.PSObject.Properties['parquet_files']) { [long]$lc.detail.parquet_files } else { -1 }
            if (-not $res) { Add-Check -Name 'datalake' -Status 'fail' -Detail "duckdb did not run: $(($r.Lines | Select-Object -Last 2) -join ' | ')" }
            elseif (@($res.unreadable).Count) { Add-Check -Name 'datalake' -Status 'fail' -Detail "$(@($res.unreadable).Count) Parquet file(s) unreadable, e.g. $(@($res.unreadable)[0])" }
            elseif ($expected -ge 0 -and [long]$res.files -ne $expected) { Add-Check -Name 'datalake' -Status 'fail' -Detail "$($res.files) Parquet files restored, manifest says $expected" }
            elseif ($expected -gt 0 -and [long]$res.rows -le 0) { Add-Check -Name 'datalake' -Status 'fail' -Detail 'every Parquet file is empty' }
            else { Add-Check -Name 'datalake' -Status 'pass' -Detail ('{0} Parquet files, {1:N0} rows, all readable by duckdb; {2} tables' -f $res.files, [long]$res.rows, @($res.tables.PSObject.Properties).Count) }
        } catch { Add-Check -Name 'datalake' -Status 'fail' -Detail "$($_.Exception.Message)" }
    }

    # -- minio -------------------------------------------------------------
    if ($plain.ContainsKey('minio')) {
        try {
            $vol = Expand-ToVolume -Component 'minio' -Suffix 'minio'
            $py = @'
import json, os
root = "/w"
fmt = os.path.join(root, ".minio.sys", "format.json")
ok = False
try:
    with open(fmt) as f:
        json.load(f)
    ok = True
except Exception:
    pass
objects = sum(1 for d, _, fs in os.walk(root) for f in fs if f == "xl.meta" and not os.path.relpath(d, root).startswith(".minio.sys"))
allmeta = sum(1 for d, _, fs in os.walk(root) for f in fs if f == "xl.meta")
print("RESULT " + json.dumps({"format_ok": ok, "objects": objects, "xl_meta": allmeta}))
'@
            $r = Invoke-Docker -Arguments @('run', '--rm', '-i', '--network', 'none', '--user', '0:0', '-v', "${vol}:/w:ro", $ToolImage, 'python', '-') -InputText $py
            $res = Get-ResultJson -Run $r
            $mc = Get-Component -Manifest $manifest -Name 'minio'
            $expected = if ($mc.detail -and $mc.detail.PSObject.Properties['objects']) { [long]$mc.detail.objects } else { -1 }
            if (-not $res) { Add-Check -Name 'minio' -Status 'fail' -Detail 'the check did not run' }
            elseif (-not $res.format_ok) { Add-Check -Name 'minio' -Status 'fail' -Detail '.minio.sys/format.json is missing or not JSON' }
            elseif ($expected -ge 0 -and [long]$res.xl_meta -ne $expected) { Add-Check -Name 'minio' -Status 'fail' -Detail "$($res.xl_meta) xl.meta restored, manifest says $expected" }
            else { Add-Check -Name 'minio' -Status 'pass' -Detail "format.json ok; $($res.objects) object(s)" }
        } catch { Add-Check -Name 'minio' -Status 'fail' -Detail "$($_.Exception.Message)" }
    }

    # -- vault-storage -----------------------------------------------------
    if ($plain.ContainsKey('vault-storage')) {
        try {
            $vol = Expand-ToVolume -Component 'vault-storage' -Suffix 'vault'
            $ls = Invoke-Docker -Arguments @('run', '--rm', '--network', 'none', '--user', '0:0', '-v', "${vol}:/w:ro", $ToolImage, 'ls', '-A', '/w')
            $missing = @('core', 'logical', 'sys') | Where-Object { $ls.Lines -notcontains $_ }
            if ($missing) { Add-Check -Name 'vault-storage' -Status 'fail' -Detail "restored storage lacks $($missing -join ', ')" }
            elseif (-not $VaultImage) { Add-Check -Name 'vault-storage' -Status 'inconclusive' -Detail 'untarred with core/logical/sys, but no Vault image to start (pass -VaultImage)' }
            else {
                $cfg = '{"storage":{"file":{"path":"/vault/file"}},"listener":{"tcp":{"address":"127.0.0.1:8200","tls_disable":true}},"disable_mlock":true,"ui":false}'
                $run = Invoke-Docker -Arguments @('run', '-d', '--name', $vaultName, '--network', 'none', '-e', 'SKIP_SETCAP=true', '-e', "VAULT_LOCAL_CONFIG=$cfg", '-v', "${vol}:/vault/file", $VaultImage, 'server')
                if ($run.ExitCode -ne 0) { throw "could not start the drill Vault: $(($run.Lines | Select-Object -Last 1))" }
                $vaultStarted = $true
                $status = $null
                for ($i = 0; $i -lt 30 -and -not $status; $i++) {
                    Start-Sleep -Seconds 1
                    $st = Invoke-Docker -Arguments @('exec', $vaultName, 'vault', 'status', '-address=http://127.0.0.1:8200', '-format=json')
                    $json = ($st.Lines -join "`n")
                    if ($json.TrimStart().StartsWith('{')) { try { $status = $json | ConvertFrom-Json } catch { $status = $null } }
                }
                if (-not $status) { Add-Check -Name 'vault-storage' -Status 'fail' -Detail 'the drill Vault never answered vault status on the restored storage' }
                elseif (-not $status.initialized) { Add-Check -Name 'vault-storage' -Status 'fail' -Detail 'Vault reads the restored storage as UNINITIALISED - the backup does not hold the store' }
                elseif (-not $status.sealed) { Add-Check -Name 'vault-storage' -Status 'fail' -Detail 'the drill Vault is unsealed, which should be impossible without the key' }
                else { Add-Check -Name 'vault-storage' -Status 'pass' -Detail "Vault $($status.version) opens the restored storage: initialized, sealed (not unsealed, by design)" }
            }
        } catch { Add-Check -Name 'vault-storage' -Status 'fail' -Detail "$($_.Exception.Message)" }
    }

    # -- components the manifest says failed -------------------------------
    foreach ($req in Get-RequiredComponent) {
        $c = Get-Component -Manifest $manifest -Name $req
        if (-not $c -or $c.status -ne 'ok') { Add-Check -Name $req -Status 'fail' -Detail 'not in this set (the manifest records it as failed or absent)' }
    }

    # -- offsite -----------------------------------------------------------
    if ($Source -eq 'Local') {
        if (-not $secrets.ReadSasUrl) { Add-Check -Name 'offsite' -Status 'skip' -Detail 'no read SAS configured; the Azure copy was not checked' }
        else {
            try {
                $inv = Get-BlobInventory -SasUrl $secrets.ReadSasUrl -Prefix "$($candidate.Name)/"
                $gaps = @()
                foreach ($c in @($manifest.components | Where-Object { $_.status -eq 'ok' })) {
                    $b = "$($candidate.Name)/$($c.file)"
                    if (-not $inv.ContainsKey($b)) { $gaps += "$($c.file) absent" }
                    elseif ([long]$inv[$b] -ne [long]$c.bytes) { $gaps += "$($c.file) is $($inv[$b]) bytes in Azure, $($c.bytes) locally" }
                }
                if (-not $inv.ContainsKey("$($candidate.Name)/manifest.json")) { $gaps += 'manifest.json absent' }
                if ($gaps.Count) { Add-Check -Name 'offsite' -Status 'fail' -Detail ($gaps -join '; ') }
                else { Add-Check -Name 'offsite' -Status 'pass' -Detail "every file of $($candidate.Name) is in $(Get-SafeContainerUrl -SasUrl $secrets.ReadSasUrl) at the same size" }
            } catch { Add-Check -Name 'offsite' -Status 'inconclusive' -Detail "could not list the container: $($_.Exception.Message)" }
        }
    }
} catch [System.OperationCanceledException] {
    # A check above already recorded why the drill stopped.
    $null = $_
} catch {
    Add-Check -Name 'drill' -Status 'inconclusive' -Detail "the drill itself failed: $($_.Exception.Message)"
} finally {
    if ($vaultStarted) { $null = Invoke-Docker -Arguments @('rm', '-f', '-v', $vaultName) }
    foreach ($v in $volumes) {
        if ($v.StartsWith('mykronos-drill-')) { $null = Invoke-Docker -Arguments @('volume', 'rm', '-f', $v) }
    }
    if (-not $KeepScratch -and (Test-Path -LiteralPath $scratch)) { Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue }
}

$verdict = Get-DrillVerdict -Checks $checks.ToArray()
$report = [ordered]@{
    drilled_utc = (Get-Date).ToUniversalTime().ToString('o')
    source      = $Source
    set         = $(if ($candidate) { $candidate.Name } else { $null })
    verdict     = $verdict.Verdict
    checks      = $checks.ToArray()
}
if ($candidate -and $Source -eq 'Local') {
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $candidate.Path "drill-$stamp.json") -Encoding ascii
}
if ($verdict.Failed.Count) { Say "not passing: $($verdict.Failed -join ', ')" }
Say "--- drill complete, verdict $($verdict.Verdict) ---"
exit $verdict.ExitCode
