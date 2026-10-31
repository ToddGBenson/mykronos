<#
.SYNOPSIS
    Drop old tags from the local image registry and reclaim their space,
    offline, without ever turning the registry's DELETE API on.

.DESCRIPTION
    `mykronos-registry` (compose service `registry`) has no `auth:` block and
    keeps `REGISTRY_STORAGE_DELETE_ENABLED: "false"` for that reason: with
    deletes on, any client that reaches port 5000 could untag every image the
    demo and production stacks pull. Nothing had ever been deleted, so every
    build since the registry was created was still on disk.

    This script never enables deletes and never publishes a port. It works on
    the registry's volume directly:

      1. It builds a KEEP set (below) from the tag links in the volume.
      2. Dry run (the default) prints, per repository, what is kept, what
         would be dropped and why, an estimate of the space freed, and writes
         a JSON report.
      3. -Apply, only while the registry is stopped, the TheHub deploy lock is
         absent and the caller vouches that no Concourse build is running
         (-ConfirmCiQuiet: the Concourse API needs a fly token this script does
         not hold, so it cannot check), removes the dropped tags'
         `_manifests/tags/<tag>` directories in a throwaway container with no
         network, then runs `registry garbage-collect --delete-untagged` with
         the registry's own image in another. Restarting the registry is left
         to the caller; the exact command is printed.

    THE KEEP SET. A tag is kept if any of these hold:
      - it is among the newest -KeepNewest (default 15) tags of its repository,
        by the mtime of `_manifests/tags/<tag>/current/link`;
      - it is a dated base-image tag `<line>-pYYYYMMDD` among the newest
        -KeepDated (default 5) of its line (dated tags are ranked by date
        instead of by the newest-N rule);
      - it is a named tag (neither a commit sha nor dated, e.g. `latest`):
        a moving name is how something pulls without a sha, so it is never
        aged out;
      - the image reference appears, by tag or digest, in a git-tracked
        .yml/.yaml/.ps1/.sh/Dockerfile of the mykronos or TheHub checkout at
        the given refs (read with `git grep <ref>`, never the working tree);
        this covers the compose pin of the registry's own image;
      - a container (`docker ps -a`, running or not) uses it, by tag or by
        digest; this covers the image the running registry was started from;
      - it starts with one of -KeepShas (7-40 hex), so `<sha>` and
        `<sha>-deploy` both match;
      - it shares a leading commit sha with a tag kept for any reason above.

    A dropped image can be rebuilt and re-pushed from its commit: the JSON
    report lists every dropped tag with its digest and sha.

.PARAMETER TheHubCheckout
    A TheHub clone. Its refs are read with git, not its working tree. Required
    for -Apply; without it a dry run warns that TheHub pins are not protected.

.PARAMETER RegistryRoot
    A local directory laid out like the volume (it contains docker/registry/v2).
    For tests and offline inspection; read-only, refused with -Apply.

.EXAMPLE
    # Dry run against the live volume (read-only; the registry may be running)
    .\Invoke-RegistryRetention.ps1 -TheHubCheckout ..\TheHub -KeepShas $prod,$develop

.EXAMPLE
    # Apply, with the registry stopped and CI quiet
    docker stop mykronos-registry
    .\Invoke-RegistryRetention.ps1 -TheHubCheckout ..\TheHub -KeepShas $prod,$develop -Apply -ConfirmCiQuiet
    docker compose --project-name mykronos-concourse --file deploy\concourse\docker-compose.yml up -d --no-deps registry
#>
[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$ConfirmCiQuiet,
    [ValidateRange(1, 10000)][int]$KeepNewest = 15,
    [ValidateRange(1, 10000)][int]$KeepDated = 5,
    [string[]]$KeepShas = @(),
    [string]$MykronosCheckout = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string[]]$MykronosRefs = @('origin/main'),
    [string]$TheHubCheckout,
    [string[]]$TheHubRefs = @('origin/main', 'origin/develop'),
    [string]$Container = 'mykronos-registry',
    [string]$Volume = 'mykronos-concourse_registry-data',
    [string]$RegistryImage,
    [string]$DeployLockPath = (Join-Path ([string]$env:LOCALAPPDATA) 'Temp\thehub-deploy.lock'),
    [string]$ReportPath,
    [string]$RegistryRoot
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$RepoPattern = '^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$'
$TagPattern = '^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$'
$DatedPattern = '^(?<line>.+)-p(?<date>\d{8})$'
$ShaPattern = '^(?<sha>[0-9a-f]{40})'
$V2 = '/var/lib/registry/docker/registry/v2'

function Stop-Refused([string]$Why) {
    Write-Host "REFUSED: $Why"
    exit 3
}

# ---------------------------------------------------------------- guards ---
# Every refusal happens before anything is read or written.
if ($Apply) {
    if ($RegistryRoot) { Stop-Refused '-RegistryRoot is a read-only source; -Apply works on the volume only.' }
    if (-not $ConfirmCiQuiet) {
        Stop-Refused ('-Apply needs -ConfirmCiQuiet: this script cannot see Concourse builds (the API ' +
            'needs a fly token), so confirm in the Concourse UI that no build is running or pending.')
    }
    if ($DeployLockPath -and (Test-Path -LiteralPath $DeployLockPath)) {
        Stop-Refused "the TheHub deploy lock exists ($DeployLockPath); a deploy may be pulling from the registry."
    }
    $state = docker inspect --format '{{.State.Running}}' $Container 2>$null
    if ($LASTEXITCODE -eq 0 -and "$state".Trim() -eq 'true') {
        Stop-Refused "the registry container $Container is running; stop it first (docker stop $Container)."
    }
    $mounted = @(docker ps --quiet --filter "volume=$Volume" 2>$null | Where-Object { "$_".Trim() })
    if ($mounted.Count -gt 0) {
        Stop-Refused "a running container mounts $Volume ($($mounted -join ', ')); stop it first."
    }
    if (-not $TheHubCheckout) { Stop-Refused '-Apply needs -TheHubCheckout so TheHub''s pinned images are kept.' }
}
foreach ($s in $KeepShas) {
    if ($s -notmatch '^[0-9a-fA-F]{7,40}$') { Stop-Refused "-KeepShas '$s' is not 7-40 hex characters." }
}
$KeepShas = @($KeepShas | ForEach-Object { $_.ToLowerInvariant() })

# ------------------------------------------------------------ data access ---
function Get-RegistryRunning {
    $state = docker inspect --format '{{.State.Running}}' $Container 2>$null
    return ($LASTEXITCODE -eq 0 -and "$state".Trim() -eq 'true')
}

function Get-ServiceImage {
    if ($RegistryImage) { return $RegistryImage }
    $img = docker inspect --format '{{.Config.Image}}' $Container 2>$null
    if ($LASTEXITCODE -ne 0 -or -not "$img".Trim()) {
        throw "cannot read the image of $Container; pass -RegistryImage."
    }
    return "$img".Trim()
}

# Runs a read-only shell script against the volume. While the registry runs,
# inside it (docker exec); otherwise in a throwaway container with the volume
# mounted read-only and no network at all.
function Invoke-VolumeRead([string]$Script) {
    if (Get-RegistryRunning) {
        $out = docker exec $Container sh -c $Script
    } else {
        $out = docker run --rm --network none --pull never `
            --volume "${Volume}:/var/lib/registry:ro" --entrypoint sh (Get-ServiceImage) -c $Script
    }
    if ($LASTEXITCODE -ne 0) { throw "reading the registry volume failed (exit $LASTEXITCODE)." }
    return @($out)
}

$ListTagsScript = @'
# retention:list-tags
cd /var/lib/registry/docker/registry/v2/repositories || exit 1
find . -path '*/_manifests/tags/*/current/link' | while read -r f; do
  printf '%s\t%s\t%s\n' "$(stat -c %Y "$f")" "$f" "$(cat "$f")"
done
'@ -replace "`r", ''

$ListManifestsScript = @'
# retention:list-manifests
cd /var/lib/registry/docker/registry/v2 || exit 1
find repositories -path '*/_manifests/revisions/sha256/*/link' | sed 's#.*/sha256/\([0-9a-f]*\)/link$#\1#' | sort -u | while read -r h; do
  f="blobs/sha256/$(echo "$h" | cut -c1-2)/$h/data"
  if [ -f "$f" ]; then echo "@@MANIFEST sha256:$h"; cat "$f"; echo; fi
done
echo "@@BLOBKB $(du -sk blobs | cut -f1)"
'@ -replace "`r", ''

function Get-TagRecords {
    $records = [System.Collections.Generic.List[object]]::new()
    if ($RegistryRoot) {
        $repos = Join-Path $RegistryRoot 'docker/registry/v2/repositories'
        $base = (Resolve-Path $repos).Path.TrimEnd('\', '/')
        foreach ($f in Get-ChildItem -LiteralPath $base -Recurse -File -Filter link) {
            $rel = $f.FullName.Substring($base.Length + 1) -replace '\\', '/'
            if ($rel -notmatch '^(?<repo>.+)/_manifests/tags/(?<tag>[^/]+)/current/link$') { continue }
            $records.Add([pscustomobject]@{
                    Repo   = $Matches.repo
                    Tag    = $Matches.tag
                    Digest = (Get-Content -Raw -LiteralPath $f.FullName).Trim()
                    MTime  = [DateTimeOffset]::new($f.LastWriteTimeUtc).ToUnixTimeSeconds()
                })
        }
        return $records
    }
    foreach ($line in Invoke-VolumeRead $ListTagsScript) {
        $parts = "$line".Split("`t")
        if ($parts.Count -ne 3) { continue }
        if ($parts[1] -notmatch '^\./(?<repo>.+)/_manifests/tags/(?<tag>[^/]+)/current/link$') { continue }
        $records.Add([pscustomobject]@{
                Repo = $Matches.repo; Tag = $Matches.tag; Digest = $parts[2].Trim(); MTime = [long]$parts[0]
            })
    }
    return $records
}

# Returns @{ Manifests = @{digest = @{Json; Size}}; BlobBytes = <long> }.
function Get-ManifestStore {
    $manifests = @{}
    $blobBytes = [long]0
    if ($RegistryRoot) {
        $v2 = Join-Path $RegistryRoot 'docker/registry/v2'
        $blobs = Join-Path $v2 'blobs'
        foreach ($l in Get-ChildItem -LiteralPath (Join-Path $v2 'repositories') -Recurse -File -Filter link) {
            if (($l.FullName -replace '\\', '/') -notmatch '/_manifests/revisions/sha256/(?<h>[0-9a-f]+)/link$') { continue }
            $h = $Matches.h
            $data = Join-Path $blobs "sha256/$($h.Substring(0, 2))/$h/data"
            if (Test-Path -LiteralPath $data) {
                $text = Get-Content -Raw -LiteralPath $data
                $manifests["sha256:$h"] = @{ Text = $text; Size = (Get-Item -LiteralPath $data).Length }
            }
        }
        if (Test-Path -LiteralPath $blobs) {
            $blobBytes = [long](Get-ChildItem -LiteralPath $blobs -Recurse -File | Measure-Object -Property Length -Sum).Sum
        }
    } else {
        $current = $null
        $buf = [System.Text.StringBuilder]::new()
        foreach ($line in (Invoke-VolumeRead $ListManifestsScript) + @('@@END')) {
            $s = "$line"
            if ($s -match '^@@(MANIFEST (?<d>sha256:[0-9a-f]+)|BLOBKB (?<kb>\d+)|END)\s*$') {
                if ($current) {
                    $t = $buf.ToString()
                    $manifests[$current] = @{ Text = $t; Size = [Text.Encoding]::UTF8.GetByteCount($t.TrimEnd("`n")) }
                }
                $current = $null; [void]$buf.Clear()
                if ($Matches['d']) { $current = $Matches['d'] }
                if ($Matches['kb']) { $blobBytes = [long]$Matches['kb'] * 1024 }
                continue
            }
            if ($current) { [void]$buf.Append($s).Append("`n") }
        }
    }
    foreach ($k in @($manifests.Keys)) {
        try { $manifests[$k].Json = $manifests[$k].Text | ConvertFrom-Json } catch { $manifests[$k].Json = $null }
    }
    return @{ Manifests = $manifests; BlobBytes = $blobBytes }
}

# ------------------------------------------------------------- references ---
function ConvertFrom-ImageRef([string]$Ref) {
    $ref = $Ref.Trim()
    if (-not $ref) { return $null }
    $digest = $null
    if ($ref -match '^(?<name>[^@]+)@(?<d>sha256:[0-9a-f]{64})$') { $ref = $Matches.name; $digest = $Matches.d }
    $segments = $ref.Split('/')
    if ($segments.Count -gt 1 -and ($segments[0] -match '[.:]' -or $segments[0] -eq 'localhost')) {
        $ref = ($segments | Select-Object -Skip 1) -join '/'
    }
    $tag = $null
    $last = $ref.Split('/')[-1]
    if ($last.Contains(':')) {
        $tag = $last.Split(':', 2)[1]
        $ref = $ref.Substring(0, $ref.Length - $tag.Length - 1)
    }
    if (-not $tag -and -not $digest) { $tag = 'latest' }
    return [pscustomobject]@{ Repo = $ref; Tag = $tag; Digest = $digest }
}

# Pins: hashtable "repo:tag" or "repo@digest" -> list of reasons.
$Pins = @{}
function Add-Pin([string]$Key, [string]$Why) {
    if (-not $Pins.ContainsKey($Key)) { $Pins[$Key] = [System.Collections.Generic.List[string]]::new() }
    if (-not $Pins[$Key].Contains($Why)) { $Pins[$Key].Add($Why) }
}

$Warnings = [System.Collections.Generic.List[string]]::new()

function Add-GitPins([string]$Checkout, [string[]]$Refs, [string]$Label, [string[]]$RepoNames) {
    if (-not $Checkout) { return }
    if (-not (Test-Path -LiteralPath $Checkout)) {
        if ($Apply) { Stop-Refused "$Label checkout $Checkout does not exist." }
        $Warnings.Add("$Label checkout $Checkout does not exist; its pins are NOT protected."); return
    }
    $alts = ($RepoNames | Sort-Object Length -Descending | ForEach-Object { [regex]::Escape($_) -replace '\\-', '-' }) -join '|'
    $ere = "(^|[^A-Za-z0-9._-])($alts)(:[A-Za-z0-9._-]+|@sha256:[0-9a-f]{64})"
    $rx = "(?<repo>$alts)(?::(?<tag>[A-Za-z0-9._-]+)|@(?<digest>sha256:[0-9a-f]{64}))$"
    foreach ($ref in $Refs) {
        $null = git -C $Checkout rev-parse --verify --quiet "$ref^{commit}" 2>$null
        if ($LASTEXITCODE -ne 0) {
            if ($Apply) { Stop-Refused "$Label ref $ref does not resolve in $Checkout; fetch it first." }
            $Warnings.Add("$Label ref $ref does not resolve; its pins are NOT protected."); continue
        }
        $hits = git -C $Checkout grep -I -h -o -E $ere $ref -- '*.yml' '*.yaml' '*.ps1' '*.psm1' '*.sh' '*Dockerfile*' 2>$null
        if ($LASTEXITCODE -gt 1) { throw "git grep failed in $Checkout at $ref (exit $LASTEXITCODE)." }
        foreach ($h in @($hits)) {
            if ("$h" -notmatch $rx) { continue }
            if ($Matches['tag']) { Add-Pin "$($Matches.repo):$($Matches.tag)" "pinned in $Label@$ref" }
            if ($Matches['digest']) { Add-Pin "$($Matches.repo)@$($Matches.digest)" "pinned by digest in $Label@$ref" }
        }
    }
}

function Add-ContainerPins {
    $rows = @(docker ps -a --no-trunc --format "{{.ID}}`t{{.Names}}`t{{.Image}}" 2>$null)
    if ($LASTEXITCODE -ne 0) { throw 'docker ps -a failed; in-use images cannot be protected.' }
    $names = @{}
    foreach ($row in $rows) {
        $p = "$row".Split("`t")
        if ($p.Count -lt 3) { continue }
        $names[$p[0]] = $p[1]
        $r = ConvertFrom-ImageRef $p[2]
        if ($r -and $r.Tag) { Add-Pin "$($r.Repo):$($r.Tag)" "used by container $($p[1])" }
        if ($r -and $r.Digest) { Add-Pin "$($r.Repo)@$($r.Digest)" "used by container $($p[1])" }
    }
    if ($names.Count -eq 0) { return }
    $imageOf = @{}
    foreach ($row in @(docker inspect --format "{{.Id}}`t{{.Image}}" @($names.Keys) 2>$null)) {
        $p = "$row".Split("`t")
        if ($p.Count -eq 2) { $imageOf[$p[0]] = $p[1] }
    }
    $ids = @($imageOf.Values | Sort-Object -Unique)
    if ($ids.Count -eq 0) { return }
    foreach ($row in @(docker image inspect --format "{{.Id}}`t{{json .RepoTags}}`t{{json .RepoDigests}}" $ids 2>$null)) {
        $p = "$row".Split("`t")
        if ($p.Count -ne 3) { continue }
        $users = @($imageOf.Keys | Where-Object { $imageOf[$_] -eq $p[0] } | ForEach-Object { $names[$_] }) -join ', '
        foreach ($t in @($p[1] | ConvertFrom-Json)) {
            $r = ConvertFrom-ImageRef $t
            if ($r -and $r.Tag) { Add-Pin "$($r.Repo):$($r.Tag)" "image of container $users" }
        }
        foreach ($d in @($p[2] | ConvertFrom-Json)) {
            $r = ConvertFrom-ImageRef $d
            if ($r -and $r.Digest) { Add-Pin "$($r.Repo)@$($r.Digest)" "image digest of container $users" }
        }
    }
}

# -------------------------------------------------------------- selection ---
function Select-Retention($Records) {
    $decisions = [System.Collections.Generic.List[object]]::new()
    foreach ($group in $Records | Group-Object Repo) {
        $repo = $group.Name
        $tags = @($group.Group)
        $why = @{}
        foreach ($t in $tags) { $why[$t.Tag] = [System.Collections.Generic.List[string]]::new() }
        $dated = @($tags | Where-Object { $_.Tag -match $DatedPattern })
        $undated = @($tags | Where-Object { $_.Tag -notmatch $DatedPattern })

        foreach ($line in $dated | Group-Object { ($_.Tag -replace $DatedPattern, '${line}') }) {
            $line.Group | Sort-Object @{ Expression = { $_.Tag -replace $DatedPattern, '${date}' }; Descending = $true },
            @{ Expression = 'MTime'; Descending = $true } | Select-Object -First $KeepDated |
            ForEach-Object { $why[$_.Tag].Add("dated: newest $KeepDated of $($line.Name)-p*") }
        }
        $byAge = @($undated | Sort-Object @{ Expression = 'MTime'; Descending = $true }, @{ Expression = 'Tag'; Descending = $true })
        $byAge | Select-Object -First $KeepNewest | ForEach-Object { $why[$_.Tag].Add("newest $KeepNewest") }
        foreach ($t in $undated) {
            if ($t.Tag -notmatch $ShaPattern) { $why[$t.Tag].Add('named tag') }
        }
        foreach ($t in $tags) {
            $k = "${repo}:$($t.Tag)"
            if ($Pins.ContainsKey($k)) { $Pins[$k] | ForEach-Object { $why[$t.Tag].Add($_) } }
            $k = "$repo@$($t.Digest)"
            if ($Pins.ContainsKey($k)) { $Pins[$k] | ForEach-Object { $why[$t.Tag].Add($_) } }
            $lower = $t.Tag.ToLowerInvariant()
            foreach ($s in $KeepShas) {
                if ($lower.StartsWith($s)) { $why[$t.Tag].Add("-KeepShas $s") }
            }
        }
        # A kept commit keeps all its tags (<sha> and <sha>-deploy).
        $keptShas = @{}
        foreach ($t in $tags) {
            if ($why[$t.Tag].Count -gt 0 -and $t.Tag -match $ShaPattern) { $keptShas[$Matches.sha] = $t.Tag }
        }
        foreach ($t in $tags) {
            if ($why[$t.Tag].Count -eq 0 -and $t.Tag -match $ShaPattern -and $keptShas.ContainsKey($Matches.sha)) {
                $why[$t.Tag].Add("same commit as kept $($keptShas[$Matches.sha])")
            }
        }
        foreach ($t in $tags) {
            $sha = if ($t.Tag -match $ShaPattern) { $Matches.sha } else { $null }
            $decisions.Add([pscustomobject]@{
                    Repo    = $repo
                    Tag     = $t.Tag
                    Digest  = $t.Digest
                    MTime   = $t.MTime
                    Sha     = $sha
                    Keep    = ($why[$t.Tag].Count -gt 0)
                    Reasons = @($why[$t.Tag])
                })
        }
    }
    return $decisions
}

# Blobs reachable from a set of manifest digests: digest -> bytes.
function Get-Reach($Digests, $Manifests) {
    $reach = @{}
    $seen = @{}
    $queue = [System.Collections.Generic.Queue[string]]::new()
    foreach ($d in $Digests) { if ($d) { $queue.Enqueue($d) } }
    while ($queue.Count -gt 0) {
        $d = $queue.Dequeue()
        if ($seen.ContainsKey($d)) { continue }
        $seen[$d] = $true
        $m = $Manifests[$d]
        if (-not $m) { continue }
        if (-not $reach.ContainsKey($d)) { $reach[$d] = [long]$m.Size }
        $j = $m.Json
        if (-not $j) { continue }
        if ($j.PSObject.Properties['config'] -and $j.config.digest) { $reach[$j.config.digest] = [long]$j.config.size }
        if ($j.PSObject.Properties['layers']) {
            foreach ($c in @($j.layers)) { if ($c.digest) { $reach[$c.digest] = [long]$c.size } }
        }
        if ($j.PSObject.Properties['manifests']) {
            foreach ($c in @($j.manifests)) {
                if ($c.digest) { $reach[$c.digest] = [long]$c.size; $queue.Enqueue($c.digest) }
            }
        }
    }
    return $reach
}

function Format-GB([long]$Bytes) { '{0:N1} GB' -f ($Bytes / 1GB) }

# ------------------------------------------------------------------- main ---
$records = @(Get-TagRecords)
if ($records.Count -eq 0) { throw 'no tags found in the registry layout; refusing to guess.' }
foreach ($r in $records) {
    if ($r.Repo -notmatch $RepoPattern -or $r.Tag -notmatch $TagPattern) {
        throw "unexpected repository or tag name '$($r.Repo):$($r.Tag)'; refusing to continue."
    }
}
$repoNames = @($records.Repo | Sort-Object -Unique)

Add-GitPins $MykronosCheckout $MykronosRefs 'mykronos' $repoNames
if ($TheHubCheckout) { Add-GitPins $TheHubCheckout $TheHubRefs 'TheHub' $repoNames }
else { $Warnings.Add('no -TheHubCheckout: images pinned only in TheHub are NOT protected.') }
Add-ContainerPins

$decisions = @(Select-Retention $records)
$store = Get-ManifestStore
$kept = @($decisions | Where-Object Keep)
$dropped = @($decisions | Where-Object { -not $_.Keep })
$keptReach = Get-Reach @($kept | ForEach-Object Digest) $store.Manifests
$keptBytes = [long](($keptReach.Values | Measure-Object -Sum).Sum)
$allDroppedOnly = @{}

$mode = if ($Apply) { 'APPLY' } else { 'DRY RUN (nothing is changed; -Apply to act)' }
Write-Host "Registry retention - $mode"
Write-Host "Rules: newest $KeepNewest per repo; dated base images newest $KeepDated per line; named tags; pins; in-use; -KeepShas $($KeepShas -join ',')"
foreach ($w in $Warnings) { Write-Host "WARNING: $w" }
Write-Host ''

$repoSummaries = [System.Collections.Generic.List[object]]::new()
foreach ($group in $decisions | Group-Object Repo | Sort-Object Name) {
    $k = @($group.Group | Where-Object Keep)
    $d = @($group.Group | Where-Object { -not $_.Keep })
    $reach = Get-Reach @($d | ForEach-Object Digest) $store.Manifests
    $only = [long]0
    foreach ($key in $reach.Keys) {
        if (-not $keptReach.ContainsKey($key)) { $only += $reach[$key]; $allDroppedOnly[$key] = $reach[$key] }
    }
    Write-Host ('{0}: {1} tags, keep {2}, drop {3} (~{4} only in dropped tags)' -f $group.Name, $group.Count, $k.Count, $d.Count, (Format-GB $only))
    foreach ($t in $k | Sort-Object MTime -Descending) { Write-Host "  keep  $($t.Tag)  [$($t.Reasons -join '; ')]" }
    if ($d.Count -gt 0) {
        Write-Host "  drop  $($d.Count) tag(s), not newest $KeepNewest and not pinned, in use or listed:"
        foreach ($t in $d | Sort-Object MTime -Descending) {
            Write-Host ("  drop  {0}  ({1:yyyy-MM-dd})" -f $t.Tag, [DateTimeOffset]::FromUnixTimeSeconds($t.MTime).UtcDateTime)
        }
    }
    $repoSummaries.Add([pscustomobject]@{
            repo = $group.Name; tags = $group.Count; kept = $k.Count; dropped = $d.Count; bytes_only_in_dropped = $only
        })
}
$droppedOnlyBytes = [long](($allDroppedOnly.Values | Measure-Object -Sum).Sum)
$gcEstimate = [Math]::Max([long]0, $store.BlobBytes - $keptBytes)
Write-Host ''
Write-Host ("Total: keep {0}, drop {1} of {2} tags." -f $kept.Count, $dropped.Count, $decisions.Count)
Write-Host ("Blob store {0}; reachable from kept tags {1}." -f (Format-GB $store.BlobBytes), (Format-GB $keptBytes))
Write-Host ("Estimated freed: {0} referenced only by dropped tags; up to {1} once garbage-collect also removes blobs nothing tagged references." -f (Format-GB $droppedOnlyBytes), (Format-GB $gcEstimate))

if (-not $ReportPath) {
    $dir = Join-Path ([IO.Path]::GetTempPath()) 'registry-retention'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $ReportPath = Join-Path $dir ("retention-{0:yyyyMMddTHHmmssZ}.json" -f [DateTime]::UtcNow)
}
$report = [ordered]@{
    generated_utc   = [DateTime]::UtcNow.ToString('o')
    mode            = if ($Apply) { 'apply' } else { 'dry-run' }
    rules           = [ordered]@{ keep_newest = $KeepNewest; keep_dated = $KeepDated; keep_shas = $KeepShas }
    warnings        = @($Warnings)
    estimate        = [ordered]@{
        blob_store_bytes = $store.BlobBytes; kept_reachable_bytes = $keptBytes
        only_in_dropped_bytes = $droppedOnlyBytes; gc_upper_bytes = $gcEstimate
    }
    repositories    = @($repoSummaries)
    dropped         = @($dropped | Sort-Object Repo, Tag | ForEach-Object {
            [ordered]@{ repo = $_.Repo; tag = $_.Tag; digest = $_.Digest; sha = $_.Sha
                pushed_utc = [DateTimeOffset]::FromUnixTimeSeconds($_.MTime).UtcDateTime.ToString('o') }
        })
    kept            = @($kept | Sort-Object Repo, Tag | ForEach-Object {
            [ordered]@{ repo = $_.Repo; tag = $_.Tag; digest = $_.Digest; reasons = $_.Reasons }
        })
}
$report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ReportPath -Encoding utf8
Write-Host "Report: $ReportPath"

if (-not $Apply) { exit 0 }
if ($dropped.Count -eq 0) { Write-Host 'Nothing to drop.'; exit 0 }

# ------------------------------------------------------------------ apply ---
$image = Get-ServiceImage
$work = Join-Path ([IO.Path]::GetTempPath()) ("registry-retention-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $work | Out-Null
$lines = @($dropped | ForEach-Object { "$($_.Repo) $($_.Tag)" })
[IO.File]::WriteAllText((Join-Path $work 'drop.txt'), (($lines -join "`n") + "`n"))

function Get-VolumeKB {
    $out = docker run --rm --network none --pull never --volume "${Volume}:/var/lib/registry:ro" `
        --entrypoint du $image -sk /var/lib/registry
    if ($LASTEXITCODE -ne 0) { throw 'measuring the volume failed.' }
    return [long](("$(@($out)[-1])" -split '\s+')[0])
}

$before = Get-VolumeKB
Write-Host ("Volume before: {0}" -f (Format-GB ($before * 1024)))

$RemoveScript = @'
# retention:remove-tags
R=/var/lib/registry/docker/registry/v2/repositories
n=0
while read -r repo tag; do
  [ -n "$repo" ] || continue
  d="$R/$repo/_manifests/tags/$tag"
  if [ -d "$d" ]; then rm -rf -- "$d" && n=$((n+1)); else echo "already gone: $repo:$tag"; fi
done < /retention/drop.txt
echo "removed $n tag directories"
'@ -replace "`r", ''
docker run --rm --network none --pull never --volume "${Volume}:/var/lib/registry" `
    --volume "${work}:/retention:ro" --entrypoint sh $image -c $RemoveScript
if ($LASTEXITCODE -ne 0) { throw "removing tag directories failed (exit $LASTEXITCODE); the report lists what was meant to go." }

$gcLog = Join-Path $work 'garbage-collect.log'
docker run --rm --network none --pull never --volume "${Volume}:/var/lib/registry" `
    $image garbage-collect --delete-untagged /etc/distribution/config.yml *> $gcLog
$gcExit = $LASTEXITCODE
Get-Content -LiteralPath $gcLog -Tail 5 | ForEach-Object { Write-Host "  gc: $_" }
if ($gcExit -ne 0) { throw "garbage-collect failed (exit $gcExit); full log: $gcLog" }

$after = Get-VolumeKB
Write-Host ("Volume after: {0} (freed {1})" -f (Format-GB ($after * 1024)), (Format-GB (($before - $after) * 1024)))
Write-Host "garbage-collect log: $gcLog"
Write-Host ''
Write-Host 'The registry is still stopped. Start it with:'
$compose = Join-Path $PSScriptRoot 'docker-compose.yml'
Write-Host "  docker compose --project-name mykronos-concourse --file `"$compose`" up -d --no-deps registry"
exit 0
