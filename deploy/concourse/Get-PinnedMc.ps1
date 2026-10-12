<#
.SYNOPSIS
    Return the path to bin\mc.exe, fetching the pinned release if it is absent.

.DESCRIPTION
    Dot-sourced by publish-netassess-run.ps1 and
    ..\personal-soc\Install-PersonalSocSkills.ps1, the two host-side halves of
    the personal-soc pipeline. One pin, so the two cannot drift apart.

    Both used to fetch https://dl.min.io/client/mc/release/windows-amd64/mc.exe
    on first use. That URL now returns 410 Gone: MinIO archived the
    open-source client. Once bin\mc.exe went missing, both Scheduled Tasks threw
    before doing anything - the weekly scan ran but never published (so
    netassess-freshness went red), and the skill install never acknowledged
    (so `package` timed out). The installed skills sat at an August commit
    while every fix after it reached only the repository.

    Same release and same rule as the pipeline's MC_RELEASE / MC_SHA256
    (PS-8, a fetched binary is code): a GitHub release pinned by tag and
    verified by digest. Bump all of them together.

.NOTES
    ASCII only - see setup.ps1.
#>

$script:McRelease = "RELEASE.2025-08-13T08-35-41Z"
$script:McWindowsSha256 = "c8db13ebeda31497f354c0e950809db0ae9b2a2a69b8afee68c128c37300c157"

function Get-PinnedMc {
    $mc = Join-Path $PSScriptRoot "bin\mc.exe"
    if (Test-Path $mc) {
        # An existing binary is checked too: a copy left behind by the old
        # unpinned fetch is exactly as unverified as a fresh one would be.
        if ((Get-FileHash $mc -Algorithm SHA256).Hash -eq $script:McWindowsSha256) { return $mc }
        Write-Host "bin\mc.exe does not match the pinned digest - replacing it." -ForegroundColor Yellow
    }

    New-Item -ItemType Directory -Force -Path (Split-Path $mc) | Out-Null
    $tmp = "$mc.download"
    Write-Host "Fetching mc $script:McRelease..." -ForegroundColor Cyan
    Invoke-WebRequest -UseBasicParsing -OutFile $tmp `
        -Uri "https://github.com/minio/mc/releases/download/$script:McRelease/mc.windows-amd64.$script:McRelease.exe"

    $actual = (Get-FileHash $tmp -Algorithm SHA256).Hash
    if ($actual -ne $script:McWindowsSha256) {
        Remove-Item $tmp -Force
        throw "mc.exe digest mismatch: expected $script:McWindowsSha256, got $actual"
    }
    Move-Item $tmp $mc -Force
    return $mc
}
