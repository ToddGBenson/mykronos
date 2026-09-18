# #59329: the appliers' source guard has six STATIC tests and has never been
# EXECUTED. The story's own bar: "a guard that has only ever been observed
# passing is not known to work". So run it, in every state it claims to refuse.
#
# Throwaway repos under $env:TEMP. Nothing touches a real checkout, no network,
# no Concourse.
$ErrorActionPreference = 'Stop'
$guard = Join-Path $PSScriptRoot 'PipelineSource.ps1'
if (-not (Test-Path $guard)) { throw "PipelineSource.ps1 not found beside this script" }
. $guard

$root = Join-Path $env:TEMP ("guardprobe-" + [guid]::NewGuid().ToString('N').Substring(0,8))
$originDir = Join-Path $root 'origin.git'
$workDir   = Join-Path $root 'work'
New-Item -ItemType Directory -Path $root -Force | Out-Null

function New-Fixture {
    param([switch]$NoOrigin, [switch]$NoMain)
    Remove-Item -Recurse -Force $originDir, $workDir -ErrorAction SilentlyContinue
    git init --bare --quiet $originDir
    git init --quiet -b main $workDir
    Push-Location $workDir
    git config user.email probe@local; git config user.name probe
    New-Item -ItemType Directory -Path 'pipelines' -Force | Out-Null
    'jobs: []' | Set-Content 'pipelines/thehub.yml'
    git add -A; git commit --quiet -m 'seed'
    if (-not $NoOrigin) {
        git remote add origin $originDir
        git push --quiet -u origin main 2>$null
    }
    if ($NoMain) { git checkout --quiet -b other; git branch -D main --quiet }
    Pop-Location
}

$results = @()
function Probe {
    param([string]$Name, [scriptblock]$Arrange, [string]$Expect)
    & $Arrange
    $verdict = 'ALLOWED'; $msg = ''
    try {
        $null = Assert-PipelineSourceIsMain -Root $workDir -Pipeline 'thehub' 6>$null
    } catch {
        $verdict = 'REFUSED'; $msg = ($_.Exception.Message -split "`n")[0]
    }
    $ok = ($verdict -eq $Expect)
    $script:results += [pscustomobject]@{
        Scenario = $Name; Expected = $Expect; Got = $verdict
        Pass = $ok; Detail = $msg.Substring(0, [Math]::Min(96, $msg.Length))
    }
}

Probe 'clean, on main, level with origin' { New-Fixture } 'ALLOWED'

Probe 'HEAD on a feature branch' {
    New-Fixture; Push-Location $workDir; git checkout --quiet -b feature/x; Pop-Location
} 'REFUSED'

Probe 'tracked file modified (dirty tree)' {
    New-Fixture; Push-Location $workDir
    'jobs: [{name: sneaked-in}]' | Set-Content 'pipelines/thehub.yml'; Pop-Location
} 'REFUSED'

Probe 'main is behind origin/main' {
    New-Fixture; Push-Location $workDir
    'jobs: [{name: newer}]' | Set-Content 'pipelines/thehub.yml'
    git add -A; git commit --quiet -m 'newer'; git push --quiet origin main 2>$null
    git reset --hard --quiet HEAD~1; Pop-Location
} 'REFUSED'

Probe 'no origin/main to compare against' { New-Fixture -NoOrigin } 'REFUSED'

Probe 'no local main branch at all' { New-Fixture -NoMain } 'REFUSED'

# The override must still work, loudly -- a guard with no escape hatch gets
# disabled wholesale the first time somebody genuinely needs one.
$ovr = 'ALLOWED'
New-Fixture; Push-Location $workDir; git checkout --quiet -b feature/y; Pop-Location
try { $null = Assert-PipelineSourceIsMain -Root $workDir -Pipeline 'thehub' -AllowAnyBranch 6>$null }
catch { $ovr = 'REFUSED' }
$results += [pscustomobject]@{
    Scenario = '-AllowAnyBranch on a feature branch'; Expected = 'ALLOWED'; Got = $ovr
    Pass = ($ovr -eq 'ALLOWED'); Detail = 'documented override'
}

$results | Format-Table -AutoSize Scenario, Expected, Got, Pass
$failed = @($results | Where-Object { -not $_.Pass })
"{0} scenarios, {1} behaved as documented, {2} did not" -f $results.Count, ($results.Count - $failed.Count), $failed.Count
if ($failed) { $failed | Format-Table -AutoSize Scenario, Expected, Got, Detail }
Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue
if ($failed) { exit 1 }
