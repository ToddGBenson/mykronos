<#
.SYNOPSIS
    Apply TheHub delivery pipeline: scan, gate, demo, DAST, and prod on a click.

.DESCRIPTION
    Spec 16. This was a scanning-only pipeline and is now the whole path to
    production, so it needs materially more than the three variables it used
    to: two deploy keys, a pinned host key, the two environment URLs, and the
    Azure service principal the cloud-posture job authenticates with.

    Where each value comes from:

      backend\.env              the ingestion token and the Oracle gate token
      deploy\concourse\.env     the Concourse login and the Azure principal
      deploy\concourse\keys\    the two deploy keys and the pinned host key

    All three are gitignored. Nothing this script writes survives it: the vars
    file is created in the temp directory and deleted in a finally block, which
    is the existing pattern across the three set-pipeline scripts and is kept
    deliberately so there is one way to do this rather than three.

    The git credential is a GitHub App installation token minted fresh by
    `mykronos github-token`. It lasts an hour: long enough to scan a branch,
    not long enough for a pipeline left running. Re-run this to refresh it.
    That limitation is CNC-2's problem to solve properly.

    Run Install-DeployKey.ps1 (in deploy\thehub) once per environment before
    this. Without the keys the deploy jobs cannot authenticate, and this script
    refuses to apply a pipeline whose deploy half is guaranteed to fail.

.PARAMETER AllowMissingAzure
    Apply the pipeline without an Azure service principal. The delivery jobs
    all work; cloud-posture fails at runtime with a message saying why. That is
    the right failure isolation - a missing backup-subscription credential
    should not block deploying TheHub - but it is opt-in, because the quiet
    version of this is a cloud scan nobody notices never ran.

.NOTES
    ASCII only - see setup.ps1.
#>

[CmdletBinding()]
param(
    [string]$Target = "mykronos",
    [string]$Pipeline = "thehub",
    [string]$Branch = "develop",
    [string]$Concourse = "http://localhost:8080",

    # The host both environments run on, reached by IP for the same reason
    # every other address in these pipelines is: garden task containers resolve
    # through public DNS and have never heard of `host.docker.internal`.
    [string]$DeployHost = "192.168.0.14",
    [string]$DeployUser = "concourse-deploy",
    [string]$DemoUrl = "http://192.168.0.14:8200",
    [string]$ProdUrl = "http://192.168.0.14:8000",

    [string]$Registry = "192.168.0.14:5000",
    [string]$ProwlerVersion = "5.5.0",
    [string]$TimeZone = "America/Phoenix",

    [switch]$AllowMissingAzure,
    [switch]$Pause
)

$ErrorActionPreference = "Stop"
$fly = Join-Path $PSScriptRoot "bin\fly.exe"
$backend = Join-Path $PSScriptRoot "..\..\backend"
$keys = Join-Path $PSScriptRoot "keys"

function Read-EnvValue {
    param([string]$Path, [string]$Key, [switch]$Optional)
    $line = Select-String -Path $Path -Pattern "^$Key=" -ErrorAction SilentlyContinue
    if (-not $line) {
        if ($Optional) { return "" }
        throw "$Key is not set in $Path"
    }
    return $line.Line.Split('=', 2)[1].Trim()
}

# A private key is many lines, and `key: -----BEGIN...` is not YAML. Emitted as
# a literal block scalar with every line indented, which preserves the newlines
# ssh requires - a key joined onto one line is rejected with "invalid format",
# which reads like a corrupt key rather than a mangled one.
function Format-YamlBlock {
    param([string]$Name, [string]$Path)
    $lines = @("${Name}: |")
    foreach ($line in (Get-Content -Path $Path)) { $lines += "  $line" }
    return $lines
}

$stackEnv = Join-Path $PSScriptRoot ".env"
$backendEnv = Join-Path $backend ".env"
foreach ($file in @($stackEnv, $backendEnv)) {
    if (-not (Test-Path $file)) { throw "Missing $file" }
}

$demoKey = Join-Path $keys "thehub-demo-deploy"
$prodKey = Join-Path $keys "thehub-prod-deploy"
$knownHosts = Join-Path $keys "thehub-known_hosts"
foreach ($file in @($demoKey, $prodKey, $knownHosts)) {
    if (-not (Test-Path $file)) {
        throw "Missing $file. Run deploy\thehub\Install-DeployKey.ps1 first - " +
              "this pipeline deploys, and applying it without deploy keys " +
              "produces a pipeline whose last three jobs cannot ever pass."
    }
}

# Optional, and deliberately so: see -AllowMissingAzure.
$azureClientId = Read-EnvValue $stackEnv "AZURE_CLIENT_ID" -Optional
$azureClientSecret = Read-EnvValue $stackEnv "AZURE_CLIENT_SECRET" -Optional
$azureTenantId = Read-EnvValue $stackEnv "AZURE_TENANT_ID" -Optional
$azureSubscriptionId = Read-EnvValue $stackEnv "AZURE_SUBSCRIPTION_ID" -Optional

if (-not $azureClientId -or -not $azureSubscriptionId) {
    if (-not $AllowMissingAzure) {
        throw "No Azure service principal in $stackEnv. Set AZURE_CLIENT_ID, " +
              "AZURE_CLIENT_SECRET, AZURE_TENANT_ID and AZURE_SUBSCRIPTION_ID, " +
              "or pass -AllowMissingAzure to apply the pipeline with the " +
              "cloud-posture job left unable to run."
    }
    Write-Host "No Azure principal: cloud-posture will fail at runtime." -ForegroundColor Yellow
}

Write-Host "Minting a GitHub App installation token (valid one hour)..." -ForegroundColor Cyan
Push-Location $backend
try {
    $ghToken = (& ".\.venv\Scripts\python.exe" -m mykronos.cli github-token ToddGBenson/TheHub 2>$null | Select-Object -Last 1).Trim()
} finally {
    Pop-Location
}
if (-not $ghToken -or -not $ghToken.StartsWith("ghs_")) {
    throw "Did not get an installation token. Is the GitHub App configured in backend/.env?"
}

& $fly --target $Target login --concourse-url $Concourse `
    --username (Read-EnvValue $stackEnv "CONCOURSE_LOCAL_USER") `
    --password (Read-EnvValue $stackEnv "CONCOURSE_LOCAL_PASSWORD") `
    --team-name main | Out-Null
if ($LASTEXITCODE -ne 0) { throw "fly login failed" }

$varsFile = Join-Path ([System.IO.Path]::GetTempPath()) "thehub-vars-$(Get-Random).yml"
try {
    $vars = @(
        "mykronos-url: http://192.168.0.14:8100",
        "mykronos-ref: v1",
        "thehub-branch: $Branch",
        "github-token: $ghToken",
        "thehub-ingestion-token: $(Read-EnvValue $backendEnv 'MYKRONOS_THEHUB_CONCOURSE_TOKEN')",
        "mykronos-gate-token: $(Read-EnvValue $backendEnv 'MYKRONOS_GATE_TOKEN')",
        "registry: $Registry",
        "prowler-version: $ProwlerVersion",
        "scan-timezone: $TimeZone",
        "thehub-demo-url: $DemoUrl",
        "thehub-prod-url: $ProdUrl",
        "deploy-host: $DeployHost",
        "deploy-ssh-user: $DeployUser",
        "azure-client-id: $azureClientId",
        "azure-client-secret: $azureClientSecret",
        "azure-tenant-id: $azureTenantId",
        "azure-subscription-id: $azureSubscriptionId",
        # Optional, and quoted so an unset webhook parses as an empty string
        # rather than YAML null. Every job's notifier checks for empty and
        # skips: the pipeline has to be applicable before Slack exists, and a
        # missing notification must never become a second failure on top of
        # the one it was trying to report.
        #
        # A webhook URL is a bearer credential - anyone holding it can post to
        # the channel - so it comes from .env with the rest of them and is
        # never written into the pipeline file.
        "slack-webhook-url: '$(Read-EnvValue $stackEnv 'SLACK_WEBHOOK_URL' -Optional)'"
    )
    $vars += Format-YamlBlock "demo-deploy-key" $demoKey
    $vars += Format-YamlBlock "prod-deploy-key" $prodKey
    $vars += Format-YamlBlock "deploy-known-hosts" $knownHosts

    $vars | Set-Content -Path $varsFile -Encoding UTF8

    # Output discarded, and this is not tidiness. `fly set-pipeline` prints the
    # *resolved* configuration as a diff, with every `((var))` already
    # substituted - so an ordinary run of this script scrolls the ingestion
    # token, the gate token and any deploy key across the terminal, into the
    # scrollback, and into whatever is recording the session.
    #
    # Spec 15 section 6 and spec 16 section 11 both say no credential appears
    # in pipeline YAML or in build logs. Neither covered set-pipeline's own
    # output, which is the one place they were all visible at once.
    #
    # Errors still surface: fly writes those to stderr, and $LASTEXITCODE is
    # checked below either way. The real fix is a credential manager, so that
    # the config never contains a secret to print (spec 15 section 6) - this
    # closes the hole in the meantime.
    & $fly --target $Target set-pipeline --pipeline $Pipeline `
        --config (Join-Path $PSScriptRoot "pipelines\thehub.yml") `
        --load-vars-from $varsFile --non-interactive | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "fly set-pipeline failed" }
} finally {
    if (Test-Path $varsFile) { Remove-Item $varsFile -Force }
}

if ($Pause) {
    & $fly --target $Target pause-pipeline --pipeline $Pipeline
    Write-Host "`nPipeline applied and left paused." -ForegroundColor Yellow
} else {
    & $fly --target $Target unpause-pipeline --pipeline $Pipeline
}

Write-Host "`nDelivering branch '$Branch'." -ForegroundColor Green
Write-Host "  demo: $DemoUrl (automatic, once Oracle clears it)"
Write-Host "  prod: $ProdUrl (waits for you to trigger deploy-prod)"
Write-Host "  $Concourse/teams/main/pipelines/$Pipeline"
