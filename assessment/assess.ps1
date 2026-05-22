# assessment/assess.ps1 - Sarge Windows entry point.
#
# Phase 1a (issue #12): runs detection + breadth-first checks across all six
# 800-53 control families and emits a Markdown + JSON report. No hardening
# in this phase; recommendations only.
#
# Read-only. Standard user. No network. No state changes outside
# %USERPROFILE%\.sarge\state\ and %USERPROFILE%\.sarge\reports\.
#
# Usage:
#   pwsh assessment/assess.ps1 [--help] [--version] [--checks-only] [--report-only]

[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $RemainingArgs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ShowHelp    = $false
$ShowVersion = $false
$ChecksOnly  = $false
$ReportOnly  = $false
foreach ($arg in @($RemainingArgs)) {
    switch ($arg) {
        '--help'         { $ShowHelp = $true }
        '-h'             { $ShowHelp = $true }
        '--version'      { $ShowVersion = $true }
        '-v'             { $ShowVersion = $true }
        '--checks-only'  { $ChecksOnly = $true }
        '--report-only'  { $ReportOnly = $true }
        default          { Write-Warning "Unknown argument ignored: $arg" }
    }
}

if ($ShowHelp) {
    @"
Sarge - NIST 800-53 Hardening Standard for OpenClaw (Windows entry point)

USAGE
    pwsh assessment/assess.ps1 [options]

OPTIONS
    --help, -h        Show this help and exit.
    --version, -v     Show version and exit.
    --checks-only     Skip the detection probe; assume windows-context.json
                      already exists. Useful when iterating on checks.
    --report-only     Skip detection and checks; rebuild the report from the
                      most recent findings JSON in state/.

SCOPE
    Detection + breadth-first checks across all six 800-53 families on
    Windows. Recommendations only; no hardening. See parent issue #12.
"@ | Write-Output
    exit 0
}

if ($ShowVersion) {
    Write-Output "Sarge assess.ps1 (Windows) - Phase 1a: detection + breadth-first checks"
    exit 0
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot  = Split-Path -Parent $scriptDir

$libDir         = Join-Path $repoRoot 'lib'
$probesDir      = Join-Path $libDir 'probes'
$checksDir      = Join-Path $scriptDir 'checks'
$reportDir      = Join-Path $scriptDir 'report'
$detectProbe    = Join-Path $scriptDir 'probes\detect-context.ps1'

# Dot-source platform + findings helpers + all 6 family probes.
. (Join-Path $libDir 'platform.ps1')
. (Join-Path $libDir 'findings.ps1')
. (Join-Path $reportDir 'build-report.ps1')

foreach ($p in 'windows-ac','windows-au','windows-cm','windows-ia','windows-sc','windows-si') {
    $path = Join-Path $probesDir ($p + '.ps1')
    if (-not (Test-Path -LiteralPath $path)) {
        Write-Error "Missing probe file: $path"
        exit 1
    }
    . $path
}

Write-Output "[SARGE] ======================================"
Write-Output "[SARGE]  Sarge - Windows assessment (Phase 1a)"
Write-Output "[SARGE]  Oscar Six Security LLC"
Write-Output "[SARGE]  $(Get-Date)"
Write-Output "[SARGE]  Host: $env:COMPUTERNAME"
Write-Output "[SARGE] ======================================"
Write-Output ""

$runId = (Get-Date).ToString('yyyyMMdd-HHmmss')

# Per-run folder: one self-contained directory per assessment run. All
# new artifacts (findings.json, report.md, report.json, context.json,
# software-inventory.json) land here. Legacy writes under
# ~\.sarge\state\windows-context.json and ~\.sarge\reports\ are preserved
# for backwards compatibility (Phase 1a, issue #12). Bash side stays on
# its existing layout for this PR; tracked separately.
$runRoot = Join-Path $env:USERPROFILE (".sarge\runs\" + $runId)
if (-not (Test-Path -LiteralPath $runRoot)) {
    New-Item -ItemType Directory -Path $runRoot -Force | Out-Null
}
$script:SargeRunRoot = $runRoot
$script:SargeRunId   = $runId

# Reset the findings list in case this is a re-entry within one session.
$script:SargeFindings = New-Object System.Collections.Generic.List[object]

# --- Detection -----------------------------------------------------------
if (-not $ChecksOnly -and -not $ReportOnly) {
    if (-not (Test-Path -LiteralPath $detectProbe)) {
        Write-Error "Detection probe not found at $detectProbe"
        exit 1
    }
    & $detectProbe
    if ($LASTEXITCODE -ne 0) {
        Write-Output "[SARGE] Detection probe exited $LASTEXITCODE; continuing with available context."
    }
}

# --- Checks --------------------------------------------------------------
if (-not $ReportOnly) {
    foreach ($fam in 'ac','au','cm','ia','sc','si') {
        $checkScript = Join-Path $checksDir ("check-" + $fam + ".ps1")
        if (-not (Test-Path -LiteralPath $checkScript)) {
            Write-Warning "Check script missing: $checkScript"
            continue
        }
        . $checkScript
    }
}

# --- Report --------------------------------------------------------------
if ($ReportOnly -and $script:SargeFindings.Count -eq 0) {
    # Load latest findings JSON from state/
    $stateDir = Join-Path $env:USERPROFILE '.sarge\state'
    $latest = Get-ChildItem -LiteralPath $stateDir -Filter 'findings-*.json' -ErrorAction SilentlyContinue |
              Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($null -eq $latest) {
        Write-Error "No findings JSON found in $stateDir. Run without --report-only first."
        exit 1
    }
    $loaded = Get-Content -LiteralPath $latest.FullName -Raw | ConvertFrom-Json
    foreach ($f in @($loaded)) { $script:SargeFindings.Add($f) | Out-Null }
}

try {
    # .ToArray() avoids a "Argument types do not match" binding error seen
    # when passing a Generic.List directly via splatting on PS 5.1.
    $findingsArr = $script:SargeFindings.ToArray()
    $result = Build-SargeReport -Findings $findingsArr -RunId $runId -RunRoot $runRoot
} catch {
    Write-Host "[SARGE] build-report failed: $($_.Exception.Message)"
    Write-Host ("[SARGE] InvocationInfo: " + $_.InvocationInfo.PositionMessage)
    Write-Host $_.ScriptStackTrace
    exit 1
}

Write-Output ""
Write-Output "[SARGE] ======================================"
Write-Output ("[SARGE]  Summary: PASS={0} FAIL={1} WARN={2} SKIP={3} EXT={4} UNT={5}" -f `
    $result.counts['PASS'], $result.counts['FAIL'], $result.counts['WARN'], `
    $result.counts['SKIP-CONTEXT-DEFERRED'], $result.counts['ENFORCED-EXTERNALLY'], $result.counts['UNTESTED'])
Write-Output "[SARGE]  Run folder:      $runRoot"
Write-Output "[SARGE]  Markdown report: $($result.markdown)"
Write-Output "[SARGE]  JSON report:     $($result.json)"
Write-Output "[SARGE]  Findings JSON:   $($result.findings)"
Write-Output "[SARGE] ======================================"

exit 0
