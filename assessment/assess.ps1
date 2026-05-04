# assessment/assess.ps1 — Sarge Windows entry point (detection-only)
#
# Mirrors the contract of assessment/assess.sh but for Windows. In this PR
# (parent issue #12, child issue #13) we only run the read-only enterprise
# context detection layer. Per-control checks land in subsequent PRs, one
# 800-53 control per PR — that's @keonik's pattern from #3 and we are
# carrying it across to the Windows surface.
#
# Read-only. Standard user. No network. No state changes outside
# %USERPROFILE%\.sarge\state\.
#
# Usage:
#   pwsh assessment/assess.ps1 [--help] [--version]

[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $RemainingArgs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ShowHelp    = $false
$ShowVersion = $false
foreach ($arg in @($RemainingArgs)) {
    switch ($arg) {
        '--help'     { $ShowHelp = $true }
        '-h'         { $ShowHelp = $true }
        '--version'  { $ShowVersion = $true }
        '-v'         { $ShowVersion = $true }
        default {
            Write-Warning "Unknown argument ignored: $arg"
        }
    }
}

if ($ShowHelp) {
    @"
Sarge — NIST 800-53 Hardening Standard for OpenClaw (Windows entry point)

USAGE
    pwsh assessment/assess.ps1 [--help] [--version]

CURRENT SCOPE
    Detection-only. Runs the read-only enterprise context probes and writes
    the result to %USERPROFILE%\.sarge\state\windows-context.json.

    Per-control checks (800-53 AC / AU / CM / IA / SC / SI families on Windows)
    land in subsequent PRs under parent issue
    https://github.com/oscarsixsecllc/sarge/issues/12.

OPTIONS
    --help, -h        Show this help and exit.
    --version, -v     Show version and exit.

ALSO SEE
    assessment/probes/detect-context.ps1   # the underlying detection probe
    lib/platform.ps1                        # Get-SargeWindowsContext function
"@ | Write-Output
    exit 0
}

if ($ShowVersion) {
    # Version surface mirrors the bash side (which has none today) — kept
    # simple and aligned with the README badge until we wire a real version
    # source. Bumping here will be a separate housekeeping PR.
    Write-Output "Sarge assess.ps1 (Windows entry point) — detection-only mode"
    exit 0
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$probe     = Join-Path $scriptDir 'probes\detect-context.ps1'

if (-not (Test-Path -LiteralPath $probe)) {
    Write-Error "Detection probe not found at $probe"
    exit 1
}

Write-Output "[SARGE] ======================================"
Write-Output "[SARGE]  Sarge — Windows enterprise context probe"
Write-Output "[SARGE]  Oscar Six Security LLC"
Write-Output "[SARGE]  $(Get-Date)"
Write-Output "[SARGE]  Host: $env:COMPUTERNAME"
Write-Output "[SARGE] ======================================"
Write-Output ""

# Run the probe (no --print here; assess.ps1 is the orchestrator, not a
# JSON dump). The probe handles its own error reporting via probe_errors.
& $probe
$probeExit = $LASTEXITCODE

if ($probeExit -ne 0) {
    Write-Output ""
    Write-Output "[SARGE] Detection probe exited with code $probeExit."
    Write-Output "[SARGE] Inspect %USERPROFILE%\.sarge\state\windows-context.json (if written)"
    Write-Output "[SARGE] and report at https://github.com/oscarsixsecllc/sarge/issues"
    exit $probeExit
}

Write-Output ""
Write-Output "[SARGE] Detection-only mode. Wrote %USERPROFILE%\.sarge\state\windows-context.json."
Write-Output "[SARGE] Per-control checks (AC / AU / CM / IA / SC / SI on Windows) land in"
Write-Output "[SARGE] subsequent PRs under parent issue:"
Write-Output "[SARGE]   https://github.com/oscarsixsecllc/sarge/issues/12"
Write-Output "[SARGE]"
Write-Output "[SARGE] Sarge is OpenClaw-scoped — it surfaces enterprise context (GPO, AppLocker,"
Write-Output "[SARGE] WDAC, Defender, Intune) so downstream checks can defer to your existing"
Write-Output "[SARGE] control authority. It is not a generic Windows hardening tool."

exit 0
