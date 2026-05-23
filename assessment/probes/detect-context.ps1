# assessment/probes/detect-context.ps1 — Sarge Windows context probe runner
#
# Calls Get-SargeWindowsContext (lib/platform.ps1), writes the JSON document
# to $env:USERPROFILE\.sarge\state\windows-context.json, and optionally prints
# it to stdout when invoked with --print.
#
# Read-only. Standard user. No network. No state changes outside the
# .sarge\state directory under the current user's profile.
#
# Companion to bash-side gap analysis under assessment/checks/. Downstream
# OpenClaw-on-Windows control modules (parent issue #12) consume the JSON
# this writes.
#
# Usage:
#   pwsh assessment/probes/detect-context.ps1            # write only
#   pwsh assessment/probes/detect-context.ps1 --print    # write + print

[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $RemainingArgs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Print = $false
foreach ($arg in @($RemainingArgs)) {
    if ([string]::IsNullOrWhiteSpace($arg)) { continue }
    switch ($arg) {
        '--print' { $Print = $true }
        '-Print'  { $Print = $true }
        default {
            Write-Warning "Unknown argument ignored: $arg"
        }
    }
}

# Load the platform module (dot-source so Get-SargeWindowsContext is in scope).
# Layout:
#   <repo>/lib/platform.ps1
#   <repo>/assessment/probes/detect-context.ps1   <- this file
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot  = Split-Path -Parent (Split-Path -Parent $scriptDir)
$module    = Join-Path $repoRoot 'lib\platform.ps1'

if (-not (Test-Path -LiteralPath $module)) {
    Write-Error "lib/platform.ps1 not found at $module"
    exit 1
}

. $module

# Resolve output location. We deliberately use $env:USERPROFILE rather than
# $HOME because Windows PowerShell 5.1's $HOME defaults to the documents
# folder under some configurations, while USERPROFILE is the canonical
# %USERPROFILE% expansion every Windows version respects.
$stateDir = Join-Path $env:USERPROFILE '.sarge\state'
if (-not (Test-Path -LiteralPath $stateDir)) {
    New-Item -ItemType Directory -Path $stateDir -Force | Out-Null
}

$outFile = Join-Path $stateDir 'windows-context.json'

$context = Get-SargeWindowsContext
$json    = $context | ConvertTo-Json -Depth 6

# Write with UTF-8 (no BOM if PS7, with BOM on PS5 — downstream JSON parsers
# in PowerShell handle both; if a non-PS consumer ever reads this file we may
# need to revisit on PS5).
Set-Content -LiteralPath $outFile -Value $json -Encoding UTF8

if ($Print) {
    Write-Output $json
}

Write-Verbose "Wrote $outFile"
exit 0
