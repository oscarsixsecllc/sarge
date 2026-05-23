# lib/findings.ps1  -  Shared verdict + finding emission helpers (Windows)
#
# Mirrors the bash side's passx/failx/skipx pattern (see assessment/assess.sh).
# Each finding is:
#   - echoed to stdout as a single human-readable line
#   - appended to the global $script:SargeFindings array of [pscustomobject]
#     records, which assess.ps1 serializes to
#     %USERPROFILE%\.sarge\state\findings-<run-id>.json at end of run
#
# Verdict vocabulary (must match build-report.ps1 + findings-catalog.json):
#   PASS                        -  control evaluated, configuration meets baseline
#   FAIL                        -  control evaluated, configuration violates baseline
#   WARN                        -  control evaluated, configuration is suspicious / review
#   SKIP-CONTEXT-DEFERRED       -  control not evaluated locally (e.g. needs elevation,
#                                no applicable resource, probe data missing). Same
#                                meaning as the bash side's skipx.
#   ENFORCED-EXTERNALLY         -  control is moot locally because AppLocker / WDAC /
#                                Intune / GPO is providing the enforcement. Sourced
#                                from Get-SargeWindowsContext.
#   UNTESTED                    -  probe ran but result is ambiguous (e.g. cmdlet
#                                returned empty unexpectedly). Treated like SKIP
#                                by the report but distinguished for triage.
#
# All findings carry the WIN- namespace prefix on the check_id where the ID is
# Windows-specific (e.g. WIN-AC-3-workspace-acl) to avoid colliding with the
# existing Ubuntu/macOS IDs in findings-catalog.json. Where a check_id matches
# the bash side semantically and the catalog already exists, we keep the
# unprefixed ID (e.g. AC-2-empty-password) for catalog reuse.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Get-Variable -Name SargeFindings -Scope Script -ErrorAction SilentlyContinue)) {
    $script:SargeFindings = New-Object System.Collections.Generic.List[object]
}

# Emit one finding. Caller passes:
#   -Id          stable check_id, e.g. 'WIN-SC-7-firewall-domain'
#   -Family      'AC' | 'AU' | 'CM' | 'IA' | 'SC' | 'SI'
#   -ControlId   '800-53 control id', e.g. 'SC-7'
#   -Verdict     PASS|FAIL|WARN|SKIP-CONTEXT-DEFERRED|ENFORCED-EXTERNALLY|UNTESTED
#   -Message     human-readable line shown in stdout + report
#   -Recommendation optional concrete fix string
function Add-SargeFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Id,
        [Parameter(Mandatory)] [ValidateSet('AC','AU','CM','IA','SC','SI','POL')] [string] $Family,
        [Parameter(Mandatory)] [string] $ControlId,
        [Parameter(Mandatory)]
        [ValidateSet('PASS','FAIL','WARN','SKIP-CONTEXT-DEFERRED','ENFORCED-EXTERNALLY','UNTESTED')]
        [string] $Verdict,
        [Parameter(Mandatory)] [string] $Message,
        [string] $Recommendation = ''
    )

    # Map verdict -> 4-letter tag for the stdout line (mirrors bash side).
    $tag = switch ($Verdict) {
        'PASS'                    { 'PASS' }
        'FAIL'                    { 'FAIL' }
        'WARN'                    { 'WARN' }
        'SKIP-CONTEXT-DEFERRED'   { 'SKIP' }
        'ENFORCED-EXTERNALLY'     { 'EXTN' }
        'UNTESTED'                { 'UNTS' }
    }

    Write-Output ("  [{0}] {1}: {2}" -f $tag, $Id, $Message)

    $script:SargeFindings.Add([pscustomobject]@{
        id              = $Id
        control_family  = $Family
        control_id      = $ControlId
        verdict         = $Verdict
        message         = $Message
        recommendation  = $Recommendation
    }) | Out-Null
}

# Helper for checks: load the previously-written windows-context.json so a
# check script can read context.active_controls.applocker_active etc. Returns
# $null if the context file doesn't exist (assess.ps1 will refuse to run
# checks in that case, but defensive nonetheless).
function Get-SargeContext {
    [CmdletBinding()]
    param()
    $ctxPath = Join-Path $env:USERPROFILE '.sarge\state\windows-context.json'
    if (-not (Test-Path -LiteralPath $ctxPath)) { return $null }
    try {
        return (Get-Content -LiteralPath $ctxPath -Raw | ConvertFrom-Json)
    } catch {
        Write-Warning "Failed to parse windows-context.json: $($_.Exception.Message)"
        return $null
    }
}

# Run a check scriptblock with the standard error-capture pattern. If the
# scriptblock throws, emit an UNTESTED finding with the exception message
# so a single broken probe doesn't kill the run.
function Invoke-SargeCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Id,
        [Parameter(Mandatory)] [ValidateSet('AC','AU','CM','IA','SC','SI','POL')] [string] $Family,
        [Parameter(Mandatory)] [string] $ControlId,
        [Parameter(Mandatory)] [scriptblock] $Check
    )
    try {
        & $Check
    } catch {
        Add-SargeFinding -Id $Id -Family $Family -ControlId $ControlId `
            -Verdict 'UNTESTED' `
            -Message ("probe raised: {0}" -f $_.Exception.Message) `
            -Recommendation 'Re-run with -Verbose; file an issue at https://github.com/oscarsixsecllc/sarge/issues if reproducible.'
    }
}
