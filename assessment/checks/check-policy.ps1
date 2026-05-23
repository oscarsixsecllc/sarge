# assessment/checks/check-policy.ps1 - Policy inspection verdicts (Windows).
#
# Phase 1b (issue #31). Consumes probes from lib/probes/windows-policy.ps1.
# Emits two top-level WIN-POL findings. The Apply-PolicyOverlay function
# itself lives in lib/policy-overlay.ps1 (issue #41 refactor) so it can be
# unit-tested in isolation; the top-level Invoke-SargeCheck calls below
# would otherwise crash Pester at dot-source time.
#
# Dot-sourced by assess.ps1 only when --inspect-policy is passed. assess.ps1
# is responsible for dot-sourcing lib/policy-overlay.ps1 alongside the other
# lib helpers. The variables this script expects in caller scope:
#   $script:SargePolicyMode      - [pscustomobject] from Get-SargeHostPolicyMode
#   $script:SargePolicyInventory - hashtable from Get-SargeMdmPolicyInventory
#                                  (may be empty/$null for non-MDM modes)
#   $script:SargePolicyGpresult  - [pscustomobject]|$null from Get-SargeGpresultData
#   $script:SargePolicyAdGpo     - [pscustomobject]|$null from Get-SargeAdGpoData
#   $script:SargeRunRoot         - per-run folder for side-output writes

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Output "[SARGE] === POL: Policy Inspection ==="

# WIN-POL-1: AAD-joined but no MDM enforcement (high severity)
Invoke-SargeCheck -Id 'WIN-POL-1' -Family 'POL' -ControlId 'CM-2' -Check {
    $mode = $script:SargePolicyMode
    if ($null -eq $mode) {
        Add-SargeFinding -Id 'WIN-POL-1' -Family 'POL' -ControlId 'CM-2' `
            -Verdict 'UNTESTED' `
            -Message 'Policy mode probe did not run' `
            -Recommendation 'Re-run with --inspect-policy; check probe_errors in side-output.'
        return
    }
    switch ($mode.mode) {
        'aad-no-mdm' {
            Add-SargeFinding -Id 'WIN-POL-1' -Family 'POL' -ControlId 'CM-2' `
                -Verdict 'FAIL' `
                -Message ("AAD-joined but no MDM enforcement: " + $mode.reason + ". Local policy is the only enforcement surface; configuration drift cannot be centrally remediated.") `
                -Recommendation 'Enroll the device in Microsoft Intune (or another MDM) under the same AAD tenant. Settings > Accounts > Access work or school > Connect; or push enrollment via Conditional Access compliance policy.'
        }
        'aad-mdm' {
            Add-SargeFinding -Id 'WIN-POL-1' -Family 'POL' -ControlId 'CM-2' `
                -Verdict 'PASS' `
                -Message ("AAD-joined with MDM enrollment: " + $mode.reason)
        }
        'ad-rsat' {
            Add-SargeFinding -Id 'WIN-POL-1' -Family 'POL' -ControlId 'CM-2' `
                -Verdict 'PASS' `
                -Message ("AD-joined with RSAT-readable GPO inventory: " + $mode.reason)
        }
        'ad-gpresult' {
            Add-SargeFinding -Id 'WIN-POL-1' -Family 'POL' -ControlId 'CM-2' `
                -Verdict 'PASS' `
                -Message ("AD-joined; GPO source-of-truth available via gpresult: " + $mode.reason)
        }
        'workgroup' {
            Add-SargeFinding -Id 'WIN-POL-1' -Family 'POL' -ControlId 'CM-2' `
                -Verdict 'WARN' `
                -Message 'Workgroup host (not AD- or AAD-joined). No central policy authority exists; this is expected for personal devices but a finding for enterprise endpoints.' `
                -Recommendation 'Join the host to Azure AD (Settings > Accounts > Access work or school) or to an AD domain, then enroll in MDM/GPO.'
        }
        'unknown' {
            Add-SargeFinding -Id 'WIN-POL-1' -Family 'POL' -ControlId 'CM-2' `
                -Verdict 'UNTESTED' `
                -Message ('Policy mode could not be determined: ' + $mode.reason) `
                -Recommendation 'Confirm dsregcmd is available; run `dsregcmd /status` manually and re-run Sarge.'
        }
        default {
            Add-SargeFinding -Id 'WIN-POL-1' -Family 'POL' -ControlId 'CM-2' `
                -Verdict 'UNTESTED' `
                -Message ("Unrecognized policy mode: " + $mode.mode)
        }
    }
}

# WIN-POL-2: Policy inventory captured (informational PASS with side-output)
Invoke-SargeCheck -Id 'WIN-POL-2' -Family 'POL' -ControlId 'CM-6' -Check {
    $mode = $script:SargePolicyMode
    $inventory = $script:SargePolicyInventory
    $gpres = $script:SargePolicyGpresult
    $ad = $script:SargePolicyAdGpo

    # Build the side-output document.
    $sideOut = [ordered]@{
        version       = 1
        captured_at   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        mode          = if ($mode) { $mode.mode } else { 'unknown' }
        mode_reason   = if ($mode) { $mode.reason } else { $null }
        mdm_inventory = $inventory
        gpresult      = $gpres
        ad_gpo        = $ad
    }

    $runRoot = $script:SargeRunRoot
    $outPath = $null
    if ($runRoot -and (Test-Path -LiteralPath $runRoot)) {
        $outPath = Join-Path $runRoot 'policy-inventory.json'
        $sideOut | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $outPath -Encoding UTF8
    }

    # Count the inventory.
    $areaCount = 0
    $settingCount = 0
    if ($inventory -and $inventory -is [hashtable]) {
        $areaCount = $inventory.Keys.Count
        foreach ($k in $inventory.Keys) {
            $settingCount += $inventory[$k].Keys.Count
        }
    }

    $gpoCount = 0
    if ($gpres -and $gpres.applied_gpos) { $gpoCount = @($gpres.applied_gpos).Count }
    if ($ad   -and $ad.gpos)             { $gpoCount += @($ad.gpos).Count }

    $msg = ("Policy inventory captured: {0} CSP area(s), {1} setting(s), {2} GPO(s); side-output: {3}" -f `
        $areaCount, $settingCount, $gpoCount, $outPath)

    Add-SargeFinding -Id 'WIN-POL-2' -Family 'POL' -ControlId 'CM-6' `
        -Verdict 'PASS' -Message $msg
}

# Apply-PolicyOverlay now lives in lib/policy-overlay.ps1 (issue #41).
# assess.ps1 dot-sources that lib alongside the other lib helpers and
# invokes Apply-PolicyOverlay after Phase 1a checks have populated findings.
