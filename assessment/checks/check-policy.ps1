# assessment/checks/check-policy.ps1 - Policy inspection verdicts (Windows).
#
# Phase 1b (issue #31). Consumes probes from lib/probes/windows-policy.ps1.
# Emits two top-level WIN-POL findings and provides the Apply-PolicyOverlay
# function used by assess.ps1 to re-verdict Phase 1a findings whose subject
# is enforced by detected managed policy.
#
# Dot-sourced by assess.ps1 only when --inspect-policy is passed. The
# variables it expects in caller scope:
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

# Apply-PolicyOverlay - re-verdict any Phase 1a finding whose subject is
# enforced by detected managed policy. Mutates the $script:SargeFindings
# list in place. Conservative: only flips FAIL/WARN -> ENFORCED-EXTERNALLY
# when a matching policy key is present and non-zero.
#
# The overlay is intentionally limited in this Phase 1b cut. We map a small
# set of well-known CSP/GPO settings to finding IDs. Future PRs will expand
# the map; for now we cover the highest-signal overlaps:
#   - DeviceLock/MaxInactivityTimeDeviceLock           -> WIN-AC-11-idle-lock
#   - DeviceGuard/EnableVirtualizationBasedSecurity    -> WIN-SI-7-wdac-policy
#   - Defender/RealtimeProtection (or similar)         -> WIN-SI-3-defender-realtime
#   - AccountPolicy/AccountLockoutThreshold            -> WIN-AC-7-lockout-threshold
function Apply-PolicyOverlay {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object] $Findings,
        [Parameter()] $Inventory,
        [Parameter()] $Gpresult,
        [Parameter()] $AdGpo
    )

    if ($null -eq $Findings) { return 0 }

    # Build a flat key->value map of policy enforcements we recognize.
    # Look in both the MDM CSP inventory and (if present) AD GPO data.
    $enforced = @{}

    if ($Inventory -and $Inventory -is [hashtable]) {
        foreach ($area in $Inventory.Keys) {
            $settings = $Inventory[$area]
            if ($null -eq $settings) { continue }
            foreach ($s in $settings.Keys) {
                $val = $settings[$s]
                if ($null -eq $val) { continue }
                # Treat any non-zero / non-empty value as "enforced".
                $isEnforced = $true
                if ($val -is [int] -and $val -eq 0) { $isEnforced = $false }
                if ($val -is [string] -and [string]::IsNullOrWhiteSpace($val)) { $isEnforced = $false }
                if ($isEnforced) {
                    $enforced[("{0}/{1}" -f $area, $s)] = $val
                }
            }
        }
    }

    # Map of substring patterns (case-insensitive) -> finding IDs they override.
    # Matched against the flat keys we built above. First-match wins.
    $overlayMap = @(
        @{ Pattern = 'DeviceLock';                     Id = 'WIN-AC-11-idle-lock';            Source = 'MDM CSP DeviceLock' },
        @{ Pattern = 'MaxInactivityTimeDeviceLock';    Id = 'WIN-AC-11-idle-lock';            Source = 'MDM CSP DeviceLock/MaxInactivityTime' },
        @{ Pattern = 'AccountLockoutThreshold';        Id = 'WIN-AC-7-lockout-threshold';     Source = 'MDM CSP AccountPolicy/Lockout' },
        @{ Pattern = 'EnableVirtualizationBasedSecurity'; Id = 'WIN-SI-7-wdac-policy';        Source = 'MDM CSP DeviceGuard/VBS' },
        @{ Pattern = 'AllowRealtimeMonitoring';        Id = 'WIN-SI-3-defender-realtime';     Source = 'MDM CSP Defender/AllowRealtimeMonitoring' },
        @{ Pattern = 'TamperProtection';               Id = 'WIN-SI-3-tamper-protection';     Source = 'MDM CSP Defender/TamperProtection' },
        @{ Pattern = 'AppLocker';                      Id = 'WIN-AC-3-workspace-acl';         Source = 'MDM CSP AppLocker' }
    )

    $overlayCount = 0
    foreach ($f in $Findings) {
        # Only consider Phase 1a FAIL/WARN findings (don't touch PASS or
        # already-EXTN). Skip the new POL findings themselves.
        if ($null -eq $f.verdict) { continue }
        if ($f.control_family -eq 'POL') { continue }
        if ($f.verdict -notin 'FAIL','WARN') { continue }

        foreach ($map in $overlayMap) {
            if ($f.id -ne $map.Id) { continue }
            $hit = $false
            foreach ($k in $enforced.Keys) {
                if ($k -imatch $map.Pattern) { $hit = $true; break }
            }
            if ($hit) {
                $oldVerdict = $f.verdict
                $f.verdict = 'ENFORCED-EXTERNALLY'
                $f.message = ("[overlay: {0}] " -f $map.Source) + $f.message + (" (was {0}; managed policy enforces this control)" -f $oldVerdict)
                $overlayCount++
                break
            }
        }
    }

    # GPO-side overlay: if any applied GPO mentions a relevant keyword in its
    # name, hint that the AD path may be enforcing the control. We don't
    # flip the verdict here because GPO display names are weak evidence;
    # future PRs will pull Get-GPRegistryValue for ground truth.

    return $overlayCount
}
