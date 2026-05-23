# lib/policy-overlay.ps1 - Pure policy-overlay logic.
#
# Phase 1b (issue #31, refactor #41). This file defines the Apply-PolicyOverlay
# function in isolation so it can be dot-sourced by tests (Pester) without
# pulling in the top-level Invoke-SargeCheck calls that live in
# assessment/checks/check-policy.ps1.
#
# Apply-PolicyOverlay re-verdicts any Phase 1a finding whose subject is
# enforced by detected managed policy. Mutates the supplied Findings list
# in place. Conservative: only flips FAIL/WARN -> ENFORCED-EXTERNALLY when
# a matching policy key is present and non-zero.
#
# The overlay is intentionally limited in this Phase 1b cut. We map a small
# set of well-known CSP/GPO settings to finding IDs. Future PRs will expand
# the map; for now we cover the highest-signal overlaps:
#   - DeviceLock/MaxInactivityTimeDeviceLock           -> WIN-AC-11-idle-lock
#   - DeviceGuard/EnableVirtualizationBasedSecurity    -> WIN-SI-7-wdac-policy
#   - Defender/RealtimeProtection (or similar)         -> WIN-SI-3-defender-realtime
#   - AccountPolicy/AccountLockoutThreshold            -> WIN-AC-7-lockout-threshold

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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
