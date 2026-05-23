# assessment/checks/check-ac.ps1  -  Access Control verdicts (Windows).
#
# Consumes probes from lib/probes/windows-ac.ps1 and emits findings via
# Add-SargeFinding. Mirrors the pattern in assessment/checks/check-ac.sh.
#
# This script is dot-sourced by assess.ps1; it expects $RepoRoot to be set
# in the caller's scope and lib/findings.ps1 + lib/probes/windows-ac.ps1
# to already be dot-sourced.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ctx = Get-SargeContext
$applockerActive = $false
$wdacActive      = $false
$intuneManaged   = $false
if ($null -ne $ctx) {
    $applockerActive = [bool]$ctx.active_controls.applocker_active
    $wdacActive      = [bool]$ctx.active_controls.wdac_active
    $intuneManaged   = [bool]$ctx.enterprise_context.intune_managed
}

Write-Output "[SARGE] === AC: Access Control ==="

# AC-2: empty-password local accounts
Invoke-SargeCheck -Id 'AC-2-empty-password' -Family 'AC' -ControlId 'AC-2' -Check {
    $r = Get-SargeAcEmptyPasswordAccounts
    if ($r.accounts.Count -eq 0) {
        Add-SargeFinding -Id 'AC-2-empty-password' -Family 'AC' -ControlId 'AC-2' `
            -Verdict 'PASS' `
            -Message "No enabled local accounts with PasswordRequired=False ($($r.total) accounts inspected)"
    } else {
        Add-SargeFinding -Id 'AC-2-empty-password' -Family 'AC' -ControlId 'AC-2' `
            -Verdict 'FAIL' `
            -Message ("Enabled local accounts not requiring a password: " + ($r.accounts -join ', ')) `
            -Recommendation 'For each account: Set-LocalUser -Name <name> -PasswordNeverExpires $false; net user <name> * (then set a password); or Disable-LocalUser -Name <name>'
    }
}

# AC-3: workspace ACL
Invoke-SargeCheck -Id 'WIN-AC-3-workspace-acl' -Family 'AC' -ControlId 'AC-3' -Check {
    $r = Get-SargeAcOpenclawAcl
    if (-not $r.present) {
        Add-SargeFinding -Id 'WIN-AC-3-workspace-acl' -Family 'AC' -ControlId 'AC-3' `
            -Verdict 'SKIP-CONTEXT-DEFERRED' `
            -Message "OpenClaw workspace not present at $($r.path)  -  nothing to evaluate"
        return
    }
    if ($r.extra_principals.Count -eq 0) {
        Add-SargeFinding -Id 'WIN-AC-3-workspace-acl' -Family 'AC' -ControlId 'AC-3' `
            -Verdict 'PASS' `
            -Message "$($r.path) ACL restricted to owner + SYSTEM + Administrators"
    } else {
        Add-SargeFinding -Id 'WIN-AC-3-workspace-acl' -Family 'AC' -ControlId 'AC-3' `
            -Verdict 'FAIL' `
            -Message ("$($r.path) has unexpected ACE principals: " + ($r.extra_principals -join ', ')) `
            -Recommendation "icacls `"$($r.path)`" /inheritance:r /grant:r `"$($r.owner):(OI)(CI)F`" /grant:r `"NT AUTHORITY\SYSTEM:(OI)(CI)F`""
    }
}

# AC-6: local Administrators membership count
Invoke-SargeCheck -Id 'WIN-AC-6-admin-group' -Family 'AC' -ControlId 'AC-6' -Check {
    $r = Get-SargeAcAdminGroupMembers
    if ($r.count -le 2) {
        Add-SargeFinding -Id 'WIN-AC-6-admin-group' -Family 'AC' -ControlId 'AC-6' `
            -Verdict 'PASS' `
            -Message "Local Administrators has $($r.count) member(s): $($r.members -join ', ')"
    } else {
        Add-SargeFinding -Id 'WIN-AC-6-admin-group' -Family 'AC' -ControlId 'AC-6' `
            -Verdict 'WARN' `
            -Message "Local Administrators has $($r.count) members: $($r.members -join ', ')  -  review least-privilege" `
            -Recommendation 'Remove non-essential members: Remove-LocalGroupMember -SID S-1-5-32-544 -Member <name>'
    }
}

# AC-7: lockout policy
Invoke-SargeCheck -Id 'WIN-AC-7-lockout-threshold' -Family 'AC' -ControlId 'AC-7' -Check {
    $r = Get-SargeAcLockoutPolicy
    if ($null -eq $r.threshold) {
        Add-SargeFinding -Id 'WIN-AC-7-lockout-threshold' -Family 'AC' -ControlId 'AC-7' `
            -Verdict 'UNTESTED' `
            -Message 'Could not parse lockout threshold from `net accounts` output (localized?)' `
            -Recommendation 'Run `net accounts` manually and confirm lockout threshold <= 10.'
        return
    }
    if ($r.threshold -ieq 'Never' -or [int]($r.threshold -replace '\D','0') -eq 0) {
        Add-SargeFinding -Id 'WIN-AC-7-lockout-threshold' -Family 'AC' -ControlId 'AC-7' `
            -Verdict 'FAIL' `
            -Message "Account lockout threshold is '$($r.threshold)' (no lockout enforced)" `
            -Recommendation 'net accounts /lockoutthreshold:10 /lockoutduration:15 /lockoutwindow:15'
    } else {
        $t = [int]($r.threshold -replace '\D','0')
        if ($t -le 10) {
            Add-SargeFinding -Id 'WIN-AC-7-lockout-threshold' -Family 'AC' -ControlId 'AC-7' `
                -Verdict 'PASS' `
                -Message "Lockout threshold $t attempts, duration $($r.duration) min"
        } else {
            Add-SargeFinding -Id 'WIN-AC-7-lockout-threshold' -Family 'AC' -ControlId 'AC-7' `
                -Verdict 'WARN' `
                -Message ("Lockout threshold $t attempts (recommend 10 or fewer)") `
                -Recommendation 'net accounts /lockoutthreshold:10'
        }
    }
}

# AC-11: idle session lock
Invoke-SargeCheck -Id 'WIN-AC-11-idle-lock' -Family 'AC' -ControlId 'AC-11' -Check {
    $r = Get-SargeAcIdleLockPolicy
    # Domain-joined / Intune-managed surfaces are usually GPO-driven  -  defer.
    if ($intuneManaged -or ($null -ne $ctx -and $ctx.enterprise_context.gpo_present)) {
        Add-SargeFinding -Id 'WIN-AC-11-idle-lock' -Family 'AC' -ControlId 'AC-11' `
            -Verdict 'ENFORCED-EXTERNALLY' `
            -Message "Idle-lock policy likely set by GPO/Intune (gpo_present=$(($ctx.enterprise_context.gpo_present)), intune=$intuneManaged); local HKCU value is advisory only" `
            -Recommendation 'Confirm policy via gpresult /h or Settings > Accounts > Sign-in options.'
        return
    }
    if ($null -eq $r.user_timeout_seconds) {
        Add-SargeFinding -Id 'WIN-AC-11-idle-lock' -Family 'AC' -ControlId 'AC-11' `
            -Verdict 'WARN' `
            -Message 'ScreenSaveTimeOut not set under HKCU\Control Panel\Desktop' `
            -Recommendation 'Set-ItemProperty HKCU:\Control` Panel\Desktop ScreenSaveTimeOut 600; Set-ItemProperty HKCU:\Control` Panel\Desktop ScreenSaverIsSecure 1'
        return
    }
    if ($r.user_timeout_seconds -le 900 -and $r.user_screensaver_secure) {
        Add-SargeFinding -Id 'WIN-AC-11-idle-lock' -Family 'AC' -ControlId 'AC-11' `
            -Verdict 'PASS' `
            -Message "Idle lock $($r.user_timeout_seconds)s with re-auth"
    } else {
        Add-SargeFinding -Id 'WIN-AC-11-idle-lock' -Family 'AC' -ControlId 'AC-11' `
            -Verdict 'FAIL' `
            -Message ("Idle lock timeout=$($r.user_timeout_seconds)s, secure=$($r.user_screensaver_secure) - should be 900s or less with secure=true") `
            -Recommendation 'Settings > Personalization > Lock screen > Screen saver: set wait <= 15 min and "On resume, display logon screen".'
    }
}
