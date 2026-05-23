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

$gpoPresentLocal = $false
if ($null -ne $ctx) { $gpoPresentLocal = [bool]$ctx.enterprise_context.gpo_present }

# AC-8: legal logon notification banner present
Invoke-SargeCheck -Id 'WIN-AC-8-legal-banner' -Family 'AC' -ControlId 'AC-8' -Check {
    $r = Get-SargeAcLegalBanner
    if ($r.caption_length -gt 0 -and $r.text_length -gt 0) {
        Add-SargeFinding -Id 'WIN-AC-8-legal-banner' -Family 'AC' -ControlId 'AC-8' `
            -Verdict 'PASS' `
            -Message ("Legal logon banner configured (caption '$($r.caption)', text $($r.text_length) chars)")
    } else {
        $verdict = if ($intuneManaged -or $gpoPresentLocal) { 'ENFORCED-EXTERNALLY' } else { 'FAIL' }
        $msg = if ($verdict -eq 'ENFORCED-EXTERNALLY') {
            "Legal banner caption/text missing locally - likely supplied by GPO/Intune (caption_length=$($r.caption_length), text_length=$($r.text_length))"
        } else {
            "No legal logon banner configured (caption_length=$($r.caption_length), text_length=$($r.text_length))"
        }
        Add-SargeFinding -Id 'WIN-AC-8-legal-banner' -Family 'AC' -ControlId 'AC-8' `
            -Verdict $verdict `
            -Message $msg `
            -Recommendation 'secpol.msc > Local Policies > Security Options > Interactive logon: Message title/text for users attempting to log on.'
    }
}

# AC-12: session termination - SMB autodisconnect
Invoke-SargeCheck -Id 'WIN-AC-12-session-termination' -Family 'AC' -ControlId 'AC-12' -Check {
    $r = Get-SargeAcSessionTermination
    if ($null -eq $r.autodisconnect_minutes) {
        Add-SargeFinding -Id 'WIN-AC-12-session-termination' -Family 'AC' -ControlId 'AC-12' `
            -Verdict 'PASS' `
            -Message 'LanmanServer autodisconnect not explicitly set (Windows default: 15 min)'
        return
    }
    if ($r.autodisconnect_minutes -lt 0) {
        $verdict = if ($gpoPresentLocal) { 'ENFORCED-EXTERNALLY' } else { 'FAIL' }
        Add-SargeFinding -Id 'WIN-AC-12-session-termination' -Family 'AC' -ControlId 'AC-12' `
            -Verdict $verdict `
            -Message "LanmanServer autodisconnect=$($r.autodisconnect_minutes) (never disconnect)" `
            -Recommendation 'Set HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters\autodisconnect to 15 (minutes).'
    } elseif ($r.autodisconnect_minutes -le 15) {
        Add-SargeFinding -Id 'WIN-AC-12-session-termination' -Family 'AC' -ControlId 'AC-12' `
            -Verdict 'PASS' `
            -Message "LanmanServer autodisconnect=$($r.autodisconnect_minutes) min (<=15)"
    } else {
        Add-SargeFinding -Id 'WIN-AC-12-session-termination' -Family 'AC' -ControlId 'AC-12' `
            -Verdict 'WARN' `
            -Message "LanmanServer autodisconnect=$($r.autodisconnect_minutes) min (recommend <=15)" `
            -Recommendation 'Lower the autodisconnect minute value to 15 or less.'
    }
}

# AC-17: RDP remote access posture
Invoke-SargeCheck -Id 'WIN-AC-17-rdp-posture' -Family 'AC' -ControlId 'AC-17' -Check {
    $r = Get-SargeAcRdpPosture
    if ($r.rdp_disabled) {
        Add-SargeFinding -Id 'WIN-AC-17-rdp-posture' -Family 'AC' -ControlId 'AC-17' `
            -Verdict 'PASS' `
            -Message 'RDP disabled (fDenyTSConnections=1) - no remote access surface'
        return
    }
    $issues = @()
    if ($null -eq $r.user_authentication) {
        $issues += 'UserAuthentication unset'
    } elseif (-not $r.nla_required) {
        $issues += "NLA disabled (UserAuthentication=$($r.user_authentication))"
    }
    if ($null -ne $r.min_encryption_level -and $r.min_encryption_level -lt 3) {
        $issues += "MinEncryptionLevel=$($r.min_encryption_level) (<3 = below High)"
    }
    if ($null -ne $r.security_layer -and $r.security_layer -lt 2) {
        $issues += "SecurityLayer=$($r.security_layer) (<2 = pre-CredSSP/TLS)"
    }
    if ($issues.Count -eq 0) {
        Add-SargeFinding -Id 'WIN-AC-17-rdp-posture' -Family 'AC' -ControlId 'AC-17' `
            -Verdict 'PASS' `
            -Message "RDP NLA required, MinEncryption=$($r.min_encryption_level), SecurityLayer=$($r.security_layer)"
    } else {
        $verdict = if ($gpoPresentLocal) { 'ENFORCED-EXTERNALLY' } else { 'FAIL' }
        Add-SargeFinding -Id 'WIN-AC-17-rdp-posture' -Family 'AC' -ControlId 'AC-17' `
            -Verdict $verdict `
            -Message ('RDP posture issues: ' + ($issues -join '; ')) `
            -Recommendation 'Set RDP-Tcp UserAuthentication=1; MinEncryptionLevel=3; SecurityLayer=2 (elevated). Or disable RDP if not needed.'
    }
}
