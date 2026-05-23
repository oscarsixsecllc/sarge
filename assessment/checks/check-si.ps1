# assessment/checks/check-si.ps1  -  System & Information Integrity verdicts.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ctx = Get-SargeContext
$wdacActive = $false
if ($null -ne $ctx) { $wdacActive = [bool]$ctx.active_controls.wdac_active }

Write-Output "[SARGE] === SI: System & Information Integrity ==="

# SI-2: pending updates
Invoke-SargeCheck -Id 'WIN-SI-2-pending-updates' -Family 'SI' -ControlId 'SI-2' -Check {
    $r = Get-SargeSiPendingUpdates
    if ($r.pending_count -eq 0) {
        Add-SargeFinding -Id 'WIN-SI-2-pending-updates' -Family 'SI' -ControlId 'SI-2' `
            -Verdict 'PASS' `
            -Message 'No pending software updates from Microsoft Update'
    } else {
        $verdict = if ($r.pending_count -gt 5) { 'FAIL' } else { 'WARN' }
        Add-SargeFinding -Id 'WIN-SI-2-pending-updates' -Family 'SI' -ControlId 'SI-2' `
            -Verdict $verdict `
            -Message ("$($r.pending_count) pending update(s); first: " + ($r.sample_titles -join ' | ')) `
            -Recommendation 'Settings > Windows Update > Check for updates; or PSWindowsUpdate: Install-WindowsUpdate -AcceptAll'
    }
}

# SI-3: Defender realtime + tamper
Invoke-SargeCheck -Id 'WIN-SI-3-defender-realtime' -Family 'SI' -ControlId 'SI-3' -Check {
    $r = Get-SargeSiDefenderStatus
    if ($r.realtime_enabled -and $r.antivirus_enabled) {
        Add-SargeFinding -Id 'WIN-SI-3-defender-realtime' -Family 'SI' -ControlId 'SI-3' `
            -Verdict 'PASS' `
            -Message "Defender realtime + antivirus enabled (sig age $($r.signature_age_days) days, engine $($r.engine_version))"
    } else {
        Add-SargeFinding -Id 'WIN-SI-3-defender-realtime' -Family 'SI' -ControlId 'SI-3' `
            -Verdict 'FAIL' `
            -Message "Defender realtime=$($r.realtime_enabled), AV=$($r.antivirus_enabled)" `
            -Recommendation 'Set-MpPreference -DisableRealtimeMonitoring $false  (elevated); confirm no third-party AV is registered.'
    }
    if ($null -eq $r.tamper_protected) {
        Add-SargeFinding -Id 'WIN-SI-3-tamper-protection' -Family 'SI' -ControlId 'SI-3' `
            -Verdict 'UNTESTED' `
            -Message 'IsTamperProtected property not exposed by Get-MpComputerStatus on this build'
    } elseif ($r.tamper_protected) {
        Add-SargeFinding -Id 'WIN-SI-3-tamper-protection' -Family 'SI' -ControlId 'SI-3' `
            -Verdict 'PASS' `
            -Message 'Defender tamper protection enabled'
    } else {
        Add-SargeFinding -Id 'WIN-SI-3-tamper-protection' -Family 'SI' -ControlId 'SI-3' `
            -Verdict 'FAIL' `
            -Message 'Defender tamper protection DISABLED' `
            -Recommendation 'Settings > Privacy & Security > Windows Security > Virus & threat protection settings > Tamper Protection: On.'
    }
}

# SI-3: ASR rules
Invoke-SargeCheck -Id 'WIN-SI-3-asr-rules' -Family 'SI' -ControlId 'SI-3' -Check {
    $r = Get-SargeSiAsrRules
    if ($r.rule_count -eq 0) {
        Add-SargeFinding -Id 'WIN-SI-3-asr-rules' -Family 'SI' -ControlId 'SI-3' `
            -Verdict 'WARN' `
            -Message 'No ASR rules configured' `
            -Recommendation 'Configure ASR via Intune or: Set-MpPreference -AttackSurfaceReductionRules_Ids <guid> -AttackSurfaceReductionRules_Actions Enabled  (per rule, elevated).'
    } else {
        # Count rules set to Block (1) vs AuditMode (2) vs Disabled (0).
        $block = 0; $audit = 0; $off = 0
        for ($i = 0; $i -lt $r.rule_count; $i++) {
            switch ([int]$r.rule_actions[$i]) {
                1 { $block++ }
                2 { $audit++ }
                default { $off++ }
            }
        }
        Add-SargeFinding -Id 'WIN-SI-3-asr-rules' -Family 'SI' -ControlId 'SI-3' `
            -Verdict 'PASS' `
            -Message "ASR rules configured: block=$block, audit=$audit, disabled=$off (total $($r.rule_count))"
    }
}

# SI-4: Sysmon presence (informational)
Invoke-SargeCheck -Id 'WIN-SI-4-sysmon' -Family 'SI' -ControlId 'SI-4' -Check {
    $r = Get-SargeSiSysmonPresent
    if ($r.installed -and $r.running) {
        Add-SargeFinding -Id 'WIN-SI-4-sysmon' -Family 'SI' -ControlId 'SI-4' `
            -Verdict 'PASS' `
            -Message 'Sysmon installed and running'
    } elseif ($r.installed) {
        Add-SargeFinding -Id 'WIN-SI-4-sysmon' -Family 'SI' -ControlId 'SI-4' `
            -Verdict 'WARN' `
            -Message 'Sysmon installed but not running'
    } else {
        Add-SargeFinding -Id 'WIN-SI-4-sysmon' -Family 'SI' -ControlId 'SI-4' `
            -Verdict 'WARN' `
            -Message 'Sysmon not installed. Sysmon improves SI-4 system monitoring posture by recording process creation, network connections, file/registry changes, and other security-relevant telemetry that the default Windows event log does not capture.' `
            -Recommendation 'Install Sysmon from https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon and configure with a published policy. Olaf Hartong''s sysmon-modular (https://github.com/olafhartong/sysmon-modular) is a reasonable starting point.'
    }
}

# SI-7: WDAC policy presence (software integrity)
Invoke-SargeCheck -Id 'WIN-SI-7-wdac-policy' -Family 'SI' -ControlId 'SI-7' -Check {
    $r = Get-SargeSiWdacPolicyPresence
    if ($wdacActive) {
        Add-SargeFinding -Id 'WIN-SI-7-wdac-policy' -Family 'SI' -ControlId 'SI-7' `
            -Verdict 'ENFORCED-EXTERNALLY' `
            -Message "WDAC enforced (active policies: $($r.count))"
    } elseif ($r.count -gt 0) {
        Add-SargeFinding -Id 'WIN-SI-7-wdac-policy' -Family 'SI' -ControlId 'SI-7' `
            -Verdict 'WARN' `
            -Message "WDAC policy files present ($($r.count)) but WDAC not in enforced state per Win32_DeviceGuard" `
            -Recommendation 'Confirm policy is deployed in enforcement mode; some policies ship in audit-only.'
    } else {
        Add-SargeFinding -Id 'WIN-SI-7-wdac-policy' -Family 'SI' -ControlId 'SI-7' `
            -Verdict 'SKIP-CONTEXT-DEFERRED' `
            -Message 'No WDAC policy files present and WDAC not active' `
            -Recommendation 'WDAC is optional for SI-7; if required by your baseline, deploy via CITool or Intune.'
    }
}
