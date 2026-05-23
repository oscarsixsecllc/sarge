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

# SI-5: security alerts pipeline - WSUS + Defender sample submission
Invoke-SargeCheck -Id 'WIN-SI-5-update-reporting' -Family 'SI' -ControlId 'SI-5' -Check {
    $r = Get-SargeSiUpdateReporting
    $wsusSet = (-not [string]::IsNullOrWhiteSpace([string]$r.wsus_status_server))
    $sampleOk = ($null -ne $r.submit_samples_consent -and $r.submit_samples_consent -ge 1)
    if ($wsusSet -or $sampleOk) {
        Add-SargeFinding -Id 'WIN-SI-5-update-reporting' -Family 'SI' -ControlId 'SI-5' `
            -Verdict 'PASS' `
            -Message ("Security alerts pipeline: wsus_status_server set=$wsusSet; SubmitSamplesConsent=$($r.submit_samples_consent)")
    } else {
        Add-SargeFinding -Id 'WIN-SI-5-update-reporting' -Family 'SI' -ControlId 'SI-5' `
            -Verdict 'WARN' `
            -Message 'No WSUS status server configured AND Defender sample submission disabled - host is not reporting security telemetry' `
            -Recommendation 'GPO > Windows Update > Specify intranet Microsoft update service location, or Set-MpPreference -SubmitSamplesConsent 1 (elevated).'
    }
}

# SI-8: spam protection - informational unless a mail role is present
Invoke-SargeCheck -Id 'WIN-SI-8-spam-protection' -Family 'SI' -ControlId 'SI-8' -Check {
    $r = Get-SargeSiMailRole
    if ($r.mail_role_detected) {
        Add-SargeFinding -Id 'WIN-SI-8-spam-protection' -Family 'SI' -ControlId 'SI-8' `
            -Verdict 'WARN' `
            -Message ("Mail-role services detected (" + ($r.mail_role_services_present -join ', ') + "); SI-8 applies - verify spam protection deployed") `
            -Recommendation 'Deploy server-side spam protection (Exchange anti-spam transport agent or third-party gateway).'
    } else {
        Add-SargeFinding -Id 'WIN-SI-8-spam-protection' -Family 'SI' -ControlId 'SI-8' `
            -Verdict 'SKIP-CONTEXT-DEFERRED' `
            -Message 'No mail role detected on host; SI-8 N/A for this asset (informational)'
    }
}

# SI-16: memory protection - DEP / ASLR / CFG / image-signing
Invoke-SargeCheck -Id 'WIN-SI-16-memory-protection' -Family 'SI' -ControlId 'SI-16' -Check {
    $r = Get-SargeSiMemoryProtection
    $issues = @()
    if ($null -eq $r.dep -or $r.dep -notmatch '(?i)ON|TRUE|ENABLE') { $issues += "DEP=$($r.dep)" }
    if ($null -eq $r.aslr_force_relocate -or $r.aslr_force_relocate -notmatch '(?i)ON|TRUE|ENABLE') { $issues += "ASLR ForceRelocate=$($r.aslr_force_relocate)" }
    if ($null -eq $r.cfg -or $r.cfg -notmatch '(?i)ON|TRUE|ENABLE') { $issues += "CFG=$($r.cfg)" }
    if ($issues.Count -eq 0) {
        Add-SargeFinding -Id 'WIN-SI-16-memory-protection' -Family 'SI' -ControlId 'SI-16' `
            -Verdict 'PASS' `
            -Message ("Memory protection enabled system-wide: DEP=$($r.dep), ASLR=$($r.aslr_force_relocate), CFG=$($r.cfg)")
    } else {
        Add-SargeFinding -Id 'WIN-SI-16-memory-protection' -Family 'SI' -ControlId 'SI-16' `
            -Verdict 'WARN' `
            -Message ('System-wide ProcessMitigation gaps: ' + ($issues -join '; ')) `
            -Recommendation 'Set-ProcessMitigation -System -Enable DEP,ForceRelocateImages,CFG (elevated). Review Get-ProcessMitigation -System for full set.'
    }
}
