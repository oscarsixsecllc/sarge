# assessment/checks/check-au.ps1  -  Audit & Accountability verdicts.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ctx = Get-SargeContext
$gpoPresent = $false
if ($null -ne $ctx) { $gpoPresent = [bool]$ctx.enterprise_context.gpo_present }

Write-Output "[SARGE] === AU: Audit & Accountability ==="

# AU-2: critical audit categories enabled
Invoke-SargeCheck -Id 'WIN-AU-2-audit-policy' -Family 'AU' -ControlId 'AU-2' -Check {
    $p = Get-SargeAuAuditPolicy
    if ($p.entries.Count -eq 0) {
        Add-SargeFinding -Id 'WIN-AU-2-audit-policy' -Family 'AU' -ControlId 'AU-2' `
            -Verdict 'SKIP-CONTEXT-DEFERRED' `
            -Message 'auditpol returned no parseable rows (likely requires elevated session)' `
            -Recommendation 'Re-run from an elevated PowerShell, or inspect via secpol.msc > Local Policies > Audit Policy.'
        return
    }
    # Sarge-mandated minimum categories (per the OpenClaw 800-53 baseline).
    $required = @('Logon','Account Logon','Account Management','Policy Change','System Integrity')
    $missing  = @()
    foreach ($req in $required) {
        $match = $p.entries | Where-Object { $_.category -ieq $req }
        if (-not $match -or $match.setting -eq 'No Auditing') {
            $missing += $req
        }
    }
    if ($missing.Count -eq 0) {
        Add-SargeFinding -Id 'WIN-AU-2-audit-policy' -Family 'AU' -ControlId 'AU-2' `
            -Verdict 'PASS' `
            -Message ("Required audit categories enabled: " + ($required -join ', '))
    } else {
        $verdict = if ($gpoPresent) { 'ENFORCED-EXTERNALLY' } else { 'FAIL' }
        $note    = if ($gpoPresent) { '  -  may be overridden by GPO' } else { '' }
        Add-SargeFinding -Id 'WIN-AU-2-audit-policy' -Family 'AU' -ControlId 'AU-2' `
            -Verdict $verdict `
            -Message ("Audit categories not enabled: " + ($missing -join ', ') + $note) `
            -Recommendation ("For each: auditpol /set /category:`"<name>`" /success:enable /failure:enable (elevated). " +
                              "Example: auditpol /set /category:`"Logon`" /success:enable /failure:enable")
    }
}

# AU-4 / AU-12: event log retention + file location
Invoke-SargeCheck -Id 'WIN-AU-4-log-retention' -Family 'AU' -ControlId 'AU-4' -Check {
    $logs = Get-SargeAuEventLogMetadata
    $undersized = @()
    foreach ($l in $logs) {
        if (-not $l.accessible) { continue }
        if ($null -ne $l.max_size_mb -and $l.max_size_mb -lt 64) {
            $undersized += ("{0}={1}MB" -f $l.name, $l.max_size_mb)
        }
    }
    if ($undersized.Count -eq 0) {
        Add-SargeFinding -Id 'WIN-AU-4-log-retention' -Family 'AU' -ControlId 'AU-4' `
            -Verdict 'PASS' `
            -Message 'Core event logs sized >= 64 MB (or metadata unreadable, which is acceptable)'
    } else {
        Add-SargeFinding -Id 'WIN-AU-4-log-retention' -Family 'AU' -ControlId 'AU-4' `
            -Verdict 'WARN' `
            -Message ('Event logs sized below 64 MB: ' + ($undersized -join ', ')) `
            -Recommendation 'wevtutil sl Security /ms:268435456  # 256 MB; repeat per channel (elevated)'
    }
    # AU-12 just notes where they live; emit as informational PASS.
    $paths = ($logs | Where-Object { $_.accessible } | ForEach-Object { $_.file_path }) -join '; '
    Add-SargeFinding -Id 'WIN-AU-12-log-location' -Family 'AU' -ControlId 'AU-12' `
        -Verdict 'PASS' `
        -Message ("Audit channel files: " + $paths)
}

# AU-9: Security log ACL
Invoke-SargeCheck -Id 'WIN-AU-9-security-log-acl' -Family 'AU' -ControlId 'AU-9' -Check {
    $r = Get-SargeAuSecurityLogAcl
    if (-not $r.accessible) {
        # Most desirable outcome: standard user cannot read the ACL.
        Add-SargeFinding -Id 'WIN-AU-9-security-log-acl' -Family 'AU' -ControlId 'AU-9' `
            -Verdict 'PASS' `
            -Message "Security.evtx ACL not readable by standard user (expected)  -  '$($r.error)'"
        return
    }
    if ($r.extra_principals.Count -eq 0) {
        Add-SargeFinding -Id 'WIN-AU-9-security-log-acl' -Family 'AU' -ControlId 'AU-9' `
            -Verdict 'PASS' `
            -Message 'Security.evtx ACL limited to SYSTEM / Administrators / EventLog'
    } else {
        Add-SargeFinding -Id 'WIN-AU-9-security-log-acl' -Family 'AU' -ControlId 'AU-9' `
            -Verdict 'FAIL' `
            -Message ('Security.evtx ACL has unexpected principals: ' + ($r.extra_principals -join ', ')) `
            -Recommendation 'Reset via: icacls "%SystemRoot%\System32\Winevt\Logs\Security.evtx" /reset (elevated)'
    }
}

# AU-3: audit record content - Sysmon config richness check
Invoke-SargeCheck -Id 'WIN-AU-3-sysmon-config' -Family 'AU' -ControlId 'AU-3' -Check {
    $r = Get-SargeAuSysmonConfig
    if (-not $r.installed) {
        Add-SargeFinding -Id 'WIN-AU-3-sysmon-config' -Family 'AU' -ControlId 'AU-3' `
            -Verdict 'SKIP-CONTEXT-DEFERRED' `
            -Message 'Sysmon not installed - AU-3 audit-record-content depth check skipped (default Windows event fields apply)' `
            -Recommendation 'Install Sysmon with a published config (e.g. sysmon-modular) to enrich audit-record content (AU-3).'
        return
    }
    if ($r.rules_bytes -gt 0 -or $null -ne $r.config_hash) {
        Add-SargeFinding -Id 'WIN-AU-3-sysmon-config' -Family 'AU' -ControlId 'AU-3' `
            -Verdict 'PASS' `
            -Message "Sysmon present with config (rules_bytes=$($r.rules_bytes), hash present=$([bool]$r.config_hash))"
    } else {
        Add-SargeFinding -Id 'WIN-AU-3-sysmon-config' -Family 'AU' -ControlId 'AU-3' `
            -Verdict 'WARN' `
            -Message 'Sysmon installed but no config rules detected in service registry parameters' `
            -Recommendation 'Apply a config: sysmon -accepteula -i <config.xml>  (elevated)'
    }
}

# AU-6: SIEM / Windows Event Forwarding configured?
Invoke-SargeCheck -Id 'WIN-AU-6-event-forwarding' -Family 'AU' -ControlId 'AU-6' -Check {
    $r = Get-SargeAuEventForwarding
    if ($r.subscription_count -gt 0) {
        Add-SargeFinding -Id 'WIN-AU-6-event-forwarding' -Family 'AU' -ControlId 'AU-6' `
            -Verdict 'PASS' `
            -Message ("WEF SubscriptionManager configured ($($r.subscription_count) URL(s))")
    } else {
        $verdict = if ($gpoPresent) { 'ENFORCED-EXTERNALLY' } else { 'WARN' }
        Add-SargeFinding -Id 'WIN-AU-6-event-forwarding' -Family 'AU' -ControlId 'AU-6' `
            -Verdict $verdict `
            -Message 'No Windows Event Forwarding subscription manager URL set (no SIEM/WEF collector configured locally)' `
            -Recommendation 'Configure WEF via GPO > Windows Components > Event Forwarding > Configure target Subscription Manager.'
    }
}

# AU-8: time stamps - W32Time authoritative source
Invoke-SargeCheck -Id 'WIN-AU-8-time-config' -Family 'AU' -ControlId 'AU-8' -Check {
    $r = Get-SargeAuTimeConfig
    if ($null -eq $r.type) {
        Add-SargeFinding -Id 'WIN-AU-8-time-config' -Family 'AU' -ControlId 'AU-8' `
            -Verdict 'UNTESTED' `
            -Message 'w32tm /query /configuration returned no parseable Type line'
        return
    }
    if ($r.type -ieq 'NoSync') {
        Add-SargeFinding -Id 'WIN-AU-8-time-config' -Family 'AU' -ControlId 'AU-8' `
            -Verdict 'FAIL' `
            -Message "W32Time Type=NoSync (no time synchronization)" `
            -Recommendation 'w32tm /config /syncfromflags:manual /manualpeerlist:"time.windows.com,0x1" /update; net stop w32time && net start w32time (elevated).'
    } elseif ($r.type -ieq 'NTP' -or $r.type -ieq 'NT5DS' -or $r.type -ieq 'AllSync') {
        Add-SargeFinding -Id 'WIN-AU-8-time-config' -Family 'AU' -ControlId 'AU-8' `
            -Verdict 'PASS' `
            -Message "W32Time Type=$($r.type); NtpServer=$($r.ntp_server)"
    } else {
        Add-SargeFinding -Id 'WIN-AU-8-time-config' -Family 'AU' -ControlId 'AU-8' `
            -Verdict 'WARN' `
            -Message "W32Time Type=$($r.type) (unrecognized - review)" `
            -Recommendation 'Verify w32tm /query /status returns Source = an authoritative NTP server.'
    }
}
