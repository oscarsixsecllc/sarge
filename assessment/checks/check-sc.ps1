# assessment/checks/check-sc.ps1  -  System & Communications Protection verdicts.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ctx = Get-SargeContext
$gpoPresent = $false
if ($null -ne $ctx) { $gpoPresent = [bool]$ctx.enterprise_context.gpo_present }

Write-Output "[SARGE] === SC: System & Communications Protection ==="

# SC-7: firewall profile state
Invoke-SargeCheck -Id 'WIN-SC-7-firewall-profiles' -Family 'SC' -ControlId 'SC-7' -Check {
    $profiles = Get-SargeScFirewallProfiles
    $disabled = @($profiles | Where-Object { -not $_.enabled } | ForEach-Object { $_.name })
    if ($disabled.Count -eq 0) {
        Add-SargeFinding -Id 'WIN-SC-7-firewall-profiles' -Family 'SC' -ControlId 'SC-7' `
            -Verdict 'PASS' `
            -Message ("All firewall profiles enabled: " + ((($profiles) | ForEach-Object { $_.name }) -join ', '))
    } else {
        $verdict = if ($gpoPresent) { 'ENFORCED-EXTERNALLY' } else { 'FAIL' }
        Add-SargeFinding -Id 'WIN-SC-7-firewall-profiles' -Family 'SC' -ControlId 'SC-7' `
            -Verdict $verdict `
            -Message ("Firewall profiles disabled: " + ($disabled -join ', ')) `
            -Recommendation ("For each: Set-NetFirewallProfile -Profile <name> -Enabled True  (elevated)")
    }
}

# SC-7: listening ports
Invoke-SargeCheck -Id 'WIN-SC-7-listening-ports' -Family 'SC' -ControlId 'SC-7' -Check {
    $r = Get-SargeScListeningPorts
    if ($r.externally_listening.Count -eq 0) {
        Add-SargeFinding -Id 'WIN-SC-7-listening-ports' -Family 'SC' -ControlId 'SC-7' `
            -Verdict 'PASS' `
            -Message "No externally-bound listening TCP ports ($($r.total_listening) total listeners)"
    } else {
        $ports = ($r.externally_listening | ForEach-Object { "$($_.port)" }) -join ', '
        Add-SargeFinding -Id 'WIN-SC-7-listening-ports' -Family 'SC' -ControlId 'SC-7' `
            -Verdict 'WARN' `
            -Message "Externally-bound listening TCP ports: $ports" `
            -Recommendation 'Get-NetTCPConnection -State Listen | ? LocalAddress -in 0.0.0.0,:: | Format-Table  (review and disable unnecessary services).'
    }
}

# SC-8: SMB signing
Invoke-SargeCheck -Id 'WIN-SC-8-smb-signing' -Family 'SC' -ControlId 'SC-8' -Check {
    $r = Get-SargeScSmbSigning
    if ($r.server_signing_required -and $r.client_signing_required) {
        Add-SargeFinding -Id 'WIN-SC-8-smb-signing' -Family 'SC' -ControlId 'SC-8' `
            -Verdict 'PASS' `
            -Message 'SMB signing required on both client and server'
    } else {
        $verdict = if ($gpoPresent) { 'ENFORCED-EXTERNALLY' } else { 'FAIL' }
        Add-SargeFinding -Id 'WIN-SC-8-smb-signing' -Family 'SC' -ControlId 'SC-8' `
            -Verdict $verdict `
            -Message ("SMB signing not required (server_required=$($r.server_signing_required), client_required=$($r.client_signing_required))") `
            -Recommendation 'Set-SmbServerConfiguration -RequireSecuritySignature $true -Force; Set-SmbClientConfiguration -RequireSecuritySignature $true -Force  (elevated)'
    }
}

# SC-13: BitLocker
Invoke-SargeCheck -Id 'WIN-SC-13-bitlocker' -Family 'SC' -ControlId 'SC-13' -Check {
    $vols = Get-SargeScBitLockerStatus
    $osVol = $vols | Where-Object { $_.volume_type -eq 'OperatingSystem' } | Select-Object -First 1
    if (-not $osVol) {
        Add-SargeFinding -Id 'WIN-SC-13-bitlocker' -Family 'SC' -ControlId 'SC-13' `
            -Verdict 'SKIP-CONTEXT-DEFERRED' `
            -Message 'No OS volume returned by Get-BitLockerVolume'
        return
    }
    if ($osVol.protection_status -eq 'On') {
        Add-SargeFinding -Id 'WIN-SC-13-bitlocker' -Family 'SC' -ControlId 'SC-13' `
            -Verdict 'PASS' `
            -Message "BitLocker On for OS volume $($osVol.mount_point) ($($osVol.encryption_method))"
    } else {
        Add-SargeFinding -Id 'WIN-SC-13-bitlocker' -Family 'SC' -ControlId 'SC-13' `
            -Verdict 'FAIL' `
            -Message "BitLocker protection status on $($osVol.mount_point) is '$($osVol.protection_status)'" `
            -Recommendation 'manage-bde -on <drive> -RecoveryPassword  (elevated); or Settings > Privacy & Security > Device encryption.'
    }
}

$intuneManaged = $false
if ($null -ne $ctx) { $intuneManaged = [bool]$ctx.enterprise_context.intune_managed }

# SC-2: UAC / application partitioning
Invoke-SargeCheck -Id 'WIN-SC-2-uac' -Family 'SC' -ControlId 'SC-2' -Check {
    $r = Get-SargeScUacConfig
    $issues = @()
    if ($null -eq $r.enable_lua) {
        $issues += 'EnableLUA registry value missing'
    } elseif ($r.enable_lua -ne 1) {
        $issues += "EnableLUA=$($r.enable_lua) (UAC disabled)"
    }
    if ($null -ne $r.consent_prompt_behavior_admin -and $r.consent_prompt_behavior_admin -lt 2) {
        $issues += "ConsentPromptBehaviorAdmin=$($r.consent_prompt_behavior_admin) (no prompt)"
    }
    if ($issues.Count -eq 0) {
        Add-SargeFinding -Id 'WIN-SC-2-uac' -Family 'SC' -ControlId 'SC-2' `
            -Verdict 'PASS' `
            -Message ("UAC enabled (EnableLUA=$($r.enable_lua), Admin=$($r.consent_prompt_behavior_admin), User=$($r.consent_prompt_behavior_user))")
    } else {
        $verdict = if ($gpoPresent) { 'ENFORCED-EXTERNALLY' } else { 'FAIL' }
        Add-SargeFinding -Id 'WIN-SC-2-uac' -Family 'SC' -ControlId 'SC-2' `
            -Verdict $verdict `
            -Message ('UAC issues: ' + ($issues -join '; ')) `
            -Recommendation 'reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f; ConsentPromptBehaviorAdmin >= 2 (elevated); reboot.'
    }
}

# SC-12: LSA Protection + Credential Guard
Invoke-SargeCheck -Id 'WIN-SC-12-key-mgmt' -Family 'SC' -ControlId 'SC-12' -Check {
    $r = Get-SargeScKeyManagement
    $issues = @()
    $untested = @()
    if ($null -eq $r.run_as_ppl) { $untested += 'RunAsPPL not set' }
    elseif ($r.run_as_ppl -ne 1) { $issues += "RunAsPPL=$($r.run_as_ppl) (LSA Protection off)" }
    if ($null -eq $r.credential_guard_running) { $untested += 'Credential Guard status unreadable' }
    elseif (-not $r.credential_guard_running)  { $issues   += 'Credential Guard not running' }
    if ($issues.Count -gt 0) {
        $verdict = if ($gpoPresent) { 'ENFORCED-EXTERNALLY' } else { 'FAIL' }
        Add-SargeFinding -Id 'WIN-SC-12-key-mgmt' -Family 'SC' -ControlId 'SC-12' `
            -Verdict $verdict `
            -Message ('Key-management protection gaps: ' + ($issues -join '; ')) `
            -Recommendation 'reg add HKLM\System\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 1 /f; enable Credential Guard via Group Policy > Computer > Admin Templates > System > Device Guard (elevated, reboot).'
    } elseif ($untested.Count -gt 0) {
        Add-SargeFinding -Id 'WIN-SC-12-key-mgmt' -Family 'SC' -ControlId 'SC-12' `
            -Verdict 'UNTESTED' `
            -Message ('Partial data: ' + ($untested -join '; '))
    } else {
        Add-SargeFinding -Id 'WIN-SC-12-key-mgmt' -Family 'SC' -ControlId 'SC-12' `
            -Verdict 'PASS' `
            -Message ("LSA Protection on (RunAsPPL=$($r.run_as_ppl)) and Credential Guard running")
    }
}

# SC-23: session authenticity - LDAP signing + NTLM restrictions
Invoke-SargeCheck -Id 'WIN-SC-23-ldap-ntlm' -Family 'SC' -ControlId 'SC-23' -Check {
    $r = Get-SargeScSessionAuthenticity
    $issues = @()
    if ($null -ne $r.ldap_server_integrity -and $r.ldap_server_integrity -lt 2) {
        $issues += "LDAPServerIntegrity=$($r.ldap_server_integrity) (signing not required)"
    }
    if ($null -eq $r.ntlm_restrict_sending) {
        $issues += 'RestrictSendingNTLMTraffic unset (no NTLM outbound restriction)'
    } elseif ($r.ntlm_restrict_sending -lt 1) {
        $issues += "RestrictSendingNTLMTraffic=$($r.ntlm_restrict_sending) (no restriction)"
    }
    if ($issues.Count -eq 0) {
        Add-SargeFinding -Id 'WIN-SC-23-ldap-ntlm' -Family 'SC' -ControlId 'SC-23' `
            -Verdict 'PASS' `
            -Message ("LDAP signing + NTLM outbound restriction in place (ldap=$($r.ldap_server_integrity), ntlm_send=$($r.ntlm_restrict_sending))")
    } else {
        $verdict = if ($gpoPresent) { 'ENFORCED-EXTERNALLY' } else { 'WARN' }
        Add-SargeFinding -Id 'WIN-SC-23-ldap-ntlm' -Family 'SC' -ControlId 'SC-23' `
            -Verdict $verdict `
            -Message ('Session authenticity gaps: ' + ($issues -join '; ')) `
            -Recommendation 'secpol.msc > Local Policies > Security Options > Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers = Audit/Deny.'
    }
}

# SC-28 policy: BitLocker encryption method + escrow target
Invoke-SargeCheck -Id 'WIN-SC-28-bitlocker-policy' -Family 'SC' -ControlId 'SC-28' -Check {
    $r = Get-SargeScBitLockerPolicy
    if ($null -eq $r.encryption_method) {
        Add-SargeFinding -Id 'WIN-SC-28-bitlocker-policy' -Family 'SC' -ControlId 'SC-28' `
            -Verdict 'SKIP-CONTEXT-DEFERRED' `
            -Message 'BitLocker not present on OS volume; SC-28 policy compliance N/A'
        return
    }
    $issues = @()
    if ($r.encryption_method -notmatch '(?i)^XtsAes(128|256)$') {
        $issues += "EncryptionMethod=$($r.encryption_method) (below XtsAes128)"
    }
    if (-not $r.escrow_configured) {
        $issues += 'No recovery-key escrow policy (OSRequireActiveDirectoryBackup unset)'
    }
    if ($issues.Count -eq 0) {
        Add-SargeFinding -Id 'WIN-SC-28-bitlocker-policy' -Family 'SC' -ControlId 'SC-28' `
            -Verdict 'PASS' `
            -Message ("BitLocker policy compliant (method=$($r.encryption_method), escrow_configured=True)")
    } else {
        $verdict = if ($gpoPresent -or $intuneManaged) { 'ENFORCED-EXTERNALLY' } else { 'WARN' }
        Add-SargeFinding -Id 'WIN-SC-28-bitlocker-policy' -Family 'SC' -ControlId 'SC-28' `
            -Verdict $verdict `
            -Message ('BitLocker policy gaps: ' + ($issues -join '; ')) `
            -Recommendation 'manage-bde -off C: && manage-bde -on C: -EncryptionMethod XtsAes256 -SkipHardwareTest (elevated). Configure escrow via GPO > BitLocker OS Drives > Choose how BitLocker-protected OS drives can be recovered.'
    }
}
