# assessment/checks/check-ia.ps1  -  Identification & Authentication verdicts.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ctx = Get-SargeContext
$gpoPresent = $false
if ($null -ne $ctx) { $gpoPresent = [bool]$ctx.enterprise_context.gpo_present }

Write-Output "[SARGE] === IA: Identification & Authentication ==="

# IA-5: password length / age policy
Invoke-SargeCheck -Id 'WIN-IA-5-password-policy' -Family 'IA' -ControlId 'IA-5' -Check {
    $p = Get-SargeIaPasswordPolicy
    $issues = @()
    if ($null -ne $p.min_length -and $p.min_length -lt 14) {
        $issues += ("min length " + $p.min_length + " less than 14")
    }
    if ($null -ne $p.max_age_days -and $p.max_age_days -gt 365) {
        $issues += "max age $($p.max_age_days) days > 365"
    }
    if ($null -ne $p.history_length -and $p.history_length -lt 5) {
        $issues += ("history " + $p.history_length + " less than 5")
    }
    if ($issues.Count -eq 0) {
        Add-SargeFinding -Id 'WIN-IA-5-password-policy' -Family 'IA' -ControlId 'IA-5' `
            -Verdict 'PASS' `
            -Message "min_length=$($p.min_length); max_age=$($p.max_age_days) days; history=$($p.history_length)"
    } else {
        $verdict = if ($gpoPresent) { 'ENFORCED-EXTERNALLY' } else { 'FAIL' }
        Add-SargeFinding -Id 'WIN-IA-5-password-policy' -Family 'IA' -ControlId 'IA-5' `
            -Verdict $verdict `
            -Message ('Password policy issues: ' + ($issues -join '; ')) `
            -Recommendation 'net accounts /minpwlen:14 /maxpwage:90 /uniquepw:5  (elevated)'
    }
}

# IA-2: account types
Invoke-SargeCheck -Id 'WIN-IA-2-account-types' -Family 'IA' -ControlId 'IA-2' -Check {
    $r = Get-SargeIaAccountTypes
    $msg = ("local={0}; msa={1}; aad={2}; other={3}" -f
            $r.local_accounts.Count, $r.msa_accounts.Count,
            $r.aad_accounts.Count, $r.other.Count)
    # Microsoft Account (consumer MSA) on a managed host is a baseline failure:
    # auditors in a Moderate/High accreditation boundary expect demonstrable
    # org control over account lifecycle (provisioning, de-provisioning,
    # attribute management). MSAs are managed by Microsoft, not the org, so
    # this fails AC-2 / IA-2. If the host is intentionally outside the
    # accreditation boundary (e.g. a personal dev laptop), treat as
    # informational. Promoted from WARN per PR #32 review (2026-05-22).
    if ($r.msa_accounts.Count -gt 0) {
        $msaList = ($r.msa_accounts -join ', ')
        $rationale = "Microsoft Account `"$msaList`" detected on the device. " +
                     "NIST 800-53 AC-2 requires demonstrable org control over account lifecycle " +
                     "(provisioning, de-provisioning, attribute management). " +
                     "MSAs are managed by Microsoft, not the org, so an auditor in a Moderate/High " +
                     "baseline will write a finding. If this host is intentionally outside the org " +
                     "accreditation boundary (e.g. personal dev laptop), treat this finding as informational. " +
                     "Inventory: $msg"
        Add-SargeFinding -Id 'WIN-IA-2-account-types' -Family 'IA' -ControlId 'IA-2' `
            -Verdict 'FAIL' `
            -Message $rationale `
            -Recommendation 'Settings > Accounts > Sign in with a local account instead, or convert to an AAD-joined identity managed by the organization. If this host is outside the accreditation boundary, document the scope exclusion.'
    } else {
        Add-SargeFinding -Id 'WIN-IA-2-account-types' -Family 'IA' -ControlId 'IA-2' `
            -Verdict 'PASS' `
            -Message ("Account inventory: $msg")
    }
}

# IA-5 complexity / IA-11 (reauth posture proxy) via secedit
Invoke-SargeCheck -Id 'WIN-IA-5-complexity' -Family 'IA' -ControlId 'IA-5' -Check {
    $r = Get-SargeIaSeceditExport
    if ($null -eq $r.password_complexity) {
        Add-SargeFinding -Id 'WIN-IA-5-complexity' -Family 'IA' -ControlId 'IA-5' `
            -Verdict 'UNTESTED' `
            -Message 'secedit returned no PasswordComplexity line'
        return
    }
    if ($r.password_complexity -eq 1 -and $r.reversible_encryption_off) {
        Add-SargeFinding -Id 'WIN-IA-5-complexity' -Family 'IA' -ControlId 'IA-5' `
            -Verdict 'PASS' `
            -Message 'PasswordComplexity=1 and reversible encryption disabled'
    } else {
        $verdict = if ($gpoPresent) { 'ENFORCED-EXTERNALLY' } else { 'FAIL' }
        Add-SargeFinding -Id 'WIN-IA-5-complexity' -Family 'IA' -ControlId 'IA-5' `
            -Verdict $verdict `
            -Message ("PasswordComplexity=$($r.password_complexity); reversible_encryption_off=$($r.reversible_encryption_off)") `
            -Recommendation 'secpol.msc > Account Policies > Password Policy: enable "Password must meet complexity requirements"; disable "Store passwords using reversible encryption".'
    }
}

# IA-11 reauth requirements  -  interactive logon: machine inactivity limit
Invoke-SargeCheck -Id 'WIN-IA-11-reauth' -Family 'IA' -ControlId 'IA-11' -Check {
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $val = $null
    try {
        $p = Get-ItemProperty -LiteralPath $key -ErrorAction Stop
        if ($p.PSObject.Properties['InactivityTimeoutSecs']) {
            $val = [int]$p.InactivityTimeoutSecs
        }
    } catch { }
    if ($null -eq $val -or $val -eq 0) {
        $verdict = if ($gpoPresent) { 'ENFORCED-EXTERNALLY' } else { 'WARN' }
        Add-SargeFinding -Id 'WIN-IA-11-reauth' -Family 'IA' -ControlId 'IA-11' `
            -Verdict $verdict `
            -Message 'InactivityTimeoutSecs not configured (machine-level reauth interval not enforced)' `
            -Recommendation 'secpol.msc > Local Policies > Security Options > Interactive logon: Machine inactivity limit = 900 (15 min).'
    } elseif ($val -le 900) {
        Add-SargeFinding -Id 'WIN-IA-11-reauth' -Family 'IA' -ControlId 'IA-11' `
            -Verdict 'PASS' `
            -Message ("InactivityTimeoutSecs=$val (re-auth at 15 min or less idle)")
    } else {
        Add-SargeFinding -Id 'WIN-IA-11-reauth' -Family 'IA' -ControlId 'IA-11' `
            -Verdict 'FAIL' `
            -Message "InactivityTimeoutSecs=$val > 900" `
            -Recommendation 'Set InactivityTimeoutSecs to <= 900 via Group Policy / secpol.msc.'
    }
}

$intuneManaged = $false
if ($null -ne $ctx) { $intuneManaged = [bool]$ctx.enterprise_context.intune_managed }

# IA-3: device identification + authentication (TPM + Secure Boot)
Invoke-SargeCheck -Id 'WIN-IA-3-device-id' -Family 'IA' -ControlId 'IA-3' -Check {
    $r = Get-SargeIaDeviceIdentity
    if ($null -eq $r.tpm_present -and $null -eq $r.secure_boot) {
        Add-SargeFinding -Id 'WIN-IA-3-device-id' -Family 'IA' -ControlId 'IA-3' `
            -Verdict 'UNTESTED' `
            -Message 'Neither Get-Tpm nor Confirm-SecureBootUEFI returned data (legacy BIOS or stripped SKU?)' `
            -Recommendation 'Verify in firmware that TPM and Secure Boot are enabled; on legacy BIOS hosts IA-3 may require alternate device-attestation evidence.'
        return
    }
    $issues = @()
    if ($null -ne $r.tpm_present -and -not $r.tpm_present) { $issues += 'TPM not present' }
    elseif ($null -ne $r.tpm_ready -and -not $r.tpm_ready) { $issues += 'TPM not Ready' }
    if ($null -ne $r.secure_boot -and -not $r.secure_boot) { $issues += 'Secure Boot disabled' }
    if ($issues.Count -eq 0) {
        Add-SargeFinding -Id 'WIN-IA-3-device-id' -Family 'IA' -ControlId 'IA-3' `
            -Verdict 'PASS' `
            -Message ("TPM present=$($r.tpm_present), ready=$($r.tpm_ready); SecureBoot=$($r.secure_boot)")
    } else {
        Add-SargeFinding -Id 'WIN-IA-3-device-id' -Family 'IA' -ControlId 'IA-3' `
            -Verdict 'FAIL' `
            -Message ('Device identity gaps: ' + ($issues -join '; ')) `
            -Recommendation 'Enable TPM + Secure Boot in firmware; ensure Get-Tpm TpmReady=True and Confirm-SecureBootUEFI=True.'
    }
}

# IA-12: identity proofing via Windows Hello / NGC
Invoke-SargeCheck -Id 'WIN-IA-12-windows-hello' -Family 'IA' -ControlId 'IA-12' -Check {
    $r = Get-SargeIaWindowsHello
    if ($r.policy_present) {
        Add-SargeFinding -Id 'WIN-IA-12-windows-hello' -Family 'IA' -ControlId 'IA-12' `
            -Verdict 'PASS' `
            -Message 'PassportForWork (Windows Hello for Business) policy present'
    } elseif ($intuneManaged) {
        Add-SargeFinding -Id 'WIN-IA-12-windows-hello' -Family 'IA' -ControlId 'IA-12' `
            -Verdict 'ENFORCED-EXTERNALLY' `
            -Message 'No PassportForWork policy locally; identity proofing likely enforced at AAD/Intune layer' `
            -Recommendation 'Verify via Intune > Endpoint Security > Account protection that Windows Hello is policy-deployed.'
    } else {
        Add-SargeFinding -Id 'WIN-IA-12-windows-hello' -Family 'IA' -ControlId 'IA-12' `
            -Verdict 'WARN' `
            -Message ("No Windows Hello policy and no MDM enforcement detected (ngc_dir_present=$($r.ngc_dir_present))") `
            -Recommendation 'Settings > Accounts > Sign-in options > Windows Hello. For managed hosts, deploy via Intune.'
    }
}
