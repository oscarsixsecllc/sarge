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
    # MSA on a security-sensitive host is a yellow flag (cloud-attached identity);
    # don't FAIL but call it out.
    if ($r.msa_accounts.Count -gt 0) {
        Add-SargeFinding -Id 'WIN-IA-2-account-types' -Family 'IA' -ControlId 'IA-2' `
            -Verdict 'WARN' `
            -Message ("Microsoft accounts present: " + ($r.msa_accounts -join ', ') + " | $msg") `
            -Recommendation 'Confirm MSA usage is intentional; for high-assurance hosts prefer local + AAD-managed identities only.'
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
