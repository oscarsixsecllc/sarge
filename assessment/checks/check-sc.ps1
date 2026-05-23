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
