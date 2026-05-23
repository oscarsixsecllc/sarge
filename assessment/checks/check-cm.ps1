# assessment/checks/check-cm.ps1  -  Configuration Management verdicts.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ctx = Get-SargeContext
$gpoPresent = $false
if ($null -ne $ctx) { $gpoPresent = [bool]$ctx.enterprise_context.gpo_present }

Write-Output "[SARGE] === CM: Configuration Management ==="

# CM-6: SMBv1 disabled
Invoke-SargeCheck -Id 'WIN-CM-6-smbv1' -Family 'CM' -ControlId 'CM-6' -Check {
    $r = Get-SargeCmSmbV1State
    if (-not $r.smb1_enabled) {
        Add-SargeFinding -Id 'WIN-CM-6-smbv1' -Family 'CM' -ControlId 'CM-6' `
            -Verdict 'PASS' `
            -Message 'SMBv1 server protocol is disabled'
    } else {
        Add-SargeFinding -Id 'WIN-CM-6-smbv1' -Family 'CM' -ControlId 'CM-6' `
            -Verdict 'FAIL' `
            -Message 'SMBv1 server protocol is ENABLED (EternalBlue surface)' `
            -Recommendation 'Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force  (elevated); also: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol'
    }
}

# CM-6: legacy services not running
Invoke-SargeCheck -Id 'WIN-CM-6-legacy-services' -Family 'CM' -ControlId 'CM-6' -Check {
    $r = Get-SargeCmLegacyServices
    if ($r.running.Count -eq 0) {
        Add-SargeFinding -Id 'WIN-CM-6-legacy-services' -Family 'CM' -ControlId 'CM-6' `
            -Verdict 'PASS' `
            -Message ("Legacy services not running (watched: " + ($r.watched -join ', ') + ")")
    } else {
        Add-SargeFinding -Id 'WIN-CM-6-legacy-services' -Family 'CM' -ControlId 'CM-6' `
            -Verdict 'FAIL' `
            -Message ("Legacy services running: " + ($r.running -join ', ')) `
            -Recommendation ("For each: Stop-Service <name> -Force; Set-Service <name> -StartupType Disabled  (elevated)")
    }
}

# CM-7: unnecessary services running
Invoke-SargeCheck -Id 'WIN-CM-7-unnecessary-services' -Family 'CM' -ControlId 'CM-7' -Check {
    $r = Get-SargeCmUnnecessaryServicesRunning
    if ($r.running.Count -eq 0) {
        Add-SargeFinding -Id 'WIN-CM-7-unnecessary-services' -Family 'CM' -ControlId 'CM-7' `
            -Verdict 'PASS' `
            -Message 'No CIS L1 "commonly-disabled" services found running'
    } else {
        $verdict = if ($gpoPresent) { 'ENFORCED-EXTERNALLY' } else { 'WARN' }
        Add-SargeFinding -Id 'WIN-CM-7-unnecessary-services' -Family 'CM' -ControlId 'CM-7' `
            -Verdict $verdict `
            -Message ("Commonly-disabled services running: " + ($r.running -join ', ')) `
            -Recommendation 'Confirm each is intentional; disable if not via Set-Service <name> -StartupType Disabled (elevated).'
    }
}

# CM-8: installed software inventory (informational PASS  -  emits count, never fails)
Invoke-SargeCheck -Id 'WIN-CM-8-software-inventory' -Family 'CM' -ControlId 'CM-8' -Check {
    $r = Get-SargeCmInstalledSoftware
    if ($r.count -eq 0) {
        Add-SargeFinding -Id 'WIN-CM-8-software-inventory' -Family 'CM' -ControlId 'CM-8' `
            -Verdict 'UNTESTED' `
            -Message 'Uninstall registry hive returned no entries (unusual; investigate)'
        return
    }
    Add-SargeFinding -Id 'WIN-CM-8-software-inventory' -Family 'CM' -ControlId 'CM-8' `
        -Verdict 'PASS' `
        -Message ("Installed software inventory captured ($($r.count) entries) to findings JSON") `
        -Recommendation 'Review the inventory in the Markdown report; remove anything not authorized.'
    # Stash the inventory in a sibling state file so the report can render it
    # without bloating findings JSON. Write to both the legacy state path
    # (backwards compat) and the per-run folder (self-contained).
    $stateDir = Join-Path $env:USERPROFILE '.sarge\state'
    $invPath = Join-Path $stateDir 'windows-software-inventory.json'
    $r.items | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $invPath -Encoding UTF8
    if (Get-Variable -Name SargeRunRoot -Scope Script -ErrorAction SilentlyContinue) {
        $runInvPath = Join-Path $script:SargeRunRoot 'software-inventory.json'
        $r.items | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $runInvPath -Encoding UTF8
    }
}
