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

# CM-2: Windows baseline configuration drift
Invoke-SargeCheck -Id 'WIN-CM-2-baseline-drift' -Family 'CM' -ControlId 'CM-2' -Check {
    $r = Get-SargeCmBaselineSnapshot
    $baselineDir = Join-Path $env:USERPROFILE '.sarge\state'
    if (-not (Test-Path -LiteralPath $baselineDir)) {
        New-Item -ItemType Directory -Path $baselineDir -Force | Out-Null
    }
    $baselinePath = Join-Path $baselineDir 'windows-baseline.json'

    if (-not (Test-Path -LiteralPath $baselinePath)) {
        $r | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $baselinePath -Encoding UTF8
        Add-SargeFinding -Id 'WIN-CM-2-baseline-drift' -Family 'CM' -ControlId 'CM-2' `
            -Verdict 'PASS' `
            -Message ("Baseline captured at $baselinePath (services=$($r.services_running.Count), tasks=$($r.scheduled_tasks.Count), reg keys=$($r.registry_digest.Keys.Count))")
        return
    }

    try {
        $prev = Get-Content -LiteralPath $baselinePath -Raw | ConvertFrom-Json
    } catch {
        Add-SargeFinding -Id 'WIN-CM-2-baseline-drift' -Family 'CM' -ControlId 'CM-2' `
            -Verdict 'UNTESTED' `
            -Message "Could not parse existing baseline at $baselinePath ($($_.Exception.Message)); re-run to recapture" `
            -Recommendation "Remove $baselinePath and re-run assess.ps1 to recapture the baseline."
        return
    }

    $prevServices = @($prev.services_running)
    $prevTasks    = @($prev.scheduled_tasks)
    $addedServices   = @($r.services_running | Where-Object { $_ -notin $prevServices })
    $removedServices = @($prevServices       | Where-Object { $_ -notin $r.services_running })
    $addedTasks      = @($r.scheduled_tasks  | Where-Object { $_ -notin $prevTasks })
    $removedTasks    = @($prevTasks          | Where-Object { $_ -notin $r.scheduled_tasks })
    $regDrift = @()
    foreach ($k in $r.registry_digest.Keys) {
        $prevVal = $null
        if ($prev.registry_digest.PSObject.Properties[$k]) { $prevVal = [string]$prev.registry_digest.$k }
        if ($prevVal -ne $r.registry_digest[$k]) { $regDrift += $k }
    }
    $total = $addedServices.Count + $removedServices.Count + $addedTasks.Count + $removedTasks.Count + $regDrift.Count
    if ($total -eq 0) {
        Add-SargeFinding -Id 'WIN-CM-2-baseline-drift' -Family 'CM' -ControlId 'CM-2' `
            -Verdict 'PASS' `
            -Message ("No drift vs $baselinePath (captured " + [string]$prev.captured_at + ")")
    } else {
        $parts = @()
        if ($addedServices.Count   -gt 0) { $parts += "services +[" + ($addedServices   -join ',') + "]" }
        if ($removedServices.Count -gt 0) { $parts += "services -[" + ($removedServices -join ',') + "]" }
        if ($addedTasks.Count      -gt 0) { $parts += "tasks +$($addedTasks.Count)" }
        if ($removedTasks.Count    -gt 0) { $parts += "tasks -$($removedTasks.Count)" }
        if ($regDrift.Count        -gt 0) { $parts += "reg drift: " + ($regDrift -join '; ') }
        Add-SargeFinding -Id 'WIN-CM-2-baseline-drift' -Family 'CM' -ControlId 'CM-2' `
            -Verdict 'WARN' `
            -Message ("Configuration drift detected: " + ($parts -join ' | ')) `
            -Recommendation "Review the changes. If intentional, refresh the baseline: Remove-Item $baselinePath; re-run assess.ps1"
    }
}

# CM-11: user-installed software policy
Invoke-SargeCheck -Id 'WIN-CM-11-user-installed-software' -Family 'CM' -ControlId 'CM-11' -Check {
    $r = Get-SargeCmUserInstalledSoftware
    if ($r.appx_count -eq 0 -and $r.hkcu_installed_count -eq 0) {
        Add-SargeFinding -Id 'WIN-CM-11-user-installed-software' -Family 'CM' -ControlId 'CM-11' `
            -Verdict 'PASS' `
            -Message 'No user-installed AppX or HKCU uninstall entries detected'
    } else {
        $verdict = if ($gpoPresent) { 'ENFORCED-EXTERNALLY' } else { 'WARN' }
        Add-SargeFinding -Id 'WIN-CM-11-user-installed-software' -Family 'CM' -ControlId 'CM-11' `
            -Verdict $verdict `
            -Message ("User-installed software present: AppX=$($r.appx_count), HKCU-uninstall=$($r.hkcu_installed_count)") `
            -Recommendation 'Confirm an allow-list / Store policy exists. GPO: Computer > Admin Templates > Windows Components > Store > Turn off the Store application.'
    }
}
