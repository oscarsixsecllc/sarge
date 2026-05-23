# lib/probes/windows-si.ps1  -  System & Information Integrity (SI) probes.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# SI-2: pending Windows Updates via the Update Session COM object. Standard
# user can instantiate and search read-only. This is slow (5-30s)  -  checks
# should not over-call.
function Get-SargeSiPendingUpdates {
    [CmdletBinding()] param()
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    # Search restricted to not-installed updates of any criticality.
    $result = $searcher.Search("IsInstalled=0 and Type='Software'")
    $count = 0
    if ($null -ne $result -and $null -ne $result.Updates) {
        $count = [int]$result.Updates.Count
    }
    $titles = @()
    for ($i = 0; $i -lt [Math]::Min($count, 10); $i++) {
        $titles += [string]$result.Updates.Item($i).Title
    }
    return [pscustomobject]@{
        pending_count = $count
        sample_titles = $titles
    }
}

# SI-3: Defender state  -  already partially captured in Get-SargeWindowsContext.
# Re-surface as a SI probe so the check script gets a clean record.
function Get-SargeSiDefenderStatus {
    [CmdletBinding()] param()
    if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
        throw 'Get-MpComputerStatus not available'
    }
    $s = Get-MpComputerStatus -ErrorAction Stop
    $tamper = $null
    if ($s.PSObject.Properties['IsTamperProtected']) {
        $tamper = [bool]$s.IsTamperProtected
    }
    return [pscustomobject]@{
        realtime_enabled          = [bool]$s.RealTimeProtectionEnabled
        antivirus_enabled         = [bool]$s.AntivirusEnabled
        antispyware_enabled       = [bool]$s.AntispywareEnabled
        tamper_protected          = $tamper
        signature_age_days        = if ($s.PSObject.Properties['AntivirusSignatureAge']) { [int]$s.AntivirusSignatureAge } else { $null }
        engine_version            = [string]$s.AMEngineVersion
    }
}

# SI-3: ASR (Attack Surface Reduction) rule configuration.
function Get-SargeSiAsrRules {
    [CmdletBinding()] param()
    if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) {
        throw 'Get-MpPreference not available'
    }
    $pref = Get-MpPreference -ErrorAction Stop
    $ids = @()
    $actions = @()
    if ($pref.PSObject.Properties['AttackSurfaceReductionRules_Ids'] -and $pref.AttackSurfaceReductionRules_Ids) {
        $ids = @($pref.AttackSurfaceReductionRules_Ids)
    }
    if ($pref.PSObject.Properties['AttackSurfaceReductionRules_Actions'] -and $pref.AttackSurfaceReductionRules_Actions) {
        $actions = @($pref.AttackSurfaceReductionRules_Actions)
    }
    return [pscustomobject]@{
        rule_ids        = $ids
        rule_actions    = $actions
        rule_count      = $ids.Count
    }
}

# SI-4: audit channel state  -  is the Microsoft-Windows-Sysmon channel present?
# Sysmon isn't required but its absence is a relevant signal for SI-4 monitoring.
function Get-SargeSiSysmonPresent {
    [CmdletBinding()] param()
    $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='Sysmon' OR Name='Sysmon64'" -ErrorAction SilentlyContinue
    if ($null -eq $svc) {
        return [pscustomobject]@{ installed = $false; running = $false }
    }
    $running = $false
    foreach ($s in @($svc)) {
        if ($s.State -eq 'Running') { $running = $true }
    }
    return [pscustomobject]@{ installed = $true; running = $running }
}

# SI-7: WDAC policy file presence. Standard user can read
# C:\Windows\System32\CodeIntegrity\*.cip and look at the CIPolicies subdir.
function Get-SargeSiWdacPolicyPresence {
    [CmdletBinding()] param()
    $policyDirs = @(
        "$env:SystemRoot\System32\CodeIntegrity",
        "$env:SystemRoot\System32\CodeIntegrity\CIPolicies\Active"
    )
    $found = @()
    foreach ($d in $policyDirs) {
        if (Test-Path -LiteralPath $d) {
            try {
                $files = Get-ChildItem -LiteralPath $d -File -Filter '*.cip' -ErrorAction Stop
                foreach ($f in $files) { $found += $f.FullName }
            } catch { }
        }
    }
    return [pscustomobject]@{
        policies = $found
        count    = $found.Count
    }
}
