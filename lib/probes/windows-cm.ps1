# lib/probes/windows-cm.ps1  -  Configuration Management (CM) probes.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# CM-6: SMBv1 server-side state. Get-SmbServerConfiguration reads as standard
# user on client SKUs. EnableSMB1Protocol = $true indicates the protocol is
# enabled (CM-6 failure).
function Get-SargeCmSmbV1State {
    [CmdletBinding()] param()
    if (-not (Get-Command Get-SmbServerConfiguration -ErrorAction SilentlyContinue)) {
        throw 'Get-SmbServerConfiguration not available'
    }
    $cfg = Get-SmbServerConfiguration -ErrorAction Stop
    return [pscustomobject]@{
        smb1_enabled = [bool]$cfg.EnableSMB1Protocol
        smb1_client  = $null   # client-side requires elevated DISM; tracked separately
    }
}

# CM-6: legacy / risky services that should not be present in a Running state.
# Win32_Service is standard-user-readable.
function Get-SargeCmLegacyServices {
    [CmdletBinding()] param()
    $watch = @('Telnet','TlntSvr','RemoteRegistry','SNMP','Browser','SharedAccess','seclogon')
    $running = @()
    $present = @()
    foreach ($s in $watch) {
        $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name = '$s'" -ErrorAction SilentlyContinue
        if ($null -ne $svc) {
            $present += $s
            if ($svc.State -eq 'Running') { $running += $s }
        }
    }
    return [pscustomobject]@{
        watched = $watch
        present = $present
        running = $running
    }
}

# CM-7: services running that are commonly disabled by hardening baselines.
# This is informational  -  we surface the list, the check script decides verdict.
function Get-SargeCmUnnecessaryServicesRunning {
    [CmdletBinding()] param()
    # Common targets per CIS L1 workstation profile. Standard user can read.
    $watch = @('Fax','XblAuthManager','XblGameSave','XboxGipSvc','XboxNetApiSvc',
               'MapsBroker','PhoneSvc','PrintNotify','RemoteAccess','RetailDemo')
    $running = @()
    foreach ($s in $watch) {
        $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name = '$s'" -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.State -eq 'Running') {
            $running += $s
        }
    }
    return [pscustomobject]@{
        watched = $watch
        running = $running
    }
}

# CM-8: installed software inventory. Read from the Uninstall registry hive
# (HKLM + HKLM Wow6432 + HKCU). Avoiding Get-WmiObject Win32_Product because
# it triggers a Windows Installer self-repair on every install (slow + dangerous
# on some software). Standard user can read these hives.
function Get-SargeCmInstalledSoftware {
    [CmdletBinding()] param()
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $items = @()
    foreach ($k in $keys) {
        try {
            $rows = Get-ItemProperty -Path $k -ErrorAction Stop |
                    Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName }
            foreach ($r in $rows) {
                $items += [pscustomobject]@{
                    name      = [string]$r.DisplayName
                    version   = if ($r.PSObject.Properties['DisplayVersion']) { [string]$r.DisplayVersion } else { '' }
                    publisher = if ($r.PSObject.Properties['Publisher'])      { [string]$r.Publisher }      else { '' }
                }
            }
        } catch { }
    }
    # De-duplicate by name+version
    $unique = $items | Sort-Object name, version -Unique
    return [pscustomobject]@{
        count = $unique.Count
        items = $unique
    }
}

# CM-2: baseline configuration snapshot for drift detection.
function Get-SargeCmBaselineSnapshot {
    [CmdletBinding()] param()
    $services = @()
    try {
        $services = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop |
                    Where-Object { $_.State -eq 'Running' } |
                    ForEach-Object { $_.Name } | Sort-Object -Unique
    } catch { }
    $tasks = @()
    if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
        try {
            $tasks = @(Get-ScheduledTask -ErrorAction Stop |
                       Where-Object { $_.State -ne 'Disabled' } |
                       ForEach-Object { ($_.TaskPath + $_.TaskName) }) | Sort-Object -Unique
        } catch { }
    }
    $regKeys = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System',
        'HKLM:\System\CurrentControlSet\Control\Lsa',
        'HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters',
        'HKLM:\System\CurrentControlSet\Control\Terminal Server'
    )
    $regDigest = @{}
    foreach ($k in $regKeys) {
        try {
            if (Test-Path -LiteralPath $k) {
                $p = Get-ItemProperty -LiteralPath $k -ErrorAction Stop
                $pairs = @()
                foreach ($prop in $p.PSObject.Properties) {
                    if ($prop.Name -like 'PS*') { continue }
                    $pairs += ("{0}={1}" -f $prop.Name, $prop.Value)
                }
                $regDigest[$k] = ($pairs | Sort-Object) -join '|'
            }
        } catch { }
    }
    return [pscustomobject]@{
        services_running = @($services)
        scheduled_tasks  = @($tasks)
        registry_digest  = $regDigest
        captured_at      = (Get-Date).ToString('o')
    }
}

# CM-11: user-installed software policy - AppX packages + HKCU uninstall hive.
function Get-SargeCmUserInstalledSoftware {
    [CmdletBinding()] param()
    $appx = @()
    if (Get-Command Get-AppxPackage -ErrorAction SilentlyContinue) {
        try {
            $appx = @(Get-AppxPackage -ErrorAction Stop |
                      Where-Object { -not $_.IsFramework -and $_.SignatureKind -ne 'System' } |
                      ForEach-Object { $_.Name })
        } catch { }
    }
    $hkcuUninstall = @()
    try {
        $rows = Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction Stop |
                Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName }
        foreach ($r in $rows) {
            $hkcuUninstall += [string]$r.DisplayName
        }
    } catch { }
    return [pscustomobject]@{
        appx_user_packages   = $appx
        appx_count           = $appx.Count
        hkcu_installed       = $hkcuUninstall
        hkcu_installed_count = $hkcuUninstall.Count
    }
}
