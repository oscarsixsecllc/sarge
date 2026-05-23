# lib/probes/windows-sc.ps1  -  System & Communications Protection (SC) probes.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# SC-7: per-profile firewall state. Get-NetFirewallProfile readable as standard
# user on Win10/11.
function Get-SargeScFirewallProfiles {
    [CmdletBinding()] param()
    if (-not (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
        throw 'Get-NetFirewallProfile not available'
    }
    $profiles = Get-NetFirewallProfile -ErrorAction Stop
    $out = @()
    foreach ($p in $profiles) {
        $out += [pscustomobject]@{
            name            = [string]$p.Name
            enabled         = [bool]$p.Enabled
            default_inbound = [string]$p.DefaultInboundAction
            default_outbound = [string]$p.DefaultOutboundAction
        }
    }
    return $out
}

# SC-7: externally-bound listening ports. Get-NetTCPConnection -State Listen
# returns 0.0.0.0 / :: bindings  -  those are the externally-reachable ones.
function Get-SargeScListeningPorts {
    [CmdletBinding()] param()
    if (-not (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
        throw 'Get-NetTCPConnection not available'
    }
    $conns = Get-NetTCPConnection -State Listen -ErrorAction Stop
    $external = @()
    foreach ($c in $conns) {
        if ($c.LocalAddress -in '0.0.0.0','::','*') {
            $external += [pscustomobject]@{
                port    = [int]$c.LocalPort
                address = [string]$c.LocalAddress
                pid     = [int]$c.OwningProcess
            }
        }
    }
    return [pscustomobject]@{
        externally_listening = $external
        total_listening      = $conns.Count
    }
}

# SC-8: SMB signing client + server. Get-SmbServerConfiguration +
# Get-SmbClientConfiguration are standard-user-readable.
function Get-SargeScSmbSigning {
    [CmdletBinding()] param()
    $server = Get-SmbServerConfiguration -ErrorAction Stop
    $client = Get-SmbClientConfiguration -ErrorAction Stop
    return [pscustomobject]@{
        server_signing_required = [bool]$server.RequireSecuritySignature
        server_signing_enabled  = [bool]$server.EnableSecuritySignature
        client_signing_required = [bool]$client.RequireSecuritySignature
        client_signing_enabled  = [bool]$client.EnableSecuritySignature
    }
}

# SC-13: BitLocker volume status. Get-BitLockerVolume normally requires admin
# for full data but the ProtectionStatus property on the OS volume is exposed
# to standard user on most Win10/11 client SKUs. If missing entirely we
# surface SKIP.
function Get-SargeScBitLockerStatus {
    [CmdletBinding()] param()
    if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
        throw 'Get-BitLockerVolume not available (Home SKU or BitLocker feature missing)'
    }
    $volumes = Get-BitLockerVolume -ErrorAction Stop
    $out = @()
    foreach ($v in $volumes) {
        $out += [pscustomobject]@{
            mount_point       = [string]$v.MountPoint
            volume_type       = [string]$v.VolumeType
            protection_status = [string]$v.ProtectionStatus
            encryption_method = [string]$v.EncryptionMethod
        }
    }
    return $out
}

# SC-2: UAC configuration. Standard user can read the System policy hive.
function Get-SargeScUacConfig {
    [CmdletBinding()] param()
    $key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    $enableLua = $null
    $admin     = $null
    $user      = $null
    try {
        $p = Get-ItemProperty -LiteralPath $key -ErrorAction Stop
        if ($p.PSObject.Properties['EnableLUA'])                  { $enableLua = [int]$p.EnableLUA }
        if ($p.PSObject.Properties['ConsentPromptBehaviorAdmin']) { $admin     = [int]$p.ConsentPromptBehaviorAdmin }
        if ($p.PSObject.Properties['ConsentPromptBehaviorUser'])  { $user      = [int]$p.ConsentPromptBehaviorUser }
    } catch { }
    return [pscustomobject]@{
        enable_lua                    = $enableLua
        consent_prompt_behavior_admin = $admin
        consent_prompt_behavior_user  = $user
    }
}

# SC-12: cryptographic key management. LSA Protection (RunAsPPL) + Credential
# Guard. Both readable as standard user on Win10/11 client SKUs.
function Get-SargeScKeyManagement {
    [CmdletBinding()] param()
    $runAsPPL = $null
    $key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
    try {
        $p = Get-ItemProperty -LiteralPath $key -ErrorAction Stop
        if ($p.PSObject.Properties['RunAsPPL']) { $runAsPPL = [int]$p.RunAsPPL }
    } catch { }
    $credGuardRunning = $null
    $vbsRunning       = $null
    try {
        $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' -ErrorAction Stop
        if ($dg -and $dg.PSObject.Properties['SecurityServicesRunning']) {
            $running = @($dg.SecurityServicesRunning)
            $credGuardRunning = ($running -contains 1)
        }
        if ($dg -and $dg.PSObject.Properties['VirtualizationBasedSecurityStatus']) {
            $vbsRunning = ([int]$dg.VirtualizationBasedSecurityStatus -eq 2)
        }
    } catch { }
    return [pscustomobject]@{
        run_as_ppl               = $runAsPPL
        credential_guard_running = $credGuardRunning
        vbs_running              = $vbsRunning
    }
}

# SC-23: session authenticity surfaces. LDAPServerIntegrity + NTLM restrictions.
function Get-SargeScSessionAuthenticity {
    [CmdletBinding()] param()
    $ldapIntegrity = $null
    $ntdsKey = 'HKLM:\System\CurrentControlSet\Services\NTDS\Parameters'
    try {
        if (Test-Path -LiteralPath $ntdsKey) {
            $p = Get-ItemProperty -LiteralPath $ntdsKey -ErrorAction Stop
            if ($p.PSObject.Properties['LDAPServerIntegrity']) {
                $ldapIntegrity = [int]$p.LDAPServerIntegrity
            }
        }
    } catch { }
    $ntlmSend = $null
    $ntlmRecv = $null
    $lsaKey = 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0'
    try {
        $p2 = Get-ItemProperty -LiteralPath $lsaKey -ErrorAction Stop
        if ($p2.PSObject.Properties['RestrictSendingNTLMTraffic'])   { $ntlmSend = [int]$p2.RestrictSendingNTLMTraffic }
        if ($p2.PSObject.Properties['RestrictReceivingNTLMTraffic']) { $ntlmRecv = [int]$p2.RestrictReceivingNTLMTraffic }
    } catch { }
    return [pscustomobject]@{
        ldap_server_integrity  = $ldapIntegrity
        ntlm_restrict_sending  = $ntlmSend
        ntlm_restrict_incoming = $ntlmRecv
    }
}

# SC-28 policy: BitLocker encryption method + AD/AAD recovery escrow policy.
function Get-SargeScBitLockerPolicy {
    [CmdletBinding()] param()
    $method = $null
    if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
        try {
            $os = Get-BitLockerVolume -ErrorAction Stop | Where-Object { $_.VolumeType -eq 'OperatingSystem' } | Select-Object -First 1
            if ($null -ne $os) { $method = [string]$os.EncryptionMethod }
        } catch { }
    }
    $adBackup = $null
    $fveKey = 'HKLM:\Software\Policies\Microsoft\FVE'
    try {
        if (Test-Path -LiteralPath $fveKey) {
            $p = Get-ItemProperty -LiteralPath $fveKey -ErrorAction Stop
            if ($p.PSObject.Properties['OSActiveDirectoryBackup'])        { $adBackup = [int]$p.OSActiveDirectoryBackup }
            if ($p.PSObject.Properties['OSRequireActiveDirectoryBackup']) { $adBackup = [int]$p.OSRequireActiveDirectoryBackup }
        }
    } catch { }
    return [pscustomobject]@{
        encryption_method  = $method
        ad_backup_required = $adBackup
        escrow_configured  = ($null -ne $adBackup -and $adBackup -ge 1)
    }
}
