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
