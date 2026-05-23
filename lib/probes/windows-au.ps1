# lib/probes/windows-au.ps1  -  Audit & Accountability (AU) probes.
#
# Standard-user-readable surfaces:
#   - auditpol /get /category:*  -  readable as standard user on Win10/11 client
#     SKUs by default (admin-only on some hardened domain configs).
#   - Get-WinEvent -ListLog (no -FilterHashtable)  -  log metadata is readable
#     even when the log contents aren't.
#   - HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\<channel>  -  read-only
#     from standard user; gives us File (log path) and MaxSize.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# AU-2: audit policy categories enabled. Returns per-category Success/Failure
# settings as a hashtable. If auditpol requires elevation (some hardened
# environments), returns $null with a thrown error so the check emits
# SKIP-CONTEXT-DEFERRED.
function Get-SargeAuAuditPolicy {
    [CmdletBinding()] param()
    $raw = & auditpol.exe /get /category:* 2>&1
    if ($LASTEXITCODE -ne 0) {
        # On some SKUs auditpol exits non-zero for standard user even when
        # category:* would be readable in elevated context.
        throw "auditpol exited $LASTEXITCODE (requires elevated session?)"
    }
    $entries = @()
    foreach ($line in $raw) {
        # Lines look like:  "  Logon                                  Success and Failure"
        if ($line -match '^\s{2,}(?<cat>\S.+?)\s{2,}(?<setting>No Auditing|Success and Failure|Success|Failure)\s*$') {
            $entries += [pscustomobject]@{
                category = $Matches['cat'].Trim()
                setting  = $Matches['setting'].Trim()
            }
        }
    }
    return [pscustomobject]@{
        entries = $entries
        raw     = ($raw -join "`n")
    }
}

# AU-4 / AU-12: per-channel log retention + file location for the core
# channels Sarge cares about.
function Get-SargeAuEventLogMetadata {
    [CmdletBinding()] param()
    $channels = @('Security','System','Application','Microsoft-Windows-PowerShell/Operational')
    $out = @()
    foreach ($name in $channels) {
        $info = $null
        try {
            $info = Get-WinEvent -ListLog $name -ErrorAction Stop
        } catch {
            # Security log read of -ListLog metadata can require admin on
            # some hardened systems; skip silently and continue.
            $out += [pscustomobject]@{
                name = $name
                accessible = $false
                file_path = $null
                max_size_mb = $null
                retention = $null
                error = $_.Exception.Message
            }
            continue
        }
        $out += [pscustomobject]@{
            name        = $name
            accessible  = $true
            file_path   = [string]$info.LogFilePath
            max_size_mb = if ($info.MaximumSizeInBytes) { [int]([math]::Floor($info.MaximumSizeInBytes / 1MB)) } else { $null }
            retention   = [string]$info.LogMode
            error       = $null
        }
    }
    return $out
}

# AU-9: ACL on the Security event log file. Returns whether any non-SYSTEM /
# non-Administrators principal has access. Most users won't be able to read
# the file at all (which is correct)  -  that's PASS.
function Get-SargeAuSecurityLogAcl {
    [CmdletBinding()] param()
    $path = "$env:SystemRoot\System32\Winevt\Logs\Security.evtx"
    if (-not (Test-Path -LiteralPath $path)) {
        return [pscustomobject]@{
            path = $path
            accessible = $false
            extra_principals = @()
            error = 'file not present'
        }
    }
    try {
        $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
    } catch {
        # Standard user typically cannot read Security.evtx ACL  -  that is
        # itself a PASS signal for AU-9.
        return [pscustomobject]@{
            path = $path
            accessible = $false
            extra_principals = @()
            error = $_.Exception.Message
        }
    }
    $extra = @()
    foreach ($ace in $acl.Access) {
        $id = [string]$ace.IdentityReference
        if ($id -match '(?i)^(NT AUTHORITY\\SYSTEM|BUILTIN\\Administrators|NT SERVICE\\EventLog)$') { continue }
        $extra += $id
    }
    return [pscustomobject]@{
        path = $path
        accessible = $true
        extra_principals = $extra
        error = $null
    }
}
