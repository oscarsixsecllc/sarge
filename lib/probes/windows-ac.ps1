# lib/probes/windows-ac.ps1  -  Access Control (AC) data-gathering probes.
#
# Each function returns a [pscustomobject] of raw observations. The verdict
# logic  -  what counts as PASS / FAIL / etc.  -  lives in
# assessment/checks/check-ac.ps1. Keeping the split lets us mock these probes
# in Pester without re-implementing verdict math.
#
# Standard user only. Targets PS 5.1 and PS 7+. Errors are captured by the
# caller via Invoke-SargeCheck; functions here should throw on real failure
# rather than silently returning $null so the exception text reaches the
# UNTESTED finding.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# AC-2: enumerate local accounts whose password is empty / not required.
# Get-LocalUser is standard-user-readable on Windows 10/11 client SKUs.
# PasswordRequired = $false means the account can have a blank password
# (analog of /etc/shadow empty field). We exclude well-known disabled SIDs.
function Get-SargeAcEmptyPasswordAccounts {
    [CmdletBinding()] param()
    if (-not (Get-Command Get-LocalUser -ErrorAction SilentlyContinue)) {
        throw 'Get-LocalUser not available (likely AD-joined server or stripped SKU)'
    }
    $users = Get-LocalUser -ErrorAction Stop
    $bad = @()
    foreach ($u in $users) {
        if ($u.Enabled -and -not $u.PasswordRequired) {
            $bad += $u.Name
        }
    }
    return [pscustomobject]@{
        accounts = $bad
        total    = $users.Count
    }
}

# AC-3: ACL state on the OpenClaw workspace dir ($env:USERPROFILE\.openclaw).
# We do NOT require the dir to exist (mirrors the bash skipx behavior); the
# check script handles the "missing" case as SKIP. When it does exist, we
# return the access-rule identities so the verdict logic can flag any
# non-owner / non-SYSTEM ACE as a finding.
function Get-SargeAcOpenclawAcl {
    [CmdletBinding()] param()
    $dir = Join-Path $env:USERPROFILE '.openclaw'
    if (-not (Test-Path -LiteralPath $dir -PathType Container)) {
        return [pscustomobject]@{
            present = $false
            path    = $dir
            owner   = $null
            extra_principals = @()
        }
    }
    $acl   = Get-Acl -LiteralPath $dir -ErrorAction Stop
    $me    = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $extra = @()
    foreach ($ace in $acl.Access) {
        if ($ace.IsInherited) { continue }
        $id = [string]$ace.IdentityReference
        if ($id -ieq $me) { continue }
        if ($id -match '(?i)^NT AUTHORITY\\SYSTEM$') { continue }
        if ($id -match '(?i)^BUILTIN\\Administrators$') { continue }
        $extra += $id
    }
    return [pscustomobject]@{
        present          = $true
        path             = $dir
        owner            = [string]$acl.Owner
        extra_principals = $extra
    }
}

# AC-6: enumerate local Administrators group members. Returns the count
# (interactive accounts in Administrators is the security signal  -  more than
# 1-2 named admins on a workstation is a red flag).
function Get-SargeAcAdminGroupMembers {
    [CmdletBinding()] param()
    if (-not (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue)) {
        throw 'Get-LocalGroupMember not available'
    }
    # English+localized group lookup: try by SID for portability.
    # S-1-5-32-544 = BUILTIN\Administrators on every Windows install.
    $members = @()
    try {
        $members = Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop
    } catch {
        # Some 11 builds emit a benign CimException when a member is an
        # orphaned SID. Fall back to "Administrators" by name.
        $members = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop
    }
    $names = @($members | ForEach-Object { [string]$_.Name })
    return [pscustomobject]@{
        members = $names
        count   = $names.Count
    }
}

# AC-7: account lockout policy via `net accounts`. Standard user can read.
# Output is localized; we parse only on values, not labels.
function Get-SargeAcLockoutPolicy {
    [CmdletBinding()] param()
    $raw = & net.exe accounts 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "net accounts exited $LASTEXITCODE"
    }
    $text = ($raw -join "`n")
    # Lockout threshold line  -  try English, then any "lockout threshold"-ish line.
    $threshold = $null
    $duration  = $null
    foreach ($line in $raw) {
        if ($line -match '(?i)Lockout\s+threshold[^\d]+(\d+|Never)') {
            $threshold = $Matches[1]
        }
        elseif ($line -match '(?i)Lockout\s+duration[^\d]+(\d+)') {
            $duration = [int]$Matches[1]
        }
    }
    return [pscustomobject]@{
        threshold = $threshold   # int as string, 'Never', or $null
        duration  = $duration    # minutes, or $null
        raw       = $text
    }
}

# AC-11: idle screen-lock policy. The standard-user-readable surface is the
# user-scope registry value HKCU:\...\Desktop\ScreenSaveTimeOut +
# ScreenSaverIsSecure. Machine-policy GPO key under HKLM is also checked
# (reads OK as standard user; writes need admin).
function Get-SargeAcIdleLockPolicy {
    [CmdletBinding()] param()
    $userTimeoutSec  = $null
    $userSecure      = $null
    $machineTimeout  = $null

    $hkcuDesktop = 'HKCU:\Control Panel\Desktop'
    try {
        $p = Get-ItemProperty -LiteralPath $hkcuDesktop -ErrorAction Stop
        if ($p.PSObject.Properties['ScreenSaveTimeOut']) {
            $userTimeoutSec = [int]$p.ScreenSaveTimeOut
        }
        if ($p.PSObject.Properties['ScreenSaverIsSecure']) {
            $userSecure = [int]$p.ScreenSaverIsSecure -eq 1
        }
    } catch { }

    $gpoPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'
    try {
        if (Test-Path -LiteralPath $gpoPath) {
            $g = Get-ItemProperty -LiteralPath $gpoPath -ErrorAction Stop
            if ($g.PSObject.Properties['ScreenSaveTimeOut']) {
                $machineTimeout = [int]$g.ScreenSaveTimeOut
            }
        }
    } catch { }

    return [pscustomobject]@{
        user_timeout_seconds   = $userTimeoutSec
        user_screensaver_secure = $userSecure
        machine_policy_timeout = $machineTimeout
    }
}

# AC-8: legal logon banner. Standard user can read the System policy hive.
function Get-SargeAcLegalBanner {
    [CmdletBinding()] param()
    $key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    $caption = $null
    $text    = $null
    try {
        $p = Get-ItemProperty -LiteralPath $key -ErrorAction Stop
        if ($p.PSObject.Properties['LegalNoticeCaption']) { $caption = [string]$p.LegalNoticeCaption }
        if ($p.PSObject.Properties['LegalNoticeText'])    { $text    = [string]$p.LegalNoticeText }
    } catch { }
    return [pscustomobject]@{
        caption        = $caption
        caption_length = if ($null -eq $caption) { 0 } else { $caption.Length }
        text_length    = if ($null -eq $text)    { 0 } else { $text.Length }
    }
}

# AC-12: SMB network logon session termination. LanmanServer autodisconnect in
# MINUTES; -1 = never. Standard user can read.
function Get-SargeAcSessionTermination {
    [CmdletBinding()] param()
    $key = 'HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters'
    $autodisconnect = $null
    try {
        $p = Get-ItemProperty -LiteralPath $key -ErrorAction Stop
        if ($p.PSObject.Properties['autodisconnect']) {
            $autodisconnect = [int]$p.autodisconnect
        }
    } catch { }
    return [pscustomobject]@{
        autodisconnect_minutes = $autodisconnect
    }
}

# AC-17: RDP remote access posture - NLA required, encryption level, security
# layer. Standard user can read the Terminal Server registry hive.
function Get-SargeAcRdpPosture {
    [CmdletBinding()] param()
    $rdpTcp = 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    $tsRoot = 'HKLM:\System\CurrentControlSet\Control\Terminal Server'
    $userAuth      = $null
    $minEncryption = $null
    $securityLayer = $null
    $denyTSConnect = $null
    try {
        $p = Get-ItemProperty -LiteralPath $rdpTcp -ErrorAction Stop
        if ($p.PSObject.Properties['UserAuthentication']) { $userAuth      = [int]$p.UserAuthentication }
        if ($p.PSObject.Properties['MinEncryptionLevel']) { $minEncryption = [int]$p.MinEncryptionLevel }
        if ($p.PSObject.Properties['SecurityLayer'])      { $securityLayer = [int]$p.SecurityLayer }
    } catch { }
    try {
        $p2 = Get-ItemProperty -LiteralPath $tsRoot -ErrorAction Stop
        if ($p2.PSObject.Properties['fDenyTSConnections']) { $denyTSConnect = [int]$p2.fDenyTSConnections }
    } catch { }
    return [pscustomobject]@{
        nla_required         = ($userAuth -eq 1)
        user_authentication  = $userAuth
        min_encryption_level = $minEncryption
        security_layer       = $securityLayer
        rdp_disabled         = ($denyTSConnect -eq 1)
        deny_ts_connections  = $denyTSConnect
    }
}
