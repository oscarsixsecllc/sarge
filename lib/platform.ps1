# lib/platform.ps1 — Sarge Windows platform detection
# PowerShell analog of lib/platform.sh, scoped to Windows only.
#
# Companion to @keonik's cross-platform foundation from PR #3. The bash side owns
# Linux + macOS detection; this module owns Windows. Downstream check modules
# (filed as separate PRs per parent issue #12) consume the JSON document this
# produces to decide PASS / WARN / FAIL / SKIP / ENFORCED-EXTERNALLY.
#
# Scope (load-bearing): we are detecting OpenClaw-on-Windows enterprise context,
# NOT generic Windows hardening posture. The probe set is intentionally narrow
# to what downstream OpenClaw control modules need to make defer-vs-check
# decisions (e.g. "AppLocker is active, so AC-3 is ENFORCED-EXTERNALLY, skip
# our directory ACL check").
#
# Targets: Windows PowerShell 5.1 (default on Windows 10/11) AND PowerShell 7+.
# All probes must work as standard user — never invoke admin-only cmdlets.
# Probes never abort the function; failures emit $null + a probe_errors entry.
#
# Exports:
#   Get-SargeWindowsContext   returns a [pscustomobject] matching the schema
#                             defined in oscarsixsecllc/sarge#13.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Internal helper — runs a probe scriptblock, captures the value, and on failure
# records the exception message in $ProbeErrors (passed by reference) under
# $ErrorKey. Never rethrows. Always returns either the probe's value or $null.
function Invoke-SargeProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ErrorKey,
        [Parameter(Mandatory)] [hashtable] $ProbeErrors,
        [Parameter(Mandatory)] [scriptblock] $Probe
    )
    try {
        return & $Probe
    } catch {
        $ProbeErrors[$ErrorKey] = $_.Exception.Message
        return $null
    }
}

# Parse `dsregcmd /status` output. The cmd is text, not JSON. Format is:
#   +----------------------------------------------------------------------+
#   | Device State                                                         |
#   +----------------------------------------------------------------------+
#
#            AzureAdJoined : YES
#         EnterpriseJoined : NO
#             DomainJoined : NO
#                ...
#                   MdmUrl : https://enrollment.manage.microsoft.com/...
#
# We tolerate variable leading whitespace and case differences on YES/NO. We
# look for the literal key labels Microsoft documents at:
#   https://learn.microsoft.com/en-us/azure/active-directory/devices/troubleshoot-device-dsregcmd
#
# Returns a hashtable with keys: AzureAdJoined (bool), DomainJoined (bool),
# DomainName (string|$null), MdmUrl (string|$null). Throws on any failure so
# Invoke-SargeProbe can capture the error.
function ConvertFrom-DsRegCmdOutput {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string[]] $Lines)

    $result = @{
        AzureAdJoined = $false
        DomainJoined  = $false
        DomainName    = $null
        MdmUrl        = $null
    }

    foreach ($line in $Lines) {
        if ($line -match '^\s*AzureAdJoined\s*:\s*(YES|NO)\s*$') {
            $result.AzureAdJoined = ($Matches[1].ToUpperInvariant() -eq 'YES')
        }
        elseif ($line -match '^\s*DomainJoined\s*:\s*(YES|NO)\s*$') {
            $result.DomainJoined = ($Matches[1].ToUpperInvariant() -eq 'YES')
        }
        elseif ($line -match '^\s*DomainName\s*:\s*(\S.*?)\s*$') {
            $result.DomainName = $Matches[1]
        }
        elseif ($line -match '^\s*MdmUrl\s*:\s*(\S.*?)\s*$') {
            $result.MdmUrl = $Matches[1]
        }
    }

    return $result
}

function Get-SargeWindowsContext {
    [CmdletBinding()]
    param()

    $probeErrors = @{}

    # ---- dsregcmd: AAD join, domain join, MDM enrollment --------------------
    # dsregcmd ships in-box on Windows 10 1607+ and Windows 11. Standard user
    # can run it; some fields are blank without elevation but the four we read
    # (AzureAdJoined, DomainJoined, DomainName, MdmUrl) are populated for
    # standard users on supported Windows versions.
    $dsreg = Invoke-SargeProbe -ErrorKey 'dsregcmd' -ProbeErrors $probeErrors -Probe {
        $raw = & dsregcmd.exe /status 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "dsregcmd exited $LASTEXITCODE"
        }
        ConvertFrom-DsRegCmdOutput -Lines $raw
    }

    # Win32_ComputerSystem fallback for domain-join only (dsregcmd preferred
    # because it also reveals AAD join / MDM enrollment).
    $cimComputer = Invoke-SargeProbe -ErrorKey 'win32_computersystem' -ProbeErrors $probeErrors -Probe {
        Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    }

    if ($dsreg) {
        $isDomainJoined = ($dsreg.AzureAdJoined -or $dsreg.DomainJoined)
        $domainName     = $dsreg.DomainName
        $intuneManaged  = -not [string]::IsNullOrWhiteSpace($dsreg.MdmUrl)
    }
    elseif ($cimComputer) {
        $isDomainJoined = [bool]$cimComputer.PartOfDomain
        $domainName     = if ($cimComputer.PartOfDomain) { $cimComputer.Domain } else { $null }
        $intuneManaged  = $null  # cannot detect Intune without dsregcmd
        if (-not $probeErrors.ContainsKey('intune_managed')) {
            $probeErrors['intune_managed'] = 'dsregcmd unavailable; cannot detect MDM enrollment without it'
        }
    }
    else {
        $isDomainJoined = $null
        $domainName     = $null
        $intuneManaged  = $null
    }

    # ---- gpresult: any applied GPOs? ----------------------------------------
    # gpresult /R /SCOPE:USER works as standard user (no elevation). We only
    # need the presence of an "Applied Group Policy Objects" section with at
    # least one entry, not the contents. On non-domain-joined hosts gpresult
    # still runs but typically reports "N/A" or empty applied list.
    #
    # Localization hazard: the section header is localized in non-English
    # Windows builds. We grep for the canonical en-US string AND a fallback of
    # any indented bullet under any heading containing "Applied" — this is a
    # heuristic; downstream check modules should re-probe directly if they
    # need precise GPO names.
    $gpoPresent = Invoke-SargeProbe -ErrorKey 'gpresult' -ProbeErrors $probeErrors -Probe {
        $raw = & gpresult.exe /R /SCOPE:USER 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "gpresult exited $LASTEXITCODE"
        }
        $text = ($raw -join "`n")
        if ($text -match '(?ms)Applied Group Policy Objects\s*-+\s*(?<body>.*?)(?:\n\s*\n|\Z)') {
            $body = $Matches['body'].Trim()
            return ($body.Length -gt 0 -and $body -notmatch '(?im)^\s*N/?A\s*$')
        }
        return $false
    }

    # ---- AppLocker effective policy -----------------------------------------
    # Get-AppLockerPolicy -Effective returns the merged policy (local + GPO).
    # Microsoft docs note this can require elevation in some configurations
    # to read the SRP store, but the merged effective policy is generally
    # readable by standard users. If it errors, we record it and emit $null
    # rather than guessing.
    #   https://learn.microsoft.com/en-us/powershell/module/applocker/get-applockerpolicy
    # The cmdlet ships with the AppLocker module which is available on
    # Enterprise / Education / Server SKUs. On Home / Pro it may be missing.
    $applockerActive = Invoke-SargeProbe -ErrorKey 'applocker' -ProbeErrors $probeErrors -Probe {
        if (-not (Get-Command Get-AppLockerPolicy -ErrorAction SilentlyContinue)) {
            throw 'Get-AppLockerPolicy not available on this SKU'
        }
        $policy = Get-AppLockerPolicy -Effective -ErrorAction Stop
        # An "empty" policy is one with no RuleCollections containing rules.
        # Convert to XML and check for any <FilePathRule>, <FileHashRule>, or
        # <FilePublisherRule> element.
        $xml = $policy.ToXml()
        return ($xml -match '<File(Path|Hash|Publisher)Rule\b')
    }

    # ---- WDAC / Device Guard ------------------------------------------------
    # Win32_DeviceGuard is in root\Microsoft\Windows\DeviceGuard and is
    # readable by standard users on Windows 10 1709+. CodeIntegrityPolicy
    # EnforcementStatus values per Microsoft:
    #   0 = Off, 1 = Audit mode, 2 = Enforced
    #   https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/operations/citool-commands
    $wdacActive = Invoke-SargeProbe -ErrorKey 'wdac' -ProbeErrors $probeErrors -Probe {
        $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' `
                              -ClassName Win32_DeviceGuard -ErrorAction Stop
        if ($null -eq $dg) {
            throw 'Win32_DeviceGuard returned no instance'
        }
        return ([int]$dg.CodeIntegrityPolicyEnforcementStatus -eq 2)
    }

    # ---- Defender realtime + tamper protection ------------------------------
    # Get-MpComputerStatus is from the Defender PowerShell module (built in on
    # Windows 10/11 client SKUs). On Server SKUs without the Defender feature
    # installed, the cmdlet is missing — handle that gracefully.
    #   https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus
    $defenderStatus = Invoke-SargeProbe -ErrorKey 'defender' -ProbeErrors $probeErrors -Probe {
        if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
            throw 'Get-MpComputerStatus not available (Defender module missing)'
        }
        Get-MpComputerStatus -ErrorAction Stop
    }

    if ($defenderStatus) {
        $defenderRealtimeActive   = [bool]$defenderStatus.RealTimeProtectionEnabled
        # IsTamperProtected was added in Defender platform updates ~2019. On
        # older builds the property may not exist; PSObject.Properties guards
        # against StrictMode property-not-found errors.
        $tpProp = $defenderStatus.PSObject.Properties['IsTamperProtected']
        if ($tpProp) {
            $defenderTamperProtection = [bool]$tpProp.Value
        } else {
            $defenderTamperProtection = $null
            $probeErrors['defender_tamper_protection'] = 'IsTamperProtected property not exposed by Get-MpComputerStatus on this build'
        }
    } else {
        $defenderRealtimeActive   = $null
        $defenderTamperProtection = $null
    }

    # ---- Local administrator check ------------------------------------------
    # WindowsPrincipal.IsInRole is the canonical, unambiguous way to ask
    # "is the current process token a member of the local Administrators
    # group" — works as standard user, requires no elevation, and respects
    # UAC filtered tokens (an admin running un-elevated reports false here,
    # which is the security-relevant answer).
    #   https://learn.microsoft.com/en-us/dotnet/api/system.security.principal.windowsprincipal.isinrole
    $isLocalAdmin = Invoke-SargeProbe -ErrorKey 'is_local_admin' -ProbeErrors $probeErrors -Probe {
        $identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    # ---- Edition + build ----------------------------------------------------
    # Get-ComputerInfo is slow (2-5s) but the canonical source. We fetch both
    # WindowsProductName and OsBuildNumber in one call to avoid running it
    # twice. Get-ComputerInfo exists in Windows PowerShell 5.1 and PS 7+.
    $computerInfo = Invoke-SargeProbe -ErrorKey 'computerinfo' -ProbeErrors $probeErrors -Probe {
        Get-ComputerInfo -Property WindowsProductName, OsBuildNumber -ErrorAction Stop
    }

    if ($computerInfo) {
        $windowsEdition = $computerInfo.WindowsProductName
        # OsBuildNumber comes back as a string already on most builds; cast
        # to string defensively for a contractual schema.
        $windowsBuild   = if ($null -ne $computerInfo.OsBuildNumber) {
                              [string]$computerInfo.OsBuildNumber
                          } else { $null }
    } else {
        $windowsEdition = $null
        $windowsBuild   = $null
    }

    # ---- OpenClaw install path detection ------------------------------------
    # Heuristic, because OpenClaw-on-Windows install layout is not yet fully
    # standardized. Check, in order:
    #   1. $env:OPENCLAW_HOME if set
    #   2. %LOCALAPPDATA%\OpenClaw   (per-user install, expected default)
    #   3. %PROGRAMFILES%\OpenClaw   (machine-wide install)
    #   4. %PROGRAMFILES(X86)%\OpenClaw
    # Returns the first existing directory or $null. Downstream control modules
    # will re-probe to validate ACLs / contents — this is just "where is it".
    $openclawInstallPath = Invoke-SargeProbe -ErrorKey 'openclaw_install_path' -ProbeErrors $probeErrors -Probe {
        $candidates = @()
        if ($env:OPENCLAW_HOME)             { $candidates += $env:OPENCLAW_HOME }
        if ($env:LOCALAPPDATA)              { $candidates += (Join-Path $env:LOCALAPPDATA 'OpenClaw') }
        if ($env:ProgramFiles)              { $candidates += (Join-Path $env:ProgramFiles 'OpenClaw') }
        if (${env:ProgramFiles(x86)})       { $candidates += (Join-Path ${env:ProgramFiles(x86)} 'OpenClaw') }
        foreach ($c in $candidates) {
            if (Test-Path -LiteralPath $c -PathType Container) {
                return $c
            }
        }
        return $null
    }

    # ---- OpenClaw service account -------------------------------------------
    # If OpenClaw is installed as a Windows service, surface the StartName
    # (the account under which the SCM launches it). Standard user can read
    # service metadata via Win32_Service. Service name pattern is uncertain;
    # match openclaw* (case-insensitive). Returns the first non-empty
    # StartName found, or $null if no matching service.
    $openclawServiceAccount = Invoke-SargeProbe -ErrorKey 'openclaw_service_account' -ProbeErrors $probeErrors -Probe {
        $svcs = Get-CimInstance -ClassName Win32_Service -Filter "Name LIKE 'openclaw%'" -ErrorAction Stop
        if ($null -eq $svcs) { return $null }
        foreach ($s in @($svcs)) {
            if (-not [string]::IsNullOrWhiteSpace($s.StartName)) {
                return $s.StartName
            }
        }
        return $null
    }

    # ---- Assemble document --------------------------------------------------
    # Schema is contractual — see oscarsixsecllc/sarge#13. Downstream check
    # modules consume this JSON. Add fields if needed; never remove or rename
    # without coordination.
    return [ordered]@{
        version            = 1
        captured_at        = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        host               = [ordered]@{
            windows_edition = $windowsEdition
            windows_build   = $windowsBuild
        }
        enterprise_context = [ordered]@{
            is_domain_joined = $isDomainJoined
            domain_name      = $domainName
            intune_managed   = $intuneManaged
            gpo_present      = $gpoPresent
        }
        active_controls    = [ordered]@{
            applocker_active           = $applockerActive
            wdac_active                = $wdacActive
            defender_realtime_active   = $defenderRealtimeActive
            defender_tamper_protection = $defenderTamperProtection
        }
        user_context       = [ordered]@{
            is_local_admin = $isLocalAdmin
        }
        openclaw           = [ordered]@{
            install_path    = $openclawInstallPath
            service_account = $openclawServiceAccount
        }
        probe_errors       = $probeErrors
    }
}

# Module side-effects intentionally limited to defining functions. Direct
# invocation (e.g. for debugging) should go through
# assessment/probes/detect-context.ps1, which is the supported entry point
# and handles writing the JSON document. This keeps dot-sourcing safe and
# avoids surprising side-effects when a future module imports this file.
