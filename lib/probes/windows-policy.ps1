# lib/probes/windows-policy.ps1 - Sarge Windows policy inspection probes.
#
# Phase 1b (issue #31): probe managed-policy state on Windows hosts. Detects
# whether the device is AAD-joined + MDM-enrolled (Intune), AD-joined with or
# without RSAT/GPMC available, or in a workgroup. Enumerates applied policy
# from the MDM CSP registry path or from gpresult HTML.
#
# Standard user only. Targets PS 5.1 + PS 7+. Each probe uses the
# Invoke-SargeProbe pattern for error capture - failure of one probe must
# not abort the run.
#
# Verdict logic lives in assessment/checks/check-policy.ps1; this module
# only gathers raw observations.
#
# Modes returned by Get-SargeHostPolicyMode:
#   ad-rsat     - AD-joined, Get-GPO / Get-GPRegistryValue available
#   ad-gpresult - AD-joined, RSAT/GPMC absent, fall back to gpresult HTML
#   aad-mdm     - AAD-joined, MDM enrolled (MdmUrl populated)
#   aad-no-mdm  - AAD-joined, no MDM enforcement (security finding WIN-POL-1)
#   workgroup   - Neither AD- nor AAD-joined, no policy authority
#   unknown     - Probe error or dsregcmd unavailable

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Re-declare here so this module can be dot-sourced independently in Pester
# without requiring lib/platform.ps1. The function is identical; PowerShell
# late-binds to the most recent definition when both are loaded.
if (-not (Get-Command Invoke-SargeProbe -ErrorAction SilentlyContinue)) {
    function Invoke-SargeProbe {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)] [string] $ErrorKey,
            [Parameter(Mandatory)] [hashtable] $ProbeErrors,
            [Parameter(Mandatory)] [scriptblock] $Probe
        )
        try { return & $Probe }
        catch {
            $ProbeErrors[$ErrorKey] = $_.Exception.Message
            return $null
        }
    }
}

# Helper: parse dsregcmd output. Duplicates the logic in lib/platform.ps1
# so windows-policy.ps1 can stand alone. Returns hashtable with keys
# AzureAdJoined, DomainJoined, DomainName, MdmUrl, TenantName.
function ConvertFrom-SargePolicyDsRegCmd {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string[]] $Lines)

    $result = @{
        AzureAdJoined = $false
        DomainJoined  = $false
        DomainName    = $null
        MdmUrl        = $null
        TenantName    = $null
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
        elseif ($line -match '^\s*TenantName\s*:\s*(\S.*?)\s*$') {
            $result.TenantName = $Matches[1]
        }
    }
    return $result
}

# Get-SargeHostPolicyMode - classifies the host's policy-management posture.
# Returns a [pscustomobject] with .mode (one of the strings listed above),
# .reason (human-readable explanation), .probe_errors (hashtable), and
# .raw (dsregcmd parsed fields).
function Get-SargeHostPolicyMode {
    [CmdletBinding()] param()

    $probeErrors = @{}
    $dsreg = Invoke-SargeProbe -ErrorKey 'dsregcmd' -ProbeErrors $probeErrors -Probe {
        $tmp = Join-Path $env:TEMP ("sarge-pol-dsreg-" + (Get-Random) + ".txt")
        try {
            dsregcmd /status 2>&1 | Out-File -Encoding utf8 -LiteralPath $tmp
            $raw = Get-Content -LiteralPath $tmp -ErrorAction Stop
            $lines = @($raw) | Where-Object { $null -ne $_ -and $_ -ne '' }
            if ($lines.Count -eq 0) { throw 'dsregcmd produced no output' }
            ConvertFrom-SargePolicyDsRegCmd -Lines $lines
        } finally {
            Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue
        }
    }

    if ($null -eq $dsreg) {
        return [pscustomobject]@{
            mode         = 'unknown'
            reason       = 'dsregcmd unavailable; cannot classify policy mode'
            probe_errors = $probeErrors
            raw          = $null
        }
    }

    # Branch on join state. MDM enrollment is signaled by MdmUrl being
    # non-empty. AD-join takes precedence over AAD-join for classification
    # when both are true (hybrid join), because GPO is the authoritative
    # surface in that case.
    if ($dsreg.DomainJoined) {
        $rsatAvailable = $null -ne (Get-Command Get-GPO -ErrorAction SilentlyContinue)
        if ($rsatAvailable) {
            return [pscustomobject]@{
                mode         = 'ad-rsat'
                reason       = "DomainJoined=$true; RSAT GroupPolicy module present"
                probe_errors = $probeErrors
                raw          = $dsreg
            }
        }
        return [pscustomobject]@{
            mode         = 'ad-gpresult'
            reason       = "DomainJoined=$true; RSAT absent, falling back to gpresult HTML"
            probe_errors = $probeErrors
            raw          = $dsreg
        }
    }

    if ($dsreg.AzureAdJoined) {
        if (-not [string]::IsNullOrWhiteSpace($dsreg.MdmUrl)) {
            return [pscustomobject]@{
                mode         = 'aad-mdm'
                reason       = "AzureAdJoined=$true; MdmUrl populated ($($dsreg.MdmUrl))"
                probe_errors = $probeErrors
                raw          = $dsreg
            }
        }
        return [pscustomobject]@{
            mode         = 'aad-no-mdm'
            reason       = 'AzureAdJoined=true but MdmUrl empty - no MDM enforcement'
            probe_errors = $probeErrors
            raw          = $dsreg
        }
    }

    return [pscustomobject]@{
        mode         = 'workgroup'
        reason       = 'Neither AzureAdJoined nor DomainJoined'
        probe_errors = $probeErrors
        raw          = $dsreg
    }
}

# Get-SargeMdmPolicyInventory - enumerate HKLM:\SOFTWARE\Microsoft\PolicyManager
# \current\device\* . Each subkey is a CSP area (e.g. Browser, DeviceLock).
# Returns hashtable {area: {setting: value, ...}}. Standard-user readable
# on all supported Windows builds.
function Get-SargeMdmPolicyInventory {
    [CmdletBinding()] param()

    $root = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device'
    $result = @{}
    if (-not (Test-Path -LiteralPath $root)) {
        return $result
    }
    $areas = Get-ChildItem -LiteralPath $root -ErrorAction Stop
    foreach ($area in $areas) {
        $areaName = $area.PSChildName
        $settings = @{}
        try {
            $props = Get-ItemProperty -LiteralPath $area.PSPath -ErrorAction Stop
            foreach ($p in $props.PSObject.Properties) {
                $n = $p.Name
                # Skip PowerShell metadata properties.
                if ($n -in 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') { continue }
                $settings[$n] = $p.Value
            }
        } catch { }
        # Also descend one level to capture nested settings under areas like
        # Browser/SmartScreenEnabled where the value is under a subkey.
        try {
            $subKeys = Get-ChildItem -LiteralPath $area.PSPath -ErrorAction SilentlyContinue
            foreach ($sub in @($subKeys)) {
                try {
                    $subProps = Get-ItemProperty -LiteralPath $sub.PSPath -ErrorAction Stop
                    foreach ($p in $subProps.PSObject.Properties) {
                        $n = $p.Name
                        if ($n -in 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') { continue }
                        $settings[("{0}/{1}" -f $sub.PSChildName, $n)] = $p.Value
                    }
                } catch { }
            }
        } catch { }
        $result[$areaName] = $settings
    }
    return $result
}

# Get-SargeMdmDiagReport - run MDMDiagnosticsTool.exe -out <tmpdir> and parse
# the resulting HTML report for applied policies. Returns [pscustomobject]
# with .available (bool), .report_path (string|$null), .policies (array of
# {area, setting, value} from the HTML). On hosts where the tool isn't
# present (very old builds) returns .available=$false.
function Get-SargeMdmDiagReport {
    [CmdletBinding()] param(
        [int] $TimeoutSeconds = 60
    )

    $exe = 'MDMDiagnosticsTool.exe'
    $cmd = Get-Command $exe -ErrorAction SilentlyContinue
    if (-not $cmd) {
        return [pscustomobject]@{
            available   = $false
            report_path = $null
            policies    = @()
            reason      = 'MDMDiagnosticsTool.exe not found on PATH'
        }
    }

    $tmpDir = Join-Path $env:TEMP ("sarge-mdmdiag-" + (Get-Random))
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
    $policies = @()
    $reportPath = $null
    try {
        $proc = Start-Process -FilePath $exe -ArgumentList @('-out', $tmpDir) `
                              -NoNewWindow -PassThru -Wait `
                              -RedirectStandardOutput (Join-Path $tmpDir 'stdout.txt') `
                              -RedirectStandardError (Join-Path $tmpDir 'stderr.txt')
        if ($proc.ExitCode -ne 0) {
            return [pscustomobject]@{
                available   = $true
                report_path = $null
                policies    = @()
                reason      = "MDMDiagnosticsTool exited $($proc.ExitCode)"
            }
        }
        # The tool writes MDMDiagReport.html (varies by build) into the out dir.
        $htmlCandidates = Get-ChildItem -LiteralPath $tmpDir -Filter '*.html' -ErrorAction SilentlyContinue
        foreach ($h in @($htmlCandidates)) {
            $reportPath = $h.FullName
            $text = Get-Content -LiteralPath $h.FullName -Raw -ErrorAction SilentlyContinue
            if (-not $text) { continue }
            # Pull policy rows. The HTML structure varies across builds; we
            # use a permissive regex that catches <td>area</td><td>setting</td>
            # <td>value</td> triples. This is heuristic - downstream consumers
            # should also read Get-SargeMdmPolicyInventory for ground truth.
            $matches = [regex]::Matches($text, '<tr[^>]*>\s*<td[^>]*>([^<]+)</td>\s*<td[^>]*>([^<]+)</td>\s*<td[^>]*>([^<]*)</td>')
            foreach ($m in $matches) {
                $policies += [pscustomobject]@{
                    area    = $m.Groups[1].Value.Trim()
                    setting = $m.Groups[2].Value.Trim()
                    value   = $m.Groups[3].Value.Trim()
                }
            }
            break
        }
    } finally {
        # Leave tmpDir on disk for inspection; assess.ps1 will copy the report
        # into the run folder. Caller is responsible for cleanup.
    }

    return [pscustomobject]@{
        available   = $true
        report_path = $reportPath
        tmp_dir     = $tmpDir
        policies    = $policies
        reason      = if ($null -eq $reportPath) { 'no HTML output located' } else { 'ok' }
    }
}

# Get-SargeGpresultData - run gpresult /h <tmphtml> and parse for applied
# GPO names and computer-scope policy settings. Standard-user runnable
# (uses /SCOPE:USER implicitly when /h alone is given on some builds; we
# explicitly include both scopes). Returns [pscustomobject].
function Get-SargeGpresultData {
    [CmdletBinding()] param()

    $tmp = Join-Path $env:TEMP ("sarge-gpresult-" + (Get-Random) + ".html")
    $applied = @()
    $denied  = @()
    $rawAvailable = $false
    try {
        # /h emits HTML; /f overwrites. We do NOT use /SCOPE:COMPUTER because
        # that requires elevation. /SCOPE:USER is standard-user OK.
        $proc = Start-Process -FilePath 'gpresult.exe' `
                              -ArgumentList @('/SCOPE:USER','/h', $tmp, '/f') `
                              -NoNewWindow -PassThru -Wait `
                              -RedirectStandardOutput ($tmp + '.stdout') `
                              -RedirectStandardError ($tmp + '.stderr')
        if ($proc.ExitCode -ne 0) {
            return [pscustomobject]@{
                available = $false
                report_path = $null
                applied_gpos = @()
                denied_gpos  = @()
                reason = "gpresult exited $($proc.ExitCode)"
            }
        }
        if (-not (Test-Path -LiteralPath $tmp)) {
            return [pscustomobject]@{
                available = $false
                report_path = $null
                applied_gpos = @()
                denied_gpos  = @()
                reason = 'gpresult produced no HTML'
            }
        }
        $rawAvailable = $true
        $text = Get-Content -LiteralPath $tmp -Raw

        # Applied / Denied GPO names. gpresult HTML uses headings + lists for
        # these. The locale-independent fragment we can rely on is the
        # standard table layout - parse <td class="info">.* and look for
        # neighbors that say "Applied" / "Denied".
        $appliedMatch = [regex]::Matches($text, '(?is)Applied\s*GPOs.*?<table[^>]*>(.*?)</table>')
        foreach ($block in $appliedMatch) {
            $rows = [regex]::Matches($block.Groups[1].Value, '<tr[^>]*>(.*?)</tr>')
            foreach ($r in $rows) {
                $cells = [regex]::Matches($r.Groups[1].Value, '<td[^>]*>([^<]*)</td>')
                if ($cells.Count -ge 1) {
                    $name = $cells[0].Groups[1].Value.Trim()
                    if ($name -and $name -notmatch '^GPO$') { $applied += $name }
                }
            }
        }
        $deniedMatch = [regex]::Matches($text, '(?is)Denied\s*GPOs.*?<table[^>]*>(.*?)</table>')
        foreach ($block in $deniedMatch) {
            $rows = [regex]::Matches($block.Groups[1].Value, '<tr[^>]*>(.*?)</tr>')
            foreach ($r in $rows) {
                $cells = [regex]::Matches($r.Groups[1].Value, '<td[^>]*>([^<]*)</td>')
                if ($cells.Count -ge 1) {
                    $name = $cells[0].Groups[1].Value.Trim()
                    if ($name -and $name -notmatch '^GPO$') { $denied += $name }
                }
            }
        }
    } catch {
        return [pscustomobject]@{
            available = $false
            report_path = $null
            applied_gpos = @()
            denied_gpos  = @()
            reason = $_.Exception.Message
        }
    }

    return [pscustomobject]@{
        available    = $rawAvailable
        report_path  = $tmp
        applied_gpos = $applied
        denied_gpos  = $denied
        reason       = 'ok'
    }
}

# Get-SargeAdGpoData - wraps Get-GPO / Get-GPRegistryValue for the AD-rsat
# path. Returns $null + a reason if the GroupPolicy module is unavailable
# or if the cmdlet requires elevation we don't have. Never elevates.
function Get-SargeAdGpoData {
    [CmdletBinding()] param()

    if (-not (Get-Command Get-GPO -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{
            available = $false
            gpos      = @()
            reason    = 'Get-GPO cmdlet not available (RSAT GroupPolicy module not installed)'
        }
    }
    try {
        # -All is the standard-user-readable form. If this throws "Access
        # denied" we don't elevate; we surface the error and let the verdict
        # become SKIP-CONTEXT-DEFERRED.
        $all = Get-GPO -All -ErrorAction Stop
        $gpos = @()
        foreach ($g in @($all)) {
            $gpos += [pscustomobject]@{
                DisplayName = [string]$g.DisplayName
                Id          = [string]$g.Id
                GpoStatus   = [string]$g.GpoStatus
            }
        }
        return [pscustomobject]@{
            available = $true
            gpos      = $gpos
            reason    = 'ok'
        }
    } catch {
        return [pscustomobject]@{
            available = $false
            gpos      = @()
            reason    = "Get-GPO failed: $($_.Exception.Message)"
        }
    }
}
