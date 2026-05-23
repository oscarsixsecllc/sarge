# lib/probes/windows-ia.ps1  -  Identification & Authentication (IA) probes.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# IA-5: password policy via `net accounts`. Reads min length, max age, min age,
# history. Standard user can run net accounts.
function Get-SargeIaPasswordPolicy {
    [CmdletBinding()] param()
    $raw = & net.exe accounts 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "net accounts exited $LASTEXITCODE"
    }
    $minLen = $null
    $maxAge = $null
    $minAge = $null
    $hist   = $null
    foreach ($line in $raw) {
        if ($line -match '(?i)Minimum\s+password\s+length[^\d]+(\d+)') { $minLen = [int]$Matches[1] }
        elseif ($line -match '(?i)Maximum\s+password\s+age[^\d]+(\d+|Unlimited)') {
            $maxAge = if ($Matches[1] -ieq 'Unlimited') { -1 } else { [int]$Matches[1] }
        }
        elseif ($line -match '(?i)Minimum\s+password\s+age[^\d]+(\d+)') { $minAge = [int]$Matches[1] }
        elseif ($line -match '(?i)Length\s+of\s+password\s+history[^\d]+(\d+|None)') {
            $hist = if ($Matches[1] -ieq 'None') { 0 } else { [int]$Matches[1] }
        }
    }
    return [pscustomobject]@{
        min_length     = $minLen
        max_age_days   = $maxAge
        min_age_days   = $minAge
        history_length = $hist
        raw            = ($raw -join "`n")
    }
}

# IA-2: account types present  -  distinguish local accounts from Microsoft
# accounts (MSA) / AzureAD accounts. We approximate via Get-LocalUser; MSA
# accounts surface with PrincipalSource = 'MicrosoftAccount' on PS 5.1+ /
# Win10 1709+. AzureAD users show as PrincipalSource = 'AzureAD'.
function Get-SargeIaAccountTypes {
    [CmdletBinding()] param()
    if (-not (Get-Command Get-LocalUser -ErrorAction SilentlyContinue)) {
        throw 'Get-LocalUser not available'
    }
    $users = Get-LocalUser -ErrorAction Stop
    $local = @()
    $msa   = @()
    $aad   = @()
    $other = @()
    foreach ($u in $users) {
        if (-not $u.Enabled) { continue }
        $src = $null
        if ($u.PSObject.Properties['PrincipalSource']) { $src = [string]$u.PrincipalSource }
        switch -Regex ($src) {
            'MicrosoftAccount' { $msa   += $u.Name; break }
            'AzureAD'          { $aad   += $u.Name; break }
            'Local'            { $local += $u.Name; break }
            default            { $other += "$($u.Name) ($src)" }
        }
    }
    return [pscustomobject]@{
        local_accounts = $local
        msa_accounts   = $msa
        aad_accounts   = $aad
        other          = $other
    }
}

# IA-11 / IA-5 (complexity): export local security policy via `secedit /export`.
# secedit /export to a temp file works as standard user for the local DB on
# Win10/11 client SKUs in most configurations; if it fails we surface SKIP.
function Get-SargeIaSeceditExport {
    [CmdletBinding()] param()
    $tmp = Join-Path $env:TEMP ("sarge-secedit-" + (Get-Random) + ".inf")
    try {
        & secedit.exe /export /cfg $tmp /areas SECURITYPOLICY 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $tmp)) {
            throw "secedit /export exited $LASTEXITCODE (often requires elevated session)"
        }
        $lines = Get-Content -LiteralPath $tmp -ErrorAction Stop
        $complexity = $null
        $reversibleEncryption = $null
        foreach ($l in $lines) {
            if ($l -match '^\s*PasswordComplexity\s*=\s*(\d+)') { $complexity = [int]$Matches[1] }
            elseif ($l -match '^\s*ClearTextPassword\s*=\s*(\d+)') { $reversibleEncryption = [int]$Matches[1] }
        }
        return [pscustomobject]@{
            password_complexity        = $complexity            # 1 = required
            reversible_encryption_off  = ($reversibleEncryption -eq 0)
        }
    } finally {
        Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue
    }
}
