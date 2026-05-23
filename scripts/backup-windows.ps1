# scripts/backup-windows.ps1 - Pre-hardening backup + rollback artifact emitter.
#
# Invoked by Phase 2 hardening (`scripts/harden-*.ps1`) BEFORE any change is
# applied. Captures a System Restore checkpoint and snapshots the mutable
# Windows surfaces Phase 2 may touch (registry policy hives, local security
# policy, audit policy, service start types, scheduled tasks), then emits a
# dynamically-generated `rollback.ps1` next to the snapshot that reverses
# whatever was captured.
#
# This script is read-mostly: it modifies only files under
# %USERPROFILE%\.sarge\runs\<run_id>\backup\ and creates one System Restore
# point. It does NOT apply any hardening.
#
# Usage:
#   pwsh -ExecutionPolicy Bypass -File scripts\backup-windows.ps1 [options]
#
# Options:
#   --run-id <id>            Use the provided run ID (typically passed by
#                            assess.ps1 / harden-*.ps1). Defaults to a fresh
#                            yyyyMMdd-HHmmss timestamp.
#   --unattended             Skip the interactive Y/N prompt; proceed as if Y.
#   --skip-restore-point     Skip the Checkpoint-Computer call. Snapshot
#                            artifacts are still produced.
#   --help, -h               Show usage and exit.
#
# Exit codes:
#   0   success (snapshot complete)
#   1   user declined the backup at the prompt
#   2   System Protection disabled on %SystemDrive% (FAIL-LOUD)
#   3   internal error (caller should treat as fatal)
#
# Closes: #28

[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $RemainingArgs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Arg parsing ---------------------------------------------------------
$ShowHelp           = $false
$Unattended         = $false
$SkipRestorePoint   = $false
$RunId              = $null

$i = 0
$argList = @($RemainingArgs)
while ($i -lt $argList.Count) {
    $arg = $argList[$i]
    if ([string]::IsNullOrWhiteSpace($arg)) { $i++; continue }
    switch ($arg) {
        '--help'              { $ShowHelp = $true }
        '-h'                  { $ShowHelp = $true }
        '--unattended'        { $Unattended = $true }
        '--skip-restore-point'{ $SkipRestorePoint = $true }
        '--run-id'            {
            if ($i + 1 -ge $argList.Count) {
                Write-Error "--run-id requires a value"
                exit 3
            }
            $RunId = $argList[$i + 1]
            $i++
        }
        default {
            Write-Warning "Unknown argument ignored: $arg"
        }
    }
    $i++
}

if ($ShowHelp) {
    @"
Sarge - Pre-hardening backup + rollback (Windows)

USAGE
    pwsh -ExecutionPolicy Bypass -File scripts\backup-windows.ps1 [options]

OPTIONS
    --run-id <id>          Use this run ID (default: yyyyMMdd-HHmmss).
    --unattended           Skip interactive prompt (proceed).
    --skip-restore-point   Skip Checkpoint-Computer; still produce snapshots.
    --help, -h             Show this help.

EXIT CODES
    0  success    1  user declined    2  System Protection off (fail-loud)
    3  internal error

See README.md "Pre-hardening backup + rollback (Windows)" for details.
"@ | Write-Output
    exit 0
}

if ([string]::IsNullOrWhiteSpace($RunId)) {
    $RunId = (Get-Date).ToString('yyyyMMdd-HHmmss')
}

# --- Tracked registry keys -----------------------------------------------
# Hardcoded list of registry hives Phase 2 hardening may touch. Derived from
# the WIN-AC-*, WIN-AU-*, WIN-CM-* FAIL emissions in assessment/checks/.
# We export these regardless of whether Phase 2 ends up touching every one,
# so the rollback covers the superset.
#
# NOTE: Extend this list as new harden-*.ps1 modules land.
$script:TrackedRegistryKeys = @(
    # AC family (lockout, idle lock, screensaver policy)
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization',
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
    'HKCU\Control Panel\Desktop',
    # AU family (audit policy registry surface, event log channel config)
    'HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security',
    'HKLM\SYSTEM\CurrentControlSet\Services\EventLog\System',
    'HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application',
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Audit',
    # CM family (SMBv1, services policy, legacy protocol policy)
    'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',
    'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters',
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate',
    # SC family (SMB signing, LM compat, NTLM)
    'HKLM\SYSTEM\CurrentControlSet\Control\Lsa',
    # IA family (logon, Negotiate)
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI'
)

# --- Helpers -------------------------------------------------------------
function Write-SargeLog {
    param([string]$Message)
    Write-Output "[SARGE-BACKUP] $Message"
}

function Test-SargeSystemProtection {
    # Returns $true if System Protection appears enabled on the system drive.
    #
    # `Get-ComputerRestorePoint` is unreliable as a sole signal: on hosts
    # where SR is fully disabled, the cmdlet returns an empty list rather
    # than throwing. We use the WMI SystemRestoreConfig class as the
    # authoritative source - RPSessionInterval == 0 means SR is off.
    # If WMI is unavailable we fall back to attempting Get-ComputerRestorePoint
    # (and default to enabled if it doesn't throw).
    try {
        $cfg = Get-CimInstance -Namespace 'root\default' -ClassName 'SystemRestoreConfig' -ErrorAction Stop
        if ($null -ne $cfg) {
            $interval = $cfg.RPSessionInterval
            if ($null -ne $interval -and $interval -gt 0) { return $true }
            return $false
        }
    } catch {
        # WMI surface missing - fall through.
    }
    try {
        $null = Get-ComputerRestorePoint -ErrorAction Stop
        # Without WMI we can't disambiguate "empty list because disabled"
        # vs "empty list because no checkpoints yet"; default to enabled.
        return $true
    } catch {
        return $false
    }
}

function Get-SargeBackupConsent {
    # Default-Y prompt. Returns $true to proceed, $false to abort.
    Write-Host ""
    Write-Host "Sarge: about to capture a pre-hardening backup."
    Write-Host "  - System Restore checkpoint (unless --skip-restore-point)"
    Write-Host "  - Registry policy hives, secedit, auditpol, services, tasks"
    Write-Host ""
    $resp = Read-Host "Create restore point + config snapshot? [Y/n]"
    if ([string]::IsNullOrWhiteSpace($resp)) { return $true }
    return ($resp.Trim() -match '^[Yy]')
}

function Export-SargeRegistryKey {
    param(
        [Parameter(Mandatory)] [string] $Key,
        [Parameter(Mandatory)] [string] $OutDir
    )
    # Convert HKLM\Foo\Bar to a filesystem-safe slug.
    $slug = ($Key -replace '[\\:]', '_')
    $outFile = Join-Path $OutDir ("$slug.reg")
    # `reg export` exits non-zero if the key does not exist; we treat that
    # as "nothing to back up" and skip silently. The rollback generator
    # only references files that actually got written.
    $proc = Start-Process -FilePath 'reg.exe' `
        -ArgumentList @('export', $Key, $outFile, '/y') `
        -NoNewWindow -PassThru -Wait `
        -RedirectStandardOutput ([System.IO.Path]::GetTempFileName()) `
        -RedirectStandardError  ([System.IO.Path]::GetTempFileName())
    if ($proc.ExitCode -eq 0 -and (Test-Path -LiteralPath $outFile)) {
        return [pscustomobject]@{ key = $Key; file = $outFile; ok = $true }
    } else {
        return [pscustomobject]@{ key = $Key; file = $null; ok = $false }
    }
}

function Export-SargeSecPol {
    param([Parameter(Mandatory)] [string] $OutFile)
    $proc = Start-Process -FilePath 'secedit.exe' `
        -ArgumentList @('/export', '/cfg', $OutFile, '/quiet') `
        -NoNewWindow -PassThru -Wait
    return ($proc.ExitCode -eq 0 -and (Test-Path -LiteralPath $OutFile))
}

function Export-SargeAuditPol {
    param([Parameter(Mandatory)] [string] $OutFile)
    $proc = Start-Process -FilePath 'auditpol.exe' `
        -ArgumentList @('/backup', "/file:$OutFile") `
        -NoNewWindow -PassThru -Wait
    return ($proc.ExitCode -eq 0 -and (Test-Path -LiteralPath $OutFile))
}

function Export-SargeServices {
    param([Parameter(Mandatory)] [string] $OutFile)
    # Capture all services with Name / Status / StartType. Rollback only
    # touches services where current StartType diverges from the snapshot.
    $allServices = Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue
    if ($null -eq $allServices) {
        $allServices = Get-Service | ForEach-Object {
            [pscustomobject]@{
                Name      = $_.Name
                State     = $_.Status.ToString()
                StartMode = $_.StartType.ToString()
                PathName  = ''
            }
        }
    }
    $snap = $allServices | ForEach-Object {
        $path = if ($_.PSObject.Properties['PathName']) { [string]$_.PathName } else { '' }
        [pscustomobject]@{
            Name      = $_.Name
            Status    = if ($_.PSObject.Properties['State']) { $_.State } else { '' }
            StartType = if ($_.PSObject.Properties['StartMode']) { $_.StartMode } else { '' }
            PathName  = $path
        }
    }
    $snap | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $OutFile -Encoding UTF8
    return (Test-Path -LiteralPath $OutFile)
}

function Export-SargeScheduledTasks {
    param([Parameter(Mandatory)] [string] $OutDir)
    # We export tasks under non-Microsoft paths. Each task gets its own
    # <slug>.xml so rollback can re-register them individually.
    $taskDir = Join-Path $OutDir 'tasks'
    if (-not (Test-Path -LiteralPath $taskDir)) {
        New-Item -ItemType Directory -Path $taskDir -Force | Out-Null
    }
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.TaskPath -and ($_.TaskPath -notlike '\Microsoft\*') -and ($_.TaskPath -ne '\Microsoft\') }
    if ($null -eq $tasks) { return @() }
    $manifest = New-Object System.Collections.Generic.List[object]
    foreach ($t in $tasks) {
        $slug = (($t.TaskPath + $t.TaskName) -replace '[\\/:*?"<>|]', '_').TrimStart('_')
        $file = Join-Path $taskDir ("$slug.xml")
        try {
            $xml = Export-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop
            Set-Content -LiteralPath $file -Value $xml -Encoding UTF8
            # File names are filename-safe slugs and lose the TaskPath/TaskName
            # distinction. Rollback needs both — task names are NOT unique across
            # TaskPath directories — so persist the manifest as JSON next to the
            # XMLs. Rollback consumes this file (see scripts/rollback-windows.ps1).
            $manifest.Add([pscustomobject]@{ taskPath = $t.TaskPath; taskName = $t.TaskName; file = $file })
        } catch {
            Write-SargeLog "WARN: could not export task $($t.TaskPath)$($t.TaskName): $($_.Exception.Message)"
        }
    }
    $manifestFile = Join-Path $taskDir 'manifest.json'
    $manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifestFile -Encoding UTF8
    return $manifest
}

function New-SargeRollbackScript {
    param(
        [Parameter(Mandatory)] [string] $BackupDir,
        [Parameter(Mandatory)] [hashtable] $Captured
    )
    # Generate a self-contained rollback.ps1 referencing the artifacts we
    # actually captured. The script is also re-runnable directly via
    # scripts/rollback-windows.ps1 - this is a convenience emitted next to
    # the backup so operators can locate it without remembering the path
    # to the standalone runner.
    $rollback = Join-Path $BackupDir 'rollback.ps1'
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('# Auto-generated by scripts/backup-windows.ps1 - DO NOT EDIT.')
    $lines.Add('# Reapplies the snapshot in this directory. Idempotent.')
    $lines.Add('# Run from an elevated PowerShell:')
    $lines.Add('#   pwsh -ExecutionPolicy Bypass -File rollback.ps1')
    $lines.Add('Set-StrictMode -Version Latest')
    $lines.Add('$ErrorActionPreference = ''Stop''')
    $lines.Add('$here = Split-Path -Parent $MyInvocation.MyCommand.Path')
    $lines.Add('Write-Output "[SARGE-ROLLBACK] applying snapshot at $here"')

    if ($Captured.ContainsKey('registry')) {
        foreach ($reg in $Captured['registry']) {
            if (-not $reg.ok) { continue }
            $relName = [System.IO.Path]::GetFileName($reg.file)
            $lines.Add(('$regFile = Join-Path $here "registry\' + $relName + '"'))
            $lines.Add('if (Test-Path -LiteralPath $regFile) {')
            $lines.Add('    Write-Output "[SARGE-ROLLBACK] reg import $regFile"')
            $lines.Add('    & reg.exe import $regFile | Out-Null')
            $lines.Add('}')
        }
    }

    if ($Captured.ContainsKey('secpol') -and $Captured['secpol']) {
        $lines.Add('$secpol = Join-Path $here "secpol.cfg"')
        $lines.Add('if (Test-Path -LiteralPath $secpol) {')
        $lines.Add('    $db = Join-Path $here "secedit.sdb"')
        $lines.Add('    Write-Output "[SARGE-ROLLBACK] secedit /configure"')
        $lines.Add('    & secedit.exe /configure /db $db /cfg $secpol /quiet | Out-Null')
        $lines.Add('}')
    }

    if ($Captured.ContainsKey('auditpol') -and $Captured['auditpol']) {
        $lines.Add('$ap = Join-Path $here "audit-policy.csv"')
        $lines.Add('if (Test-Path -LiteralPath $ap) {')
        $lines.Add('    Write-Output "[SARGE-ROLLBACK] auditpol /restore"')
        $lines.Add('    & auditpol.exe /restore /file:$ap | Out-Null')
        $lines.Add('}')
    }

    if ($Captured.ContainsKey('services') -and $Captured['services']) {
        $lines.Add('$svcFile = Join-Path $here "services.json"')
        $lines.Add('if (Test-Path -LiteralPath $svcFile) {')
        $lines.Add('    Write-Output "[SARGE-ROLLBACK] re-applying service StartType from snapshot"')
        $lines.Add('    $snap = Get-Content -Raw -LiteralPath $svcFile | ConvertFrom-Json')
        $lines.Add('    foreach ($s in $snap) {')
        $lines.Add('        if ([string]::IsNullOrWhiteSpace($s.Name)) { continue }')
        $lines.Add('        $current = Get-Service -Name $s.Name -ErrorAction SilentlyContinue')
        $lines.Add('        if ($null -eq $current) { continue }')
        $lines.Add('        $target = switch ($s.StartType) {')
        $lines.Add('            ''Auto''     { ''Automatic'' }')
        $lines.Add('            ''Manual''   { ''Manual'' }')
        $lines.Add('            ''Disabled'' { ''Disabled'' }')
        $lines.Add('            default     { $null }')
        $lines.Add('        }')
        $lines.Add('        if ($null -eq $target) { continue }')
        $lines.Add('        if ($current.StartType.ToString() -ieq $target) { continue }')
        $lines.Add('        try { Set-Service -Name $s.Name -StartupType $target -ErrorAction Stop }')
        $lines.Add('        catch { Write-Warning "could not reset $($s.Name) -> $target : $($_.Exception.Message)" }')
        $lines.Add('    }')
        $lines.Add('}')
    }

    if ($Captured.ContainsKey('tasks') -and $Captured['tasks']) {
        $lines.Add('$taskDir = Join-Path $here "tasks"')
        $lines.Add('if (Test-Path -LiteralPath $taskDir) {')
        $lines.Add('    foreach ($xml in Get-ChildItem -LiteralPath $taskDir -Filter *.xml -ErrorAction SilentlyContinue) {')
        $lines.Add('        $name = [System.IO.Path]::GetFileNameWithoutExtension($xml.Name)')
        $lines.Add('        try {')
        $lines.Add('            $existing = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue')
        $lines.Add('            if ($null -ne $existing) { continue }  # idempotent: already registered')
        $lines.Add('            $body = Get-Content -Raw -LiteralPath $xml.FullName')
        $lines.Add('            Register-ScheduledTask -Xml $body -TaskName $name -Force | Out-Null')
        $lines.Add('        } catch { Write-Warning "could not re-register task $name : $($_.Exception.Message)" }')
        $lines.Add('    }')
        $lines.Add('}')
    }

    $lines.Add('Write-Output "[SARGE-ROLLBACK] complete"')
    Set-Content -LiteralPath $rollback -Value ($lines -join "`r`n") -Encoding UTF8
    return $rollback
}

function New-SargeBackupSummary {
    param(
        [Parameter(Mandatory)] [string] $RunRoot,
        [Parameter(Mandatory)] [string] $BackupDir,
        [Parameter(Mandatory)] [hashtable] $Captured,
        [Parameter(Mandatory)] [string]   $RunId,
        [bool] $RestorePointCreated
    )
    $summary = Join-Path $RunRoot 'backup-summary.md'
    $lines = @()
    $lines += "# Sarge pre-hardening backup - $RunId"
    $lines += ""
    $lines += "Captured: $(Get-Date -Format o)"
    $lines += "Host: $env:COMPUTERNAME"
    $lines += "User: $env:USERNAME"
    $lines += "Backup directory: ``$BackupDir``"
    $lines += ""
    $lines += "## Artifacts captured"
    $lines += ""
    if ($RestorePointCreated) {
        $lines += "- System Restore checkpoint: ``Sarge pre-hardening $RunId``"
    } else {
        $lines += "- System Restore checkpoint: SKIPPED (--skip-restore-point or throttled)"
    }
    if ($Captured.ContainsKey('registry')) {
        $ok = @($Captured['registry'] | Where-Object { $_.ok })
        $lines += "- Registry hives exported: $($ok.Count)"
        foreach ($r in $ok) { $lines += "    - ``$($r.key)``" }
    }
    if ($Captured['secpol'])   { $lines += "- Local security policy: ``secpol.cfg``" }
    if ($Captured['auditpol']) { $lines += "- Audit policy: ``audit-policy.csv``" }
    if ($Captured['services']) { $lines += "- Service start types: ``services.json``" }
    if ($Captured.ContainsKey('tasks') -and $Captured['tasks']) {
        $lines += "- Scheduled tasks (non-Microsoft): $($Captured['tasks'].Count)"
    }
    $lines += ""
    $lines += "## How to roll back"
    $lines += ""
    $lines += "From an elevated PowerShell:"
    $lines += ""
    $lines += '```powershell'
    $lines += "pwsh -ExecutionPolicy Bypass -File scripts\rollback-windows.ps1 -BackupDir `"$BackupDir`""
    $lines += '```'
    $lines += ""
    $lines += "Or invoke the generated convenience script directly:"
    $lines += ""
    $lines += '```powershell'
    $lines += "pwsh -ExecutionPolicy Bypass -File `"$BackupDir\rollback.ps1`""
    $lines += '```'
    $lines += ""
    if ($RestorePointCreated) {
        $lines += "If config-level rollback is insufficient, use the System Restore"
        $lines += "checkpoint above via ``rstrui.exe``."
    }
    Set-Content -LiteralPath $summary -Value ($lines -join "`r`n") -Encoding UTF8
    return $summary
}

# --- Main ----------------------------------------------------------------
Write-SargeLog "run_id = $RunId"

if (-not $Unattended) {
    if (-not (Get-SargeBackupConsent)) {
        Write-SargeLog "user declined backup - aborting"
        exit 1
    }
}

# System Protection check - fail loud if disabled and a restore point is wanted.
if (-not $SkipRestorePoint) {
    if (-not (Test-SargeSystemProtection)) {
        $msg = @"
System Protection is disabled on $env:SystemDrive.

Sarge will not proceed with hardening without a restore-point safety net.
Enable System Protection in System Properties -> System Protection ->
Configure -> Turn on, then re-run.

To bypass this check (NOT recommended for production hosts), pass
--skip-restore-point.
"@
        # Write to stderr without triggering -ErrorAction=Stop unwind so the
        # `exit 2` below is actually reached. We want the caller's
        # $LASTEXITCODE to be exactly 2.
        [Console]::Error.WriteLine($msg)
        exit 2
    }
}

# Create per-run folder layout.
$runRoot   = Join-Path $env:USERPROFILE (".sarge\runs\" + $RunId)
$backupDir = Join-Path $runRoot 'backup'
$regDir    = Join-Path $backupDir 'registry'
foreach ($d in @($runRoot, $backupDir, $regDir)) {
    if (-not (Test-Path -LiteralPath $d)) {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
    }
}
Write-SargeLog "backup dir = $backupDir"

$captured = @{}

# 1) Restore point.
$rpCreated = $false
if (-not $SkipRestorePoint) {
    try {
        Write-SargeLog "Checkpoint-Computer (this may take 30-60s)..."
        Checkpoint-Computer -Description "Sarge pre-hardening $RunId" -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop
        $rpCreated = $true
        Write-SargeLog "restore point created"
    } catch {
        # Windows throttles restore points to 1 per 24h by default. Surface
        # as a warning rather than a hard failure - the config snapshot is
        # still valuable.
        Write-Warning "Checkpoint-Computer failed: $($_.Exception.Message)"
        Write-SargeLog "continuing with config snapshot only"
    }
} else {
    Write-SargeLog "--skip-restore-point: not creating checkpoint"
}

# 2) Registry exports.
$regResults = New-Object System.Collections.Generic.List[object]
foreach ($k in $script:TrackedRegistryKeys) {
    $r = Export-SargeRegistryKey -Key $k -OutDir $regDir
    $regResults.Add($r) | Out-Null
    if ($r.ok) {
        Write-SargeLog "  exported $k"
    } else {
        Write-SargeLog "  skipped $k (key absent or unreadable)"
    }
}
$captured['registry'] = $regResults

# 3) secedit export.
$secpolFile = Join-Path $backupDir 'secpol.cfg'
$captured['secpol'] = Export-SargeSecPol -OutFile $secpolFile
if ($captured['secpol']) { Write-SargeLog "  secedit -> secpol.cfg" } else { Write-SargeLog "  secedit FAILED (need elevation?)" }

# 4) auditpol backup.
$auditFile = Join-Path $backupDir 'audit-policy.csv'
$captured['auditpol'] = Export-SargeAuditPol -OutFile $auditFile
if ($captured['auditpol']) { Write-SargeLog "  auditpol -> audit-policy.csv" } else { Write-SargeLog "  auditpol FAILED (need elevation?)" }

# 5) services.json
$svcFile = Join-Path $backupDir 'services.json'
$captured['services'] = Export-SargeServices -OutFile $svcFile
if ($captured['services']) { Write-SargeLog "  services -> services.json" }

# 6) scheduled tasks
$taskManifest = Export-SargeScheduledTasks -OutDir $backupDir
$captured['tasks'] = $taskManifest
Write-SargeLog ("  scheduled tasks -> {0} non-Microsoft task(s)" -f (@($taskManifest)).Count)

# 7) rollback.ps1
$rollbackPath = New-SargeRollbackScript -BackupDir $backupDir -Captured $captured
Write-SargeLog "rollback script: $rollbackPath"

# 8) summary.md (under runRoot so it sits next to other run artifacts).
$summaryPath = New-SargeBackupSummary -RunRoot $runRoot -BackupDir $backupDir `
    -Captured $captured -RunId $RunId -RestorePointCreated $rpCreated
Write-SargeLog "summary: $summaryPath"

Write-SargeLog "DONE."
exit 0
