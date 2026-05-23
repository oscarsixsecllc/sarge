# scripts/rollback-windows.ps1 - Reapply a Sarge pre-hardening backup.
#
# Standalone runner. Consumes the artifacts produced by
# `scripts/backup-windows.ps1` and reverses each captured surface:
#   - reg import <each>.reg
#   - secedit /configure /db secedit.sdb /cfg secpol.cfg
#   - auditpol /restore /file:audit-policy.csv
#   - Set-Service -Name X -StartupType Y from services.json
#   - Register-ScheduledTask -Xml from tasks\<slug>.xml (if missing)
#
# Idempotent: re-running with state already matching the snapshot performs
# no net change. Safe to run multiple times.
#
# Usage:
#   pwsh -ExecutionPolicy Bypass -File scripts\rollback-windows.ps1 `
#        -BackupDir "C:\Users\<u>\.sarge\runs\<id>\backup"
#
# Exit codes:
#   0   success
#   1   backup directory missing or unreadable
#   2   one or more restore steps failed (details on stderr)

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $BackupDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-SargeLog {
    param([string]$Message)
    Write-Output "[SARGE-ROLLBACK] $Message"
}

if (-not (Test-Path -LiteralPath $BackupDir)) {
    Write-Error "BackupDir not found: $BackupDir"
    exit 1
}

$failures = 0
Write-SargeLog "applying backup from $BackupDir"

# 1) Registry imports.
$regDir = Join-Path $BackupDir 'registry'
if (Test-Path -LiteralPath $regDir) {
    foreach ($f in Get-ChildItem -LiteralPath $regDir -Filter '*.reg' -ErrorAction SilentlyContinue) {
        Write-SargeLog "reg import $($f.Name)"
        try {
            $proc = Start-Process -FilePath 'reg.exe' `
                -ArgumentList @('import', $f.FullName) `
                -NoNewWindow -PassThru -Wait
            if ($proc.ExitCode -ne 0) {
                Write-Warning "reg import non-zero exit ($($proc.ExitCode)) for $($f.Name) - likely needs elevation"
                $failures++
            }
        } catch {
            Write-Warning "reg import threw for $($f.Name): $($_.Exception.Message)"
            $failures++
        }
    }
}

# 2) secedit /configure
$secpol = Join-Path $BackupDir 'secpol.cfg'
if (Test-Path -LiteralPath $secpol) {
    Write-SargeLog "secedit /configure (from secpol.cfg)"
    try {
        $db = Join-Path $BackupDir 'secedit.sdb'
        $proc = Start-Process -FilePath 'secedit.exe' `
            -ArgumentList @('/configure', '/db', $db, '/cfg', $secpol, '/quiet') `
            -NoNewWindow -PassThru -Wait
        if ($proc.ExitCode -ne 0) {
            Write-Warning "secedit non-zero exit: $($proc.ExitCode) (likely needs elevation)"
            $failures++
        }
    } catch {
        Write-Warning "secedit threw: $($_.Exception.Message)"
        $failures++
    }
}

# 3) auditpol /restore
$ap = Join-Path $BackupDir 'audit-policy.csv'
if (Test-Path -LiteralPath $ap) {
    Write-SargeLog "auditpol /restore (from audit-policy.csv)"
    try {
        $proc = Start-Process -FilePath 'auditpol.exe' `
            -ArgumentList @('/restore', "/file:$ap") `
            -NoNewWindow -PassThru -Wait
        if ($proc.ExitCode -ne 0) {
            Write-Warning "auditpol non-zero exit: $($proc.ExitCode) (likely needs elevation)"
            $failures++
        }
    } catch {
        Write-Warning "auditpol threw: $($_.Exception.Message)"
        $failures++
    }
}

# 4) services.json - reset StartType only when divergent (idempotent).
$svcFile = Join-Path $BackupDir 'services.json'
if (Test-Path -LiteralPath $svcFile) {
    Write-SargeLog "reconciling service StartType from services.json"
    try {
        $snap = Get-Content -Raw -LiteralPath $svcFile | ConvertFrom-Json
        foreach ($s in $snap) {
            if ([string]::IsNullOrWhiteSpace($s.Name)) { continue }
            $current = Get-Service -Name $s.Name -ErrorAction SilentlyContinue
            if ($null -eq $current) { continue }
            $target = switch ($s.StartType) {
                'Auto'     { 'Automatic' }
                'Manual'   { 'Manual' }
                'Disabled' { 'Disabled' }
                default     { $null }
            }
            if ($null -eq $target) { continue }
            if ($current.StartType.ToString() -ieq $target) { continue }
            try {
                Set-Service -Name $s.Name -StartupType $target -ErrorAction Stop
                Write-SargeLog "  $($s.Name): -> $target"
            } catch {
                Write-Warning "  $($s.Name): could not set $target : $($_.Exception.Message)"
                $failures++
            }
        }
    } catch {
        Write-Warning "services.json processing threw: $($_.Exception.Message)"
        $failures++
    }
}

# 5) Scheduled tasks - re-register only if absent (idempotent).
$taskDir = Join-Path $BackupDir 'tasks'
if (Test-Path -LiteralPath $taskDir) {
    foreach ($xml in Get-ChildItem -LiteralPath $taskDir -Filter '*.xml' -ErrorAction SilentlyContinue) {
        $name = [System.IO.Path]::GetFileNameWithoutExtension($xml.Name)
        $existing = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
        if ($null -ne $existing) { continue }
        Write-SargeLog "re-registering task $name"
        try {
            $body = Get-Content -Raw -LiteralPath $xml.FullName
            Register-ScheduledTask -Xml $body -TaskName $name -Force | Out-Null
        } catch {
            Write-Warning "could not re-register $name : $($_.Exception.Message)"
            $failures++
        }
    }
}

if ($failures -gt 0) {
    Write-SargeLog "completed with $failures failure(s)"
    exit 2
}
Write-SargeLog "complete (no errors)"
exit 0
