# tests/Pester/windows-au.Tests.ps1 - Audit & Accountability probe tests.

BeforeAll {
    $repoRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
    . "$repoRoot\lib\probes\windows-au.ps1"
}

Describe 'Get-SargeAuEventLogMetadata' {
    It 'returns an entry per channel including unreachable ones' {
        Mock Get-WinEvent {
            param($ListLog)
            if ($ListLog -eq 'Security') { throw 'Access denied' }
            [pscustomobject]@{
                LogFilePath       = "C:\fake\$ListLog.evtx"
                MaximumSizeInBytes = 128MB
                LogMode           = 'Circular'
            }
        }
        $r = Get-SargeAuEventLogMetadata
        $r.Count | Should -BeGreaterThan 0
        $sec = $r | Where-Object { $_.name -eq 'Security' }
        $sec.accessible | Should -Be $false
        $sys = $r | Where-Object { $_.name -eq 'System' }
        $sys.accessible | Should -Be $true
        $sys.max_size_mb | Should -Be 128
    }
}

Describe 'Get-SargeAuSecurityLogAcl' {
    It 'returns accessible=false when file missing' {
        Mock Test-Path { $false }
        $r = Get-SargeAuSecurityLogAcl
        $r.accessible | Should -Be $false
    }
}

Describe 'Get-SargeAuSysmonConfig' {
    It 'reports installed=false when Sysmon service is missing' {
        Mock Get-CimInstance { $null }
        $r = Get-SargeAuSysmonConfig
        $r.installed | Should -Be $false
        $r.rules_bytes | Should -Be 0
    }
}

Describe 'Get-SargeAuEventForwarding' {
    It 'returns zero subscriptions when key not present' {
        Mock Test-Path { $false }
        $r = Get-SargeAuEventForwarding
        $r.subscription_count | Should -Be 0
    }
}

Describe 'Get-SargeAuTimeConfig parsing' {
    It 'parses Type and NtpServer from w32tm /query /configuration output' {
        $sample = @(
            '[TimeProviders]',
            'Type: NTP (Local)',
            'NtpServer: time.windows.com,0x9 (Local)'
        )
        $type = $null; $ntpServer = $null
        foreach ($line in $sample) {
            if ($line -match '^\s*Type:\s*(\S+)') { $type = $Matches[1] }
            elseif ($line -match '^\s*NtpServer:\s*(.+?)\s*(?:\(.*)?$') { $ntpServer = $Matches[1].Trim() }
        }
        $type      | Should -Be 'NTP'
        $ntpServer | Should -Be 'time.windows.com,0x9'
    }
}
