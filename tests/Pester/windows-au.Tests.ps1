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
