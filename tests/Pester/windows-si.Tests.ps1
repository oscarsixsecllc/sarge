# tests/Pester/windows-si.Tests.ps1 - System & Information Integrity tests.

BeforeAll {
    $repoRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
    . "$repoRoot\lib\probes\windows-si.ps1"
}

Describe 'Get-SargeSiDefenderStatus' {
    It 'maps RealTimeProtectionEnabled etc into the schema' {
        Mock Get-MpComputerStatus {
            [pscustomobject]@{
                RealTimeProtectionEnabled = $true
                AntivirusEnabled          = $true
                AntispywareEnabled        = $true
                IsTamperProtected         = $true
                AntivirusSignatureAge     = 0
                AMEngineVersion           = '1.1.0'
            }
        }
        $r = Get-SargeSiDefenderStatus
        $r.realtime_enabled | Should -Be $true
        $r.tamper_protected | Should -Be $true
        $r.engine_version   | Should -Be '1.1.0'
    }
    It 'throws when Get-MpComputerStatus missing' {
        Mock Get-Command { $null } -ParameterFilter { $Name -eq 'Get-MpComputerStatus' }
        { Get-SargeSiDefenderStatus } | Should -Throw
    }
}

Describe 'Get-SargeSiWdacPolicyPresence' {
    It 'reports count=0 when policy dirs absent' {
        Mock Test-Path { $false }
        $r = Get-SargeSiWdacPolicyPresence
        $r.count | Should -Be 0
    }
}
