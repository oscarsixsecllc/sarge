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

Describe 'Get-SargeSiUpdateReporting' {
    It 'returns nulls when neither WSUS nor Defender preference are set' {
        Mock Test-Path { $false }
        Mock Get-MpPreference { [pscustomobject]@{} }
        $r = Get-SargeSiUpdateReporting
        $r.wsus_status_server     | Should -Be $null
        $r.submit_samples_consent | Should -Be $null
    }
}

Describe 'Get-SargeSiMailRole' {
    It 'reports no mail role when no relevant services present' {
        Mock Get-CimInstance { $null }
        $r = Get-SargeSiMailRole
        $r.mail_role_detected            | Should -Be $false
        $r.mail_role_services_present.Count | Should -Be 0
    }
}

Describe 'Get-SargeSiMemoryProtection' {
    It 'throws when Get-ProcessMitigation is unavailable' {
        Mock Get-Command { $null } -ParameterFilter { $Name -eq 'Get-ProcessMitigation' }
        { Get-SargeSiMemoryProtection } | Should -Throw
    }
}
