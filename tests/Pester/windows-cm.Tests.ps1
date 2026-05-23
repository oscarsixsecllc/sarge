# tests/Pester/windows-cm.Tests.ps1 - Configuration Management probe tests.

BeforeAll {
    $repoRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
    . "$repoRoot\lib\probes\windows-cm.ps1"
}

Describe 'Get-SargeCmSmbV1State' {
    It 'reports smb1_enabled=false when disabled' {
        Mock Get-SmbServerConfiguration { [pscustomobject]@{ EnableSMB1Protocol = $false } }
        $r = Get-SargeCmSmbV1State
        $r.smb1_enabled | Should -Be $false
    }
    It 'reports smb1_enabled=true when enabled' {
        Mock Get-SmbServerConfiguration { [pscustomobject]@{ EnableSMB1Protocol = $true } }
        $r = Get-SargeCmSmbV1State
        $r.smb1_enabled | Should -Be $true
    }
}

Describe 'Get-SargeCmLegacyServices' {
    It 'flags running services among the watch list' {
        Mock Get-CimInstance {
            param($ClassName, $Filter)
            if ($Filter -like "*Telnet*") { return [pscustomobject]@{ State='Running' } }
            $null
        }
        $r = Get-SargeCmLegacyServices
        $r.running | Should -Contain 'Telnet'
    }
}

Describe 'Get-SargeCmBaselineSnapshot' {
    It 'returns a snapshot with running services' {
        Mock Get-CimInstance {
            @(
                [pscustomobject]@{ Name='Spooler';   State='Running' }
                [pscustomobject]@{ Name='WinDefend'; State='Running' }
                [pscustomobject]@{ Name='Disabled';  State='Stopped' }
            )
        }
        Mock Get-ScheduledTask { @() }
        Mock Test-Path { $false }
        $r = Get-SargeCmBaselineSnapshot
        $r.services_running | Should -Contain 'Spooler'
        $r.services_running | Should -Not -Contain 'Disabled'
    }
}

Describe 'Get-SargeCmUserInstalledSoftware' {
    It 'returns zero when no AppX/HKCU entries' {
        Mock Get-AppxPackage { @() }
        Mock Get-ItemProperty { throw 'no hkcu' }
        $r = Get-SargeCmUserInstalledSoftware
        $r.appx_count           | Should -Be 0
        $r.hkcu_installed_count | Should -Be 0
    }
}
