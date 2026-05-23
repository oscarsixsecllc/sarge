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
