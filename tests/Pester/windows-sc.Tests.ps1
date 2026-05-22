# tests/Pester/windows-sc.Tests.ps1 - System & Communications Protection.

BeforeAll {
    $repoRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
    . "$repoRoot\lib\probes\windows-sc.ps1"
}

Describe 'Get-SargeScFirewallProfiles' {
    It 'maps each profile object to the schema' {
        Mock Get-NetFirewallProfile {
            @(
                [pscustomobject]@{ Name='Domain';  Enabled=$true;  DefaultInboundAction='Block'; DefaultOutboundAction='Allow' },
                [pscustomobject]@{ Name='Public';  Enabled=$false; DefaultInboundAction='Block'; DefaultOutboundAction='Allow' }
            )
        }
        $r = Get-SargeScFirewallProfiles
        ($r | Where-Object { $_.name -eq 'Public' }).enabled | Should -Be $false
        ($r | Where-Object { $_.name -eq 'Domain' }).enabled | Should -Be $true
    }
}

Describe 'Get-SargeScListeningPorts' {
    It 'filters to externally-bound listeners' {
        Mock Get-NetTCPConnection {
            @(
                [pscustomobject]@{ LocalAddress='0.0.0.0';  LocalPort=22;   OwningProcess=10 },
                [pscustomobject]@{ LocalAddress='127.0.0.1'; LocalPort=8080; OwningProcess=20 },
                [pscustomobject]@{ LocalAddress='::';        LocalPort=443;  OwningProcess=30 }
            )
        }
        $r = Get-SargeScListeningPorts
        $r.externally_listening.Count | Should -Be 2
        ($r.externally_listening | ForEach-Object { $_.port }) | Should -Contain 22
        ($r.externally_listening | ForEach-Object { $_.port }) | Should -Not -Contain 8080
    }
}
