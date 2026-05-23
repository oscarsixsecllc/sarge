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

Describe 'Get-SargeScUacConfig' {
    It 'reads UAC values when present' {
        Mock Get-ItemProperty {
            [pscustomobject]@{
                EnableLUA = 1
                ConsentPromptBehaviorAdmin = 5
                ConsentPromptBehaviorUser = 1
            }
        }
        $r = Get-SargeScUacConfig
        $r.enable_lua                    | Should -Be 1
        $r.consent_prompt_behavior_admin | Should -Be 5
    }
    It 'returns nulls when key absent' {
        Mock Get-ItemProperty { throw 'absent' }
        $r = Get-SargeScUacConfig
        $r.enable_lua | Should -Be $null
    }
}

Describe 'Get-SargeScKeyManagement' {
    It 'returns RunAsPPL value when present' {
        Mock Get-ItemProperty { [pscustomobject]@{ RunAsPPL = 1 } }
        Mock Get-CimInstance { $null }
        $r = Get-SargeScKeyManagement
        $r.run_as_ppl | Should -Be 1
    }
}

Describe 'Get-SargeScBitLockerPolicy' {
    It 'returns null encryption_method when BitLocker not available' {
        Mock Get-Command { $null }
        Mock Test-Path { $false }
        $r = Get-SargeScBitLockerPolicy
        $r.encryption_method  | Should -Be $null
        $r.escrow_configured  | Should -Be $false
    }
}

Describe 'Get-SargeScSessionAuthenticity' {
    It 'returns nulls when keys absent' {
        Mock Test-Path { $false }
        Mock Get-ItemProperty { throw 'absent' }
        $r = Get-SargeScSessionAuthenticity
        $r.ldap_server_integrity  | Should -Be $null
        $r.ntlm_restrict_sending  | Should -Be $null
    }
    It 'reads LDAP and NTLM values when present' {
        Mock Test-Path { $true }
        Mock Get-ItemProperty {
            param($LiteralPath)
            if ($LiteralPath -match 'NTDS') {
                [pscustomobject]@{ LDAPServerIntegrity = 2 }
            } else {
                [pscustomobject]@{ RestrictSendingNTLMTraffic = 2; RestrictReceivingNTLMTraffic = 2 }
            }
        }
        $r = Get-SargeScSessionAuthenticity
        $r.ldap_server_integrity   | Should -Be 2
        $r.ntlm_restrict_sending   | Should -Be 2
        $r.ntlm_restrict_incoming  | Should -Be 2
    }
}
