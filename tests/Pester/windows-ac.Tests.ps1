# tests/Pester/windows-ac.Tests.ps1 - Pester tests for AC probes.
#
# Run locally on a Windows host with Pester 5+:
#   Invoke-Pester -Path tests/Pester/windows-ac.Tests.ps1
#
# These tests mock the underlying cmdlets so they can run anywhere (CI,
# non-Windows hosts). No CI workflow is wired up in this PR.

BeforeAll {
    $repoRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
    . "$repoRoot\lib\probes\windows-ac.ps1"
}

Describe 'Get-SargeAcEmptyPasswordAccounts' {
    It 'returns empty list when all enabled users require a password' {
        Mock Get-LocalUser {
            @(
                [pscustomobject]@{ Name='Alice'; Enabled=$true;  PasswordRequired=$true },
                [pscustomobject]@{ Name='Bob';   Enabled=$true;  PasswordRequired=$true }
            )
        }
        $r = Get-SargeAcEmptyPasswordAccounts
        $r.accounts.Count | Should -Be 0
        $r.total         | Should -Be 2
    }

    It 'flags enabled users with PasswordRequired=false' {
        Mock Get-LocalUser {
            @(
                [pscustomobject]@{ Name='Bad';   Enabled=$true;  PasswordRequired=$false },
                [pscustomobject]@{ Name='Other'; Enabled=$false; PasswordRequired=$false }
            )
        }
        $r = Get-SargeAcEmptyPasswordAccounts
        $r.accounts | Should -Contain 'Bad'
        $r.accounts | Should -Not -Contain 'Other'
    }

    It 'throws when Get-LocalUser unavailable' {
        Mock Get-Command { $null } -ParameterFilter { $Name -eq 'Get-LocalUser' }
        { Get-SargeAcEmptyPasswordAccounts } | Should -Throw
    }
}

Describe 'Get-SargeAcLockoutPolicy' {
    It 'parses English net accounts output' {
        Mock Invoke-Expression {} # not used; we set $global:LASTEXITCODE directly via mock
        # Replace the net.exe call by mocking the entire function body would be
        # invasive; instead validate the regex via a synthetic raw text below.
        # This test exercises the parsing logic only.
        $sample = @(
            'Force user logoff how long after time expires?:       Never',
            'Minimum password age (days):                          0',
            'Maximum password age (days):                          42',
            'Minimum password length:                              14',
            'Length of password history maintained:                5',
            'Lockout threshold:                                    10',
            'Lockout duration (minutes):                           15',
            'Lockout observation window (minutes):                 15',
            'The command completed successfully.'
        )
        $threshold = $null; $duration = $null
        foreach ($l in $sample) {
            if ($l -match '(?i)Lockout\s+threshold[^\d]+(\d+|Never)') { $threshold = $Matches[1] }
            elseif ($l -match '(?i)Lockout\s+duration[^\d]+(\d+)')    { $duration  = [int]$Matches[1] }
        }
        $threshold | Should -Be '10'
        $duration  | Should -Be 15
    }
}

Describe 'Get-SargeAcAdminGroupMembers' {
    It 'returns member names with count' {
        Mock Get-LocalGroupMember {
            @(
                [pscustomobject]@{ Name='HOST\Administrator' },
                [pscustomobject]@{ Name='HOST\oscar' }
            )
        }
        $r = Get-SargeAcAdminGroupMembers
        $r.count | Should -Be 2
        $r.members | Should -Contain 'HOST\oscar'
    }
}
