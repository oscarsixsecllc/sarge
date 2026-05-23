# tests/Pester/windows-ia.Tests.ps1 - Identification & Authentication tests.

BeforeAll {
    $repoRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
    . "$repoRoot\lib\probes\windows-ia.ps1"
}

Describe 'Get-SargeIaAccountTypes' {
    It 'classifies MSA / AzureAD / Local' {
        Mock Get-LocalUser {
            @(
                [pscustomobject]@{ Name='Loc'; Enabled=$true;  PrincipalSource='Local' },
                [pscustomobject]@{ Name='MSA'; Enabled=$true;  PrincipalSource='MicrosoftAccount' },
                [pscustomobject]@{ Name='Aad'; Enabled=$true;  PrincipalSource='AzureAD' },
                [pscustomobject]@{ Name='Off'; Enabled=$false; PrincipalSource='Local' }
            )
        }
        $r = Get-SargeIaAccountTypes
        $r.local_accounts | Should -Contain 'Loc'
        $r.msa_accounts   | Should -Contain 'MSA'
        $r.aad_accounts   | Should -Contain 'Aad'
        $r.local_accounts | Should -Not -Contain 'Off'   # disabled, skipped
    }
}

Describe 'Get-SargeIaPasswordPolicy parsing' {
    It 'parses minimum length and history' {
        $sample = @(
            'Minimum password length:                              14',
            'Length of password history maintained:                5'
        )
        $minLen=$null; $hist=$null
        foreach ($l in $sample) {
            if ($l -match '(?i)Minimum\s+password\s+length[^\d]+(\d+)')         { $minLen = [int]$Matches[1] }
            elseif ($l -match '(?i)Length\s+of\s+password\s+history[^\d]+(\d+|None)') {
                $hist = if ($Matches[1] -ieq 'None') { 0 } else { [int]$Matches[1] }
            }
        }
        $minLen | Should -Be 14
        $hist   | Should -Be 5
    }
}

Describe 'Get-SargeIaDeviceIdentity' {
    It 'returns nulls when neither cmdlet is available' {
        Mock Get-Command { $null }
        $r = Get-SargeIaDeviceIdentity
        $r.tpm_present | Should -Be $null
        $r.secure_boot | Should -Be $null
    }
}

Describe 'Get-SargeIaWindowsHello' {
    It 'returns booleans for policy and ngc directory checks' {
        Mock Test-Path { $false }
        $r = Get-SargeIaWindowsHello
        $r.policy_present  | Should -Be $false
        $r.ngc_dir_present | Should -Be $false
    }
}
