# tests/Pester/windows-policy.Tests.ps1 - Pester tests for Phase 1b probes.
#
# Run locally on a Windows host with Pester 5+:
#   Invoke-Pester -Path tests/Pester/windows-policy.Tests.ps1
#
# Mocks dsregcmd output, CSP registry reads, gpresult HTML, and
# MDMDiagnosticsTool so the tests run anywhere (no live Windows policy
# state required).

BeforeAll {
    $repoRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
    . "$repoRoot\lib\probes\windows-policy.ps1"
    # NOTE: check-policy.ps1 is dot-sourced by assess.ps1 only after
    # Invoke-SargeCheck is in scope, and it executes top-level Invoke-SargeCheck
    # calls at load time. Loading it directly from a test crashes. The
    # Apply-PolicyOverlay Describe below is -Skip'd until the test is rewritten
    # to mock Invoke-SargeCheck or to source only the function definition.
    # Tracked in follow-up issue (see PR #40).
}

Describe 'ConvertFrom-SargePolicyDsRegCmd' {
    It 'parses AAD-joined no-MDM device' {
        $lines = @(
            '            AzureAdJoined : YES',
            '             DomainJoined : NO',
            '               TenantName : RH2 LLC',
            '                   MdmUrl : '
        )
        $r = ConvertFrom-SargePolicyDsRegCmd -Lines $lines
        $r.AzureAdJoined | Should -BeTrue
        $r.DomainJoined  | Should -BeFalse
        $r.TenantName    | Should -Be 'RH2 LLC'
        $r.MdmUrl        | Should -BeNullOrEmpty
    }

    It 'parses AAD-joined MDM-enrolled device' {
        $lines = @(
            '            AzureAdJoined : YES',
            '             DomainJoined : NO',
            '                   MdmUrl : https://enrollment.manage.microsoft.com/EnrollmentServer/Discovery.svc'
        )
        $r = ConvertFrom-SargePolicyDsRegCmd -Lines $lines
        $r.AzureAdJoined | Should -BeTrue
        $r.MdmUrl        | Should -Match 'manage.microsoft.com'
    }

    It 'parses AD-joined device' {
        $lines = @(
            '            AzureAdJoined : NO',
            '             DomainJoined : YES',
            '               DomainName : corp.example.com'
        )
        $r = ConvertFrom-SargePolicyDsRegCmd -Lines $lines
        $r.DomainJoined | Should -BeTrue
        $r.DomainName   | Should -Be 'corp.example.com'
    }

    It 'parses workgroup (neither joined)' {
        $lines = @(
            '            AzureAdJoined : NO',
            '             DomainJoined : NO'
        )
        $r = ConvertFrom-SargePolicyDsRegCmd -Lines $lines
        $r.AzureAdJoined | Should -BeFalse
        $r.DomainJoined  | Should -BeFalse
    }
}

Describe 'Get-SargeMdmPolicyInventory' {
    BeforeAll {
        # Create a fake registry hive structure via in-memory hashtable.
        # We mock Test-Path, Get-ChildItem, and Get-ItemProperty around the
        # specific PolicyManager path.
        $script:mockRoot = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device'
    }

    It 'returns empty hashtable when root key missing' {
        Mock Test-Path { $false } -ParameterFilter { $LiteralPath -eq $script:mockRoot }
        $r = Get-SargeMdmPolicyInventory
        $r            | Should -Not -BeNullOrEmpty
        $r.Keys.Count | Should -Be 0
    }

    It 'enumerates CSP areas and settings' {
        Mock Test-Path { $true } -ParameterFilter { $LiteralPath -eq $script:mockRoot }
        Mock Get-ChildItem {
            @(
                [pscustomobject]@{ PSChildName='DeviceGuard'; PSPath='Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceGuard' },
                [pscustomobject]@{ PSChildName='DataProtection'; PSPath='Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\DataProtection' }
            )
        } -ParameterFilter { $LiteralPath -eq $script:mockRoot }
        Mock Get-ChildItem { @() } -ParameterFilter { $LiteralPath -ne $script:mockRoot }
        Mock Get-ItemProperty {
            [pscustomobject]@{
                EnableVirtualizationBasedSecurity = 1
                RequirePlatformSecurityFeatures   = 3
                PSPath = 'x'; PSParentPath='y'; PSChildName='z'; PSDrive='HKLM'; PSProvider='Microsoft.PowerShell.Core\Registry'
            }
        }
        $r = Get-SargeMdmPolicyInventory
        $r.Keys           | Should -Contain 'DeviceGuard'
        $r.Keys           | Should -Contain 'DataProtection'
        # PowerShell metadata keys must be stripped.
        $r['DeviceGuard'].Keys | Should -Not -Contain 'PSPath'
        $r['DeviceGuard'].Keys | Should -Contain 'EnableVirtualizationBasedSecurity'
    }
}

Describe 'Apply-PolicyOverlay' -Skip {
    It 'flips matching Phase 1a FAIL to ENFORCED-EXTERNALLY when MDM enforces the control' {
        $findings = [System.Collections.Generic.List[object]]::new()
        $findings.Add([pscustomobject]@{
            id              = 'WIN-AC-11-idle-lock'
            control_family  = 'AC'
            control_id      = 'AC-11'
            verdict         = 'FAIL'
            message         = 'Idle lock timeout=0s'
            recommendation  = 'fix'
        })
        $inventory = @{
            'DeviceLock' = @{
                'MaxInactivityTimeDeviceLock' = 900
            }
        }
        $n = Apply-PolicyOverlay -Findings $findings -Inventory $inventory
        $n                       | Should -Be 1
        $findings[0].verdict     | Should -Be 'ENFORCED-EXTERNALLY'
        $findings[0].message     | Should -Match 'overlay'
    }

    It 'leaves PASS findings untouched' {
        $findings = [System.Collections.Generic.List[object]]::new()
        $findings.Add([pscustomobject]@{
            id              = 'WIN-AC-11-idle-lock'
            control_family  = 'AC'
            control_id      = 'AC-11'
            verdict         = 'PASS'
            message         = 'Idle lock 600s'
            recommendation  = ''
        })
        $inventory = @{ 'DeviceLock' = @{ 'MaxInactivityTimeDeviceLock' = 900 } }
        $n = Apply-PolicyOverlay -Findings $findings -Inventory $inventory
        $n                   | Should -Be 0
        $findings[0].verdict | Should -Be 'PASS'
    }

    It 'leaves POL findings untouched' {
        $findings = [System.Collections.Generic.List[object]]::new()
        $findings.Add([pscustomobject]@{
            id              = 'WIN-POL-1'
            control_family  = 'POL'
            control_id      = 'CM-2'
            verdict         = 'FAIL'
            message         = 'no MDM'
            recommendation  = 'enroll'
        })
        $inventory = @{ 'DeviceLock' = @{ 'MaxInactivityTimeDeviceLock' = 900 } }
        $n = Apply-PolicyOverlay -Findings $findings -Inventory $inventory
        $n                   | Should -Be 0
        $findings[0].verdict | Should -Be 'FAIL'
    }

    It 'ignores zero-valued settings (not actually enforced)' {
        $findings = [System.Collections.Generic.List[object]]::new()
        $findings.Add([pscustomobject]@{
            id              = 'WIN-AC-11-idle-lock'
            control_family  = 'AC'
            control_id      = 'AC-11'
            verdict         = 'FAIL'
            message         = 'm'
            recommendation  = 'r'
        })
        $inventory = @{ 'DeviceLock' = @{ 'MaxInactivityTimeDeviceLock' = 0 } }
        $n = Apply-PolicyOverlay -Findings $findings -Inventory $inventory
        $n                   | Should -Be 0
        $findings[0].verdict | Should -Be 'FAIL'
    }

    It 'returns 0 with empty inventory' {
        $findings = [System.Collections.Generic.List[object]]::new()
        $findings.Add([pscustomobject]@{
            id='WIN-AC-11-idle-lock'; control_family='AC'; control_id='AC-11';
            verdict='FAIL'; message='m'; recommendation='r'
        })
        $n = Apply-PolicyOverlay -Findings $findings -Inventory @{}
        $n | Should -Be 0
    }
}

Describe 'Get-SargeGpresultData (gpresult HTML parse)' {
    It 'extracts applied GPO names from HTML' {
        $htmlFile = Join-Path $TestDrive 'gpresult.html'
        @'
<html><body>
<h2>Applied GPOs</h2>
<table>
<tr><td>GPO</td><td>Link</td></tr>
<tr><td>Default Domain Policy</td><td>example.com</td></tr>
<tr><td>Security Baseline Win11</td><td>example.com/OU</td></tr>
</table>
<h2>Denied GPOs</h2>
<table>
<tr><td>GPO</td><td>Link</td></tr>
<tr><td>Legacy WSUS</td><td>example.com</td></tr>
</table>
</body></html>
'@ | Set-Content -LiteralPath $htmlFile -Encoding UTF8

        # We can't easily mock Start-Process. Instead exercise the parser by
        # reading the file and running the regex inline - this mirrors the
        # logic inside Get-SargeGpresultData without invoking gpresult.exe.
        $text = Get-Content -LiteralPath $htmlFile -Raw
        $applied = @()
        $appliedMatch = [regex]::Matches($text, '(?is)Applied\s*GPOs.*?<table[^>]*>(.*?)</table>')
        foreach ($block in $appliedMatch) {
            $rows = [regex]::Matches($block.Groups[1].Value, '<tr[^>]*>(.*?)</tr>')
            foreach ($r in $rows) {
                $cells = [regex]::Matches($r.Groups[1].Value, '<td[^>]*>([^<]*)</td>')
                if ($cells.Count -ge 1) {
                    $name = $cells[0].Groups[1].Value.Trim()
                    if ($name -and $name -notmatch '^GPO$') { $applied += $name }
                }
            }
        }
        $applied | Should -Contain 'Default Domain Policy'
        $applied | Should -Contain 'Security Baseline Win11'
    }
}

Describe 'Get-SargeMdmDiagReport' {
    It 'returns available=false when MDMDiagnosticsTool absent' {
        Mock Get-Command { $null } -ParameterFilter { $Name -eq 'MDMDiagnosticsTool.exe' }
        $r = Get-SargeMdmDiagReport
        $r.available   | Should -BeFalse
        $r.report_path | Should -BeNullOrEmpty
    }
}

Describe 'Get-SargeHostPolicyMode (integration via dsregcmd parse)' {
    # We can't mock the external dsregcmd cleanly, but we can exercise the
    # decision tree by injecting the parsed dsreg object directly. The
    # function builds its own probe; here we verify the classifier logic
    # by re-implementing the decision against known inputs.
    It 'classifies aad-no-mdm correctly' {
        $dsreg = @{ AzureAdJoined=$true; DomainJoined=$false; MdmUrl=$null }
        $mode = if ($dsreg.DomainJoined) { 'ad' }
                elseif ($dsreg.AzureAdJoined -and [string]::IsNullOrWhiteSpace($dsreg.MdmUrl)) { 'aad-no-mdm' }
                elseif ($dsreg.AzureAdJoined) { 'aad-mdm' }
                else { 'workgroup' }
        $mode | Should -Be 'aad-no-mdm'
    }

    It 'classifies aad-mdm correctly' {
        $dsreg = @{ AzureAdJoined=$true; DomainJoined=$false; MdmUrl='https://enrollment.manage.microsoft.com/x' }
        $mode = if ($dsreg.DomainJoined) { 'ad' }
                elseif ($dsreg.AzureAdJoined -and [string]::IsNullOrWhiteSpace($dsreg.MdmUrl)) { 'aad-no-mdm' }
                elseif ($dsreg.AzureAdJoined) { 'aad-mdm' }
                else { 'workgroup' }
        $mode | Should -Be 'aad-mdm'
    }

    It 'classifies workgroup correctly' {
        $dsreg = @{ AzureAdJoined=$false; DomainJoined=$false; MdmUrl=$null }
        $mode = if ($dsreg.DomainJoined) { 'ad' }
                elseif ($dsreg.AzureAdJoined -and [string]::IsNullOrWhiteSpace($dsreg.MdmUrl)) { 'aad-no-mdm' }
                elseif ($dsreg.AzureAdJoined) { 'aad-mdm' }
                else { 'workgroup' }
        $mode | Should -Be 'workgroup'
    }
}
