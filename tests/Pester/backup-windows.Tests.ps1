# tests/Pester/backup-windows.Tests.ps1 - Pester tests for the pre-hardening
# backup + rollback generator.
#
# Mocks the platform-mutating cmdlets (Checkpoint-Computer,
# Get-ComputerRestorePoint, reg.exe, secedit.exe, auditpol.exe,
# Register-ScheduledTask) so the suite is safe to run on any host - it
# does NOT actually checkpoint, restore, or rewrite system state.
#
# Run:
#   Invoke-Pester -Path tests/Pester/backup-windows.Tests.ps1

BeforeAll {
    $script:repoRoot   = (Resolve-Path "$PSScriptRoot\..\..").Path
    $script:backupPs1  = Join-Path $repoRoot 'scripts\backup-windows.ps1'
    $script:rollbackPs1= Join-Path $repoRoot 'scripts\rollback-windows.ps1'

    # Dot-sourcing the script directly executes the main body, which mutates
    # the filesystem. For unit tests we instead pull the helpers out via AST
    # and evaluate just the function definitions in this scope.
    $script:src = Get-Content -Raw -LiteralPath $backupPs1
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput(
        $script:src, [ref]$tokens, [ref]$errors)
    $funcs = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
    foreach ($f in $funcs) {
        $def = $f.Extent.Text
        Invoke-Expression $def
    }
}

Describe 'backup-windows.ps1 script presence' {
    It 'backup-windows.ps1 exists and is non-empty' {
        Test-Path -LiteralPath $script:backupPs1 | Should -BeTrue
        (Get-Item $script:backupPs1).Length | Should -BeGreaterThan 0
    }
    It 'rollback-windows.ps1 exists and is non-empty' {
        Test-Path -LiteralPath $script:rollbackPs1 | Should -BeTrue
        (Get-Item $script:rollbackPs1).Length | Should -BeGreaterThan 0
    }
    It 'declares the documented flags' {
        $script:src | Should -Match '--run-id'
        $script:src | Should -Match '--unattended'
        $script:src | Should -Match '--skip-restore-point'
    }
    It 'fails loud with exit code 2 when System Protection is off' {
        $script:src | Should -Match 'exit 2'
        $script:src | Should -Match 'Enable System Protection'
    }
    It 'uses MODIFY_SETTINGS restore point type' {
        $script:src | Should -Match 'MODIFY_SETTINGS'
    }
}

Describe 'Test-SargeSystemProtection' {
    It 'returns $true when SystemRestoreConfig.RPSessionInterval > 0' {
        Mock Get-CimInstance { return [pscustomobject]@{ RPSessionInterval = 1 } } -ParameterFilter { $ClassName -eq 'SystemRestoreConfig' }
        Test-SargeSystemProtection | Should -BeTrue
    }
    It 'returns $false when SystemRestoreConfig.RPSessionInterval == 0' {
        Mock Get-CimInstance { return [pscustomobject]@{ RPSessionInterval = 0 } } -ParameterFilter { $ClassName -eq 'SystemRestoreConfig' }
        Test-SargeSystemProtection | Should -BeFalse
    }
}

Describe 'Export-SargeRegistryKey' {
    BeforeEach {
        $script:tmp = Join-Path $env:TEMP ("sarge-pester-" + [Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:tmp -Force | Out-Null
    }
    AfterEach {
        Remove-Item -LiteralPath $script:tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
    It 'returns ok=$true when reg.exe exits 0 and file is created' {
        Mock Start-Process {
            $outFile = $ArgumentList[2]
            Set-Content -LiteralPath $outFile -Value 'Windows Registry Editor Version 5.00' -Encoding ASCII
            return [pscustomobject]@{ ExitCode = 0 }
        }
        $r = Export-SargeRegistryKey -Key 'HKLM\SOFTWARE\Sarge\Fake' -OutDir $script:tmp
        $r.ok | Should -BeTrue
        Test-Path -LiteralPath $r.file | Should -BeTrue
    }
    It 'returns ok=$false when reg.exe exits non-zero' {
        Mock Start-Process { return [pscustomobject]@{ ExitCode = 1 } }
        $r = Export-SargeRegistryKey -Key 'HKLM\SOFTWARE\Sarge\Missing' -OutDir $script:tmp
        $r.ok | Should -BeFalse
    }
}

Describe 'New-SargeRollbackScript' {
    BeforeEach {
        $script:tmp = Join-Path $env:TEMP ("sarge-pester-rb-" + [Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:tmp -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $script:tmp 'registry') -Force | Out-Null
    }
    AfterEach {
        Remove-Item -LiteralPath $script:tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
    It 'generates rollback.ps1 referencing all captured artifacts' {
        $captured = @{
            registry = @(
                [pscustomobject]@{ key='HKLM\SOFTWARE\Test'; file=(Join-Path $script:tmp 'registry\HKLM_SOFTWARE_Test.reg'); ok=$true }
            )
            secpol   = $true
            auditpol = $true
            services = $true
            tasks    = @([pscustomobject]@{ taskPath='\Vendor\'; taskName='X'; file=(Join-Path $script:tmp 'tasks\Vendor_X.xml') })
        }
        $rb = New-SargeRollbackScript -BackupDir $script:tmp -Captured $captured
        Test-Path -LiteralPath $rb | Should -BeTrue
        $body = Get-Content -Raw -LiteralPath $rb
        $body | Should -Match 'reg.exe import'
        $body | Should -Match 'secedit.exe /configure'
        $body | Should -Match 'auditpol.exe /restore'
        $body | Should -Match 'Set-Service'
        $body | Should -Match 'Register-ScheduledTask'
    }
    It 'omits sections for surfaces that were not captured' {
        $captured = @{ registry=@(); secpol=$false; auditpol=$false; services=$false; tasks=@() }
        $rb = New-SargeRollbackScript -BackupDir $script:tmp -Captured $captured
        $body = Get-Content -Raw -LiteralPath $rb
        $body | Should -Not -Match 'secedit.exe /configure'
        $body | Should -Not -Match 'auditpol.exe /restore'
        $body | Should -Not -Match 'Set-Service -Name'
    }
    It 'rollback.ps1 is syntactically valid PowerShell' {
        $captured = @{
            registry = @([pscustomobject]@{ key='HKLM\X'; file=(Join-Path $script:tmp 'registry\HKLM_X.reg'); ok=$true })
            secpol   = $true
            auditpol = $true
            services = $true
            tasks    = @()
        }
        $rb = New-SargeRollbackScript -BackupDir $script:tmp -Captured $captured
        $errors = $null
        $tokens = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($rb, [ref]$tokens, [ref]$errors)
        @($errors).Count | Should -Be 0
    }
}

Describe 'New-SargeBackupSummary' {
    BeforeEach {
        $script:tmp = Join-Path $env:TEMP ("sarge-pester-sum-" + [Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:tmp -Force | Out-Null
    }
    AfterEach {
        Remove-Item -LiteralPath $script:tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
    It 'emits a markdown summary including the rollback command' {
        $captured = @{ registry=@(); secpol=$true; auditpol=$true; services=$true; tasks=@() }
        $summary = New-SargeBackupSummary -RunRoot $script:tmp -BackupDir (Join-Path $script:tmp 'backup') `
            -Captured $captured -RunId 'testrun-1' -RestorePointCreated $true
        Test-Path -LiteralPath $summary | Should -BeTrue
        (Get-Content -Raw -LiteralPath $summary) | Should -Match 'rollback-windows.ps1'
    }
}

Describe 'rollback-windows.ps1 references' {
    It 'mentions BackupDir parameter' {
        $body = Get-Content -Raw -LiteralPath $script:rollbackPs1
        $body | Should -Match '\[string\] \$BackupDir'
    }
    It 'is syntactically valid PowerShell' {
        $errors = $null
        $tokens = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($script:rollbackPs1, [ref]$tokens, [ref]$errors)
        @($errors).Count | Should -Be 0
    }
}
