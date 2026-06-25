# tests/Pester/windows-host-only.Tests.ps1 - Pester tests for --host-only flag.
#
# Validates that assess.ps1 accepts the --host-only flag and sets the
# expected script-scope variables. No agent-specific Windows checks exist
# yet, so this primarily tests flag parsing and mode header output.

Describe '--host-only flag parsing' {
    BeforeAll {
        $repoRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
        $assessScript = Join-Path $repoRoot 'assessment\assess.ps1'
    }

    It 'assess.ps1 contains --host-only in argument switch' {
        $content = Get-Content -Path $assessScript -Raw
        $content | Should -Match '--host-only'
    }

    It 'assess.ps1 help text documents --host-only' {
        $content = Get-Content -Path $assessScript -Raw
        $content | Should -Match 'host-only.*agent-runtime'
    }

    It 'assess.ps1 sets SargeMode to host-only when flag is present' {
        $content = Get-Content -Path $assessScript -Raw
        $content | Should -Match "SargeMode.*host-only"
    }

    It 'assess.ps1 sets SargeMode to agent-host by default' {
        $content = Get-Content -Path $assessScript -Raw
        $content | Should -Match "SargeMode.*agent-host"
    }
}

Describe 'findings-catalog.json scope field' {
    BeforeAll {
        $repoRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
        $catalogPath = Join-Path $repoRoot 'assessment\findings-catalog.json'
        $catalog = Get-Content -Path $catalogPath -Raw | ConvertFrom-Json
    }

    It 'schema documents the scope field' {
        $catalog._doc.schema.scope | Should -Not -BeNullOrEmpty
    }

    It 'agent-scoped entries have scope=agent' {
        $agentIds = @(
            'AC-3-openclaw-dir-perm',
            'AC-3-secrets-dir-perm',
            'AC-3-secret-file-perm',
            'AU-12-no-openclaw-rules',
            'SC-8-cloudflared-not-detected',
            'SC-28-config-perm',
            'SC-28-config-owner',
            'SC-28-world-readable-secrets'
        )
        foreach ($id in $agentIds) {
            $catalog.$id.scope | Should -Be 'agent' -Because "$id should be scope:agent"
        }
    }

    It 'host-scoped entries do not have a scope field' {
        $hostIds = @('AC-2-empty-password', 'AC-6-passwordless-sudo', 'AU-2-auditd-not-running')
        foreach ($id in $hostIds) {
            $catalog.$id.PSObject.Properties.Name | Should -Not -Contain 'scope' -Because "$id is host-scope (implicit)"
        }
    }
}
