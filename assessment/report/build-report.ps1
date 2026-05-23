# assessment/report/build-report.ps1 - Build Markdown + JSON reports.
#
# Consumes the in-memory $script:SargeFindings list populated by the check
# scripts, plus the windows-context.json document, and emits:
#   ~/.sarge/reports/sarge-windows-<timestamp>.md
#   ~/.sarge/reports/sarge-windows-<timestamp>.json
#   ~/.sarge/state/findings-<run-id>.json
#
# Domain-joined branch: when context.enterprise_context.is_domain_joined is
# true, every FAIL recommendation in the Markdown report is suffixed with a
# GPO override note pointing at the --inspect-policy follow-up issue. The
# JSON report is unaffected (machine-consumable).
#
# Phase 1b (issue #31): when assess.ps1 ran with --inspect-policy, the
# report header now reflects the 5-way detected mode (ad-rsat, ad-gpresult,
# aad-mdm, aad-no-mdm, workgroup) instead of the binary domain-joined
# branch. The overlay note is suppressed when policy data is present
# because Apply-PolicyOverlay has already flipped the relevant verdicts.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# GPO follow-up issue number is filled in after the issue is filed in
# the same PR turn. If we couldn't file it (no auth), it stays as the
# placeholder string and the report links to issue #12 (parent) instead.
# Updated by the script that calls gh issue create.
$script:SargeGpoFollowupIssue = '#31'

function Build-SargeReport {
    param(
        $Findings,
        $RunId,
        $ReportDir,
        $StateDir,
        $RunRoot
    )

    if (-not $ReportDir) { $ReportDir = (Join-Path $env:USERPROFILE '.sarge\reports') }
    if (-not $StateDir)  { $StateDir  = (Join-Path $env:USERPROFILE '.sarge\state') }
    if (-not $RunId)     { $RunId = (Get-Date).ToString('yyyyMMdd-HHmmss') }
    if (-not $RunRoot)   { $RunRoot = (Join-Path $env:USERPROFILE (".sarge\runs\" + $RunId)) }
    if (-not (Test-Path -LiteralPath $RunRoot)) {
        New-Item -ItemType Directory -Path $RunRoot -Force | Out-Null
    }

    # Normalize to plain array
    $FindingsArr = @($Findings)

    Write-Host ("[REPORT] Building from " + $FindingsArr.Count + " findings; runId=" + $RunId)

    if (-not (Test-Path -LiteralPath $ReportDir)) {
        New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null
    }
    if (-not (Test-Path -LiteralPath $StateDir)) {
        New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
    }

    # Load context. Tolerate missing.
    $ctxPath = Join-Path $StateDir 'windows-context.json'
    $isDomainJoined = $false
    $contextJson = $null
    if (Test-Path -LiteralPath $ctxPath) {
        try {
            $contextJson = Get-Content -LiteralPath $ctxPath -Raw | ConvertFrom-Json
            $isDomainJoined = [bool]$contextJson.enterprise_context.is_domain_joined
        } catch { }
    }

    # Phase 1b: pick up the policy mode if assess.ps1 set it. When
    # --inspect-policy ran, $script:SargePolicyMode is a pscustomobject with
    # .mode / .reason. When it didn't, fall back to the binary
    # is_domain_joined header.
    $policyMode       = $null
    $policyModeReason = $null
    $inspectPolicy    = $false
    if (Get-Variable -Name SargePolicyMode -Scope Script -ErrorAction SilentlyContinue) {
        $pm = $script:SargePolicyMode
        if ($null -ne $pm) {
            $policyMode       = [string]$pm.mode
            $policyModeReason = [string]$pm.reason
        }
    }
    if (Get-Variable -Name SargeInspectPolicy -Scope Script -ErrorAction SilentlyContinue) {
        $inspectPolicy = [bool]$script:SargeInspectPolicy
    }
    $overlayCount = 0
    if (Get-Variable -Name SargePolicyOverlayCount -Scope Script -ErrorAction SilentlyContinue) {
        $overlayCount = [int]$script:SargePolicyOverlayCount
    }

    # Counts
    $counts = @{ PASS=0; FAIL=0; WARN=0; 'SKIP-CONTEXT-DEFERRED'=0; 'ENFORCED-EXTERNALLY'=0; UNTESTED=0 }
    foreach ($f in $FindingsArr) {
        if ($counts.ContainsKey($f.verdict)) { $counts[$f.verdict]++ }
    }

    # --- Write state findings JSON (machine-readable, no decoration) -----
    # Legacy path (kept for backwards compatibility with PR #14 contract).
    $findingsPath = Join-Path $StateDir ("findings-" + $RunId + ".json")
    $FindingsArr | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $findingsPath -Encoding UTF8

    # Per-run folder: self-contained copy.
    $runFindingsPath = Join-Path $RunRoot 'findings.json'
    $FindingsArr | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $runFindingsPath -Encoding UTF8

    # Copy context.json into the run folder if present.
    if (Test-Path -LiteralPath $ctxPath) {
        Copy-Item -LiteralPath $ctxPath -Destination (Join-Path $RunRoot 'context.json') -Force
    }

    # --- Write report JSON ------------------------------------------------
    $jsonReport = [ordered]@{
        run_id            = $RunId
        generated_at      = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        host              = $env:COMPUTERNAME
        is_domain_joined  = $isDomainJoined
        policy_mode       = $policyMode
        policy_mode_reason = $policyModeReason
        inspect_policy    = $inspectPolicy
        overlay_count     = $overlayCount
        counts            = $counts
        findings          = $FindingsArr
        context_excerpt   = if ($contextJson) {
            [ordered]@{
                enterprise_context = $contextJson.enterprise_context
                active_controls    = $contextJson.active_controls
                host               = $contextJson.host
            }
        } else { $null }
    }
    $reportJsonPath = Join-Path $ReportDir ("sarge-windows-" + $RunId + ".json")
    $jsonReport | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $reportJsonPath -Encoding UTF8
    # Per-run folder copy.
    $jsonReport | ConvertTo-Json -Depth 6 |
        Set-Content -LiteralPath (Join-Path $RunRoot 'report.json') -Encoding UTF8

    # --- Write Markdown ---------------------------------------------------
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("# Sarge - Windows Assessment Report")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("Run: ``$RunId``  ")
    [void]$sb.AppendLine("Host: ``$env:COMPUTERNAME``  ")
    [void]$sb.AppendLine("Generated: $((Get-Date).ToUniversalTime().ToString('u'))  ")
    [void]$sb.AppendLine("Domain-joined: ``$isDomainJoined``  ")
    if ($policyMode) {
        [void]$sb.AppendLine("Policy mode: ``$policyMode`` - $policyModeReason  ")
        [void]$sb.AppendLine("Policy overlay re-verdicts: ``$overlayCount``  ")
    } elseif ($inspectPolicy) {
        [void]$sb.AppendLine("Policy mode: ``unknown`` (--inspect-policy ran but produced no classification)  ")
    }
    [void]$sb.AppendLine("Run folder: ``$RunRoot``")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("All artifacts for this run (findings.json, report.json, report.md, context.json, software-inventory.json) are co-located in the run folder above.")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("## Summary")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("| Verdict | Count |")
    [void]$sb.AppendLine("|---------|-------|")
    foreach ($k in 'PASS','FAIL','WARN','SKIP-CONTEXT-DEFERRED','ENFORCED-EXTERNALLY','UNTESTED') {
        [void]$sb.AppendLine("| $k | $($counts[$k]) |")
    }
    [void]$sb.AppendLine("")

    # Mode-aware caveat (5-way branching, Phase 1b).
    if ($policyMode) {
        switch ($policyMode) {
            'ad-rsat' {
                [void]$sb.AppendLine("> **AD-joined host (RSAT readable).** GPO inventory was probed via Get-GPO. Findings tagged ``ENFORCED-EXTERNALLY`` mean the controlling GPO already enforces the relevant setting; fixes for those should be applied to the GPO, not the local host.")
            }
            'ad-gpresult' {
                [void]$sb.AppendLine("> **AD-joined host (gpresult fallback).** RSAT/GPMC is not installed; policy detection relied on ``gpresult /h`` HTML parse. Coverage is partial - install RSAT (``Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0``) for ground-truth per-setting attribution.")
            }
            'aad-mdm' {
                [void]$sb.AppendLine("> **AAD-joined, MDM-managed host.** Intune MDM CSP inventory was probed under ``HKLM:\SOFTWARE\Microsoft\PolicyManager``. Findings tagged ``ENFORCED-EXTERNALLY`` are controlled by Intune; fixes for those should be applied in the Intune admin center, not on the local host.")
            }
            'aad-no-mdm' {
                [void]$sb.AppendLine("> **AAD-joined but no MDM enforcement (WIN-POL-1 FAIL).** The device is joined to Azure AD but is not enrolled in Intune (or any MDM). Local policy is the only enforcement surface, so configuration drift cannot be centrally remediated. See WIN-POL-1 below.")
            }
            'workgroup' {
                [void]$sb.AppendLine("> **Workgroup host.** Neither AD- nor AAD-joined. No central policy authority exists; every finding below applies to the local machine in isolation.")
            }
            'unknown' {
                [void]$sb.AppendLine("> **Policy mode could not be determined.** dsregcmd probe failed or produced no output. Findings below assume local-policy authority; re-run after confirming dsregcmd is operational.")
            }
        }
        [void]$sb.AppendLine("")
    } elseif ($isDomainJoined) {
        [void]$sb.AppendLine("> **Domain-joined host.** Local registry / policy probes show the merged effective configuration but cannot tell you whether the values come from a local override or a Group Policy push. Re-run with ``--inspect-policy`` (tracking: $script:SargeGpoFollowupIssue) for per-finding source attribution.")
        [void]$sb.AppendLine("")
    }

    # Group by family
    $byFamily = $FindingsArr | Group-Object -Property control_family | Sort-Object Name
    foreach ($g in $byFamily) {
        [void]$sb.AppendLine("## $($g.Name) Family")
        [void]$sb.AppendLine("")
        foreach ($f in $g.Group) {
            [void]$sb.AppendLine("### $($f.id)  -  $($f.verdict)")
            [void]$sb.AppendLine("")
            [void]$sb.AppendLine("Control: ``$($f.control_id)``")
            [void]$sb.AppendLine("")
            [void]$sb.AppendLine("$($f.message)")
            [void]$sb.AppendLine("")
            if ($f.recommendation -and $f.recommendation -ne '') {
                $rec = $f.recommendation
                # If we did NOT run --inspect-policy and the host is
                # domain-joined, keep the GPO caveat (Phase 1a behavior).
                # If we DID run --inspect-policy, the overlay already
                # flipped the verdict where applicable, so no caveat needed.
                if (-not $policyMode -and $isDomainJoined -and $f.verdict -in 'FAIL','WARN') {
                    $rec = "$rec`n`n> _May be overridden by GPO. Re-run with ``--inspect-policy`` (tracking: $script:SargeGpoFollowupIssue)._"
                }
                [void]$sb.AppendLine("**Recommendation:** $rec")
                [void]$sb.AppendLine("")
            }
        }
    }

    $reportMdPath = Join-Path $ReportDir ("sarge-windows-" + $RunId + ".md")
    Set-Content -LiteralPath $reportMdPath -Value $sb.ToString() -Encoding UTF8
    # Per-run folder copy.
    Set-Content -LiteralPath (Join-Path $RunRoot 'report.md') -Value $sb.ToString() -Encoding UTF8

    return [pscustomobject]@{
        markdown = $reportMdPath
        json     = $reportJsonPath
        findings = $findingsPath
        counts   = $counts
    }
}
