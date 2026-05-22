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
# GPO override note pointing at the --inspect-gpo follow-up issue. The
# JSON report is unaffected (machine-consumable).

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
        $StateDir
    )

    if (-not $ReportDir) { $ReportDir = (Join-Path $env:USERPROFILE '.sarge\reports') }
    if (-not $StateDir)  { $StateDir  = (Join-Path $env:USERPROFILE '.sarge\state') }
    if (-not $RunId)     { $RunId = (Get-Date).ToString('yyyyMMdd-HHmmss') }

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

    # Counts
    $counts = @{ PASS=0; FAIL=0; WARN=0; 'SKIP-CONTEXT-DEFERRED'=0; 'ENFORCED-EXTERNALLY'=0; UNTESTED=0 }
    foreach ($f in $FindingsArr) {
        if ($counts.ContainsKey($f.verdict)) { $counts[$f.verdict]++ }
    }

    # --- Write state findings JSON (machine-readable, no decoration) -----
    $findingsPath = Join-Path $StateDir ("findings-" + $RunId + ".json")
    $FindingsArr | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $findingsPath -Encoding UTF8

    # --- Write report JSON ------------------------------------------------
    $jsonReport = [ordered]@{
        run_id            = $RunId
        generated_at      = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        host              = $env:COMPUTERNAME
        is_domain_joined  = $isDomainJoined
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

    # --- Write Markdown ---------------------------------------------------
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("# Sarge - Windows Assessment Report")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("Run: ``$RunId``  ")
    [void]$sb.AppendLine("Host: ``$env:COMPUTERNAME``  ")
    [void]$sb.AppendLine("Generated: $((Get-Date).ToUniversalTime().ToString('u'))  ")
    [void]$sb.AppendLine("Domain-joined: ``$isDomainJoined``")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("## Summary")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("| Verdict | Count |")
    [void]$sb.AppendLine("|---------|-------|")
    foreach ($k in 'PASS','FAIL','WARN','SKIP-CONTEXT-DEFERRED','ENFORCED-EXTERNALLY','UNTESTED') {
        [void]$sb.AppendLine("| $k | $($counts[$k]) |")
    }
    [void]$sb.AppendLine("")

    if ($isDomainJoined) {
        [void]$sb.AppendLine("> **Domain-joined host.** Local registry / policy probes show the merged effective configuration but cannot tell you whether the values come from a local override or a Group Policy push. Recommendations below assume local-policy authority; if the host is GPO-managed, the actual fix lives in the controlling GPO. Re-run with ``--inspect-gpo`` (tracking: $script:SargeGpoFollowupIssue) for per-finding GPO source attribution.")
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
                if ($isDomainJoined -and $f.verdict -in 'FAIL','WARN') {
                    $rec = "$rec`n`n> _May be overridden by GPO. Re-run with ``--inspect-gpo`` once available (tracking: $script:SargeGpoFollowupIssue)._"
                }
                [void]$sb.AppendLine("**Recommendation:** $rec")
                [void]$sb.AppendLine("")
            }
        }
    }

    $reportMdPath = Join-Path $ReportDir ("sarge-windows-" + $RunId + ".md")
    Set-Content -LiteralPath $reportMdPath -Value $sb.ToString() -Encoding UTF8

    return [pscustomobject]@{
        markdown = $reportMdPath
        json     = $reportJsonPath
        findings = $findingsPath
        counts   = $counts
    }
}
