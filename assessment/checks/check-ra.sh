#!/usr/bin/env bash
# check-ra.sh — Risk Assessment (RA) checks — NIST 800-53 Rev 5
# Platform-specific data acquisition lives in lib/platforms/<os>.sh.

# RA-5: Vulnerability Monitoring and Scanning
#
# Checks for evidence that vulnerability scanning is configured and recent.
# On an OpenClaw agent host, this means:
#   1. apt security-audit tools are installed (apt-get, unattended-upgrades)
#   2. A vulnerability scanner is present (trivy, grype, or OS-level tools)
#   3. Recent scan evidence exists (scan output files, last-run timestamps)
#   4. OpenClaw npm dependencies have been audited recently
log "RA-5: Vulnerability monitoring and scanning"

# RA-5 sub-check 1: OS-level vulnerability scanner installed
RA5_SCANNER_FOUND=0
RA5_SCANNER_NAME=""
for scanner in trivy grype oscap lynis debsecan; do
  if command -v "$scanner" &>/dev/null; then
    RA5_SCANNER_FOUND=1
    RA5_SCANNER_NAME="${RA5_SCANNER_NAME}${RA5_SCANNER_NAME:+, }$scanner"
  fi
done
if [[ "$RA5_SCANNER_FOUND" -eq 1 ]]; then
  passx "RA-5-scanner-installed" "RA-5: Vulnerability scanner(s) installed: $RA5_SCANNER_NAME"
else
  warnx "RA-5-scanner-installed" "RA-5: No recognized vulnerability scanner found (checked: trivy, grype, oscap, lynis, debsecan) — install one to enable automated vulnerability scanning"
fi

# RA-5 sub-check 2: Recent scan evidence
RA5_SCAN_EVIDENCE=0
RA5_EVIDENCE_NOTE=""
RA5_SCAN_DIRS=(
  "$HOME/.openclaw/scans"
  "$HOME/.openclaw/reports"
  "/var/log/trivy"
  "/var/log/lynis"
  "/var/lib/oscap"
)
for scan_dir in "${RA5_SCAN_DIRS[@]}"; do
  if [[ -d "$scan_dir" ]]; then
    RA5_RECENT=$(find "$scan_dir" -maxdepth 2 -type f \( -name "*.json" -o -name "*.html" -o -name "*.xml" -o -name "*.txt" \) -mtime -30 2>/dev/null | head -1)
    if [[ -n "$RA5_RECENT" ]]; then
      RA5_SCAN_EVIDENCE=1
      RA5_EVIDENCE_NOTE="${RA5_EVIDENCE_NOTE}${RA5_EVIDENCE_NOTE:+, }$scan_dir"
    fi
  fi
done
# Also check for Sarge's own report output
SARGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RA5_SARGE_REPORT=$(find "$SARGE_DIR" -maxdepth 3 -name "report.json" -mtime -30 2>/dev/null | head -1)
if [[ -n "$RA5_SARGE_REPORT" ]]; then
  RA5_SCAN_EVIDENCE=1
  RA5_EVIDENCE_NOTE="${RA5_EVIDENCE_NOTE}${RA5_EVIDENCE_NOTE:+, }sarge report"
fi

if [[ "$RA5_SCAN_EVIDENCE" -eq 1 ]]; then
  passx "RA-5-scan-evidence" "RA-5: Recent scan evidence found (within 30 days) in: $RA5_EVIDENCE_NOTE"
else
  warnx "RA-5-scan-evidence" "RA-5: No recent vulnerability scan output found (checked ~/.openclaw/scans, /var/log/trivy, /var/log/lynis, /var/lib/oscap, sarge reports) — run a vulnerability scan and store results"
fi

# RA-5 sub-check 3: npm audit for OpenClaw dependencies
if [[ "${SARGE_HOST_ONLY:-0}" != "1" ]]; then
  RA5_OC_INSTALL=""
  for candidate in /usr/lib/node_modules/openclaw /usr/local/lib/node_modules/openclaw "$HOME/.npm-global/lib/node_modules/openclaw"; do
    if [[ -d "$candidate" && -f "$candidate/package.json" ]]; then
      RA5_OC_INSTALL="$candidate"
      break
    fi
  done
  if [[ -n "$RA5_OC_INSTALL" ]] && command -v npm &>/dev/null; then
    RA5_AUDIT_OUTPUT=$(cd "$RA5_OC_INSTALL" && npm audit --json 2>/dev/null)
    if [[ -n "$RA5_AUDIT_OUTPUT" ]]; then
      RA5_VULN_COUNT=$(echo "$RA5_AUDIT_OUTPUT" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    meta = d.get("metadata", {}).get("vulnerabilities", {})
    total = meta.get("total", 0)
    if total == 0:
        total = meta.get("high", 0) + meta.get("critical", 0) + meta.get("moderate", 0) + meta.get("low", 0)
    print(total)
except Exception:
    print("-1")
' 2>/dev/null)
      RA5_CRIT_COUNT=$(echo "$RA5_AUDIT_OUTPUT" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    meta = d.get("metadata", {}).get("vulnerabilities", {})
    print(meta.get("critical", 0) + meta.get("high", 0))
except Exception:
    print("-1")
' 2>/dev/null)
      if [[ "$RA5_VULN_COUNT" == "0" ]]; then
        passx "RA-5-npm-audit" "RA-5: npm audit reports 0 known vulnerabilities in OpenClaw dependencies"
      elif [[ "$RA5_CRIT_COUNT" -gt 0 ]]; then
        failx "RA-5-npm-audit" "RA-5: npm audit found $RA5_VULN_COUNT vulnerabilities ($RA5_CRIT_COUNT critical/high) in OpenClaw dependencies at $RA5_OC_INSTALL — run 'npm audit fix'"
      elif [[ "$RA5_VULN_COUNT" -gt 0 ]]; then
        warnx "RA-5-npm-audit" "RA-5: npm audit found $RA5_VULN_COUNT vulnerabilities (none critical/high) in OpenClaw dependencies at $RA5_OC_INSTALL — review and remediate"
      else
        skipx "RA-5-npm-audit" "RA-5: npm audit output could not be parsed — run 'npm audit' manually in $RA5_OC_INSTALL"
      fi
    else
      skipx "RA-5-npm-audit" "RA-5: npm audit returned no output for $RA5_OC_INSTALL — may require 'npm install' first"
    fi
  elif [[ "${SARGE_HOST_ONLY:-0}" != "1" ]]; then
    skipx "RA-5-npm-audit" "RA-5: OpenClaw npm installation not found at standard paths, or npm not available — cannot run dependency audit"
  fi
fi

# RA-5 sub-check 4: OS package security updates pending (distinct from CM-6 —
# this checks specifically for CVE-tagged security updates)
if platform_supports pending_security_updates_count; then
  RA5_SEC_UPDATES=$(platform pending_security_updates_count)
  if [[ "$RA5_SEC_UPDATES" -eq 0 ]]; then
    passx "RA-5-os-security-patches" "RA-5: No pending OS security patches"
  else
    warnx "RA-5-os-security-patches" "RA-5: $RA5_SEC_UPDATES OS security update(s) pending — apply to close known vulnerabilities"
  fi
else
  skipx "RA-5-os-security-patches" "RA-5: Security update counting not available on ${SARGE_OS_DESCRIPTION}"
fi
