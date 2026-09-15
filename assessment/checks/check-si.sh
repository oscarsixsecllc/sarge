#!/usr/bin/env bash
# check-si.sh — System & Information Integrity (SI) — partial — NIST 800-53 Rev 5
# Platform-specific data acquisition lives in lib/platforms/<os>.sh.

# SI-2: Flaw Remediation — package updates
log "SI-2: Flaw remediation"
if ! platform_supports pending_security_updates_count; then
  skipx "SI-2-security-updates-low" "SI-2: pending security-update counting via apt is not applicable on ${SARGE_OS_DESCRIPTION}; review 'softwareupdate --list' or MDM compliance reports"
else
  SECURITY_UPDATES=$(platform pending_security_updates_count)
  if [[ "$SECURITY_UPDATES" -eq 0 ]]; then
    # On macOS, distinguish "no updates" from "no cached scan data"
    if platform_supports softwareupdate_no_scan_data && platform softwareupdate_no_scan_data; then
      warnx "SI-2-security-updates-low" "SI-2: softwareupdate has no cached scan data. Run 'softwareupdate --list' to populate, then re-assess"
    else
      passx "SI-2-security-updates-low" "SI-2: No pending security updates"
    fi
  elif [[ "$SECURITY_UPDATES" -le 3 ]]; then
    warnx "SI-2-security-updates-low" "SI-2: $SECURITY_UPDATES security updates pending. Apply soon"
  else
    failx "SI-2-security-updates-high" "SI-2: $SECURITY_UPDATES security updates pending. Apply immediately"
  fi
fi

# SI-2: Kernel version check
log "SI-2: Kernel currency"
KERNEL=$(uname -r)
passx "SI-2-security-updates-low" "SI-2: Running kernel: $KERNEL (manual review recommended for currency)"

# SI-3: Malicious code protection
log "SI-3: Malicious code protection"
if ! platform_supports clamav_installed; then
  skipx "SI-3-clamav-not-installed" "SI-3: macOS ships XProtect + Gatekeeper + Notarization as built-in malware protection; no third-party scanner required"
elif platform clamav_installed; then
  passx "SI-3-clamav-not-installed" "SI-3: ClamAV is installed"
  if platform service_active clamav-daemon; then
    passx "SI-3-clamav-daemon-stopped" "SI-3: ClamAV daemon is running"
  else
    warnx "SI-3-clamav-daemon-stopped" "SI-3: ClamAV installed but daemon not running — consider enabling for real-time protection"
  fi
  if platform service_active clamav-freshclam; then
    passx "SI-3-freshclam-stopped" "SI-3: ClamAV signature updater (freshclam) is running"
  else
    warnx "SI-3-freshclam-stopped" "SI-3: freshclam not running — ClamAV signatures may be outdated"
  fi
else
  warnx "SI-3-clamav-not-installed" "SI-3: ClamAV not installed — consider installing for malware detection: sudo apt install clamav"
fi

# SI-2/SI-3: fail2ban (intrusion/brute-force protection)
log "SI-2/SI-3: Brute force protection"
if ! platform_supports fail2ban_status; then
  skipx "SI-3-fail2ban-not-running" "SI-3: fail2ban has no native macOS analog; rate-limiting for SSH/remote services is delegated to the firewall (socketfilterfw / pf) or upstream appliance"
elif platform service_active fail2ban; then
  passx "SI-3-fail2ban-not-running" "SI-3: fail2ban is running"
  F2B_STATUS=$(platform fail2ban_status)
  if [[ -n "$F2B_STATUS" ]]; then
    JAILS=$(echo "$F2B_STATUS" | grep "Jail list" | sed 's/.*Jail list:\s*//')
    passx "SI-3-fail2ban-not-running" "SI-3: fail2ban active jails: ${JAILS:-none listed}"
  fi
else
  failx "SI-3-fail2ban-not-running" "SI-3: fail2ban is not running — run harden-fail2ban.sh to configure"
fi

# SI-7: Software integrity — verify Sarge script checksums if available
log "SI-7: Software integrity"
SARGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECKSUM_FILE="$SARGE_DIR/CHECKSUMS.sha256"
if [[ -f "$CHECKSUM_FILE" ]]; then
  if (cd "$SARGE_DIR" && platform verify_checksums "$CHECKSUM_FILE"); then
    passx "SI-7-checksum-mismatch" "SI-7: Sarge script checksums verified"
  else
    failx "SI-7-checksum-mismatch" "SI-7: Sarge script checksum verification FAILED — scripts may have been modified"
  fi
else
  skipx "SI-7-checksum-mismatch" "SI-7: No CHECKSUMS.sha256 file found — generate with: sha256sum scripts/*.sh assessment/**/*.sh > CHECKSUMS.sha256"
fi

# SI-7: Software & Information Integrity — package signature verification
log "SI-7: Package signature verification"
if ! platform_supports apt_config_available; then
  skipx "SI-7-package-signing" "SI-7: apt-config inspection is a Debian/Ubuntu construct; not applicable on ${SARGE_OS_DESCRIPTION} — review the platform's native package-signing policy separately"
elif ! platform apt_config_available; then
  skipx "SI-7-package-signing" "SI-7: apt-config not available — cannot verify package signature enforcement"
else
  ALLOW_UNAUTH=$(platform apt_allow_unauthenticated)
  TRUSTED_KEYS=$(platform apt_trusted_keys_count)
  if [[ "$ALLOW_UNAUTH" == "true" ]]; then
    failx "SI-7-package-signing" "SI-7: APT::Get::AllowUnauthenticated is true — unsigned packages can be installed; unset it or set to false"
  elif [[ -z "$TRUSTED_KEYS" || "$TRUSTED_KEYS" -eq 0 ]]; then
    warnx "SI-7-package-signing" "SI-7: no apt trusted GPG keys found under /etc/apt/trusted.gpg.d/ — package signature verification may not be configured"
  else
    passx "SI-7-package-signing" "SI-7: apt signature verification enforced (AllowUnauthenticated=${ALLOW_UNAUTH:-unset}, $TRUSTED_KEYS trusted key file(s))"
  fi
fi

# SI-16: Memory Protection — ASLR
log "SI-16: Memory protection (ASLR)"
if ! platform_supports aslr_setting; then
  skipx "SI-16-aslr" "SI-16: /proc/sys/kernel/randomize_va_space is a Linux-specific control; review ${SARGE_OS_DESCRIPTION}'s native memory-protection posture separately"
else
  ASLR=$(platform aslr_setting)
  if [[ -z "$ASLR" ]]; then
    warnx "SI-16-aslr" "SI-16: could not read /proc/sys/kernel/randomize_va_space"
  elif [[ "$ASLR" -eq 2 ]]; then
    passx "SI-16-aslr" "SI-16: ASLR is fully enabled (randomize_va_space=2)"
  elif [[ "$ASLR" -eq 1 ]]; then
    warnx "SI-16-aslr" "SI-16: ASLR is only partially enabled (randomize_va_space=1) — set to 2 for full randomization"
  else
    failx "SI-16-aslr" "SI-16: ASLR is disabled (randomize_va_space=$ASLR) — enable it: sudo sysctl -w kernel.randomize_va_space=2"
  fi
fi

# SI-4: Information System Monitoring — auditd rules for auth events and OpenClaw diagnostics
log "SI-4: System monitoring"
if platform_supports audit_daemon_active; then
  if platform audit_daemon_active; then
    passx "SI-4-auditd-active" "SI-4: auditd is running"

    # Check for auth-related audit rules
    SI4_RULES=$(platform audit_rules 2>/dev/null || true)
    SI4_AUTH_RULES=0
    if echo "$SI4_RULES" | grep -qE "auth|pam|login|shadow|passwd|faillog|lastlog|tallylog"; then
      SI4_AUTH_RULES=1
    fi
    if [[ "$SI4_AUTH_RULES" -eq 1 ]]; then
      passx "SI-4-auth-audit-rules" "SI-4: Audit rules covering authentication events are configured"
    else
      warnx "SI-4-auth-audit-rules" "SI-4: No audit rules for auth events detected (shadow, pam, login, faillog). Add rules: -w /var/log/auth.log -p wa -k auth_log"
    fi

    # Check for OpenClaw-specific audit rules
    SI4_OC_RULES=0
    if echo "$SI4_RULES" | grep -qiE "openclaw|claude"; then
      SI4_OC_RULES=1
    fi
    if [[ "$SI4_OC_RULES" -eq 1 ]]; then
      passx "SI-4-openclaw-audit-rules" "SI-4: Audit rules covering OpenClaw/Claude activity are configured"
    else
      warnx "SI-4-openclaw-audit-rules" "SI-4: No audit rules for OpenClaw/Claude paths detected. Consider: -w $HOME/.openclaw -p wa -k openclaw_config"
    fi
  else
    failx "SI-4-auditd-active" "SI-4: auditd is not running. Install and enable: sudo apt install auditd && sudo systemctl enable --now auditd"
  fi
else
  skipx "SI-4-auditd-active" "SI-4: auditd monitoring not applicable on ${SARGE_OS_DESCRIPTION}"
fi

# SI-4: Check for log analysis tooling (logwatch or equivalent)
log "SI-4: Log analysis tooling"
if platform_supports package_installed; then
  SI4_LOGWATCH=0
  SI4_LOGANALYZER=""
  for pkg in logwatch logcheck syslog-ng; do
    if platform package_installed "$pkg"; then
      SI4_LOGWATCH=1
      SI4_LOGANALYZER="$pkg"
      break
    fi
  done
  if [[ "$SI4_LOGWATCH" -eq 1 ]]; then
    passx "SI-4-log-analysis" "SI-4: Log analysis tool installed ($SI4_LOGANALYZER)"
  else
    warnx "SI-4-log-analysis" "SI-4: No log analysis tool detected (logwatch, logcheck, syslog-ng). Consider: sudo apt install logwatch"
  fi
else
  skipx "SI-4-log-analysis" "SI-4: Package check not available on ${SARGE_OS_DESCRIPTION}"
fi

# SI-4: OpenClaw diagnostics and audit settings
if [[ "${SARGE_HOST_ONLY:-0}" != "1" ]]; then
  SI4_OC_CONFIG=""
  for candidate in "$HOME/.openclaw/openclaw.json" "$HOME/.openclaw/config.json"; do
    if [[ -f "$candidate" ]]; then
      SI4_OC_CONFIG="$candidate"
      break
    fi
  done
  if [[ -n "$SI4_OC_CONFIG" ]]; then
    SI4_CONFIG_NAME=$(basename "$SI4_OC_CONFIG")
    SI4_DIAG=$(python3 -c '
import json, sys
try:
    cfg = json.load(open(sys.argv[1]))
    diag = cfg.get("diagnostics", {}).get("enabled")
    audit = cfg.get("audit", {}).get("enabled")
    cron_alert = cfg.get("cron", {}).get("failureAlert", {}).get("enabled")
    suppressions = cfg.get("security", {}).get("audit", {}).get("suppressions", [])
    parts = []
    if diag is True: parts.append("PASS:diagnostics=enabled")
    elif diag is False: parts.append("WARN:diagnostics=disabled")
    if audit is True: parts.append("PASS:audit=enabled")
    elif audit is False: parts.append("FAIL:audit=disabled")
    if cron_alert is True: parts.append("PASS:cronAlert=enabled")
    elif cron_alert is False: parts.append("WARN:cronAlert=disabled")
    if isinstance(suppressions, list) and len(suppressions) > 0:
        parts.append(f"WARN:suppressions={len(suppressions)} rules")
    print("|".join(parts) if parts else "none")
except Exception:
    print("error")
' "$SI4_OC_CONFIG" 2>/dev/null)
    if [[ "$SI4_DIAG" == "error" || "$SI4_DIAG" == "none" ]]; then
      skipx "SI-4-oc-diagnostics" "SI-4: Could not parse monitoring settings from $SI4_CONFIG_NAME"
    else
      IFS='|' read -ra SI4_ITEMS <<< "$SI4_DIAG"
      for item in "${SI4_ITEMS[@]}"; do
        SI4_LEVEL="${item%%:*}"
        SI4_MSG="${item#*:}"
        case "$SI4_LEVEL" in
          FAIL)
            failx "SI-4-oc-diagnostics" "SI-4: $SI4_MSG in $SI4_CONFIG_NAME, enable for monitoring coverage"
            ;;
          WARN)
            warnx "SI-4-oc-diagnostics" "SI-4: $SI4_MSG in $SI4_CONFIG_NAME, review for monitoring blind spots"
            ;;
          PASS)
            passx "SI-4-oc-diagnostics" "SI-4: $SI4_MSG in $SI4_CONFIG_NAME"
            ;;
        esac
      done
    fi
  else
    skipx "SI-4-oc-diagnostics" "SI-4: OpenClaw config not found, cannot check monitoring settings"
  fi
fi

# SI-6: Security Function Verification — confirm security services are still active
log "SI-6: Security function verification"
SI6_SERVICES_CHECKED=0
SI6_SERVICES_DOWN=""

# Check auditd
if platform_supports audit_daemon_active; then
  SI6_SERVICES_CHECKED=$((SI6_SERVICES_CHECKED + 1))
  if ! platform audit_daemon_active; then
    SI6_SERVICES_DOWN="${SI6_SERVICES_DOWN}${SI6_SERVICES_DOWN:+, }auditd"
  fi
fi

# Check UFW
if platform_supports firewall_active; then
  SI6_SERVICES_CHECKED=$((SI6_SERVICES_CHECKED + 1))
  if ! platform firewall_active; then
    SI6_SERVICES_DOWN="${SI6_SERVICES_DOWN}${SI6_SERVICES_DOWN:+, }ufw"
  fi
fi

# Check fail2ban
if platform_supports fail2ban_status; then
  SI6_SERVICES_CHECKED=$((SI6_SERVICES_CHECKED + 1))
  if ! platform service_active fail2ban; then
    SI6_SERVICES_DOWN="${SI6_SERVICES_DOWN}${SI6_SERVICES_DOWN:+, }fail2ban"
  fi
fi

# Check sshd (should be running if SSH is expected)
if platform_supports sshd_active; then
  SI6_SERVICES_CHECKED=$((SI6_SERVICES_CHECKED + 1))
  if ! platform sshd_active; then
    SI6_SERVICES_DOWN="${SI6_SERVICES_DOWN}${SI6_SERVICES_DOWN:+, }sshd"
  fi
fi

if [[ "$SI6_SERVICES_CHECKED" -eq 0 ]]; then
  skipx "SI-6-services-active" "SI-6: No verifiable security services on ${SARGE_OS_DESCRIPTION}"
elif [[ -z "$SI6_SERVICES_DOWN" ]]; then
  passx "SI-6-services-active" "SI-6: All $SI6_SERVICES_CHECKED security services are running (auditd, ufw, fail2ban, sshd as applicable)"
else
  failx "SI-6-services-active" "SI-6: Security services not running: $SI6_SERVICES_DOWN. Restart them or investigate why they stopped"
fi

# SI-6: Check if drift detection cron is configured (periodic security verification)
SI6_SARGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SI6_DRIFT_CRON=$(crontab -l 2>/dev/null | grep -c "drift" || true)
SI6_DRIFT_SCRIPT="$SI6_SARGE_DIR/drift/drift-cron.sh"
if [[ -f "$SI6_DRIFT_SCRIPT" ]]; then
  if [[ "$SI6_DRIFT_CRON" -gt 0 ]]; then
    passx "SI-6-drift-cron" "SI-6: Drift detection cron job is configured ($SI6_DRIFT_CRON entry/entries)"
  else
    warnx "SI-6-drift-cron" "SI-6: drift-cron.sh exists but no cron job references it. Add to crontab for periodic security verification"
  fi
else
  skipx "SI-6-drift-cron" "SI-6: drift-cron.sh not found at $SI6_DRIFT_SCRIPT"
fi
