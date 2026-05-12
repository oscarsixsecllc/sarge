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
    passx "SI-2-security-updates-low" "SI-2: No pending security updates"
  elif [[ "$SECURITY_UPDATES" -le 3 ]]; then
    warnx "SI-2-security-updates-low" "SI-2: $SECURITY_UPDATES security updates pending — apply soon"
  else
    failx "SI-2-security-updates-high" "SI-2: $SECURITY_UPDATES security updates pending — apply immediately"
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
