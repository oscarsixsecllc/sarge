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
