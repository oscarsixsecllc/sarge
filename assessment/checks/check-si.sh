#!/usr/bin/env bash
# check-si.sh — System & Information Integrity (SI) — partial — NIST 800-53 Rev 5

# SI-2: Flaw Remediation — package updates
log "SI-2: Flaw remediation"
SECURITY_UPDATES=$(apt list --upgradable 2>/dev/null | grep -ic "security" || echo 0); SECURITY_UPDATES=$(echo "$SECURITY_UPDATES" | head -1 | tr -d "[:space:]")
if [[ "$SECURITY_UPDATES" -eq 0 ]]; then
  pass "SI-2: No pending security updates"
elif [[ "$SECURITY_UPDATES" -le 3 ]]; then
  warn "SI-2: $SECURITY_UPDATES security updates pending — apply soon"
else
  fail "SI-2: $SECURITY_UPDATES security updates pending — apply immediately"
fi

# SI-2: Kernel version check
log "SI-2: Kernel currency"
KERNEL=$(uname -r)
pass "SI-2: Running kernel: $KERNEL (manual review recommended for currency)"

# SI-3: Malicious code protection
log "SI-3: Malicious code protection"
if command -v clamscan &>/dev/null || command -v clamav &>/dev/null; then
  pass "SI-3: ClamAV is installed"
  if systemctl is-active --quiet clamav-daemon 2>/dev/null; then
    pass "SI-3: ClamAV daemon is running"
  else
    warn "SI-3: ClamAV installed but daemon not running — consider enabling for real-time protection"
  fi
  # Check freshclam (signature updates)
  if systemctl is-active --quiet clamav-freshclam 2>/dev/null; then
    pass "SI-3: ClamAV signature updater (freshclam) is running"
  else
    warn "SI-3: freshclam not running — ClamAV signatures may be outdated"
  fi
else
  warn "SI-3: ClamAV not installed — consider installing for malware detection: sudo apt install clamav"
fi

# SI-2: fail2ban (intrusion/brute-force protection)
log "SI-2/SI-3: Brute force protection"
if systemctl is-active --quiet fail2ban 2>/dev/null; then
  pass "SI-3: fail2ban is running"
  F2B_STATUS=$(fail2ban-client status 2>/dev/null || sudo fail2ban-client status 2>/dev/null || echo "")
  if [[ -n "$F2B_STATUS" ]]; then
    JAILS=$(echo "$F2B_STATUS" | grep "Jail list" | sed 's/.*Jail list:\s*//')
    pass "SI-3: fail2ban active jails: ${JAILS:-none listed}"
  fi
else
  fail "SI-3: fail2ban is not running — run harden-fail2ban.sh to configure"
fi

# SI-7: Software integrity — verify Sarge script checksums if available
log "SI-7: Software integrity"
SARGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECKSUM_FILE="$SARGE_DIR/CHECKSUMS.sha256"
if [[ -f "$CHECKSUM_FILE" ]]; then
  if sha256sum --check "$CHECKSUM_FILE" --quiet 2>/dev/null; then
    pass "SI-7: Sarge script checksums verified"
  else
    fail "SI-7: Sarge script checksum verification FAILED — scripts may have been modified"
  fi
else
  skip "SI-7: No CHECKSUMS.sha256 file found — generate with: sha256sum scripts/*.sh assessment/**/*.sh > CHECKSUMS.sha256"
fi
