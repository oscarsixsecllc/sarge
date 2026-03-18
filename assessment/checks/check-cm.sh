#!/usr/bin/env bash
# check-cm.sh — Configuration Management (CM) checks — NIST 800-53 Rev 5

SARGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# CM-2: Baseline configuration documented
log "CM-2: Baseline configuration"
if [[ -f "$SARGE_DIR/baseline/openclaw.json.baseline" ]]; then
  pass "CM-2: Sarge baseline config file exists"
else
  warn "CM-2: No Sarge baseline found at $SARGE_DIR/baseline/openclaw.json.baseline"
fi

# CM-6: Unattended security upgrades
log "CM-6: Automatic security updates"
if dpkg -l unattended-upgrades 2>/dev/null | grep -q "^ii"; then
  pass "CM-6: unattended-upgrades is installed"
  UA_CONF="/etc/apt/apt.conf.d/50unattended-upgrades"
  if [[ -f "$UA_CONF" ]] && grep -q "Unattended-Upgrade::Automatic-Reboot" "$UA_CONF" 2>/dev/null; then
    pass "CM-6: unattended-upgrades configured"
  else
    warn "CM-6: unattended-upgrades installed but configuration not verified — check $UA_CONF"
  fi
else
  fail "CM-6: unattended-upgrades not installed — sudo apt install unattended-upgrades"
fi

# CM-6: Pending security updates
log "CM-6: Pending updates"
PENDING=$(apt list --upgradable 2>/dev/null | grep -c "upgradable" || echo 0); PENDING=$(echo "$PENDING" | head -1 | tr -d "[:space:]")
if [[ "$PENDING" -eq 0 ]]; then
  pass "CM-6: No pending package updates"
elif [[ "$PENDING" -le 5 ]]; then
  warn "CM-6: $PENDING package updates pending — review and apply"
else
  fail "CM-6: $PENDING package updates pending — apply security updates immediately"
fi

# CM-7: Least functionality — unnecessary services
log "CM-7: Unnecessary services"
RISKY_SERVICES=("telnet" "rsh" "rlogin" "vsftpd" "pure-ftpd" "proftpd" "xinetd" "cups" "avahi-daemon")
for svc in "${RISKY_SERVICES[@]}"; do
  if systemctl is-active --quiet "$svc" 2>/dev/null; then
    fail "CM-7: Unnecessary/risky service is running: $svc"
  elif systemctl is-enabled --quiet "$svc" 2>/dev/null; then
    warn "CM-7: Unnecessary/risky service is enabled (not running): $svc"
  else
    pass "CM-7: $svc is not active or enabled"
  fi
done

# CM-7: SSH hardening
log "CM-7: SSH configuration"
if systemctl is-active --quiet ssh 2>/dev/null || systemctl is-active --quiet sshd 2>/dev/null; then
  SSHD_CONFIG="/etc/ssh/sshd_config"
  if [[ -f "$SSHD_CONFIG" ]]; then
    if grep -qiE "^PermitRootLogin\s+(no|prohibit-password)" "$SSHD_CONFIG" 2>/dev/null; then
      pass "CM-7: SSH PermitRootLogin is disabled or limited"
    else
      fail "CM-7: SSH PermitRootLogin should be 'no' or 'prohibit-password'"
    fi
    if grep -qiE "^PasswordAuthentication\s+no" "$SSHD_CONFIG" 2>/dev/null; then
      pass "CM-7: SSH PasswordAuthentication disabled (key-only)"
    else
      warn "CM-7: SSH PasswordAuthentication is not explicitly disabled — consider key-only auth"
    fi
  fi
fi
