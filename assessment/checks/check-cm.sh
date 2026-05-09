#!/usr/bin/env bash
# check-cm.sh — Configuration Management (CM) checks — NIST 800-53 Rev 5
# Platform-specific data acquisition lives in lib/platforms/<os>.sh.

SARGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# CM-2: Baseline configuration documented
log "CM-2: Baseline configuration"
if [[ -f "$SARGE_DIR/baseline/openclaw.json.baseline" ]]; then
  passx "CM-2-no-baseline" "CM-2: Sarge baseline config file exists"
else
  warnx "CM-2-no-baseline" "CM-2: No Sarge baseline found at $SARGE_DIR/baseline/openclaw.json.baseline"
fi

# CM-6: Unattended security upgrades
log "CM-6: Automatic security updates"
if platform package_installed unattended-upgrades; then
  passx "CM-6-unattended-not-installed" "CM-6: unattended-upgrades is installed"
  UA_CONF=$(platform unattended_upgrades_config_path)
  if [[ -f "$UA_CONF" ]] && grep -q "Unattended-Upgrade::Automatic-Reboot" "$UA_CONF" 2>/dev/null; then
    passx "CM-6-unattended-not-configured" "CM-6: unattended-upgrades configured"
  else
    warnx "CM-6-unattended-not-configured" "CM-6: unattended-upgrades installed but configuration not verified — check $UA_CONF"
  fi
else
  failx "CM-6-unattended-not-installed" "CM-6: unattended-upgrades not installed — sudo apt install unattended-upgrades"
fi

# CM-6: Pending security updates
log "CM-6: Pending updates"
PENDING=$(platform pending_package_updates_count)
if [[ "$PENDING" -eq 0 ]]; then
  passx "CM-6-pending-updates-low" "CM-6: No pending package updates"
elif [[ "$PENDING" -le 5 ]]; then
  warnx "CM-6-pending-updates-low" "CM-6: $PENDING package updates pending — review and apply"
else
  failx "CM-6-pending-updates-high" "CM-6: $PENDING package updates pending — apply security updates immediately"
fi

# CM-7: Least functionality — unnecessary services
log "CM-7: Unnecessary services"
RISKY_SERVICES=("telnet" "rsh" "rlogin" "vsftpd" "pure-ftpd" "proftpd" "xinetd" "cups" "avahi-daemon")
for svc in "${RISKY_SERVICES[@]}"; do
  if platform service_active "$svc"; then
    failx "CM-7-risky-service-running" "CM-7: Unnecessary/risky service is running: $svc"
  elif platform service_enabled "$svc"; then
    warnx "CM-7-risky-service-enabled" "CM-7: Unnecessary/risky service is enabled (not running): $svc"
  else
    passx "CM-7-risky-service-running" "CM-7: $svc is not active or enabled"
  fi
done

# CM-7: SSH hardening
log "CM-7: SSH configuration"
if platform sshd_active; then
  SSHD_CONFIG=$(platform sshd_config_path)
  if [[ -f "$SSHD_CONFIG" ]]; then
    if grep -qiE "^PermitRootLogin\s+(no|prohibit-password)" "$SSHD_CONFIG" 2>/dev/null; then
      passx "CM-7-ssh-permit-root" "CM-7: SSH PermitRootLogin is disabled or limited"
    else
      failx "CM-7-ssh-permit-root" "CM-7: SSH PermitRootLogin should be 'no' or 'prohibit-password'"
    fi
    if grep -qiE "^PasswordAuthentication\s+no" "$SSHD_CONFIG" 2>/dev/null; then
      passx "CM-7-ssh-password-auth" "CM-7: SSH PasswordAuthentication disabled (key-only)"
    else
      warnx "CM-7-ssh-password-auth" "CM-7: SSH PasswordAuthentication is not explicitly disabled — consider key-only auth"
    fi
  fi
fi
