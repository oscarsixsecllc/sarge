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
if ! platform_supports package_installed; then
  skipx "CM-6-unattended-not-installed" "CM-6: unattended-upgrades is an apt construct; on ${SARGE_OS_DESCRIPTION} system updates are delegated to softwareupdate / MDM (Jamf, Intune, Kandji)"
elif platform package_installed unattended-upgrades; then
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
if ! platform_supports pending_package_updates_count; then
  skipx "CM-6-pending-updates-low" "CM-6: pending-package counting via apt is not applicable on ${SARGE_OS_DESCRIPTION}; review 'softwareupdate --list' or MDM compliance reports"
else
  PENDING=$(platform pending_package_updates_count)
  if [[ "$PENDING" -eq 0 ]]; then
    passx "CM-6-pending-updates-low" "CM-6: No pending package updates"
  elif [[ "$PENDING" -le 5 ]]; then
    warnx "CM-6-pending-updates-low" "CM-6: $PENDING package updates pending — review and apply"
  else
    failx "CM-6-pending-updates-high" "CM-6: $PENDING package updates pending — apply security updates immediately"
  fi
fi

# CM-7: Least functionality — unnecessary services
log "CM-7: Unnecessary services"
if ! platform_supports linux_legacy_service_names; then
  skipx "CM-7-risky-service-running" "CM-7: legacy Linux service inventory (telnet/rsh/cups/...) does not map to launchd labels on ${SARGE_OS_DESCRIPTION}; review System Settings ▸ Sharing for enabled services"
else
  while IFS= read -r svc; do
    [[ -z "$svc" ]] && continue
    if platform service_active "$svc"; then
      failx "CM-7-risky-service-running" "CM-7: Unnecessary/risky service is running: $svc"
    elif platform service_enabled "$svc"; then
      warnx "CM-7-risky-service-enabled" "CM-7: Unnecessary/risky service is enabled (not running): $svc"
    else
      passx "CM-7-risky-service-running" "CM-7: $svc is not active or enabled"
    fi
  done < <(platform linux_legacy_service_names)
fi

# CM-7: SSH hardening
log "CM-7: SSH configuration"
if platform sshd_active; then
  SSHD_CONFIG=$(platform sshd_config_path)
  # Build a list of config files to search: the main sshd_config plus any
  # drop-ins in sshd_config.d/ (used by harden-ssh-macos.sh on macOS and
  # supported on modern OpenSSH everywhere). sshd evaluates drop-ins in
  # lexical order; the LAST match wins, so if the main config says
  # "PermitRootLogin yes" and a drop-in says "no", sshd uses "no". Our
  # check mirrors this by treating a match in ANY file as sufficient.
  _SSHD_CONF_FILES=("$SSHD_CONFIG")
  SSHD_DROPIN_DIR="${SSHD_CONFIG%/*}/sshd_config.d"
  if [[ -d "$SSHD_DROPIN_DIR" ]]; then
    while IFS= read -r f; do
      _SSHD_CONF_FILES+=("$f")
    done < <(find "$SSHD_DROPIN_DIR" -maxdepth 1 -name '*.conf' -type f 2>/dev/null | sort)
  fi
  if [[ ${#_SSHD_CONF_FILES[@]} -gt 0 ]]; then
    if grep -qiE "^PermitRootLogin\s+(no|prohibit-password)" "${_SSHD_CONF_FILES[@]}" 2>/dev/null; then
      passx "CM-7-ssh-permit-root" "CM-7: SSH PermitRootLogin is disabled or limited"
    else
      failx "CM-7-ssh-permit-root" "CM-7: SSH PermitRootLogin should be 'no' or 'prohibit-password'"
    fi
    if grep -qiE "^PasswordAuthentication\s+no" "${_SSHD_CONF_FILES[@]}" 2>/dev/null; then
      passx "CM-7-ssh-password-auth" "CM-7: SSH PasswordAuthentication disabled (key-only)"
    else
      warnx "CM-7-ssh-password-auth" "CM-7: SSH PasswordAuthentication is not explicitly disabled — consider key-only auth"
    fi
  fi
fi
