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
  # supported on modern OpenSSH everywhere). OpenSSH uses first-match
  # semantics: the first value obtained for a keyword wins. macOS Ventura+
  # places 'Include /etc/ssh/sshd_config.d/*' at the top of sshd_config,
  # so drop-in values take precedence over later entries in the main file.
  # Our check treats a match in ANY file as sufficient.
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

# CM-3: Configuration Change Control — is ~/.openclaw under version control?
#
# Two acceptable signals: the config directory itself is a git working
# tree, or Sarge's own drift-snapshot tracking (drift/snapshot.sh) has a
# baseline recorded so unreviewed changes are at least detectable.
log "CM-3: Configuration change control"
CM3_SNAPSHOT_DIR="${SARGE_SNAPSHOT_DIR:-$HOME/.sarge/snapshots}"
if [[ -d "$HOME/.openclaw/.git" ]]; then
  passx "CM-3-change-control" "CM-3: ~/.openclaw is under version control (.git present)"
elif [[ -e "$CM3_SNAPSHOT_DIR/latest.json" ]]; then
  passx "CM-3-change-control" "CM-3: Sarge drift-snapshot tracking is enabled ($CM3_SNAPSHOT_DIR/latest.json found)"
else
  warnx "CM-3-change-control" "CM-3: ~/.openclaw is not under version control and no Sarge drift snapshot was found — run drift/snapshot.sh or git-init ~/.openclaw to track configuration changes"
fi

# CM-5: Access Restrictions for Change — OpenClaw config file ownership
#
# Same openclaw.json -> config.json fallback used throughout check-ac.sh /
# check-ia.sh / check-sa.sh (issue #61).
log "CM-5: Access restrictions for change"
CM5_USER=$(whoami)
CM5_OC_CONFIG=""
for candidate in "$HOME/.openclaw/openclaw.json" "$HOME/.openclaw/config.json"; do
  if [[ -f "$candidate" ]]; then
    CM5_OC_CONFIG="$candidate"
    break
  fi
done
if [[ -n "$CM5_OC_CONFIG" ]]; then
  CM5_CONFIG_NAME=$(basename "$CM5_OC_CONFIG")
  CM5_OWNER=$(platform file_owner "$CM5_OC_CONFIG")
  if [[ "$CM5_OWNER" == "$CM5_USER" ]]; then
    passx "CM-5-config-owner" "CM-5: $CM5_CONFIG_NAME is owned by $CM5_USER (the agent account)"
  elif [[ "$CM5_OWNER" == "root" ]]; then
    failx "CM-5-config-owner" "CM-5: $CM5_CONFIG_NAME is owned by root, not the agent account ($CM5_USER) — the agent account cannot manage its own configuration under least-privilege change control"
  else
    warnx "CM-5-config-owner" "CM-5: $CM5_CONFIG_NAME is owned by $CM5_OWNER, not the current user ($CM5_USER) — verify this is intentional"
  fi
else
  skipx "CM-5-config-owner" "CM-5: OpenClaw config not found at ~/.openclaw/openclaw.json (or legacy ~/.openclaw/config.json)"
fi

# CM-8: System Component Inventory — Node.js runtime + MCP servers + plugins
#
# Informational: lists what's installed so operators can reconcile against
# an approved component list. Always PASS — absence of an inventory tool
# (jq/python3) is noted in the message rather than escalated, matching how
# SA-9 treats the same jq/python3 fallback (check-sa.sh).
log "CM-8: System component inventory"
CM8_NODE_VER=$(node --version 2>/dev/null || echo "not found")
CM8_OC_CONFIG=""
for candidate in "$HOME/.openclaw/openclaw.json" "$HOME/.openclaw/config.json"; do
  if [[ -f "$candidate" ]]; then
    CM8_OC_CONFIG="$candidate"
    break
  fi
done
CM8_MCP_COUNT="unknown"
CM8_PLUGIN_COUNT="unknown"
if [[ -n "$CM8_OC_CONFIG" ]] && command -v jq &>/dev/null; then
  CM8_MCP_COUNT=$(jq -r '(.mcp.servers // {}) | to_entries | map(select(.key | startswith("_") | not)) | length' "$CM8_OC_CONFIG" 2>/dev/null)
  CM8_PLUGIN_COUNT=$(jq -r '(.plugins.entries // .plugins // {}) | (if type=="object" then (keys|length) elif type=="array" then length else 0 end)' "$CM8_OC_CONFIG" 2>/dev/null)
fi
passx "CM-8-component-inventory" "CM-8: Node.js ${CM8_NODE_VER}, ${CM8_MCP_COUNT} MCP server(s), ${CM8_PLUGIN_COUNT} plugin(s) configured — review against the approved component list"

# CM-11: User-Installed Software — globally-installed npm packages
#
# Global npm packages sit outside the OpenClaw workspace tree and outside
# package.json-tracked dependencies, so they're a common source of
# unreviewed user-installed software. npm itself and anything with
# "openclaw" in the name are expected and excluded.
log "CM-11: User-installed software (global npm packages)"
if command -v npm &>/dev/null; then
  CM11_GLOBAL=$(npm list -g --depth=0 2>/dev/null | tail -n +2 | sed -E 's/^[├└──│ ]+//' | grep -vE '^\s*$')
  CM11_UNEXPECTED=$(echo "$CM11_GLOBAL" | grep -viE '^npm@|openclaw' || true)
  if [[ -z "$CM11_UNEXPECTED" ]]; then
    passx "CM-11-global-npm-packages" "CM-11: No unexpected globally-installed npm packages found outside the OpenClaw tree"
  else
    warnx "CM-11-global-npm-packages" "CM-11: Unexpected global npm packages found — review: $(echo "$CM11_UNEXPECTED" | tr '\n' '|')"
  fi
else
  skipx "CM-11-global-npm-packages" "CM-11: npm not found on PATH — global package inventory check skipped"
fi
