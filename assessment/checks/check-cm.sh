#!/usr/bin/env bash
# check-cm.sh — Configuration Management (CM) checks — NIST 800-53 Rev 5
# Platform-specific data acquisition lives in lib/platforms/<os>.sh.

SARGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# CM-2: Baseline configuration documented
log "CM-2: Baseline configuration"
BASELINE_FILE="$SARGE_DIR/baseline/openclaw.json.baseline"
if [[ -f "$BASELINE_FILE" ]]; then
  passx "CM-2-no-baseline" "CM-2: Sarge baseline config file exists"

  # CM-2: Baseline schema-version pin (issue #63). The baseline should
  # declare which OpenClaw release its schema was authored against so
  # drift tooling can refuse or warn on stale comparisons. Uses python3
  # (available on every supported platform) to avoid a jq dependency.
  BASELINE_OC_VER=$(python3 -c "
import json, sys
try:
    with open('$BASELINE_FILE') as fh:
        cfg = json.load(fh)
    print(cfg.get('_openclawVersion', ''))
except Exception:
    print('')
" 2>/dev/null)

  if [[ -z "$BASELINE_OC_VER" ]]; then
    warnx "CM-2-baseline-version-pin-missing" "CM-2: baseline is missing _openclawVersion schema-version pin"
  else
    passx "CM-2-baseline-version-pin-missing" "CM-2: baseline pins _openclawVersion=${BASELINE_OC_VER}"

    # CM-2: Compare pinned version against the running OpenClaw. Skip
    # cleanly when openclaw is not on PATH (Sarge can run against a
    # non-OpenClaw host too). Extract the version token; `openclaw --version`
    # emits "OpenClaw 2026.7.1-2 (hash)" — take field 2.
    if command -v openclaw &>/dev/null; then
      RUNNING_OC_VER=$(openclaw --version 2>/dev/null | awk 'NR==1 {print $2}')
      if [[ -z "$RUNNING_OC_VER" ]]; then
        warnx "CM-2-baseline-version-drift" "CM-2: could not parse running OpenClaw version (openclaw --version output unexpected)"
      else
        # Compare major.minor. Format: YYYY.M[.P[-B]] — split on dot,
        # take first two fields. Different major or minor > 1 apart = drift.
        _oc_ver_parts() {
          echo "$1" | awk -F'[.-]' '{printf "%s %s\n", $1, $2}'
        }
        read -r B_MAJ B_MIN < <(_oc_ver_parts "$BASELINE_OC_VER")
        read -r R_MAJ R_MIN < <(_oc_ver_parts "$RUNNING_OC_VER")
        if [[ "$B_MAJ" != "$R_MAJ" ]]; then
          warnx "CM-2-baseline-version-drift" "CM-2: baseline pin ($BASELINE_OC_VER) and running OpenClaw ($RUNNING_OC_VER) differ in major version — regenerate baseline"
        elif [[ -n "$B_MIN" && -n "$R_MIN" ]] && (( B_MIN > R_MIN + 1 || R_MIN > B_MIN + 1 )); then
          warnx "CM-2-baseline-version-drift" "CM-2: baseline pin ($BASELINE_OC_VER) and running OpenClaw ($RUNNING_OC_VER) differ by more than one minor release — regenerate baseline"
        else
          passx "CM-2-baseline-version-drift" "CM-2: baseline pin ($BASELINE_OC_VER) is within one minor of running OpenClaw ($RUNNING_OC_VER)"
        fi
      fi
    fi
  fi
else
  warnx "CM-2-no-baseline" "CM-2: No Sarge baseline found at $BASELINE_FILE"
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

# CM-10: Software Usage Restrictions — license/allowlist check
#
# Checks whether a Sarge software-allowlist file exists and whether
# installed packages contain any known restrictively-licensed software.
# This is a lightweight signal: a full license audit requires a dedicated
# tool (e.g. license_finder, fossa). Sarge flags the absence of a policy
# file and spots common non-permissive indicators in dpkg descriptions.
log "CM-10: Software Usage Restrictions"
CM10_ALLOWLIST="${SARGE_DIR}/baseline/software-allowlist.txt"
if [[ -f "$CM10_ALLOWLIST" ]]; then
  passx "CM-10-allowlist-present" "CM-10: Software allowlist is present at $CM10_ALLOWLIST"
  # Cross-check: are there installed packages NOT on the allowlist?
  if command -v dpkg &>/dev/null; then
    CM10_INSTALLED=$(dpkg --get-selections 2>/dev/null | awk '/\tinstall$/{print $1}')
    CM10_UNLISTED=""
    CM10_COUNT=0
    while IFS= read -r pkg; do
      [[ -z "$pkg" ]] && continue
      if ! grep -qxF "$pkg" "$CM10_ALLOWLIST" 2>/dev/null; then
        CM10_COUNT=$((CM10_COUNT + 1))
        if [[ $CM10_COUNT -le 5 ]]; then
          CM10_UNLISTED="${CM10_UNLISTED:+$CM10_UNLISTED, }${pkg}"
        fi
      fi
    done <<< "$CM10_INSTALLED"
    if [[ $CM10_COUNT -eq 0 ]]; then
      passx "CM-10-unlisted-packages" "CM-10: All installed packages are on the software allowlist"
    else
      warnx "CM-10-unlisted-packages" "CM-10: ${CM10_COUNT} installed package(s) not on software allowlist — first 5: ${CM10_UNLISTED}"
    fi
  fi
else
  warnx "CM-10-allowlist-present" "CM-10: No software allowlist found at $CM10_ALLOWLIST — create one to enforce software usage restrictions"
fi

# CM-12: Information Location — data-at-rest location mapping
#
# Enumerates known data-storage locations for an OpenClaw deployment so
# operators know where sensitive data lives. Informational: always PASS
# with a summary of discovered locations (matches the CM-8 approach).
log "CM-12: Information Location"
CM12_LOCATIONS=""
CM12_COUNT=0
# OpenClaw workspace
if [[ -d "$HOME/.openclaw" ]]; then
  CM12_SIZE=$(du -sh "$HOME/.openclaw" 2>/dev/null | awk '{print $1}')
  CM12_LOCATIONS="${CM12_LOCATIONS}~/.openclaw(${CM12_SIZE:-?})"
  CM12_COUNT=$((CM12_COUNT + 1))
fi
# Sarge snapshots/runs
SARGE_DATA_DIR="${SARGE_SNAPSHOT_DIR:-$HOME/.sarge}"
if [[ -d "$SARGE_DATA_DIR" ]]; then
  CM12_SARGE_SIZE=$(du -sh "$SARGE_DATA_DIR" 2>/dev/null | awk '{print $1}')
  CM12_LOCATIONS="${CM12_LOCATIONS:+$CM12_LOCATIONS, }~/.sarge(${CM12_SARGE_SIZE:-?})"
  CM12_COUNT=$((CM12_COUNT + 1))
fi
# Secrets directory
if [[ -d "$HOME/.openclaw/secrets" ]]; then
  CM12_SEC_COUNT=$(find "$HOME/.openclaw/secrets" -maxdepth 1 -type f 2>/dev/null | wc -l)
  CM12_LOCATIONS="${CM12_LOCATIONS:+$CM12_LOCATIONS, }secrets(${CM12_SEC_COUNT} files)"
fi
# Media directory (if media.ttlHours is in play)
MEDIA_DIR="$HOME/.openclaw/media"
if [[ -d "$MEDIA_DIR" ]]; then
  CM12_MEDIA_SIZE=$(du -sh "$MEDIA_DIR" 2>/dev/null | awk '{print $1}')
  CM12_LOCATIONS="${CM12_LOCATIONS:+$CM12_LOCATIONS, }media(${CM12_MEDIA_SIZE:-?})"
  CM12_COUNT=$((CM12_COUNT + 1))
fi
# Transcript/log directories
for tdir in "$HOME/.openclaw/transcripts" "$HOME/.openclaw/logs"; do
  if [[ -d "$tdir" ]]; then
    tname=$(basename "$tdir")
    tsize=$(du -sh "$tdir" 2>/dev/null | awk '{print $1}')
    CM12_LOCATIONS="${CM12_LOCATIONS:+$CM12_LOCATIONS, }${tname}(${tsize:-?})"
    CM12_COUNT=$((CM12_COUNT + 1))
  fi
done
if [[ $CM12_COUNT -gt 0 ]]; then
  passx "CM-12-data-locations" "CM-12: Data-at-rest locations: $CM12_LOCATIONS — verify each is backed up and access-controlled per policy"
else
  warnx "CM-12-data-locations" "CM-12: No standard OpenClaw data directories found — verify data storage locations"
fi
