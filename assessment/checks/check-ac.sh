#!/usr/bin/env bash
# check-ac.sh — Access Control (AC) checks — NIST 800-53 Rev 5
# Platform-specific data acquisition lives in lib/platforms/<os>.sh; this
# file contains 800-53 control assertions and verdict logic only.

# AC-2: Account Management
log "AC-2: Account Management"
NOPASSWD_USERS=$(platform users_with_empty_passwords)
if [[ -z "$NOPASSWD_USERS" ]]; then
  passx "AC-2-empty-password" "AC-2: No accounts with empty passwords found"
else
  failx "AC-2-empty-password" "AC-2: Accounts with empty passwords: $NOPASSWD_USERS"
fi

ROOT_SHELLS=$(platform uid_zero_non_root_users)
if [[ -z "$ROOT_SHELLS" ]]; then
  passx "AC-2-uid-zero" "AC-2: No non-root accounts with UID 0"
else
  failx "AC-2-uid-zero" "AC-2: Non-root accounts with UID 0: $ROOT_SHELLS"
fi

# AC-3: Access Enforcement — filesystem permissions on OpenClaw workspace
if [[ "${SARGE_HOST_ONLY:-0}" != "1" ]]; then
  log "AC-3: Access Enforcement"
  OC_DIR="$HOME/.openclaw"
  if [[ -d "$OC_DIR" ]]; then
    OC_PERM=$(platform file_perm "$OC_DIR")
    if [[ "$OC_PERM" == "700" ]]; then
      passx "AC-3-openclaw-dir-perm" "AC-3: ~/.openclaw permissions are 700"
    else
      failx "AC-3-openclaw-dir-perm" "AC-3: ~/.openclaw permissions are $OC_PERM — should be 700"
    fi

    SECRETS_DIR="$OC_DIR/secrets"
    if [[ -d "$SECRETS_DIR" ]]; then
      S_PERM=$(platform file_perm "$SECRETS_DIR")
      if [[ "$S_PERM" == "700" ]]; then
        passx "AC-3-secrets-dir-perm" "AC-3: ~/.openclaw/secrets permissions are 700"
      else
        failx "AC-3-secrets-dir-perm" "AC-3: ~/.openclaw/secrets permissions are $S_PERM — should be 700"
      fi

      while IFS= read -r -d '' f; do
        F_PERM=$(platform file_perm "$f")
        if [[ "$F_PERM" == "600" ]]; then
          passx "AC-3-secret-file-perm" "AC-3: Secret file $f is 600"
        else
          failx "AC-3-secret-file-perm" "AC-3: Secret file $f is $F_PERM — should be 600"
        fi
      done < <(find "$SECRETS_DIR" -maxdepth 1 -type f -print0 2>/dev/null)
    else
      skipx "AC-3-secrets-dir-perm" "AC-3: No secrets directory found at $SECRETS_DIR"
    fi
  else
    skipx "AC-3-openclaw-dir-perm" "AC-3: No ~/.openclaw directory found"
  fi
fi

# AC-6: Least Privilege — sudo configuration
log "AC-6: Least Privilege"
if platform passwordless_sudo_for_current_user; then
  warnx "AC-6-passwordless-sudo" "AC-6: Current user has passwordless sudo — review if intentional"
else
  passx "AC-6-passwordless-sudo" "AC-6: sudo requires password (not passwordless)"
fi

CURRENT_USER=$(whoami)
ADMIN_GROUP=$(platform admin_group_name)
if platform user_in_admin_group "$CURRENT_USER"; then
  warnx "AC-6-user-in-sudo-group" "AC-6: User $CURRENT_USER is in the $ADMIN_GROUP group — confirm this is the admin account, not the service account"
else
  passx "AC-6-user-in-sudo-group" "AC-6: User $CURRENT_USER is not in the $ADMIN_GROUP group"
fi

# AC-17: Remote Access
log "AC-17: Remote Access"
if platform firewall_command_available; then
  if platform firewall_active; then
    passx "AC-17-ufw-inactive" "AC-17: Firewall is active"
  else
    failx "AC-17-ufw-inactive" "AC-17: Firewall is not active — remote access uncontrolled"
  fi
else
  warnx "AC-17-ufw-not-installed" "AC-17: Firewall command not available — verify alternative firewall is in place"
fi

LISTENING=$(platform externally_listening_ports || true)
if [[ -z "$LISTENING" ]]; then
  passx "AC-17-external-ports" "AC-17: No unexpected externally-listening ports detected"
else
  warnx "AC-17-external-ports" "AC-17: Externally-listening ports found — review: $(echo "$LISTENING" | tr '\n' ' ')"
fi

# AC-4: Information Flow Enforcement — OpenClaw outbound network restriction
#
# Live OpenClaw 2026.7.x writes runtime config to `openclaw.json`; older
# installs used `config.json`. Same fallback probe as check-ia.sh / check-sa.sh
# (issue #61).
log "AC-4: Information Flow Enforcement"
AC_OC_CONFIG=""
for candidate in "$HOME/.openclaw/openclaw.json" "$HOME/.openclaw/config.json"; do
  if [[ -f "$candidate" ]]; then
    AC_OC_CONFIG="$candidate"
    break
  fi
done
if [[ -n "$AC_OC_CONFIG" ]]; then
  AC_CONFIG_NAME=$(basename "$AC_OC_CONFIG")
  if grep -qE '"allowedHosts"' "$AC_OC_CONFIG" 2>/dev/null; then
    passx "AC-4-network-isolation" "AC-4: network.allowedHosts is configured in $AC_CONFIG_NAME"
  else
    warnx "AC-4-network-isolation" "AC-4: No network.allowedHosts restriction found in $AC_CONFIG_NAME — outbound network access is unrestricted"
  fi
else
  skipx "AC-4-network-isolation" "AC-4: OpenClaw config not found at ~/.openclaw/openclaw.json (or legacy ~/.openclaw/config.json)"
fi

# AC-5: Separation of Duties — agent account vs. system admin account
log "AC-5: Separation of Duties"
AC5_USER=$(whoami)
AC5_ADMIN_GROUP=$(platform admin_group_name)
if [[ -d "$HOME/.openclaw" ]] && platform user_in_admin_group "$AC5_USER"; then
  warnx "AC-5-agent-admin-same-account" "AC-5: $AC5_USER runs OpenClaw and is a member of the $AC5_ADMIN_GROUP group — agent and system-admin accounts should be separated"
else
  passx "AC-5-agent-admin-same-account" "AC-5: OpenClaw account ($AC5_USER) is not in the $AC5_ADMIN_GROUP admin group, or no OpenClaw install detected"
fi

# AC-7: Unsuccessful Logon Attempts — pam_faillock lockout policy
log "AC-7: Unsuccessful Logon Attempts"
if ! platform_supports pam_faillock_configured; then
  skipx "AC-7-faillock-not-configured" "AC-7: pam_faillock is a Linux-PAM construct; on ${SARGE_OS_DESCRIPTION} account lockout is enforced via pwpolicy / MDM account policies"
elif platform pam_faillock_configured; then
  AC7_DENY=$(platform faillock_value deny)
  if [[ -n "$AC7_DENY" && "$AC7_DENY" -ge 3 ]]; then
    passx "AC-7-faillock-deny" "AC-7: pam_faillock deny is $AC7_DENY (lockout after $AC7_DENY attempts)"
  else
    warnx "AC-7-faillock-deny" "AC-7: pam_faillock deny is ${AC7_DENY:-unset} — recommend 3 or more failed attempts before lockout"
  fi
else
  failx "AC-7-faillock-not-configured" "AC-7: pam_faillock not referenced in common-auth — no unsuccessful-logon lockout configured"
fi

# AC-8: System Use Notification — SSH login banner
#
# Reuses the sshd_config + sshd_config.d drop-in discovery pattern from
# CM-7's SSH section (check-cm.sh) — see that file's comment for the
# first-match-wins rationale.
log "AC-8: System Use Notification"
if platform sshd_active; then
  AC8_SSHD_CONFIG=$(platform sshd_config_path)
  _AC8_SSHD_CONF_FILES=("$AC8_SSHD_CONFIG")
  AC8_SSHD_DROPIN_DIR="${AC8_SSHD_CONFIG%/*}/sshd_config.d"
  if [[ -d "$AC8_SSHD_DROPIN_DIR" ]]; then
    while IFS= read -r f; do
      _AC8_SSHD_CONF_FILES+=("$f")
    done < <(find "$AC8_SSHD_DROPIN_DIR" -maxdepth 1 -name '*.conf' -type f 2>/dev/null | sort)
  fi
  if grep -qiE "^Banner\s+\S" "${_AC8_SSHD_CONF_FILES[@]}" 2>/dev/null; then
    passx "AC-8-ssh-banner" "AC-8: SSH login Banner is configured"
  else
    warnx "AC-8-ssh-banner" "AC-8: No SSH Banner directive found — configure a system-use notification banner"
  fi
else
  skipx "AC-8-ssh-banner" "AC-8: SSH server not active — banner check not applicable"
fi

# AC-10: Concurrent Session Control — limits.conf maxlogins
log "AC-10: Concurrent Session Control"
AC10_LIMITS_CONF="/etc/security/limits.conf"
if [[ -f "$AC10_LIMITS_CONF" ]] && grep -qE "maxlogins" "$AC10_LIMITS_CONF" 2>/dev/null; then
  passx "AC-10-maxlogins" "AC-10: maxlogins limit configured in $AC10_LIMITS_CONF"
else
  warnx "AC-10-maxlogins" "AC-10: No maxlogins limit configured in $AC10_LIMITS_CONF — concurrent sessions are unbounded"
fi

# AC-11: Device Lock — shell session idle timeout (TMOUT)
log "AC-11: Device Lock"
AC11_TMOUT=$(platform session_timeout_setting)
if [[ -n "$AC11_TMOUT" ]]; then
  passx "AC-11-session-timeout" "AC-11: Session timeout is configured: $AC11_TMOUT"
else
  warnx "AC-11-session-timeout" "AC-11: No TMOUT session timeout configured — idle sessions do not auto-lock"
fi

# AC-12: Session Termination — OpenClaw session idle timeout
log "AC-12: Session Termination"
AC_OC_CONFIG=""
for candidate in "$HOME/.openclaw/openclaw.json" "$HOME/.openclaw/config.json"; do
  if [[ -f "$candidate" ]]; then
    AC_OC_CONFIG="$candidate"
    break
  fi
done
if [[ -n "$AC_OC_CONFIG" ]]; then
  AC_CONFIG_NAME=$(basename "$AC_OC_CONFIG")
  AC12_IDLE_MIN=$(grep -oE '"idleTimeoutMinutes"[[:space:]]*:[[:space:]]*[0-9]+' "$AC_OC_CONFIG" 2>/dev/null | grep -oE '[0-9]+$' | head -1)
  if [[ -n "$AC12_IDLE_MIN" ]]; then
    passx "AC-12-session-idle-timeout" "AC-12: sessions.idleTimeoutMinutes is $AC12_IDLE_MIN in $AC_CONFIG_NAME"
  else
    warnx "AC-12-session-idle-timeout" "AC-12: sessions.idleTimeoutMinutes not set in $AC_CONFIG_NAME — sessions may never auto-terminate"
  fi
else
  skipx "AC-12-session-idle-timeout" "AC-12: OpenClaw config not found at ~/.openclaw/openclaw.json (or legacy ~/.openclaw/config.json)"
fi

# AC-14: Permitted Actions Without Identification or Authentication
log "AC-14: Permitted Actions Without Identification"
AC_OC_CONFIG=""
for candidate in "$HOME/.openclaw/openclaw.json" "$HOME/.openclaw/config.json"; do
  if [[ -f "$candidate" ]]; then
    AC_OC_CONFIG="$candidate"
    break
  fi
done
if [[ -n "$AC_OC_CONFIG" ]]; then
  AC_CONFIG_NAME=$(basename "$AC_OC_CONFIG")
  AC14_AUTH_ENABLED=""
  if command -v jq &>/dev/null; then
    AC14_AUTH_ENABLED=$(jq -r '.auth.enabled // empty' "$AC_OC_CONFIG" 2>/dev/null)
  elif command -v python3 &>/dev/null; then
    AC14_AUTH_ENABLED=$(python3 -c '
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    v = (d.get("auth") or {}).get("enabled")
    if v is not None:
        print(str(v).lower())
except Exception:
    pass
' "$AC_OC_CONFIG" 2>/dev/null)
  fi
  if [[ "$AC14_AUTH_ENABLED" == "false" ]]; then
    failx "AC-14-auth-disabled" "AC-14: OpenClaw auth.enabled is false in $AC_CONFIG_NAME — the gateway permits actions without identification"
  elif [[ "$AC14_AUTH_ENABLED" == "true" ]]; then
    passx "AC-14-auth-disabled" "AC-14: OpenClaw auth.enabled is true in $AC_CONFIG_NAME"
  else
    warnx "AC-14-auth-disabled" "AC-14: No explicit auth.enabled found in $AC_CONFIG_NAME — verify unauthenticated access is not permitted"
  fi
else
  skipx "AC-14-auth-disabled" "AC-14: OpenClaw config not found at ~/.openclaw/openclaw.json (or legacy ~/.openclaw/config.json)"
fi

# AC-2(3): Disable Inactive Accounts — lastlog idle check
#
# Checks for local accounts that have not logged in for 90+ days and are
# not system accounts (UID >= 1000). Headless service accounts that never
# log in interactively (e.g. www-data) are excluded by UID threshold.
log "AC-2(3): Disable Inactive Accounts"
if command -v lastlog &>/dev/null; then
  # lastlog outputs: Username  Port  From  Latest
  # "**Never logged in**" appears for accounts with no login record.
  # We flag non-system accounts (UID >= 1000) that have NEVER logged in
  # AND are not locked/expired. Truly idle accounts (logged in 90+ days
  # ago) are flagged as well.
  AC23_STALE=""
  while IFS= read -r line; do
    local_user=$(echo "$line" | awk '{print $1}')
    [[ -z "$local_user" || "$local_user" == "Username" ]] && continue
    local_uid=$(id -u "$local_user" 2>/dev/null) || continue
    [[ "$local_uid" -lt 1000 ]] && continue
    # Skip locked accounts (password field starts with ! or *)
    local_shadow=$(sudo getent shadow "$local_user" 2>/dev/null | cut -d: -f2) || true
    [[ "$local_shadow" == "!"* || "$local_shadow" == "*" ]] && continue
    if echo "$line" | grep -q "Never logged in"; then
      AC23_STALE="${AC23_STALE:+$AC23_STALE, }${local_user}(never)"
    else
      # Parse the date from lastlog output and check if > 90 days ago
      last_date=$(echo "$line" | awk '{for(i=4;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/ *$//')
      if [[ -n "$last_date" ]]; then
        last_epoch=$(date -d "$last_date" +%s 2>/dev/null) || continue
        now_epoch=$(date +%s)
        days_ago=$(( (now_epoch - last_epoch) / 86400 ))
        if [[ "$days_ago" -ge 90 ]]; then
          AC23_STALE="${AC23_STALE:+$AC23_STALE, }${local_user}(${days_ago}d)"
        fi
      fi
    fi
  done < <(lastlog 2>/dev/null)
  if [[ -z "$AC23_STALE" ]]; then
    passx "AC-2-3-inactive-accounts" "AC-2(3): No inactive local accounts (>90 days) found"
  else
    warnx "AC-2-3-inactive-accounts" "AC-2(3): Inactive accounts found: $AC23_STALE — review and disable or remove"
  fi
else
  skipx "AC-2-3-inactive-accounts" "AC-2(3): lastlog command not available — cannot check account activity"
fi

# AC-20: Use of External Systems — MCP servers and plugins pointing to external endpoints
#
# Enumerates configured MCP servers and plugin entries in openclaw.json
# that reference external URLs/hosts. Informational: always PASS with
# a summary so operators can reconcile against their approved-external-
# systems list (mirrors the CM-8 / SA-9 approach).
log "AC-20: Use of External Systems"
AC20_OC_CONFIG=""
for candidate in "$HOME/.openclaw/openclaw.json" "$HOME/.openclaw/config.json"; do
  if [[ -f "$candidate" ]]; then
    AC20_OC_CONFIG="$candidate"
    break
  fi
done
if [[ -n "$AC20_OC_CONFIG" ]]; then
  AC20_CONFIG_NAME=$(basename "$AC20_OC_CONFIG")
  AC20_EXTERNAL_COUNT="unknown"
  if command -v python3 &>/dev/null; then
    AC20_EXTERNAL_COUNT=$(python3 -c '
import json, sys, re
try:
    with open(sys.argv[1]) as fh:
        cfg = json.load(fh)
    count = 0
    # MCP servers with external URLs or non-local commands
    servers = (cfg.get("mcp") or {}).get("servers") or {}
    for name, srv in servers.items():
        if name.startswith("_"):
            continue
        url = (srv.get("url") or srv.get("command") or "")
        if re.search(r"https?://", str(url)):
            count += 1
    # Plugin entries with external URLs
    plugins = (cfg.get("plugins") or {}).get("entries") or cfg.get("plugins") or {}
    if isinstance(plugins, dict):
        for name, plg in plugins.items():
            url = str(plg) if isinstance(plg, str) else (plg.get("url") or "")
            if re.search(r"https?://", url):
                count += 1
    print(count)
except Exception:
    print("unknown")
' "$AC20_OC_CONFIG" 2>/dev/null)
  fi
  passx "AC-20-external-systems" "AC-20: ${AC20_EXTERNAL_COUNT} external MCP server(s)/plugin(s) detected in $AC20_CONFIG_NAME — reconcile against approved external systems list"
else
  skipx "AC-20-external-systems" "AC-20: OpenClaw config not found at ~/.openclaw/openclaw.json (or legacy ~/.openclaw/config.json)"
fi

# AC-22: Publicly Accessible Content — web interface and exposed endpoints
#
# Checks whether the OpenClaw web UI is enabled and whether any HTTP
# endpoints are configured for public access. A running web interface
# means the host serves content that may be reachable from the network.
log "AC-22: Publicly Accessible Content"
AC22_OC_CONFIG=""
for candidate in "$HOME/.openclaw/openclaw.json" "$HOME/.openclaw/config.json"; do
  if [[ -f "$candidate" ]]; then
    AC22_OC_CONFIG="$candidate"
    break
  fi
done
if [[ -n "$AC22_OC_CONFIG" ]]; then
  AC22_CONFIG_NAME=$(basename "$AC22_OC_CONFIG")
  AC22_WEB_ENABLED=""
  AC22_HTTP_ENDPOINTS=""
  if command -v python3 &>/dev/null; then
    AC22_WEB_ENABLED=$(python3 -c '
import json, sys
try:
    with open(sys.argv[1]) as fh:
        cfg = json.load(fh)
    web = (cfg.get("web") or {}).get("enabled")
    print(str(web).lower() if web is not None else "unset")
except Exception:
    print("unknown")
' "$AC22_OC_CONFIG" 2>/dev/null)
    AC22_HTTP_ENDPOINTS=$(python3 -c '
import json, sys
try:
    with open(sys.argv[1]) as fh:
        cfg = json.load(fh)
    endpoints = ((cfg.get("gateway") or {}).get("http") or {}).get("endpoints") or {}
    enabled = [k for k, v in endpoints.items() if isinstance(v, dict) and v.get("enabled") in [True, "true"]]
    print(",".join(enabled) if enabled else "none")
except Exception:
    print("unknown")
' "$AC22_OC_CONFIG" 2>/dev/null)
  fi
  if [[ "$AC22_WEB_ENABLED" == "true" ]]; then
    warnx "AC-22-public-content" "AC-22: web.enabled is true in $AC22_CONFIG_NAME — verify public-facing content is authorized and reviewed"
  elif [[ "$AC22_WEB_ENABLED" == "false" ]]; then
    passx "AC-22-public-content" "AC-22: web.enabled is false in $AC22_CONFIG_NAME"
  else
    passx "AC-22-public-content" "AC-22: web.enabled is ${AC22_WEB_ENABLED:-unset} in $AC22_CONFIG_NAME — no explicit public web content"
  fi
  if [[ -n "$AC22_HTTP_ENDPOINTS" && "$AC22_HTTP_ENDPOINTS" != "none" && "$AC22_HTTP_ENDPOINTS" != "unknown" ]]; then
    warnx "AC-22-http-endpoints" "AC-22: HTTP endpoints enabled in $AC22_CONFIG_NAME: $AC22_HTTP_ENDPOINTS — ensure each is intentionally exposed"
  else
    passx "AC-22-http-endpoints" "AC-22: No HTTP endpoints enabled in $AC22_CONFIG_NAME"
  fi
else
  skipx "AC-22-public-content" "AC-22: OpenClaw config not found at ~/.openclaw/openclaw.json (or legacy ~/.openclaw/config.json)"
fi
