#!/usr/bin/env bash
# check-ia.sh — Identification & Authentication (IA) checks — NIST 800-53 Rev 5
# Platform-specific data acquisition lives in lib/platforms/<os>.sh.

# IA-5: Authenticator Management — password aging policy
log "IA-5: Password policy"
if ! platform_supports login_defs_value; then
  skipx "IA-5-pass-max-days" "IA-5: /etc/login.defs is a Linux-PAM construct; on ${SARGE_OS_DESCRIPTION} password aging is set via pwpolicy / MDM account policies"
else
  PASS_MAX=$(platform login_defs_value PASS_MAX_DAYS)
  PASS_MIN=$(platform login_defs_value PASS_MIN_DAYS)
  PASS_WARN=$(platform login_defs_value PASS_WARN_AGE)

  if [[ -n "$PASS_MAX" && "$PASS_MAX" -le 90 ]]; then
    passx "IA-5-pass-max-days" "IA-5: PASS_MAX_DAYS is $PASS_MAX (<=90)"
  else
    failx "IA-5-pass-max-days" "IA-5: PASS_MAX_DAYS is ${PASS_MAX:-unset} — should be 90 or less"
  fi

  if [[ -n "$PASS_MIN" && "$PASS_MIN" -ge 1 ]]; then
    passx "IA-5-pass-min-days" "IA-5: PASS_MIN_DAYS is $PASS_MIN (>=1)"
  else
    warnx "IA-5-pass-min-days" "IA-5: PASS_MIN_DAYS is ${PASS_MIN:-unset} — should be at least 1"
  fi

  if [[ -n "$PASS_WARN" && "$PASS_WARN" -ge 7 ]]; then
    passx "IA-5-pass-warn-age" "IA-5: PASS_WARN_AGE is $PASS_WARN (>=7 days)"
  else
    warnx "IA-5-pass-warn-age" "IA-5: PASS_WARN_AGE is ${PASS_WARN:-unset} — recommend 7 or more"
  fi
fi

# IA-5: pwquality (password complexity)
log "IA-5: Password complexity (pwquality)"
if ! platform_supports pwquality_config_path; then
  skipx "IA-5-pwquality-missing" "IA-5: libpam-pwquality is a Linux-PAM module; on ${SARGE_OS_DESCRIPTION} password complexity is enforced via pwpolicy / MDM account policies"
else
  PWQUAL=$(platform pwquality_config_path)
  if [[ -f "$PWQUAL" ]]; then
    MINLEN=$(platform pwquality_value minlen)
    if [[ -n "$MINLEN" && "$MINLEN" -ge 12 ]]; then
      passx "IA-5-pwquality-minlen" "IA-5: pwquality minlen is $MINLEN (>=12)"
    else
      failx "IA-5-pwquality-minlen" "IA-5: pwquality minlen is ${MINLEN:-unset} — should be 12 or more"
    fi

    for param in dcredit ucredit ocredit lcredit; do
      VAL=$(platform pwquality_value "$param")
      if [[ -n "$VAL" ]]; then
        passx "IA-5-pwquality-credit" "IA-5: pwquality $param is configured ($VAL)"
      else
        warnx "IA-5-pwquality-credit" "IA-5: pwquality $param not set — consider enabling character complexity requirements"
      fi
    done
  else
    failx "IA-5-pwquality-missing" "IA-5: $PWQUAL not found — install libpam-pwquality and configure"
  fi
fi

# IA-2: Identification — PAM faillock (account lockout)
log "IA-2: Account lockout (faillock)"
if ! platform_supports pam_auth_path; then
  skipx "IA-2-faillock-not-configured" "IA-2: pam_faillock is a Linux-PAM module; on ${SARGE_OS_DESCRIPTION} account lockout is enforced via pwpolicy / MDM"
else
  PAM_AUTH=$(platform pam_auth_path)
  if [[ -f "$PAM_AUTH" ]]; then
    if platform pam_faillock_configured; then
      passx "IA-2-faillock-not-configured" "IA-2: pam_faillock is configured in common-auth"
      FAILLOCK_CONF=$(platform faillock_config_path)
      if [[ -f "$FAILLOCK_CONF" ]]; then
        DENY=$(platform faillock_value deny)
        UNLOCK_TIME=$(platform faillock_value unlock_time)
        if [[ -n "$DENY" && "$DENY" -le 5 ]]; then
          passx "IA-2-faillock-deny" "IA-2: faillock deny threshold is $DENY (<=5 attempts)"
        else
          warnx "IA-2-faillock-deny" "IA-2: faillock deny is ${DENY:-unset} — recommend 5 or fewer attempts"
        fi
        if [[ -n "$UNLOCK_TIME" && "$UNLOCK_TIME" -ge 1800 ]]; then
          passx "IA-2-faillock-unlock-time" "IA-2: faillock unlock_time is $UNLOCK_TIME seconds (>=30 min)"
        else
          warnx "IA-2-faillock-unlock-time" "IA-2: faillock unlock_time is ${UNLOCK_TIME:-unset} — recommend 1800 (30 min)"
        fi
      else
        warnx "IA-2-faillock-conf-missing" "IA-2: pam_faillock referenced but $FAILLOCK_CONF not found"
      fi
    else
      failx "IA-2-faillock-not-configured" "IA-2: pam_faillock not configured — account lockout policy not enforced"
    fi
  fi
fi

# IA-2: Session timeout
log "IA-2: Session timeout"
TMOUT_SET=$(platform session_timeout_setting)
if [[ -n "$TMOUT_SET" ]]; then
  passx "IA-2-tmout-unset" "IA-2: Session timeout (TMOUT) is configured: $TMOUT_SET"
else
  warnx "IA-2-tmout-unset" "IA-2: TMOUT not set in /etc/profile or /etc/profile.d/ — recommend TMOUT=900"
fi

# IA-4: Identifier Management — UID uniqueness
#
# /etc/passwd exists on every platform Sarge supports (macOS keeps a local
# copy alongside Open Directory). Duplicate UIDs mean two identifiers
# resolve to the same authorization context — a violation of IA-4's
# "unique identifier per user" requirement regardless of OS. No
# platform-specific probe needed; read directly like AC-2 does.
log "IA-4: Identifier Management (UID uniqueness)"
if [[ -r /etc/passwd ]]; then
  DUP_UIDS=$(awk -F: '{print $3}' /etc/passwd | sort | uniq -d)
  if [[ -z "$DUP_UIDS" ]]; then
    passx "IA-4-duplicate-uids" "IA-4: No duplicate UIDs in /etc/passwd — every identifier is unique"
  else
    failx "IA-4-duplicate-uids" "IA-4: Duplicate UIDs found in /etc/passwd (identifier reuse): $(echo "$DUP_UIDS" | tr '\n' ' ')"
  fi
else
  warnx "IA-4-duplicate-uids" "IA-4: /etc/passwd not readable — cannot verify UID uniqueness"
fi

# IA-7: Cryptographic Module Authentication — SSH protocol/cipher hygiene
log "IA-7: Cryptographic Module Authentication (SSH protocol/ciphers)"
if ! platform_supports sshd_config_path; then
  skipx "IA-7-ssh-protocol" "IA-7: SSH config path probe not implemented for ${SARGE_OS_DESCRIPTION}"
else
  SSHD_CONFIG=$(platform sshd_config_path)
  # Same drop-in discovery as CM-7's SSH section (check-cm.sh) — first
  # match wins under OpenSSH semantics, so a match in any file is enough.
  _IA7_SSHD_CONF_FILES=("$SSHD_CONFIG")
  IA7_SSHD_DROPIN_DIR="${SSHD_CONFIG%/*}/sshd_config.d"
  if [[ -d "$IA7_SSHD_DROPIN_DIR" ]]; then
    while IFS= read -r f; do
      _IA7_SSHD_CONF_FILES+=("$f")
    done < <(find "$IA7_SSHD_DROPIN_DIR" -maxdepth 1 -name '*.conf' -type f 2>/dev/null | sort)
  fi
  if [[ -f "$SSHD_CONFIG" ]]; then
    if grep -qiE "^[[:space:]]*Protocol[[:space:]]+1(\b|,)" "${_IA7_SSHD_CONF_FILES[@]}" 2>/dev/null; then
      failx "IA-7-ssh-protocol" "IA-7: SSHv1 (Protocol 1) is configured — must be SSHv2 only"
    else
      passx "IA-7-ssh-protocol" "IA-7: SSHv1 (Protocol 1) not configured — SSHv2 in effect"
    fi

    WEAK_CIPHERS=$(grep -iE "^[[:space:]]*Ciphers" "${_IA7_SSHD_CONF_FILES[@]}" 2>/dev/null | grep -iE "3des|arcfour|-cbc" || true)
    if [[ -n "$WEAK_CIPHERS" ]]; then
      failx "IA-7-ssh-weak-ciphers" "IA-7: Weak SSH cipher(s) explicitly configured: $(echo "$WEAK_CIPHERS" | tr '\n' ' ')"
    else
      passx "IA-7-ssh-weak-ciphers" "IA-7: No weak SSH ciphers (3des/arcfour/*-cbc) explicitly configured"
    fi
  else
    skipx "IA-7-ssh-protocol" "IA-7: $SSHD_CONFIG not found — cannot verify SSH protocol/cipher configuration"
  fi
fi

# IA-7: Cryptographic Module Authentication — gateway TLS version
#
# Live OpenClaw 2026.7.x writes runtime config to `openclaw.json`; older
# installs used `config.json`. Same fallback probe as check-sc.sh's SC-28
# section (issue #61) so long-lived hosts don't get a spurious SKIP.
log "IA-7: Cryptographic Module Authentication (gateway TLS)"
IA_OC_CONFIG=""
for candidate in "$HOME/.openclaw/openclaw.json" "$HOME/.openclaw/config.json"; do
  if [[ -f "$candidate" ]]; then
    IA_OC_CONFIG="$candidate"
    break
  fi
done
if [[ -n "$IA_OC_CONFIG" ]]; then
  IA_CONFIG_NAME=$(basename "$IA_OC_CONFIG")
  if grep -qiE '"(minVersion|min_version)"[[:space:]]*:[[:space:]]*"TLSv?1\.[01]"' "$IA_OC_CONFIG" 2>/dev/null; then
    failx "IA-7-gateway-tls-version" "IA-7: OpenClaw gateway TLS minVersion allows TLSv1.0/1.1 in $IA_CONFIG_NAME — set to TLSv1.2 or higher"
  elif grep -qiE '"tls"' "$IA_OC_CONFIG" 2>/dev/null; then
    passx "IA-7-gateway-tls-version" "IA-7: OpenClaw gateway TLS is configured in $IA_CONFIG_NAME — no TLSv1.0/1.1 minVersion detected"
  else
    warnx "IA-7-gateway-tls-version" "IA-7: No explicit TLS configuration found in $IA_CONFIG_NAME — verify the TLS terminator (e.g. Cloudflare Tunnel) enforces TLSv1.2+"
  fi
else
  skipx "IA-7-gateway-tls-version" "IA-7: OpenClaw config not found at ~/.openclaw/openclaw.json (or legacy ~/.openclaw/config.json)"
fi

# IA-8: Identification and Authentication (Non-Organizational Users)
#
# External/anonymous channel users (Discord, Telegram, etc.) must be
# identified before the gateway extends any trust. Sarge can't see
# per-message auth at the OS layer, so this checks the config-level
# controls: an explicit auth mode, registered providers, and that
# anonymous access isn't left wide open.
log "IA-8: Identification and Authentication (Non-Org Users)"
IA_OC_CONFIG=""
for candidate in "$HOME/.openclaw/openclaw.json" "$HOME/.openclaw/config.json"; do
  if [[ -f "$candidate" ]]; then
    IA_OC_CONFIG="$candidate"
    break
  fi
done
if [[ -n "$IA_OC_CONFIG" ]]; then
  IA_CONFIG_NAME=$(basename "$IA_OC_CONFIG")
  AUTH_MODE=$(grep -oE '"mode"[[:space:]]*:[[:space:]]*"[^"]*"' "$IA_OC_CONFIG" 2>/dev/null | head -1 | sed -E 's/.*"([^"]+)"$/\1/')
  if [[ -n "$AUTH_MODE" ]]; then
    passx "IA-8-auth-mode" "IA-8: $IA_CONFIG_NAME declares an auth.mode ($AUTH_MODE) for external/channel users"
  else
    warnx "IA-8-auth-mode" "IA-8: No auth.mode found in $IA_CONFIG_NAME — verify external channel users are identified before gateway trust"
  fi

  if grep -qiE '"anonymous"[[:space:]]*:[[:space:]]*true' "$IA_OC_CONFIG" 2>/dev/null; then
    failx "IA-8-anonymous-access" "IA-8: Anonymous access is enabled in $IA_CONFIG_NAME — non-org users are not authenticated before gateway trust"
  else
    passx "IA-8-anonymous-access" "IA-8: Anonymous access is not enabled in $IA_CONFIG_NAME"
  fi

  if grep -qE '"providers"' "$IA_OC_CONFIG" 2>/dev/null; then
    passx "IA-8-auth-providers" "IA-8: auth.providers configured in $IA_CONFIG_NAME"
  else
    warnx "IA-8-auth-providers" "IA-8: No auth.providers found in $IA_CONFIG_NAME — external channel identities may not be mapped to allowlisted users"
  fi
else
  skipx "IA-8-auth-mode" "IA-8: OpenClaw config not found at ~/.openclaw/openclaw.json (or legacy ~/.openclaw/config.json)"
fi

# IA-11: Re-authentication — gateway session idle timeout
#
# mcp.sessionIdleTtlMs (and equivalents) bound how long a session can sit
# idle before it must re-authenticate. Missing = never expires; 0 =
# explicitly disabled/infinite. Both are IA-11 gaps.
log "IA-11: Re-authentication (session idle timeout)"
IA_OC_CONFIG=""
for candidate in "$HOME/.openclaw/openclaw.json" "$HOME/.openclaw/config.json"; do
  if [[ -f "$candidate" ]]; then
    IA_OC_CONFIG="$candidate"
    break
  fi
done
if [[ -n "$IA_OC_CONFIG" ]]; then
  IA_CONFIG_NAME=$(basename "$IA_OC_CONFIG")
  IDLE_TTL=$(grep -oE '"sessionIdleTtlMs"[[:space:]]*:[[:space:]]*[0-9]+' "$IA_OC_CONFIG" 2>/dev/null | grep -oE '[0-9]+$' | head -1)
  if [[ -z "$IDLE_TTL" ]]; then
    warnx "IA-11-session-idle-ttl" "IA-11: mcp.sessionIdleTtlMs not set in $IA_CONFIG_NAME — sessions may never require re-authentication"
  elif [[ "$IDLE_TTL" -eq 0 ]]; then
    failx "IA-11-session-idle-ttl" "IA-11: mcp.sessionIdleTtlMs is 0 (infinite/disabled) in $IA_CONFIG_NAME — require periodic re-authentication"
  elif [[ "$IDLE_TTL" -le 86400000 ]]; then
    passx "IA-11-session-idle-ttl" "IA-11: mcp.sessionIdleTtlMs is ${IDLE_TTL}ms (<=24h) in $IA_CONFIG_NAME"
  else
    warnx "IA-11-session-idle-ttl" "IA-11: mcp.sessionIdleTtlMs is ${IDLE_TTL}ms (>24h) in $IA_CONFIG_NAME — consider a shorter re-authentication window"
  fi
else
  skipx "IA-11-session-idle-ttl" "IA-11: OpenClaw config not found at ~/.openclaw/openclaw.json (or legacy ~/.openclaw/config.json)"
fi
