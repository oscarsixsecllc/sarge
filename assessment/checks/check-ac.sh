#!/usr/bin/env bash
# check-ac.sh — Access Control (AC) checks — NIST 800-53 Rev 5
# Platform-specific data acquisition lives in lib/platforms/<os>.sh; this
# file contains 800-53 control assertions and verdict logic only.

# AC-2: Account Management
log "AC-2: Account Management"
NOPASSWD_USERS=$(platform users_with_empty_passwords)
if [[ -z "$NOPASSWD_USERS" ]]; then
  pass "AC-2: No accounts with empty passwords found"
else
  fail "AC-2: Accounts with empty passwords: $NOPASSWD_USERS"
fi

ROOT_SHELLS=$(platform uid_zero_non_root_users)
if [[ -z "$ROOT_SHELLS" ]]; then
  pass "AC-2: No non-root accounts with UID 0"
else
  fail "AC-2: Non-root accounts with UID 0: $ROOT_SHELLS"
fi

# AC-3: Access Enforcement — filesystem permissions on OpenClaw workspace
log "AC-3: Access Enforcement"
OC_DIR="$HOME/.openclaw"
if [[ -d "$OC_DIR" ]]; then
  OC_PERM=$(platform file_perm "$OC_DIR")
  if [[ "$OC_PERM" == "700" ]]; then
    pass "AC-3: ~/.openclaw permissions are 700"
  else
    fail "AC-3: ~/.openclaw permissions are $OC_PERM — should be 700"
  fi

  SECRETS_DIR="$OC_DIR/secrets"
  if [[ -d "$SECRETS_DIR" ]]; then
    S_PERM=$(platform file_perm "$SECRETS_DIR")
    if [[ "$S_PERM" == "700" ]]; then
      pass "AC-3: ~/.openclaw/secrets permissions are 700"
    else
      fail "AC-3: ~/.openclaw/secrets permissions are $S_PERM — should be 700"
    fi

    while IFS= read -r -d '' f; do
      F_PERM=$(platform file_perm "$f")
      if [[ "$F_PERM" == "600" ]]; then
        pass "AC-3: Secret file $f is 600"
      else
        fail "AC-3: Secret file $f is $F_PERM — should be 600"
      fi
    done < <(find "$SECRETS_DIR" -maxdepth 1 -type f -print0 2>/dev/null)
  else
    skip "AC-3: No secrets directory found at $SECRETS_DIR"
  fi
else
  skip "AC-3: No ~/.openclaw directory found"
fi

# AC-6: Least Privilege — sudo configuration
log "AC-6: Least Privilege"
if platform passwordless_sudo_for_current_user; then
  warn "AC-6: Current user has passwordless sudo — review if intentional"
else
  pass "AC-6: sudo requires password (not passwordless)"
fi

CURRENT_USER=$(whoami)
ADMIN_GROUP=$(platform admin_group_name)
if platform user_in_admin_group "$CURRENT_USER"; then
  warn "AC-6: User $CURRENT_USER is in the $ADMIN_GROUP group — confirm this is the admin account, not the service account"
else
  pass "AC-6: User $CURRENT_USER is not in the $ADMIN_GROUP group"
fi

# AC-17: Remote Access
log "AC-17: Remote Access"
if platform firewall_command_available; then
  if platform firewall_active; then
    pass "AC-17: Firewall is active"
  else
    fail "AC-17: Firewall is not active — remote access uncontrolled"
  fi
else
  warn "AC-17: Firewall command not available — verify alternative firewall is in place"
fi

LISTENING=$(platform externally_listening_ports || true)
if [[ -z "$LISTENING" ]]; then
  pass "AC-17: No unexpected externally-listening ports detected"
else
  warn "AC-17: Externally-listening ports found — review: $(echo "$LISTENING" | tr '\n' ' ')"
fi
