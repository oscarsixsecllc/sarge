#!/usr/bin/env bash
# check-ac.sh — Access Control (AC) checks — NIST 800-53 Rev 5

# AC-2: Account Management
log "AC-2: Account Management"
NOPASSWD_USERS=$(awk -F: '($2 == "" ) {print $1}' /etc/shadow 2>/dev/null || echo "")
if [[ -z "$NOPASSWD_USERS" ]]; then
  pass "AC-2: No accounts with empty passwords found"
else
  fail "AC-2: Accounts with empty passwords: $NOPASSWD_USERS"
fi

ROOT_SHELLS=$(awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd)
if [[ -z "$ROOT_SHELLS" ]]; then
  pass "AC-2: No non-root accounts with UID 0"
else
  fail "AC-2: Non-root accounts with UID 0: $ROOT_SHELLS"
fi

# AC-3: Access Enforcement — filesystem permissions on OpenClaw workspace
log "AC-3: Access Enforcement"
OC_DIR="$HOME/.openclaw"
if [[ -d "$OC_DIR" ]]; then
  OC_PERM=$(stat -c "%a" "$OC_DIR")
  if [[ "$OC_PERM" == "700" ]]; then
    pass "AC-3: ~/.openclaw permissions are 700"
  else
    fail "AC-3: ~/.openclaw permissions are $OC_PERM — should be 700"
  fi

  SECRETS_DIR="$OC_DIR/secrets"
  if [[ -d "$SECRETS_DIR" ]]; then
    S_PERM=$(stat -c "%a" "$SECRETS_DIR")
    if [[ "$S_PERM" == "700" ]]; then
      pass "AC-3: ~/.openclaw/secrets permissions are 700"
    else
      fail "AC-3: ~/.openclaw/secrets permissions are $S_PERM — should be 700"
    fi

    while IFS= read -r -d '' f; do
      F_PERM=$(stat -c "%a" "$f")
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
if sudo -n true 2>/dev/null; then
  warn "AC-6: Current user has passwordless sudo — review if intentional"
else
  pass "AC-6: sudo requires password (not passwordless)"
fi

CURRENT_USER=$(whoami)
if groups "$CURRENT_USER" | grep -qw sudo; then
  warn "AC-6: User $CURRENT_USER is in the sudo group — confirm this is the admin account, not the service account"
else
  pass "AC-6: User $CURRENT_USER is not in the sudo group"
fi

# AC-17: Remote Access
log "AC-17: Remote Access"
if command -v ufw &>/dev/null; then
  UFW_STATUS=$(sudo ufw status 2>/dev/null || ufw status 2>/dev/null || echo "inactive")
  if echo "$UFW_STATUS" | grep -q "Status: active"; then
    pass "AC-17: UFW firewall is active"
  else
    fail "AC-17: UFW firewall is not active — remote access uncontrolled"
  fi
else
  warn "AC-17: UFW not installed — verify alternative firewall is in place"
fi

if command -v ss &>/dev/null; then
  LISTENING=$(ss -tlnp 2>/dev/null | grep -v "127.0.0.1\|::1\|Address" | awk '{print $4}' | grep -v "^$" || true)
  if [[ -z "$LISTENING" ]]; then
    pass "AC-17: No unexpected externally-listening ports detected"
  else
    warn "AC-17: Externally-listening ports found — review: $(echo "$LISTENING" | tr '\n' ' ')"
  fi
fi
