#!/usr/bin/env bash
# check-ia.sh — Identification & Authentication (IA) checks — NIST 800-53 Rev 5

# IA-5: Authenticator Management — password policy
log "IA-5: Password policy"
LOGIN_DEFS="/etc/login.defs"
if [[ -f "$LOGIN_DEFS" ]]; then
  PASS_MAX=$(grep "^PASS_MAX_DAYS" "$LOGIN_DEFS" | awk '{print $2}')
  PASS_MIN=$(grep "^PASS_MIN_DAYS" "$LOGIN_DEFS" | awk '{print $2}')
  PASS_WARN=$(grep "^PASS_WARN_AGE" "$LOGIN_DEFS" | awk '{print $2}')

  if [[ -n "$PASS_MAX" && "$PASS_MAX" -le 90 ]]; then
    pass "IA-5: PASS_MAX_DAYS is $PASS_MAX (<=90)"
  else
    fail "IA-5: PASS_MAX_DAYS is ${PASS_MAX:-unset} — should be 90 or less"
  fi

  if [[ -n "$PASS_MIN" && "$PASS_MIN" -ge 1 ]]; then
    pass "IA-5: PASS_MIN_DAYS is $PASS_MIN (>=1)"
  else
    warn "IA-5: PASS_MIN_DAYS is ${PASS_MIN:-unset} — should be at least 1"
  fi

  if [[ -n "$PASS_WARN" && "$PASS_WARN" -ge 7 ]]; then
    pass "IA-5: PASS_WARN_AGE is $PASS_WARN (>=7 days)"
  else
    warn "IA-5: PASS_WARN_AGE is ${PASS_WARN:-unset} — recommend 7 or more"
  fi
fi

# IA-5: pwquality (password complexity)
log "IA-5: Password complexity (pwquality)"
PWQUAL="/etc/security/pwquality.conf"
if [[ -f "$PWQUAL" ]]; then
  MINLEN=$(grep "^minlen" "$PWQUAL" | awk -F= '{print $2}' | tr -d ' ')
  if [[ -n "$MINLEN" && "$MINLEN" -ge 12 ]]; then
    pass "IA-5: pwquality minlen is $MINLEN (>=12)"
  else
    fail "IA-5: pwquality minlen is ${MINLEN:-unset} — should be 12 or more"
  fi

  for param in dcredit ucredit ocredit lcredit; do
    VAL=$(grep "^${param}" "$PWQUAL" | awk -F= '{print $2}' | tr -d ' ')
    if [[ -n "$VAL" ]]; then
      pass "IA-5: pwquality $param is configured ($VAL)"
    else
      warn "IA-5: pwquality $param not set — consider enabling character complexity requirements"
    fi
  done
else
  fail "IA-5: /etc/security/pwquality.conf not found — install libpam-pwquality and configure"
fi

# IA-2: Identification — PAM faillock (account lockout)
log "IA-2: Account lockout (faillock)"
PAM_AUTH="/etc/pam.d/common-auth"
if [[ -f "$PAM_AUTH" ]]; then
  if grep -q "pam_faillock" "$PAM_AUTH" 2>/dev/null; then
    pass "IA-2: pam_faillock is configured in common-auth"
    FAILLOCK_CONF="/etc/security/faillock.conf"
    if [[ -f "$FAILLOCK_CONF" ]]; then
      DENY=$(grep "^deny" "$FAILLOCK_CONF" | awk '{ print $3 }')
      UNLOCK_TIME=$(grep "^unlock_time" "$FAILLOCK_CONF" | awk '{ print $3 }')
      if [[ -n "$DENY" && "$DENY" -le 5 ]]; then
        pass "IA-2: faillock deny threshold is $DENY (<=5 attempts)"
      else
        warn "IA-2: faillock deny is ${DENY:-unset} — recommend 5 or fewer attempts"
      fi
      if [[ -n "$UNLOCK_TIME" && "$UNLOCK_TIME" -ge 1800 ]]; then
        pass "IA-2: faillock unlock_time is $UNLOCK_TIME seconds (>=30 min)"
      else
        warn "IA-2: faillock unlock_time is ${UNLOCK_TIME:-unset} — recommend 1800 (30 min)"
      fi
    else
      warn "IA-2: pam_faillock referenced but /etc/security/faillock.conf not found"
    fi
  else
    fail "IA-2: pam_faillock not configured — account lockout policy not enforced"
  fi
fi

# IA-2: Session timeout
log "IA-2: Session timeout"
TMOUT_SET=$(grep -rh "TMOUT" /etc/profile /etc/profile.d/ /etc/bash.bashrc 2>/dev/null | grep -v "^#" | head -1)
if [[ -n "$TMOUT_SET" ]]; then
  pass "IA-2: Session timeout (TMOUT) is configured: $TMOUT_SET"
else
  warn "IA-2: TMOUT not set in /etc/profile or /etc/profile.d/ — recommend TMOUT=900"
fi
