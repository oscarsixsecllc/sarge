#!/usr/bin/env bash
# check-ia.sh — Identification & Authentication (IA) checks — NIST 800-53 Rev 5
# Platform-specific data acquisition lives in lib/platforms/<os>.sh.

# IA-5: Authenticator Management — password aging policy
log "IA-5: Password policy"
PASS_MAX=$(platform login_defs_value PASS_MAX_DAYS)
PASS_MIN=$(platform login_defs_value PASS_MIN_DAYS)
PASS_WARN=$(platform login_defs_value PASS_WARN_AGE)

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

# IA-5: pwquality (password complexity)
log "IA-5: Password complexity (pwquality)"
PWQUAL=$(platform pwquality_config_path)
if [[ -f "$PWQUAL" ]]; then
  MINLEN=$(platform pwquality_value minlen)
  if [[ -n "$MINLEN" && "$MINLEN" -ge 12 ]]; then
    pass "IA-5: pwquality minlen is $MINLEN (>=12)"
  else
    fail "IA-5: pwquality minlen is ${MINLEN:-unset} — should be 12 or more"
  fi

  for param in dcredit ucredit ocredit lcredit; do
    VAL=$(platform pwquality_value "$param")
    if [[ -n "$VAL" ]]; then
      pass "IA-5: pwquality $param is configured ($VAL)"
    else
      warn "IA-5: pwquality $param not set — consider enabling character complexity requirements"
    fi
  done
else
  fail "IA-5: $PWQUAL not found — install libpam-pwquality and configure"
fi

# IA-2: Identification — PAM faillock (account lockout)
log "IA-2: Account lockout (faillock)"
PAM_AUTH=$(platform pam_auth_path)
if [[ -f "$PAM_AUTH" ]]; then
  if platform pam_faillock_configured; then
    pass "IA-2: pam_faillock is configured in common-auth"
    FAILLOCK_CONF=$(platform faillock_config_path)
    if [[ -f "$FAILLOCK_CONF" ]]; then
      DENY=$(platform faillock_value deny)
      UNLOCK_TIME=$(platform faillock_value unlock_time)
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
      warn "IA-2: pam_faillock referenced but $FAILLOCK_CONF not found"
    fi
  else
    fail "IA-2: pam_faillock not configured — account lockout policy not enforced"
  fi
fi

# IA-2: Session timeout
log "IA-2: Session timeout"
TMOUT_SET=$(platform session_timeout_setting)
if [[ -n "$TMOUT_SET" ]]; then
  pass "IA-2: Session timeout (TMOUT) is configured: $TMOUT_SET"
else
  warn "IA-2: TMOUT not set in /etc/profile or /etc/profile.d/ — recommend TMOUT=900"
fi
