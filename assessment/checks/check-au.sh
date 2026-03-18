#!/usr/bin/env bash
# check-au.sh — Audit & Accountability (AU) checks — NIST 800-53 Rev 5

# AU-2 / AU-12: Audit daemon running
log "AU-2/AU-12: Audit daemon"
if systemctl is-active --quiet auditd 2>/dev/null; then
  pass "AU-2: auditd is running"
else
  fail "AU-2: auditd is not running — install and enable: sudo apt install auditd"
fi

# AU-12: Audit rules covering OpenClaw secrets
log "AU-12: Audit rules"
if command -v auditctl &>/dev/null; then
  AUDIT_RULES=$(auditctl -l 2>/dev/null || sudo auditctl -l 2>/dev/null || echo "")
  OC_SECRETS="$HOME/.openclaw/secrets"
  if echo "$AUDIT_RULES" | grep -q "openclaw\|$OC_SECRETS"; then
    pass "AU-12: Audit rules cover OpenClaw secrets directory"
  else
    fail "AU-12: No audit rules found for OpenClaw secrets — run harden-auditd.sh"
  fi
  if echo "$AUDIT_RULES" | grep -q "passwd\|shadow\|sudoers"; then
    pass "AU-12: Audit rules cover auth-critical files"
  else
    warn "AU-12: No audit rules for /etc/passwd, /etc/shadow, or /etc/sudoers"
  fi
else
  skip "AU-12: auditctl not available"
fi

# AU-3 / AU-9: Audit log protection
log "AU-3/AU-9: Audit log integrity"
AUDIT_LOG="/var/log/audit/audit.log"
if [[ -f "$AUDIT_LOG" ]]; then
  LOG_PERM=$(stat -c "%a" "$AUDIT_LOG")
  LOG_OWNER=$(stat -c "%U" "$AUDIT_LOG")
  if [[ "$LOG_OWNER" == "root" ]]; then
    pass "AU-9: audit.log owned by root"
  else
    fail "AU-9: audit.log owned by $LOG_OWNER — should be root"
  fi
  if [[ "$LOG_PERM" == "600" ]]; then
    pass "AU-9: audit.log permissions are 600"
  else
    warn "AU-9: audit.log permissions are $LOG_PERM — should be 600"
  fi
else
  if systemctl is-active --quiet auditd 2>/dev/null; then
    warn "AU-9: auditd is running but $AUDIT_LOG not found — check auditd config"
  else
    skip "AU-9: auditd not running — no audit log to check"
  fi
fi

# AU-2: System logging (journald/syslog)
log "AU-2: System logging"
if systemctl is-active --quiet systemd-journald 2>/dev/null; then
  pass "AU-2: systemd-journald is running"
else
  warn "AU-2: systemd-journald not active — verify syslog is configured"
fi

JOURNAL_PERSIST=$(journalctl --disk-usage 2>/dev/null | grep -c "Archived\|journals" || echo "0")
if [[ "$JOURNAL_PERSIST" -gt 0 ]]; then
  pass "AU-2: Journal logs are persisted to disk"
else
  warn "AU-2: Journal persistence unclear — verify /etc/systemd/journald.conf Storage setting"
fi
