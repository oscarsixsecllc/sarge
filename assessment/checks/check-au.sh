#!/usr/bin/env bash
# check-au.sh — Audit & Accountability (AU) checks — NIST 800-53 Rev 5
# Platform-specific data acquisition lives in lib/platforms/<os>.sh.

# AU-2 / AU-12: Audit daemon running
log "AU-2/AU-12: Audit daemon"
if platform audit_daemon_active; then
  pass "AU-2: audit daemon is running"
else
  fail "AU-2: audit daemon is not running — install and enable: sudo apt install auditd"
fi

# AU-12: Audit rules covering OpenClaw secrets
log "AU-12: Audit rules"
if platform auditctl_available; then
  AUDIT_RULES=$(platform audit_rules)
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
  skip "AU-12: audit rule inspection tool not available"
fi

# AU-3 / AU-9: Audit log protection
log "AU-3/AU-9: Audit log integrity"
AUDIT_LOG=$(platform audit_log_path)
if [[ -f "$AUDIT_LOG" ]]; then
  LOG_PERM=$(platform file_perm "$AUDIT_LOG")
  LOG_OWNER=$(platform file_owner "$AUDIT_LOG")
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
  if platform audit_daemon_active; then
    warn "AU-9: audit daemon is running but $AUDIT_LOG not found — check audit config"
  else
    skip "AU-9: audit daemon not running — no audit log to check"
  fi
fi

# AU-2: System logging (journald/syslog)
log "AU-2: System logging"
if platform system_logger_active; then
  pass "AU-2: system logger is running"
else
  warn "AU-2: system logger not active — verify syslog is configured"
fi

JOURNAL_USAGE=$(platform journal_disk_usage)
JOURNAL_PERSIST=$(echo "$JOURNAL_USAGE" | grep -c "Archived\|journals" || echo "0")
if [[ "$JOURNAL_PERSIST" -gt 0 ]]; then
  pass "AU-2: Journal logs are persisted to disk"
else
  warn "AU-2: Journal persistence unclear — verify /etc/systemd/journald.conf Storage setting"
fi
