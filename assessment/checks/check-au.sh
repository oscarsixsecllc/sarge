#!/usr/bin/env bash
# check-au.sh — Audit & Accountability (AU) checks — NIST 800-53 Rev 5
# Platform-specific data acquisition lives in lib/platforms/<os>.sh.

# AU-2 / AU-12: Audit daemon running
log "AU-2/AU-12: Audit daemon"
if ! platform_supports audit_daemon_active; then
  skipx "AU-2-auditd-not-running" "AU-2: BSM auditd is deprecated on ${SARGE_OS_DESCRIPTION}; audit functions are delegated to Endpoint Security / MDM"
elif platform audit_daemon_active; then
  passx "AU-2-auditd-not-running" "AU-2: audit daemon is running"
else
  failx "AU-2-auditd-not-running" "AU-2: audit daemon is not running — install and enable: sudo apt install auditd"
fi

# AU-12: Audit rules
log "AU-12: Audit rules"
if ! platform_supports auditctl_available; then
  if [[ "${SARGE_HOST_ONLY:-0}" != "1" ]]; then
    skipx "AU-12-no-openclaw-rules" "AU-12: per-file audit rules are a Linux auditd construct; not applicable on ${SARGE_OS_DESCRIPTION}"
  fi
elif platform auditctl_available; then
  AUDIT_RULES=$(platform audit_rules)
  if [[ "${SARGE_HOST_ONLY:-0}" != "1" ]]; then
    OC_SECRETS="$HOME/.openclaw/secrets"
    if echo "$AUDIT_RULES" | grep -q "openclaw\|$OC_SECRETS"; then
      passx "AU-12-no-openclaw-rules" "AU-12: Audit rules cover OpenClaw secrets directory"
    else
      failx "AU-12-no-openclaw-rules" "AU-12: No audit rules found for OpenClaw secrets — run harden-auditd.sh"
    fi
  fi
  if echo "$AUDIT_RULES" | grep -q "passwd\|shadow\|sudoers"; then
    passx "AU-12-no-auth-rules" "AU-12: Audit rules cover auth-critical files"
  else
    warnx "AU-12-no-auth-rules" "AU-12: No audit rules for /etc/passwd, /etc/shadow, or /etc/sudoers"
  fi
else
  if [[ "${SARGE_HOST_ONLY:-0}" != "1" ]]; then
    skipx "AU-12-no-openclaw-rules" "AU-12: audit rule inspection tool not available"
  fi
fi

# AU-3 / AU-9: Audit log protection
log "AU-3/AU-9: Audit log integrity"
if ! platform_supports audit_log_path; then
  skipx "AU-9-audit-log-perm" "AU-9: no Linux-style audit log on ${SARGE_OS_DESCRIPTION}; review Unified Logging / MDM-collected logs separately"
else
  AUDIT_LOG=$(platform audit_log_path)
  if [[ -f "$AUDIT_LOG" ]]; then
    LOG_PERM=$(platform file_perm "$AUDIT_LOG")
    LOG_OWNER=$(platform file_owner "$AUDIT_LOG")
    if [[ "$LOG_OWNER" == "root" ]]; then
      passx "AU-9-audit-log-bad-owner" "AU-9: audit.log owned by root"
    else
      failx "AU-9-audit-log-bad-owner" "AU-9: audit.log owned by $LOG_OWNER — should be root"
    fi
    if [[ "$LOG_PERM" == "600" ]]; then
      passx "AU-9-audit-log-perm" "AU-9: audit.log permissions are 600"
    else
      warnx "AU-9-audit-log-perm" "AU-9: audit.log permissions are $LOG_PERM — should be 600"
    fi
  else
    if platform audit_daemon_active; then
      warnx "AU-9-audit-log-missing" "AU-9: audit daemon is running but $AUDIT_LOG not found — check audit config"
    else
      skipx "AU-9-audit-log-missing" "AU-9: audit daemon not running — no audit log to check"
    fi
  fi
fi

# AU-2: System logging (journald/syslog/Unified Logging)
log "AU-2: System logging"
if platform system_logger_active; then
  passx "AU-2-journald-inactive" "AU-2: system logger is running"
else
  warnx "AU-2-journald-inactive" "AU-2: system logger not active — verify syslog is configured"
fi

if ! platform_supports journal_disk_usage; then
  skipx "AU-2-journal-not-persisted" "AU-2: journald persistence check is Linux-specific; on ${SARGE_OS_DESCRIPTION} review Unified Logging retention via 'log config' / MDM"
else
  JOURNAL_USAGE=$(platform journal_disk_usage)
  JOURNAL_PERSIST=$(echo "$JOURNAL_USAGE" | grep -c "Archived\|journals" || echo "0")
  if [[ "$JOURNAL_PERSIST" -gt 0 ]]; then
    passx "AU-2-journal-not-persisted" "AU-2: Journal logs are persisted to disk"
  else
    warnx "AU-2-journal-not-persisted" "AU-2: Journal persistence unclear — verify /etc/systemd/journald.conf Storage setting"
  fi
fi
