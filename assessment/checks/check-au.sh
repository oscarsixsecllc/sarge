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

# AU-4: Audit log storage capacity
log "AU-4: Audit log storage capacity"
if ! platform_supports log_partition_free_pct; then
  skipx "AU-4-log-storage" "AU-4: audit log partition free-space check is Linux-specific; not applicable on ${SARGE_OS_DESCRIPTION}"
else
  FREE_PCT=$(platform log_partition_free_pct)
  if [[ -z "$FREE_PCT" ]]; then
    warnx "AU-4-log-storage" "AU-4: could not determine free space on the audit log partition"
  elif [[ "$FREE_PCT" -gt 10 ]]; then
    passx "AU-4-log-storage" "AU-4: audit log partition has ${FREE_PCT}% free — adequate headroom"
  else
    failx "AU-4-log-storage" "AU-4: audit log partition has only ${FREE_PCT}% free — expand storage or tighten log rotation"
  fi
fi

# AU-5: Response to audit failures
log "AU-5: Response to audit failures"
if ! platform_supports auditd_config_value; then
  skipx "AU-5-audit-failure-response" "AU-5: auditd.conf inspection is a Linux auditd construct; not applicable on ${SARGE_OS_DESCRIPTION}"
elif [[ ! -f "$(platform auditd_config_path)" ]]; then
  skipx "AU-5-audit-failure-response" "AU-5: $(platform auditd_config_path) not found — auditd may not be installed"
else
  DISK_FULL_ACTION=$(platform auditd_config_value "disk_full_action")
  SPACE_LEFT_ACTION=$(platform auditd_config_value "admin_space_left_action")
  if [[ -n "$DISK_FULL_ACTION" && "${DISK_FULL_ACTION^^}" != "IGNORE" \
        && -n "$SPACE_LEFT_ACTION" && "${SPACE_LEFT_ACTION^^}" != "IGNORE" ]]; then
    passx "AU-5-audit-failure-response" "AU-5: disk_full_action=$DISK_FULL_ACTION, admin_space_left_action=$SPACE_LEFT_ACTION"
  else
    warnx "AU-5-audit-failure-response" "AU-5: disk_full_action=${DISK_FULL_ACTION:-unset}, admin_space_left_action=${SPACE_LEFT_ACTION:-unset} — set both to something other than IGNORE (e.g. SYSLOG, EMAIL, HALT)"
  fi
fi

# AU-7: Audit reduction and report generation
log "AU-7: Audit reduction and report generation"
if ! platform_supports journalctl_available; then
  skipx "AU-7-log-tooling" "AU-7: journalctl/ausearch availability check is Linux-specific; not applicable on ${SARGE_OS_DESCRIPTION}"
else
  TOOLING_NOTE=""
  if platform journalctl_available; then
    TOOLING_NOTE="journalctl"
  fi
  if platform_supports ausearch_available && platform ausearch_available; then
    TOOLING_NOTE="${TOOLING_NOTE:+$TOOLING_NOTE, }ausearch"
  fi
  if platform_supports syslog_forwarding_configured && platform syslog_forwarding_configured; then
    TOOLING_NOTE="${TOOLING_NOTE:+$TOOLING_NOTE, }syslog forwarding"
  fi
  if [[ -n "$TOOLING_NOTE" ]]; then
    passx "AU-7-log-tooling" "AU-7: log query/aggregation tooling available ($TOOLING_NOTE)"
  else
    warnx "AU-7-log-tooling" "AU-7: no log query/aggregation tooling detected — install auditd (ausearch) or configure syslog forwarding"
  fi
fi

# AU-8: Time stamps
log "AU-8: Time stamps"
if ! platform_supports time_sync_active; then
  skipx "AU-8-time-sync" "AU-8: NTP sync check via timedatectl/chronyc is Linux-specific; verify time sync via ${SARGE_OS_DESCRIPTION} equivalent separately"
elif platform time_sync_active; then
  passx "AU-8-time-sync" "AU-8: system clock is synchronized (NTP)"
else
  failx "AU-8-time-sync" "AU-8: system clock is not synchronized — enable NTP: sudo timedatectl set-ntp true"
fi

# AU-11: Audit record retention
log "AU-11: Audit record retention"
if ! platform_supports logrotate_audit_config_path; then
  skipx "AU-11-log-retention" "AU-11: logrotate inspection is a Linux construct; not applicable on ${SARGE_OS_DESCRIPTION}"
else
  LOGROTATE_CONF=$(platform logrotate_audit_config_path)
  if [[ ! -f "$LOGROTATE_CONF" ]]; then
    warnx "AU-11-log-retention" "AU-11: no logrotate config found for audit logs at $LOGROTATE_CONF — configure log rotation with adequate retention"
  else
    ROTATE_COUNT=$(platform logrotate_rotate_count "$LOGROTATE_CONF")
    if [[ -z "$ROTATE_COUNT" ]]; then
      warnx "AU-11-log-retention" "AU-11: $LOGROTATE_CONF has no 'rotate' directive — retention period is undefined"
    elif [[ "$ROTATE_COUNT" -ge 4 ]]; then
      passx "AU-11-log-retention" "AU-11: audit logs retained for $ROTATE_COUNT rotation cycles ($LOGROTATE_CONF)"
    else
      warnx "AU-11-log-retention" "AU-11: audit logs retained for only $ROTATE_COUNT rotation cycles — recommend >= 4 weeks retention"
    fi
  fi
fi
