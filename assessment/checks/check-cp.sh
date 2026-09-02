#!/usr/bin/env bash
# check-cp.sh — Contingency Planning (CP) — NIST 800-53 Rev 5
# Platform-specific data acquisition lives in lib/platforms/<os>.sh.

# CP-9: System Backup — cron/systemd backup mechanism + recent backup evidence
log "CP-9: System backup"
CP_BACKUP_FOUND=0
CP_BACKUP_NOTE=""

if command -v crontab &>/dev/null; then
  CP_CRON_HIT=$(crontab -l 2>/dev/null | grep -Eiv "^[[:space:]]*#" | grep -i "backup" | head -1)
  if [[ -n "$CP_CRON_HIT" ]]; then
    CP_BACKUP_FOUND=1
    CP_BACKUP_NOTE="${CP_BACKUP_NOTE:+$CP_BACKUP_NOTE, }crontab entry"
  fi
else
  CP_CRON_UNAVAILABLE=1
fi

if command -v systemctl &>/dev/null; then
  CP_TIMER_HIT=$(systemctl list-timers --all 2>/dev/null | grep -i "backup" | head -1)
  if [[ -n "$CP_TIMER_HIT" ]]; then
    CP_BACKUP_FOUND=1
    CP_BACKUP_NOTE="${CP_BACKUP_NOTE:+$CP_BACKUP_NOTE, }systemd timer"
  fi
fi

if [[ "$CP_BACKUP_FOUND" -eq 1 ]]; then
  passx "CP-9-backup-mechanism" "CP-9: backup mechanism found ($CP_BACKUP_NOTE)"
elif [[ "${CP_CRON_UNAVAILABLE:-0}" == "1" ]] && ! command -v systemctl &>/dev/null; then
  skipx "CP-9-backup-mechanism" "CP-9: neither crontab nor systemctl available — cannot verify backup mechanism"
else
  warnx "CP-9-backup-mechanism" "CP-9: no backup cron entry or systemd timer found (searched for 'backup') — configure a scheduled backup of ~/.openclaw config, secrets, and workspace state"
fi
