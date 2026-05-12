#!/usr/bin/env bash
# drift-cron.sh — Scheduled Drift Detection — NIST 800-53 CM-2
# Add to cron: 0 6 * * * /home/oscar/sarge/drift/drift-cron.sh >> /var/log/sarge-drift.log 2>&1
set -euo pipefail

SARGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.."

# shellcheck source=../lib/platform.sh
source "${SARGE_DIR}/lib/platform.sh"
sarge_require_supported_os
sarge_require_os ubuntu macos
LOG_FILE="${SARGE_LOG_FILE:-$HOME/.sarge/drift.log}"
mkdir -p "$(dirname "$LOG_FILE")"

# Portable ISO-8601 timestamp. `date -Iseconds` is supported by GNU date
# (Ubuntu) and modern BSD date (macOS 14+), but older BSD date predates
# the flag; fall back to an explicit format string so cron runs on every
# supported platform produce a parseable timestamp.
ts() { date -Iseconds 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ; }

echo "[$(ts)] Sarge drift check starting" >> "$LOG_FILE"

if "$SARGE_DIR/drift/compare.sh" >> "$LOG_FILE" 2>&1; then
  echo "[$(ts)] No drift detected." >> "$LOG_FILE"
else
  MSG="[Sarge ALERT] Configuration drift detected on $(hostname) at $(date). Check $LOG_FILE for details."
  echo "[$(ts)] DRIFT ALERT: $MSG" >> "$LOG_FILE"
  # Notify via OpenClaw if available
  if command -v openclaw &>/dev/null; then
    openclaw message --text "$MSG" 2>/dev/null || true
  fi
fi
