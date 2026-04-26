#!/usr/bin/env bash
# snapshot.sh — Capture Sarge Baseline Snapshot — NIST 800-53 CM-2
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# shellcheck source=../lib/platform.sh
source "${REPO_ROOT}/lib/platform.sh"
sarge_require_supported_os
sarge_require_os ubuntu

SNAPSHOT_DIR="${SARGE_SNAPSHOT_DIR:-$HOME/.sarge/snapshots}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
SNAPSHOT_FILE="$SNAPSHOT_DIR/snapshot-${TIMESTAMP}.json"
mkdir -p "$SNAPSHOT_DIR"

echo "[Sarge] Taking baseline snapshot..."
cat > "$SNAPSHOT_FILE" << SNAPEOF
{
  "timestamp": "$(date -Iseconds)",
  "host": "$(hostname)",
  "kernel": "$(uname -r)",
  "os": "$(lsb_release -sd 2>/dev/null || echo unknown)",
  "ufw_status": "$(ufw status 2>/dev/null | head -1 || echo unknown)",
  "auditd_active": "$(systemctl is-active auditd 2>/dev/null || echo unknown)",
  "fail2ban_active": "$(systemctl is-active fail2ban 2>/dev/null || echo unknown)",
  "openclaw_dir_perm": "$(stat -c '%a' $HOME/.openclaw 2>/dev/null || echo unknown)",
  "tmout_set": "$(grep -rh TMOUT /etc/profile.d/ 2>/dev/null | head -1 || echo unset)",
  "pass_max_days": "$(grep ^PASS_MAX_DAYS /etc/login.defs 2>/dev/null | awk '{print $2}' || echo unknown)",
  "pending_updates": $(apt list --upgradable 2>/dev/null | grep -c upgradable || echo 0)
}
SNAPEOF

echo "[Sarge] Snapshot saved: $SNAPSHOT_FILE"
ln -sf "$SNAPSHOT_FILE" "$SNAPSHOT_DIR/latest.json"
