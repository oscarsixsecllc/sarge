#!/usr/bin/env bash
# compare.sh — Compare Current State vs Sarge Snapshot — NIST 800-53 CM-2
set -euo pipefail

SNAPSHOT_DIR="${SARGE_SNAPSHOT_DIR:-$HOME/.sarge/snapshots}"
LATEST="$SNAPSHOT_DIR/latest.json"

[[ -f "$LATEST" ]] || { echo "[Sarge] No snapshot found. Run snapshot.sh first."; exit 1; }

DRIFT=0
check() {
  local field="$1" current="$2"
  local baseline
  baseline=$(python3 -c "import json,sys; d=json.load(open('$LATEST')); print(d.get('$field','unknown'))" 2>/dev/null || echo "unknown")
  if [[ "$current" == "$baseline" ]]; then
    echo "  [OK]   $field: $current"
  else
    echo "  [DRIFT] $field: was '$baseline', now '$current'"
    DRIFT=$((DRIFT+1))
  fi
}

echo "[Sarge] Drift Detection — comparing against $(stat -c '%y' "$LATEST" | cut -d. -f1)"
check "ufw_status"        "$(ufw status 2>/dev/null | head -1 || echo unknown)"
check "auditd_active"     "$(systemctl is-active auditd 2>/dev/null || echo unknown)"
check "fail2ban_active"   "$(systemctl is-active fail2ban 2>/dev/null || echo unknown)"
check "openclaw_dir_perm" "$(stat -c '%a' $HOME/.openclaw 2>/dev/null || echo unknown)"
check "pass_max_days"     "$(grep ^PASS_MAX_DAYS /etc/login.defs 2>/dev/null | awk '{print $2}' || echo unknown)"

echo ""
if [[ "$DRIFT" -eq 0 ]]; then
  echo "[Sarge] No drift detected. Configuration matches baseline."
else
  echo "[Sarge] DRIFT DETECTED: $DRIFT items changed. Review and remediate."
  exit 2
fi
