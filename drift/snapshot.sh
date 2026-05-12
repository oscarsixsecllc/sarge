#!/usr/bin/env bash
# snapshot.sh — Capture Sarge Baseline Snapshot — NIST 800-53 CM-2
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# shellcheck source=../lib/platform.sh
source "${REPO_ROOT}/lib/platform.sh"
sarge_require_supported_os
sarge_require_os ubuntu macos

# shellcheck source=../lib/platforms/_dispatch.sh
source "${REPO_ROOT}/lib/platforms/_dispatch.sh"

SNAPSHOT_DIR="${SARGE_SNAPSHOT_DIR:-$HOME/.sarge/snapshots}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
SNAPSHOT_FILE="$SNAPSHOT_DIR/snapshot-${TIMESTAMP}.json"
mkdir -p "$SNAPSHOT_DIR"

echo "[Sarge] Taking baseline snapshot..."

# Platform-specific fields are emitted by `platform drift_snapshot_fields`
# (defined in lib/platforms/<os>.sh). Nesting under "fields" lets compare.sh
# enumerate what was captured and lets us evolve per-platform field sets
# without breaking the top-level metadata shape.
cat > "$SNAPSHOT_FILE" <<EOF
{
  "timestamp": "$(date -Iseconds 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)",
  "platform": "${SARGE_OS}",
  "host": "$(hostname)",
  "kernel": "$(uname -r)",
  "os": "${SARGE_OS_DESCRIPTION}",
  "fields": {
$(platform drift_snapshot_fields)
  }
}
EOF

echo "[Sarge] Snapshot saved: $SNAPSHOT_FILE"
ln -sf "$SNAPSHOT_FILE" "$SNAPSHOT_DIR/latest.json"
