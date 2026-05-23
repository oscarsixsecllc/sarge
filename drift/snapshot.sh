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

# Per-run folder layout (issue #34). When the caller hasn't already
# established a run root (e.g. snapshot.sh invoked standalone, outside
# assess.sh), create one here so the snapshot lands in a self-contained
# folder under ~/.sarge/runs/.
SARGE_RUN_ID="${SARGE_RUN_ID:-$TIMESTAMP}"
SARGE_RUN_ROOT="${SARGE_RUN_ROOT:-$HOME/.sarge/runs/$SARGE_RUN_ID}"
mkdir -p "$SARGE_RUN_ROOT"
export SARGE_RUN_ID SARGE_RUN_ROOT

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

# Mirror into the per-run folder. compare.sh still reads from the legacy
# SNAPSHOT_DIR/latest.json so the baseline survives across runs — the
# in-run copy is for archival/self-contained-run-folder purposes only.
cp "$SNAPSHOT_FILE" "$SARGE_RUN_ROOT/drift-snapshot.json"
echo "[Sarge] Run folder: $SARGE_RUN_ROOT"
