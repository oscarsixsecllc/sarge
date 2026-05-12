#!/usr/bin/env bash
# compare.sh — Compare Current State vs Sarge Snapshot — NIST 800-53 CM-2
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
LATEST="$SNAPSHOT_DIR/latest.json"

[[ -f "$LATEST" ]] || { echo "[Sarge] No snapshot found. Run snapshot.sh first."; exit 1; }

# The platform's drift_check_fields function calls this helper for each
# field it knows about. Reads the baseline value out of the snapshot JSON
# via a python one-liner (python3 is on every supported platform); falls
# back to top-level keys for snapshots produced before the "fields"
# nesting was introduced.
DRIFT=0
check() {
  local field="$1" current="$2"
  local baseline
  baseline=$(python3 - "$LATEST" "$field" <<'PY'
import json, sys
path, field = sys.argv[1], sys.argv[2]
with open(path) as fh:
    data = json.load(fh)
fields = data.get("fields", data)
print(fields.get(field, "unknown"))
PY
)
  if [[ "$current" == "$baseline" ]]; then
    echo "  [OK]   $field: $current"
  else
    echo "  [DRIFT] $field: was '$baseline', now '$current'"
    DRIFT=$((DRIFT+1))
  fi
}

# stat -c (GNU) and stat -f (BSD) disagree on flags; pick the right one
# for the timestamp display only — no functional impact on drift logic.
if SNAP_MTIME=$(stat -c '%y' "$LATEST" 2>/dev/null); then
  SNAP_MTIME=${SNAP_MTIME%.*}
else
  SNAP_MTIME=$(stat -f '%Sm' -t '%Y-%m-%d %H:%M:%S' "$LATEST" 2>/dev/null || echo "unknown")
fi
echo "[Sarge] Drift Detection — comparing against ${SNAP_MTIME}"
platform drift_check_fields

echo ""
if [[ "$DRIFT" -eq 0 ]]; then
  echo "[Sarge] No drift detected. Configuration matches baseline."
else
  echo "[Sarge] DRIFT DETECTED: $DRIFT items changed. Review and remediate."
  exit 2
fi
