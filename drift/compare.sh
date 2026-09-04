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

# Per-run folder layout (issue #34). Standalone compare.sh invocations get
# a fresh run root; when assess.sh / drift-cron.sh exports one we reuse it.
SARGE_RUN_ID="${SARGE_RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
SARGE_RUN_ROOT="${SARGE_RUN_ROOT:-$HOME/.sarge/runs/$SARGE_RUN_ID}"
mkdir -p "$SARGE_RUN_ROOT"
export SARGE_RUN_ID SARGE_RUN_ROOT
DRIFT_REPORT="$SARGE_RUN_ROOT/drift-report.json"
DRIFT_ITEMS_FILE="$(mktemp)"
trap 'rm -f "$DRIFT_ITEMS_FILE"' EXIT

# The platform's drift_check_fields function calls this helper for each
# field it knows about. Reads the baseline value out of the snapshot JSON
# via a python one-liner (python3 is on every supported platform); falls
# back to top-level keys for snapshots produced before the "fields"
# nesting was introduced. The Python snippet swallows its own errors and
# the assignment is guarded with `|| true` so that a missing python3, an
# unreadable snapshot, or malformed JSON degrades gracefully (one field
# reported as drift against "unknown") instead of aborting under set -e.
DRIFT=0
check() {
  local field="$1" current="$2"
  local baseline
  baseline=$(python3 - "$LATEST" "$field" <<'PY' 2>/dev/null
import json, sys
try:
    path, field = sys.argv[1], sys.argv[2]
    with open(path) as fh:
        data = json.load(fh)
    fields = data.get("fields", data)
    print(fields.get(field, "unknown"))
except Exception:
    print("unknown")
PY
) || true
  baseline=${baseline:-unknown}
  if [[ "$current" == "$baseline" ]]; then
    echo "  [OK]   $field: $current"
    printf '%s\t%s\t%s\t%s\n' "ok" "$field" "$baseline" "$current" >> "$DRIFT_ITEMS_FILE"
  else
    echo "  [DRIFT] $field: was '$baseline', now '$current'"
    DRIFT=$((DRIFT+1))
    printf '%s\t%s\t%s\t%s\n' "drift" "$field" "$baseline" "$current" >> "$DRIFT_ITEMS_FILE"
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

# Tamper-evident snapshot chain verification. The current snapshot
# records the hash of the file that WAS latest.json at the moment it was
# taken (see drift/snapshot.sh). To verify, find that predecessor file
# on disk — snapshot filenames sort lexicographically by timestamp, so
# it's the entry immediately before the current target in a sorted
# listing — and recompute its hash. A mismatch (or a recorded hash that
# no longer resolves to any file on disk) means either the predecessor
# was retroactively edited or the chain metadata itself was tampered
# with. Missing predecessor (first-ever snapshot, "none") is valid.
CHAIN_VALID="true"
CURRENT_PREV_HASH=$(python3 - "$LATEST" <<'PY' 2>/dev/null
import json, sys
try:
    with open(sys.argv[1]) as fh:
        data = json.load(fh)
    print(data.get("previous_hash", "none"))
except Exception:
    print("none")
PY
) || true
CURRENT_PREV_HASH=${CURRENT_PREV_HASH:-none}

CURRENT_TARGET=$(readlink -f "$LATEST" 2>/dev/null || readlink "$LATEST" 2>/dev/null || echo "$LATEST")
if [[ "$CURRENT_PREV_HASH" == "none" ]]; then
  echo "[CHAIN] Snapshot integrity: OK (first snapshot in chain)"
else
  PREDECESSOR=""
  while IFS= read -r f; do
    if [[ "$f" == "$CURRENT_TARGET" ]]; then
      break
    fi
    PREDECESSOR="$f"
  done < <(find "$SNAPSHOT_DIR" -maxdepth 1 -name 'snapshot-*.json' 2>/dev/null | sort)

  if [[ -z "$PREDECESSOR" ]] || [[ ! -f "$PREDECESSOR" ]]; then
    # Predecessor no longer exists on disk — can't verify either way.
    # Don't fail the chain on legitimate pruning/rotation; only flag a
    # mismatch when we CAN compute a hash and it disagrees.
    echo "[CHAIN] Snapshot integrity: UNVERIFIABLE (predecessor snapshot not found on disk)"
  elif command -v sha256sum &>/dev/null; then
    ACTUAL_PREV_HASH=$(sha256sum "$PREDECESSOR" 2>/dev/null | awk '{print $1}') || true
    if [[ "$ACTUAL_PREV_HASH" == "$CURRENT_PREV_HASH" ]]; then
      echo "[CHAIN] Snapshot integrity: OK"
    else
      echo "[CHAIN] Snapshot integrity: BROKEN"
      CHAIN_VALID="false"
    fi
  else
    echo "[CHAIN] Snapshot integrity: UNVERIFIABLE (sha256sum unavailable)"
  fi
fi

# Write per-run drift-report.json (issue #34). Self-contained machine-
# readable view of this compare invocation; the legacy stdout summary
# above is unchanged so existing log scrapers keep working.
NOW_TS=$(date -Iseconds 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)
if command -v jq &>/dev/null; then
  jq -R -s \
    --arg ts "$NOW_TS" \
    --arg host "$(hostname)" \
    --arg snapshot "$LATEST" \
    --argjson drift_count "$DRIFT" \
    --argjson chain_valid "$CHAIN_VALID" \
    '{
      timestamp: $ts,
      host: $host,
      baseline_snapshot: $snapshot,
      drift_count: $drift_count,
      chain_valid: $chain_valid,
      items: (
        split("\n")
        | map(select(length > 0))
        | map(split("\t"))
        | map({status: .[0], field: .[1], baseline: .[2], current: .[3]})
      )
    }' < "$DRIFT_ITEMS_FILE" > "$DRIFT_REPORT" 2>/dev/null || true
else
  {
    echo "{"
    echo "  \"timestamp\": \"${NOW_TS}\","
    echo "  \"host\": \"$(hostname)\","
    echo "  \"baseline_snapshot\": \"${LATEST}\","
    echo "  \"drift_count\": ${DRIFT},"
    echo "  \"chain_valid\": ${CHAIN_VALID},"
    echo "  \"items\": ["
    total_lines=$(wc -l < "$DRIFT_ITEMS_FILE" | tr -d ' ')
    idx=0
    while IFS=$'\t' read -r st field baseline current; do
      idx=$((idx+1))
      esc_baseline=$(printf '%s' "$baseline" | sed 's/\\/\\\\/g; s/"/\\"/g')
      esc_current=$(printf '%s' "$current" | sed 's/\\/\\\\/g; s/"/\\"/g')
      sep=","; [[ "$idx" -eq "$total_lines" ]] && sep=""
      echo "    {\"status\": \"${st}\", \"field\": \"${field}\", \"baseline\": \"${esc_baseline}\", \"current\": \"${esc_current}\"}${sep}"
    done < "$DRIFT_ITEMS_FILE"
    echo "  ]"
    echo "}"
  } > "$DRIFT_REPORT"
fi

echo "[Sarge] Drift report: $DRIFT_REPORT"
echo "[Sarge] Run folder:   $SARGE_RUN_ROOT"

if [[ "$DRIFT" -eq 0 ]]; then
  echo "[Sarge] No drift detected. Configuration matches baseline."
else
  echo "[Sarge] DRIFT DETECTED: $DRIFT items changed. Review and remediate."
  exit 2
fi
