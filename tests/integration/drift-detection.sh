#!/usr/bin/env bash
# tests/integration/drift-detection.sh
# Validates the drift detection pipeline: snapshot → compare → detect.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

PASS=0; TESTS=0
fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { PASS=$((PASS+1)); TESTS=$((TESTS+1)); echo "  ok: $*"; }

# Use a temp directory so we don't pollute real snapshot state
TMPDIR_DRIFT=$(mktemp -d)
trap 'rm -rf "$TMPDIR_DRIFT"' EXIT
export SARGE_SNAPSHOT_DIR="$TMPDIR_DRIFT/snapshots"
export SARGE_RUN_ROOT="$TMPDIR_DRIFT/run"
export SARGE_RUN_ID="test-drift-$$"
mkdir -p "$SARGE_SNAPSHOT_DIR" "$SARGE_RUN_ROOT"

# --- Syntax checks ---
bash -n "$REPO_ROOT/drift/snapshot.sh" || fail "snapshot.sh syntax error"
ok "snapshot.sh syntax"

bash -n "$REPO_ROOT/drift/compare.sh" || fail "compare.sh syntax error"
ok "compare.sh syntax"

# --- Snapshot creation ---
bash "$REPO_ROOT/drift/snapshot.sh" > /dev/null 2>&1 || fail "snapshot.sh exited non-zero"
[[ -L "$SARGE_SNAPSHOT_DIR/latest.json" ]] || fail "latest.json symlink not created"
ok "snapshot creates latest.json symlink"

# Verify snapshot JSON has required fields
LATEST="$SARGE_SNAPSHOT_DIR/latest.json"
for field in timestamp platform fields; do
  if command -v jq &>/dev/null; then
    val=$(jq -r ".$field // empty" "$LATEST" 2>/dev/null)
  else
    val=$(python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
v=d.get(sys.argv[2])
if v is not None: print('present')
" "$LATEST" "$field" 2>/dev/null)
  fi
  [[ -n "$val" ]] || fail "snapshot JSON missing required field: $field"
done
ok "snapshot JSON has timestamp, platform, fields"

# --- No-drift baseline ---
# Reset run root for compare
export SARGE_RUN_ROOT="$TMPDIR_DRIFT/run-nodrift"
export SARGE_RUN_ID="test-nodrift-$$"
mkdir -p "$SARGE_RUN_ROOT"

bash "$REPO_ROOT/drift/compare.sh" > /dev/null 2>&1
rc=$?
[[ "$rc" -eq 0 ]] || fail "compare.sh should exit 0 (no drift) immediately after snapshot, got exit $rc"
ok "no-drift baseline: compare exits 0 immediately after snapshot"

# --- Drift detection via snapshot modification ---
# Modify the snapshot JSON to simulate drift (change a field value).
# This tests the comparison logic without invasive system changes.
export SARGE_RUN_ROOT="$TMPDIR_DRIFT/run-drift"
export SARGE_RUN_ID="test-drift-detect-$$"
mkdir -p "$SARGE_RUN_ROOT"

if command -v jq &>/dev/null; then
  # Pick the first field under .fields and change its value
  FIRST_KEY=$(jq -r '.fields | keys[0] // empty' "$LATEST" 2>/dev/null)
  if [[ -n "$FIRST_KEY" ]]; then
    jq --arg k "$FIRST_KEY" '.fields[$k] = "TAMPERED_VALUE_FOR_DRIFT_TEST"' "$LATEST" > "${LATEST}.tmp"
    mv "${LATEST}.tmp" "$LATEST"
  else
    fail "snapshot has no fields to tamper with"
  fi
else
  # python3 fallback
  FIRST_KEY=$(python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
keys=list(d.get('fields',{}).keys())
if keys: print(keys[0])
" "$LATEST" 2>/dev/null)
  if [[ -n "$FIRST_KEY" ]]; then
    python3 -c "
import json,sys
path=sys.argv[1]
key=sys.argv[2]
with open(path) as f: d=json.load(f)
d['fields'][key]='TAMPERED_VALUE_FOR_DRIFT_TEST'
with open(path,'w') as f: json.dump(d,f,indent=2)
" "$LATEST" "$FIRST_KEY"
  else
    fail "snapshot has no fields to tamper with"
  fi
fi

bash "$REPO_ROOT/drift/compare.sh" > /dev/null 2>&1
rc=$?
[[ "$rc" -eq 2 ]] || fail "compare.sh should exit 2 (drift detected) after tampering, got exit $rc"
ok "drift detection: compare exits 2 after snapshot field modification"

# --- Drift report output ---
[[ -f "$SARGE_RUN_ROOT/drift-report.json" ]] || fail "drift-report.json not created in run root"
ok "drift-report.json exists in run root"

# Verify drift-report.json is valid JSON with drift_count > 0
if command -v jq &>/dev/null; then
  dc=$(jq -r '.drift_count // 0' "$SARGE_RUN_ROOT/drift-report.json" 2>/dev/null)
else
  dc=$(python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
print(d.get('drift_count',0))
" "$SARGE_RUN_ROOT/drift-report.json" 2>/dev/null)
fi
[[ "$dc" -gt 0 ]] || fail "drift-report.json drift_count should be > 0, got $dc"
ok "drift-report.json shows drift_count > 0"

echo ""
echo "drift-detection: $PASS/$TESTS passed"
[[ "$PASS" -eq "$TESTS" ]]
