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

# --- File integrity hash fields (issue: file hashing) ---
for field in openclaw_json_sha256 sshd_config_sha256 pam_common_auth_sha256 \
             audit_rules_sha256 ufw_rules_sha256; do
  if command -v jq &>/dev/null; then
    val=$(jq -r ".fields.${field} // empty" "$LATEST" 2>/dev/null)
  else
    val=$(python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
v=d.get('fields',{}).get(sys.argv[2])
if v is not None: print(v)
" "$LATEST" "$field" 2>/dev/null)
  fi
  [[ -n "$val" ]] || fail "snapshot JSON missing file-hash field: $field"
done
ok "snapshot JSON has file-integrity hash fields"

# --- Package/service inventory hashes (issue: inventory tracking) ---
for field in installed_packages_sha256 enabled_services_sha256; do
  if command -v jq &>/dev/null; then
    val=$(jq -r ".fields.${field} // empty" "$LATEST" 2>/dev/null)
  else
    val=$(python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
v=d.get('fields',{}).get(sys.argv[2])
if v is not None: print(v)
" "$LATEST" "$field" 2>/dev/null)
  fi
  [[ -n "$val" ]] || fail "snapshot JSON missing inventory-hash field: $field"
done
ok "snapshot JSON has package/service inventory hash fields"

# --- Control-catalog sync field (issue: catalog sync check) ---
if command -v jq &>/dev/null; then
  cat_val=$(jq -r '.fields.catalog_controls_sha256 // empty' "$LATEST" 2>/dev/null)
else
  cat_val=$(python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
v=d.get('fields',{}).get('catalog_controls_sha256')
if v is not None: print(v)
" "$LATEST" 2>/dev/null)
fi
[[ -n "$cat_val" ]] || fail "snapshot JSON missing catalog_controls_sha256 field"
ok "snapshot JSON has catalog sync field (catalog_controls_sha256)"

# --- Tamper-evident snapshot chain (issue: hash-chained snapshots) ---
# Uses its own fresh SARGE_SNAPSHOT_DIR: the drift-simulation test above
# rewrites latest.json in place (jq output moved onto the symlink path),
# which turns latest.json from a symlink into a plain file and would
# otherwise confuse the chain's file-identity assumptions here.
CHAIN_SNAPSHOT_DIR="$TMPDIR_DRIFT/snapshots-chain"
mkdir -p "$CHAIN_SNAPSHOT_DIR"
export SARGE_SNAPSHOT_DIR="$CHAIN_SNAPSHOT_DIR"
CHAIN_LATEST="$CHAIN_SNAPSHOT_DIR/latest.json"

export SARGE_RUN_ROOT="$TMPDIR_DRIFT/run-chain1"
export SARGE_RUN_ID="test-chain1-$$"
mkdir -p "$SARGE_RUN_ROOT"
bash "$REPO_ROOT/drift/snapshot.sh" > /dev/null 2>&1 || fail "first chain snapshot.sh exited non-zero"

# First-ever snapshot in a fresh SARGE_SNAPSHOT_DIR has no predecessor,
# so previous_hash must be the literal "none".
if command -v jq &>/dev/null; then
  prev_hash=$(jq -r '.previous_hash // empty' "$CHAIN_LATEST" 2>/dev/null)
else
  prev_hash=$(python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
v=d.get('previous_hash')
if v is not None: print(v)
" "$CHAIN_LATEST" 2>/dev/null)
fi
[[ "$prev_hash" == "none" ]] || fail "first snapshot previous_hash should be 'none', got '$prev_hash'"
ok "first snapshot previous_hash is 'none'"

# Take a second snapshot and confirm its previous_hash is a real sha256
# (not 'none') and the chain reports OK.
export SARGE_RUN_ROOT="$TMPDIR_DRIFT/run-chain2"
export SARGE_RUN_ID="test-chain2-$$"
mkdir -p "$SARGE_RUN_ROOT"
sleep 1
bash "$REPO_ROOT/drift/snapshot.sh" > /dev/null 2>&1 || fail "second snapshot.sh exited non-zero"
if command -v jq &>/dev/null; then
  prev_hash2=$(jq -r '.previous_hash // empty' "$CHAIN_LATEST" 2>/dev/null)
else
  prev_hash2=$(python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
v=d.get('previous_hash')
if v is not None: print(v)
" "$CHAIN_LATEST" 2>/dev/null)
fi
[[ -n "$prev_hash2" && "$prev_hash2" != "none" ]] || fail "second snapshot previous_hash should be a real hash, got '$prev_hash2'"
ok "second snapshot previous_hash records predecessor's hash"

export SARGE_RUN_ROOT="$TMPDIR_DRIFT/run-chain-ok"
export SARGE_RUN_ID="test-chain-ok-$$"
mkdir -p "$SARGE_RUN_ROOT"
CHAIN_OUT=$(bash "$REPO_ROOT/drift/compare.sh" 2>&1)
echo "$CHAIN_OUT" | grep -q "\[CHAIN\] Snapshot integrity: OK" || fail "expected intact chain to report OK, got: $CHAIN_OUT"
ok "compare.sh reports chain OK for an untampered chain"

# Restore the original snapshot dir for anything after this point.
export SARGE_SNAPSHOT_DIR="$TMPDIR_DRIFT/snapshots"

echo ""
echo "drift-detection: $PASS/$TESTS passed"
[[ "$PASS" -eq "$TESTS" ]]
