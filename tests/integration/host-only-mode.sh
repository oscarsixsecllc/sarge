#!/usr/bin/env bash
# tests/integration/host-only-mode.sh
# Validates --host-only mode: catalog scope tags, guard coverage, syntax.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CATALOG="$REPO_ROOT/assessment/findings-catalog.json"

PASS=0; TESTS=0
fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { PASS=$((PASS+1)); TESTS=$((TESTS+1)); echo "  ok: $*"; }

# --- Syntax checks ---
bash -n "$REPO_ROOT/assessment/assess.sh" || fail "assess.sh syntax error"
ok "assess.sh syntax"

for f in "$REPO_ROOT"/assessment/checks/check-*.sh; do
  bash -n "$f" || fail "$(basename "$f") syntax error"
done
ok "all check-*.sh syntax"

# --- Catalog scope tags ---
AGENT_IDS=(
  AC-3-openclaw-dir-perm
  AC-3-secrets-dir-perm
  AC-3-secret-file-perm
  AU-12-no-openclaw-rules
  SC-8-cloudflared-not-detected
  SC-28-config-perm
  SC-28-config-owner
  SC-28-world-readable-secrets
)

for id in "${AGENT_IDS[@]}"; do
  scope=$(python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
e=d.get(sys.argv[2],{})
print(e.get('scope',''))
" "$CATALOG" "$id" 2>/dev/null)
  [[ "$scope" == "agent" ]] || fail "catalog entry $id missing scope:agent (got '$scope')"
done
ok "all agent findings have scope:agent in catalog"

HOST_IDS=(AC-2-empty-password AC-6-passwordless-sudo AU-2-auditd-not-running CM-2-no-baseline)
for id in "${HOST_IDS[@]}"; do
  scope=$(python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
e=d.get(sys.argv[2],{})
print(e.get('scope',''))
" "$CATALOG" "$id" 2>/dev/null)
  [[ "$scope" == "" ]] || fail "host-scope entry $id should NOT have scope field (got '$scope')"
done
ok "host findings have no scope tag (implicit host)"

# --- Guard coverage: agent blocks are wrapped in SARGE_HOST_ONLY checks ---
# Verify that every agent check ID appears inside a SARGE_HOST_ONLY guarded
# block. We check that the guard line appears before the first use of the ID.
for id in "${AGENT_IDS[@]}"; do
  found=0
  for check_file in "$REPO_ROOT"/assessment/checks/check-*.sh; do
    if grep -q "$id" "$check_file" 2>/dev/null; then
      found=1
      guard_line=$(grep -n 'SARGE_HOST_ONLY' "$check_file" | head -1 | cut -d: -f1)
      id_line=$(grep -n "$id" "$check_file" | head -1 | cut -d: -f1)
      [[ -n "$guard_line" && -n "$id_line" && "$guard_line" -lt "$id_line" ]] \
        || fail "$id in $(basename "$check_file") is not guarded by SARGE_HOST_ONLY"
    fi
  done
  [[ "$found" -eq 1 ]] || fail "$id not found in any check file"
done
ok "all agent check IDs are guarded by SARGE_HOST_ONLY"

# --- assess.sh accepts --host-only without error ---
grep -q '\-\-host-only' "$REPO_ROOT/assessment/assess.sh" || fail "assess.sh doesn't parse --host-only"
ok "assess.sh parses --host-only flag"

# --- report.sh accepts --mode ---
grep -q '\-\-mode' "$REPO_ROOT/assessment/report/report.sh" || fail "report.sh doesn't parse --mode"
ok "report.sh parses --mode parameter"

echo ""
echo "host-only-mode: $PASS/$TESTS passed"
[[ "$PASS" -eq "$TESTS" ]]
