#!/usr/bin/env bash
# tests/integration/catalog-platform-field.sh
# Validates per-platform map resolution in catalog_field().

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CATALOG="$REPO_ROOT/assessment/findings-catalog.json"

PASS=0; TESTS=0
fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { PASS=$((PASS+1)); TESTS=$((TESTS+1)); echo "  ok: $*"; }

# Source catalog_field() from report.sh by extracting the function.
# We can't source the whole file (it runs logic), so define it inline
# matching report.sh's implementation.
catalog_field() {
  local id="$1" field="$2"
  [[ -z "$id" ]] && return 1
  [[ ! -f "$CATALOG" ]] && return 1
  local val=""
  local os="${SARGE_OS:-}"
  if command -v jq &>/dev/null; then
    val=$(jq -r --arg id "$id" --arg f "$field" --arg os "$os" '
      .[$id][$f] as $v |
      if $v == null then empty
      elif ($v | type) == "object" then
        ($v[$os] // $v["default"] // empty)
      else $v
      end
    ' "$CATALOG" 2>/dev/null)
  elif command -v python3 &>/dev/null; then
    val=$(python3 -c '
import json,sys
try:
  d=json.load(open(sys.argv[1]))
  v=d.get(sys.argv[2],{}).get(sys.argv[3])
  if v is None:
    sys.exit(0)
  if isinstance(v, dict):
    os=sys.argv[4]
    v=v.get(os, v.get("default",""))
  if v is None: v=""
  print(v)
except Exception:
  pass
' "$CATALOG" "$id" "$field" "$os" 2>/dev/null)
  else
    return 1
  fi
  [[ -n "$val" ]] && echo "$val"
}

echo "=== catalog_field per-platform resolution ==="

# --- Test 1: macOS platform selects macos-specific fix ---
SARGE_OS=macos
result=$(catalog_field "AC-17-ufw-inactive" "fix")
[[ "$result" == *"socketfilterfw"* ]] || fail "macos fix should contain 'socketfilterfw', got: $result"
ok "SARGE_OS=macos returns macOS-specific fix for AC-17-ufw-inactive"

# --- Test 2: ubuntu platform selects default fix ---
SARGE_OS=ubuntu
result=$(catalog_field "AC-17-ufw-inactive" "fix")
[[ "$result" == *"ufw enable"* ]] || fail "ubuntu fix should contain 'ufw enable', got: $result"
ok "SARGE_OS=ubuntu falls back to default fix for AC-17-ufw-inactive"

# --- Test 3: macOS platform selects macos-specific expected ---
SARGE_OS=macos
result=$(catalog_field "AC-17-ufw-inactive" "expected")
[[ "$result" == *"Application Firewall"* ]] || fail "macos expected should mention 'Application Firewall', got: $result"
ok "SARGE_OS=macos returns macOS-specific expected for AC-17-ufw-inactive"

# --- Test 4: plain string fields are unaffected ---
SARGE_OS=macos
result=$(catalog_field "AC-17-ufw-inactive" "family")
[[ "$result" == "AC-17 — Remote Access" ]] || fail "family should be plain string, got: $result"
ok "plain string field unaffected by SARGE_OS"

# --- Test 5: empty/unset SARGE_OS falls back to default ---
SARGE_OS=""
result=$(catalog_field "AC-17-ufw-inactive" "fix")
[[ "$result" == *"ufw enable"* ]] || fail "empty SARGE_OS fix should fall back to default, got: $result"
ok "empty SARGE_OS falls back to default fix"

echo "--- $PASS/$TESTS passed ---"
[[ $PASS -eq $TESTS ]] || exit 1
