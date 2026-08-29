#!/usr/bin/env bash
# tests/integration/agent-safety-checks.sh
#
# Validates that the AS (Agent Safety) family check emits the expected
# structured findings for each of AS-1..AS-8 under three scenarios:
#
#   1. Nothing installed   -> AS-1, AS-2, AS-3, AS-4, AS-8 FAIL; AS-6/AS-7 WARN
#                             (AS-5 SKIPs when the deployed and upstream
#                             gate_common.py copies are both absent)
#   2. Everything present  -> all AS checks PASS
#   3. Weak permissions    -> AS-3, AS-6, AS-8 FAIL on perm; content pass
#
# Also verifies:
#   - check-as.sh has valid bash syntax
#   - Every AS check_id emitted by the script has a matching entry in
#     assessment/findings-catalog.json (report.sh joins on check_id)
#   - The AS family is agent-scoped (SARGE_HOST_ONLY=1 skips the whole file)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

PASS=0; TESTS=0
fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { PASS=$((PASS+1)); TESTS=$((TESTS+1)); echo "  ok: $*"; }

# --- Syntax check ---
bash -n "$REPO_ROOT/assessment/checks/check-as.sh" || fail "check-as.sh syntax error"
ok "check-as.sh syntax"

# --- Isolated temp home so nothing on the running host bleeds in ---
TMPHOME=$(mktemp -d)
trap 'rm -rf "$TMPHOME"' EXIT
export HOME="$TMPHOME"
export SARGE_REPORT_DIR="$TMPHOME/reports"
export SARGE_STATE_DIR="$TMPHOME/state"
export SARGE_RUN_ROOT="$TMPHOME/run"
export SARGE_RUN_ID="test-as-$$"
mkdir -p "$SARGE_REPORT_DIR" "$SARGE_STATE_DIR" "$SARGE_RUN_ROOT"

run_check() {
  # Runs assess.sh and returns the raw output so scenarios can grep for
  # specific AS-N verdict lines.
  bash "$REPO_ROOT/assessment/assess.sh" 2>&1
}

# ---------- Scenario 1: nothing installed ----------
OUT=$(run_check)
echo "$OUT" | grep -q "\[FAIL\] AS-1: tool-gate hook files missing" \
  || fail "scenario1: AS-1 did not FAIL on missing hooks; got: $(echo "$OUT" | grep AS-1)"
ok "scenario1: AS-1 FAILs on missing hooks"

echo "$OUT" | grep -q "\[FAIL\] AS-2: ~/.config/o6-gate-mode missing" \
  || fail "scenario1: AS-2 did not FAIL on missing mode file"
ok "scenario1: AS-2 FAILs on missing mode file"

echo "$OUT" | grep -q "\[FAIL\] AS-3: decisions ledger missing" \
  || fail "scenario1: AS-3 did not FAIL on missing ledger"
ok "scenario1: AS-3 FAILs on missing ledger"

echo "$OUT" | grep -q "\[FAIL\] AS-8: cron-trust.json missing" \
  || fail "scenario1: AS-8 did not FAIL on missing cron-trust.json"
ok "scenario1: AS-8 FAILs on missing cron-trust.json"

echo "$OUT" | grep -Eq "\[WARN\] AS-6: workspace-attestations/ missing" \
  || fail "scenario1: AS-6 did not WARN on missing attestations dir"
ok "scenario1: AS-6 WARNs on missing attestations dir"

echo "$OUT" | grep -Eq "\[WARN\] AS-7: skill-workshop/ missing" \
  || fail "scenario1: AS-7 did not WARN on missing workshop"
ok "scenario1: AS-7 WARNs on missing workshop"

# ---------- Scenario 2: everything present, well-formed ----------
mkdir -p "$TMPHOME/.claude/hooks" "$TMPHOME/.config" \
         "$TMPHOME/.openclaw/state/tool-gate" \
         "$TMPHOME/.openclaw/workspace-attestations" \
         "$TMPHOME/.openclaw/skill-workshop/proposals" \
         "$TMPHOME/openclaw/security/tool-gate"

echo "print('gate')" > "$TMPHOME/.claude/hooks/tool-gate.py"
echo "print('taint')" > "$TMPHOME/.claude/hooks/taint-record.py"
echo 'print("common")' > "$TMPHOME/openclaw/security/tool-gate/gate_common.py"
cp "$TMPHOME/openclaw/security/tool-gate/gate_common.py" \
   "$TMPHOME/.claude/hooks/gate_common.py"
cat > "$TMPHOME/.claude/settings.json" <<'JSON'
{ "hooks": { "PreToolUse": [ { "hooks": [ { "type": "command", "command": ".claude/hooks/tool-gate.py" } ] } ] } }
JSON
echo "tier-c" > "$TMPHOME/.config/o6-gate-mode"
echo '{}' > "$TMPHOME/.openclaw/state/tool-gate/decisions.jsonl"
chmod 600 "$TMPHOME/.openclaw/state/tool-gate/decisions.jsonl"
echo '{}' > "$TMPHOME/.openclaw/state/tool-gate/cron-trust.json"
chmod 600 "$TMPHOME/.openclaw/state/tool-gate/cron-trust.json"
chmod 700 "$TMPHOME/.openclaw/workspace-attestations"
touch "$TMPHOME/.openclaw/workspace-attestations/abc123.attested"

OUT=$(run_check)
echo "$OUT" | grep -q "\[PASS\] AS-1: tool-gate.py + taint-record.py present" \
  || fail "scenario2: AS-1 did not PASS with hooks wired; got: $(echo "$OUT" | grep AS-1)"
ok "scenario2: AS-1 PASSes with hooks wired"

echo "$OUT" | grep -q "\[PASS\] AS-2: gate mode is 'tier-c'" \
  || fail "scenario2: AS-2 did not PASS on tier-c mode"
ok "scenario2: AS-2 PASSes on tier-c mode"

echo "$OUT" | grep -q "\[PASS\] AS-3: decisions.jsonl permissions are 600" \
  || fail "scenario2: AS-3 did not PASS on 600 ledger"
ok "scenario2: AS-3 PASSes on 600 ledger"

echo "$OUT" | grep -q "\[PASS\] AS-5: deployed gate_common.py matches upstream" \
  || fail "scenario2: AS-5 did not PASS on matching gate_common.py"
ok "scenario2: AS-5 PASSes on matching gate_common.py"

echo "$OUT" | grep -q "\[PASS\] AS-6: workspace-attestations/ permissions are 700" \
  || fail "scenario2: AS-6 did not PASS on 700 attestations dir"
ok "scenario2: AS-6 PASSes on 700 attestations dir"

echo "$OUT" | grep -q "\[PASS\] AS-7: skill-workshop/ + proposals/ subdirectory present" \
  || fail "scenario2: AS-7 did not PASS on present workshop"
ok "scenario2: AS-7 PASSes on present workshop"

echo "$OUT" | grep -q "\[PASS\] AS-8: cron-trust.json permissions are 600" \
  || fail "scenario2: AS-8 did not PASS on 600 cron-trust"
ok "scenario2: AS-8 PASSes on 600 cron-trust"

# ---------- Scenario 3: weak permissions ----------
chmod 664 "$TMPHOME/.openclaw/state/tool-gate/decisions.jsonl"
chmod 775 "$TMPHOME/.openclaw/workspace-attestations"
chmod 664 "$TMPHOME/.openclaw/state/tool-gate/cron-trust.json"

OUT=$(run_check)
echo "$OUT" | grep -q "\[FAIL\] AS-3: decisions.jsonl permissions are 664" \
  || fail "scenario3: AS-3 did not FAIL on 664 ledger"
ok "scenario3: AS-3 FAILs on 664 ledger"

echo "$OUT" | grep -q "\[FAIL\] AS-6: workspace-attestations/ permissions are 775" \
  || fail "scenario3: AS-6 did not FAIL on 775 attestations dir"
ok "scenario3: AS-6 FAILs on 775 attestations dir"

echo "$OUT" | grep -q "\[FAIL\] AS-8: cron-trust.json permissions are 664" \
  || fail "scenario3: AS-8 did not FAIL on 664 cron-trust"
ok "scenario3: AS-8 FAILs on 664 cron-trust"

# ---------- Scenario 4: catalog coverage ----------
# Every AS check_id that the script emits must exist in
# findings-catalog.json so report.sh can render a Findings block for it.
EMITTED_IDS=$(grep -Eho 'passx "AS-[^"]+"|warnx "AS-[^"]+"|failx "AS-[^"]+"|skipx "AS-[^"]+"' \
  "$REPO_ROOT/assessment/checks/check-as.sh" \
  | awk -F'"' '{print $2}' | sort -u)
[[ -n "$EMITTED_IDS" ]] || fail "scenario4: could not extract any AS check_ids from check-as.sh"

MISSING=""
while IFS= read -r id; do
  [[ -z "$id" ]] && continue
  python3 -c "
import json, sys
with open('$REPO_ROOT/assessment/findings-catalog.json') as f:
    d = json.load(f)
sys.exit(0 if '$id' in d else 1)
" 2>/dev/null || MISSING="$MISSING $id"
done <<< "$EMITTED_IDS"
[[ -z "$MISSING" ]] || fail "scenario4: AS check_ids missing from findings-catalog.json:$MISSING"
ok "scenario4: every AS check_id has a findings-catalog entry"

# ---------- Scenario 5: host-only mode skips AS entirely ----------
OUT=$(SARGE_HOST_ONLY=1 bash "$REPO_ROOT/assessment/assess.sh" 2>&1)
if echo "$OUT" | grep -q "AS-"; then
  fail "scenario5: host-only mode emitted AS-* checks; agent-scope guard broken"
fi
ok "scenario5: host-only mode skips AS family"

echo ""
echo "agent-safety-checks: $PASS/$TESTS passed"
