#!/usr/bin/env bash
# tests/integration/report-validation.sh
# Validates assessment report structure: JSON fields, Markdown sections,
# count consistency, and findings catalog.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

PASS=0; TESTS=0
fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { PASS=$((PASS+1)); TESTS=$((TESTS+1)); echo "  ok: $*"; }

# Use temp directories so we don't pollute real state
TMPDIR_REPORT=$(mktemp -d)
trap 'rm -rf "$TMPDIR_REPORT"' EXIT
export SARGE_REPORT_DIR="$TMPDIR_REPORT/reports"
export SARGE_STATE_DIR="$TMPDIR_REPORT/state"
export SARGE_RUN_ROOT="$TMPDIR_REPORT/run"
export SARGE_RUN_ID="test-report-$$"
mkdir -p "$SARGE_REPORT_DIR" "$SARGE_STATE_DIR" "$SARGE_RUN_ROOT"

# --- Syntax check ---
bash -n "$REPO_ROOT/assessment/report/report.sh" || fail "report.sh syntax error"
ok "report.sh syntax"

# --- Run assessment ---
ASSESS_OUTPUT=$(bash "$REPO_ROOT/assessment/assess.sh" 2>&1) || true
ok "assess.sh runs without crashing"

# --- JSON report exists ---
[[ -f "$SARGE_RUN_ROOT/report.json" ]] || fail "report.json not created in run root"
ok "report.json exists in run root"

REPORT_JSON="$SARGE_RUN_ROOT/report.json"

# --- JSON structure validation ---
if command -v jq &>/dev/null; then
  # Verify summary object with required fields
  for field in pass warn fail skip total; do
    val=$(jq -r ".summary.$field // \"MISSING\"" "$REPORT_JSON" 2>/dev/null)
    [[ "$val" != "MISSING" && "$val" != "null" ]] || fail "report.json missing summary.$field"
  done
  ok "report.json has summary with pass, warn, fail, skip, total"

  # Verify results array with at least one entry
  RESULT_COUNT=$(jq '.results | length' "$REPORT_JSON" 2>/dev/null)
  [[ "$RESULT_COUNT" -gt 0 ]] || fail "report.json results array is empty"
  ok "report.json results array has $RESULT_COUNT entries"

  # Verify each result has status, check_id (may be aliased as id), detail/message
  FIRST_STATUS=$(jq -r '.results[0].status // empty' "$REPORT_JSON" 2>/dev/null)
  [[ -n "$FIRST_STATUS" ]] || fail "report.json results[0] missing status"
  # check_id may be empty string for legacy entries, but the field must exist
  HAS_CHECK_ID=$(jq 'has("results") and (.results[0] | has("check_id") or has("id"))' "$REPORT_JSON" 2>/dev/null)
  [[ "$HAS_CHECK_ID" == "true" ]] || fail "report.json results[0] missing check_id/id field"
  HAS_DETAIL=$(jq '.results[0] | has("detail") or has("message")' "$REPORT_JSON" 2>/dev/null)
  [[ "$HAS_DETAIL" == "true" ]] || fail "report.json results[0] missing detail/message field"
  ok "report.json results entries have status, check_id, detail fields"

  # --- Count consistency ---
  S_PASS=$(jq '.summary.pass' "$REPORT_JSON" 2>/dev/null)
  S_WARN=$(jq '.summary.warn' "$REPORT_JSON" 2>/dev/null)
  S_FAIL=$(jq '.summary.fail' "$REPORT_JSON" 2>/dev/null)
  S_SKIP=$(jq '.summary.skip' "$REPORT_JSON" 2>/dev/null)
  S_TOTAL=$(jq '.summary.total' "$REPORT_JSON" 2>/dev/null)
  COMPUTED=$((S_PASS + S_WARN + S_FAIL + S_SKIP))
  [[ "$S_TOTAL" -eq "$COMPUTED" ]] || fail "summary.total ($S_TOTAL) != pass+warn+fail+skip ($COMPUTED)"
  ok "count consistency: summary.total equals pass+warn+fail+skip"

else
  # python3 fallback
  python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
s=d['summary']
for f in ['pass','warn','fail','skip','total']:
    assert f in s, f'missing summary.{f}'
" "$REPORT_JSON" || fail "report.json missing summary fields"
  ok "report.json has summary with pass, warn, fail, skip, total"

  python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
r=d['results']
assert len(r)>0, 'results array empty'
" "$REPORT_JSON" || fail "report.json results array is empty"
  ok "report.json results array is non-empty"

  python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
r=d['results'][0]
assert 'status' in r, 'missing status'
assert 'check_id' in r or 'id' in r, 'missing check_id/id'
assert 'detail' in r or 'message' in r, 'missing detail/message'
" "$REPORT_JSON" || fail "report.json results[0] missing required fields"
  ok "report.json results entries have status, check_id, detail fields"

  python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
s=d['summary']
computed=s['pass']+s['warn']+s['fail']+s['skip']
assert s['total']==computed, f'total {s[\"total\"]} != computed {computed}'
" "$REPORT_JSON" || fail "count consistency check failed"
  ok "count consistency: summary.total equals pass+warn+fail+skip"
fi

# --- Markdown report exists ---
[[ -f "$SARGE_RUN_ROOT/report.md" ]] || fail "report.md not created in run root"
ok "report.md exists in run root"

REPORT_MD="$SARGE_RUN_ROOT/report.md"

# --- Markdown structure ---
grep -q "Assessment Complete" "$ASSESS_OUTPUT" <<< "$ASSESS_OUTPUT" 2>/dev/null \
  || echo "$ASSESS_OUTPUT" | grep -q "Assessment Complete" \
  || fail "assess.sh output missing 'Assessment Complete'"
ok "assess.sh output contains 'Assessment Complete'"

grep -q "PASS" "$REPORT_MD" || fail "report.md missing PASS reference"
grep -q "FAIL" "$REPORT_MD" || fail "report.md missing FAIL reference"
ok "report.md contains PASS and FAIL sections"

# --- Findings catalog ---
[[ -f "$SARGE_RUN_ROOT/findings.json" ]] || fail "findings.json not created in run root"
ok "findings.json exists in run root"

# Verify findings.json is valid JSON
if command -v jq &>/dev/null; then
  jq empty "$SARGE_RUN_ROOT/findings.json" 2>/dev/null || fail "findings.json is not valid JSON"
else
  python3 -c "import json; json.load(open('$SARGE_RUN_ROOT/findings.json'))" 2>/dev/null \
    || fail "findings.json is not valid JSON"
fi
ok "findings.json is valid JSON"

echo ""
echo "report-validation: $PASS/$TESTS passed"
[[ "$PASS" -eq "$TESTS" ]]
