#!/usr/bin/env bash
# tests/integration/readme-control-counts.sh
# Fails CI if README.md's declared per-family/total control counts drift
# from baseline/controls.json (the source of truth). See #88, #95 —
# this has recurred twice from manual edits that don't get kept in sync.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONTROLS="$REPO_ROOT/baseline/controls.json"
README="$REPO_ROOT/README.md"

command -v jq &>/dev/null || { echo "FAIL: jq is required" >&2; exit 1; }

FAILED=0
fail() { echo "FAIL: $*" >&2; FAILED=1; }
ok()   { echo "  ok: $*"; }

# --- Ground truth: per-family and total counts from controls.json, by id field ---
TOTAL_ACTUAL=$(jq '.controls | length' "$CONTROLS")

declare -A FAMILY_ACTUAL
while IFS=$'\t' read -r fam count; do
  FAMILY_ACTUAL["$fam"]="$count"
done < <(jq -r '.controls[].id | capture("^(?<f>[A-Z]+)-").f' "$CONTROLS" | sort | uniq -c | awk '{print $2"\t"$1}')

echo "=== README control-count consistency (ground truth: baseline/controls.json) ==="
echo "  total controls: $TOTAL_ACTUAL"
for fam in "${!FAMILY_ACTUAL[@]}"; do
  echo "  $fam: ${FAMILY_ACTUAL[$fam]}"
done | sort

# --- README: per-family section headers, e.g. "### AC — Access Control (15 controls)" ---
while IFS=$'\t' read -r fam count; do
  actual="${FAMILY_ACTUAL[$fam]:-}"
  if [[ -z "$actual" ]]; then
    fail "README has a '### $fam' section header but controls.json has no $fam controls"
  elif [[ "$count" != "$actual" ]]; then
    fail "README '### $fam' section header says $count controls, controls.json has $actual"
  else
    ok "### $fam header matches controls.json ($actual)"
  fi
done < <(grep -oP '^### (?<fam>[A-Z]{2}) — .+ \((?<n>\d+) controls?\)$' "$README" | grep -oP '[A-Z]{2}|\d+' | paste - -)

# --- README: "Summary by family" bullet list, e.g. "- **AC — Access Control** — 15 controls — ..." ---
while IFS=$'\t' read -r fam count; do
  actual="${FAMILY_ACTUAL[$fam]:-}"
  if [[ -z "$actual" ]]; then
    fail "README summary-by-family bullet lists $fam but controls.json has no $fam controls"
  elif [[ "$count" != "$actual" ]]; then
    fail "README summary-by-family bullet says $fam has $count controls, controls.json has $actual"
  else
    ok "summary bullet for $fam matches controls.json ($actual)"
  fi
done < <(grep -oP '^- \*\*(?<fam>[A-Z]{2}) — [^*]+\*\* — (?<n>\d+) controls?( |—)' "$README" | grep -oP '[A-Z]{2}|\d+' | paste - -)

# --- Every family present in controls.json must appear in the summary-by-family list ---
SUMMARY_FAMS=$(grep -oP '^- \*\*(?<fam>[A-Z]{2}) — ' "$README" | grep -oP '[A-Z]{2}' | sort -u)
for fam in "${!FAMILY_ACTUAL[@]}"; do
  if ! grep -qx "$fam" <<<"$SUMMARY_FAMS"; then
    fail "controls.json has $fam controls but the summary-by-family bullet list has no $fam entry"
  fi
done

# --- README: narrative total-count sentences ---
# "Sarge's baseline (...) documents 69 individual NIST 800-53 Rev 5 controls across 12 families."
INTRO_TOTAL=$(grep -oP 'documents (?<n>\d+) individual NIST 800-53 Rev 5 controls' "$README" | grep -oP '\d+' | head -1)
if [[ -n "$INTRO_TOTAL" ]]; then
  if [[ "$INTRO_TOTAL" != "$TOTAL_ACTUAL" ]]; then
    fail "README intro sentence says $INTRO_TOTAL controls, controls.json has $TOTAL_ACTUAL"
  else
    ok "intro sentence total matches controls.json ($TOTAL_ACTUAL)"
  fi
fi

# "**69 controls across 12 NIST families + AS agent-safety overlay**"
HEADLINE_TOTAL=$(grep -oP '(?<n>\d+) controls across \d+ NIST families' "$README" | grep -oP '^\d+' | head -1)
if [[ -n "$HEADLINE_TOTAL" ]]; then
  if [[ "$HEADLINE_TOTAL" != "$TOTAL_ACTUAL" ]]; then
    fail "README headline says $HEADLINE_TOTAL controls, controls.json has $TOTAL_ACTUAL"
  else
    ok "headline total matches controls.json ($TOTAL_ACTUAL)"
  fi
fi

echo "---"
if [[ $FAILED -eq 0 ]]; then
  echo "PASS: README control counts match baseline/controls.json"
  exit 0
else
  echo "README control counts are out of sync with baseline/controls.json — update README.md"
  exit 1
fi
