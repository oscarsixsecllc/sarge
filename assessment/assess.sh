#!/usr/bin/env bash
# assess.sh — Sarge Gap Analysis Runner
# NIST 800-53 Rev 5 | Oscar Six Security LLC
# No sudo required. Read-only. No network calls.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# shellcheck source=../lib/platform.sh
source "${REPO_ROOT}/lib/platform.sh"
sarge_require_supported_os

# Assessment checks are currently Ubuntu-only. macOS-aware probes ship in a
# follow-up PR — until then, refuse on non-Ubuntu rather than emit garbage
# results. Exit 2 is deliberate (not exit 0): assess is a measurement tool, so
# a silent exit 0 could be misread by CI as "no NIST gaps found." See the
# "Script Exit Codes" section in README.md for the full per-script contract.
if [[ "$SARGE_OS" != "ubuntu" ]]; then
  echo "[Sarge] Gap analysis on ${SARGE_OS_DESCRIPTION} is not yet implemented." >&2
  echo "[Sarge] Track the rollout: https://github.com/oscarsixsecllc/sarge/issues" >&2
  exit 2
fi

REPORT_DIR="${SARGE_REPORT_DIR:-$HOME/.sarge/reports}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
REPORT_BASE="${REPORT_DIR}/sarge-report-${TIMESTAMP}"

# Counters
PASS=0; WARN=0; FAIL=0; SKIP=0
declare -a RESULTS=()

mkdir -p "$REPORT_DIR"

log()   { echo "[SARGE] $*"; }
pass()  { echo "  [PASS] $*"; PASS=$((PASS+1)); RESULTS+=("PASS|$*"); }
warn()  { echo "  [WARN] $*"; WARN=$((WARN+1)); RESULTS+=("WARN|$*"); }
fail()  { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); RESULTS+=("FAIL|$*"); }
skip()  { echo "  [SKIP] $*"; SKIP=$((SKIP+1)); RESULTS+=("SKIP|$*"); }

export -f pass warn fail skip
export PASS WARN FAIL SKIP

log "======================================"
log " Sarge NIST 800-53 Gap Analysis"
log " Oscar Six Security LLC"
log " $(date)"
log " Host: $(hostname)"
log " OS: $(lsb_release -sd 2>/dev/null || uname -a)"
log "======================================"
echo ""

CHECKS_DIR="${SCRIPT_DIR}/checks"
for check in "$CHECKS_DIR"/check-*.sh; do
  [[ -x "$check" ]] || chmod +x "$check"
  family=$(basename "$check" .sh | sed 's/check-//' | tr '[:lower:]' '[:upper:]')
  log "--- Running ${family} checks ---"
  # Source each check so they can call pass/warn/fail/skip and accumulate counts
  source "$check" || true
  echo ""
done

log "======================================"
log " Assessment Complete"
log " PASS: $PASS | WARN: $WARN | FAIL: $FAIL | SKIP: $SKIP"
log " Total: $((PASS+WARN+FAIL+SKIP))"
log "======================================"

# Generate reports
"${SCRIPT_DIR}/report/report.sh" \
  --pass "$PASS" --warn "$WARN" --fail "$FAIL" --skip "$SKIP" \
  --output "$REPORT_BASE" \
  --results "$(printf '%s\n' "${RESULTS[@]}")" 2>/dev/null || true

log "Reports written to: $REPORT_BASE.md and $REPORT_BASE.json"
