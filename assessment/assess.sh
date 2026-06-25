#!/usr/bin/env bash
# assess.sh — Sarge Gap Analysis Runner
# NIST 800-53 Rev 5 | Oscar Six Security LLC
# No sudo required. Read-only. No network calls.

set -uo pipefail

SARGE_HOST_ONLY="${SARGE_HOST_ONLY:-0}"
for arg in "$@"; do
  case "$arg" in
    --host-only) SARGE_HOST_ONLY=1 ;;
  esac
done
export SARGE_HOST_ONLY

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# shellcheck source=../lib/platform.sh
source "${REPO_ROOT}/lib/platform.sh"
sarge_require_supported_os

# Assessment checks dispatch through lib/platforms/<os>.sh; controls that
# have no native analog on the active platform emit a clean skipx with a
# platform-aware rationale (see check-au.sh / check-ia.sh / check-cm.sh /
# check-si.sh). For platforms outside the support matrix we still refuse
# with exit 2 — assess is a measurement tool, so a silent exit 0 on an
# unsupported platform could be misread by CI as "no NIST gaps found."
# See the "Script Exit Codes" section in README.md for the full contract.
case "$SARGE_OS" in
  ubuntu|macos) ;;
  *)
    echo "[Sarge] Gap analysis on ${SARGE_OS_DESCRIPTION} is not yet implemented." >&2
    echo "[Sarge] Track the rollout: https://github.com/oscarsixsecllc/sarge/issues" >&2
    exit 2
    ;;
esac

# Load platform helper dispatch — checks call `platform <probe>` instead of
# inline platform-specific commands.
# shellcheck source=../lib/platforms/_dispatch.sh
source "${REPO_ROOT}/lib/platforms/_dispatch.sh"

REPORT_DIR="${SARGE_REPORT_DIR:-$HOME/.sarge/reports}"
STATE_DIR="${SARGE_STATE_DIR:-$HOME/.sarge/state}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
REPORT_BASE="${REPORT_DIR}/sarge-report-${TIMESTAMP}"

# Per-run folder layout (mirrors the Windows port — PR #32, issue #34).
# Every artifact for THIS run lands under $SARGE_RUN_ROOT in addition to
# the legacy $REPORT_DIR / $STATE_DIR paths, so downstream consumers that
# read from the old locations keep working while new tooling can rely on
# a single self-contained per-run directory.
SARGE_RUN_ID="${SARGE_RUN_ID:-$TIMESTAMP}"
SARGE_RUN_ROOT="${SARGE_RUN_ROOT:-$HOME/.sarge/runs/$SARGE_RUN_ID}"
export SARGE_RUN_ID SARGE_RUN_ROOT

# Counters
PASS=0; WARN=0; FAIL=0; SKIP=0
declare -a RESULTS=()

mkdir -p "$REPORT_DIR" "$STATE_DIR" "$SARGE_RUN_ROOT"

# Initialize install timestamp on first run
INSTALLED_AT_FILE="$STATE_DIR/installed-at.txt"
if [[ ! -f "$INSTALLED_AT_FILE" ]]; then
  date -Iseconds -u > "$INSTALLED_AT_FILE"
fi

# Initialize drift counter on first run
DRIFT_COUNT_FILE="$STATE_DIR/drift-count.txt"
if [[ ! -f "$DRIFT_COUNT_FILE" ]]; then
  echo 0 > "$DRIFT_COUNT_FILE"
fi

log()   { echo "[SARGE] $*"; }

# Legacy helpers — description only, no structured check_id.
# Kept for backwards compatibility with downstream callers; emit results with
# an empty check_id so report.sh falls back to "no rationale available".
pass()  { echo "  [PASS] $*"; PASS=$((PASS+1)); RESULTS+=("PASS||$*"); }
warn()  { echo "  [WARN] $*"; WARN=$((WARN+1)); RESULTS+=("WARN||$*"); }
fail()  { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); RESULTS+=("FAIL||$*"); }
skip()  { echo "  [SKIP] $*"; SKIP=$((SKIP+1)); RESULTS+=("SKIP||$*"); }

# Structured helpers — first arg is check_id (must match findings-catalog.json),
# remaining args are the human-readable description. Use these for new checks
# so report.sh can render proper Findings detail blocks.
passx() { local id="$1"; shift; echo "  [PASS] $*"; PASS=$((PASS+1)); RESULTS+=("PASS|${id}|$*"); }
warnx() { local id="$1"; shift; echo "  [WARN] $*"; WARN=$((WARN+1)); RESULTS+=("WARN|${id}|$*"); }
failx() { local id="$1"; shift; echo "  [FAIL] $*"; FAIL=$((FAIL+1)); RESULTS+=("FAIL|${id}|$*"); }
skipx() { local id="$1"; shift; echo "  [SKIP] $*"; SKIP=$((SKIP+1)); RESULTS+=("SKIP|${id}|$*"); }

export -f pass warn fail skip passx warnx failx skipx
export PASS WARN FAIL SKIP

SARGE_MODE="agent-host"
[[ "$SARGE_HOST_ONLY" == "1" ]] && SARGE_MODE="host-only"
export SARGE_MODE

log "======================================"
log " Sarge NIST 800-53 Gap Analysis"
log " Oscar Six Security LLC"
log " $(date)"
log " Host: $(hostname)"
log " OS: ${SARGE_OS_DESCRIPTION}"
log " Mode: ${SARGE_MODE}"
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
  --report-dir "$REPORT_DIR" \
  --state-dir "$STATE_DIR" \
  --run-root "$SARGE_RUN_ROOT" \
  --run-id "$SARGE_RUN_ID" \
  --mode "$SARGE_MODE" \
  --catalog "$SCRIPT_DIR/findings-catalog.json" \
  --results "$(printf '%s\n' "${RESULTS[@]}")" || true

log "Reports written to: $REPORT_BASE.md and $REPORT_BASE.json"
log "Run folder: $SARGE_RUN_ROOT"
