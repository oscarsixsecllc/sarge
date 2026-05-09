#!/usr/bin/env bash
# report.sh — Sarge Report Generator
# Generates Markdown and JSON reports from assessment results.
# New format (issue #10): summary table with deltas vs previous run,
# per-finding detail blocks (FAIL + WARN), drift counter, install date.

set -uo pipefail

PASS=0; WARN=0; FAIL=0; SKIP=0
OUTPUT=""
RESULTS=""
REPORT_DIR=""
STATE_DIR=""
CATALOG=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pass) PASS="$2"; shift 2 ;;
    --warn) WARN="$2"; shift 2 ;;
    --fail) FAIL="$2"; shift 2 ;;
    --skip) SKIP="$2"; shift 2 ;;
    --output) OUTPUT="$2"; shift 2 ;;
    --results) RESULTS="$2"; shift 2 ;;
    --report-dir) REPORT_DIR="$2"; shift 2 ;;
    --state-dir) STATE_DIR="$2"; shift 2 ;;
    --catalog) CATALOG="$2"; shift 2 ;;
    *) shift ;;
  esac
done

[[ -z "$OUTPUT" ]] && exit 0

# Defaults
REPORT_DIR="${REPORT_DIR:-$HOME/.sarge/reports}"
STATE_DIR="${STATE_DIR:-$HOME/.sarge/state}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CATALOG="${CATALOG:-$SCRIPT_DIR/../findings-catalog.json}"

mkdir -p "$REPORT_DIR" "$STATE_DIR"

TIMESTAMP=$(date -Iseconds)
TOTAL=$((PASS+WARN+FAIL+SKIP))
HOST=$(hostname)
OS=$(lsb_release -sd 2>/dev/null || uname -a)

INSTALLED_AT_FILE="$STATE_DIR/installed-at.txt"
DRIFT_COUNT_FILE="$STATE_DIR/drift-count.txt"

INSTALLED_AT=""
[[ -f "$INSTALLED_AT_FILE" ]] && INSTALLED_AT=$(cat "$INSTALLED_AT_FILE")
[[ -z "$INSTALLED_AT" ]] && INSTALLED_AT="$TIMESTAMP"

DRIFT_COUNT=0
[[ -f "$DRIFT_COUNT_FILE" ]] && DRIFT_COUNT=$(cat "$DRIFT_COUNT_FILE" 2>/dev/null || echo 0)
[[ -z "$DRIFT_COUNT" ]] && DRIFT_COUNT=0

# --- Find previous report (most recent JSON in REPORT_DIR, excluding the
# one we are about to write). Filenames sort lexically by timestamp. ---
CURRENT_JSON_BASENAME="$(basename "$OUTPUT").json"
PREV_JSON=""
if [[ -d "$REPORT_DIR" ]]; then
  PREV_JSON=$(find "$REPORT_DIR" -maxdepth 1 -type f -name 'sarge-report-*.json' \
              ! -name "$CURRENT_JSON_BASENAME" 2>/dev/null \
              | sort | tail -n1)
fi

PREV_PASS=0; PREV_WARN=0; PREV_FAIL=0; PREV_SKIP=0
HAS_PREV=0
if [[ -n "$PREV_JSON" && -f "$PREV_JSON" ]]; then
  if command -v jq &>/dev/null; then
    PREV_PASS=$(jq -r '.summary.pass // 0' "$PREV_JSON" 2>/dev/null || echo 0)
    PREV_WARN=$(jq -r '.summary.warn // 0' "$PREV_JSON" 2>/dev/null || echo 0)
    PREV_FAIL=$(jq -r '.summary.fail // 0' "$PREV_JSON" 2>/dev/null || echo 0)
    PREV_SKIP=$(jq -r '.summary.skip // 0' "$PREV_JSON" 2>/dev/null || echo 0)
    HAS_PREV=1
  elif command -v python3 &>/dev/null; then
    read -r PREV_PASS PREV_WARN PREV_FAIL PREV_SKIP < <(python3 -c '
import json,sys
try:
  d=json.load(open(sys.argv[1]))
  s=d.get("summary",{})
  print(s.get("pass",0), s.get("warn",0), s.get("fail",0), s.get("skip",0))
except Exception:
  print("0 0 0 0")
' "$PREV_JSON" 2>/dev/null) || { PREV_PASS=0; PREV_WARN=0; PREV_FAIL=0; PREV_SKIP=0; }
    HAS_PREV=1
  else
    # Last-ditch grep parser — assumes the original sarge JSON layout
    # ("pass": N, "warn": N, ...) on its own lines inside summary.
    PREV_PASS=$(grep -oE '"pass"[[:space:]]*:[[:space:]]*[0-9]+' "$PREV_JSON" | head -1 | grep -oE '[0-9]+$' || echo 0)
    PREV_WARN=$(grep -oE '"warn"[[:space:]]*:[[:space:]]*[0-9]+' "$PREV_JSON" | head -1 | grep -oE '[0-9]+$' || echo 0)
    PREV_FAIL=$(grep -oE '"fail"[[:space:]]*:[[:space:]]*[0-9]+' "$PREV_JSON" | head -1 | grep -oE '[0-9]+$' || echo 0)
    PREV_SKIP=$(grep -oE '"skip"[[:space:]]*:[[:space:]]*[0-9]+' "$PREV_JSON" | head -1 | grep -oE '[0-9]+$' || echo 0)
    [[ -z "$PREV_PASS" ]] && PREV_PASS=0
    [[ -z "$PREV_WARN" ]] && PREV_WARN=0
    [[ -z "$PREV_FAIL" ]] && PREV_FAIL=0
    [[ -z "$PREV_SKIP" ]] && PREV_SKIP=0
    HAS_PREV=1
  fi
fi

# Compute deltas
DELTA_PASS=$((PASS - PREV_PASS))
DELTA_WARN=$((WARN - PREV_WARN))
DELTA_FAIL=$((FAIL - PREV_FAIL))
DELTA_SKIP=$((SKIP - PREV_SKIP))

fmt_delta() {
  local v="$1"
  if [[ "$HAS_PREV" -eq 0 ]]; then echo "—"; return; fi
  if [[ "$v" -gt 0 ]]; then echo "+${v}"
  elif [[ "$v" -lt 0 ]]; then echo "${v}"
  else echo "0"
  fi
}

DELTA_PASS_STR=$(fmt_delta "$DELTA_PASS")
DELTA_WARN_STR=$(fmt_delta "$DELTA_WARN")
DELTA_FAIL_STR=$(fmt_delta "$DELTA_FAIL")
DELTA_SKIP_STR=$(fmt_delta "$DELTA_SKIP")

# Increment drift counter only when current FAIL > previous FAIL (and we have a previous)
if [[ "$HAS_PREV" -eq 1 && "$FAIL" -gt "$PREV_FAIL" ]]; then
  DRIFT_COUNT=$((DRIFT_COUNT + 1))
  echo "$DRIFT_COUNT" > "$DRIFT_COUNT_FILE"
fi

# --- Parse RESULTS into arrays of FAIL and WARN entries (status|check_id|description) ---
declare -a FAIL_LINES=()
declare -a WARN_LINES=()
declare -a ALL_LINES=()
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  ALL_LINES+=("$line")
  case "$line" in
    FAIL\|*) FAIL_LINES+=("$line") ;;
    WARN\|*) WARN_LINES+=("$line") ;;
  esac
done <<< "$RESULTS"

# Sort FAIL/WARN lines by check_id (which embeds family ordering by NIST family
# alphabetically — AC, AU, CM, IA, SC, SI). Empty check_ids sort to end via |~.
sort_by_check_id() {
  local arr_name="$1"
  eval "local arr=(\"\${${arr_name}[@]}\")"
  local out=()
  while IFS= read -r line; do
    out+=("$line")
  done < <(printf '%s\n' "${arr[@]}" | awk -F'|' '{
    id = ($2 == "" ? "~~" : $2);
    print id "\t" $0
  }' | sort | cut -f2-)
  eval "${arr_name}=(\"\${out[@]}\")"
}

[[ ${#FAIL_LINES[@]} -gt 0 ]] && sort_by_check_id FAIL_LINES
[[ ${#WARN_LINES[@]} -gt 0 ]] && sort_by_check_id WARN_LINES

# --- Catalog lookup helpers ---
catalog_field() {
  # $1 = check_id, $2 = field (family|what|expected|why|fix)
  local id="$1" field="$2"
  [[ -z "$id" ]] && return 1
  [[ ! -f "$CATALOG" ]] && return 1
  local val=""
  if command -v jq &>/dev/null; then
    val=$(jq -r --arg id "$id" --arg f "$field" '.[$id][$f] // empty' "$CATALOG" 2>/dev/null)
  elif command -v python3 &>/dev/null; then
    val=$(python3 -c '
import json,sys
try:
  d=json.load(open(sys.argv[1]))
  v=d.get(sys.argv[2],{}).get(sys.argv[3],"")
  if v is None: v=""
  print(v)
except Exception:
  pass
' "$CATALOG" "$id" "$field" 2>/dev/null)
  else
    return 1
  fi
  [[ -z "$val" || "$val" == "null" ]] && return 1
  printf '%s' "$val"
}

render_finding_block() {
  # $1 = status emoji+label heading prefix, $2 = status|check_id|description
  local heading_prefix="$1"
  local line="$2"
  local check_id description family what expected why fix
  check_id=$(echo "$line" | awk -F'|' '{print $2}')
  description=$(echo "$line" | awk -F'|' '{ for (i=3;i<=NF;i++) { printf "%s%s", (i==3?"":"|"), $i } }')

  family=$(catalog_field "$check_id" "family" || true)
  what=$(catalog_field "$check_id" "what" || true)
  expected=$(catalog_field "$check_id" "expected" || true)
  why=$(catalog_field "$check_id" "why" || true)
  fix=$(catalog_field "$check_id" "fix" || true)

  local heading
  if [[ -n "$family" ]]; then
    heading="#### ${heading_prefix} ${family}"
  elif [[ -n "$check_id" ]]; then
    heading="#### ${heading_prefix} ${check_id}"
  else
    heading="#### ${heading_prefix} (no check_id)"
  fi
  echo "$heading"
  echo ""
  echo "**What:** ${description}"
  if [[ -n "$expected" ]]; then
    echo ""
    echo "**Expected:** ${expected}"
  fi
  echo ""
  if [[ -n "$why" ]]; then
    echo "**Why it matters:** ${why}"
  else
    echo "**Why it matters:** _No detail catalog entry — TODO: add to findings-catalog.json_"
  fi
  echo ""
  if [[ -n "$fix" ]]; then
    echo "**Fix:** \`${fix}\`"
  else
    echo "**Fix:** _No detail catalog entry — TODO: add to findings-catalog.json_"
  fi
  echo ""
}

# --- Build markdown report ---
DATE_HUMAN=$(date "+%Y-%m-%d %H:%M:%S %Z")
INSTALL_DATE_HUMAN="$INSTALLED_AT"

{
  echo "# Sarge Hardening Report — ${HOST} — ${DATE_HUMAN}"
  echo ""
  echo "> Drifts caught on this host since first install (${INSTALL_DATE_HUMAN}): **${DRIFT_COUNT}**"
  echo ""
  echo "**OS:** ${OS}"
  echo ""
  echo "## Summary"
  echo ""
  echo "| Status   | Count | Δ vs previous run |"
  echo "|----------|-------|-------------------|"
  printf "| ✅ PASS  | %5d | %-17s |\n" "$PASS" "$DELTA_PASS_STR"
  printf "| ⚠️ WARN  | %5d | %-17s |\n" "$WARN" "$DELTA_WARN_STR"
  printf "| ❌ FAIL  | %5d | %-17s |\n" "$FAIL" "$DELTA_FAIL_STR"
  printf "| ⏭️ SKIP  | %5d | %-17s |\n" "$SKIP" "$DELTA_SKIP_STR"
  printf "| Total    | %5d | %-17s |\n" "$TOTAL" "—"
  echo ""
  echo ""

  if [[ "$HAS_PREV" -eq 1 ]]; then
    PREV_BASENAME=$(basename "$PREV_JSON")
    echo "_Deltas computed against previous report: \`${PREV_BASENAME}\`._"
  else
    echo "_First run on this host — no previous report to compare against._"
  fi
  echo ""

  echo "## Findings"
  echo ""

  if [[ ${#FAIL_LINES[@]} -eq 0 && ${#WARN_LINES[@]} -eq 0 ]]; then
    echo "_No FAIL or WARN findings on this run._"
    echo ""
  fi

  if [[ ${#FAIL_LINES[@]} -gt 0 ]]; then
    echo "### ❌ Failures (${#FAIL_LINES[@]})"
    echo ""
    for line in "${FAIL_LINES[@]}"; do
      render_finding_block "❌" "$line"
    done
  fi

  if [[ ${#WARN_LINES[@]} -gt 0 ]]; then
    echo "### ⚠️ Warnings (${#WARN_LINES[@]})"
    echo ""
    for line in "${WARN_LINES[@]}"; do
      render_finding_block "⚠️" "$line"
    done
  fi

  echo "---"
  echo "_Generated by Sarge v0.2.0 — https://github.com/oscarsixsecllc/sarge_"
  echo "_Assessment timestamp: ${TIMESTAMP}_"
} > "${OUTPUT}.md"

# --- Build JSON report ---
# Use jq when available for safe escaping; otherwise hand-roll.
if command -v jq &>/dev/null; then
  # Build results array as JSON via jq
  RESULTS_JSON=$(printf '%s\n' "${ALL_LINES[@]}" | jq -R -s '
    split("\n")
    | map(select(length > 0))
    | map(split("|"))
    | map({
        status: .[0],
        check_id: (.[1] // ""),
        detail: (.[2:] | join("|"))
      })
  ')

  jq -n \
    --arg version "0.2.0" \
    --arg date "$TIMESTAMP" \
    --arg host "$HOST" \
    --arg os "$OS" \
    --arg installed "$INSTALLED_AT" \
    --argjson drift "$DRIFT_COUNT" \
    --argjson total "$TOTAL" \
    --argjson pass "$PASS" \
    --argjson warn "$WARN" \
    --argjson fail "$FAIL" \
    --argjson skip "$SKIP" \
    --argjson dpass "$DELTA_PASS" \
    --argjson dwarn "$DELTA_WARN" \
    --argjson dfail "$DELTA_FAIL" \
    --argjson dskip "$DELTA_SKIP" \
    --argjson hasprev "$HAS_PREV" \
    --arg prevjson "${PREV_JSON:-}" \
    --argjson results "$RESULTS_JSON" \
    '{
      sarge_version: $version,
      assessment_date: $date,
      host: $host,
      os: $os,
      installedAt: $installed,
      driftCount: $drift,
      summary: {
        total: $total,
        pass: $pass,
        warn: $warn,
        fail: $fail,
        skip: $skip
      },
      deltas: (if $hasprev == 1 then {
        pass: $dpass,
        warn: $dwarn,
        fail: $dfail,
        skip: $dskip,
        previousReport: $prevjson
      } else null end),
      results: $results
    }' > "${OUTPUT}.json"
else
  # Fallback: hand-roll JSON (no escaping of special chars in detail strings).
  {
    echo "{"
    echo "  \"sarge_version\": \"0.2.0\","
    echo "  \"assessment_date\": \"${TIMESTAMP}\","
    echo "  \"host\": \"${HOST}\","
    echo "  \"os\": \"${OS}\","
    echo "  \"installedAt\": \"${INSTALLED_AT}\","
    echo "  \"driftCount\": ${DRIFT_COUNT},"
    echo "  \"summary\": {"
    echo "    \"total\": ${TOTAL},"
    echo "    \"pass\": ${PASS},"
    echo "    \"warn\": ${WARN},"
    echo "    \"fail\": ${FAIL},"
    echo "    \"skip\": ${SKIP}"
    echo "  },"
    if [[ "$HAS_PREV" -eq 1 ]]; then
      echo "  \"deltas\": {"
      echo "    \"pass\": ${DELTA_PASS},"
      echo "    \"warn\": ${DELTA_WARN},"
      echo "    \"fail\": ${DELTA_FAIL},"
      echo "    \"skip\": ${DELTA_SKIP},"
      echo "    \"previousReport\": \"${PREV_JSON}\""
      echo "  },"
    else
      echo "  \"deltas\": null,"
    fi
    echo "  \"results\": ["
    n=${#ALL_LINES[@]}; i=0
    for line in "${ALL_LINES[@]}"; do
      i=$((i+1))
      status=$(echo "$line" | awk -F'|' '{print $1}')
      check_id=$(echo "$line" | awk -F'|' '{print $2}')
      detail=$(echo "$line" | awk -F'|' '{ for (k=3;k<=NF;k++) { printf "%s%s", (k==3?"":"|"), $k } }')
      # Best-effort escape: backslashes and double-quotes
      detail_escaped=$(printf '%s' "$detail" | sed 's/\\/\\\\/g; s/"/\\"/g')
      sep=","; [[ "$i" -eq "$n" ]] && sep=""
      echo "    {\"status\": \"${status}\", \"check_id\": \"${check_id}\", \"detail\": \"${detail_escaped}\"}${sep}"
    done
    echo "  ]"
    echo "}"
  } > "${OUTPUT}.json"
fi
