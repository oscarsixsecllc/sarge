#!/usr/bin/env bash
# lib/platforms/_dispatch.sh — Cross-platform helper dispatch
#
# Loads the active platform's implementation file and exposes a single
# dispatcher function:
#
#   platform <probe-name> [args...]
#
# This calls ${SARGE_OS}_<probe-name> if defined; otherwise returns 127
# ("not implemented for this platform"). Callers distinguish via exit code:
#
#   value=$(platform password_max_days) || true        # 127 = no support
#   if platform audit_daemon_active; then ...; fi      # 0 = yes, !0 = no/unsupported
#
# Adding a new platform: drop a file at lib/platforms/<os>.sh that defines
# helpers as `<os>_<probe-name>`. There is no central registry; the
# dispatcher discovers helpers via `declare -F` at call time.
#
# Adding a new probe: define it in every supported platform's file. Probes
# missing from a platform return 127 — control files should treat that as
# "skip with reason".

[[ -n "${_SARGE_PLATFORMS_LOADED:-}" ]] && return 0
_SARGE_PLATFORMS_LOADED=1

: "${SARGE_OS:?lib/platform.sh must be sourced before lib/platforms/_dispatch.sh}"

_SARGE_PLATFORMS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -r "${_SARGE_PLATFORMS_DIR}/${SARGE_OS}.sh" ]]; then
  # shellcheck source=/dev/null
  source "${_SARGE_PLATFORMS_DIR}/${SARGE_OS}.sh"
else
  echo "[Sarge] No platform implementation: ${_SARGE_PLATFORMS_DIR}/${SARGE_OS}.sh" >&2
  return 1
fi

platform() {
  if [[ $# -eq 0 ]]; then
    echo "[Sarge] platform: missing probe name (usage: platform <probe> [args...])" >&2
    return 2
  fi
  local fn="${SARGE_OS}_$1"; shift
  if declare -F "$fn" &>/dev/null; then
    "$fn" "$@"
    return $?
  fi
  return 127
}

# 0 if the active platform implements <probe>, nonzero otherwise. Lets
# control checks distinguish "probe ran and said no" from "probe doesn't
# exist on this OS" — the latter routes to a skipx with a platform-aware
# rationale instead of a misleading failx. Cheaper than calling the probe
# and inspecting exit code 127, and side-effect free.
platform_supports() {
  declare -F "${SARGE_OS}_$1" &>/dev/null
}

# ---------- Drift field plumbing (shared across platforms) ----------
#
# Each platform defines `_<os>_drift_fields` that emits one `key=value`
# line per field it captures (see lib/platforms/<os>.sh). The two sinks
# below consume that stream:
#
#   _<os>_drift_fields | sarge_emit_drift_snapshot_json
#   _<os>_drift_fields | sarge_emit_drift_check_calls
#
# Living here (not per-platform) because the loops are byte-for-byte
# identical across platforms — only the field set is platform-specific.
# Pulling them up means adding a new platform's drift coverage is one
# function (the field emitter), not three.

# Emit a strict-JSON object body (no surrounding braces) from a stream
# of `key=value` lines on stdin. Each line becomes `"key": "value",`
# except the last, which omits the trailing comma. Skips blank lines so
# field emitters can use empty echos as visual separators if desired.
sarge_emit_drift_snapshot_json() {
  local lines=() pair k v
  while IFS= read -r pair; do
    [[ -z "$pair" ]] && continue
    k="${pair%%=*}"
    v="${pair#*=}"
    lines+=("    \"$k\": \"$v\"")
  done
  local n=${#lines[@]} i=0
  while [[ $i -lt $n ]]; do
    if [[ $i -lt $((n - 1)) ]]; then
      printf '%s,\n' "${lines[$i]}"
    else
      printf '%s\n' "${lines[$i]}"
    fi
    i=$((i + 1))
  done
}

# For each `key=value` line on stdin, invoke `check <key> <value>`. The
# `check` function must already be defined in the caller's scope (see
# drift/compare.sh). Unchanged from the per-platform loop it replaces.
sarge_emit_drift_check_calls() {
  local pair k v
  while IFS= read -r pair; do
    [[ -z "$pair" ]] && continue
    k="${pair%%=*}"
    v="${pair#*=}"
    check "$k" "$v"
  done
}
