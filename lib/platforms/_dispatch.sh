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
