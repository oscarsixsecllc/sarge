#!/usr/bin/env bash
# lib/platform.sh — Sarge platform detection and capability gates
# Sourced by assessment, hardening, and drift scripts.
#
# Exports:
#   SARGE_OS              "ubuntu" | "macos" | "unsupported"
#   SARGE_OS_VERSION      version string (e.g. "24.04", "14.5")
#   SARGE_OS_DESCRIPTION  human-readable identifier (e.g. "Ubuntu 24.04 LTS")
#
# Provides:
#   sarge_require_supported_os    refuse to run on platforms outside the support matrix
#   sarge_require_os <os...>      refuse to run if SARGE_OS is not in the allowed list
#
# Idempotent: safe to source multiple times within a single shell.

[[ -n "${_SARGE_PLATFORM_LOADED:-}" ]] && return 0
_SARGE_PLATFORM_LOADED=1

_sarge_uname_s=$(uname -s)
case "$_sarge_uname_s" in
  Linux)
    if [[ -r /etc/os-release ]]; then
      # shellcheck disable=SC1091
      . /etc/os-release
      if [[ "${ID:-}" == "ubuntu" ]]; then
        SARGE_OS="ubuntu"
        SARGE_OS_VERSION="${VERSION_ID:-unknown}"
        SARGE_OS_DESCRIPTION="${PRETTY_NAME:-Ubuntu $SARGE_OS_VERSION}"
      else
        SARGE_OS="unsupported"
        SARGE_OS_VERSION="${VERSION_ID:-unknown}"
        SARGE_OS_DESCRIPTION="${PRETTY_NAME:-Linux $SARGE_OS_VERSION}"
      fi
    else
      SARGE_OS="unsupported"
      SARGE_OS_VERSION="unknown"
      SARGE_OS_DESCRIPTION="Linux (no /etc/os-release)"
    fi
    ;;
  Darwin)
    SARGE_OS="macos"
    SARGE_OS_VERSION=$(sw_vers -productVersion 2>/dev/null || echo "unknown")
    SARGE_OS_DESCRIPTION="macOS ${SARGE_OS_VERSION}"
    ;;
  *)
    SARGE_OS="unsupported"
    SARGE_OS_VERSION="unknown"
    SARGE_OS_DESCRIPTION="$_sarge_uname_s"
    ;;
esac
unset _sarge_uname_s

export SARGE_OS SARGE_OS_VERSION SARGE_OS_DESCRIPTION

# Support matrix — keep in sync with README control coverage table
_sarge_is_supported_version() {
  case "$SARGE_OS" in
    ubuntu)
      case "$SARGE_OS_VERSION" in
        22.04|24.04) return 0 ;;
        *) return 1 ;;
      esac
      ;;
    macos)
      # Any macOS version. Apple's release cadence and year-aligned naming
      # (Sonoma 14, Sequoia 15, Tahoe 26, ...) make a tight allowlist brittle,
      # and OpenClaw is a developer-facing surface where we want to meet users
      # on whatever Mac they have. Tighten only if a specific version proves
      # incompatible.
      [[ -n "$SARGE_OS_VERSION" && "$SARGE_OS_VERSION" != "unknown" ]] && return 0
      return 1
      ;;
    *) return 1 ;;
  esac
}

sarge_require_supported_os() {
  if [[ "$SARGE_OS" == "unsupported" ]] || ! _sarge_is_supported_version; then
    echo "[Sarge] Unsupported platform: ${SARGE_OS_DESCRIPTION}" >&2
    echo "[Sarge] Sarge supports:" >&2
    echo "  - Ubuntu 22.04 / 24.04 LTS  (full coverage)" >&2
    echo "  - macOS                     (in progress — see roadmap)" >&2
    echo "[Sarge] Roadmap: https://github.com/oscarsixsecllc/sarge/issues" >&2
    exit 2
  fi
}

# Gate a script to a specific OS list. Exits 0 (clean skip) when not applicable,
# so platform-specific modules don't break a multi-module install on other OSes.
sarge_require_os() {
  local allowed
  for allowed in "$@"; do
    if [[ "$SARGE_OS" == "$allowed" ]]; then
      return 0
    fi
  done
  echo "[Sarge] Module not applicable on ${SARGE_OS} — requires: $*. Skipping." >&2
  exit 0
}
