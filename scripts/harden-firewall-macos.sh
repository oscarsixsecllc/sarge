#!/usr/bin/env bash
# harden-firewall-macos.sh — macOS Application Layer Firewall — NIST 800-53 AC-17
# Idempotent | Non-destructive | macOS | Requires sudo
#
# Enables the macOS Application Layer Firewall (socketfilterfw) with sensible
# defaults for an OpenClaw deployment:
#   - Global firewall ON
#   - Stealth mode ON (suppresses ICMP/probe responses — AC-17 boundary protection)
#   - Block-all OFF (allow signed + explicitly-permitted apps; block-all bricks OpenClaw)
#   - Allow signed system binaries and signed apps
#
# This script must be run with sudo (socketfilterfw writes require root).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# shellcheck source=../lib/platform.sh
source "${REPO_ROOT}/lib/platform.sh"
sarge_require_os macos

ALF="/usr/libexec/ApplicationFirewall/socketfilterfw"

if [[ ! -x "$ALF" ]]; then
  echo "[Sarge] ERROR: socketfilterfw not found at $ALF" >&2
  echo "[Sarge] This macOS installation may be missing the Application Firewall." >&2
  exit 1
fi

echo "[Sarge] macOS Firewall Hardening — AC-17: Remote Access"
echo "  Tool: $ALF"
echo ""
echo "  This module will:"
echo "    1. Enable the Application Layer Firewall"
echo "    2. Enable stealth mode (suppress ICMP probes)"
echo "    3. Disable block-all mode (allow signed + permitted apps)"
echo "    4. Allow signed system and app-store binaries"
echo ""
read -r -p "Apply macOS firewall hardening? [y/N] " confirm
[[ "$confirm" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }

# ---------- Helper: idempotent state setter ----------
# Reads current state, only writes if it differs.
# Usage: alf_set <get-flag> <set-flag> <desired-grep-pattern> <label>
alf_set() {
  local get_flag="$1"
  local set_flag="$2"
  local desired_pattern="$3"
  local label="$4"

  local current
  current=$("$ALF" "$get_flag" 2>/dev/null || true)

  if echo "$current" | grep -qE "$desired_pattern"; then
    echo "  [OK] $label — already in desired state"
  else
    "$ALF" "$set_flag" 2>/dev/null
    echo "  [APPLIED] $label"
  fi
}

# 1. Global firewall ON
alf_set --getglobalstate "--setglobalstate on" \
  "State = [12]|Firewall is enabled" \
  "Global firewall: enabled"

# 2. Stealth mode ON
alf_set --getstealthmode "--setstealthmode on" \
  "Stealth mode enabled|mode = [12]" \
  "Stealth mode: enabled"

# 3. Block-all OFF (must not brick OpenClaw)
alf_set --getblockall "--setblockall off" \
  "Block all DISABLED|mode = 0" \
  "Block-all mode: disabled"

# 4. Allow signed system binaries
alf_set --getallowsigned "--setallowsigned on" \
  "Signed.*allowed|mode = [12]|ENABLED" \
  "Allow signed system binaries: enabled"

# 5. Allow signed downloaded apps
alf_set --getallowsignedapp "--setallowsignedapp on" \
  "Signed.*allowed|mode = [12]|ENABLED" \
  "Allow signed downloaded apps: enabled"

echo ""
echo "[Sarge] macOS firewall hardening applied."
echo ""
echo "  Verify with: $ALF --getglobalstate"
echo "  Full status: $ALF --listapps"
