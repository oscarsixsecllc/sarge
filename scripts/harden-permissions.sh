#!/usr/bin/env bash
# harden-permissions.sh — File/Directory Permissions — NIST 800-53 AC-3, SC-28
set -euo pipefail

# Resolve the invoking user's home directory. When this script is run under
# sudo (e.g. via scripts/install.sh, or `sudo bash harden-permissions.sh`),
# Ubuntu's default sudoers resets $HOME to /root — which would harden
# /root/.openclaw instead of the operator's workspace. Detect $SUDO_USER and
# use its home so the right directory gets locked down.
resolve_home_for_user() {
  local user="$1"
  local resolved_home=""

  # Only allow conventional account names before querying the OS database.
  if [[ ! "$user" =~ ^[A-Za-z_][A-Za-z0-9_.-]*[$]?$ ]]; then
    return 1
  fi

  if command -v getent >/dev/null 2>&1; then
    resolved_home=$(getent passwd "$user" | cut -d: -f6)
  elif command -v dscl >/dev/null 2>&1; then
    resolved_home=$(dscl . -read "/Users/$user" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
  fi

  if [[ -n "$resolved_home" && "$resolved_home" = /* ]]; then
    printf '%s\n' "$resolved_home"
    return 0
  fi

  return 1
}

if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
  if TARGET_HOME=$(resolve_home_for_user "$SUDO_USER"); then
    TARGET_USER="$SUDO_USER"
  else
    TARGET_HOME="$HOME"
    TARGET_USER=$(whoami)
  fi
else
  TARGET_HOME="$HOME"
  TARGET_USER=$(whoami)
fi

echo "[Sarge] Permissions Hardening — AC-3/SC-28"
echo "  Target user: $TARGET_USER"
echo "  Target home: $TARGET_HOME"
read -r -p "Apply OpenClaw file permission hardening? [y/N] " confirm
[[ "$confirm" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }

OC_DIR="$TARGET_HOME/.openclaw"
if [[ -d "$OC_DIR" ]]; then
  chmod 700 "$OC_DIR"
  echo "  Set $OC_DIR → 700"
  if [[ -d "$OC_DIR/secrets" ]]; then
    chmod 700 "$OC_DIR/secrets" && echo "  Set $OC_DIR/secrets → 700"
    find "$OC_DIR/secrets" -type f -exec chmod 600 {} \; 2>/dev/null && echo "  Set secret files → 600"
  fi
  [[ -f "$OC_DIR/config.json" ]] && chmod 600 "$OC_DIR/config.json" && echo "  Set config.json → 600"
fi
echo "[Sarge] Permissions hardening applied."
