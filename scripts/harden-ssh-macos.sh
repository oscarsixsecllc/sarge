#!/usr/bin/env bash
# harden-ssh-macos.sh — SSH Hardening (macOS) — NIST 800-53 CM-7
# Idempotent | Non-destructive | macOS (Ventura+) | Requires sudo
#
# Drops a hardening config into /etc/ssh/sshd_config.d/sarge.conf:
#   PermitRootLogin no
#   PasswordAuthentication no
#   ChallengeResponseAuthentication no
#
# Drop-in rationale:
#   - macOS sshd_config includes /etc/ssh/sshd_config.d/* since Ventura.
#   - Drop-ins survive macOS upgrades; in-place edits get clobbered.
#   - Easy rollback: rm /etc/ssh/sshd_config.d/sarge.conf && reload sshd.
#
# After writing, reloads sshd via launchctl so the config takes effect
# without a logout/reboot.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# shellcheck source=../lib/platform.sh
source "${REPO_ROOT}/lib/platform.sh"
sarge_require_os macos

# --- Constants ---
SSHD_CONFIG="/etc/ssh/sshd_config"
DROPIN_DIR="/etc/ssh/sshd_config.d"
DROPIN_FILE="${DROPIN_DIR}/sarge.conf"
LAUNCHD_LABEL="com.openssh.sshd"

DESIRED_CONTENT="# Sarge SSH hardening — NIST 800-53 CM-7
PermitRootLogin no
PasswordAuthentication no
ChallengeResponseAuthentication no"

# --- Preflight: verify Include directive ---
echo "[Sarge] SSH Hardening (macOS) — CM-7: Least Functionality"
echo ""

if ! grep -qE '^\s*Include\s+/etc/ssh/sshd_config\.d/\*' "$SSHD_CONFIG" 2>/dev/null; then
  echo "[Sarge] ERROR: $SSHD_CONFIG does not contain 'Include /etc/ssh/sshd_config.d/*'." >&2
  echo "[Sarge] The drop-in approach requires this directive (present by default since Ventura)." >&2
  echo "[Sarge] Add 'Include /etc/ssh/sshd_config.d/*' to the top of $SSHD_CONFIG and re-run." >&2
  exit 1
fi

# --- Idempotency check ---
if [[ -f "$DROPIN_FILE" ]]; then
  existing=$(cat "$DROPIN_FILE" 2>/dev/null) || true
  if [[ "$existing" == "$DESIRED_CONTENT" ]]; then
    echo "[Sarge] Drop-in already matches desired state: $DROPIN_FILE"
    echo "[Sarge] Nothing to do."
    exit 0
  fi
  echo "[Sarge] Existing drop-in found but content differs — will overwrite."
fi

# --- Warn about current session auth method ---
echo "  Drop-in:   $DROPIN_FILE"
echo "  Settings:  PermitRootLogin no"
echo "             PasswordAuthentication no"
echo "             ChallengeResponseAuthentication no"
echo ""

# Detect if current SSH session is key-based or password-based.
# SSH_AUTH_SOCK being set strongly suggests key-based auth (agent forwarding).
# SSH_CONNECTION being set means we're in an SSH session at all.
if [[ -n "${SSH_CONNECTION:-}" ]]; then
  if [[ -n "${SSH_AUTH_SOCK:-}" ]]; then
    echo "[Sarge] You appear to be connected via SSH with key-based auth."
    echo "[Sarge] Your current session will survive this change."
  else
    echo "[Sarge] WARNING: You appear to be connected via SSH without key-based auth."
    echo "[Sarge] After applying, password-based SSH will be disabled."
    echo "[Sarge] Ensure you have key-based access configured before proceeding,"
    echo "[Sarge] or you may lose remote access to this machine."
  fi
  echo ""
fi

# --- Confirmation ---
read -r -p "Apply SSH hardening? [y/N] " confirm
[[ "$confirm" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }

# --- Apply ---
# Ensure drop-in directory exists (should already on Ventura+)
if [[ ! -d "$DROPIN_DIR" ]]; then
  mkdir -p "$DROPIN_DIR"
  chmod 755 "$DROPIN_DIR"
  echo "  Created $DROPIN_DIR"
fi

printf '%s\n' "$DESIRED_CONTENT" > "$DROPIN_FILE"
chmod 644 "$DROPIN_FILE"
echo "  Wrote $DROPIN_FILE"

# --- Reload sshd ---
if launchctl print "system/${LAUNCHD_LABEL}" &>/dev/null; then
  launchctl kickstart -k "system/${LAUNCHD_LABEL}"
  echo "  Reloaded sshd via launchctl"
else
  echo "  sshd is not currently loaded — config will take effect when sshd starts."
fi

echo ""
echo "[Sarge] SSH hardening applied."
echo "[Sarge] Verify: sudo sshd -T | grep -iE 'permitrootlogin|passwordauthentication|challengeresponseauthentication'"
echo "[Sarge] Rollback: sudo rm $DROPIN_FILE && sudo launchctl kickstart -k system/${LAUNCHD_LABEL}"
