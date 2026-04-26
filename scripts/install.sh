#!/usr/bin/env bash
# install.sh — Sarge One-Shot Interactive Hardening — NIST 800-53 Rev 5
# Runs all hardening scripts in sequence. Each prompts individually.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# shellcheck source=../lib/platform.sh
source "${REPO_ROOT}/lib/platform.sh"
sarge_require_supported_os

echo "============================================"
echo " Sarge — NIST 800-53 Hardening"
echo " Oscar Six Security LLC"
echo " Platform: ${SARGE_OS_DESCRIPTION}"
echo " This script applies all hardening modules."
echo " Each module will prompt before making changes."
echo "============================================"
echo ""
read -r -p "Begin Sarge hardening sequence? [y/N] " confirm
[[ "$confirm" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }

# Per-platform module list. Ubuntu retains full coverage; macOS ships only
# the POSIX-clean modules that have been validated. Native macOS firewall,
# auth, and audit modules will land in subsequent PRs.
case "$SARGE_OS" in
  ubuntu)
    MODULES=(harden-permissions harden-pam harden-auditd harden-fail2ban harden-ufw harden-systemd)
    ;;
  macos)
    MODULES=(harden-permissions)
    echo ""
    echo "[Sarge] macOS hardening is rolling out one module per PR."
    echo "[Sarge] This release applies file-permission hardening only."
    echo "[Sarge] Track the rollout: https://github.com/oscarsixsecllc/sarge/issues"
    echo ""
    ;;
esac

for script in "${MODULES[@]}"; do
  echo ""
  echo "--- $script ---"
  bash "$SCRIPT_DIR/${script}.sh"
done

echo ""
echo "============================================"
echo " Sarge hardening complete."
echo " Run a gap analysis to verify: ./assessment/assess.sh"
echo "============================================"
