#!/usr/bin/env bash
# install.sh — Sarge One-Shot Interactive Hardening — NIST 800-53 Rev 5
# Runs all hardening scripts in sequence. Each prompts individually.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "============================================"
echo " Sarge — NIST 800-53 Hardening"
echo " Oscar Six Security LLC"
echo " This script applies all hardening modules."
echo " Each module will prompt before making changes."
echo "============================================"
echo ""
read -r -p "Begin Sarge hardening sequence? [y/N] " confirm
[[ "$confirm" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }

for script in harden-permissions harden-pam harden-auditd harden-fail2ban harden-ufw harden-systemd; do
  echo ""
  echo "--- $script ---"
  bash "$SCRIPT_DIR/${script}.sh"
done

echo ""
echo "============================================"
echo " Sarge hardening complete."
echo " Run a gap analysis to verify: ./assessment/assess.sh"
echo "============================================"
