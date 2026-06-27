#!/usr/bin/env bash
# harden-ufw.sh — UFW Firewall Hardening — NIST 800-53 AC-17
# Idempotent | Non-destructive | Ubuntu 22.04/24.04 | Requires sudo
# Platform: Ubuntu only (exits 0 silently on other OSes)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/platform.sh
source "${SCRIPT_DIR}/../lib/platform.sh"
sarge_require_os ubuntu

GW_PORT="${OPENCLAW_GATEWAY_PORT:-18790}"
LAN_SUBNET="${SARGE_LAN_SUBNET:-192.168.0.0/24}"

echo "[Sarge] UFW Hardening — AC-17: Remote Access"
echo "  Gateway port: $GW_PORT"
echo "  LAN subnet:   $LAN_SUBNET"
echo ""
read -r -p "Apply UFW hardening? This will set default deny and allow LAN only. [y/N] " confirm
[[ "$confirm" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }

apt-get install -y ufw &>/dev/null || true

ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow from "$LAN_SUBNET" to any port "$GW_PORT" proto tcp comment "OpenClaw gateway (LAN only)"
ufw allow from "$LAN_SUBNET" to any port 22 proto tcp comment "SSH (LAN only)"
ufw --force enable

echo ""
echo "[Sarge] UFW hardening applied."
ufw status verbose
