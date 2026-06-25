#!/usr/bin/env bash
# harden-systemd.sh — Systemd Service Hardening — NIST 800-53 CM-7
# Platform: Ubuntu only (exits 0 silently on other OSes)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/platform.sh
source "${SCRIPT_DIR}/../lib/platform.sh"
sarge_require_os ubuntu

echo "[Sarge] Systemd Hardening — CM-7: Least Functionality"
read -r -p "Apply systemd hardening for OpenClaw service? [y/N] " confirm
[[ "$confirm" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }

OVERRIDE_DIR="/etc/systemd/system/openclaw-gateway.service.d"
mkdir -p "$OVERRIDE_DIR"
cat > "$OVERRIDE_DIR/sarge-hardening.conf" << SVCEOF
[Service]
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RemoveIPC=true
RestrictNamespaces=true
SVCEOF

systemctl daemon-reload
echo "[Sarge] Systemd hardening applied. Reload openclaw-gateway to activate."
