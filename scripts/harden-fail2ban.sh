#!/usr/bin/env bash
# harden-fail2ban.sh — fail2ban Hardening — NIST 800-53 SI-3, AC-17
set -euo pipefail

GW_PORT="${OPENCLAW_GATEWAY_PORT:-18790}"
echo "[Sarge] fail2ban Hardening — SI-3/AC-17. Gateway port: $GW_PORT"
read -r -p "Install and configure fail2ban? [y/N] " confirm
[[ "$confirm" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }

apt-get install -y fail2ban &>/dev/null || true

cat > /etc/fail2ban/jail.d/sarge.conf << F2BEOF
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port    = ssh
logpath = /var/log/auth.log

[openclaw-gateway]
enabled  = true
port     = ${GW_PORT}
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 5
bantime  = 3600
F2BEOF

systemctl enable --now fail2ban
echo "[Sarge] fail2ban configured."
fail2ban-client status 2>/dev/null || true
