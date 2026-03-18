#!/usr/bin/env bash
# harden-auditd.sh — Audit Daemon Hardening — NIST 800-53 AU-2, AU-9, AU-12
set -euo pipefail

OC_SECRETS="${HOME}/.openclaw/secrets"
echo "[Sarge] auditd Hardening — AU-2/AU-9/AU-12"
read -r -p "Install and configure auditd? [y/N] " confirm
[[ "$confirm" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }

apt-get install -y auditd audispd-plugins &>/dev/null || true

RULES_FILE="/etc/audit/rules.d/sarge.rules"
cat > "$RULES_FILE" << RULESEOF
# Sarge auditd rules — NIST 800-53 Rev 5
# AU-12: Audit OpenClaw secrets access
-w ${OC_SECRETS} -p rwxa -k openclaw_secrets
# AU-12: Audit OpenClaw config changes
-w ${HOME}/.openclaw -p wa -k openclaw_config
# AU-12: Audit auth files
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d -p wa -k sudoers
# AU-12: Audit privilege escalation
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid!=unset -k privilege_escalation
# AU-12: Audit login events
-w /var/log/auth.log -p wa -k auth_log
RULESEOF

systemctl enable --now auditd
augenrules --load 2>/dev/null || auditctl -R "$RULES_FILE" 2>/dev/null || true
echo "[Sarge] auditd configured. Rules file: $RULES_FILE"
