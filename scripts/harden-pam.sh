#!/usr/bin/env bash
# harden-pam.sh — PAM Hardening — NIST 800-53 IA-2, IA-5
set -euo pipefail

echo "[Sarge] PAM Hardening — IA-2 (faillock) + IA-5 (pwquality)"
read -r -p "Apply PAM hardening? [y/N] " confirm
[[ "$confirm" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }

apt-get install -y libpam-pwquality &>/dev/null || true

# pwquality
cat > /etc/security/pwquality.conf << PWEOF
minlen = 12
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
maxrepeat = 3
gecoscheck = 1
PWEOF

# faillock
cat > /etc/security/faillock.conf << FLEOF
deny = 5
unlock_time = 1800
fail_interval = 900
silent
audit
FLEOF

# login.defs
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs

# Session timeout
TIMEOUT_FILE="/etc/profile.d/sarge-timeout.sh"
cat > "$TIMEOUT_FILE" << TOEOF
# Sarge: Session timeout — NIST 800-53 IA-2
export TMOUT=900
readonly TMOUT
TOEOF
chmod 644 "$TIMEOUT_FILE"

echo "[Sarge] PAM hardening applied."
