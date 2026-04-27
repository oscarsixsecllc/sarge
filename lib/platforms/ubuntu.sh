#!/usr/bin/env bash
# lib/platforms/ubuntu.sh — Ubuntu probe + primitive implementations.
#
# Functions are named `ubuntu_<probe>` and called via the dispatcher in
# _dispatch.sh as `platform <probe>`. Keep this file focused on platform
# data acquisition; 800-53 control logic and verdict messages live in the
# control files (assessment/checks/check-*.sh, scripts/harden-*.sh).
#
# Each probe documents what it returns and any relevant exit-code semantics.

# ---------- Filesystem ----------

# Print octal mode (e.g. "700") of a path. Empty if missing.
ubuntu_file_perm() { stat -c "%a" "$1" 2>/dev/null; }

# Print owning user of a path. Empty if missing.
ubuntu_file_owner() { stat -c "%U" "$1" 2>/dev/null; }

# Print world-readable files under a directory (newline-separated, capped).
ubuntu_world_readable_files_in() {
  find "$1" -type f -perm /004 2>/dev/null | head -10
}

# ---------- Accounts (AC family) ----------

# Print users that have an empty password field in /etc/shadow.
ubuntu_users_with_empty_passwords() {
  awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null
}

# Print non-root users with UID 0.
ubuntu_uid_zero_non_root_users() {
  awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd 2>/dev/null
}

# 0 = current user has passwordless sudo, nonzero otherwise.
ubuntu_passwordless_sudo_for_current_user() { sudo -n true 2>/dev/null; }

# Name of the admin group on this platform.
ubuntu_admin_group_name() { echo "sudo"; }

# 0 if the given user is in the admin group, nonzero otherwise.
ubuntu_user_in_admin_group() { groups "$1" 2>/dev/null | grep -qw sudo; }

# ---------- Firewall (AC-17) ----------

ubuntu_firewall_command_available() { command -v ufw &>/dev/null; }

# Full text of `ufw status`. Uses non-interactive sudo so the assessment never
# blocks on a password prompt — falls back to plain `ufw status` (works if the
# operator has read access) and finally the literal string "inactive".
ubuntu_firewall_status_text() {
  sudo -n ufw status 2>/dev/null || ufw status 2>/dev/null || echo "inactive"
}

# 0 if firewall is active, nonzero otherwise.
ubuntu_firewall_active() { ubuntu_firewall_status_text | grep -q "Status: active"; }

# Print externally-bound listening sockets (one per line, "Local Address:Port").
ubuntu_externally_listening_ports() {
  ss -tlnp 2>/dev/null | grep -v "127.0.0.1\|::1\|Address" | awk '{print $4}' | grep -v "^$"
}

# 0 if the given TCP port is listening (any interface).
ubuntu_port_listening() { ss -tlnp 2>/dev/null | grep -q ":$1\b"; }

# ---------- Audit (AU family) ----------

ubuntu_audit_daemon_active() { systemctl is-active --quiet auditd 2>/dev/null; }
ubuntu_auditctl_available()  { command -v auditctl &>/dev/null; }

# Full text of loaded audit rules. Tries direct first, then non-interactive
# sudo (no password prompt) — assessment must never hang on sudo.
ubuntu_audit_rules() {
  auditctl -l 2>/dev/null || sudo -n auditctl -l 2>/dev/null || echo ""
}

# Path to the primary audit log on this platform.
ubuntu_audit_log_path() { echo "/var/log/audit/audit.log"; }

ubuntu_system_logger_active() { systemctl is-active --quiet systemd-journald 2>/dev/null; }

# Output of `journalctl --disk-usage` (used to detect persisted journals).
ubuntu_journal_disk_usage() { journalctl --disk-usage 2>/dev/null; }

# ---------- Packages / Services (CM family + SI family) ----------

# 0 if a deb package is installed.
ubuntu_package_installed() { dpkg -l "$1" 2>/dev/null | grep -q "^ii"; }

ubuntu_unattended_upgrades_config_path() { echo "/etc/apt/apt.conf.d/50unattended-upgrades"; }

# Count of pending package updates. Always prints a single integer.
ubuntu_pending_package_updates_count() {
  local n
  n=$(apt list --upgradable 2>/dev/null | grep -c "upgradable" || echo 0)
  echo "$n" | head -1 | tr -d "[:space:]"
}

# Count of pending updates flagged "security". Always prints an integer.
ubuntu_pending_security_updates_count() {
  local n
  n=$(apt list --upgradable 2>/dev/null | grep -ic "security" || echo 0)
  echo "$n" | head -1 | tr -d "[:space:]"
}

ubuntu_service_active()  { systemctl is-active  --quiet "$1" 2>/dev/null; }
ubuntu_service_enabled() { systemctl is-enabled --quiet "$1" 2>/dev/null; }

# 0 if the SSH server is active under either of its common unit names.
ubuntu_sshd_active() {
  systemctl is-active --quiet ssh 2>/dev/null || systemctl is-active --quiet sshd 2>/dev/null
}

ubuntu_sshd_config_path() { echo "/etc/ssh/sshd_config"; }

# ---------- Authentication (IA family) ----------

# Read a numeric value from /etc/login.defs (e.g. PASS_MAX_DAYS). Empty if unset.
ubuntu_login_defs_value() {
  grep "^$1" /etc/login.defs 2>/dev/null | awk '{print $2}'
}

ubuntu_pwquality_config_path() { echo "/etc/security/pwquality.conf"; }

# Read `name = value` from pwquality.conf. Empty if unset.
ubuntu_pwquality_value() {
  grep "^$1" /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' '
}

ubuntu_pam_auth_path() { echo "/etc/pam.d/common-auth"; }

# 0 if pam_faillock is referenced in common-auth.
ubuntu_pam_faillock_configured() {
  grep -q "pam_faillock" /etc/pam.d/common-auth 2>/dev/null
}

ubuntu_faillock_config_path() { echo "/etc/security/faillock.conf"; }

# Read a value from faillock.conf (e.g. deny, unlock_time). Empty if unset.
# Parser only handles the space-delimited form (`deny = 5`) — that's what
# harden-pam.sh writes, so it's correct for Sarge-managed files. Tightening
# the parser to also handle `deny=5` (no spaces) would be a behavior change
# beyond this refactor's scope; tracked as a follow-up.
ubuntu_faillock_value() {
  grep "^$1" /etc/security/faillock.conf 2>/dev/null | awk '{ print $3 }'
}

# First non-comment TMOUT line found in profile files. Empty if none.
ubuntu_session_timeout_setting() {
  grep -rh "TMOUT" /etc/profile /etc/profile.d/ /etc/bash.bashrc 2>/dev/null \
    | grep -v "^#" | head -1
}

# ---------- Integrity (SI family) ----------

# 0 if any ClamAV scanner binary is on PATH.
ubuntu_clamav_installed() {
  command -v clamscan &>/dev/null || command -v clamav &>/dev/null
}

# Full text of `fail2ban-client status`. Tries direct first, then non-interactive
# sudo (no password prompt). Empty on failure — caller treats that as
# "unavailable" rather than blocking the whole assessment.
ubuntu_fail2ban_status() {
  fail2ban-client status 2>/dev/null || sudo -n fail2ban-client status 2>/dev/null || echo ""
}

# 0 if the checksum file verifies against the working directory.
# Caller is responsible for `cd`'ing to the repo root before calling.
ubuntu_verify_checksums() { sha256sum --check "$1" --quiet 2>/dev/null; }
