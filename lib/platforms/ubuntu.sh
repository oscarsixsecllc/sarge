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

# CM-7 inventory of legacy Unix services Sarge knows how to flag. Defined
# as a platform probe (rather than hardcoded in check-cm.sh) so non-Linux
# platforms — where these systemd unit names don't map to native service
# labels — can skip the section cleanly via platform_supports rather than
# emit misleading "telnet is not running" PASSes for a control surface
# that doesn't exist on the host.
ubuntu_linux_legacy_service_names() {
  cat <<NAMES
telnet
rsh
rlogin
vsftpd
pure-ftpd
proftpd
xinetd
cups
avahi-daemon
NAMES
}

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
# Parser handles both the space-delimited form (`deny = 5`) that harden-pam.sh
# writes AND the no-space form (`deny=5`) that operators may use when hand-
# editing. Skips comment lines and bare keywords (silent / audit).
ubuntu_faillock_value() {
  awk -F= -v key="$1" '
    /^[[:space:]]*#/ { next }
    NF < 2          { next }
    {
      lhs = $1
      rhs = $2
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", lhs)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", rhs)
      if (lhs == key) { print rhs; exit }
    }
  ' "$(ubuntu_faillock_config_path)" 2>/dev/null
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

# ---------- Drift (CM-2) ----------
#
# Emits the platform-specific "fields" block consumed by drift/snapshot.sh
# and drift/compare.sh. Same key list the pre-platforms snapshot used, so
# operators with existing snapshots see no drift after upgrade.
#
# Capture pattern: `var=$(cmd) || true; echo "k=${var:-unknown}"`.
# Two correctness properties this guards:
#   1. `systemctl is-active` exits non-zero when a unit is inactive/failed
#      but prints the meaningful state ("inactive", "failed") on stdout.
#      An inline `... || echo unknown` would *append* "unknown" to that
#      stdout (giving a literal "inactive\nunknown" capture that breaks
#      JSON); a trailing `|| var=""` would overwrite the captured signal.
#      `|| true` short-circuits set -e without touching the variable.
#   2. Pipelines like `cmd | head -1 || echo unknown` don't trigger the
#      fallback when the *left* side fails — without `pipefail` the
#      pipeline exit is from head (zero on empty stdin). Capture-then-
#      default sidesteps that entirely.
_ubuntu_drift_fields() {
  local ufw auditd f2b perm pmd
  ufw=$(ufw status 2>/dev/null | head -1) || true
  auditd=$(systemctl is-active auditd 2>/dev/null) || true
  f2b=$(systemctl is-active fail2ban 2>/dev/null) || true
  perm=$(stat -c '%a' "$HOME/.openclaw" 2>/dev/null) || true
  pmd=$(grep ^PASS_MAX_DAYS /etc/login.defs 2>/dev/null | awk '{print $2}') || true
  echo "ufw_status=${ufw:-unknown}"
  echo "auditd_active=${auditd:-unknown}"
  echo "fail2ban_active=${f2b:-unknown}"
  echo "openclaw_dir_perm=${perm:-unknown}"
  echo "pass_max_days=${pmd:-unknown}"
}

# Snapshot + compare dispatch entry points. The actual loops live in
# lib/platforms/_dispatch.sh (sarge_emit_drift_snapshot_json /
# sarge_emit_drift_check_calls) — these wrappers exist only to satisfy
# the `platform drift_*_fields` dispatch contract.
#
# The snapshot wrapper uses a pipe; the check wrapper uses process
# substitution. They look symmetric but they're not — see the rationale
# block on sarge_emit_drift_check_calls in _dispatch.sh. tl;dr: `check`
# mutates a DRIFT counter in compare.sh's scope, and a pipe would run
# the sink in a subshell that drops the mutation.
ubuntu_drift_snapshot_fields() { _ubuntu_drift_fields | sarge_emit_drift_snapshot_json; }
ubuntu_drift_check_fields()    { sarge_emit_drift_check_calls < <(_ubuntu_drift_fields); }
