#!/usr/bin/env bash
# lib/platforms/macos.sh — macOS probe + primitive implementations.
#
# Functions are named `macos_<probe>` and called via the dispatcher in
# _dispatch.sh as `platform <probe>`. Mirrors lib/platforms/ubuntu.sh in
# shape. Probes that have no native macOS analog are intentionally left
# undefined so the dispatcher returns 127 and check files route to
# skipx with a macOS-appropriate rationale rather than emitting a failx
# with Ubuntu-flavored remediation text.
#
# Design notes
# ------------
#   - macOS uses BSD coreutils. `stat -f` / `find -perm -o+r` replace the
#     GNU forms used by ubuntu.sh.
#   - Account state lives in Open Directory (`dscl`), not /etc/shadow.
#   - The macOS firewall surface is the Application Layer Firewall via
#     `socketfilterfw` (the same toggle exposed in System Settings ▸
#     Network ▸ Firewall). `pf` is also present but less commonly used
#     on workstation deployments.
#   - The BSM auditd subsystem was deprecated by Apple; modern monitoring
#     uses the Endpoint Security framework, which is not driveable from a
#     shell probe. audit_* probes are deliberately not implemented.
#   - login.defs, pwquality, and pam_faillock are Linux-PAM constructs.
#     macOS password policy is set via pwpolicy/account-policy plists,
#     frequently delegated to MDM. Probing locally returns "unset" on
#     managed Macs, which would be more misleading than a clean skip.

# ---------- Filesystem ----------

# Print octal mode (e.g. "700") of a path. Empty if missing.
macos_file_perm() { stat -f "%A" "$1" 2>/dev/null; }

# Print owning user of a path. Empty if missing.
macos_file_owner() { stat -f "%Su" "$1" 2>/dev/null; }

# Print world-readable files under a directory (newline-separated, capped).
# Symbolic -perm form is portable across BSD and GNU find.
macos_world_readable_files_in() {
  find "$1" -type f -perm -o+r 2>/dev/null | head -10
}

# ---------- Accounts (AC family) ----------

# Print non-system users (UID >= 500, name not starting with "_") whose
# Open Directory record has no ShadowHash AuthenticationAuthority — the
# closest semantic to /etc/shadow's "empty password" on macOS. On a
# normally provisioned Mac this returns empty.
macos_users_with_empty_passwords() {
  local user aa
  dscl . -list /Users UniqueID 2>/dev/null \
    | awk '$2 >= 500 && $1 !~ /^_/ {print $1}' \
    | while read -r user; do
        aa=$(dscl . -read "/Users/$user" AuthenticationAuthority 2>/dev/null)
        if [[ -z "$aa" ]] || ! echo "$aa" | grep -q "ShadowHash"; then
          echo "$user"
        fi
      done
}

# Print non-root users with UID 0.
macos_uid_zero_non_root_users() {
  dscl . -list /Users UniqueID 2>/dev/null \
    | awk '$2 == 0 && $1 != "root" {print $1}'
}

# 0 = current user has passwordless sudo, nonzero otherwise.
macos_passwordless_sudo_for_current_user() { sudo -n true 2>/dev/null; }

# Name of the admin group on this platform.
macos_admin_group_name() { echo "admin"; }

# 0 if the given user is in the admin group, nonzero otherwise.
macos_user_in_admin_group() { groups "$1" 2>/dev/null | grep -qw admin; }

# ---------- Firewall (AC-17) ----------

# socketfilterfw is the Application Layer Firewall control surface. Present
# on every supported macOS release; pf is also available but socketfilterfw
# matches what System Settings exposes to operators.
_MACOS_ALF=/usr/libexec/ApplicationFirewall/socketfilterfw

macos_firewall_command_available() { [[ -x "$_MACOS_ALF" ]]; }

# Full text of `socketfilterfw --getglobalstate`. Tries non-interactive
# sudo first (no password prompt — assessment must never hang on sudo),
# falls back to unprivileged invocation (which still prints the state on
# modern macOS), and finally a literal "inactive" so callers always get a
# deterministic string.
macos_firewall_status_text() {
  if [[ ! -x "$_MACOS_ALF" ]]; then
    echo "inactive"
    return 0
  fi
  sudo -n "$_MACOS_ALF" --getglobalstate 2>/dev/null \
    || "$_MACOS_ALF" --getglobalstate 2>/dev/null \
    || echo "inactive"
}

# 0 if firewall is active. socketfilterfw prints "Firewall is enabled.
# (State = 1)" for "block incoming for specific apps" and "(State = 2)" for
# "block all incoming"; "State = 0" means off.
macos_firewall_active() {
  macos_firewall_status_text | grep -qE "State = [12]|Firewall is enabled"
}

# Print externally-bound listening sockets (one per line, "addr:port").
# lsof is preinstalled on macOS. System-owned listeners may show command
# fields as "-" without elevation but the address:port we care about is
# still surfaced.
macos_externally_listening_ports() {
  lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null \
    | awk 'NR>1 {print $9}' \
    | grep -vE '^127\.0\.0\.1:|^\[::1\]:|^\*:0$' \
    | sort -u
}

# 0 if the given TCP port is listening (any interface).
macos_port_listening() {
  lsof -nP -iTCP:"$1" -sTCP:LISTEN 2>/dev/null | grep -q LISTEN
}

# ---------- Audit (AU family) ----------
#
# Apple deprecated the BSM auditd subsystem; modern monitoring uses
# Endpoint Security, which is not driveable from a shell probe. The
# following probes are intentionally NOT defined so AU controls route
# to skipx with a macOS-appropriate rationale:
#   audit_daemon_active, auditctl_available, audit_rules,
#   audit_log_path, journal_disk_usage
#
# Unified Logging (`log`) is always-on on macOS — there is no "off"
# state — so AU-2 "system logging exists" is structurally satisfied.
# We map system_logger_active to a successful exit so check-au.sh's
# verdict logic emits PASS.
macos_system_logger_active() { return 0; }

# ---------- Packages / Services (CM family + SI family) ----------
#
# macOS package install/update flows through softwareupdate (system) and
# Homebrew/MAS (third-party). unattended-upgrades has no equivalent —
# it is typically delegated to MDM (Jamf, Intune, Kandji). Intentionally
# left undefined:
#   package_installed, unattended_upgrades_config_path,
#   pending_package_updates_count, pending_security_updates_count
#
# Likewise the Linux legacy service inventory (telnet, rsh, vsftpd, cups,
# avahi-daemon as systemd unit names) does not map to launchd labels;
# `linux_legacy_service_names` is intentionally Ubuntu-only.

# Generic service status via launchctl. macOS service labels are
# reverse-DNS (e.g. com.openssh.sshd), unlike Ubuntu's short unit names —
# callers must pass the macOS-form label.
macos_service_active() {
  launchctl print "system/$1" &>/dev/null
}

# launchd does not separate "enabled" from "loaded" the way systemd does;
# a service is either bootstrapped or not. We model "enabled" as "the
# plist exists in a system LaunchDaemons directory" so callers can
# distinguish "configured to run at boot" from "currently running."
macos_service_enabled() {
  local dir
  for dir in /System/Library/LaunchDaemons /Library/LaunchDaemons; do
    [[ -r "$dir/$1.plist" ]] && return 0
  done
  return 1
}

# 0 if the SSH server is active under its macOS launchd label. On macOS
# sshd runs via launchd (com.openssh.sshd) rather than a systemd unit.
macos_sshd_active() { launchctl print system/com.openssh.sshd &>/dev/null; }

macos_sshd_config_path() { echo "/etc/ssh/sshd_config"; }

# ---------- Authentication (IA family) ----------
#
# /etc/login.defs, pwquality.conf, and pam_faillock are Linux-PAM
# constructs. macOS uses pwpolicy/account-policy plists, frequently
# delegated to MDM. Probes intentionally NOT defined:
#   login_defs_value, pwquality_config_path, pwquality_value,
#   pam_auth_path, pam_faillock_configured, faillock_config_path,
#   faillock_value
#
# Session timeout (TMOUT) is shell-level on both platforms and worth
# probing on macOS too — macOS defaults to zsh, but operators may set
# TMOUT in /etc/profile or /etc/bashrc for bash sessions.
macos_session_timeout_setting() {
  local f line
  for f in /etc/profile /etc/zshrc /etc/zprofile /etc/bashrc; do
    [[ -r "$f" ]] || continue
    line=$(grep "TMOUT" "$f" 2>/dev/null | grep -v "^[[:space:]]*#" | head -1)
    [[ -n "$line" ]] && { echo "$line"; return 0; }
  done
  if [[ -d /etc/profile.d ]]; then
    grep -rh "TMOUT" /etc/profile.d/ 2>/dev/null | grep -v "^[[:space:]]*#" | head -1
  fi
}

# ---------- Integrity (SI family) ----------
#
# macOS ships XProtect + Gatekeeper + Notarization rather than a
# user-installed AV. fail2ban has no native analog. Intentionally NOT
# defined: clamav_installed, fail2ban_status.

# 0 if the checksum file verifies against the working directory. macOS
# ships `shasum` instead of GNU `sha256sum`; output formats are
# compatible in both directions, so a CHECKSUMS.sha256 produced on
# Ubuntu verifies correctly here.
macos_verify_checksums() { shasum -a 256 -c "$1" --quiet 2>/dev/null; }

# ---------- Drift (CM-2) ----------
#
# Emits the platform-specific "fields" block consumed by drift/snapshot.sh
# and drift/compare.sh. One key=value pair per line; the snapshot writer
# wraps these into a JSON object.
#
# Capture pattern: `var=$(cmd) || true; echo "k=${var:-default}"`. See
# the rationale comment on _ubuntu_drift_fields — same correctness
# concerns apply (pipefail-less pipelines, signal-bearing exit codes
# from grep/awk when there's no match).
_macos_drift_fields() {
  local fw perm sshd_state sshd_conf permit_root pw_auth sip
  fw=$(macos_firewall_status_text 2>/dev/null | head -1 | tr -d '\n') || true
  perm=$(stat -f '%A' "$HOME/.openclaw" 2>/dev/null) || true
  if launchctl print system/com.openssh.sshd &>/dev/null; then
    sshd_state="active"
  else
    sshd_state="inactive"
  fi
  sshd_conf="/etc/ssh/sshd_config"
  if [[ -r "$sshd_conf" ]]; then
    permit_root=$(grep -iE '^PermitRootLogin' "$sshd_conf" 2>/dev/null | awk '{print $2}' | head -1) || true
    pw_auth=$(grep -iE '^PasswordAuthentication' "$sshd_conf" 2>/dev/null | awk '{print $2}' | head -1) || true
  fi
  sip=$(csrutil status 2>/dev/null | awk -F': ' '/status:/{print $2}' | tr -d '.') || true
  echo "firewall_status=${fw:-unknown}"
  echo "openclaw_dir_perm=${perm:-unknown}"
  echo "sshd_active=${sshd_state}"
  echo "ssh_permit_root_login=${permit_root:-unset}"
  echo "ssh_password_auth=${pw_auth:-unset}"
  echo "system_integrity_protection=${sip:-unknown}"
}

# Snapshot + compare dispatch entry points. The actual loops live in
# lib/platforms/_dispatch.sh (sarge_emit_drift_snapshot_json /
# sarge_emit_drift_check_calls) — these wrappers exist only to satisfy
# the `platform drift_*_fields` dispatch contract.
macos_drift_snapshot_fields() { _macos_drift_fields | sarge_emit_drift_snapshot_json; }
macos_drift_check_fields()    { sarge_emit_drift_check_calls < <(_macos_drift_fields); }
