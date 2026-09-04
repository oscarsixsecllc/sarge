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

# Print world-readable files under a directory that match Sarge's
# known-sensitive allowlist (newline-separated, capped). Scope is narrow
# on purpose — see the SC-28 comment in assessment/checks/check-sc.sh
# and issue #64. The list captures:
#   - the live and legacy OpenClaw config (openclaw.json / config.json)
#     and any of their `.bak*` / `.backup*` siblings
#   - anything under secrets/, credentials/, auth/ (case-insensitive)
#   - filename patterns that look like credential material
#     (*.key, *.pem, *.env, *-token*, *-secret*, id_rsa*, id_ed25519*)
# Symbolic -perm form is portable across BSD and GNU find.
ubuntu_world_readable_sensitive_files_in() {
  find "$1" -type f -perm -o+r \( \
       -path "$1/openclaw.json" \
    -o -path "$1/config.json" \
    -o -name "openclaw.json.bak*" \
    -o -name "openclaw.json.backup*" \
    -o -name "config.json.bak*" \
    -o -name "config.json.backup*" \
    -o -ipath "$1/secrets/*" \
    -o -ipath "$1/credentials/*" \
    -o -ipath "$1/auth/*" \
    -o -name "*.key" \
    -o -name "*.pem" \
    -o -name "*.env" \
    -o -name "*-token*" \
    -o -name "*-secret*" \
    -o -name "id_rsa*" \
    -o -name "id_ed25519*" \
  \) 2>/dev/null | head -10
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

# Percentage of free space on the partition backing the audit log
# directory (falls back to /var/log if /var/log/audit doesn't exist).
# Prints an integer 0-100. Empty if df is unavailable or the path is
# missing entirely.
ubuntu_log_partition_free_pct() {
  local target="/var/log/audit"
  [[ -d "$target" ]] || target="/var/log"
  df -P "$target" 2>/dev/null | awk 'NR==2 { gsub("%","",$5); print 100-$5 }'
}

ubuntu_auditd_config_path() { echo "/etc/audit/auditd.conf"; }

# Read `key = value` from auditd.conf (case-insensitive key match). Empty
# if unset or the file doesn't exist.
ubuntu_auditd_config_value() {
  grep -i "^$1" "$(ubuntu_auditd_config_path)" 2>/dev/null | awk -F= '{print $2}' | tr -d ' '
}

ubuntu_journalctl_available() { command -v journalctl &>/dev/null; }
ubuntu_ausearch_available()   { command -v ausearch &>/dev/null; }

# 0 if rsyslog is configured to forward logs to a remote collector
# (legacy `*.* @host` / `@@host` syntax or modern omfwd action blocks).
ubuntu_syslog_forwarding_configured() {
  grep -rhE '^\s*\*\.\*\s+@|action\(type="omfwd"' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -q .
}

# 0 if the system clock is synchronized via NTP (timedatectl first,
# chrony as fallback for hosts running chronyd directly).
ubuntu_time_sync_active() {
  local synced
  synced=$(timedatectl show -p NTPSynchronized --value 2>/dev/null)
  [[ "$synced" == "yes" ]] && return 0
  chronyc tracking 2>/dev/null | grep -qi "Leap status.*Normal"
}

# Human-readable time sync status, for diagnostics only.
ubuntu_time_sync_status_text() {
  timedatectl status 2>/dev/null || chronyc tracking 2>/dev/null || echo ""
}

# Path to the logrotate config governing the audit log, if any exists.
ubuntu_logrotate_audit_config_path() {
  local f
  for f in /etc/logrotate.d/auditd /etc/logrotate.d/audit; do
    [[ -f "$f" ]] && { echo "$f"; return 0; }
  done
  echo "/etc/logrotate.d/auditd"
}

# Read the `rotate N` cycle count from a logrotate config file. Empty if
# unset or the file doesn't exist.
ubuntu_logrotate_rotate_count() {
  grep -E "^\s*rotate\s+[0-9]+" "$1" 2>/dev/null | awk '{print $2}' | head -1
}

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

# 0 if apt is available at all (gates the SI-7 package-integrity checks).
ubuntu_apt_config_available() { command -v apt-config &>/dev/null; }

# Value of APT::Get::AllowUnauthenticated, lowercased. Empty if unset —
# apt treats unset the same as "false" (signature checks enforced).
ubuntu_apt_allow_unauthenticated() {
  apt-config dump 2>/dev/null | grep -i "AllowUnauthenticated" | awk -F'"' '{print $2}' | tr '[:upper:]' '[:lower:]'
}

# Count of trusted apt GPG keyring files (modern /etc/apt/trusted.gpg.d/
# *.gpg plus the legacy single-file /etc/apt/trusted.gpg, if present).
# Always prints a single integer.
ubuntu_apt_trusted_keys_count() {
  local count=0
  count=$(find /etc/apt/trusted.gpg.d -maxdepth 1 -name "*.gpg" 2>/dev/null | wc -l | tr -d '[:space:]')
  [[ -f /etc/apt/trusted.gpg ]] && count=$((count + 1))
  echo "$count"
}

# Value of /proc/sys/kernel/randomize_va_space: 2=full ASLR, 1=partial,
# 0=disabled. Empty if the file doesn't exist (non-Linux, exotic kernel).
ubuntu_aslr_setting() { cat /proc/sys/kernel/randomize_va_space 2>/dev/null; }

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
# SHA-256 of a single file's contents. Prints "missing" if the file
# doesn't exist, isn't readable, or `sha256sum` isn't available — never
# fails under `set -euo pipefail`.
_ubuntu_sha256_of_file() {
  local path="$1" hash
  if [[ ! -r "$path" ]] || ! command -v sha256sum &>/dev/null; then
    echo "missing"
    return 0
  fi
  hash=$(sha256sum "$path" 2>/dev/null | awk '{print $1}') || true
  echo "${hash:-missing}"
}

# SHA-256 of the concatenated, sorted contents of a glob of files (e.g.
# a rules.d/*.rules directory). Sorting the file list first makes the
# hash stable regardless of filesystem enumeration order. Prints
# "missing" if no files match or sha256sum is unavailable.
_ubuntu_sha256_of_glob() {
  local -a files=("$@")
  local existing=() f hash
  command -v sha256sum &>/dev/null || { echo "missing"; return 0; }
  for f in "${files[@]}"; do
    [[ -r "$f" ]] && existing+=("$f")
  done
  if [[ ${#existing[@]} -eq 0 ]]; then
    echo "missing"
    return 0
  fi
  hash=$(cat "$(printf '%s\n' "${existing[@]}" | sort)" 2>/dev/null | sha256sum | awk '{print $1}') || true
  echo "${hash:-missing}"
}

# SHA-256 of a command's (sorted) stdout. Used for package/service
# inventory hashing. Prints "missing" if the command fails or
# sha256sum is unavailable — never fails under `set -euo pipefail`.
_ubuntu_sha256_of_command() {
  local hash
  command -v sha256sum &>/dev/null || { echo "missing"; return 0; }
  hash=$("$@" 2>/dev/null | sort | sha256sum | awk '{print $1}') || true
  echo "${hash:-missing}"
}

_ubuntu_drift_fields() {
  local ufw auditd f2b perm pmd log_free ntp_sync disk_full_action rotate_count
  local dup_uid_count ssh_protocol_1 ia_oc_config auth_mode session_idle_ttl
  local aslr apt_allow_unauth
  ufw=$(ufw status 2>/dev/null | head -1) || true
  auditd=$(systemctl is-active auditd 2>/dev/null) || true
  f2b=$(systemctl is-active fail2ban 2>/dev/null) || true
  perm=$(stat -c '%a' "$HOME/.openclaw" 2>/dev/null) || true
  pmd=$(grep ^PASS_MAX_DAYS /etc/login.defs 2>/dev/null | awk '{print $2}') || true
  log_free=$(ubuntu_log_partition_free_pct) || true
  ntp_sync=$(ubuntu_time_sync_active && echo "yes" || echo "no") || true
  disk_full_action=$(ubuntu_auditd_config_value "disk_full_action") || true
  rotate_count=$(ubuntu_logrotate_rotate_count "$(ubuntu_logrotate_audit_config_path)") || true
  # IA-4: duplicate UID count (identifier reuse signal)
  dup_uid_count=$(awk -F: '{print $3}' /etc/passwd 2>/dev/null | sort | uniq -d | wc -l | tr -d '[:space:]') || true
  # IA-7: whether SSHv1 (Protocol 1) is explicitly configured
  if grep -qiE "^[[:space:]]*Protocol[[:space:]]+1(\b|,)" /etc/ssh/sshd_config 2>/dev/null; then
    ssh_protocol_1="yes"
  else
    ssh_protocol_1="no"
  fi
  # IA-8 / IA-11: OpenClaw gateway auth mode + session idle TTL. Same
  # openclaw.json -> config.json fallback used by check-ia.sh and
  # check-sc.sh (issue #61).
  for candidate in "$HOME/.openclaw/openclaw.json" "$HOME/.openclaw/config.json"; do
    if [[ -f "$candidate" ]]; then
      ia_oc_config="$candidate"
      break
    fi
  done
  if [[ -n "${ia_oc_config:-}" ]]; then
    auth_mode=$(grep -oE '"mode"[[:space:]]*:[[:space:]]*"[^"]*"' "$ia_oc_config" 2>/dev/null | head -1 | sed -E 's/.*"([^"]+)"$/\1/') || true
    session_idle_ttl=$(grep -oE '"sessionIdleTtlMs"[[:space:]]*:[[:space:]]*[0-9]+' "$ia_oc_config" 2>/dev/null | grep -oE '[0-9]+$' | head -1) || true
  fi
  echo "ufw_status=${ufw:-unknown}"
  echo "auditd_active=${auditd:-unknown}"
  echo "fail2ban_active=${f2b:-unknown}"
  echo "openclaw_dir_perm=${perm:-unknown}"
  echo "pass_max_days=${pmd:-unknown}"
  echo "log_partition_free_pct=${log_free:-unknown}"
  echo "ntp_synchronized=${ntp_sync:-unknown}"
  echo "auditd_disk_full_action=${disk_full_action:-unknown}"
  echo "auditd_log_rotate_count=${rotate_count:-unknown}"
  echo "duplicate_uid_count=${dup_uid_count:-unknown}"
  echo "ssh_protocol_1_configured=${ssh_protocol_1:-unknown}"
  echo "gateway_auth_mode=${auth_mode:-unknown}"
  echo "gateway_session_idle_ttl_ms=${session_idle_ttl:-unknown}"
  # SI-16: ASLR setting (memory protection)
  aslr=$(ubuntu_aslr_setting) || true
  echo "aslr_setting=${aslr:-unknown}"
  # SI-7: apt unauthenticated-package allowance
  apt_allow_unauth=$(ubuntu_apt_allow_unauthenticated) || true
  echo "apt_allow_unauthenticated=${apt_allow_unauth:-unknown}"
  # SA-22: OS + Node.js runtime versions (EOL tracking inputs)
  echo "os_version=${SARGE_OS_VERSION:-unknown}"
  echo "node_version=$(node --version 2>/dev/null | tr -d 'v')"
  # SA-9: external MCP server count. Same openclaw.json -> config.json
  # fallback used by check-sa.sh / check-ia.sh (issue #61).
  local sa_oc_config mcp_server_count
  for candidate in "$HOME/.openclaw/openclaw.json" "$HOME/.openclaw/config.json"; do
    if [[ -f "$candidate" ]]; then
      sa_oc_config="$candidate"
      break
    fi
  done
  if [[ -n "${sa_oc_config:-}" ]]; then
    if command -v jq &>/dev/null; then
      mcp_server_count=$(jq -r '(.mcp.servers // {}) | to_entries | map(select(.key | startswith("_") | not)) | length' "$sa_oc_config" 2>/dev/null)
    fi
  fi
  echo "mcp_external_server_count=${mcp_server_count:-unknown}"
  # MP-6: media retention TTL
  local media_ttl
  if [[ -n "${sa_oc_config:-}" ]]; then
    media_ttl=$(grep -oE '"ttlHours"[[:space:]]*:[[:space:]]*[0-9]+' "$sa_oc_config" 2>/dev/null | grep -oE '[0-9]+$' | head -1) || true
  fi
  echo "media_ttl_hours=${media_ttl:-unknown}"
  # SR-11: apt trusted-key count (reuses SI-7's probe)
  local apt_trusted_keys
  apt_trusted_keys=$(ubuntu_apt_trusted_keys_count) || true
  echo "apt_trusted_keys_count=${apt_trusted_keys:-unknown}"

  # SI-7 / CM-2: file-integrity hashes for security-critical files.
  # `sha256sum` prints "missing" for the value when the file doesn't
  # exist or hashing fails, so callers under `set -euo pipefail` never
  # abort on an absent file (some hosts don't run auditd, ufw, etc.).
  local oc_json_hash sshd_hash pam_hash audit_hash ufw_hash
  local oc_json_path
  for candidate in "$HOME/.openclaw/openclaw.json" "$HOME/.openclaw/config.json"; do
    if [[ -f "$candidate" ]]; then
      oc_json_path="$candidate"
      break
    fi
  done
  oc_json_hash=$(_ubuntu_sha256_of_file "${oc_json_path:-$HOME/.openclaw/openclaw.json}")
  sshd_hash=$(_ubuntu_sha256_of_file "/etc/ssh/sshd_config")
  pam_hash=$(_ubuntu_sha256_of_file "/etc/pam.d/common-auth")
  audit_hash=$(_ubuntu_sha256_of_glob "/etc/audit/rules.d/"*.rules)
  ufw_hash=$(_ubuntu_sha256_of_file "/etc/ufw/user.rules")
  echo "openclaw_json_sha256=${oc_json_hash}"
  echo "sshd_config_sha256=${sshd_hash}"
  echo "pam_common_auth_sha256=${pam_hash}"
  echo "audit_rules_sha256=${audit_hash}"
  echo "ufw_rules_sha256=${ufw_hash}"

  # CM-8: package + service inventory hashes. Detects package
  # additions/removals and enabled-service changes between snapshots
  # without storing the full (large) inventory in the snapshot itself.
  local pkg_hash svc_hash
  pkg_hash=$(_ubuntu_sha256_of_command dpkg --get-selections)
  svc_hash=$(_ubuntu_sha256_of_command systemctl list-unit-files --state=enabled --no-legend)
  echo "installed_packages_sha256=${pkg_hash}"
  echo "enabled_services_sha256=${svc_hash}"

  # OpenClaw config surface (shared across platforms, defined in _dispatch.sh)
  _sarge_openclaw_config_drift_fields

  # CM-2: control-catalog sync check (shared across platforms, _dispatch.sh)
  _sarge_catalog_sync_field
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
