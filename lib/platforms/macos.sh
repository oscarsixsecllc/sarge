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

# Print world-readable files under a directory that match Sarge's
# known-sensitive allowlist. Mirrors ubuntu_world_readable_sensitive_files_in
# — see the header on that function for the scope rationale. BSD find
# does not implement `-ipath`, so we lowercase-match via `-iname` on
# well-known subdirectory names by walking with `-path`.
macos_world_readable_sensitive_files_in() {
  find "$1" -type f -perm -o+r \( \
       -path "$1/openclaw.json" \
    -o -path "$1/config.json" \
    -o -name "openclaw.json.bak*" \
    -o -name "openclaw.json.backup*" \
    -o -name "config.json.bak*" \
    -o -name "config.json.backup*" \
    -o -path "$1/secrets/*" \
    -o -path "$1/Secrets/*" \
    -o -path "$1/credentials/*" \
    -o -path "$1/Credentials/*" \
    -o -path "$1/auth/*" \
    -o -path "$1/Auth/*" \
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
# Same rationale extends to the AU-4/5/7/8/11 probes added for issue #72
# (log_partition_free_pct, auditd_config_path, auditd_config_value,
# journalctl_available, ausearch_available, syslog_forwarding_configured,
# time_sync_active, time_sync_status_text, logrotate_audit_config_path,
# logrotate_rotate_count) — auditd.conf, logrotate, and journalctl/
# ausearch are Linux constructs with no macOS analog; NTP/time sync on
# macOS is MDM/System Settings-managed, not shell-probeable the same way.
#
# Unified Logging (`log`) is always-on on macOS — there is no "off"
# state — so AU-2 "system logging exists" is structurally satisfied.
# We map system_logger_active to a successful exit so check-au.sh's
# verdict logic emits PASS.
macos_system_logger_active() { return 0; }

# ---------- Packages / Services (CM family + SI family) ----------
#
# macOS package install/update flows through softwareupdate (system) and
# Homebrew/MAS (third-party). unattended-upgrades has no equivalent --
# it is typically delegated to MDM (Jamf, Intune, Kandji). Intentionally
# left undefined:
#   package_installed, unattended_upgrades_config_path
#
# Likewise the Linux legacy service inventory (telnet, rsh, vsftpd, cups,
# avahi-daemon as systemd unit names) does not map to launchd labels;
# `linux_legacy_service_names` is intentionally Ubuntu-only.
#
# Issue #24: native CM-6 / SI-2 probes via softwareupdate --list --no-scan

# Internal: fetch and cache softwareupdate output for the session.
# Uses --no-scan to read the cached scan result (avoids 5-30s CDN hit).
# Operators should schedule periodic `softwareupdate --list` (with scan)
# via launchd or cron so the cached state stays meaningful.
_MACOS_SWUPDATE_CACHE=""
_MACOS_SWUPDATE_CACHED=0
_MACOS_SWUPDATE_NO_DATA=0

_macos_swupdate_load() {
  if [[ "$_MACOS_SWUPDATE_CACHED" -eq 1 ]]; then
    return 0
  fi
  _MACOS_SWUPDATE_CACHED=1

  if ! command -v softwareupdate &>/dev/null; then
    _MACOS_SWUPDATE_NO_DATA=1
    return 0
  fi

  # --no-scan reads cached results; --list formats them for parsing.
  # softwareupdate may print "No new software available." when cache is
  # empty or no updates are pending. Both are valid zero-update states.
  _MACOS_SWUPDATE_CACHE=$(softwareupdate --list --no-scan 2>&1 || true)

  # Detect "never scanned" state: softwareupdate prints a specific message
  # when there's no cached scan data at all.
  if echo "$_MACOS_SWUPDATE_CACHE" | grep -qiE "No scan has been done|Run softwareupdate"; then
    _MACOS_SWUPDATE_NO_DATA=1
  fi
}

# 0 if softwareupdate has never been scanned (no cached data).
# Check scripts can use this to annotate verdicts with "no scan data"
# rather than a misleading "no updates pending."
macos_softwareupdate_no_scan_data() {
  _macos_swupdate_load
  [[ "$_MACOS_SWUPDATE_NO_DATA" -eq 1 ]]
}

# Count of pending package updates from softwareupdate.
# Returns 0 (not 127) when softwareupdate has never scanned, per issue #24
# acceptance criteria. The check verdict distinguishes "no updates" from
# "no data" via the NO_DATA flag.
macos_pending_package_updates_count() {
  _macos_swupdate_load

  if [[ "$_MACOS_SWUPDATE_NO_DATA" -eq 1 ]]; then
    echo "0"
    return 0
  fi

  # Count lines starting with "* Label:" which indicate available updates.
  # "No new software available." produces 0 matches = 0 updates.
  local count
  count=$(echo "$_MACOS_SWUPDATE_CACHE" | grep -c '^\s*\* Label:' || echo 0)
  echo "$count" | tr -d '[:space:]'
}

# Count of pending security-relevant updates. Per Apple's CVE accounting,
# entries with "Recommended: YES" are implicitly security-relevant.
# This is the pragmatic rule documented in issue #24.
macos_pending_security_updates_count() {
  _macos_swupdate_load

  if [[ "$_MACOS_SWUPDATE_NO_DATA" -eq 1 ]]; then
    echo "0"
    return 0
  fi

  local count
  count=$(echo "$_MACOS_SWUPDATE_CACHE" | grep -c 'Recommended: YES' || echo 0)
  echo "$count" | tr -d '[:space:]'
}

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
# macOS password policy is set via `pwpolicy -getaccountpolicies`, which
# returns an XML plist of account-policy entries. On MDM-managed Macs the
# plist is often empty because the policy lives at the MDM tier (Jamf,
# Intune, Kandji). We detect the MDM case and return 127 so the check
# emits SKIP with the MDM rationale rather than a misleading FAIL.
#
# Issue #23: native IA-5 / IA-2 probes via pwpolicy -getaccountpolicies

# Internal: fetch and cache pwpolicy output for the session.
# Returns 127 if the Mac is MDM-managed (policy lives at MDM tier).
# Returns 1 if pwpolicy is not available.
_MACOS_PWPOLICY_CACHE=""
_MACOS_PWPOLICY_CACHED=0
_MACOS_PWPOLICY_MDM=0

_macos_pwpolicy_load() {
  if [[ "$_MACOS_PWPOLICY_CACHED" -eq 1 ]]; then
    [[ "$_MACOS_PWPOLICY_MDM" -eq 1 ]] && return 127
    [[ -z "$_MACOS_PWPOLICY_CACHE" ]] && return 1
    return 0
  fi
  _MACOS_PWPOLICY_CACHED=1

  if ! command -v pwpolicy &>/dev/null; then
    return 1
  fi

  _MACOS_PWPOLICY_CACHE=$(pwpolicy -getaccountpolicies 2>/dev/null || true)

  # Detect MDM-managed Mac: pwpolicy output is empty/placeholder AND
  # management profiles are installed. In this case the local pwpolicy
  # data is not authoritative.
  if [[ -z "$_MACOS_PWPOLICY_CACHE" ]] || ! echo "$_MACOS_PWPOLICY_CACHE" | grep -q "policyContent"; then
    if command -v profiles &>/dev/null && profiles show -type configuration 2>/dev/null | grep -q "profileIdentifier"; then
      _MACOS_PWPOLICY_MDM=1
      return 127
    fi
    # Not MDM-managed but pwpolicy is empty (default policy, no custom rules)
    [[ -z "$_MACOS_PWPOLICY_CACHE" ]] && return 1
  fi
  return 0
}

# Extract a value from the cached pwpolicy plist by attribute name.
# Returns the value on stdout or empty if not found.
_macos_pwpolicy_attr() {
  local attr="$1"
  if [[ -z "$_MACOS_PWPOLICY_CACHE" ]]; then
    return 1
  fi
  # The plist uses <key>attrName</key><integer>N</integer> or <real>N</real> pairs.
  # We use a simple grep+sed approach that works for flat numeric values.
  echo "$_MACOS_PWPOLICY_CACHE" | grep -A1 "<key>${attr}</key>" 2>/dev/null \
    | grep -oE '<(integer|real)>[^<]+</(integer|real)>' \
    | sed -E 's/<[^>]+>//g' | head -1
}

# Map Linux login.defs keys to macOS pwpolicy attributes.
# Returns 127 on MDM-managed Macs (-> SKIP with MDM rationale).
macos_login_defs_value() {
  _macos_pwpolicy_load || return $?
  local key="$1" attr=""
  case "$key" in
    PASS_MAX_DAYS) attr="policyAttributeMaximumPasswordAgeInDays" ;;
    PASS_MIN_DAYS) attr="policyAttributeMinimumPasswordAgeInDays" ;;
    PASS_WARN_AGE)
      # No direct macOS equivalent for password-expiry warning days.
      # Return empty so the check emits WARN (not FAIL).
      echo ""
      return 0
      ;;
    *) return 1 ;;
  esac
  _macos_pwpolicy_attr "$attr"
}

# Sentinel path representing the pwpolicy backing store. The "file" never
# exists on disk, but returning a non-empty path lets check-ia.sh's
# conditional logic proceed to the value checks rather than emitting
# "config file not found."
macos_pwquality_config_path() {
  _macos_pwpolicy_load || return $?
  echo "/var/db/pwpolicy (pwpolicy -getaccountpolicies)"
}

# Map Linux pwquality keys to macOS pwpolicy attributes.
macos_pwquality_value() {
  _macos_pwpolicy_load || return $?
  local key="$1" attr=""
  case "$key" in
    minlen)  attr="policyAttributeMinimumLength" ;;
    dcredit) attr="policyAttributeMinimumNumberOfDigits" ;;
    ucredit) attr="policyAttributeMinimumNumberOfUppercaseLetters" ;;
    ocredit) attr="policyAttributeMinimumNumberOfSymbolCharacters" ;;
    lcredit) attr="policyAttributeMinimumNumberOfLowercaseLetters" ;;
    *) return 1 ;;
  esac
  _macos_pwpolicy_attr "$attr"
}

# Sentinel path for PAM auth. Lets check-ia.sh's faillock section proceed.
macos_pam_auth_path() {
  _macos_pwpolicy_load || return $?
  echo "/var/db/pwpolicy (pwpolicy -getaccountpolicies)"
}

# 0 if pwpolicy contains a max-failed-authentications policy.
macos_pam_faillock_configured() {
  _macos_pwpolicy_load || return $?
  _macos_pwpolicy_attr "policyAttributeMaximumFailedAuthentications" | grep -q .
}

# Sentinel path for faillock config. Lets check-ia.sh proceed to value checks.
macos_faillock_config_path() {
  _macos_pwpolicy_load || return $?
  echo "/var/db/pwpolicy (pwpolicy -getaccountpolicies)"
}

# Map Linux faillock keys to macOS pwpolicy attributes.
macos_faillock_value() {
  _macos_pwpolicy_load || return $?
  local key="$1"
  case "$key" in
    deny)
      _macos_pwpolicy_attr "policyAttributeMaximumFailedAuthentications"
      ;;
    unlock_time)
      # pwpolicy stores reset time in minutes; faillock uses seconds.
      local minutes
      minutes=$(_macos_pwpolicy_attr "policyAttributeMinutesUntilFailedAuthenticationReset")
      if [[ -n "$minutes" ]]; then
        echo $(( minutes * 60 ))
      fi
      ;;
    *) return 1 ;;
  esac
}

# Session timeout (TMOUT) is shell-level on both platforms and worth
# probing on macOS too. macOS defaults to zsh, but operators may set
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
  local dup_uid_count ssh_protocol_1 ia_oc_config auth_mode session_idle_ttl
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
    if grep -qiE "^[[:space:]]*Protocol[[:space:]]+1(\b|,)" "$sshd_conf" 2>/dev/null; then
      ssh_protocol_1="yes"
    else
      ssh_protocol_1="no"
    fi
  fi
  sip=$(csrutil status 2>/dev/null | awk -F': ' '/status:/{print $2}' | tr -d '.') || true
  # IA-4: duplicate UID count (identifier reuse signal). /etc/passwd on
  # macOS only carries local accounts (Open Directory holds the rest),
  # but a duplicate here is still a hygiene signal worth tracking.
  dup_uid_count=$(awk -F: '{print $3}' /etc/passwd 2>/dev/null | sort | uniq -d | wc -l | tr -d '[:space:]') || true
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
  echo "firewall_status=${fw:-unknown}"
  echo "openclaw_dir_perm=${perm:-unknown}"
  echo "sshd_active=${sshd_state}"
  echo "ssh_permit_root_login=${permit_root:-unset}"
  echo "ssh_password_auth=${pw_auth:-unset}"
  echo "system_integrity_protection=${sip:-unknown}"
  echo "duplicate_uid_count=${dup_uid_count:-unknown}"
  echo "ssh_protocol_1_configured=${ssh_protocol_1:-unknown}"
  echo "gateway_auth_mode=${auth_mode:-unknown}"
  echo "gateway_session_idle_ttl_ms=${session_idle_ttl:-unknown}"

  # Pending updates (issue #24). Uses cached softwareupdate output.
  local pending_total pending_security
  pending_total=$(macos_pending_package_updates_count 2>/dev/null) || true
  pending_security=$(macos_pending_security_updates_count 2>/dev/null) || true
  echo "pending_updates_total=${pending_total:-unknown}"
  echo "pending_updates_security=${pending_security:-unknown}"

  # OpenClaw config surface (shared across platforms, defined in _dispatch.sh)
  _sarge_openclaw_config_drift_fields
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
macos_drift_snapshot_fields() { _macos_drift_fields | sarge_emit_drift_snapshot_json; }
macos_drift_check_fields()    { sarge_emit_drift_check_calls < <(_macos_drift_fields); }
