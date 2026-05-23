#!/usr/bin/env bash
# backup-macos-smoke.sh — dry-run smoke test for scripts/backup-macos.sh
#
# This test runs on Linux (Sarge's primary dev surface). It does NOT
# validate that the macOS-specific commands (tmutil, pfctl, defaults,
# socketfilterfw, csrutil, spctl, fdesetup) behave correctly on a real
# Mac — that requires hardware we don't have. It only verifies:
#
#   1. The script honors SARGE_BACKUP_DRY_RUN=1 on non-Darwin
#   2. The expected artifacts are created in the per-run backup dir
#   3. rollback.sh is emitted and is executable
#   4. summary.md is emitted with the expected sections
#
# Real-Mac validation is tracked as untested in PR #30's body.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BACKUP_SH="$REPO_ROOT/scripts/backup-macos.sh"

TMP="$(mktemp -d -t sarge-backup-macos-smoke.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

STUBS="$TMP/stubs"
mkdir -p "$STUBS"

# Stub the macOS-only binaries with no-op shims that emit something on
# stdout so 'set -e' style consumers see a successful exit. Even though
# the script uses SARGE_BACKUP_DRY_RUN=1 to skip executing these, having
# stubs on PATH proves the dry-run path doesn't accidentally invoke
# real binaries.
for cmd in tmutil pfctl defaults csrutil spctl fdesetup launchctl diskutil; do
  cat > "$STUBS/$cmd" <<EOF
#!/usr/bin/env bash
echo "[stub:$cmd] \$@"
EOF
  chmod +x "$STUBS/$cmd"
done

# socketfilterfw lives at /usr/libexec/ApplicationFirewall/ — the script
# calls it via that absolute path. We don't try to stub absolute paths
# on Linux; in dry-run mode the script doesn't invoke it anyway.

RUN_ID="smoke-$(date +%s)"
export SARGE_RUN_ROOT="$TMP/runs/$RUN_ID"
export SARGE_BACKUP_DRY_RUN=1
export PATH="$STUBS:$PATH"

echo "[smoke] bash -n syntax check..."
if ! bash -n "$BACKUP_SH"; then
  echo "[smoke] FAIL: bash -n failed" >&2
  exit 1
fi
echo "[smoke]   ok"

echo "[smoke] bash -n rollback-macos.sh..."
bash -n "$REPO_ROOT/scripts/rollback-macos.sh" || { echo "[smoke] FAIL: rollback-macos.sh syntax" >&2; exit 1; }
echo "[smoke]   ok"

echo "[smoke] Running backup-macos.sh --unattended --run-id $RUN_ID ..."
if ! bash "$BACKUP_SH" --unattended --run-id "$RUN_ID" > "$TMP/stdout.log" 2> "$TMP/stderr.log"; then
  echo "[smoke] FAIL: backup-macos.sh exited non-zero" >&2
  echo "--- stdout ---"; cat "$TMP/stdout.log"
  echo "--- stderr ---"; cat "$TMP/stderr.log"
  exit 1
fi

BACKUP_DIR="$SARGE_RUN_ROOT/backup"

assert_file() {
  if [[ ! -e "$1" ]]; then
    echo "[smoke] FAIL: expected file missing: $1" >&2
    echo "--- backup dir tree ---"
    find "$BACKUP_DIR" -print 2>/dev/null
    exit 1
  fi
  echo "[smoke]   ok: $1"
}

echo "[smoke] Verifying expected artifacts..."
assert_file "$BACKUP_DIR/apfs-snapshot.txt"
assert_file "$BACKUP_DIR/socketfilterfw.txt"
assert_file "$BACKUP_DIR/pf-state.txt"
assert_file "$BACKUP_DIR/launchctl.txt"
assert_file "$BACKUP_DIR/security-status.txt"
assert_file "$BACKUP_DIR/defaults-com.apple.loginwindow.txt"
assert_file "$BACKUP_DIR/defaults-com.apple.screensaver.txt"
assert_file "$BACKUP_DIR/defaults-com.apple.security.txt"
assert_file "$BACKUP_DIR/defaults-_Library_Preferences_com.apple.alf.txt"
assert_file "$BACKUP_DIR/etc/etc/pam.d"
assert_file "$BACKUP_DIR/etc/etc/ssh/sshd_config"
assert_file "$BACKUP_DIR/etc/etc/sudoers.d"
assert_file "$BACKUP_DIR/etc/etc/security/audit_control"
assert_file "$BACKUP_DIR/rollback.sh"
assert_file "$BACKUP_DIR/summary.md"

echo "[smoke] Verifying rollback.sh is executable..."
[[ -x "$BACKUP_DIR/rollback.sh" ]] || { echo "[smoke] FAIL: rollback.sh not executable" >&2; exit 1; }
bash -n "$BACKUP_DIR/rollback.sh" || { echo "[smoke] FAIL: rollback.sh syntax" >&2; exit 1; }
echo "[smoke]   ok"

echo "[smoke] Verifying summary.md sections..."
for needle in "Run ID" "APFS snapshot" "How to roll back" "tmutil restore"; do
  if ! grep -q "$needle" "$BACKUP_DIR/summary.md"; then
    echo "[smoke] FAIL: summary.md missing '$needle'" >&2
    exit 1
  fi
done
echo "[smoke]   ok"

echo "[smoke] Verifying non-Darwin platform guard rejects without dry-run..."
unset SARGE_BACKUP_DRY_RUN
if bash "$BACKUP_SH" --unattended --run-id guard-test > /dev/null 2>&1; then
  echo "[smoke] FAIL: backup-macos.sh ran on non-Darwin without dry-run flag" >&2
  exit 1
fi
echo "[smoke]   ok (correctly refused)"

echo "[smoke] ALL CHECKS PASSED"
