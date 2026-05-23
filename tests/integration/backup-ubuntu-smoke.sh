#!/usr/bin/env bash
# tests/integration/backup-ubuntu-smoke.sh
# Smoke-tests scripts/backup-ubuntu.sh against a temp run dir.
# Does NOT mutate any real system config — uses --test-mode + a temp backup root.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BACKUP_SCRIPT="$REPO_ROOT/scripts/backup-ubuntu.sh"
ROLLBACK_SCRIPT="$REPO_ROOT/scripts/rollback-ubuntu.sh"

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "  ok: $*"; }

[[ -x "$BACKUP_SCRIPT"   ]] || fail "backup-ubuntu.sh not executable"
[[ -x "$ROLLBACK_SCRIPT" ]] || fail "rollback-ubuntu.sh not executable"

bash -n "$BACKUP_SCRIPT"   || fail "backup-ubuntu.sh syntax"
bash -n "$ROLLBACK_SCRIPT" || fail "rollback-ubuntu.sh syntax"
pass "syntax check"

TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "$TMP_ROOT"' EXIT
RUN_ID="smoke-$(date +%s)"
BACKUP_DIR="$TMP_ROOT/$RUN_ID/backup"

"$BACKUP_SCRIPT" --unattended --test-mode \
  --run-id "$RUN_ID" \
  --backup-root "$BACKUP_DIR" >/dev/null

[[ -d "$BACKUP_DIR" ]]                 || fail "backup dir not created"
[[ -f "$BACKUP_DIR/rollback.sh" ]]     || fail "rollback.sh missing"
[[ -x "$BACKUP_DIR/rollback.sh" ]]     || fail "rollback.sh not executable"
[[ -f "$BACKUP_DIR/summary.md" ]]      || fail "summary.md missing"
[[ -f "$BACKUP_DIR/ufw-state.txt" ]]   || fail "ufw-state.txt missing"
[[ -f "$BACKUP_DIR/audit-state.txt" ]] || fail "audit-state.txt missing"
[[ -f "$BACKUP_DIR/services.txt" ]]    || fail "services.txt missing"
[[ -f "$BACKUP_DIR/packages.txt" ]]    || fail "packages.txt missing"
[[ -f "$BACKUP_DIR/backup.log" ]]      || fail "backup.log missing"
pass "all expected artifacts present"

# Rollback wrapper validates a complete backup dir without applying it.
wrapper_out="$("$ROLLBACK_SCRIPT" --backup-dir "$BACKUP_DIR" </dev/null 2>&1 || true)"
if grep -q "Backup directory: $BACKUP_DIR" <<<"$wrapper_out"; then
  pass "rollback wrapper validates backup dir"
else
  echo "$wrapper_out" >&2
  fail "rollback wrapper failed to validate backup dir"
fi

echo "PASS: backup-ubuntu smoke test"
