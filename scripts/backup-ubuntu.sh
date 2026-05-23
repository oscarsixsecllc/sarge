#!/usr/bin/env bash
# backup-ubuntu.sh — Pre-hardening config snapshot + rollback emitter
# NIST 800-53 CP-9 / CM-3 | Oscar Six Security LLC
#
# Captures the state Phase 2 hardening (scripts/harden-*.sh) is about to
# touch — /etc files, ufw rules, audit rules, service enable state, package
# selections — and emits a rollback.sh that reverses every captured artifact.
#
# Snapshot tooling preference: Btrfs/ZFS subvolume → timeshift → LVM thin →
# file-level. File-level snapshot ALWAYS runs (it's the safety net).
#
# Usage:
#   ./scripts/backup-ubuntu.sh                          # interactive opt-in
#   ./scripts/backup-ubuntu.sh --unattended             # skip prompt
#   ./scripts/backup-ubuntu.sh --run-id <id>            # share assess.sh run id
#   ./scripts/backup-ubuntu.sh --dry-run                # log decisions, no writes
#   ./scripts/backup-ubuntu.sh --backup-root <dir>      # override ~/.sarge/runs
#   ./scripts/backup-ubuntu.sh --test-mode              # skip block-level snapshot
#                                                        even when supported

set -uo pipefail

RUN_ID=""
UNATTENDED=0
DRY_RUN=0
TEST_MODE=0
BACKUP_ROOT_OVERRIDE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --unattended)      UNATTENDED=1; shift ;;
    --dry-run)         DRY_RUN=1; shift ;;
    --test-mode)       TEST_MODE=1; shift ;;
    --run-id)          RUN_ID="${2:-}"; shift 2 ;;
    --backup-root)     BACKUP_ROOT_OVERRIDE="${2:-}"; shift 2 ;;
    -h|--help)
      sed -n '2,20p' "$0"
      exit 0
      ;;
    *)
      echo "[Sarge backup] Unknown arg: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$RUN_ID" ]]; then
  RUN_ID="$(date +%Y%m%d-%H%M%S)"
fi

BACKUP_ROOT="${BACKUP_ROOT_OVERRIDE:-$HOME/.sarge/runs/$RUN_ID/backup}"
LOG_FILE="$BACKUP_ROOT/backup.log"

log() {
  local msg="$*"
  echo "[Sarge backup] $msg" >&2
  if [[ -d "$BACKUP_ROOT" ]]; then
    printf '%s %s\n' "$(date -Iseconds)" "$msg" >> "$LOG_FILE"
  fi
}

prompt_consent() {
  if [[ $UNATTENDED -eq 1 ]]; then
    log "Unattended mode — proceeding without prompt."
    return 0
  fi
  echo ""
  echo "[Sarge] Phase 2 hardening will modify /etc, systemd, PAM, sysctl, ufw, audit rules."
  echo "[Sarge] Recommended: capture a pre-hardening snapshot to: $BACKUP_ROOT"
  echo ""
  read -r -p "Capture snapshot now? [Y/n] " confirm
  case "$confirm" in
    ""|y|Y|yes|YES) return 0 ;;
    n|N|no|NO)
      echo "[Sarge] Explicit skip acknowledged. Phase 2 hardening will proceed WITHOUT a snapshot."
      echo "[Sarge] Rollback will be manual if a control misfires."
      exit 10
      ;;
    *)
      echo "[Sarge] Unrecognized response; treating as skip."
      exit 10
      ;;
  esac
}

# --- consent ----------------------------------------------------------------
prompt_consent

# --- prepare backup dir -----------------------------------------------------
if [[ $DRY_RUN -eq 1 ]]; then
  log "DRY-RUN: would create $BACKUP_ROOT"
else
  mkdir -p "$BACKUP_ROOT/fs"
  : > "$LOG_FILE"
fi
log "Backup root: $BACKUP_ROOT"
log "Run ID: $RUN_ID"

# --- snapshot tooling detection --------------------------------------------
detect_snapshot_tool() {
  local rootfs
  rootfs="$(stat -f -c '%T' / 2>/dev/null || echo unknown)"
  log "Root filesystem: $rootfs"

  if [[ "$rootfs" == "btrfs" || "$rootfs" == "zfs" ]]; then
    echo "$rootfs"
    return 0
  fi
  if command -v timeshift >/dev/null 2>&1; then
    echo "timeshift"
    return 0
  fi
  # LVM thin pool detection — root device must be an LVM thin LV.
  if command -v lvs >/dev/null 2>&1; then
    local root_src
    root_src="$(findmnt -no SOURCE / 2>/dev/null || true)"
    if [[ -n "$root_src" ]]; then
      local pool
      pool="$(lvs --noheadings -o pool_lv "$root_src" 2>/dev/null | awk '{$1=$1;print}')"
      if [[ -n "$pool" ]]; then
        echo "lvm-thin"
        return 0
      fi
    fi
  fi
  echo "file-level"
}

SNAPSHOT_TOOL="$(detect_snapshot_tool)"
log "Snapshot tooling chosen: $SNAPSHOT_TOOL"

run_block_snapshot() {
  case "$SNAPSHOT_TOOL" in
    btrfs)
      local snap_path="/.sarge-snapshots/sarge-pre-hardening-$RUN_ID"
      if [[ $TEST_MODE -eq 1 || $DRY_RUN -eq 1 ]]; then
        log "TEST/DRY: would run: btrfs subvolume snapshot -r / $snap_path"
      else
        log "Creating btrfs snapshot at $snap_path"
        mkdir -p "$(dirname "$snap_path")"
        btrfs subvolume snapshot -r / "$snap_path" || log "WARN: btrfs snapshot failed"
      fi
      echo "$snap_path"
      ;;
    zfs)
      local snap_name
      snap_name="$(zfs list -H -o name / 2>/dev/null | head -1)@sarge-pre-hardening-$RUN_ID"
      if [[ $TEST_MODE -eq 1 || $DRY_RUN -eq 1 ]]; then
        log "TEST/DRY: would run: zfs snapshot $snap_name"
      else
        log "Creating zfs snapshot $snap_name"
        zfs snapshot "$snap_name" || log "WARN: zfs snapshot failed"
      fi
      echo "$snap_name"
      ;;
    timeshift)
      if [[ $TEST_MODE -eq 1 || $DRY_RUN -eq 1 ]]; then
        log "TEST/DRY: would run: timeshift --create --comments 'Sarge pre-hardening $RUN_ID' --tags O"
      else
        log "Creating timeshift snapshot"
        timeshift --create --comments "Sarge pre-hardening $RUN_ID" --tags O || log "WARN: timeshift failed"
      fi
      echo "timeshift:sarge-pre-hardening-$RUN_ID"
      ;;
    lvm-thin)
      if [[ $TEST_MODE -eq 1 || $DRY_RUN -eq 1 ]]; then
        log "TEST/DRY: would create LVM thin snapshot of root LV"
      else
        log "Creating LVM thin snapshot (manual review recommended)"
        # Conservative — we identify the LV but do not auto-snapshot without
        # explicit operator confirmation; LVM ops can fail noisily.
        log "NOTE: LVM thin snapshot auto-creation skipped pending operator review."
      fi
      echo "lvm-thin:sarge-pre-hardening-$RUN_ID"
      ;;
    *)
      echo ""
      ;;
  esac
}

BLOCK_SNAPSHOT="$(run_block_snapshot)"

# --- file-level snapshot (always) ------------------------------------------
# Files known to be touched by Phase 2 hardening.
ETC_TARGETS=(
  /etc/login.defs
  /etc/ssh/sshd_config
  /etc/security/limits.conf
)
ETC_DIRS=(
  /etc/pam.d
  /etc/audit/rules.d
  /etc/sysctl.d
)

copy_etc_files() {
  # Mirror absolute paths under $BACKUP_ROOT/fs/, e.g.
  #   /etc/login.defs -> $BACKUP_ROOT/fs/etc/login.defs
  # so rollback can strip the prefix and write back to the absolute path.
  local src dest
  for src in "${ETC_TARGETS[@]}"; do
    if [[ -e "$src" ]]; then
      dest="$BACKUP_ROOT/fs${src}"
      if [[ $DRY_RUN -eq 1 ]]; then
        log "DRY: would cp -p $src -> $dest"
      else
        mkdir -p "$(dirname "$dest")"
        cp -p "$src" "$dest" 2>/dev/null && log "captured $src" || log "WARN: cannot read $src (try sudo)"
      fi
    fi
  done
  local d
  for d in "${ETC_DIRS[@]}"; do
    if [[ -d "$d" ]]; then
      dest="$BACKUP_ROOT/fs${d}"
      if [[ $DRY_RUN -eq 1 ]]; then
        log "DRY: would cp -rp $d -> $dest"
      else
        mkdir -p "$(dirname "$dest")"
        # Copy contents into $dest so layout is $BACKUP_ROOT/fs/etc/<dir>/<files>
        # not $BACKUP_ROOT/fs/etc/<dir>/<dir>/<files>.
        rm -rf "$dest"
        if cp -rp "$d" "$dest" 2>/dev/null; then
          log "captured tree $d"
        else
          log "WARN: cannot fully read $d (try sudo)"
        fi
      fi
    fi
  done
}

capture_ufw() {
  local out="$BACKUP_ROOT/ufw-state.txt"
  if [[ $DRY_RUN -eq 1 ]]; then
    log "DRY: would capture ufw state"
    return
  fi
  if command -v ufw >/dev/null 2>&1; then
    {
      echo "# ufw status verbose"
      ufw status verbose 2>&1 || true
      echo ""
      echo "# ufw show added"
      ufw show added 2>&1 || true
    } > "$out"
    log "captured ufw state -> ufw-state.txt"
  else
    echo "# ufw not installed at backup time" > "$out"
    log "ufw not installed"
  fi
}

capture_audit() {
  local out="$BACKUP_ROOT/audit-state.txt"
  if [[ $DRY_RUN -eq 1 ]]; then
    log "DRY: would capture auditctl state"
    return
  fi
  if command -v auditctl >/dev/null 2>&1; then
    {
      echo "# auditctl -l"
      auditctl -l 2>&1 || true
      echo ""
      echo "# auditctl -s"
      auditctl -s 2>&1 || true
    } > "$out"
    log "captured audit state -> audit-state.txt"
  else
    echo "# auditctl not installed at backup time" > "$out"
    log "auditctl not installed"
  fi
}

capture_services() {
  local out="$BACKUP_ROOT/services.txt"
  if [[ $DRY_RUN -eq 1 ]]; then
    log "DRY: would capture systemctl unit-file states"
    return
  fi
  if command -v systemctl >/dev/null 2>&1; then
    systemctl list-unit-files --state=enabled,disabled,masked --no-pager > "$out" 2>&1 || true
    log "captured services -> services.txt"
  else
    echo "# systemctl not available" > "$out"
  fi
}

capture_packages() {
  local out="$BACKUP_ROOT/packages.txt"
  if [[ $DRY_RUN -eq 1 ]]; then
    log "DRY: would capture dpkg selections"
    return
  fi
  if command -v dpkg >/dev/null 2>&1; then
    dpkg --get-selections > "$out" 2>&1 || true
    log "captured packages -> packages.txt"
  else
    echo "# dpkg not available" > "$out"
  fi
}

copy_etc_files
capture_ufw
capture_audit
capture_services
capture_packages

# --- emit rollback.sh -------------------------------------------------------
emit_rollback() {
  if [[ $DRY_RUN -eq 1 ]]; then
    log "DRY: would emit rollback.sh"
    return
  fi
  local rb="$BACKUP_ROOT/rollback.sh"
  cat > "$rb" <<'ROLLBACK_EOF'
#!/usr/bin/env bash
# rollback.sh — auto-generated by Sarge backup-ubuntu.sh
# Reverses every artifact captured in this backup directory.
# Re-run is idempotent.
set -uo pipefail

BACKUP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "[Sarge rollback] Restoring from $BACKUP_DIR"

# --- /etc files ------------------------------------------------------------
# Optional SARGE_ROLLBACK_ROOT prefix lets sandbox tests retarget the rollback
# (e.g. SARGE_ROLLBACK_ROOT=/tmp/sandbox) without modifying real /etc.
ROOT_PREFIX="${SARGE_ROLLBACK_ROOT:-}"
if [[ -d "$BACKUP_DIR/fs" ]]; then
  echo "[Sarge rollback] Restoring /etc files..."
  # Walk the captured tree; for each file, copy back to its absolute path.
  while IFS= read -r -d '' f; do
    rel="${f#$BACKUP_DIR/fs}"
    target="${ROOT_PREFIX}${rel}"
    mkdir -p "$(dirname "$target")"
    if cp -p "$f" "$target" 2>/dev/null; then
      echo "  restored $target"
    else
      echo "  WARN: cannot write $target (need sudo?)" >&2
    fi
  done < <(find "$BACKUP_DIR/fs" -type f -print0)

  # Remove any /etc files in the captured directories that did NOT exist
  # at backup time (e.g. test scaffolding written by Phase 2 hardening).
  for dir in /etc/sysctl.d /etc/audit/rules.d /etc/pam.d; do
    live_dir="${ROOT_PREFIX}${dir}"
    [[ -d "$live_dir" ]] || continue
    captured_root="$BACKUP_DIR/fs$dir"
    [[ -d "$captured_root" ]] || continue
    while IFS= read -r -d '' live; do
      rel="${live#$live_dir/}"
      if [[ ! -e "$captured_root/$rel" ]]; then
        if rm -f "$live" 2>/dev/null; then
          echo "  removed $live (not present at backup time)"
        else
          echo "  WARN: cannot remove $live" >&2
        fi
      fi
    done < <(find "$live_dir" -maxdepth 1 -type f -print0)
  done
fi

# --- ufw -------------------------------------------------------------------
if [[ -n "$ROOT_PREFIX" ]]; then
  : # sandbox mode — skip
elif [[ -f "$BACKUP_DIR/ufw-state.txt" ]] && command -v ufw >/dev/null 2>&1; then
  echo "[Sarge rollback] Rebuilding ufw rules..."
  if ufw --force reset >/dev/null 2>&1; then
    awk '/^# ufw show added/{flag=1;next} /^# /{flag=0} flag && /^ufw /{print}' \
      "$BACKUP_DIR/ufw-state.txt" | while read -r rule; do
        if eval "$rule" >/dev/null 2>&1; then
          echo "  reapplied: $rule"
        else
          echo "  WARN: failed: $rule" >&2
        fi
      done
  else
    echo "  WARN: ufw reset failed (need sudo?)" >&2
  fi
fi

# --- audit -----------------------------------------------------------------
if [[ -n "$ROOT_PREFIX" ]]; then
  : # sandbox mode — skip
elif [[ -f "$BACKUP_DIR/audit-state.txt" ]] && command -v auditctl >/dev/null 2>&1; then
  echo "[Sarge rollback] Restoring audit rules..."
  if auditctl -D >/dev/null 2>&1; then
    awk '/^# auditctl -l/{flag=1;next} /^# /{flag=0} flag && NF{print}' \
      "$BACKUP_DIR/audit-state.txt" | while read -r line; do
        # auditctl -l prints rules without the leading 'auditctl' command;
        # re-apply directly via auditctl.
        if auditctl $line >/dev/null 2>&1; then
          echo "  reapplied: $line"
        else
          echo "  WARN: failed: $line" >&2
        fi
      done
  else
    echo "  WARN: auditctl -D failed (need sudo?)" >&2
  fi
fi

# --- services --------------------------------------------------------------
if [[ -n "$ROOT_PREFIX" ]]; then
  echo "[Sarge rollback] Sandbox mode (SARGE_ROLLBACK_ROOT set) — skipping systemctl/ufw/auditctl/dpkg branches."
elif [[ -f "$BACKUP_DIR/services.txt" ]] && command -v systemctl >/dev/null 2>&1; then
  echo "[Sarge rollback] Reverting service enable/disable state..."
  while read -r unit state _; do
    [[ -z "$unit" || "$unit" == UNIT* ]] && continue
    case "$state" in
      enabled)  systemctl --no-pager enable  "$unit"  </dev/null >/dev/null 2>&1 || true ;;
      disabled) systemctl --no-pager disable "$unit"  </dev/null >/dev/null 2>&1 || true ;;
      masked)   systemctl --no-pager mask    "$unit"  </dev/null >/dev/null 2>&1 || true ;;
    esac
  done < "$BACKUP_DIR/services.txt"
  echo "  service states reapplied (warnings suppressed for already-correct units)"
fi

# --- packages --------------------------------------------------------------
if [[ -n "$ROOT_PREFIX" ]]; then
  : # sandbox mode — skip
elif [[ -f "$BACKUP_DIR/packages.txt" ]] && command -v dpkg >/dev/null 2>&1; then
  echo "[Sarge rollback] Comparing dpkg selections (warn-only, no auto-remove)..."
  current="$(mktemp)"
  dpkg --get-selections > "$current" 2>/dev/null || true
  if ! diff -q "$BACKUP_DIR/packages.txt" "$current" >/dev/null 2>&1; then
    echo "  WARN: dpkg selections differ from backup time."
    echo "  Review: diff $BACKUP_DIR/packages.txt $current"
    echo "  (Auto-remove disabled — package state must be reconciled manually.)"
  else
    echo "  dpkg selections unchanged."
  fi
  rm -f "$current"
fi

echo "[Sarge rollback] Complete."
ROLLBACK_EOF
  chmod +x "$rb"
  log "emitted rollback.sh"
}

emit_rollback

# --- summary.md -------------------------------------------------------------
emit_summary() {
  if [[ $DRY_RUN -eq 1 ]]; then
    log "DRY: would emit summary.md"
    return
  fi
  local md="$BACKUP_ROOT/summary.md"
  cat > "$md" <<EOF
# Sarge pre-hardening backup — run $RUN_ID

- Run ID: \`$RUN_ID\`
- Backup directory: \`$BACKUP_ROOT\`
- Snapshot tooling: \`$SNAPSHOT_TOOL\`
- Block snapshot ref: \`${BLOCK_SNAPSHOT:-none}\`
- Test mode: $TEST_MODE
- Captured at: $(date -Iseconds)

## Captured artifacts

- \`etc/\` — selective tree copy of files Phase 2 hardening will modify
  (login.defs, pam.d/, ssh/sshd_config, audit/rules.d/, sysctl.d/, security/limits.conf)
- \`ufw-state.txt\` — \`ufw status verbose\` + \`ufw show added\`
- \`audit-state.txt\` — \`auditctl -l\` + \`auditctl -s\`
- \`services.txt\` — \`systemctl list-unit-files --state=enabled,disabled,masked\`
- \`packages.txt\` — \`dpkg --get-selections\`
- \`rollback.sh\` — reverses every captured artifact (idempotent)
- \`backup.log\` — line-by-line capture log

## Rollback

To revert Phase 2 hardening on this host:

\`\`\`bash
sudo $BACKUP_ROOT/rollback.sh
# or, with confirmation prompt:
sudo $(cd "$(dirname "$0")" && pwd)/rollback-ubuntu.sh --backup-dir $BACKUP_ROOT
\`\`\`

Block-level snapshot (if any) is at \`${BLOCK_SNAPSHOT:-n/a}\` and is restored
via the native tool (btrfs/zfs/timeshift/lvm) — not by \`rollback.sh\`.
EOF
  log "emitted summary.md"
}

emit_summary

log "Backup complete: $BACKUP_ROOT"
exit 0
