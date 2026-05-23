#!/usr/bin/env bash
# backup-macos.sh — Sarge pre-hardening backup (macOS)
# NIST 800-53 CP-9 / CP-10 | Oscar Six Security LLC
#
# UNTESTED ON REAL macOS HARDWARE: Oscar Six does not have a Mac test
# surface available. This script follows the spec in issue #30 and the
# Ubuntu/Windows backup-script patterns, but has not been exercised
# against `tmutil`, `pfctl`, `socketfilterfw`, `defaults`, `csrutil`,
# `spctl`, or `fdesetup` on a live macOS host. The `bash -n` syntax
# check and the dry-run smoke test in tests/integration/ are the only
# validation performed. Community validation contributions welcome —
# see README.md "Pre-hardening backup + rollback (macOS)".
#
# Per-run folder pattern matches PR #42 (issue #34):
#   ~/.sarge/runs/<run_id>/backup/
#
# Heavy-lift backstop is an APFS local snapshot (tmutil localsnapshot),
# reversible via `tmutil restore <snapshot>`. File-level rollback.sh is
# emitted alongside for granular reverts.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# -----------------------------------------------------------------------------
# Platform guard — macOS only. Lets the dry-run smoke test on Linux exit
# cleanly with a clear message.
# -----------------------------------------------------------------------------
UNAME_S="$(uname -s 2>/dev/null || echo unknown)"
DRY_RUN="${SARGE_BACKUP_DRY_RUN:-0}"

if [[ "$UNAME_S" != "Darwin" && "$DRY_RUN" != "1" ]]; then
  echo "[Sarge] backup-macos.sh: macOS only (detected: ${UNAME_S})." >&2
  echo "[Sarge] Set SARGE_BACKUP_DRY_RUN=1 to exercise the dry-run path on non-Darwin." >&2
  exit 2
fi

# -----------------------------------------------------------------------------
# Argument parsing
# -----------------------------------------------------------------------------
UNATTENDED=0
RUN_ID=""
INCLUDE_TIME_MACHINE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --unattended)        UNATTENDED=1; shift ;;
    --run-id)            RUN_ID="${2:-}"; shift 2 ;;
    --run-id=*)          RUN_ID="${1#*=}"; shift ;;
    --time-machine)      INCLUDE_TIME_MACHINE=1; shift ;;
    -h|--help)
      cat <<EOF
Usage: backup-macos.sh [options]

Options:
  --unattended         Skip interactive prompts (assume APFS snapshot, no TM)
  --run-id <id>        Reuse a run ID established by assess.sh
  --time-machine       Also trigger a Time Machine snapshot (slower)
  -h, --help           This message

Environment:
  SARGE_BACKUP_DRY_RUN=1   Stub all macOS-only commands via PATH; do not
                           execute snapshots. Used by tests/integration/.
EOF
      exit 0
      ;;
    *)
      echo "[Sarge] backup-macos.sh: unknown arg '$1'" >&2
      exit 2
      ;;
  esac
done

TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
RUN_ID="${RUN_ID:-${SARGE_RUN_ID:-$TIMESTAMP}}"
SARGE_RUN_ROOT="${SARGE_RUN_ROOT:-$HOME/.sarge/runs/$RUN_ID}"
BACKUP_DIR="$SARGE_RUN_ROOT/backup"
mkdir -p "$BACKUP_DIR"

log() { echo "[Sarge][backup-macos] $*"; }
warn() { echo "[Sarge][backup-macos][WARN] $*" >&2; }
die()  { echo "[Sarge][backup-macos][FATAL] $*" >&2; exit 1; }

log "Run ID:      $RUN_ID"
log "Backup dir:  $BACKUP_DIR"
log "Dry run:     $DRY_RUN"

# -----------------------------------------------------------------------------
# Interactive consent (skipped under --unattended)
# -----------------------------------------------------------------------------
if [[ "$UNATTENDED" != "1" && "$DRY_RUN" != "1" ]]; then
  read -r -p "[Sarge] Take APFS local snapshot + capture mutable state before hardening? [Y/n] " ans
  case "${ans:-Y}" in
    Y|y|"") ;;
    *) die "User declined backup. Refusing to proceed (hardening blocked until --unattended or consent)." ;;
  esac
fi

# -----------------------------------------------------------------------------
# 1. APFS local snapshot — fail loudly if boot volume isn't APFS.
# -----------------------------------------------------------------------------
APFS_SNAPSHOT_ID=""
APFS_SNAPSHOT_STATUS="not-attempted"

apfs_check_boot_volume() {
  # Boot volume must be APFS for `tmutil localsnapshot` to work.
  # `diskutil info /` reports the file system personality.
  local fs
  if ! fs="$(diskutil info / 2>/dev/null | awk -F: '/File System Personality/ {gsub(/^ +| +$/,"",$2); print $2; exit}')"; then
    return 1
  fi
  [[ "$fs" == *APFS* ]]
}

take_apfs_snapshot() {
  log "Requesting APFS local snapshot via tmutil localsnapshot ..."
  local out
  if ! out="$(tmutil localsnapshot 2>&1)"; then
    APFS_SNAPSHOT_STATUS="failed"
    warn "tmutil localsnapshot failed: $out"
    return 1
  fi
  # tmutil emits a line like:
  #   Created local snapshot with date: 2026-05-23-120000
  APFS_SNAPSHOT_ID="$(printf '%s\n' "$out" | awk '/Created local snapshot/ {print $NF; exit}')"
  APFS_SNAPSHOT_STATUS="created"
  printf '%s\n' "$out" > "$BACKUP_DIR/apfs-snapshot.txt"
  log "APFS snapshot created: ${APFS_SNAPSHOT_ID:-unknown-id}"
}

if [[ "$DRY_RUN" == "1" ]]; then
  log "[DRY-RUN] Would run: diskutil info / | grep 'File System Personality'"
  log "[DRY-RUN] Would run: tmutil localsnapshot"
  APFS_SNAPSHOT_ID="dry-run-snapshot"
  APFS_SNAPSHOT_STATUS="dry-run"
  echo "DRY-RUN: tmutil localsnapshot would have been invoked" > "$BACKUP_DIR/apfs-snapshot.txt"
else
  if ! apfs_check_boot_volume; then
    die "Boot volume is not APFS — refusing to proceed. Pre-hardening backup requires APFS local snapshots."
  fi
  if ! take_apfs_snapshot; then
    die "APFS local snapshot failed. Local snapshots may be disabled. Aborting — see https://support.apple.com/HT204015"
  fi
fi

# -----------------------------------------------------------------------------
# 2. Optional Time Machine snapshot
# -----------------------------------------------------------------------------
TM_STATUS="skipped"
if [[ "$INCLUDE_TIME_MACHINE" == "1" ]]; then
  if [[ "$DRY_RUN" == "1" ]]; then
    log "[DRY-RUN] Would run: tmutil startbackup --block"
    TM_STATUS="dry-run"
    echo "DRY-RUN: tmutil startbackup --block would have been invoked" > "$BACKUP_DIR/time-machine.txt"
  else
    log "Triggering Time Machine snapshot (this may be slow)..."
    if tmutil startbackup --block > "$BACKUP_DIR/time-machine.txt" 2>&1; then
      TM_STATUS="completed"
    else
      TM_STATUS="failed"
      warn "Time Machine snapshot failed — APFS local snapshot still covers rollback."
    fi
  fi
fi

# -----------------------------------------------------------------------------
# 3. File-level snapshots (run regardless of volume-snapshot success)
# -----------------------------------------------------------------------------
ETC_BACKUP="$BACKUP_DIR/etc"
mkdir -p "$ETC_BACKUP"

copy_etc() {
  local src="$1"
  local dst_rel="${src#/}"
  local dst="$ETC_BACKUP/$dst_rel"
  if [[ "$DRY_RUN" == "1" ]]; then
    log "[DRY-RUN] Would copy $src -> $dst"
    mkdir -p "$(dirname "$dst")"
    : > "$dst"
    return 0
  fi
  if [[ ! -e "$src" ]]; then
    warn "Source not present, skipping: $src"
    return 0
  fi
  mkdir -p "$(dirname "$dst")"
  # -p preserves perms; -R for dirs; -a preserves more but isn't portable
  cp -Rp "$src" "$dst" || warn "cp failed for $src"
}

log "Capturing /etc files ..."
copy_etc "/etc/pam.d"
copy_etc "/etc/ssh/sshd_config"
copy_etc "/etc/sudoers.d"

# audit_* glob — expand carefully
if [[ "$DRY_RUN" == "1" ]]; then
  log "[DRY-RUN] Would copy /etc/security/audit_* -> $ETC_BACKUP/etc/security/"
  mkdir -p "$ETC_BACKUP/etc/security"
  : > "$ETC_BACKUP/etc/security/audit_control"
else
  mkdir -p "$ETC_BACKUP/etc/security"
  shopt -s nullglob
  for f in /etc/security/audit_*; do
    cp -Rp "$f" "$ETC_BACKUP/etc/security/" 2>/dev/null || warn "cp failed for $f"
  done
  shopt -u nullglob
fi

# socketfilterfw — application-layer firewall
log "Capturing socketfilterfw state ..."
if [[ "$DRY_RUN" == "1" ]]; then
  log "[DRY-RUN] Would run: /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate"
  echo "DRY-RUN socketfilterfw" > "$BACKUP_DIR/socketfilterfw.txt"
else
  {
    echo "### /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate"
    /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>&1 || true
    echo
    echo "### --getblockall"
    /usr/libexec/ApplicationFirewall/socketfilterfw --getblockall 2>&1 || true
    echo
    echo "### --getallowsigned"
    /usr/libexec/ApplicationFirewall/socketfilterfw --getallowsigned 2>&1 || true
    echo
    echo "### --listapps"
    /usr/libexec/ApplicationFirewall/socketfilterfw --listapps 2>&1 || true
  } > "$BACKUP_DIR/socketfilterfw.txt"
fi

# pfctl — packet filter
log "Capturing pf state ..."
if [[ "$DRY_RUN" == "1" ]]; then
  log "[DRY-RUN] Would run: pfctl -sa"
  echo "DRY-RUN pfctl -sa" > "$BACKUP_DIR/pf-state.txt"
else
  sudo -n pfctl -sa > "$BACKUP_DIR/pf-state.txt" 2>&1 || \
    pfctl -sa > "$BACKUP_DIR/pf-state.txt" 2>&1 || \
    warn "pfctl -sa failed (may need sudo). State partial."
fi

# launchctl
log "Capturing launchctl service inventory ..."
if [[ "$DRY_RUN" == "1" ]]; then
  log "[DRY-RUN] Would run: launchctl list"
  echo "DRY-RUN launchctl list" > "$BACKUP_DIR/launchctl.txt"
else
  launchctl list > "$BACKUP_DIR/launchctl.txt" 2>&1 || warn "launchctl list failed."
fi

# defaults read — touched domains (Phase 2 has not enumerated final set;
# this is the starting list per issue #30).
DEFAULTS_DOMAINS=(
  "com.apple.loginwindow"
  "com.apple.screensaver"
  "com.apple.security"
  "/Library/Preferences/com.apple.alf"
)

log "Capturing defaults for ${#DEFAULTS_DOMAINS[@]} domains ..."
for domain in "${DEFAULTS_DOMAINS[@]}"; do
  # Use a slug derived from the domain for the filename
  slug="$(printf '%s' "$domain" | tr '/' '_' | tr ' ' '_')"
  out="$BACKUP_DIR/defaults-${slug}.txt"
  if [[ "$DRY_RUN" == "1" ]]; then
    log "[DRY-RUN] Would run: defaults read $domain"
    echo "DRY-RUN defaults read $domain" > "$out"
  else
    defaults read "$domain" > "$out" 2>&1 || warn "defaults read failed for $domain"
  fi
done

# Security posture probes
log "Capturing security posture (csrutil/spctl/fdesetup) ..."
if [[ "$DRY_RUN" == "1" ]]; then
  log "[DRY-RUN] Would run: csrutil status; spctl --status; fdesetup status"
  cat > "$BACKUP_DIR/security-status.txt" <<EOF
DRY-RUN csrutil status
DRY-RUN spctl --status
DRY-RUN fdesetup status
EOF
else
  {
    echo "### csrutil status"
    csrutil status 2>&1 || true
    echo
    echo "### spctl --status"
    spctl --status 2>&1 || true
    echo
    echo "### fdesetup status"
    fdesetup status 2>&1 || true
  } > "$BACKUP_DIR/security-status.txt"
fi

# -----------------------------------------------------------------------------
# 4. Emit rollback.sh
# -----------------------------------------------------------------------------
ROLLBACK_SH="$BACKUP_DIR/rollback.sh"
cat > "$ROLLBACK_SH" <<ROLLBACK
#!/usr/bin/env bash
# rollback.sh — Sarge pre-hardening rollback (macOS)
# Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Run ID:    $RUN_ID
#
# This script reverses each granular artifact captured under:
#   $BACKUP_DIR
#
# The heavy-lift backstop is the APFS local snapshot — if granular
# rollback fails or the system is in a worse state than expected, you
# can restore the whole boot volume with:
#
#     tmutil restore $APFS_SNAPSHOT_ID
#
# (See: man tmutil — restore. Reboot to the macOS Recovery environment
# if a live restore can't proceed.)
#
# UNTESTED ON REAL macOS HARDWARE — verify before relying on in
# production. See https://github.com/oscarsixsecllc/sarge/issues/30.

set -uo pipefail

if [[ "\$(uname -s)" != "Darwin" ]]; then
  echo "[Sarge] rollback.sh: macOS only." >&2
  exit 2
fi

BACKUP_DIR="\${BACKUP_DIR:-$BACKUP_DIR}"
ETC_BACKUP="\$BACKUP_DIR/etc"

echo "[Sarge] rollback.sh: restoring from \$BACKUP_DIR"

# --- 1. /etc files ---
if [[ -d "\$ETC_BACKUP/etc" ]]; then
  echo "[Sarge] Restoring /etc files (requires sudo)..."
  # Walk the saved tree and cp -Rp back into place.
  (cd "\$ETC_BACKUP" && find etc -mindepth 1 -maxdepth 1 -print0) | while IFS= read -r -d '' entry; do
    sudo cp -Rp "\$ETC_BACKUP/\$entry" "/\$entry" || echo "[Sarge][WARN] cp back failed for /\$entry"
  done
fi

# --- 2. pf rules ---
if [[ -s "\$BACKUP_DIR/pf-state.txt" ]]; then
  echo "[Sarge] Re-applying pf rules (best-effort)..."
  # pfctl -sa output is human-readable, not directly loadable. We restore
  # the saved anchors/rules conservatively: if the captured output contains
  # a rules section, pipe it back through pfctl -f -. If no parseable rules
  # are present, fall back to disabling any new anchors Sarge added.
  if grep -q "^scrub\|^block\|^pass" "\$BACKUP_DIR/pf-state.txt" 2>/dev/null; then
    # Extract a rules-only view; this is best-effort because pfctl -sa
    # interleaves multiple sections. Real restore should use a snapshot of
    # pfctl -sr captured BEFORE the hardening change — Phase 2 should
    # supplement this script with that finer-grained capture.
    sudo pfctl -f "\$BACKUP_DIR/pf-state.txt" 2>/dev/null || \
      echo "[Sarge][WARN] pfctl -f failed; consider 'tmutil restore $APFS_SNAPSHOT_ID' for a clean rollback."
  fi
fi

# --- 3. socketfilterfw rules ---
if [[ -s "\$BACKUP_DIR/socketfilterfw.txt" ]]; then
  echo "[Sarge] Re-applying socketfilterfw global state (best-effort)..."
  # socketfilterfw has no native bulk-import; replay flags from the saved
  # globalstate. Per-app rules in --listapps need to be re-added with
  # --add <path>; this is best-effort per the captured output.
  if grep -q "Firewall is enabled" "\$BACKUP_DIR/socketfilterfw.txt" 2>/dev/null; then
    sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on 2>/dev/null || true
  fi
fi

# --- 4. defaults import ---
for f in "\$BACKUP_DIR"/defaults-*.txt; do
  [[ -e "\$f" ]] || continue
  # defaults read produces a plist-style dump — not directly importable.
  # Phase 2 should switch the capture step to 'defaults export <domain> <file>.plist'
  # so this loop can do 'defaults import'. For now, emit a manual-review note.
  echo "[Sarge] Defaults capture in \$f — manual review required (capture format is 'defaults read', not 'defaults export')."
done

# --- 5. launchctl service-state delta ---
if [[ -s "\$BACKUP_DIR/launchctl.txt" ]]; then
  echo "[Sarge] launchctl: comparing captured services to current state..."
  current="\$(mktemp)"
  launchctl list > "\$current" 2>/dev/null || true
  # Services present at backup but not now -> load
  # Services not at backup but now -> unload
  # (Best-effort; some labels require a plist path or domain target.)
  awk 'NR>1 {print \$3}' "\$BACKUP_DIR/launchctl.txt" | sort -u > "\${current}.before"
  awk 'NR>1 {print \$3}' "\$current" | sort -u > "\${current}.after"
  comm -23 "\${current}.before" "\${current}.after" | while read -r label; do
    [[ -n "\$label" ]] || continue
    sudo launchctl load -w "/Library/LaunchDaemons/\${label}.plist" 2>/dev/null || \
      launchctl load -w "\$HOME/Library/LaunchAgents/\${label}.plist" 2>/dev/null || true
  done
  comm -13 "\${current}.before" "\${current}.after" | while read -r label; do
    [[ -n "\$label" ]] || continue
    sudo launchctl unload -w "/Library/LaunchDaemons/\${label}.plist" 2>/dev/null || \
      launchctl unload -w "\$HOME/Library/LaunchAgents/\${label}.plist" 2>/dev/null || true
  done
  rm -f "\$current" "\${current}.before" "\${current}.after"
fi

echo "[Sarge] rollback.sh complete. If state is still wrong, run:"
echo "    tmutil restore $APFS_SNAPSHOT_ID"
ROLLBACK
chmod +x "$ROLLBACK_SH"

# -----------------------------------------------------------------------------
# 5. Emit summary.md
# -----------------------------------------------------------------------------
cat > "$BACKUP_DIR/summary.md" <<EOF
# Sarge pre-hardening backup — macOS

- **Run ID:** \`$RUN_ID\`
- **Backup dir:** \`$BACKUP_DIR\`
- **Captured at:** $(date -u +%Y-%m-%dT%H:%M:%SZ)
- **APFS snapshot:** \`${APFS_SNAPSHOT_ID:-none}\` (status: $APFS_SNAPSHOT_STATUS)
- **Time Machine:** $TM_STATUS
- **Dry run:** $DRY_RUN

## What was captured

| Artifact | Path |
| --- | --- |
| APFS snapshot ID | \`apfs-snapshot.txt\` |
| /etc tree (pam.d, sshd_config, sudoers.d, audit_*) | \`etc/\` |
| socketfilterfw state | \`socketfilterfw.txt\` |
| pf state (pfctl -sa) | \`pf-state.txt\` |
| launchctl inventory | \`launchctl.txt\` |
| defaults domains | \`defaults-*.txt\` |
| Security posture (csrutil/spctl/fdesetup) | \`security-status.txt\` |

## How to roll back

Granular (file-level) rollback:

\`\`\`bash
bash "$BACKUP_DIR/rollback.sh"
\`\`\`

Heavy-lift backstop (whole boot volume):

\`\`\`bash
tmutil restore ${APFS_SNAPSHOT_ID:-<snapshot-id>}
\`\`\`

> **Untested on real macOS hardware.** See README "Pre-hardening backup + rollback (macOS)" and issue #30.
EOF

log "Backup complete."
log "  APFS snapshot: ${APFS_SNAPSHOT_ID:-none} ($APFS_SNAPSHOT_STATUS)"
log "  Rollback:      $ROLLBACK_SH"
log "  Summary:       $BACKUP_DIR/summary.md"

# Emit machine-readable status line for assess.sh wiring
echo "SARGE_BACKUP_OK run_id=$RUN_ID dir=$BACKUP_DIR apfs=${APFS_SNAPSHOT_ID:-none}"
