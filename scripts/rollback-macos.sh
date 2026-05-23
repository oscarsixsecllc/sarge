#!/usr/bin/env bash
# rollback-macos.sh — Sarge rollback wrapper (macOS)
# Locates the generated per-run rollback.sh and exec's it. Mirrors the
# Ubuntu wrapper pattern so callers don't need to know the per-run
# folder layout.
#
# UNTESTED ON REAL macOS HARDWARE — see scripts/backup-macos.sh and
# README.md "Pre-hardening backup + rollback (macOS)".

set -uo pipefail

UNAME_S="$(uname -s 2>/dev/null || echo unknown)"
DRY_RUN="${SARGE_BACKUP_DRY_RUN:-0}"

if [[ "$UNAME_S" != "Darwin" && "$DRY_RUN" != "1" ]]; then
  echo "[Sarge] rollback-macos.sh: macOS only (detected: ${UNAME_S})." >&2
  exit 2
fi

usage() {
  cat <<EOF
Usage: rollback-macos.sh [--run-id <id>] [--latest]

Options:
  --run-id <id>    Roll back the named run under ~/.sarge/runs/<id>/backup/
  --latest         Roll back the most recent run found in ~/.sarge/runs/
  -h, --help       This message

Without args, --latest is assumed.
EOF
}

RUN_ID=""
PICK_LATEST=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-id)   RUN_ID="${2:-}"; PICK_LATEST=0; shift 2 ;;
    --run-id=*) RUN_ID="${1#*=}"; PICK_LATEST=0; shift ;;
    --latest)   PICK_LATEST=1; shift ;;
    -h|--help)  usage; exit 0 ;;
    *) echo "[Sarge] rollback-macos.sh: unknown arg '$1'" >&2; usage; exit 2 ;;
  esac
done

RUNS_ROOT="${SARGE_RUNS_ROOT:-$HOME/.sarge/runs}"

if [[ "$PICK_LATEST" == "1" ]]; then
  if [[ ! -d "$RUNS_ROOT" ]]; then
    echo "[Sarge] No runs found under $RUNS_ROOT" >&2
    exit 1
  fi
  RUN_ID="$(ls -1t "$RUNS_ROOT" 2>/dev/null | head -n1)"
  if [[ -z "$RUN_ID" ]]; then
    echo "[Sarge] No runs found under $RUNS_ROOT" >&2
    exit 1
  fi
fi

ROLLBACK_SH="$RUNS_ROOT/$RUN_ID/backup/rollback.sh"
if [[ ! -x "$ROLLBACK_SH" ]]; then
  echo "[Sarge] rollback.sh not found or not executable: $ROLLBACK_SH" >&2
  echo "[Sarge] Heavy-lift fallback: 'tmutil listlocalsnapshots /' then 'tmutil restore <id>'" >&2
  exit 1
fi

echo "[Sarge] Executing $ROLLBACK_SH"
exec bash "$ROLLBACK_SH"
