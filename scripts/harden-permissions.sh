#!/usr/bin/env bash
# harden-permissions.sh — File/Directory Permissions — NIST 800-53 AC-3, SC-28
set -euo pipefail

echo "[Sarge] Permissions Hardening — AC-3/SC-28"
read -r -p "Apply OpenClaw file permission hardening? [y/N] " confirm
[[ "$confirm" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }

OC_DIR="$HOME/.openclaw"
if [[ -d "$OC_DIR" ]]; then
  chmod 700 "$OC_DIR"
  echo "  Set $OC_DIR → 700"
  mkdir -p "$OC_DIR/secrets" && chmod 700 "$OC_DIR/secrets" && echo "  Set $OC_DIR/secrets → 700"
  find "$OC_DIR/secrets" -type f -exec chmod 600 {} \; 2>/dev/null && echo "  Set secret files → 600"
  [[ -f "$OC_DIR/config.json" ]] && chmod 600 "$OC_DIR/config.json" && echo "  Set config.json → 600"
fi
echo "[Sarge] Permissions hardening applied."
