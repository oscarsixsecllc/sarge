#!/usr/bin/env bash
# check-sc.sh — System & Communications Protection (SC) — partial — NIST 800-53 Rev 5
# Platform-specific data acquisition lives in lib/platforms/<os>.sh.

# SC-8: Transmission Confidentiality — check for TLS on gateway port
log "SC-8: Transmission confidentiality"
GW_PORT="${OPENCLAW_GATEWAY_PORT:-18790}"
if platform port_listening "$GW_PORT"; then
  pass "SC-8: OpenClaw gateway is listening on port $GW_PORT"
  # Check if Cloudflare tunnel is the access path (preferred over direct TLS)
  if pgrep -x "cloudflared" &>/dev/null; then
    pass "SC-8: cloudflared is running — Cloudflare Tunnel provides TLS termination"
  else
    warn "SC-8: cloudflared not detected — verify TLS is configured on gateway directly"
  fi
else
  skip "SC-8: OpenClaw gateway port $GW_PORT not detected — may be using different port"
fi

# SC-28: Protection at rest — OpenClaw config permissions
log "SC-28: Protection of information at rest"
OC_CONFIG="$HOME/.openclaw/config.json"
if [[ -f "$OC_CONFIG" ]]; then
  CONFIG_PERM=$(platform file_perm "$OC_CONFIG")
  CONFIG_OWNER=$(platform file_owner "$OC_CONFIG")
  if [[ "$CONFIG_PERM" == "600" || "$CONFIG_PERM" == "400" ]]; then
    pass "SC-28: OpenClaw config.json is $CONFIG_PERM (restricted)"
  else
    fail "SC-28: OpenClaw config.json is $CONFIG_PERM — should be 600"
  fi
  CURRENT_USER=$(whoami)
  if [[ "$CONFIG_OWNER" == "$CURRENT_USER" ]]; then
    pass "SC-28: config.json owned by current service user ($CURRENT_USER)"
  else
    warn "SC-28: config.json owned by $CONFIG_OWNER — expected $CURRENT_USER"
  fi
else
  skip "SC-28: OpenClaw config.json not found at $OC_CONFIG"
fi

# SC-28: Check for world-readable sensitive files
log "SC-28: World-readable sensitive files"
OC_DIR="$HOME/.openclaw"
if [[ -d "$OC_DIR" ]]; then
  WORLD_READABLE=$(platform world_readable_files_in "$OC_DIR")
  if [[ -z "$WORLD_READABLE" ]]; then
    pass "SC-28: No world-readable files in ~/.openclaw"
  else
    fail "SC-28: World-readable files found in ~/.openclaw: $(echo "$WORLD_READABLE" | tr '\n' ' ')"
  fi
fi
