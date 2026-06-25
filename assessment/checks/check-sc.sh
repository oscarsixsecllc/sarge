#!/usr/bin/env bash
# check-sc.sh — System & Communications Protection (SC) — partial — NIST 800-53 Rev 5
# Platform-specific data acquisition lives in lib/platforms/<os>.sh.

if [[ "${SARGE_HOST_ONLY:-0}" != "1" ]]; then
  # SC-8: Transmission Confidentiality — check for TLS on gateway port
  log "SC-8: Transmission confidentiality"
  GW_PORT="${OPENCLAW_GATEWAY_PORT:-18790}"
  if platform port_listening "$GW_PORT"; then
    passx "SC-8-cloudflared-not-detected" "SC-8: OpenClaw gateway is listening on port $GW_PORT"
    if pgrep -x "cloudflared" &>/dev/null; then
      passx "SC-8-cloudflared-not-detected" "SC-8: cloudflared is running — Cloudflare Tunnel provides TLS termination"
    else
      warnx "SC-8-cloudflared-not-detected" "SC-8: cloudflared not detected — verify TLS is configured on gateway directly"
    fi
  else
    skipx "SC-8-cloudflared-not-detected" "SC-8: OpenClaw gateway port $GW_PORT not detected — may be using different port"
  fi

  # SC-28: Protection at rest — OpenClaw config permissions
  log "SC-28: Protection of information at rest"
  OC_CONFIG="$HOME/.openclaw/config.json"
  if [[ -f "$OC_CONFIG" ]]; then
    CONFIG_PERM=$(platform file_perm "$OC_CONFIG")
    CONFIG_OWNER=$(platform file_owner "$OC_CONFIG")
    if [[ "$CONFIG_PERM" == "600" || "$CONFIG_PERM" == "400" ]]; then
      passx "SC-28-config-perm" "SC-28: OpenClaw config.json is $CONFIG_PERM (restricted)"
    else
      failx "SC-28-config-perm" "SC-28: OpenClaw config.json is $CONFIG_PERM — should be 600"
    fi
    CURRENT_USER=$(whoami)
    if [[ "$CONFIG_OWNER" == "$CURRENT_USER" ]]; then
      passx "SC-28-config-owner" "SC-28: config.json owned by current service user ($CURRENT_USER)"
    else
      warnx "SC-28-config-owner" "SC-28: config.json owned by $CONFIG_OWNER — expected $CURRENT_USER"
    fi
  else
    skipx "SC-28-config-perm" "SC-28: OpenClaw config.json not found at $OC_CONFIG"
  fi

  # SC-28: Check for world-readable sensitive files
  log "SC-28: World-readable sensitive files"
  OC_DIR="$HOME/.openclaw"
  if [[ -d "$OC_DIR" ]]; then
    WORLD_READABLE=$(platform world_readable_files_in "$OC_DIR")
    if [[ -z "$WORLD_READABLE" ]]; then
      passx "SC-28-world-readable-secrets" "SC-28: No world-readable files in ~/.openclaw"
    else
      failx "SC-28-world-readable-secrets" "SC-28: World-readable files found in ~/.openclaw: $(echo "$WORLD_READABLE" | tr '\n' ' ')"
    fi
  fi
fi
