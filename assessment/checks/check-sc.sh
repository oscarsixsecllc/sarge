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
  #
  # Live OpenClaw 2026.7.x writes runtime config to `openclaw.json`. Older
  # installs (pre-2026.4) used `config.json`. Probe the current filename
  # first, then fall back to the legacy name so long-lived hosts don't get
  # a spurious SKIP. See issue #61.
  log "SC-28: Protection of information at rest"
  OC_CONFIG=""
  for candidate in "$HOME/.openclaw/openclaw.json" "$HOME/.openclaw/config.json"; do
    if [[ -f "$candidate" ]]; then
      OC_CONFIG="$candidate"
      break
    fi
  done
  if [[ -n "$OC_CONFIG" ]]; then
    CONFIG_NAME=$(basename "$OC_CONFIG")
    CONFIG_PERM=$(platform file_perm "$OC_CONFIG")
    CONFIG_OWNER=$(platform file_owner "$OC_CONFIG")
    if [[ "$CONFIG_PERM" == "600" || "$CONFIG_PERM" == "400" ]]; then
      passx "SC-28-config-perm" "SC-28: OpenClaw $CONFIG_NAME is $CONFIG_PERM (restricted)"
    else
      failx "SC-28-config-perm" "SC-28: OpenClaw $CONFIG_NAME is $CONFIG_PERM — should be 600"
    fi
    CURRENT_USER=$(whoami)
    if [[ "$CONFIG_OWNER" == "$CURRENT_USER" ]]; then
      passx "SC-28-config-owner" "SC-28: $CONFIG_NAME owned by current service user ($CURRENT_USER)"
    else
      warnx "SC-28-config-owner" "SC-28: $CONFIG_NAME owned by $CONFIG_OWNER — expected $CURRENT_USER"
    fi
  else
    skipx "SC-28-config-perm" "SC-28: OpenClaw config not found at ~/.openclaw/openclaw.json (or legacy ~/.openclaw/config.json)"
  fi

  # SC-28: Check for world-readable sensitive files
  #
  # Scope is intentionally narrow: only files under known-sensitive paths
  # (secrets/, credentials/, auth/), the live + legacy config, config
  # backups, and files that look like credential material by name (*.key,
  # *.pem, *.env, *-token*, *-secret*). A broad `find ~/.openclaw -perm
  # /004` catches intentionally-readable workspace canon (SOUL.md,
  # HEARTBEAT.md, AGENTS.md, USER.md, TOOLS.md, BOOTSTRAP.md) and
  # workspace/.git/* — none of which contain secrets — and drowns the
  # real signal in noise. See issue #64.
  log "SC-28: World-readable sensitive files"
  OC_DIR="$HOME/.openclaw"
  if [[ -d "$OC_DIR" ]]; then
    WORLD_READABLE=$(platform world_readable_sensitive_files_in "$OC_DIR")
    if [[ -z "$WORLD_READABLE" ]]; then
      passx "SC-28-world-readable-secrets" "SC-28: No world-readable sensitive files in ~/.openclaw"
    else
      failx "SC-28-world-readable-secrets" "SC-28: World-readable sensitive files found in ~/.openclaw: $(echo "$WORLD_READABLE" | tr '\n' ' ')"
    fi
  fi
fi
