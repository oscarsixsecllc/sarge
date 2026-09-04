#!/usr/bin/env bash
# check-mp.sh — Media Protection (MP) checks — NIST 800-53 Rev 5
# Platform-specific data acquisition lives in lib/platforms/<os>.sh.

# MP-6: Media Sanitization
#
# OpenClaw's `media.ttlHours` governs how long generated/received media
# (images, audio, video, downloads) sits on disk before cleanup. Without
# a TTL, media accumulates indefinitely — the agent-equivalent of media
# that's never sanitized. `media.maxSizeMb` is a secondary indicator:
# even with a TTL configured, an unbounded max size means a burst of
# large media can sit at rest for the full TTL window.
log "MP-6: Media sanitization (retention TTL)"

# Live OpenClaw 2026.7.x writes runtime config to `openclaw.json`. Older
# installs (pre-2026.4) used `config.json`. Same fallback probe used by
# check-sc.sh / check-ia.sh (issue #61).
MP_OC_CONFIG=""
for candidate in "$HOME/.openclaw/openclaw.json" "$HOME/.openclaw/config.json"; do
  if [[ -f "$candidate" ]]; then
    MP_OC_CONFIG="$candidate"
    break
  fi
done

if [[ -n "$MP_OC_CONFIG" ]]; then
  MP_CONFIG_NAME=$(basename "$MP_OC_CONFIG")

  TTL_HOURS=$(grep -oE '"ttlHours"[[:space:]]*:[[:space:]]*[0-9]+' "$MP_OC_CONFIG" 2>/dev/null | grep -oE '[0-9]+$' | head -1)
  if [[ -z "$TTL_HOURS" ]]; then
    warnx "MP-6-media-ttl" "MP-6: media.ttlHours not set in $MP_CONFIG_NAME — generated/received media is retained indefinitely; set a retention window"
  elif [[ "$TTL_HOURS" -eq 0 ]]; then
    warnx "MP-6-media-ttl" "MP-6: media.ttlHours is 0 (disabled) in $MP_CONFIG_NAME — media is never sanitized"
  else
    passx "MP-6-media-ttl" "MP-6: media.ttlHours is ${TTL_HOURS}h in $MP_CONFIG_NAME"
  fi

  # Secondary indicator: media.maxSizeMb
  MAX_SIZE=$(grep -oE '"maxSizeMb"[[:space:]]*:[[:space:]]*[0-9]+' "$MP_OC_CONFIG" 2>/dev/null | grep -oE '[0-9]+$' | head -1)
  if [[ -n "$MAX_SIZE" ]]; then
    passx "MP-6-media-max-size" "MP-6: media.maxSizeMb is set to ${MAX_SIZE}MB in $MP_CONFIG_NAME"
  else
    warnx "MP-6-media-max-size" "MP-6: media.maxSizeMb not set in $MP_CONFIG_NAME — no upper bound on stored media size"
  fi
else
  skipx "MP-6-media-ttl" "MP-6: OpenClaw config not found at ~/.openclaw/openclaw.json (or legacy ~/.openclaw/config.json)"
fi
