#!/usr/bin/env bash
# check-sa.sh — System & Services Acquisition (SA) checks — NIST 800-53 Rev 5
# Platform-specific data acquisition lives in lib/platforms/<os>.sh.

# SA-9: External System Services
#
# Enumerates external MCP servers / API dependencies declared under
# `mcp.servers` in the live OpenClaw config. Presence of external services
# isn't itself a finding (agents legitimately call out to MCP servers) —
# this is an informational WARN so the list surfaces for manual review of
# data-sharing agreements and supply-chain exposure, matching how AS-7 /
# check-as.sh treats primitive-presence as WARN rather than FAIL.
log "SA-9: External system services (MCP servers)"

# Live OpenClaw 2026.7.x writes runtime config to `openclaw.json`. Older
# installs (pre-2026.4) used `config.json`. Same fallback probe used by
# check-sc.sh / check-ia.sh (issue #61).
SA_OC_CONFIG=""
for candidate in "$HOME/.openclaw/openclaw.json" "$HOME/.openclaw/config.json"; do
  if [[ -f "$candidate" ]]; then
    SA_OC_CONFIG="$candidate"
    break
  fi
done

if [[ -n "$SA_OC_CONFIG" ]]; then
  SA_CONFIG_NAME=$(basename "$SA_OC_CONFIG")
  if command -v jq &>/dev/null; then
    MCP_SERVERS=$(jq -r '(.mcp.servers // {}) | to_entries[] | select(.key | startswith("_") | not) | .key + " -> " + (.value.url? // "no url")' "$SA_OC_CONFIG" 2>/dev/null)
    MCP_COUNT=$(echo "$MCP_SERVERS" | grep -c . 2>/dev/null || echo 0)
  elif command -v python3 &>/dev/null; then
    MCP_SERVERS=$(python3 -c '
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    servers = (d.get("mcp") or {}).get("servers") or {}
    for k, v in servers.items():
        if k.startswith("_"):
            continue
        url = v.get("url", "no url") if isinstance(v, dict) else "no url"
        print(f"{k} -> {url}")
except Exception:
    pass
' "$SA_OC_CONFIG" 2>/dev/null)
    MCP_COUNT=$(echo "$MCP_SERVERS" | grep -c . 2>/dev/null || echo 0)
  else
    MCP_SERVERS=""
    MCP_COUNT=""
  fi

  if [[ -z "$MCP_COUNT" ]]; then
    warnx "SA-9-external-mcp-servers" "SA-9: neither jq nor python3 available — cannot enumerate mcp.servers in $SA_CONFIG_NAME"
  elif [[ "$MCP_COUNT" -gt 0 ]]; then
    warnx "SA-9-external-mcp-servers" "SA-9: $MCP_COUNT external MCP server(s)/API dependencies configured in $SA_CONFIG_NAME — review each for data-sharing agreements and supply-chain risk: $(echo "$MCP_SERVERS" | tr '\n' '|')"
  else
    passx "SA-9-external-mcp-servers" "SA-9: no external MCP servers configured in $SA_CONFIG_NAME"
  fi
else
  skipx "SA-9-external-mcp-servers" "SA-9: OpenClaw config not found at ~/.openclaw/openclaw.json (or legacy ~/.openclaw/config.json)"
fi

# SA-22: Unsupported System Components — Ubuntu release EOL
#
# Ubuntu LTS EOL dates (standard support, not ESM): 20.04 Apr 2025,
# 22.04 Apr 2027, 24.04 Apr 2029, 26.04 Apr 2031. FAIL past EOL, WARN
# inside the 6-month glidepath, PASS otherwise. Ubuntu-only lookup table
# by design (see task scope) — SARGE_OS_VERSION is populated for macOS
# too but the EOL table doesn't apply there.
log "SA-22: Operating system support status (Ubuntu EOL)"
if [[ "$SARGE_OS" == "ubuntu" ]]; then
  UBUNTU_EOL=""
  case "$SARGE_OS_VERSION" in
    20.04) UBUNTU_EOL="2025-04-01" ;;
    22.04) UBUNTU_EOL="2027-04-01" ;;
    24.04) UBUNTU_EOL="2029-04-01" ;;
    26.04) UBUNTU_EOL="2031-04-01" ;;
  esac
  if [[ -z "$UBUNTU_EOL" ]]; then
    warnx "SA-22-ubuntu-eol" "SA-22: no known EOL date for Ubuntu ${SARGE_OS_VERSION} — verify support status at https://endoflife.date/ubuntu"
  else
    NOW_EPOCH=$(date +%s)
    EOL_EPOCH=$(date -d "$UBUNTU_EOL" +%s 2>/dev/null)
    WARN_EPOCH=$(date -d "$UBUNTU_EOL -6 months" +%s 2>/dev/null)
    if [[ -z "$EOL_EPOCH" || -z "$WARN_EPOCH" ]]; then
      warnx "SA-22-ubuntu-eol" "SA-22: could not compute EOL date for Ubuntu ${SARGE_OS_VERSION} — verify support status at https://endoflife.date/ubuntu"
    elif [[ "$NOW_EPOCH" -ge "$EOL_EPOCH" ]]; then
      failx "SA-22-ubuntu-eol" "SA-22: Ubuntu ${SARGE_OS_VERSION} reached end-of-life on ${UBUNTU_EOL} — upgrade to a supported LTS release"
    elif [[ "$NOW_EPOCH" -ge "$WARN_EPOCH" ]]; then
      warnx "SA-22-ubuntu-eol" "SA-22: Ubuntu ${SARGE_OS_VERSION} reaches end-of-life on ${UBUNTU_EOL} (within 6 months) — plan an upgrade"
    else
      passx "SA-22-ubuntu-eol" "SA-22: Ubuntu ${SARGE_OS_VERSION} is supported until ${UBUNTU_EOL}"
    fi
  fi
else
  skipx "SA-22-ubuntu-eol" "SA-22: Ubuntu EOL lookup table does not apply on ${SARGE_OS_DESCRIPTION}"
fi

# SA-22: Unsupported System Components — Node.js runtime EOL
#
# Node.js EOL dates: 18 Apr 2025, 20 Apr 2026, 22 Apr 2027, 24 Apr 2028.
# Same FAIL/WARN/PASS glidepath as the Ubuntu check above.
log "SA-22: Node.js runtime support status"
if command -v node &>/dev/null; then
  NODE_VER=$(node --version 2>/dev/null | tr -d 'v')
  NODE_MAJOR="${NODE_VER%%.*}"
  NODE_EOL=""
  case "$NODE_MAJOR" in
    18) NODE_EOL="2025-04-30" ;;
    20) NODE_EOL="2026-04-30" ;;
    22) NODE_EOL="2027-04-30" ;;
    24) NODE_EOL="2028-04-30" ;;
  esac
  if [[ -z "$NODE_EOL" ]]; then
    warnx "SA-22-node-eol" "SA-22: no known EOL date for Node.js ${NODE_VER:-unknown} (major ${NODE_MAJOR:-unknown}) — verify support status at https://endoflife.date/nodejs"
  else
    NOW_EPOCH=$(date +%s)
    EOL_EPOCH=$(date -d "$NODE_EOL" +%s 2>/dev/null)
    WARN_EPOCH=$(date -d "$NODE_EOL -6 months" +%s 2>/dev/null)
    if [[ -z "$EOL_EPOCH" || -z "$WARN_EPOCH" ]]; then
      warnx "SA-22-node-eol" "SA-22: could not compute EOL date for Node.js ${NODE_VER} — verify support status at https://endoflife.date/nodejs"
    elif [[ "$NOW_EPOCH" -ge "$EOL_EPOCH" ]]; then
      failx "SA-22-node-eol" "SA-22: Node.js ${NODE_VER} (major $NODE_MAJOR) reached end-of-life on ${NODE_EOL} — upgrade to a supported LTS release"
    elif [[ "$NOW_EPOCH" -ge "$WARN_EPOCH" ]]; then
      warnx "SA-22-node-eol" "SA-22: Node.js ${NODE_VER} reaches end-of-life on ${NODE_EOL} (within 6 months) — plan an upgrade"
    else
      passx "SA-22-node-eol" "SA-22: Node.js ${NODE_VER} is supported until ${NODE_EOL}"
    fi
  fi
else
  skipx "SA-22-node-eol" "SA-22: node not found on PATH — Node.js runtime EOL check skipped"
fi
