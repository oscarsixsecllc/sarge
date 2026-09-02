#!/usr/bin/env bash
# check-ca.sh — Assessment, Authorization & Monitoring (CA) — NIST 800-53 Rev 5
# Platform-specific data acquisition lives in lib/platforms/<os>.sh.

# CA-9: Internal System Connections — enumerate OpenClaw MCP server entries
log "CA-9: Internal system connections (MCP servers)"
CA_OC_CONFIG=""
for candidate in "$HOME/.openclaw/openclaw.json" "$HOME/.openclaw/config.json"; do
  if [[ -f "$candidate" ]]; then
    CA_OC_CONFIG="$candidate"
    break
  fi
done

if [[ -z "$CA_OC_CONFIG" ]]; then
  skipx "CA-9-mcp-connections" "CA-9: OpenClaw config not found at ~/.openclaw/openclaw.json (or legacy ~/.openclaw/config.json) — cannot enumerate MCP server connections"
elif ! command -v python3 &>/dev/null; then
  skipx "CA-9-mcp-connections" "CA-9: python3 not available — cannot parse $CA_OC_CONFIG for mcp.servers entries"
else
  MCP_SERVERS=$(python3 -c '
import json, sys
try:
    with open(sys.argv[1]) as f:
        cfg = json.load(f)
except Exception:
    print("")
    sys.exit(0)
servers = (cfg.get("mcp") or {}).get("servers") or {}
if isinstance(servers, dict):
    names = list(servers.keys())
elif isinstance(servers, list):
    names = [s.get("name", "unnamed") if isinstance(s, dict) else str(s) for s in servers]
else:
    names = []
print("\n".join(names))
' "$CA_OC_CONFIG" 2>/dev/null)
  MCP_COUNT=0
  if [[ -n "$MCP_SERVERS" ]]; then
    MCP_COUNT=$(echo "$MCP_SERVERS" | grep -c .)
  fi
  if [[ "$MCP_COUNT" -eq 0 ]]; then
    passx "CA-9-mcp-connections" "CA-9: no MCP server connections configured in $CA_OC_CONFIG"
  else
    NAMES_LIST=$(echo "$MCP_SERVERS" | tr '\n' ',' | sed 's/,$//')
    warnx "CA-9-mcp-connections" "CA-9: $MCP_COUNT MCP server connection(s) configured ($NAMES_LIST) — confirm each is documented in the system security plan / interconnection agreements"
  fi
fi
