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

# SC-2: Application Partitioning — OpenClaw process isolation
log "SC-2: Application partitioning"
if [[ "${SARGE_HOST_ONLY:-0}" != "1" ]]; then
  SC2_OC_PID=$(pgrep -f "openclaw" 2>/dev/null | head -1)
  if [[ -n "$SC2_OC_PID" ]]; then
    SC2_OC_USER=$(ps -o user= -p "$SC2_OC_PID" 2>/dev/null | tr -d ' ')
    SC2_CURRENT=$(whoami)
    if [[ "$SC2_OC_USER" == "root" ]]; then
      failx "SC-2-process-isolation" "SC-2: OpenClaw is running as root (PID $SC2_OC_PID) — run under a dedicated non-root service account"
    else
      passx "SC-2-process-isolation" "SC-2: OpenClaw is running as $SC2_OC_USER (PID $SC2_OC_PID) — not root"
    fi
    if [[ -d "/proc/$SC2_OC_PID/ns" ]]; then
      SC2_PID1_MNT=$(readlink /proc/1/ns/mnt 2>/dev/null)
      SC2_OC_MNT=$(readlink "/proc/$SC2_OC_PID/ns/mnt" 2>/dev/null)
      if [[ -n "$SC2_PID1_MNT" && -n "$SC2_OC_MNT" && "$SC2_PID1_MNT" != "$SC2_OC_MNT" ]]; then
        passx "SC-2-namespace-isolation" "SC-2: OpenClaw process has a separate mount namespace — container or namespace isolation detected"
      else
        warnx "SC-2-namespace-isolation" "SC-2: OpenClaw shares the host mount namespace — consider running in a container or with namespace isolation"
      fi
    fi
  else
    skipx "SC-2-process-isolation" "SC-2: No running OpenClaw process found — cannot verify process isolation"
  fi
else
  skipx "SC-2-process-isolation" "SC-2: host-only mode — OpenClaw process checks skipped"
fi

# SC-4: Information in Shared Resources — /tmp and shared memory cleanup
log "SC-4: Information in shared resources"
SC4_TMP_OC_FILES=$(find /tmp -maxdepth 2 -name "*openclaw*" -o -name "*claude*" 2>/dev/null | wc -l)
if [[ "$SC4_TMP_OC_FILES" -gt 10 ]]; then
  warnx "SC-4-tmp-residual" "SC-4: $SC4_TMP_OC_FILES OpenClaw/Claude temp files found in /tmp — residual session data may contain sensitive information; configure periodic cleanup"
elif [[ "$SC4_TMP_OC_FILES" -gt 0 ]]; then
  passx "SC-4-tmp-residual" "SC-4: $SC4_TMP_OC_FILES OpenClaw/Claude temp file(s) in /tmp — within normal range"
else
  passx "SC-4-tmp-residual" "SC-4: No OpenClaw/Claude residual files found in /tmp"
fi
SC4_SHM_FILES=$(find /dev/shm -maxdepth 1 -type f 2>/dev/null | wc -l)
if [[ "$SC4_SHM_FILES" -gt 0 ]]; then
  warnx "SC-4-shm-residual" "SC-4: $SC4_SHM_FILES file(s) in /dev/shm — review for sensitive data residue"
else
  passx "SC-4-shm-residual" "SC-4: No files in /dev/shm"
fi

# SC-12: Cryptographic Key Establishment and Management
log "SC-12: Cryptographic key management"
SC12_SECRETS_DIR="$HOME/.openclaw/secrets"
if [[ -d "$SC12_SECRETS_DIR" ]]; then
  SC12_KEY_COUNT=0
  SC12_BAD_PERM=""
  while IFS= read -r -d '' kf; do
    SC12_KEY_COUNT=$((SC12_KEY_COUNT + 1))
    KF_PERM=$(platform file_perm "$kf")
    if [[ "$KF_PERM" != "600" && "$KF_PERM" != "400" ]]; then
      SC12_BAD_PERM="${SC12_BAD_PERM}${SC12_BAD_PERM:+, }$(basename "$kf"):$KF_PERM"
    fi
  done < <(find "$SC12_SECRETS_DIR" -maxdepth 1 -type f \( -name "*.key" -o -name "*.pem" -o -name "*.p12" -o -name "*-key" -o -name "*-token" -o -name "*-secret" -o -name "*.env" \) -print0 2>/dev/null)
  if [[ "$SC12_KEY_COUNT" -eq 0 ]]; then
    passx "SC-12-key-permissions" "SC-12: No key/credential files found in $SC12_SECRETS_DIR (or using non-file-based key management)"
  elif [[ -z "$SC12_BAD_PERM" ]]; then
    passx "SC-12-key-permissions" "SC-12: All $SC12_KEY_COUNT key/credential file(s) in secrets/ have restricted permissions (600 or 400)"
  else
    failx "SC-12-key-permissions" "SC-12: Key/credential files with weak permissions: $SC12_BAD_PERM — should be 600 or 400"
  fi
else
  skipx "SC-12-key-permissions" "SC-12: No secrets directory at ~/.openclaw/secrets"
fi
SC12_SSH_DIR="$HOME/.ssh"
if [[ -d "$SC12_SSH_DIR" ]]; then
  SC12_SSH_BAD=""
  while IFS= read -r -d '' sk; do
    SK_PERM=$(platform file_perm "$sk")
    if [[ "$SK_PERM" != "600" && "$SK_PERM" != "400" ]]; then
      SC12_SSH_BAD="${SC12_SSH_BAD}${SC12_SSH_BAD:+, }$(basename "$sk"):$SK_PERM"
    fi
  done < <(find "$SC12_SSH_DIR" -maxdepth 1 -type f -name "id_*" ! -name "*.pub" -print0 2>/dev/null)
  if [[ -z "$SC12_SSH_BAD" ]]; then
    passx "SC-12-ssh-key-permissions" "SC-12: SSH private keys in ~/.ssh have restricted permissions"
  else
    failx "SC-12-ssh-key-permissions" "SC-12: SSH private keys with weak permissions: $SC12_SSH_BAD — should be 600"
  fi
else
  skipx "SC-12-ssh-key-permissions" "SC-12: No ~/.ssh directory found"
fi

# SC-13: Cryptographic Protection — TLS and cipher configuration
log "SC-13: Cryptographic protection"
SC13_OPENSSL_VER=$(openssl version 2>/dev/null)
if [[ -n "$SC13_OPENSSL_VER" ]]; then
  SC13_MAJOR=$(echo "$SC13_OPENSSL_VER" | grep -oE '[0-9]+\.[0-9]+' | head -1)
  case "$SC13_MAJOR" in
    3.*|1.1)
      passx "SC-13-openssl-version" "SC-13: $SC13_OPENSSL_VER — FIPS-capable version"
      ;;
    *)
      warnx "SC-13-openssl-version" "SC-13: $SC13_OPENSSL_VER — review if this version meets organizational cryptographic requirements"
      ;;
  esac
else
  warnx "SC-13-openssl-version" "SC-13: openssl not found on PATH — cannot verify cryptographic library version"
fi
SC13_NODE_VER=$(node --version 2>/dev/null)
if [[ -n "$SC13_NODE_VER" ]]; then
  SC13_NODE_MAJOR=$(echo "$SC13_NODE_VER" | grep -oE '[0-9]+' | head -1)
  if [[ "$SC13_NODE_MAJOR" -ge 18 ]]; then
    passx "SC-13-node-tls" "SC-13: Node.js $SC13_NODE_VER uses OpenSSL 3.x by default (TLS 1.2+ enforced)"
  else
    warnx "SC-13-node-tls" "SC-13: Node.js $SC13_NODE_VER — versions below 18 may not enforce TLS 1.2+ by default"
  fi
else
  skipx "SC-13-node-tls" "SC-13: Node.js not found on PATH"
fi

# SC-15: Collaborative Computing Devices — camera/microphone access
log "SC-15: Collaborative computing devices"
if [[ "${SARGE_HOST_ONLY:-0}" != "1" ]]; then
  SC15_OC_CONFIG=""
  for candidate in "$HOME/.openclaw/openclaw.json" "$HOME/.openclaw/config.json"; do
    if [[ -f "$candidate" ]]; then
      SC15_OC_CONFIG="$candidate"
      break
    fi
  done
  if [[ -n "$SC15_OC_CONFIG" ]]; then
    SC15_CONFIG_NAME=$(basename "$SC15_OC_CONFIG")
    SC15_CAMERA=$(grep -oE '"camera"[[:space:]]*:[[:space:]]*(true|false|"[^"]*")' "$SC15_OC_CONFIG" 2>/dev/null | head -1)
    SC15_MIC=$(grep -oE '"microphone"[[:space:]]*:[[:space:]]*(true|false|"[^"]*")' "$SC15_OC_CONFIG" 2>/dev/null | head -1)
    SC15_SCREEN=$(grep -oE '"screen"[[:space:]]*:[[:space:]]*(true|false|"[^"]*")' "$SC15_OC_CONFIG" 2>/dev/null | head -1)
    SC15_ANY_FOUND=0
    if [[ -n "$SC15_CAMERA" || -n "$SC15_MIC" || -n "$SC15_SCREEN" ]]; then
      SC15_ANY_FOUND=1
    fi
    if [[ "$SC15_ANY_FOUND" -eq 1 ]]; then
      SC15_DETAIL=""
      [[ -n "$SC15_CAMERA" ]] && SC15_DETAIL="camera=$SC15_CAMERA"
      [[ -n "$SC15_MIC" ]] && SC15_DETAIL="${SC15_DETAIL:+$SC15_DETAIL, }mic=$SC15_MIC"
      [[ -n "$SC15_SCREEN" ]] && SC15_DETAIL="${SC15_DETAIL:+$SC15_DETAIL, }screen=$SC15_SCREEN"
      warnx "SC-15-device-access" "SC-15: Collaborative device capabilities configured in $SC15_CONFIG_NAME ($SC15_DETAIL) — confirm each is authorized for this agent's mission"
    else
      passx "SC-15-device-access" "SC-15: No camera/microphone/screen capture capabilities detected in $SC15_CONFIG_NAME"
    fi
  else
    skipx "SC-15-device-access" "SC-15: OpenClaw config not found — cannot check device capability grants"
  fi
  if command -v v4l2-ctl &>/dev/null; then
    SC15_V4L_DEVS=$(v4l2-ctl --list-devices 2>/dev/null | grep -c "^[^ ]")
    if [[ "$SC15_V4L_DEVS" -gt 0 ]]; then
      warnx "SC-15-video-devices" "SC-15: $SC15_V4L_DEVS video capture device(s) detected on host — verify agent access is intentional"
    else
      passx "SC-15-video-devices" "SC-15: No video capture devices detected"
    fi
  elif [[ -e /dev/video0 ]]; then
    warnx "SC-15-video-devices" "SC-15: /dev/video0 exists — video capture hardware is present; verify agent access is intentional"
  else
    passx "SC-15-video-devices" "SC-15: No /dev/video* devices found"
  fi
else
  skipx "SC-15-device-access" "SC-15: host-only mode — device capability checks skipped"
fi

# SC-23: Session Authenticity — OpenClaw auth and session token configuration
log "SC-23: Session authenticity"
if [[ "${SARGE_HOST_ONLY:-0}" != "1" ]]; then
  SC23_OC_CONFIG=""
  for candidate in "$HOME/.openclaw/openclaw.json" "$HOME/.openclaw/config.json"; do
    if [[ -f "$candidate" ]]; then
      SC23_OC_CONFIG="$candidate"
      break
    fi
  done
  if [[ -n "$SC23_OC_CONFIG" ]]; then
    SC23_CONFIG_NAME=$(basename "$SC23_OC_CONFIG")
    SC23_AUTH_ENABLED=$(python3 -c '
import json, sys
try:
    cfg = json.load(open(sys.argv[1]))
    auth = cfg.get("auth", {})
    if isinstance(auth, dict):
        val = auth.get("enabled")
        if val is not None:
            print(str(val).lower())
        else:
            print("unset")
    else:
        print("unset")
except Exception:
    print("error")
' "$SC23_OC_CONFIG" 2>/dev/null)
    case "$SC23_AUTH_ENABLED" in
      true)
        passx "SC-23-auth-enabled" "SC-23: Authentication is enabled in $SC23_CONFIG_NAME"
        ;;
      false)
        failx "SC-23-auth-enabled" "SC-23: auth.enabled is false in $SC23_CONFIG_NAME — sessions are unauthenticated"
        ;;
      unset)
        warnx "SC-23-auth-enabled" "SC-23: auth.enabled not explicitly set in $SC23_CONFIG_NAME — verify the default behavior authenticates sessions"
        ;;
      *)
        skipx "SC-23-auth-enabled" "SC-23: Could not parse auth configuration in $SC23_CONFIG_NAME"
        ;;
    esac
    SC23_GATEWAY_TOKEN=$(grep -oE '"gatewayToken"[[:space:]]*:[[:space:]]*"[^"]*"' "$SC23_OC_CONFIG" 2>/dev/null | head -1)
    if [[ -n "$SC23_GATEWAY_TOKEN" ]]; then
      passx "SC-23-gateway-token" "SC-23: gatewayToken is configured in $SC23_CONFIG_NAME"
    else
      warnx "SC-23-gateway-token" "SC-23: No gatewayToken found in $SC23_CONFIG_NAME — gateway API may be accessible without a token"
    fi
  else
    skipx "SC-23-auth-enabled" "SC-23: OpenClaw config not found — cannot check session authenticity settings"
  fi
else
  skipx "SC-23-auth-enabled" "SC-23: host-only mode — session authenticity checks skipped"
fi

# SC-39: Process Isolation — cgroup and namespace enforcement
log "SC-39: Process isolation"
if [[ "${SARGE_HOST_ONLY:-0}" != "1" ]]; then
  SC39_OC_PID=$(pgrep -f "openclaw" 2>/dev/null | head -1)
  if [[ -n "$SC39_OC_PID" ]]; then
    SC39_CGROUP=$(cat "/proc/$SC39_OC_PID/cgroup" 2>/dev/null | head -1)
    if [[ -n "$SC39_CGROUP" ]]; then
      if echo "$SC39_CGROUP" | grep -qE "docker|containerd|lxc|podman|systemd.*scope"; then
        passx "SC-39-cgroup-isolation" "SC-39: OpenClaw process is in a scoped cgroup ($SC39_CGROUP) — container or systemd isolation active"
      else
        warnx "SC-39-cgroup-isolation" "SC-39: OpenClaw process cgroup ($SC39_CGROUP) does not indicate container isolation — consider adding resource limits via systemd slice or container runtime"
      fi
    else
      skipx "SC-39-cgroup-isolation" "SC-39: Cannot read cgroup for OpenClaw process (PID $SC39_OC_PID)"
    fi
    SC39_PID_NS=$(readlink "/proc/$SC39_OC_PID/ns/pid" 2>/dev/null)
    SC39_HOST_PID_NS=$(readlink /proc/1/ns/pid 2>/dev/null)
    if [[ -n "$SC39_PID_NS" && -n "$SC39_HOST_PID_NS" ]]; then
      if [[ "$SC39_PID_NS" != "$SC39_HOST_PID_NS" ]]; then
        passx "SC-39-pid-namespace" "SC-39: OpenClaw runs in a separate PID namespace — process isolation enforced"
      else
        warnx "SC-39-pid-namespace" "SC-39: OpenClaw shares the host PID namespace — processes are visible to and from the agent"
      fi
    fi
    SC39_NET_NS=$(readlink "/proc/$SC39_OC_PID/ns/net" 2>/dev/null)
    SC39_HOST_NET_NS=$(readlink /proc/1/ns/net 2>/dev/null)
    if [[ -n "$SC39_NET_NS" && -n "$SC39_HOST_NET_NS" ]]; then
      if [[ "$SC39_NET_NS" != "$SC39_HOST_NET_NS" ]]; then
        passx "SC-39-net-namespace" "SC-39: OpenClaw runs in a separate network namespace — network isolation enforced"
      else
        warnx "SC-39-net-namespace" "SC-39: OpenClaw shares the host network namespace — agent can access all host network interfaces"
      fi
    fi
  else
    skipx "SC-39-cgroup-isolation" "SC-39: No running OpenClaw process found — cannot verify process isolation"
  fi
else
  skipx "SC-39-cgroup-isolation" "SC-39: host-only mode — process isolation checks skipped"
fi

# SC-5: Denial-of-Service Protection — rate limits on gateway and agent concurrency
log "SC-5: Denial-of-service protection"
if [[ "${SARGE_HOST_ONLY:-0}" != "1" ]]; then
  SC5_OC_CONFIG=""
  for candidate in "$HOME/.openclaw/openclaw.json" "$HOME/.openclaw/config.json"; do
    if [[ -f "$candidate" ]]; then
      SC5_OC_CONFIG="$candidate"
      break
    fi
  done
  if [[ -n "$SC5_OC_CONFIG" ]]; then
    SC5_CONFIG_NAME=$(basename "$SC5_OC_CONFIG")
    # Check gateway auth rate limiting
    SC5_RATE_LIMIT=$(python3 -c '
import json, sys
try:
    cfg = json.load(open(sys.argv[1]))
    rl = cfg.get("gateway", {}).get("auth", {}).get("rateLimit", {})
    ma = rl.get("maxAttempts")
    if ma is not None:
        print(f"configured:{ma}")
    else:
        print("unset")
except Exception:
    print("error")
' "$SC5_OC_CONFIG" 2>/dev/null)
    case "$SC5_RATE_LIMIT" in
      configured:*)
        SC5_RL_VAL="${SC5_RATE_LIMIT#configured:}"
        if [[ "$SC5_RL_VAL" -le 20 ]] 2>/dev/null; then
          passx "SC-5-gateway-rate-limit" "SC-5: Gateway auth rate limit set to $SC5_RL_VAL maxAttempts in $SC5_CONFIG_NAME"
        else
          warnx "SC-5-gateway-rate-limit" "SC-5: Gateway auth rate limit is $SC5_RL_VAL maxAttempts, consider lowering to 10-20 to mitigate brute-force DoS"
        fi
        ;;
      unset)
        warnx "SC-5-gateway-rate-limit" "SC-5: gateway.auth.rateLimit.maxAttempts not set in $SC5_CONFIG_NAME, no auth rate limiting is enforced"
        ;;
      *)
        skipx "SC-5-gateway-rate-limit" "SC-5: Could not parse rate limit configuration from $SC5_CONFIG_NAME"
        ;;
    esac

    # Check agent concurrency limits
    SC5_CONCURRENCY=$(python3 -c '
import json, sys
try:
    cfg = json.load(open(sys.argv[1]))
    ad = cfg.get("agents", {}).get("defaults", {})
    mc = ad.get("maxConcurrent")
    smc = ad.get("subagents", {}).get("maxConcurrent")
    cmc = cfg.get("cron", {}).get("maxConcurrentRuns")
    parts = []
    if mc is not None: parts.append(f"agents={mc}")
    if smc is not None: parts.append(f"subagents={smc}")
    if cmc is not None: parts.append(f"cron={cmc}")
    if parts:
        print("configured:" + ",".join(parts))
    else:
        print("unset")
except Exception:
    print("error")
' "$SC5_OC_CONFIG" 2>/dev/null)
    case "$SC5_CONCURRENCY" in
      configured:*)
        SC5_CONC_DETAIL="${SC5_CONCURRENCY#configured:}"
        passx "SC-5-concurrency-limits" "SC-5: Concurrency limits configured ($SC5_CONC_DETAIL) in $SC5_CONFIG_NAME"
        ;;
      unset)
        warnx "SC-5-concurrency-limits" "SC-5: No agent/subagent/cron concurrency limits found in $SC5_CONFIG_NAME, unbounded concurrency increases DoS risk"
        ;;
      *)
        skipx "SC-5-concurrency-limits" "SC-5: Could not parse concurrency settings from $SC5_CONFIG_NAME"
        ;;
    esac
  else
    skipx "SC-5-gateway-rate-limit" "SC-5: OpenClaw config not found, cannot check DoS protection settings"
  fi

  # SC-5: Check if gateway port has connection-level rate limiting via UFW
  GW_PORT="${OPENCLAW_GATEWAY_PORT:-18790}"
  if platform firewall_command_available && platform firewall_active; then
    SC5_UFW_LIMIT=$(ufw status 2>/dev/null | grep -E "$GW_PORT.*LIMIT" || true)
    if [[ -n "$SC5_UFW_LIMIT" ]]; then
      passx "SC-5-ufw-rate-limit" "SC-5: UFW rate limiting active on gateway port $GW_PORT"
    else
      warnx "SC-5-ufw-rate-limit" "SC-5: No UFW rate limit rule on gateway port $GW_PORT, consider: sudo ufw limit $GW_PORT/tcp"
    fi
  else
    skipx "SC-5-ufw-rate-limit" "SC-5: UFW not active, cannot check network-level rate limiting"
  fi
else
  skipx "SC-5-gateway-rate-limit" "SC-5: host-only mode, DoS protection checks skipped"
fi

# SC-7: Boundary Protection — firewall posture and unexpected open ports
log "SC-7: Boundary protection"
if platform firewall_command_available; then
  if platform firewall_active; then
    passx "SC-7-firewall-active" "SC-7: Host firewall (UFW) is active"

    # Check default incoming policy
    SC7_DEFAULT_IN=$(ufw status verbose 2>/dev/null | grep "Default:" | grep -oE "deny \(incoming\)|reject \(incoming\)" || true)
    if [[ -n "$SC7_DEFAULT_IN" ]]; then
      passx "SC-7-default-deny" "SC-7: Default incoming policy is deny/reject"
    else
      failx "SC-7-default-deny" "SC-7: Default incoming policy is not deny/reject, run: sudo ufw default deny incoming"
    fi

    # Check for unexpected externally-listening ports
    SC7_EXPECTED_PORTS="${SARGE_EXPECTED_PORTS:-22,${OPENCLAW_GATEWAY_PORT:-18790}}"
    SC7_UNEXPECTED=""
    while IFS= read -r line; do
      SC7_PORT=$(echo "$line" | grep -oE ':[0-9]+' | head -1 | tr -d ':')
      if [[ -n "$SC7_PORT" ]]; then
        SC7_FOUND=0
        IFS=',' read -ra SC7_EP_ARR <<< "$SC7_EXPECTED_PORTS"
        for ep in "${SC7_EP_ARR[@]}"; do
          if [[ "$SC7_PORT" == "$ep" ]]; then
            SC7_FOUND=1
            break
          fi
        done
        if [[ "$SC7_FOUND" -eq 0 ]]; then
          SC7_UNEXPECTED="${SC7_UNEXPECTED}${SC7_UNEXPECTED:+, }$SC7_PORT"
        fi
      fi
    done < <(ss -tlnp 2>/dev/null | grep -v "127.0.0" | grep -v "::1" | tail -n +2)
    if [[ -z "$SC7_UNEXPECTED" ]]; then
      passx "SC-7-unexpected-ports" "SC-7: No unexpected externally-listening ports (expected: $SC7_EXPECTED_PORTS)"
    else
      warnx "SC-7-unexpected-ports" "SC-7: Unexpected externally-listening ports detected: $SC7_UNEXPECTED (expected: $SC7_EXPECTED_PORTS)"
    fi
  else
    failx "SC-7-firewall-active" "SC-7: Host firewall (UFW) is installed but not active, run: sudo ufw enable"
  fi
else
  warnx "SC-7-firewall-active" "SC-7: UFW not installed, no host firewall detected"
fi

# SC-7: OpenClaw boundary settings (SSRF, mDNS, hooks)
if [[ "${SARGE_HOST_ONLY:-0}" != "1" ]]; then
  SC7_OC_CONFIG=""
  for candidate in "$HOME/.openclaw/openclaw.json" "$HOME/.openclaw/config.json"; do
    if [[ -f "$candidate" ]]; then
      SC7_OC_CONFIG="$candidate"
      break
    fi
  done
  if [[ -n "$SC7_OC_CONFIG" ]]; then
    SC7_CONFIG_NAME=$(basename "$SC7_OC_CONFIG")
    SC7_BOUNDARY=$(python3 -c '
import json, sys
try:
    cfg = json.load(open(sys.argv[1]))
    ssrf = cfg.get("browser", {}).get("ssrfPolicy", {}).get("dangerouslyAllowPrivateNetwork")
    mdns = cfg.get("discovery", {}).get("mdns", {}).get("mode")
    hooks = cfg.get("hooks", {}).get("enabled")
    web = cfg.get("web", {}).get("enabled")
    results = []
    if ssrf is True:
        results.append("FAIL:ssrf_private_net=true")
    elif ssrf is False:
        results.append("PASS:ssrf_private_net=false")
    if mdns is not None:
        if mdns in ("off", "minimal", "disabled"):
            results.append(f"PASS:mdns={mdns}")
        else:
            results.append(f"WARN:mdns={mdns}")
    if hooks is True:
        results.append("WARN:hooks=enabled")
    elif hooks is False:
        results.append("PASS:hooks=disabled")
    if web is True:
        results.append("WARN:web=enabled")
    print("|".join(results) if results else "none")
except Exception:
    print("error")
' "$SC7_OC_CONFIG" 2>/dev/null)
    if [[ "$SC7_BOUNDARY" == "error" || "$SC7_BOUNDARY" == "none" ]]; then
      skipx "SC-7-ssrf-policy" "SC-7: Could not parse boundary settings from $SC7_CONFIG_NAME"
    else
      IFS='|' read -ra SC7_ITEMS <<< "$SC7_BOUNDARY"
      for item in "${SC7_ITEMS[@]}"; do
        SC7_LEVEL="${item%%:*}"
        SC7_MSG="${item#*:}"
        case "$SC7_LEVEL" in
          FAIL)
            failx "SC-7-ssrf-policy" "SC-7: Dangerous boundary setting: $SC7_MSG in $SC7_CONFIG_NAME"
            ;;
          WARN)
            warnx "SC-7-boundary-config" "SC-7: Review boundary setting: $SC7_MSG in $SC7_CONFIG_NAME"
            ;;
          PASS)
            passx "SC-7-boundary-config" "SC-7: Boundary setting OK: $SC7_MSG in $SC7_CONFIG_NAME"
            ;;
        esac
      done
    fi
  else
    skipx "SC-7-ssrf-policy" "SC-7: OpenClaw config not found, cannot check boundary settings"
  fi
fi
