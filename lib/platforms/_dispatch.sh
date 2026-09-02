#!/usr/bin/env bash
# lib/platforms/_dispatch.sh — Cross-platform helper dispatch
#
# Loads the active platform's implementation file and exposes a single
# dispatcher function:
#
#   platform <probe-name> [args...]
#
# This calls ${SARGE_OS}_<probe-name> if defined; otherwise returns 127
# ("not implemented for this platform"). Callers distinguish via exit code:
#
#   value=$(platform password_max_days) || true        # 127 = no support
#   if platform audit_daemon_active; then ...; fi      # 0 = yes, !0 = no/unsupported
#
# Adding a new platform: drop a file at lib/platforms/<os>.sh that defines
# helpers as `<os>_<probe-name>`. There is no central registry; the
# dispatcher discovers helpers via `declare -F` at call time.
#
# Adding a new probe: define it in every supported platform's file. Probes
# missing from a platform return 127 — control files should treat that as
# "skip with reason".

[[ -n "${_SARGE_PLATFORMS_LOADED:-}" ]] && return 0
_SARGE_PLATFORMS_LOADED=1

: "${SARGE_OS:?lib/platform.sh must be sourced before lib/platforms/_dispatch.sh}"

_SARGE_PLATFORMS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -r "${_SARGE_PLATFORMS_DIR}/${SARGE_OS}.sh" ]]; then
  # shellcheck source=/dev/null
  source "${_SARGE_PLATFORMS_DIR}/${SARGE_OS}.sh"
else
  echo "[Sarge] No platform implementation: ${_SARGE_PLATFORMS_DIR}/${SARGE_OS}.sh" >&2
  return 1
fi

platform() {
  if [[ $# -eq 0 ]]; then
    echo "[Sarge] platform: missing probe name (usage: platform <probe> [args...])" >&2
    return 2
  fi
  local fn="${SARGE_OS}_$1"; shift
  if declare -F "$fn" &>/dev/null; then
    "$fn" "$@"
    return $?
  fi
  return 127
}

# 0 if the active platform implements <probe>, nonzero otherwise. Lets
# control checks distinguish "probe ran and said no" from "probe doesn't
# exist on this OS" — the latter routes to a skipx with a platform-aware
# rationale instead of a misleading failx. Cheaper than calling the probe
# and inspecting exit code 127, and side-effect free.
platform_supports() {
  declare -F "${SARGE_OS}_$1" &>/dev/null
}

# ---------- OpenClaw config drift fields (shared across platforms) ----------
#
# Extracts security-relevant config values from the live OpenClaw config
# (~/.openclaw/openclaw.json) for CM-2 drift detection. These fields
# complement the OS-level fields each platform emits. The extraction uses
# python3 + json (both available on every supported platform) to avoid
# jq as a hard dependency.
#
# Adding a new config field: add a "path|default" line to the heredoc
# below. The path uses dot-delimited JSON keys; arrays are not traversed.
_sarge_openclaw_config_drift_fields() {
  local config_file="${OPENCLAW_CONFIG_PATH:-$HOME/.openclaw/openclaw.json}"
  if [[ ! -r "$config_file" ]]; then
    echo "oc_config_readable=false"
    return 0
  fi
  python3 - "$config_file" <<'PYEOF' 2>/dev/null || true
import json, sys

config_file = sys.argv[1]
try:
    with open(config_file) as fh:
        cfg = json.load(fh)
except Exception:
    print("oc_config_readable=false")
    sys.exit(0)

# Resolve a dot-path into the config dict. Returns the value or None.
def resolve(obj, path):
    keys = path.split(".")
    cur = obj
    for k in keys:
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return None
    return cur

# Each tuple: (emit_key, json_path, default_if_missing)
fields = [
    ("oc_config_readable",                        None, "true"),
    ("oc_gateway_bind",                           "gateway.bind", "unknown"),
    ("oc_gateway_auth_mode",                      "gateway.auth.mode", "unknown"),
    ("oc_gateway_auth_ratelimit_max",             "gateway.auth.rateLimit.maxAttempts", "unknown"),
    ("oc_gateway_tls_enabled",                    "gateway.tls.enabled", "unknown"),
    ("oc_gateway_terminal_enabled",               "gateway.terminal.enabled", "unknown"),
    ("oc_agents_sandbox_mode",                    "agents.defaults.sandbox.mode", "unknown"),
    ("oc_agents_compaction_mode",                 "agents.defaults.compaction.mode", "unknown"),
    ("oc_agents_compaction_midturn",              "agents.defaults.compaction.midTurnPrecheck.enabled", "unknown"),
    ("oc_agents_compaction_memflush",             "agents.defaults.compaction.memoryFlush.enabled", "unknown"),
    ("oc_agents_max_concurrent",                  "agents.defaults.maxConcurrent", "unknown"),
    ("oc_agents_subagents_max_concurrent",        "agents.defaults.subagents.maxConcurrent", "unknown"),
    ("oc_browser_enabled",                        "browser.enabled", "unknown"),
    ("oc_browser_no_sandbox",                     "browser.noSandbox", "unknown"),
    ("oc_browser_attach_only",                    "browser.attachOnly", "unknown"),
    ("oc_hooks_enabled",                          "hooks.enabled", "unknown"),
    ("oc_hooks_allow_request_session_key",        "hooks.allowRequestSessionKey", "unknown"),
    ("oc_tools_fs_workspace_only",                "tools.fs.workspaceOnly", "unknown"),
    ("oc_tools_exec_elevated",                    "tools.exec.elevated", "unknown"),
    ("oc_skills_workshop_approval_policy",        "skills.workshop.approvalPolicy", "unknown"),
    ("oc_session_dm_scope",                       "session.dmScope", "unknown"),
    ("oc_messages_visible_replies",               "messages.groupChat.visibleReplies", "unknown"),
    ("oc_audit_enabled",                          "audit.enabled", "unknown"),
    ("oc_cron_max_concurrent",                    "cron.maxConcurrentRuns", "unknown"),
    ("oc_logging_level",                          "logging.level", "unknown"),
    ("oc_logging_redact_sensitive",               "logging.redactSensitive", "unknown"),
    ("oc_discovery_mdns_mode",                    "discovery.mdns.mode", "unknown"),
    ("oc_update_auto_enabled",                    "update.auto.enabled", "unknown"),

    # --- Added in baseline v0.4.0 (OpenClaw 2026.7.1-2) ---
    ("oc_browser_evaluate_enabled",               "browser.evaluateEnabled", "unknown"),
    ("oc_browser_ssrf_allow_private",             "browser.ssrfPolicy.dangerouslyAllowPrivateNetwork", "unknown"),
    ("oc_agents_subagents_allow_child_overrides", "agents.defaults.subagents.allowChildOverrides", "unknown"),
    ("oc_agents_compaction_truncate",             "agents.defaults.compaction.truncateAfterCompaction", "unknown"),
    ("oc_agents_compaction_notify",               "agents.defaults.compaction.notifyUser", "unknown"),
    ("oc_skills_allow_uploaded_archives",         "skills.install.allowUploadedArchives", "unknown"),
    ("oc_skills_allow_symlink_writes",            "skills.workshop.allowSymlinkTargetWrites", "unknown"),
    ("oc_diagnostics_otel_capture_content",       "diagnostics.otel.captureContent.enabled", "unknown"),
    ("oc_diagnostics_cache_trace",                "diagnostics.cacheTrace.enabled", "unknown"),
    ("oc_gateway_controlui_allow_insecure",       "gateway.controlUi.allowInsecureAuth", "unknown"),
    ("oc_gateway_controlui_host_fallback",        "gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback", "unknown"),
    ("oc_gateway_tailscale_mode",                 "gateway.tailscale.mode", "unknown"),
    ("oc_gateway_http_chat_completions",          "gateway.http.endpoints.chatCompletions.enabled", "unknown"),
    ("oc_gateway_http_responses",                 "gateway.http.endpoints.responses.enabled", "unknown"),
    ("oc_acp_enabled",                            "acp.enabled", "unknown"),
    ("oc_acp_max_concurrent_sessions",            "acp.maxConcurrentSessions", "unknown"),
    ("oc_commitments_enabled",                    "commitments.enabled", "unknown"),
    ("oc_tools_code_mode",                        "tools.codeMode.enabled", "unknown"),
    ("oc_approvals_exec_enabled",                 "approvals.exec.enabled", "unknown"),
    ("oc_cron_failure_alert_enabled",             "cron.failureAlert.enabled", "unknown"),

    # --- Added in baseline v0.5.0 (full schema surface coverage) ---
    ("oc_security_install_policy_enabled",        "security.installPolicy.enabled", "unknown"),
    ("oc_proxy_enabled",                          "proxy.enabled", "unknown"),
    ("oc_proxy_loopback_mode",                    "proxy.loopbackMode", "unknown"),
    ("oc_nodehost_browser_proxy_enabled",         "nodeHost.browserProxy.enabled", "unknown"),
    ("oc_transcripts_enabled",                    "transcripts.enabled", "unknown"),
    ("oc_broadcast_strategy",                     "broadcast.strategy", "unknown"),
    ("oc_crestodian_rescue_enabled",              "crestodian.rescue.enabled", "unknown"),
    ("oc_crestodian_rescue_owner_dm_only",        "crestodian.rescue.ownerDmOnly", "unknown"),
    ("oc_web_enabled",                            "web.enabled", "unknown"),
    ("oc_media_ttl_hours",                        "media.ttlHours", "unknown"),
    ("oc_media_preserve_filenames",               "media.preserveFilenames", "unknown"),
    ("oc_talk_interrupt_on_speech",               "talk.interruptOnSpeech", "unknown"),

    # --- Added in baseline v0.6.0 (audio + surfaces schema coverage) ---
    ("oc_audio_transcription_timeout",            "audio.transcription.timeoutSeconds", "unknown"),
]

for emit_key, path, default in fields:
    if path is None:
        print(f"{emit_key}={default}")
        continue
    val = resolve(cfg, path)
    if val is None:
        out = default
    elif isinstance(val, bool):
        out = str(val).lower()
    else:
        out = str(val)
    print(f"{emit_key}={out}")
PYEOF
}

# ---------- Drift field plumbing (shared across platforms) ----------
#
# Each platform defines `_<os>_drift_fields` that emits one `key=value`
# line per field it captures (see lib/platforms/<os>.sh). The two sinks
# below consume that stream — but the calling convention is asymmetric:
#
#   # snapshot: pipe is fine (sink writes stdout only, no shared state)
#   _<os>_drift_fields | sarge_emit_drift_snapshot_json
#
#   # check: MUST use process substitution, NOT a pipe
#   sarge_emit_drift_check_calls < <(_<os>_drift_fields)
#
# Why: sarge_emit_drift_check_calls invokes `check`, which is defined in
# drift/compare.sh and mutates a parent-shell `DRIFT` counter. In bash,
# pipeline elements run in subshells by default, so a pipe here would
# drop every DRIFT increment — compare.sh would print `[DRIFT] …` lines
# but still exit 0 with "No drift detected." Process substitution keeps
# the while-loop in the caller's shell, preserving the mutation.
#
# Living here (not per-platform) because the loops are byte-for-byte
# identical across platforms — only the field set is platform-specific.
# Pulling them up means adding a new platform's drift coverage is one
# function (the field emitter), not three.

# Emit a strict-JSON object body (no surrounding braces) from a stream
# of `key=value` lines on stdin. Each line becomes `"key": "value",`
# except the last, which omits the trailing comma. Skips blank lines so
# field emitters can use empty echos as visual separators if desired.
sarge_emit_drift_snapshot_json() {
  local lines=() pair k v
  while IFS= read -r pair; do
    [[ -z "$pair" ]] && continue
    k="${pair%%=*}"
    v="${pair#*=}"
    lines+=("    \"$k\": \"$v\"")
  done
  local n=${#lines[@]} i=0
  while [[ $i -lt $n ]]; do
    if [[ $i -lt $((n - 1)) ]]; then
      printf '%s,\n' "${lines[$i]}"
    else
      printf '%s\n' "${lines[$i]}"
    fi
    i=$((i + 1))
  done
}

# For each `key=value` line on stdin, invoke `check <key> <value>`. The
# `check` function must already be defined in the caller's scope (see
# drift/compare.sh). Unchanged from the per-platform loop it replaces.
sarge_emit_drift_check_calls() {
  local pair k v
  while IFS= read -r pair; do
    [[ -z "$pair" ]] && continue
    k="${pair%%=*}"
    v="${pair#*=}"
    check "$k" "$v"
  done
}
