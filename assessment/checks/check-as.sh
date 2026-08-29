#!/usr/bin/env bash
# check-as.sh — Agent Safety (AS) overlay — Oscar Six / OpenClaw
#
# The AS family is a Sarge-specific overlay on top of NIST 800-53. Each
# AS-N check maps to one or more Rev 5 controls (documented per-check in
# findings-catalog.json) but groups them under a single "agent safety"
# banner so operators see the tool-gate + attestation + workshop +
# cron-trust posture in one block rather than scattered across AC/AU/CM/SI.
#
# Positioning per `project_sarge_agent_safety_lens.md`: workspace ACLs,
# audit, and rollback are Tier 1 agent-safety; baseline OS hygiene is
# Tier 2. Everything in this file is Tier 1.
#
# All AS checks are agent-scoped (SARGE_HOST_ONLY skips the whole file).

if [[ "${SARGE_HOST_ONLY:-0}" != "1" ]]; then

  # ---------- AS-1: tool-gate installed ----------
  #
  # Verifies the tool-gate PreToolUse hook is present on disk AND wired
  # into ~/.claude/settings.json. Both halves matter: a hook file that
  # isn't referenced from settings never fires; a settings entry pointing
  # at a missing file blows up the runtime.
  #
  # Maps to: AC-3 (write gate enforcement), AC-6 (origin-scoped tools).
  log "AS-1: Tool-gate hook installation"
  TG_HOOK="$HOME/.claude/hooks/tool-gate.py"
  TR_HOOK="$HOME/.claude/hooks/taint-record.py"
  TG_SETTINGS="$HOME/.claude/settings.json"
  if [[ -f "$TG_HOOK" && -f "$TR_HOOK" ]]; then
    if [[ -f "$TG_SETTINGS" ]] && grep -q "tool-gate\.py" "$TG_SETTINGS" 2>/dev/null; then
      passx "AS-1-tool-gate-installed" "AS-1: tool-gate.py + taint-record.py present and referenced from ~/.claude/settings.json"
    elif [[ -f "$TG_SETTINGS" ]]; then
      failx "AS-1-tool-gate-installed" "AS-1: hook files present but not referenced from ~/.claude/settings.json — hook will not fire"
    else
      failx "AS-1-tool-gate-installed" "AS-1: hook files present but ~/.claude/settings.json missing — hook will not fire"
    fi
  else
    failx "AS-1-tool-gate-installed" "AS-1: tool-gate hook files missing at ~/.claude/hooks/ (need tool-gate.py AND taint-record.py)"
  fi

  # ---------- AS-2: gate mode ----------
  #
  # Reads ~/.config/o6-gate-mode. Values: shadow (log only), tier-c
  # (block worst tier), tier-bc (block tiers B and C). Missing file =
  # shadow-by-default = FAIL because a caller might assume tier-c and
  # act on it.
  #
  # Maps to: AC-3 (enforcement mode), CM-6 (config settings).
  log "AS-2: Tool-gate enforcement mode"
  MODE_FILE="$HOME/.config/o6-gate-mode"
  if [[ -f "$MODE_FILE" ]]; then
    MODE=$(tr -d '[:space:]' < "$MODE_FILE")
    case "$MODE" in
      tier-c|tier-bc)
        passx "AS-2-gate-mode" "AS-2: gate mode is '$MODE' (enforcing)"
        ;;
      shadow)
        warnx "AS-2-gate-mode" "AS-2: gate mode is 'shadow' — decisions logged but not enforced; graduate to 'tier-c' when clean-run window closes"
        ;;
      *)
        failx "AS-2-gate-mode" "AS-2: unknown gate mode '$MODE' at ~/.config/o6-gate-mode (expected shadow, tier-c, or tier-bc)"
        ;;
    esac
  else
    failx "AS-2-gate-mode" "AS-2: ~/.config/o6-gate-mode missing — gate has no explicit mode setting"
  fi

  # ---------- AS-3: decisions ledger ----------
  #
  # decisions.jsonl is tool-gate's audit trail. Must exist, be 600, and
  # not be stale (a ledger frozen for days means the hook isn't running).
  #
  # Maps to: AU-2 (auditable events), AU-9 (protection of audit info).
  log "AS-3: Tool-gate decisions ledger"
  LEDGER="$HOME/.openclaw/state/tool-gate/decisions.jsonl"
  if [[ -f "$LEDGER" ]]; then
    LEDGER_PERM=$(platform file_perm "$LEDGER")
    if [[ "$LEDGER_PERM" == "600" || "$LEDGER_PERM" == "400" ]]; then
      passx "AS-3-decisions-ledger-perm" "AS-3: decisions.jsonl permissions are $LEDGER_PERM"
    else
      failx "AS-3-decisions-ledger-perm" "AS-3: decisions.jsonl permissions are $LEDGER_PERM — should be 600 (contains taint decisions across every tool call)"
    fi
    # Freshness: file modified within the last 7 days is a reasonable
    # signal the hook is still firing on this host.
    LEDGER_AGE_DAYS=$(( ( $(date +%s) - $(stat -c '%Y' "$LEDGER" 2>/dev/null || stat -f '%m' "$LEDGER" 2>/dev/null || echo 0) ) / 86400 ))
    if [[ "$LEDGER_AGE_DAYS" -le 7 ]]; then
      passx "AS-3-decisions-ledger-fresh" "AS-3: decisions.jsonl last modified ${LEDGER_AGE_DAYS}d ago (hook active)"
    else
      warnx "AS-3-decisions-ledger-fresh" "AS-3: decisions.jsonl last modified ${LEDGER_AGE_DAYS}d ago — verify tool-gate hook is still firing"
    fi
  else
    failx "AS-3-decisions-ledger-perm" "AS-3: decisions ledger missing at ~/.openclaw/state/tool-gate/decisions.jsonl — hook may never have run"
  fi

  # ---------- AS-4: daily digest cron ----------
  #
  # gate-digest.sh --post runs daily, summarizes would-block events, and
  # posts to Discord. Without it, the shadow-mode signal is invisible.
  #
  # Maps to: SI-4 (system monitoring), AU-6 (audit review).
  log "AS-4: Tool-gate daily digest cron"
  if command -v crontab &>/dev/null; then
    if crontab -l 2>/dev/null | grep -Eq "^[^#]*gate-digest\.sh"; then
      passx "AS-4-digest-cron" "AS-4: gate-digest.sh cron entry registered"
    else
      failx "AS-4-digest-cron" "AS-4: gate-digest.sh not in crontab — daily would-block summary will not post"
    fi
  else
    skipx "AS-4-digest-cron" "AS-4: crontab command not available — cannot verify digest cron"
  fi

  # ---------- AS-5: gate_common.py integrity ----------
  #
  # SENSITIVE_WRITE_PATHS and taint promotion logic live in gate_common.py.
  # A tampered copy could silently narrow the gate. Compares the deployed
  # ~/.claude/hooks/gate_common.py against the upstream reference at
  # ~/openclaw/security/tool-gate/gate_common.py — SKIP if either is
  # missing (test-only hosts, sandbox hosts) rather than FAIL, so this
  # check doesn't fire on installs that use a different distribution mode.
  #
  # Maps to: SI-7 (software integrity), CM-6 (config settings).
  log "AS-5: gate_common.py integrity"
  GC_DEPLOYED="$HOME/.claude/hooks/gate_common.py"
  GC_UPSTREAM="$HOME/openclaw/security/tool-gate/gate_common.py"
  if [[ -f "$GC_DEPLOYED" && -f "$GC_UPSTREAM" ]]; then
    if [[ "$(sha256sum "$GC_DEPLOYED" 2>/dev/null | awk '{print $1}')" == "$(sha256sum "$GC_UPSTREAM" 2>/dev/null | awk '{print $1}')" ]]; then
      passx "AS-5-gate-common-integrity" "AS-5: deployed gate_common.py matches upstream reference"
    else
      failx "AS-5-gate-common-integrity" "AS-5: deployed gate_common.py DIFFERS from upstream — inspect for tampering (diff ~/.claude/hooks/gate_common.py ~/openclaw/security/tool-gate/gate_common.py)"
    fi
  else
    skipx "AS-5-gate-common-integrity" "AS-5: cannot compare gate_common.py — deployed or upstream copy missing (host may use a different distribution)"
  fi

  # ---------- AS-6: workspace attestations ----------
  #
  # workspace-attestations/ records signed attestations of workspace
  # canon (SOUL.md, USER.md, AGENTS.md). Directory should exist, be 700,
  # and hold at least one attestation not older than 30 days.
  #
  # Maps to: CM-2 (baseline configuration), SI-7 (software integrity).
  log "AS-6: Workspace attestations"
  ATT_DIR="$HOME/.openclaw/workspace-attestations"
  if [[ -d "$ATT_DIR" ]]; then
    ATT_PERM=$(platform file_perm "$ATT_DIR")
    if [[ "$ATT_PERM" == "700" ]]; then
      passx "AS-6-attestations-dir-perm" "AS-6: workspace-attestations/ permissions are 700"
    else
      failx "AS-6-attestations-dir-perm" "AS-6: workspace-attestations/ permissions are $ATT_PERM — should be 700"
    fi
    # Freshness: at least one attestation modified in the last 30 days.
    NEWEST_ATT=$(find "$ATT_DIR" -maxdepth 1 -type f -name "*.attested" -printf '%T@\n' 2>/dev/null | sort -n | tail -1)
    if [[ -n "$NEWEST_ATT" ]]; then
      ATT_AGE_DAYS=$(( ( $(date +%s) - ${NEWEST_ATT%.*} ) / 86400 ))
      if [[ "$ATT_AGE_DAYS" -le 30 ]]; then
        passx "AS-6-attestations-fresh" "AS-6: newest workspace attestation is ${ATT_AGE_DAYS}d old"
      else
        warnx "AS-6-attestations-fresh" "AS-6: newest workspace attestation is ${ATT_AGE_DAYS}d old — refresh so drift signal stays meaningful"
      fi
    else
      warnx "AS-6-attestations-fresh" "AS-6: no *.attested files in workspace-attestations/ — no baseline captured for drift comparison"
    fi
  else
    warnx "AS-6-attestations-dir-perm" "AS-6: workspace-attestations/ missing at ~/.openclaw/ — install or trigger a workspace attestation run"
  fi

  # ---------- AS-7: skill-workshop review gate ----------
  #
  # skill-workshop/ is the review-gated ingestion path for new skills.
  # Presence alone is the useful signal today; enable/disable is
  # authoritatively read from openclaw.json (out of scope for this check
  # in v1). Warn on missing so operators know the primitive isn't
  # available on their install.
  #
  # Maps to: CM-5 (access restrictions for change), CM-7 (least functionality).
  log "AS-7: Skill-workshop review gate"
  WS_DIR="$HOME/.openclaw/skill-workshop"
  if [[ -d "$WS_DIR" ]]; then
    WS_PROPOSALS_DIR="$WS_DIR/proposals"
    if [[ -d "$WS_PROPOSALS_DIR" ]]; then
      passx "AS-7-workshop-present" "AS-7: skill-workshop/ + proposals/ subdirectory present — review gate available"
    else
      warnx "AS-7-workshop-present" "AS-7: skill-workshop/ present but proposals/ subdirectory missing — review queue not initialized"
    fi
  else
    warnx "AS-7-workshop-present" "AS-7: skill-workshop/ missing at ~/.openclaw/ — review gate for new skills is not enabled on this install"
  fi

  # ---------- AS-8: cron-trust registration ----------
  #
  # cron-trust.json holds the allowlist for cron jobs whose actions
  # tool-gate should treat as trusted-origin (not external). Every non-
  # comment crontab line that runs an openclaw / claude / gateway job
  # needs a CRON_JOB_NAME marker AND a matching entry, or tool-gate
  # treats it as untrusted and blocks Tier-B/C actions. Memory:
  # `feedback_cron_jobs_need_gate_registration.md`.
  #
  # Maps to: CM-6 (config settings), AU-2 (auditable events).
  log "AS-8: cron-trust registration"
  CT_FILE="$HOME/.openclaw/state/tool-gate/cron-trust.json"
  if [[ -f "$CT_FILE" ]]; then
    CT_PERM=$(platform file_perm "$CT_FILE")
    if [[ "$CT_PERM" == "600" || "$CT_PERM" == "400" ]]; then
      passx "AS-8-cron-trust-perm" "AS-8: cron-trust.json permissions are $CT_PERM"
    else
      failx "AS-8-cron-trust-perm" "AS-8: cron-trust.json permissions are $CT_PERM — should be 600"
    fi
    # Registration coverage: every non-comment crontab entry that
    # references an openclaw / claude / gateway pathname must set a
    # CRON_JOB_NAME variable. We can't verify each name lands in the
    # trust file (job names are per-line env vars, not standalone
    # tokens), but we can flag lines that mention the runtime and lack
    # the marker.
    if command -v crontab &>/dev/null; then
      UNREGISTERED=$(crontab -l 2>/dev/null | awk '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*$/ { next }
        /openclaw|claude|gateway/ {
          if ($0 !~ /CRON_JOB_NAME/) print $0
        }
      ' | head -5)
      if [[ -z "$UNREGISTERED" ]]; then
        passx "AS-8-cron-trust-coverage" "AS-8: every runtime-related crontab entry declares CRON_JOB_NAME"
      else
        warnx "AS-8-cron-trust-coverage" "AS-8: crontab entries reference the runtime without CRON_JOB_NAME (first 5): $(echo "$UNREGISTERED" | tr '\n' '|')"
      fi
    else
      skipx "AS-8-cron-trust-coverage" "AS-8: crontab command not available — cannot verify per-entry registration"
    fi
  else
    failx "AS-8-cron-trust-perm" "AS-8: cron-trust.json missing at ~/.openclaw/state/tool-gate/ — every cron job is treated as untrusted-origin"
  fi

fi
