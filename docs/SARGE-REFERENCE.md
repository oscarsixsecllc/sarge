# Sarge — Deep Reference Document

> **Version:** 0.7.0 | **Publisher:** Oscar Six Security LLC | **License:** Apache 2.0
> **Focus Forward. We've Got Your Six.**

This document is a comprehensive technical reference for the Sarge codebase. It is designed to let any developer or AI agent cold-start into the project without reading every file.

---

## Table of Contents

1. [Mission & Threat Model](#mission--threat-model)
2. [Architecture Overview](#architecture-overview)
3. [Tech Stack](#tech-stack)
4. [Platform Support Matrix](#platform-support-matrix)
5. [File Map](#file-map)
6. [CLI Commands & Entry Points](#cli-commands--entry-points)
7. [Assessment Engine (Gap Analysis)](#assessment-engine-gap-analysis)
8. [Check Categories & NIST 800-53 Control Mapping](#check-categories--nist-800-53-control-mapping)
9. [Findings Catalog](#findings-catalog)
10. [Report Generation](#report-generation)
11. [Hardening Scripts](#hardening-scripts)
12. [Drift Detection](#drift-detection)
13. [Pre-Hardening Backup & Rollback](#pre-hardening-backup--rollback)
14. [Platform Abstraction Layer](#platform-abstraction-layer)
15. [Windows Assessment Engine](#windows-assessment-engine)
16. [Policy Overlay (Windows Phase 1b)](#policy-overlay-windows-phase-1b)
17. [Configuration & Baseline](#configuration--baseline)
18. [OpenClaw Integration (Skill)](#openclaw-integration-skill)
19. [Testing](#testing)
20. [Deployment & Packaging](#deployment--packaging)
21. [Exit Code Contract](#exit-code-contract)
22. [Hard Rules & Conventions](#hard-rules--conventions)
23. [Roadmap & Issue Tracker](#roadmap--issue-tracker)

---

## Mission & Threat Model

Sarge is an **agent-safety control** for OpenClaw deployments, not a generic OS hardening kit.

The primary use case: verify that a host running OpenClaw (or another AI agent) meets an 800-53 baseline **before** the agent is allowed to make autonomous changes. The risk isn't abstract "this laptop has CVE-X open" — it's "an agent with shell access is about to act on a system whose posture we haven't verified, and a wrong action against a weak baseline cascades into incident territory."

**Two-phase safety net:**
1. **Pre-flight (Sarge):** Assess the host against NIST 800-53 Rev 5. Surface gaps before the agent gets the keys.
2. **Post-action recovery (rollback/restore):** When the agent makes the wrong change, the rollback path is the safety net. Drift detection feeds this — drift is the signal that recovery may be needed.

**Check prioritization (Tier system from memory):**
- **Tier 1 — Agent-safety controls:** Workspace ACLs, audit trail for agent actions, rollback capability, secrets directory permissions. These are the controls that directly contain agent risk.
- **Tier 2 — Baseline hygiene:** Password policy, firewall, ClamAV, unattended-upgrades, SSH hardening. These form the surrounding baseline that makes Tier 1 controls meaningful. Weak workspace ACLs let one compromised tool exfiltrate secrets; missing audit means an agent's wrong action is invisible.

---

## Architecture Overview

Sarge is a pure-shell (bash + PowerShell) project with zero runtime dependencies beyond the target OS's built-in tools. No Node.js, no Python (used only for optional JSON parsing in report generation), no external APIs.

```
┌─────────────────────────────────────────────────────────┐
│                    Entry Points                          │
│  assess.sh (Linux/macOS)    assess.ps1 (Windows)        │
│  install.sh                 snapshot.sh / compare.sh     │
└────────────┬────────────────────────┬───────────────────┘
             │                        │
    ┌────────▼────────┐      ┌────────▼────────┐
    │ Platform Layer  │      │ Platform Layer  │
    │ lib/platform.sh │      │ lib/platform.ps1│
    │ lib/platforms/  │      │ lib/findings.ps1│
    │   _dispatch.sh  │      │ lib/probes/     │
    │   ubuntu.sh     │      │   windows-*.ps1 │
    │   macos.sh      │      │ lib/policy-     │
    └────────┬────────┘      │   overlay.ps1   │
             │               └────────┬────────┘
    ┌────────▼────────┐      ┌────────▼────────┐
    │  Check Scripts  │      │  Check Scripts  │
    │  checks/        │      │  checks/        │
    │  check-ac.sh    │      │  check-ac.ps1   │
    │  check-au.sh    │      │  check-au.ps1   │
    │  check-cm.sh    │      │  check-cm.ps1   │
    │  check-ia.sh    │      │  check-ia.ps1   │
    │  check-sc.sh    │      │  check-sc.ps1   │
    │  check-si.sh    │      │  check-si.ps1   │
    └────────┬────────┘      └────────┬────────┘
             │                        │
    ┌────────▼────────┐      ┌────────▼────────┐
    │ Report Engine   │      │ Report Engine   │
    │ report/         │      │ report/         │
    │  report.sh      │      │  build-report   │
    │                 │      │    .ps1         │
    └─────────────────┘      └─────────────────┘
```

**Key architectural decisions:**
- Platform-specific data acquisition is separated from 800-53 control logic. Check scripts contain assertions and verdicts; platform files contain probes.
- The dispatcher pattern (`platform <probe>`) allows check scripts to be platform-agnostic. Missing probes return exit 127 (not implemented), which routes to a `skipx` with a platform-aware rationale.
- All state lives under `~/.sarge/` (reports, snapshots, runs, state counters).
- Per-run folders (`~/.sarge/runs/<run-id>/`) are self-contained: each run gets its own report.md, report.json, findings.json, and optionally drift-snapshot.json, drift-report.json, and backup/.

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Assessment engine (Linux/macOS) | Bash (POSIX-compatible where possible) |
| Assessment engine (Windows) | PowerShell 5.1+ / PowerShell 7+ |
| Platform probes (Linux) | GNU coreutils, systemctl, apt, auditctl, ss, ufw |
| Platform probes (macOS) | BSD coreutils, dscl, launchctl, socketfilterfw, lsof |
| Platform probes (Windows) | CIM cmdlets, dsregcmd, gpresult, Get-MpComputerStatus, Get-AppLockerPolicy |
| Report generation | Bash (jq preferred, python3 fallback, grep last-resort) |
| Report generation (Windows) | PowerShell (ConvertTo-Json) |
| Integrity verification | sha256sum (GNU) / shasum (BSD) |
| Drift comparison | python3 one-liner for JSON field extraction |
| CI | GitHub Actions (Pester on windows-latest) |
| Test framework (Windows) | Pester 5.5+ |
| Test framework (Linux/macOS) | Shell integration tests (bash scripts) |
| Container image | Ubuntu 26.04 + Node 22 (Dockerfile.hardened) |

---

## Platform Support Matrix

| Platform | Gap Analysis | Hardening | Drift Detection | Backup/Rollback |
|----------|-------------|-----------|----------------|-----------------|
| Ubuntu 22.04 LTS | Full (47 controls) | Full (6 modules) | Full | Full (#29) |
| Ubuntu 24.04 LTS | Full (47 controls) | Full (6 modules) | Full | Full (#29) |
| macOS (any version) | Full (platform-aware skips) | Partial (3 modules) | Full | Spec'd, untested (#30) |
| Windows (any) | Full (Phase 1a + 1b) | Blocked on backup (#28) | N/A | Spec'd (#28) |

---

## File Map

### Root

| File | Purpose |
|------|---------|
| `README.md` | Project documentation, quickstart, control coverage tables |
| `SKILL.md` | OpenClaw skill definition for ClawhHub |
| `CHECKSUMS.sha256` | Integrity verification hashes for all scripts |
| `CHANGELOG.md` | Version history |
| `CONTRIBUTING.md` | Contribution guidelines |
| `CODE_OF_CONDUCT.md` | Community standards |
| `SECURITY.md` | Vulnerability disclosure policy |
| `LICENSE` | Apache 2.0 |
| `Dockerfile.hardened` | QA test environment (Ubuntu 26.04 + Node 22) |
| `Dockerfile.qa` | Additional QA image |

### `assessment/` — Gap Analysis Engine

| File | Purpose |
|------|---------|
| `assess.sh` | **Main entry point** (Linux/macOS). Sources platform libs, runs all check-*.sh, generates reports. |
| `assess.ps1` | **Main entry point** (Windows). Loads probes, runs check-*.ps1, builds report. |
| `findings-catalog.json` | Per-finding rationale catalog. Maps check_id → family, what, expected, why, fix. |
| `checks/check-ac.sh` | Access Control checks (AC-2, AC-3, AC-6, AC-17) |
| `checks/check-au.sh` | Audit & Accountability checks (AU-2, AU-3, AU-4, AU-5, AU-7, AU-8, AU-9, AU-11, AU-12) |
| `checks/check-cm.sh` | Configuration Management checks (CM-2, CM-6, CM-7) |
| `checks/check-ia.sh` | Identification & Authentication checks (IA-2, IA-5) |
| `checks/check-sc.sh` | System & Communications Protection checks (SC-8, SC-28) |
| `checks/check-si.sh` | System & Information Integrity checks (SI-2, SI-3, SI-7) |
| `checks/check-ac.ps1` | Windows AC checks |
| `checks/check-au.ps1` | Windows AU checks |
| `checks/check-cm.ps1` | Windows CM checks |
| `checks/check-ia.ps1` | Windows IA checks |
| `checks/check-sc.ps1` | Windows SC checks |
| `checks/check-si.ps1` | Windows SI checks |
| `checks/check-policy.ps1` | Windows policy overlay checks (Phase 1b) |
| `probes/detect-context.ps1` | Windows enterprise context detection probe |
| `report/report.sh` | Markdown + JSON report generator (Linux/macOS) |
| `report/build-report.ps1` | Report builder (Windows) |

### `lib/` — Platform Abstraction & Shared Libraries

| File | Purpose |
|------|---------|
| `platform.sh` | OS detection: exports `SARGE_OS`, `SARGE_OS_VERSION`, `SARGE_OS_DESCRIPTION`. Gates: `sarge_require_supported_os`, `sarge_require_os`. |
| `platform.ps1` | Windows context detection: `Get-SargeWindowsContext` → enterprise context JSON (dsregcmd, GPO, AppLocker, WDAC, Defender, edition, OpenClaw path). |
| `findings.ps1` | Windows finding emission: `Add-SargeFinding`, `Get-SargeContext`, `Invoke-SargeCheck`. Verdict vocabulary: PASS, FAIL, WARN, SKIP-CONTEXT-DEFERRED, ENFORCED-EXTERNALLY, UNTESTED. |
| `policy-overlay.ps1` | `Apply-PolicyOverlay` — re-verdicts Phase 1a FAIL/WARN → ENFORCED-EXTERNALLY when managed policy enforces the control. |
| `platforms/_dispatch.sh` | Cross-platform dispatcher: `platform <probe> [args...]` calls `${SARGE_OS}_<probe>`. `platform_supports <probe>` checks existence. Shared drift field helpers. |
| `platforms/ubuntu.sh` | Ubuntu probe implementations (35+ functions). |
| `platforms/macos.sh` | macOS probe implementations (20+ functions). Intentionally missing probes for auditd, pwquality, faillock, package management → routes to skipx. |
| `probes/windows-ac.ps1` | Windows Access Control probes |
| `probes/windows-au.ps1` | Windows Audit probes |
| `probes/windows-cm.ps1` | Windows Configuration Management probes |
| `probes/windows-ia.ps1` | Windows Identification & Authentication probes |
| `probes/windows-sc.ps1` | Windows System & Communications Protection probes |
| `probes/windows-si.ps1` | Windows System & Information Integrity probes |
| `probes/windows-policy.ps1` | Windows policy probe (Phase 1b): `Get-SargeHostPolicyMode`, `Get-SargeMdmPolicyInventory`, `Get-SargeAdGpoData`, `Get-SargeGpresultData` |

### `scripts/` — Hardening Modules

| File | Platform | Sudo? | NIST Controls |
|------|----------|-------|---------------|
| `install.sh` | Ubuntu, macOS | Yes | All — orchestrator |
| `harden-permissions.sh` | Ubuntu, macOS | **No** (runs as invoking user) | AC-3, SC-28 |
| `harden-pam.sh` | Ubuntu only | Yes | IA-2, IA-5 |
| `harden-auditd.sh` | Ubuntu only | Yes | AU-2, AU-9, AU-12 |
| `harden-fail2ban.sh` | Ubuntu only | Yes | SI-3, AC-17 |
| `harden-ufw.sh` | Ubuntu only | Yes | AC-17 |
| `harden-systemd.sh` | Ubuntu only | Yes | CM-7 |
| `harden-firewall-macos.sh` | macOS only | Yes | AC-17 |
| `harden-ssh-macos.sh` | macOS only | Yes | CM-7 |
| `backup-ubuntu.sh` | Ubuntu only | Mixed | Pre-hardening backup |
| `backup-macos.sh` | macOS only | Yes | Pre-hardening backup |
| `backup-windows.ps1` | Windows only | Yes | Pre-hardening backup |
| `rollback-ubuntu.sh` | Ubuntu only | Mixed | Rollback |
| `rollback-macos.sh` | macOS only | Yes | Rollback |
| `rollback-windows.ps1` | Windows only | Yes | Rollback |

### `drift/` — Drift Detection

| File | Purpose |
|------|---------|
| `snapshot.sh` | Capture baseline snapshot → `~/.sarge/snapshots/snapshot-<ts>.json` + `latest.json` symlink |
| `compare.sh` | Compare current state vs latest snapshot. Exit 0 = no drift, exit 2 = drift detected. |
| `drift-cron.sh` | Cron wrapper for compare.sh. Logs to `~/.sarge/drift.log`, notifies via OpenClaw on drift. |

### `baseline/` — Reference Configurations

| File | Purpose |
|------|---------|
| `controls.json` | Machine-readable NIST 800-53 control mapping (23 controls, per-control OpenClaw settings + OS checks + remediation) |
| `controls.md` | Human-readable control mapping (same content, Markdown format) |
| `openclaw.json.baseline` | Hardened OpenClaw configuration baseline with inline 800-53 control annotations |

### `tests/` — Test Suites

| File | Purpose |
|------|---------|
| `integration/drift-detection.sh` | Snapshot → compare → verify pipeline |
| `integration/report-validation.sh` | Runs assessment, validates JSON/MD output structure |
| `integration/hardening-roundtrip.sh` | Assess → harden UFW → reassess → verify fix (needs NET_ADMIN) |
| `integration/host-only-mode.sh` | Validates --host-only excludes agent findings |
| `integration/backup-ubuntu-smoke.sh` | Ubuntu backup script smoke test |
| `integration/backup-macos-smoke.sh` | macOS backup script smoke test (dry-run on Linux) |
| `integration/catalog-platform-field.sh` | Validates per-platform fields in findings-catalog.json |
| `Pester/windows-*.Tests.ps1` | Pester unit tests for all 6 Windows control families + policy + backup (mocked cmdlets) |

### `docs/` — Documentation

| File | Purpose |
|------|---------|
| `quickstart.md` | Getting started guide |
| `accepted-risks.md` | Documented risk acceptances |
| `sarge-agent.md` | Agent integration documentation |
| `SARGE-REFERENCE.md` | This document |

---

## CLI Commands & Entry Points

### Gap Analysis

```bash
# Linux/macOS — full agent-host mode (default)
./assessment/assess.sh

# Linux/macOS — host-only mode (no agent-runtime checks)
./assessment/assess.sh --host-only

# Windows
pwsh assessment/assess.ps1
pwsh assessment/assess.ps1 --host-only
pwsh assessment/assess.ps1 --inspect-policy    # Phase 1b: probe managed policy
pwsh assessment/assess.ps1 --checks-only       # Skip detection, reuse existing context
pwsh assessment/assess.ps1 --report-only       # Rebuild report from last findings JSON
```

### Hardening

```bash
# Interactive installer (prompts per module)
sudo ./scripts/install.sh

# Individual modules
bash scripts/harden-permissions.sh       # NO sudo (uses $HOME)
sudo bash scripts/harden-pam.sh          # Ubuntu only
sudo bash scripts/harden-auditd.sh       # Ubuntu only
sudo bash scripts/harden-fail2ban.sh     # Ubuntu only
sudo bash scripts/harden-ufw.sh          # Ubuntu only
sudo bash scripts/harden-systemd.sh      # Ubuntu only
sudo bash scripts/harden-firewall-macos.sh  # macOS only
sudo bash scripts/harden-ssh-macos.sh       # macOS only
```

### Drift Detection

```bash
# Capture baseline
./drift/snapshot.sh

# Compare against baseline
./drift/compare.sh

# Cron-friendly wrapper (logs + notifies)
./drift/drift-cron.sh

# Suggested cron entry:
# 0 6 * * * /path/to/sarge/drift/drift-cron.sh >> /var/log/sarge-drift.log 2>&1
```

### Backup & Rollback

```bash
# Ubuntu
bash scripts/backup-ubuntu.sh --run-id "$SARGE_RUN_ID"
bash scripts/backup-ubuntu.sh --unattended --run-id "$SARGE_RUN_ID"
bash scripts/rollback-ubuntu.sh                  # latest run
bash scripts/rollback-ubuntu.sh --run-id <id>     # specific run

# macOS
bash scripts/backup-macos.sh --run-id "$SARGE_RUN_ID"
bash scripts/rollback-macos.sh --latest

# Windows
pwsh scripts/backup-windows.ps1
pwsh scripts/rollback-windows.ps1 -BackupDir "$env:USERPROFILE\.sarge\runs\<id>\backup"
```

---

## Assessment Engine (Gap Analysis)

### Linux/macOS (`assess.sh`)

**Flow:**
1. Source `lib/platform.sh` — detect OS, version, validate support matrix
2. Source `lib/platforms/_dispatch.sh` — load platform-specific probes
3. Initialize state: report dir (`~/.sarge/reports/`), state dir (`~/.sarge/state/`), per-run dir (`~/.sarge/runs/<run-id>/`)
4. Initialize counters: `PASS=0; WARN=0; FAIL=0; SKIP=0`
5. Export verdict helper functions: `pass`, `warn`, `fail`, `skip` (legacy, no check_id) and `passx`, `warnx`, `failx`, `skipx` (structured, with check_id)
6. Set scan mode: `agent-host` (default) or `host-only` (via `--host-only`)
7. Source each `checks/check-*.sh` — they call verdict helpers which accumulate results in `RESULTS` array
8. Pass accumulated results to `report/report.sh` for Markdown + JSON generation

**Result format (internal):** Each result is a pipe-delimited string: `STATUS|check_id|description`
- Legacy helpers emit: `STATUS||description` (empty check_id)
- Structured helpers emit: `STATUS|check_id|description`

**Key functions in assess.sh:**
- `log()` — prefixed output: `[SARGE] message`
- `pass(desc)` / `warn(desc)` / `fail(desc)` / `skip(desc)` — legacy verdict helpers
- `passx(id, desc)` / `warnx(id, desc)` / `failx(id, desc)` / `skipx(id, desc)` — structured verdict helpers with catalog-joinable check_id

**Environment variables:**
- `SARGE_HOST_ONLY=1` — host-only mode (also set via `--host-only`)
- `SARGE_REPORT_DIR` — override report output directory
- `SARGE_STATE_DIR` — override state directory
- `SARGE_RUN_ID` — override run identifier
- `SARGE_RUN_ROOT` — override per-run directory
- `SARGE_VERBOSE=1` — show skip messages from `sarge_require_os`

### Windows (`assess.ps1`)

**Flow:**
1. Dot-source `lib/platform.ps1`, `lib/findings.ps1`, `lib/policy-overlay.ps1`, `report/build-report.ps1`
2. Dot-source all 6 family probes from `lib/probes/windows-*.ps1`
3. Run detection probe (`probes/detect-context.ps1`) → writes `windows-context.json`
4. If `--inspect-policy`: run policy probe → populate policy inventory
5. If `--inspect-policy`: run `checks/check-policy.ps1` first
6. Source each `checks/check-*.ps1` — they call `Add-SargeFinding` / `Invoke-SargeCheck`
7. If `--inspect-policy`: apply `Apply-PolicyOverlay` to mutate FAIL/WARN → ENFORCED-EXTERNALLY
8. Call `Build-SargeReport` → generates Markdown + JSON + findings.json

**Key functions:**
- `Add-SargeFinding -Id -Family -ControlId -Verdict -Message [-Recommendation]` — emit one finding
- `Invoke-SargeCheck -Id -Family -ControlId -Check { ... }` — run a check with error capture (throws → UNTESTED)
- `Get-SargeContext` — load previously-written windows-context.json
- `Get-SargeWindowsContext` — detect enterprise context (dsregcmd, CIM, AppLocker, WDAC, Defender)

**Verdict vocabulary (Windows):**
- `PASS` — meets baseline
- `FAIL` — violates baseline
- `WARN` — suspicious / review
- `SKIP-CONTEXT-DEFERRED` — not evaluable locally
- `ENFORCED-EXTERNALLY` — managed policy (MDM/GPO) enforces the control
- `UNTESTED` — probe ambiguous / errored

---

## Check Categories & NIST 800-53 Control Mapping

### AC — Access Control (8 checks on Linux/macOS)

| Check ID | Control | What it checks |
|----------|---------|---------------|
| `AC-2-empty-password` | AC-2 | Accounts with empty password fields |
| `AC-2-uid-zero` | AC-2 | Non-root accounts with UID 0 |
| `AC-3-openclaw-dir-perm` | AC-3 | `~/.openclaw` directory is 700 (agent-scoped) |
| `AC-3-secrets-dir-perm` | AC-3 | `~/.openclaw/secrets` directory is 700 (agent-scoped) |
| `AC-3-secret-file-perm` | AC-3 | Individual secret files are 600 (agent-scoped) |
| `AC-6-passwordless-sudo` | AC-6 | NOPASSWD sudo for current user |
| `AC-6-user-in-sudo-group` | AC-6 | Current user in sudo/admin group |
| `AC-17-ufw-inactive` | AC-17 | Host firewall active |
| `AC-17-ufw-not-installed` | AC-17 | Firewall command available |
| `AC-17-external-ports` | AC-17 | Externally-listening TCP ports |

### AU — Audit & Accountability (13 checks on Linux/macOS)

| Check ID | Control | What it checks |
|----------|---------|---------------|
| `AU-2-auditd-not-running` | AU-2 | Audit daemon running |
| `AU-2-journald-inactive` | AU-2 | System logger (journald) active |
| `AU-2-journal-not-persisted` | AU-2 | Journal logs persisted to disk |
| `AU-4-log-storage` | AU-4 | Audit log partition has adequate free space (>10%) |
| `AU-5-audit-failure-response` | AU-5 | auditd disk_full_action / admin_space_left_action not IGNORE |
| `AU-7-log-tooling` | AU-7 | Log query/aggregation tooling available (journalctl, ausearch, syslog forwarding) |
| `AU-8-time-sync` | AU-8 | System clock synchronized via NTP |
| `AU-9-audit-log-bad-owner` | AU-9 | audit.log owned by root |
| `AU-9-audit-log-perm` | AU-9 | audit.log permissions are 600 |
| `AU-9-audit-log-missing` | AU-9 | audit.log exists when daemon is running |
| `AU-11-log-retention` | AU-11 | logrotate retention for audit logs (>= 4 cycles) |
| `AU-12-no-openclaw-rules` | AU-12 | Audit rules cover OpenClaw secrets (agent-scoped) |
| `AU-12-no-auth-rules` | AU-12 | Audit rules cover /etc/passwd, shadow, sudoers |

### CM — Configuration Management (10 checks on Linux/macOS)

| Check ID | Control | What it checks |
|----------|---------|---------------|
| `CM-2-no-baseline` | CM-2 | Sarge baseline file exists |
| `CM-6-unattended-not-installed` | CM-6 | unattended-upgrades installed |
| `CM-6-unattended-not-configured` | CM-6 | unattended-upgrades configured |
| `CM-6-pending-updates-low` | CM-6 | 1-5 pending package updates |
| `CM-6-pending-updates-high` | CM-6 | >5 pending package updates |
| `CM-7-risky-service-running` | CM-7 | Deny-listed service running |
| `CM-7-risky-service-enabled` | CM-7 | Deny-listed service enabled |
| `CM-7-ssh-permit-root` | CM-7 | SSH PermitRootLogin disabled |
| `CM-7-ssh-password-auth` | CM-7 | SSH PasswordAuthentication disabled |

### IA — Identification & Authentication (10 checks on Linux/macOS)

| Check ID | Control | What it checks |
|----------|---------|---------------|
| `IA-5-pass-max-days` | IA-5 | PASS_MAX_DAYS ≤ 90 |
| `IA-5-pass-min-days` | IA-5 | PASS_MIN_DAYS ≥ 1 |
| `IA-5-pass-warn-age` | IA-5 | PASS_WARN_AGE ≥ 7 |
| `IA-5-pwquality-minlen` | IA-5 | pwquality minlen ≥ 12 |
| `IA-5-pwquality-credit` | IA-5 | pwquality dcredit/ucredit/ocredit/lcredit set |
| `IA-5-pwquality-missing` | IA-5 | pwquality.conf exists |
| `IA-2-faillock-not-configured` | IA-2 | pam_faillock in PAM stack |
| `IA-2-faillock-deny` | IA-2 | faillock deny ≤ 5 |
| `IA-2-faillock-unlock-time` | IA-2 | faillock unlock_time ≥ 1800s |
| `IA-2-faillock-conf-missing` | IA-2 | faillock.conf exists |
| `IA-2-tmout-unset` | IA-2 | TMOUT session timeout configured |

### SC — System & Communications Protection (6 checks, partial)

| Check ID | Control | What it checks |
|----------|---------|---------------|
| `SC-8-cloudflared-not-detected` | SC-8 | Gateway TLS via cloudflared or direct (agent-scoped) |
| `SC-28-config-perm` | SC-28 | config.json permissions 600/400 (agent-scoped) |
| `SC-28-config-owner` | SC-28 | config.json owned by service user (agent-scoped) |
| `SC-28-world-readable-secrets` | SC-28 | No world-readable files in ~/.openclaw (agent-scoped) |

### SI — System & Information Integrity (5 checks, partial)

| Check ID | Control | What it checks |
|----------|---------|---------------|
| `SI-2-security-updates-low` | SI-2 | 1-3 security updates pending |
| `SI-2-security-updates-high` | SI-2 | >3 security updates pending |
| `SI-3-clamav-not-installed` | SI-3 | ClamAV installed |
| `SI-3-clamav-daemon-stopped` | SI-3 | ClamAV daemon running |
| `SI-3-freshclam-stopped` | SI-3 | freshclam (signature updater) running |
| `SI-3-fail2ban-not-running` | SI-3 | fail2ban running with jails |
| `SI-7-checksum-mismatch` | SI-7 | Sarge script checksums verified |

### Windows-Specific Checks (WIN- prefix)

The Windows assessment covers all 6 families with 30+ checks. Key additions beyond the Linux/macOS set:

| Check ID | Control | What it checks |
|----------|---------|---------------|
| `WIN-AC-3-workspace-acl` | AC-3 | OpenClaw workspace ACL restricted |
| `WIN-AC-6-admin-group` | AC-6 | Local Administrators group membership |
| `WIN-AC-7-lockout-threshold` | AC-7 | Account lockout threshold 1-10 |
| `WIN-AC-8-legal-banner` | AC-8 | Logon banner text set |
| `WIN-AC-11-idle-lock` | AC-11 | Screen saver timeout + re-auth |
| `WIN-AC-12-session-termination` | AC-12 | SMB autodisconnect ≤ 15 min |
| `WIN-AC-17-rdp-posture` | AC-17 | RDP NLA + encryption + security layer |
| `WIN-AU-2-audit-policy` | AU-2 | Required audit categories enabled |
| `WIN-AU-3-sysmon-config` | AU-3 | Sysmon configuration present |
| `WIN-AU-4-log-retention` | AU-4 | Event log channel sizes ≥ 64 MB |
| `WIN-AU-6-event-forwarding` | AU-6 | WEF SubscriptionManager configured |
| `WIN-AU-8-time-config` | AU-8 | W32Time sync mode valid |
| `WIN-AU-9-security-log-acl` | AU-9 | Security.evtx ACL restricted |
| `WIN-CM-2-baseline-drift` | CM-2 | Config drift vs stored baseline |
| `WIN-CM-6-smbv1` | CM-6 | SMBv1 disabled |
| `WIN-CM-6-legacy-services` | CM-6 | Legacy services stopped |
| `WIN-CM-7-unnecessary-services` | CM-7 | CIS L1 services disabled |
| `WIN-CM-8-software-inventory` | CM-8 | Software inventory captured |
| `WIN-CM-11-user-installed-software` | CM-11 | Per-user installs governed |
| `WIN-IA-2-account-types` | IA-2/AC-2 | MSA accounts flagged |
| `WIN-IA-3-device-id` | IA-3 | TPM + Secure Boot present |
| `WIN-IA-5-password-policy` | IA-5 | Local password policy baselines |
| `WIN-IA-5-complexity` | IA-5 | Password complexity + no reversible encryption |
| `WIN-IA-11-reauth` | IA-11 | Inactivity timeout ≤ 900s |
| `WIN-IA-12-windows-hello` | IA-12 | Windows Hello credentials present |
| `WIN-SC-2-uac` | SC-2 | UAC enabled with consent prompt |
| `WIN-SC-7-firewall-profiles` | SC-7 | All 3 firewall profiles enabled |
| `WIN-SC-7-listening-ports` | SC-7 | 0.0.0.0/:: listeners reviewed |
| `WIN-SC-8-smb-signing` | SC-8 | SMB signing required |
| `WIN-SC-12-key-mgmt` | SC-12 | LSA Protection + Credential Guard |
| `WIN-SC-13-bitlocker` | SC-13 | BitLocker on OS volume |
| `WIN-SC-23-ldap-ntlm` | SC-23 | LDAP signing + NTLM restriction |
| `WIN-SC-28-bitlocker-policy` | SC-28 | BitLocker encryption method + escrow |
| `WIN-SI-2-pending-updates` | SI-2 | Windows Update pending |
| `WIN-SI-3-defender-realtime` | SI-3 | Defender real-time + AV enabled |
| `WIN-SI-3-tamper-protection` | SI-3 | Defender tamper protection |
| `WIN-SI-3-asr-rules` | SI-3 | ASR rules configured |
| `WIN-SI-4-sysmon` | SI-4 | Sysmon installed |
| `WIN-SI-5-update-reporting` | SI-5 | WSUS status server or Defender sample submission |
| `WIN-SI-7-wdac-policy` | SI-7 | WDAC enforced |
| `WIN-SI-8-spam-protection` | SI-8 | Mail role detection (N/A for most hosts) |
| `WIN-SI-16-memory-protection` | SI-16 | DEP, ASLR, CFG, image signing |
| `WIN-POL-1` | CM-2 | AAD-joined but no MDM enrollment |
| `WIN-POL-2` | CM-6 | Policy inventory captured (informational) |

### Agent-Scoped vs Host-Scoped

Checks with `scope: "agent"` in findings-catalog.json are excluded in `--host-only` mode:
- `AC-3-openclaw-dir-perm`, `AC-3-secrets-dir-perm`, `AC-3-secret-file-perm`
- `AU-12-no-openclaw-rules`
- `SC-8-cloudflared-not-detected`, `SC-28-config-perm`, `SC-28-config-owner`, `SC-28-world-readable-secrets`
- `WIN-AC-3-workspace-acl`

---

## Findings Catalog

`assessment/findings-catalog.json` is the central rationale database. Each entry is keyed by `check_id` and contains:

```json
{
  "check_id": {
    "family": "AC-3 — Access Enforcement",
    "what": "Short description of the observed condition",
    "expected": "What the value/state should be",
    "why": "2-3 sentences explaining the security risk + NIST reference",
    "fix": "Runnable command or one-line action",
    "scope": "host | agent"
  }
}
```

**Per-platform fields:** `expected`, `why`, and `fix` can be either a string or a per-platform map:
```json
{
  "fix": {
    "default": "sudo ufw enable",
    "macos": "sudo socketfilterfw --setglobalstate on"
  }
}
```
Report generation resolves via `$SARGE_OS` with fallback to `default`.

**Naming convention:** `<NIST-FAMILY>-<CONTROL-NUMBER>-<short-slug>`. Family + control are uppercase (e.g. AC-3); slug is lowercase-kebab. Windows-specific IDs use the `WIN-` prefix. IDs are stable — never rename without a migration note.

**Coverage rule:** Every `failx` and `warnx` callsite in check scripts MUST have a corresponding catalog entry. PASS and SKIP do not need entries.

---

## Report Generation

### Linux/macOS (`report/report.sh`)

**Inputs:** Pass/warn/fail/skip counts, pipe-delimited results array, output path, catalog path, mode.

**Outputs:**
- `<output>.md` — Markdown report with summary table, delta vs previous run, per-finding detail blocks
- `<output>.json` — Machine-readable report (sarge_version, assessment_date, host, os, mode, summary, deltas, results)
- `<run-root>/report.md` — Copy in per-run folder
- `<run-root>/report.json` — Copy in per-run folder
- `<run-root>/findings.json` — Flat findings array

**Features:**
- **Delta computation:** Finds previous report (prefers per-run layout, falls back to legacy `~/.sarge/reports/`), computes PASS/WARN/FAIL/SKIP deltas, renders Δ column in summary table
- **Drift counter:** Increments when current FAIL > previous FAIL. Persisted in `~/.sarge/state/drift-count.txt`
- **Install date tracking:** First-run date stored in `~/.sarge/state/installed-at.txt`
- **Finding detail blocks:** For each FAIL/WARN, renders a block with: what, expected, why it matters, fix — all joined from findings-catalog.json
- **JSON parser fallback chain:** jq (preferred) → python3 → grep regex

### Windows (`report/build-report.ps1`)

`Build-SargeReport` function accepts findings array, run ID, run root. Produces the same output shapes (report.md, report.json, findings.json). Uses PowerShell's `ConvertTo-Json` for JSON generation.

---

## Hardening Scripts

All hardening scripts are:
- **Idempotent** — safe to run multiple times
- **Interactive** — each prompts `[y/N]` before making changes
- **Non-destructive by default** — no changes without explicit confirmation
- **Platform-gated** — wrong-platform scripts exit 0 silently via `sarge_require_os`

### `harden-permissions.sh` (AC-3, SC-28)
- Sets `~/.openclaw` → 700, `~/.openclaw/secrets` → 700, secret files → 600, config.json → 600
- **Does NOT require sudo** — runs as invoking user. Resolves `$SUDO_USER` to find the correct home directory when invoked under sudo.
- Function: `resolve_home_for_user($user)` — looks up home via `getent passwd` or `dscl`

### `harden-pam.sh` (IA-2, IA-5) — Ubuntu only
- Installs `libpam-pwquality`
- Writes `/etc/security/pwquality.conf`: minlen=12, dcredit/ucredit/ocredit/lcredit=-1, maxrepeat=3, gecoscheck=1
- Writes `/etc/security/faillock.conf`: deny=5, unlock_time=1800, fail_interval=900, silent, audit
- Sets `/etc/login.defs`: PASS_MAX_DAYS=90, PASS_MIN_DAYS=1, PASS_WARN_AGE=14
- Writes `/etc/profile.d/sarge-timeout.sh`: TMOUT=900, readonly

### `harden-auditd.sh` (AU-2, AU-9, AU-12) — Ubuntu only
- Installs `auditd` + `audispd-plugins`
- Writes `/etc/audit/rules.d/sarge.rules` with watch rules for:
  - `~/.openclaw/secrets` (rwxa, key: openclaw_secrets)
  - `~/.openclaw` (wa, key: openclaw_config)
  - `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/sudoers.d` (wa, key: identity/sudoers)
  - Privilege escalation (execve with euid=0)
  - `/var/log/auth.log` (wa, key: auth_log)
- Enables + starts auditd, loads rules via `augenrules --load`

### `harden-ufw.sh` (AC-17) — Ubuntu only
- Installs UFW, resets rules
- Default deny incoming, allow outgoing
- Allows gateway port (default 18790) from LAN subnet only
- Allows SSH from LAN subnet only
- Environment variables: `OPENCLAW_GATEWAY_PORT` (default 18790), `SARGE_LAN_SUBNET` (default 192.168.0.0/24)

### `harden-fail2ban.sh` (SI-3, AC-17) — Ubuntu only
- Installs fail2ban
- Writes `/etc/fail2ban/jail.d/sarge.conf` with:
  - Default: bantime=3600, findtime=600, maxretry=5
  - sshd jail enabled
  - openclaw-gateway jail (same auth log, gateway port)
- Enables + starts fail2ban

### `harden-systemd.sh` (CM-7) — Ubuntu only
- Creates systemd override for `openclaw-gateway.service`:
  - NoNewPrivileges, ProtectSystem=strict, ProtectHome=read-only, PrivateTmp, PrivateDevices
  - ProtectKernelTunables/Modules/ControlGroups, RestrictSUIDSGID, RemoveIPC, RestrictNamespaces

### `harden-firewall-macos.sh` (AC-17) — macOS only
- Uses `socketfilterfw` (Application Layer Firewall)
- Global firewall ON, stealth mode ON, block-all OFF (to not brick OpenClaw)
- Allow signed system binaries + signed downloaded apps
- Helper function: `alf_set(get_flag, set_flag, desired_pattern, label)` — idempotent state setter

### `harden-ssh-macos.sh` (CM-7) — macOS only
- Drops `/etc/ssh/sshd_config.d/sarge.conf` with: PermitRootLogin no, PasswordAuthentication no, ChallengeResponseAuthentication no
- Drop-in approach survives macOS upgrades (in-place edits get clobbered)
- Preflight: verifies `Include /etc/ssh/sshd_config.d/*` in main sshd_config
- Warns if current SSH session appears password-based
- Reloads sshd via `launchctl kickstart -k system/com.openssh.sshd`

---

## Drift Detection

### Snapshot (`drift/snapshot.sh`)

Captures current system state into a JSON document at `~/.sarge/snapshots/snapshot-<ts>.json` and symlinks to `latest.json`.

**JSON structure:**
```json
{
  "timestamp": "ISO-8601",
  "platform": "ubuntu|macos",
  "host": "hostname",
  "kernel": "uname -r",
  "os": "OS description",
  "fields": {
    "key1": "value1",
    "key2": "value2"
  }
}
```

**Ubuntu fields:** `ufw_status`, `auditd_active`, `fail2ban_active`, `openclaw_dir_perm`, `pass_max_days`

**macOS fields:** `firewall_status`, `openclaw_dir_perm`, `sshd_active`, `ssh_permit_root_login`, `ssh_password_auth`, `system_integrity_protection`

### Compare (`drift/compare.sh`)

Reads `latest.json` snapshot, re-probes current state for each field, compares. Uses python3 for JSON field extraction with graceful fallback.

**Function: `check(field, current)`**
- Reads baseline value from snapshot JSON (`fields.<field>` with fallback to top-level)
- Compares: match → `[OK]`, mismatch → `[DRIFT]` (increments DRIFT counter)

**Output:** Per-run `drift-report.json` with items array (status, field, baseline, current).

**Exit codes:** 0 = no drift, 2 = drift detected, 1 = no snapshot found.

### Drift Cron (`drift/drift-cron.sh`)

Wrapper for `compare.sh` suitable for cron. Logs to `~/.sarge/drift.log`. On drift detection, sends alert via `openclaw message` if available.

---

## Pre-Hardening Backup & Rollback

### Ubuntu (`scripts/backup-ubuntu.sh`)

**Snapshot tooling preference order:**
1. Btrfs/ZFS root subvolume snapshot
2. timeshift
3. LVM thin snapshot (skips classic LVM — thick provisioning makes snapshots brittle)
4. File-level snapshot (always collected as safety net)

**File-level capture:** cp -p of every `/etc/` path hardening can touch, plus `ufw status`, `auditctl -l`, `systemctl list-unit-files`, `dpkg --get-selections`, full `/etc/pam.d/`.

**Output directory:** `~/.sarge/runs/<run-id>/backup/` with: `fs/etc/...`, state files, `rollback.sh`, `summary.md`.

**Flags:** `--run-id <id>`, `--unattended`, `--test-mode` (log-only, no destructive snapshot).

**Rollback:** `scripts/rollback-ubuntu.sh` — restores from backup, supports `--run-id` and `--unattended`. `SARGE_ROLLBACK_ROOT=<prefix>` for sandbox testing.

### macOS (`scripts/backup-macos.sh`)

**Layers:**
1. APFS local snapshot via `tmutil localsnapshot`
2. Optional Time Machine snapshot via `--time-machine`
3. File-level capture of `/etc/pam.d/`, sshd_config, sudoers.d, firewall state, launchctl list, defaults domains, SIP/Gatekeeper/FileVault status
4. Generated `rollback.sh` + `summary.md`

**Status:** Spec'd per issue #30, untested on real macOS hardware.

### Windows (`scripts/backup-windows.ps1`)

**Captures:**
- System Restore checkpoint
- Registry exports per tracked policy hive (AC/AU/CM/SC/IA)
- `secedit /export` of local security policy
- `auditpol /backup` of audit policy
- `Get-Service` snapshot
- `Export-ScheduledTask` for non-Microsoft tasks
- Auto-generated `rollback.ps1`

**Dependency:** System Protection must be enabled on `%SystemDrive%`. Fails loud (exit 2) if disabled. `--skip-restore-point` to override.

---

## Platform Abstraction Layer

### OS Detection (`lib/platform.sh`)

Exports:
- `SARGE_OS` — `"ubuntu"` | `"macos"` | `"windows"` | `"unsupported"`
- `SARGE_OS_VERSION` — version string (e.g. "24.04", "14.5")
- `SARGE_OS_DESCRIPTION` — human-readable (e.g. "Ubuntu 24.04 LTS")

Functions:
- `sarge_require_supported_os()` — exit 2 if unsupported
- `sarge_require_os <os...>` — exit 0 (clean skip) if not in allowed list; silent by default, verbose with `SARGE_VERBOSE=1`

### Dispatcher (`lib/platforms/_dispatch.sh`)

`platform <probe> [args...]` — calls `${SARGE_OS}_<probe>`. Returns exit 127 if probe undefined.

`platform_supports <probe>` — 0 if probe exists, nonzero otherwise. Side-effect free, cheaper than calling the probe.

### Ubuntu Probes (`lib/platforms/ubuntu.sh`)

35+ functions named `ubuntu_<probe>`. Categories:
- **Filesystem:** `file_perm`, `file_owner`, `world_readable_files_in`
- **Accounts:** `users_with_empty_passwords`, `uid_zero_non_root_users`, `passwordless_sudo_for_current_user`, `admin_group_name`, `user_in_admin_group`
- **Firewall:** `firewall_command_available`, `firewall_status_text`, `firewall_active`, `externally_listening_ports`, `port_listening`
- **Audit:** `audit_daemon_active`, `auditctl_available`, `audit_rules`, `audit_log_path`, `system_logger_active`, `journal_disk_usage`
- **Packages/Services:** `package_installed`, `unattended_upgrades_config_path`, `pending_package_updates_count`, `pending_security_updates_count`, `service_active`, `service_enabled`, `linux_legacy_service_names`, `sshd_active`, `sshd_config_path`
- **Authentication:** `login_defs_value`, `pwquality_config_path`, `pwquality_value`, `pam_auth_path`, `pam_faillock_configured`, `faillock_config_path`, `faillock_value`, `session_timeout_setting`
- **Integrity:** `clamav_installed`, `fail2ban_status`, `verify_checksums`
- **Drift:** `drift_snapshot_fields`, `drift_check_fields`

### macOS Probes (`lib/platforms/macos.sh`)

20+ functions named `macos_<probe>`. Same categories but with macOS-specific implementations:
- Uses BSD `stat -f` instead of GNU `stat -c`
- Uses `dscl` instead of `/etc/shadow` for account management
- Uses `socketfilterfw` instead of UFW for firewall
- Uses `lsof -nP -iTCP` instead of `ss -tlnp` for port detection
- Uses `launchctl` instead of `systemctl` for service management
- Uses `shasum -a 256` instead of `sha256sum` for checksums

**Intentionally undefined probes** (routes to skipx with macOS rationale):
- `audit_daemon_active`, `auditctl_available`, `audit_rules`, `audit_log_path` — BSM auditd deprecated, Endpoint Security framework not shell-driveable
- `journal_disk_usage` — Unified Logging is always-on
- `package_installed`, `unattended_upgrades_config_path`, `pending_*_count` — softwareupdate/MDM, not apt
- `login_defs_value`, `pwquality_*`, `pam_faillock_*`, `faillock_*` — Linux-PAM constructs
- `clamav_installed` — macOS ships XProtect + Gatekeeper
- `fail2ban_status` — no native macOS analog
- `linux_legacy_service_names` — systemd unit names don't map to launchd labels

### Windows Context Detection (`lib/platform.ps1`)

`Get-SargeWindowsContext` returns an ordered hashtable:
```
version, captured_at, host{edition, build},
enterprise_context{is_domain_joined, is_aad_joined, is_in_managed_domain, domain_name, intune_managed, gpo_present},
active_controls{applocker_active, wdac_active, defender_realtime_active, defender_tamper_protection},
user_context{is_local_admin},
openclaw{install_path, service_account},
probe_errors{...}
```

Helper: `Invoke-SargeProbe -ErrorKey -ProbeErrors -Probe { scriptblock }` — runs probe, captures errors into hashtable, never rethrows.

Helper: `ConvertFrom-DsRegCmdOutput -Lines` — parses `dsregcmd /status` text output into structured hashtable.

---

## Policy Overlay (Windows Phase 1b)

`lib/policy-overlay.ps1` — `Apply-PolicyOverlay` function.

**Purpose:** Re-verdict Phase 1a FAIL/WARN findings as ENFORCED-EXTERNALLY when managed policy (MDM CSP / GPO) provides the enforcement.

**Input:** Findings list (mutated in place), MDM CSP inventory hashtable, gpresult data, AD GPO data.

**Overlay map** (pattern → finding ID):
- `DeviceLock` → `WIN-AC-11-idle-lock`
- `AccountLockoutThreshold` → `WIN-AC-7-lockout-threshold`
- `EnableVirtualizationBasedSecurity` → `WIN-SI-7-wdac-policy`
- `AllowRealtimeMonitoring` → `WIN-SI-3-defender-realtime`
- `TamperProtection` → `WIN-SI-3-tamper-protection`
- `AppLocker` → `WIN-AC-3-workspace-acl`

**Conservative:** Only flips FAIL/WARN → ENFORCED-EXTERNALLY when a matching policy key is present and non-zero. Does not touch PASS or already-EXTN findings. Skips POL-family findings.

**Phase 1b findings:** `WIN-POL-1` (AAD-joined, no MDM), `WIN-POL-2` (policy inventory captured).

---

## Configuration & Baseline

### `baseline/openclaw.json.baseline`

Hardened OpenClaw configuration with inline 800-53 control annotations:

| Setting | Value | NIST Control |
|---------|-------|-------------|
| `gateway.bind` | `"lan"` | AC-17 |
| `gateway.tls` | `true` | SC-8 |
| `agents.defaults.sandbox.mode` | `"all"` | AC-3, AC-6 |
| `agents.allowlist` | `[]` | AC-2 |
| `tools.fs.workspaceOnly` | `true` | AC-3 |
| `tools.exec.elevated` | `false` | AC-6 |
| `logging.level` | `"info"` | AU-2 |
| `logging.includeTimestamp` | `true` | AU-3 |
| `logging.includeUser` | `true` | AU-3 |
| `logging.auditActions` | `true` | AU-12 |
| `memory.encryption` | `true` | SC-28 |

### `baseline/controls.json`

Machine-readable control mapping. 23 controls across 6 families. Each entry:
```json
{
  "id": "AC-2",
  "family": "AC",
  "name": "Account Management",
  "status": "full|partial",
  "openclaw_settings": ["agents.allowlist", ...],
  "os_checks": ["getent passwd", ...],
  "remediation": "Remove unused accounts..."
}
```

### Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `SARGE_HOST_ONLY` | `0` | Skip agent-scoped checks |
| `SARGE_REPORT_DIR` | `~/.sarge/reports` | Report output directory |
| `SARGE_STATE_DIR` | `~/.sarge/state` | State persistence directory |
| `SARGE_RUN_ID` | Timestamp | Run identifier |
| `SARGE_RUN_ROOT` | `~/.sarge/runs/<run-id>` | Per-run directory |
| `SARGE_SNAPSHOT_DIR` | `~/.sarge/snapshots` | Drift snapshot directory |
| `SARGE_VERBOSE` | `0` | Show skip messages from `sarge_require_os` |
| `SARGE_LOG_FILE` | `~/.sarge/drift.log` | Drift cron log file |
| `OPENCLAW_GATEWAY_PORT` | `18790` | Gateway port for SC-8 + UFW checks |
| `SARGE_LAN_SUBNET` | `192.168.0.0/24` | LAN subnet for UFW rules |
| `SARGE_ROLLBACK_ROOT` | (unset) | Sandbox prefix for rollback testing |

---

## OpenClaw Integration (Skill)

`SKILL.md` defines Sarge as an OpenClaw skill for ClawhHub (planned at v0.3):

**Invocation phrases:**
- "Run a Sarge gap analysis" → `assess.sh`
- "Check for drift since last Sarge snapshot" → `compare.sh`
- "Apply Sarge hardening scripts" → `install.sh` (interactive)
- "Show Sarge control mapping for AC-2" → reads `baseline/controls.md`
- "Take a Sarge snapshot" → `snapshot.sh`

**Security model:** No data leaves the system. No external API calls. No API keys required. Air-gap compatible.

---

## Testing

### Integration Tests (Linux/macOS)

All tests are read-only unless noted. Run from the repo root.

| Test | What it validates |
|------|------------------|
| `tests/integration/drift-detection.sh` | Snapshot → compare → verify no-drift + drift-detected paths |
| `tests/integration/report-validation.sh` | Runs assessment, validates JSON structure + MD output |
| `tests/integration/hardening-roundtrip.sh` | Assess → harden UFW → reassess → verify PASS. Needs `iptables`/NET_ADMIN; skips in containers. |
| `tests/integration/host-only-mode.sh` | Validates `--host-only` excludes agent-scoped findings |
| `tests/integration/backup-ubuntu-smoke.sh` | Ubuntu backup script smoke test |
| `tests/integration/backup-macos-smoke.sh` | macOS backup dry-run on Linux |
| `tests/integration/catalog-platform-field.sh` | Validates per-platform fields in findings-catalog.json |

### Pester Tests (Windows)

Under `tests/Pester/`. All use mocked cmdlets — no real system state modified.

| Test file | Coverage |
|-----------|----------|
| `windows-ac.Tests.ps1` | Access Control probes + checks |
| `windows-au.Tests.ps1` | Audit probes + checks |
| `windows-cm.Tests.ps1` | Configuration Management probes + checks |
| `windows-ia.Tests.ps1` | Identification & Authentication probes + checks |
| `windows-sc.Tests.ps1` | System & Communications Protection probes + checks |
| `windows-si.Tests.ps1` | System & Information Integrity probes + checks |
| `windows-policy.Tests.ps1` | Policy overlay logic |
| `windows-host-only.Tests.ps1` | Host-only mode filtering |
| `backup-windows.Tests.ps1` | Backup script logic |

**Run locally:** `Invoke-Pester -Path tests/Pester`

### CI

GitHub Actions workflow: `.github/workflows/pester-windows.yml`
- Triggers on push/PR to main when Windows-relevant files change
- Runs on `windows-latest`
- Installs Pester 5.5+, runs all tests, uploads NUnit XML results

No Linux/macOS CI workflow wired up yet — integration tests are manual.

---

## Deployment & Packaging

### Installation

```bash
git clone https://github.com/oscarsixsecllc/sarge.git
cd sarge
chmod +x scripts/*.sh assessment/assess.sh assessment/checks/*.sh \
  assessment/report/report.sh drift/*.sh
```

### Docker (QA/Test Environment)

`Dockerfile.hardened` — Ubuntu 26.04 base with Node 22, all hardening dependencies pre-installed (auditd, fail2ban, PAM, UFW, OpenClaw), CUPS + avahi for CM-7 testing.

```bash
docker build -f Dockerfile.hardened -t sarge-qa .
docker run sarge-qa  # runs assess.sh by default
```

**Known limitation:** Full hardening in Docker requires systemd as PID 1 with `--privileged --cgroupns=host`. Standard containers skip systemd-dependent modules.

### Checksum Verification

```bash
cd sarge
sha256sum --check CHECKSUMS.sha256
```

To regenerate after intentional changes:
```bash
sha256sum scripts/*.sh assessment/**/*.sh > CHECKSUMS.sha256
```

---

## Exit Code Contract

| Script | Exit 0 | Exit 1 | Exit 2 |
|--------|--------|--------|--------|
| `assess.sh` | Assessment ran, report generated (exit 0 ≠ "passed") | Runtime error | Platform not supported |
| `assess.ps1` | Assessment ran, report generated | Missing probe/build error | — |
| `install.sh` | Hardening complete (or operator declined) | — | Platform unsupported |
| `harden-*.sh` | Module applied (or operator declined) | — | — |
| `snapshot.sh` | Snapshot captured or clean skip | — | Platform unsupported |
| `compare.sh` | No drift detected or clean skip | No snapshot found | Drift detected |
| `drift-cron.sh` | Success or clean skip | — | Platform unsupported |
| `backup-*.sh` | Backup complete | — | System Protection off (Windows) |
| `rollback-*.sh` | Rollback complete | — | — |

**Key distinction:** `assess.sh` exits 2 on unsupported platforms (loud failure for CI). Drift scripts exit 0 on clean skip (correct behavior under cron).

---

## Hard Rules & Conventions

1. **No data leaves the system.** No telemetry, no callbacks, no external API calls. Ever.
2. **No API keys or service registration required.**
3. **All scripts are human-readable.** No obfuscated code, no binary blobs.
4. **Gap analysis is read-only.** Never writes to system state.
5. **Hardening scripts require explicit confirmation.** Each module prompts `[y/N]`.
6. **Hardening scripts are idempotent.** Safe to run multiple times.
7. **Sudo only for hardening.** `harden-permissions.sh` is the exception — runs as invoking user.
8. **Platform probes never abort the function.** Failures return empty/null + error entry.
9. **Check scripts contain assertions, not data acquisition.** Platform files contain probes.
10. **findings-catalog.json IDs are stable.** Never rename without a migration note.
11. **Every FAIL/WARN callsite needs a catalog entry.** PASS/SKIP do not.
12. **Agent-scoped checks are excluded in `--host-only` mode.**
13. **The per-run folder is self-contained.** Everything needed to understand one run lives under `~/.sarge/runs/<run-id>/`.
14. **Sarge is scoped to OpenClaw deployments.** It is NOT a general-purpose hardening tool.
15. **Tier 1 (agent-safety) > Tier 2 (baseline hygiene)** in check prioritization. Both are covered, but agent-safety controls are the primary mission.

---

## Roadmap & Issue Tracker

All tracked at [github.com/oscarsixsecllc/sarge/issues](https://github.com/oscarsixsecllc/sarge/issues).

**Key issues:**
- **#1** — Expanded SC coverage
- **#2** — Expanded SI coverage
- **#12** — Windows roadmap (parent issue)
- **#28** — Windows pre-hardening backup (spec'd)
- **#29** — Ubuntu pre-hardening backup (closed)
- **#30** — macOS pre-hardening backup (spec'd, untested)
- **#31** — Windows `--inspect-policy` (Phase 1b, implemented)
- **#34** — Per-run folder layout
- **#50** — `--host-only` mode

---

*Generated 2026-07-06 by Oscar — Oscar Six Security LLC*
