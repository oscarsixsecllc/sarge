# Sarge — NIST 800-53 Hardening Standard for OpenClaw

> **Focus Forward. We've Got Your Six.** — Oscar Six Security LLC

[![Version](https://img.shields.io/badge/version-v0.7.0-green)](https://github.com/oscarsixsecllc/sarge/releases)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Ubuntu%20%7C%20macOS%20%7C%20Windows-orange)](docs/quickstart.md)

Sarge is an open source NIST 800-53 Rev 5 hardening standard, gap analysis tool, and drift detection system designed exclusively for [OpenClaw](https://openclaw.ai) deployments.

**Sarge answers one question:** *Is your OpenClaw instance configured to NIST 800-53 standards? If not, what's wrong and how do you fix it?*

---

## What Sarge Does

- 📋 **Gap Analysis** — Scans your OpenClaw instance and underlying OS against a documented 800-53 baseline. Produces a structured report: control ID, status (pass/warn/fail), current value, required value, and remediation steps. **63 controls across 12 NIST families + AS agent-safety overlay** on a standard Ubuntu 24.04 host with OpenClaw 2026.7.x. See [NIST 800-53 Rev 5 Control Coverage](#nist-800-53-rev-5-control-coverage) below for the full per-control breakdown.
- 🔒 **Hardening Scripts** — Idempotent, auditable bash scripts for UFW, auditd, PAM (faillock + pwquality), fail2ban, systemd service hardening, and file permissions.
- 📸 **Drift Detection** — Compares current system state against a captured baseline. Any drift generates a notification via your OpenClaw-configured channel.
- 🗺️ **Control Mapping** — Every OpenClaw setting and OS-level recommendation mapped to its 800-53 control ID, in both JSON and Markdown.

## What Sarge Is NOT

- Not a general-purpose compliance scanner
- Not a web vulnerability scanner (see: [Radar](https://radar.oscarsixsecurityllc.com))
- Not a CMMC certification tool (see: Sgt. Major)
- Not a substitute for a professional security assessment
- Not applicable to non-OpenClaw systems

---

## Threat model & scope

Sarge is an **agent-safety control**, not a generic OS hardening kit.

The primary use case is verifying that a host running OpenClaw (or another AI agent) meets the organization's baseline **before** the agent is allowed to make autonomous changes. The risk Sarge addresses isn't "this laptop has CVE-X open" in the abstract — it's "an agent with shell or API access is about to act on a system whose posture we haven't verified, and a wrong action against a weak baseline cascades into incident territory."

Two halves of the safety net:

1. **Pre-flight (Sarge):** assess the host against an 800-53 baseline. If the host isn't safe for autonomous agent action — weak ACLs, missing audit, no antimalware, MSA-attached identity outside org control — that should be visible *before* the agent is handed the keys.
2. **Post-action recovery (rollback/restore, tracked in issues #28 / #29 / #30):** when the agent does make the wrong change, the rollback path is the safety net. Sarge's drift detection feeds this — drift is the signal that a recovery may be needed.

Sarge covers the broader 800-53 control surface (not just an "agent-relevant subset") because most agent-safety failures cascade from baseline hygiene issues. Weak workspace ACLs let one compromised tool exfiltrate secrets; missing audit means an agent's wrong action is invisible; no antimalware means a downloaded artifact runs unchecked. We cover the agent-relevant controls **and** the surrounding baseline that makes them meaningful.

---

## Quickstart

```bash
# Clone the repo
git clone https://github.com/oscarsixsecllc/sarge.git
cd sarge

# Run gap analysis (no sudo required)
./assessment/assess.sh

# Reports saved to ~/.sarge/reports/

# Apply hardening (requires sudo, interactive — each module prompts)
sudo ./scripts/install.sh
```

Full docs: [docs/quickstart.md](docs/quickstart.md)

### Scan Modes

By default, Sarge runs in **agent-host** mode — it emits both the generic NIST 800-53 host findings AND the OpenClaw agent-runtime-specific findings (workspace ACL, secrets-dir perms, gateway TLS, etc.).

For hosts that don't run AI agents, or when you want a clean compliance baseline without agent-runtime context, pass `--host-only`:

```bash
# Host-only mode — pure baseline scan, no agent-overlay findings
./assessment/assess.sh --host-only

# Windows
pwsh assessment/assess.ps1 --host-only
```

In host-only mode, agent-scoped findings are excluded entirely (not even SKIP — they're out of scope). The report header states which mode the run used. See [#50](https://github.com/oscarsixsecllc/sarge/issues/50) for details.

---

## NIST 800-53 Rev 5 Control Coverage

Sarge's baseline (`baseline/controls.json`) documents 63 individual NIST 800-53 Rev 5 controls across 12 families. Each control lists the exact OpenClaw settings and OS-level checks Sarge inspects, plus remediation guidance.

### Summary by family

- **AC — Access Control** — 12 controls — Partial (11 full, 1 partial)
- **AU — Audit and Accountability** — 10 controls — Full
- **CM — Configuration Management** — 7 controls — Partial (6 full, 1 partial)
- **IA — Identification and Authentication** — 7 controls — Full
- **SC — System and Communications Protection** — 11 controls — Full
- **SI — System and Information Integrity** — 7 controls — Partial (4 full, 3 partial)
- **CP — Contingency Planning** — 2 controls — Partial (1 full, 1 partial)
- **CA — Assessment, Authorization, and Monitoring** — 2 controls — Partial (1 full, 1 partial)
- **SA — System and Services Acquisition** — 2 controls — Partial (both partial)
- **MP — Media Protection** — 1 control — Partial
- **SR — Supply Chain Risk Management** — 1 control — Partial
- **RA — Risk Assessment** — 1 control — Full

"Full" means the control has a fully automatable check with a concrete pass/fail verdict. "Partial" means Sarge checks what it can automate, but part of the control (a policy decision, an external agreement, or something outside what a scanner can verify) still needs human review.

---

### AC — Access Control (12 controls)

- **AC-2 — Account Management** (full) — Checks `agents.allowlist`, `channels.*.allowedUsers`, `gateway.nodes.pairing.autoApproveCidrs`; OS: `getent passwd`, `lastlog`, `who`. Remediation: remove unused accounts, restrict the OpenClaw allowlist to named users only.
- **AC-3 — Access Enforcement** (full) — Checks `tools.fs.workspaceOnly`, `agents.defaults.sandbox.mode`, `browser.attachOnly`, `browser.noSandbox`, `browser.evaluateEnabled`, `hooks.allowRequestSessionKey`, `hooks.allowedAgentIds`, `commands.ownerAllowFrom`, `gateway.controlUi.allowedOrigins`, `gateway.controlUi.allowInsecureAuth`, `approvals.exec.enabled`, `acp.allowedAgents`, `tools.codeMode.enabled`, `tools.sandbox.tools.alsoAllow`, `gateway.nodes.allowCommands`, `gateway.nodes.denyCommands`, `nodeHost.browserProxy.enabled`, `nodeHost.browserProxy.allowProfiles`, `crestodian.rescue.ownerDmOnly`, `talk.realtime.consultRouting`; OS: file permissions on `~/.openclaw/`, sudoers review. Remediation: set `workspaceOnly=true`, set sandbox mode to `all`, restrict sudoers, disable browser `noSandbox`, set `hooks.allowRequestSessionKey=false`.
- **AC-4 — Information Flow Enforcement** (full) — Checks `session.dmScope`, `messages.groupChat.visibleReplies`, `tools.web.search.enabled`, `tools.web.fetch.enabled`, `diagnostics.otel.captureContent.enabled`, `broadcast.strategy`, `acp.stream.maxOutputChars`, `surfaces.*.silentReply`. Remediation: set `session.dmScope` to `per-channel-peer`, review `tools.web` settings, disable `diagnostics.otel.captureContent` unless the collector is within your data boundary.
- **AC-5 — Separation of Duties** (full) — OS: `whoami`, `groups <user>`. Remediation: run OpenClaw under a dedicated service account that is not a member of the sudo/admin group.
- **AC-6 — Least Privilege** (full) — Checks `tools.exec.elevated`, `agents.defaults.sandbox.mode`, `agents.defaults.subagents.allowChildOverrides`, `gateway.terminal.enabled`, `browser.evaluateEnabled`; OS: `sudo -l`, `groups <user>`. Remediation: disable elevated exec unless required, confirm the service account has no unnecessary group memberships, set `subagents.allowChildOverrides=false`, disable the gateway terminal.
- **AC-7 — Unsuccessful Logon Attempts** (full) — Checks `gateway.auth.rateLimit.maxAttempts`, `gateway.auth.rateLimit.windowMs`, `gateway.auth.rateLimit.lockoutMs`, `auth.cooldowns`; OS: `pam_faillock status`. Remediation: configure `gateway.auth.rateLimit` (maxAttempts=10, windowMs=60000, lockoutMs=300000), configure PAM faillock.
- **AC-8 — System Use Notification** (full) — OS: `grep ^Banner /etc/ssh/sshd_config`. Remediation: set a `Banner` directive in `sshd_config` pointing to a system-use notification file.
- **AC-10 — Concurrent Session Control** (partial) — OS: `grep maxlogins /etc/security/limits.conf`. Remediation: set a `maxlogins` limit in `/etc/security/limits.conf` to bound concurrent sessions per user.
- **AC-11 — Device Lock** (full) — OS: `grep TMOUT /etc/profile /etc/profile.d/*`. Remediation: set `TMOUT` in `/etc/profile` or `/etc/profile.d/` to auto-lock idle shell sessions.
- **AC-12 — Session Termination** (full) — Checks `mcp.sessionIdleTtlMs`, `agents.defaults.subagents.archiveAfterMinutes`, `cron.sessionRetention`, `acp.runtime.ttlMinutes`, `crestodian.rescue.pendingTtlMinutes`. Remediation: set `mcp.sessionIdleTtlMs` to 600000 (10 min), set `subagents.archiveAfterMinutes` to 60, review `cron.sessionRetention`.
- **AC-14 — Permitted Actions Without Identification or Authentication** (full) — Checks `auth.enabled`. Remediation: set `auth.enabled` to `true` so gateway actions require identification/authentication.
- **AC-17 — Remote Access** (full) — Checks `gateway.bind`, `gateway.auth.mode`, `gateway.auth.rateLimit`, `gateway.controlUi.allowedOrigins`, `gateway.terminal.enabled`, `hooks.enabled`; OS: `ufw status`, `ss -tlnp`. Remediation: bind the gateway to loopback, enable `gateway.auth.mode=token`, set an auth rate limit, disable external hooks and the gateway terminal.

### AU — Audit and Accountability (10 controls)

- **AU-2 — Event Logging** (full) — Checks `logging.level`, `logging.destination`; OS: `systemctl status auditd`, `auditctl -l`. Remediation: enable auditd, set OpenClaw logging level to `info` or higher.
- **AU-3 — Content of Audit Records** (full) — Checks `logging.includeTimestamp`, `logging.includeUser`; OS: `ausearch -m LOGIN`, `last`. Remediation: ensure audit records include timestamp, user, action, and outcome.
- **AU-4 — Audit Log Storage Capacity** (full) — OS: `df -P /var/log/audit`, `df -P /var/log`. Remediation: keep at least 10% free space on the audit log partition; configure log rotation with adequate headroom or expand storage.
- **AU-5 — Response to Audit Processing Failures** (full) — OS: `grep disk_full_action /etc/audit/auditd.conf`, `grep admin_space_left_action /etc/audit/auditd.conf`. Remediation: set `disk_full_action` and `admin_space_left_action` to something other than `IGNORE` (e.g. `SYSLOG`, `EMAIL`, `HALT`).
- **AU-6 — Audit Review, Analysis, and Reporting** (full) — Checks `security.audit.suppressions`; OS: `auditctl -l`. Remediation: review every `security.audit.suppressions` entry — each suppression must be justified and periodically reviewed, or it creates a blind spot.
- **AU-7 — Audit Record Reduction and Report Generation** (full) — OS: `which journalctl`, `which ausearch`, `grep -r '@' /etc/rsyslog.d/`. Remediation: install auditd (provides `ausearch`) or configure rsyslog forwarding so audit records can be queried and aggregated.
- **AU-8 — Time Stamps** (full) — OS: `timedatectl show -p NTPSynchronized`, `chronyc tracking`. Remediation: enable NTP sync — `sudo timedatectl set-ntp true`.
- **AU-9 — Protection of Audit Information** (full) — Checks `agents.defaults.compaction.mode`, `agents.defaults.compaction.memoryFlush.enabled`, `logging.redactSensitive`; OS: `ls -la /var/log/audit/`, `stat /var/log/audit/audit.log`. Remediation: audit logs must be owned by root, mode 600; restrict write access.
- **AU-11 — Audit Record Retention** (full) — OS: `grep rotate /etc/logrotate.d/auditd`. Remediation: configure logrotate for audit logs with a `rotate` count of at least 4 (weekly rotation) for minimum retention.
- **AU-12 — Audit Record Generation** (full) — Checks `logging.auditActions`, `transcripts.enabled`, `transcripts.autoStart`; OS: `auditctl -l | grep openclaw`. Remediation: add auditd watch rules for `~/.openclaw/secrets/` and OpenClaw config files; review `transcripts.autoStart` sources.

### CM — Configuration Management (7 controls)

- **CM-2 — Baseline Configuration** (full) — Checks `*` (all settings against baseline); OS: `dpkg --get-selections`, `systemctl list-units --state=enabled`. Remediation: maintain `openclaw.json.baseline` as the documented configuration baseline.
- **CM-3 — Configuration Change Control** (full) — Checks `gateway.reload.mode`, `update.auto.enabled`, `commands.restart`. Remediation: set `gateway.reload.mode` to `hybrid`, disable `update.auto` unless `stableDelayHours >= 6`, review restart command availability.
- **CM-5 — Access Restrictions for Change** (full) — Checks `skills.workshop.approvalPolicy`, `skills.install.allowUploadedArchives`, `skills.workshop.allowSymlinkTargetWrites`, `plugins.entries`. Remediation: set `skills.workshop.approvalPolicy` to `review`, disable `allowUploadedArchives` and `allowSymlinkTargetWrites`, review plugin entries for `hooks.allowPromptInjection`.
- **CM-6 — Configuration Settings** (full) — Checks `tools.fs.workspaceOnly`, `agents.defaults.sandbox.mode`, `gateway.bind`, `models.mode`, `session.dmScope`, `messages.groupChat.visibleReplies`, `cron.maxConcurrentRuns`; OS: `ufw status verbose`, `sshd -T | grep -i permit`. Remediation: apply all settings in `openclaw.json.baseline` and all Sarge hardening scripts; verify `models.mode`, `session.dmScope`, and cron settings match baseline.
- **CM-7 — Least Functionality** (full) — Checks `plugins.entries`, `plugins.slots`, `tools.web`, `tools.codeMode.enabled`, `skills.entries`, `skills.workshop.approvalPolicy`, `skills.install.allowUploadedArchives`, `skills.load.allowSymlinkTargets`, `browser.enabled`, `browser.evaluateEnabled`, `browser.ssrfPolicy`, `mcp.servers`, `discovery.mdns.mode`, `gateway.http.endpoints.chatCompletions.enabled`, `gateway.http.endpoints.responses.enabled`, `gateway.tools.deny`, `gateway.tools.allow`, `commitments.enabled`, `security.installPolicy.enabled`, `marketplaces.feeds`, `marketplaces.sources`, `audio.transcription.command`; OS: `systemctl list-units --state=enabled`, `apt list --installed`. Remediation: disable unused plugins/skills/tools, set `skills.workshop.approvalPolicy=review`, disable the browser unless needed, set `discovery.mdns.mode=minimal`, remove unnecessary OS packages.
- **CM-8 — System Component Inventory** (full) — Checks `mcp.servers`, `plugins.entries`; OS: `node --version`. Remediation: maintain an approved component list and reconcile it against the reported Node.js version, MCP servers, and plugins.
- **CM-11 — User-Installed Software** (partial) — OS: `npm list -g --depth=0`. Remediation: review globally-installed npm packages and remove any not approved for the host.

### IA — Identification and Authentication (7 controls)

- **IA-2 — Identification and Authentication (Org Users)** (full) — Checks `channels.*.allowedUsers`; OS: `pam_faillock status`, `grep pam_faillock /etc/pam.d/common-auth`. Remediation: enable PAM faillock; restrict OpenClaw to authenticated Discord/channel users only.
- **IA-4 — Identifier Management** (full) — OS: `awk -F: '{print $3}' /etc/passwd | sort | uniq -d`. Remediation: eliminate duplicate UIDs in `/etc/passwd`; never reuse a UID after deleting an account.
- **IA-5 — Authenticator Management** (full) — Checks `auth.profiles`, `auth.order`, `auth.cooldowns`, `secrets.providers`, `gateway.auth.token`; OS: `grep minlen /etc/security/pwquality.conf`, `grep PASS_MAX_DAYS /etc/login.defs`. Remediation: set pwquality `minlen=12` plus complexity rules; set `PASS_MAX_DAYS=90`, `PASS_MIN_DAYS=1`.
- **IA-6 — Authentication Feedback** (full) — OS: `grep pam_unix /etc/pam.d/common-auth`. Remediation: ensure login failure messages don't reveal whether the username or password was wrong.
- **IA-7 — Cryptographic Module Authentication** (full) — Checks `gateway.tls`; OS: `grep Protocol /etc/ssh/sshd_config`, `grep Ciphers /etc/ssh/sshd_config`. Remediation: disable SSHv1 and weak ciphers (3DES, RC4/arcfour, CBC-mode) in `sshd_config`; set gateway TLS `minVersion` to TLSv1.2 or higher.
- **IA-8 — Identification and Authentication (Non-Org Users)** (full) — Checks `auth.mode`, `auth.providers`. Remediation: set an explicit `auth.mode`, register `auth.providers`, and disable anonymous access so external channel users (Discord/Telegram/etc.) are identified before gateway trust.
- **IA-11 — Re-authentication** (full) — Checks `mcp.sessionIdleTtlMs`. Remediation: set `mcp.sessionIdleTtlMs` to a finite, reasonable value (e.g. 24h or less) so idle sessions require re-authentication.

### SC — System and Communications Protection (11 controls)

- **SC-2 — Application Partitioning** (full) — OS: `ps aux`, `readlink /proc/PID/ns/mnt`. Remediation: run OpenClaw under a dedicated non-root service account; consider container or namespace isolation.
- **SC-4 — Information in Shared Resources** (full) — OS: `find /tmp -name *openclaw*`, `ls /dev/shm`. Remediation: configure periodic cleanup of `/tmp` session data; review `/dev/shm` for sensitive residue.
- **SC-5 — Denial-of-Service Protection** (full) — Checks `models.rateLimit`, `agents.defaults.maxConcurrent`, `agents.defaults.subagents.maxConcurrent`, `cron.maxConcurrentRuns`, `gateway.auth.rateLimit`, `acp.maxConcurrentSessions`, `acp.stream.maxOutputChars`, `audio.transcription.timeoutSeconds`; OS: `ufw status`. Remediation: set per-model rate limits, bound `maxConcurrent` to 4 for agents / 8 for subagents, set `cron.maxConcurrentRuns` to 8.
- **SC-7 — Boundary Protection** (full) — Checks `browser.ssrfPolicy.dangerouslyAllowPrivateNetwork`, `gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback`, `discovery.mdns.mode`, `hooks.enabled`, `gateway.tailscale.mode`, `proxy.enabled`, `proxy.loopbackMode`, `nodeHost.browserProxy.enabled`, `web.enabled`; OS: `ufw status`, `ss -tlnp`. Remediation: set `browser.ssrfPolicy.dangerouslyAllowPrivateNetwork=false`, set `discovery.mdns.mode=minimal`, disable external hooks unless required.
- **SC-8 — Transmission Confidentiality and Integrity** (full) — Checks `gateway.tls.enabled`, `gateway.controlUi.allowInsecureAuth`, `mcp.servers`; OS: `ss -tlnp`, `openssl s_client -connect localhost:18790`. Remediation: enable TLS on the gateway; use Cloudflare Tunnel (TLS enforced) for all remote access.
- **SC-12 — Cryptographic Key Establishment and Management** (full) — OS: `stat ~/.openclaw/secrets/*.key`, `stat ~/.ssh/id_*`. Remediation: all key/credential files must be 600 or 400; SSH private keys must be 600.
- **SC-13 — Cryptographic Protection** (full) — OS: `openssl version`, `node --version`. Remediation: use OpenSSL 1.1+ or 3.x for FIPS capability; Node.js 18+ enforces TLS 1.2+ by default.
- **SC-15 — Collaborative Computing Devices** (full) — Checks `nodes.*.capabilities.camera`, `nodes.*.capabilities.microphone`; OS: `v4l2-ctl --list-devices`, `ls /dev/video*`. Remediation: disable camera/microphone capabilities in `openclaw.json` unless required; remove `/dev/video*` access for the agent user.
- **SC-23 — Session Authenticity** (full) — Checks `auth.enabled`, `gatewayToken`. Remediation: set `auth.enabled: true` and configure a strong `gatewayToken`.
- **SC-28 — Protection of Information at Rest** (full) — Checks `memory.encryption`, `secrets.providers`, `logging.redactSensitive`, `diagnostics.otel.captureContent.enabled`, `diagnostics.cacheTrace.enabled`, `env`, `media.preserveFilenames`, `media.ttlHours`; OS: `stat ~/.openclaw/secrets/`, `ls -la ~/.openclaw/`. Remediation: secrets directory must be 700; all secret files must be 600; owner must be the service account only.
- **SC-39 — Process Isolation** (full) — OS: `cat /proc/PID/cgroup`, `readlink /proc/PID/ns/{pid,net,mnt}`. Remediation: run OpenClaw in a container or systemd slice with resource limits; use network and PID namespaces to isolate the agent.

### SI — System and Information Integrity (7 controls)

- **SI-2 — Flaw Remediation** (partial) — OS: `apt list --upgradable`, `unattended-upgrades --dry-run`. Remediation: enable unattended-upgrades for security patches; review and apply pending updates.
- **SI-3 — Malicious Code Protection** (partial) — OS: `which clamav`, `systemctl status clamav-daemon`. Remediation: install and configure ClamAV or equivalent; schedule regular scans.
- **SI-4 — Information System Monitoring** (full) — Checks `diagnostics.enabled`, `audit.enabled`, `cron.failureAlert.enabled`, `security.audit.suppressions`; OS: `systemctl status auditd`. Remediation: enable diagnostics, audit, and `cron.failureAlert`; enable auditd on the host; review `security.audit.suppressions` for blind spots.
- **SI-7 — Software, Firmware, and Information Integrity** (partial) — OS: `apt-config dump | grep -i AllowUnauthenticated`, `ls /etc/apt/trusted.gpg.d/`. Remediation: ensure `APT::Get::AllowUnauthenticated` is unset or false; verify apt repository GPG keys are configured under `/etc/apt/trusted.gpg.d/`.
- **SI-12 — Information Management and Retention** (full) — Checks `agents.defaults.compaction.mode`, `agents.defaults.compaction.memoryFlush.enabled`, `agents.defaults.compaction.truncateAfterCompaction`, `transcripts.enabled`, `transcripts.maxUtterances`, `media.ttlHours`. Remediation: set `compaction.mode` to `safeguard`, enable `memoryFlush` and `truncateAfterCompaction`, review `transcripts.maxUtterances` and `media.ttlHours` retention bounds.
- **SI-16 — Memory Protection** (full) — OS: `cat /proc/sys/kernel/randomize_va_space`. Remediation: set `kernel.randomize_va_space=2` for full ASLR — `sudo sysctl -w kernel.randomize_va_space=2`.
- **SI-17 — Fail-Safe Procedures** (full) — Checks `cron.retry.maxAttempts`, `crestodian.rescue.enabled`, `crestodian.rescue.pendingTtlMinutes`. Remediation: bound `cron.retry.maxAttempts`; if crestodian rescue is enabled, set a short `pendingTtlMinutes`.

### CP — Contingency Planning (2 controls)

- **CP-9 — System Backup** (partial) — OS: `crontab -l | grep -i backup`, `systemctl list-timers --all | grep -i backup`. Remediation: configure a scheduled backup (cron or systemd timer) of `~/.openclaw` config, secrets, and workspace state; verify backups are recoverable.
- **CP-10 — System Recovery and Reconstitution** (full) — Checks `crestodian.rescue.enabled`, `crestodian.rescue.ownerDmOnly`, `crestodian.rescue.pendingTtlMinutes`. Remediation: if rescue mode is enabled, restrict to `ownerDmOnly=true`; set `pendingTtlMinutes` to a short window (5 min default) to prevent stale rescue state.

### CA — Assessment, Authorization, and Monitoring (2 controls)

- **CA-7 — Continuous Monitoring** (full) — Checks `security.installPolicy.enabled`, `security.audit.suppressions`, `diagnostics.enabled`; OS: `systemctl status auditd`, `unattended-upgrades --dry-run`. Remediation: enable `security.installPolicy`, review audit suppressions, enable diagnostics.
- **CA-9 — Internal System Connections** (partial) — Checks `mcp.servers`; OS: parse `~/.openclaw/openclaw.json` `mcp.servers`. Remediation: document each MCP server connection in the system security plan / interconnection agreements; remove any unused or unauthorized servers.

### SA — System and Services Acquisition (2 controls)

- **SA-9 — External System Services** (partial) — Checks `mcp.servers`. Remediation: review each configured `mcp.servers` entry for a data-sharing agreement and supply-chain risk assessment; remove servers that are no longer needed.
- **SA-22 — Unsupported System Components** (partial) — OS: `cat /etc/os-release`, `node --version`. Remediation: upgrade Ubuntu and Node.js before their end-of-life dates; track EOL schedules at endoflife.date.

### MP — Media Protection (1 control)

- **MP-6 — Media Sanitization** (partial) — Checks `media.ttlHours`, `media.maxSizeMb`. Remediation: set `media.ttlHours` to a positive retention window and `media.maxSizeMb` to bound stored media size in the OpenClaw config.

### SR — Supply Chain Risk Management (1 control)

- **SR-11 — Component Authenticity** (partial) — OS: `ls ~/.openclaw/skills`, `ls /etc/apt/trusted.gpg.d/`. Remediation: add source/author/origin metadata to installed skills; verify APT package signing keys are present under `/etc/apt/trusted.gpg.d/`.

### RA — Risk Assessment (1 control)

- **RA-5 — Vulnerability Monitoring and Scanning** (full) — OS: `trivy`/`grype`/`oscap`/`lynis`/`debsecan`, `npm audit`, `apt list --upgradable`. Remediation: install a vulnerability scanner (trivy or grype recommended), run `npm audit` on OpenClaw dependencies, apply pending OS security patches.

### Families not covered

Sarge does not attempt to automate 7 of the 19 NIST 800-53 Rev 5 families, because they're organizational, administrative, or physical-security controls that a host/config scanner cannot meaningfully verify:

- **AT — Awareness and Training** — training program content and completion tracking, not a system state.
- **IR — Incident Response** — response plans, playbooks, and tabletop exercises are process artifacts, not scannable config.
- **MA — Maintenance** — maintenance scheduling, tooling, and personnel controls.
- **PE — Physical and Environmental Protection** — facility access, environmental controls — not visible to a host-level scan.
- **PL — Planning** — system security plans and policy documents.
- **PM — Program Management** — organization-wide security program governance.
- **PS — Personnel Security** — background checks, termination procedures, personnel screening.

These require documentation review and organizational process audit, not automated scanning — they're out of scope for a tool that inspects OpenClaw config and OS state.

---

## Control Coverage

Ubuntu 24.04 LTS + OpenClaw 2026.7.x, run date 2026-08-29:

| Family | ID | Checks Emitted | Coverage |
|--------|----|----------------|----------|
| Access Control | AC | 17 | Full |
| Audit & Accountability | AU | 5 | Full |
| Configuration Management | CM | 15 | Full |
| Identification & Authentication | IA | 10 | Full |
| System & Communications Protection | SC | 5 | Partial |
| System & Information Integrity | SI | 5 | Partial |
| Agent Safety (Sarge/OpenClaw overlay) | AS | 11 | New |
| **Total** | | **68** | |

Per-file secrets checks (AC-3), per-service CM-7 checks, and per-class pwquality (IA-5) checks each emit one finding per item, so the total scales with what's on the host — 68 is the number Sarge emits on a normally-provisioned OpenClaw 2026.7 install; a stripped-down VM may show fewer.

**AS family (agent-safety overlay):** Sarge-specific checks for the OpenClaw agent-runtime primitives — tool-gate hook installation and mode (AS-1, AS-2), tool-gate decisions ledger and integrity (AS-3, AS-5), daily digest cron (AS-4), workspace attestations (AS-6), skill-workshop review gate (AS-7), and cron-trust registration coverage (AS-8). Every AS check maps to underlying NIST 800-53 Rev 5 controls (AC-3, AC-6, AU-2, AU-9, CM-2, CM-5, CM-6, CM-7, SI-4, SI-7) but they're grouped under AS so operators see the agent-safety posture in one block. AS is agent-scoped — `--host-only` mode skips the whole family.

**Baseline:** NIST SP 800-53 Rev 5 | **Platforms:** Ubuntu 22.04 / 24.04 LTS (full); macOS (gap analysis + drift; permissions hardening only); Windows (detection + breadth-first recommendations across all 6 control families; hardening blocked on pre-hardening backup work)

> **Platform support status:** Full coverage on Ubuntu 22.04 / 24.04 LTS today. On macOS, gap analysis (`assessment/assess.sh`) and drift detection (`drift/snapshot.sh`, `drift/compare.sh`) now run natively — controls with a clean macOS analog (filesystem, accounts, firewall, listening ports, SSH, integrity checksums, session timeout) are evaluated; controls rooted in Linux-only facilities (auditd / pam_faillock / pwquality / login.defs / apt / unattended-upgrades / clamav / fail2ban) are skipped with a platform-aware rationale rather than emitting misleading FAILs with Ubuntu remediation text. `scripts/install.sh` on macOS still applies file-permission hardening only; native macOS hardening modules (firewall, SSH, logging policy) are tracked in [GitHub issues](https://github.com/oscarsixsecllc/sarge/issues). **Windows now has detection + recommendation coverage across all six 800-53 families (AC, AU, CM, IA, SC, SI)** via `assessment/assess.ps1` — read-only PowerShell probes capture enterprise context (domain / AAD join, Intune enrollment, GPO, AppLocker, WDAC, Defender) AND per-control verdicts with concrete remediation steps. Findings on domain-joined hosts are tagged "may be overridden by GPO" unless `--inspect-policy` (Phase 1b, [#31](https://github.com/oscarsixsecllc/sarge/issues/31)) is passed — that mode probes managed-policy state (Intune MDM CSP on AAD-joined hosts; GPO via RSAT or `gpresult /h` on AD-joined hosts), emits a top-level `WIN-POL-1` finding when an AAD-joined device is not enrolled in any MDM, and overlays verdicts onto Phase 1a control findings (FAIL/WARN -> ENFORCED-EXTERNALLY) where managed policy already enforces the relevant setting. Side-output: `policy-inventory.json` in the run folder. Pester tests live under `tests/Pester/windows-*.Tests.ps1` (mocked cmdlets; run locally via `Invoke-Pester -Path tests/Pester`; no CI workflow wired up yet). Windows hardening (Phase 2) is gated on the pre-hardening backup features tracked in [#28](https://github.com/oscarsixsecllc/sarge/issues/28) (Windows), [#29](https://github.com/oscarsixsecllc/sarge/issues/29) (Ubuntu), and [#30](https://github.com/oscarsixsecllc/sarge/issues/30) (macOS). Sarge on Windows is scoped to OpenClaw deployment hardening — it is not a generic Windows hardening tool. Roadmap is tracked under parent issue [#12](https://github.com/oscarsixsecllc/sarge/issues/12).

> **Why SC and SI are partial:**
> 
> **SC (partial):** Many System & Communications Protection controls require network infrastructure decisions that vary by deployment — full boundary protection architecture, PKI certificate lifecycle, and cryptographic key management go beyond what a single-VM OpenClaw deployment can meaningfully self-assess. Sarge covers the controls that are universally applicable: transmission confidentiality (SC-8) and protection of data at rest (SC-28). Expanded SC coverage is tracked in [#1](https://github.com/oscarsixsecllc/sarge/issues/1).
>
> **SI (partial):** Full System & Information Integrity coverage (particularly SI-4 System Monitoring) requires a SIEM or centralized log analysis setup — a significant dependency that would narrow Sarge's applicability. Sarge covers what every deployment can implement: flaw remediation (SI-2), malware protection (SI-3), and script integrity verification (SI-7). Expanded SI coverage is tracked in [#2](https://github.com/oscarsixsecllc/sarge/issues/2).

---

## Validated Results

Ubuntu 24.04 LTS host, OpenClaw 2026.7.1-2, run date 2026-08-29:

| Status | Count |
|--------|-------|
| ✅ PASS | 42 |
| ⚠️ WARN | 13 |
| ❌ FAIL | 11 |
| ⏭️ SKIP | 2 |
| **Total** | **68** |

Numbers were captured on this VM (development host, no hardening applied) — treat them as an indicative baseline, not a target. On a hardened VM with `scripts/install.sh` completed, WARN and FAIL counts collapse toward zero as ufw, auditd, pam_faillock, fail2ban, systemd-service hardening, and file-permission fixes land. A few WARN/FAIL cells are structurally expected on a stock desktop image (e.g. per-class pwquality character-class WARNs, avahi/cups running on a desktop profile) and are addressed by running the corresponding `harden-*` module.

> **Testing in containers — known limitation.** When running `scripts/install.sh` inside a default Docker container (PID 1 = `bash`/`sleep`, no systemd), only `harden-permissions` and `harden-pam` will apply — the other 4 modules error at `systemctl is-system-running`. To exercise the full install flow in a container, start it with systemd as PID 1 (`docker run --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run -e container=docker <image> /sbin/init`), or use a real VM (multipass / vagrant / lima). Validation runs against a standard Ubuntu 24.04 LTS VM, not a container.

> **macOS coverage.** The numbers above are Ubuntu 24.04 only. On macOS, gap analysis and drift detection now run natively; controls without a macOS-native equivalent emit SKIP with a platform-aware rationale (delegated to MDM, Endpoint Security, pwpolicy, etc.) rather than a misleading FAIL. Native macOS hardening modules (firewall, SSH, logging policy) are landing per-PR — each will publish its own validated PASS/WARN/FAIL count as it ships.

---

## OpenClaw Integration

Sarge integrates with OpenClaw as a skill. Install from [ClawhHub](https://clawhub.com) (available at v0.3) or load the [SKILL.md](SKILL.md) directly. Your agent can invoke:

- `"Run a Sarge gap analysis"` → executes `assess.sh`, posts summary to your channel
- `"Check for drift since last Sarge snapshot"` → runs `compare.sh`, reports changes
- `"Apply Sarge hardening"` → runs `install.sh` interactively (requires confirmation at each step)
- `"Show Sarge control mapping for AC-2"` → reads from `baseline/controls.md`

---

## Security Commitment

- ❌ **No data leaves your system.** No telemetry, no callbacks, no external API calls.
- ❌ **No API keys or service registration required.**
- ✅ **All scripts are human-readable and auditable.** No obfuscated code, no binary blobs.
- ✅ **Checksum verification** for all scripts via `CHECKSUMS.sha256`.
- ✅ **Sudo only required for hardening scripts** — gap analysis is fully read-only.
- ✅ **Air-gap compatible** — no internet connectivity required after install.

See [SECURITY.md](SECURITY.md) for vulnerability disclosure policy.

---

## Script Exit Codes

Sarge scripts use exit codes to signal *what they did*, not just *whether they succeeded*. The contract differs per script because each one serves a different role. Unless explicitly noted below, any non-`0` / non-`2` exit should be treated as an unexpected runtime or precondition error and investigated from the script output.

| Script | Exit 0 | Exit 2 | Notes |
|---|---|---|---|
| `assessment/assess.sh` | Assessment ran; Markdown + JSON report generated | Platform not yet supported (no assessment performed) | **Exit 0 ≠ "your system passed."** Read the report for PASS/WARN/FAIL counts. |
| `scripts/install.sh` | Hardening complete (or operator declined at any prompt) | Platform unsupported | Each module also prompts `[y/N]`; declining a module is exit 0 from that module. Privilege requirements vary per module (see below). |
| `scripts/harden-*.sh` | Module applied (or operator declined) | — | **Privilege requirements vary by module — check each script's header for the authoritative requirement.** `harden-permissions.sh` runs as the invoking user and uses `$HOME` (do **not** invoke with `sudo` directly, or `$HOME` will resolve to `/root` and the wrong workspace will be hardened). The other modules (`harden-pam`, `harden-auditd`, `harden-fail2ban`, `harden-ufw`, `harden-systemd`) write to `/etc/` and require `sudo`. |
| `drift/snapshot.sh` | Snapshot captured *or* clean skip on non-applicable platform | Platform unsupported | Designed to be safe in cron. |
| `drift/compare.sh` | No drift detected *or* clean skip on non-applicable platform | Drift detected **or** platform unsupported (read script output to disambiguate) | Exits `1` when no snapshot exists (`No snapshot found. Run snapshot.sh first.`) — run `snapshot.sh` first. |
| `drift/drift-cron.sh` | Success or clean skip | Platform unsupported | Wraps `compare.sh`; suitable for cron. |

> **Why `assess.sh` exits 2 (not 0) on unsupported platforms.** Assessment is a *measurement* tool — exit 0 carries the meaning "I performed an assessment and produced a report." A silent exit 0 on an unsupported platform could be misread by CI pipelines as "this host has zero NIST gaps." Drift scripts use exit 0 for clean-skip because skipping is the desired behavior under cron; assess is interactive and CI-driven, where a loud failure is the correct signal.

> **Verbose skip messages.** `sarge_require_os` (used by Linux-only modules to skip cleanly on macOS) is silent by default. Set `SARGE_VERBOSE=1` in the environment to see why a module skipped.

---

## Pre-hardening backup + rollback (Ubuntu)

Before any `harden-*.sh` runs on Ubuntu, Sarge captures a layered backup
so every change is reversible. Closes
[#29](https://github.com/oscarsixsecllc/sarge/issues/29).

### Snapshot tooling — preference order

`scripts/backup-ubuntu.sh` probes for snapshot tooling and uses the first
match. The file-level snapshot **always** runs regardless of which
block-level tool was selected (it's the safety net).

1. **Btrfs / ZFS root subvolume snapshot** — if `stat -f -c '%T' /`
   returns `btrfs` or `zfs`. Snapshot tagged
   `sarge-pre-hardening-<run-id>`.
2. **timeshift** — if installed.
   `timeshift --create --comments "Sarge pre-hardening <run-id>" --tags O`.
3. **LVM thin snapshot** — if root LV is on a thin pool. Classic LVM
   is skipped (thick provisioning makes snapshots brittle).
4. **File-level snapshot (fallback, always collected)** —
   `cp -p` of every `/etc/` path Phase 2 hardening can touch, plus
   `ufw status verbose`, `ufw show added`, `auditctl -l`, `auditctl -s`,
   `systemctl list-unit-files --state=enabled,disabled,masked`,
   `dpkg --get-selections`, full `/etc/pam.d/`.

Artifacts land under `~/.sarge/runs/<run-id>/backup/`:

```
~/.sarge/runs/<run-id>/backup/
├── fs/etc/...           # mirrored /etc tree (login.defs, ssh/, pam.d/, audit/rules.d/, sysctl.d/, security/limits.conf)
├── ufw-state.txt
├── audit-state.txt
├── services.txt
├── packages.txt
├── backup.log
├── rollback.sh          # auto-generated, executable
└── summary.md
```

### Usage

```bash
# Interactive opt-in (Y/Enter proceeds, N explicit-skip)
bash scripts/backup-ubuntu.sh --run-id "$SARGE_RUN_ID"

# Unattended (CI / chained from assess.sh)
bash scripts/backup-ubuntu.sh --unattended --run-id "$SARGE_RUN_ID"

# Roll back the most recent run (prompts for confirmation)
bash scripts/rollback-ubuntu.sh

# Roll back a specific run
bash scripts/rollback-ubuntu.sh --run-id 20260523-120000

# Unattended rollback
bash scripts/rollback-ubuntu.sh --backup-dir ~/.sarge/runs/<id>/backup --unattended
```

`--test-mode` logs the chosen snapshot tool but skips the destructive
block-level snapshot — used by the smoke test
(`tests/integration/backup-ubuntu-smoke.sh`).

### Sandbox / non-root testing

`rollback.sh` honors `SARGE_ROLLBACK_ROOT=<prefix>` for sandbox round-trip
tests — when set, file restores are written under the prefix and the
systemctl / ufw / auditctl / dpkg branches are skipped.

---

## Pre-hardening backup + rollback (macOS)

> **Untested on real macOS hardware.** Oscar Six does not currently have
> a Mac test surface available. The macOS backup + rollback scripts
> (`scripts/backup-macos.sh`, `scripts/rollback-macos.sh`) follow the
> issue [#30](https://github.com/oscarsixsecllc/sarge/issues/30) spec
> and the Ubuntu/Windows backup patterns, but have only been exercised
> via `bash -n` and a Linux dry-run smoke test
> (`tests/integration/backup-macos-smoke.sh`). The macOS-specific
> commands (`tmutil`, `pfctl`, `defaults`, `socketfilterfw`, `csrutil`,
> `spctl`, `fdesetup`, `launchctl`) have **not** been validated against
> live binaries. **Community validation contributions are welcome** —
> open a PR or comment on issue #30 with results from a real Mac.

Before any `harden-*.sh` runs on macOS, Sarge captures a layered backup
so any change is reversible:

1. **APFS local snapshot** (heavy-lift backstop) via `tmutil localsnapshot`.
   Survives reboots, costs no extra disk until divergence, restorable
   via `tmutil restore <snapshot-id>`. The script **fails loudly** if
   the boot volume isn't APFS or local snapshots are disabled — it does
   not silently proceed.
2. **Optional Time Machine snapshot** via `tmutil startbackup --block`
   when `--time-machine` is passed and TM is configured. Slower;
   complements the APFS snapshot.
3. **File-level capture** under `~/.sarge/runs/<run-id>/backup/`:
   - `/etc/pam.d/`, `/etc/ssh/sshd_config`, `/etc/sudoers.d/`,
     `/etc/security/audit_*` copied with `cp -Rp`
   - `socketfilterfw --getglobalstate` + per-app rules → `socketfilterfw.txt`
   - `pfctl -sa` → `pf-state.txt`
   - `launchctl list` → `launchctl.txt`
   - `defaults read` of touched domains (`com.apple.loginwindow`,
     `com.apple.screensaver`, `com.apple.security`,
     `/Library/Preferences/com.apple.alf`) → `defaults-<domain>.txt`
   - `csrutil status`, `spctl --status`, `fdesetup status` →
     `security-status.txt`
4. **Generated `rollback.sh`** that reverses each granular artifact
   (cp `/etc/` back, `pfctl -f` the saved state, re-enable
   socketfilterfw, replay launchctl delta, defaults manual-review
   pointer) and documents the APFS snapshot ID as the backstop.
5. **`summary.md`** with capture inventory + both rollback paths.

### Usage

```bash
# Interactive (prompts before snapshot)
bash scripts/backup-macos.sh --run-id "$SARGE_RUN_ID"

# Unattended (CI / chained from assess.sh)
bash scripts/backup-macos.sh --unattended --run-id "$SARGE_RUN_ID"

# Also trigger a Time Machine snapshot
bash scripts/backup-macos.sh --unattended --time-machine --run-id "$SARGE_RUN_ID"

# Roll back the most recent run
bash scripts/rollback-macos.sh --latest

# Roll back a specific run
bash scripts/rollback-macos.sh --run-id 20260523-120000
```

### Heavy-lift fallback

If granular rollback fails or leaves the system in an unexpected state,
restore the APFS local snapshot:

```bash
tmutil listlocalsnapshots /
tmutil restore <snapshot-id-from-summary.md>
```

### Phase 2 follow-ups (tracked as untested debt)

- `defaults read` capture is human-readable, not directly importable
  by `defaults import`. Phase 2 should switch to
  `defaults export <domain> <file>.plist` so `rollback.sh` can
  re-import non-interactively.
- `pfctl -sa` is a mixed-section dump; a finer-grained `pfctl -sr`
  capture would let `rollback.sh` reload rules deterministically.
- `socketfilterfw` per-app rules have no bulk-import; rollback emits
  the captured `--listapps` output for manual replay.

---

## Pre-hardening backup + rollback (Windows)

Sarge's Phase 2 Windows hardening (`scripts/harden-*.ps1`, in flight) will
mutate registry policy hives, local security policy, audit policy, service
start types, and scheduled tasks. Before *any* of that runs, Sarge offers
to capture a restorable snapshot via `scripts/backup-windows.ps1`. A
misapplied control should never leave a host in an unrecoverable state.
Closes [#28](https://github.com/oscarsixsecllc/sarge/issues/28).

**Workflow (operator):**

```powershell
# 1. Capture the backup. Defaults to interactive consent.
pwsh -ExecutionPolicy Bypass -File scripts\backup-windows.ps1

# 2. (later) Apply hardening - Phase 2 modules will call backup-windows.ps1
#    automatically with their assess.ps1 run-id.

# 3. Roll back if anything regresses.
pwsh -ExecutionPolicy Bypass -File scripts\rollback-windows.ps1 `
    -BackupDir "$env:USERPROFILE\.sarge\runs\<run-id>\backup"
```

**What gets captured into `%USERPROFILE%\.sarge\runs\<run-id>\backup\`:**

- A System Restore checkpoint named `Sarge pre-hardening <run-id>`.
- `registry\*.reg` - one export per tracked policy hive (AC / AU / CM / SC / IA).
- `secpol.cfg` - `secedit /export` of local security policy.
- `audit-policy.csv` - `auditpol /backup` of audit policy.
- `services.json` - `Get-Service` snapshot (Name / Status / StartType).
- `tasks\*.xml` - `Export-ScheduledTask` for tasks under non-Microsoft paths.
- `rollback.ps1` - auto-generated reverser keyed to what was actually captured.

A `backup-summary.md` lands in the run folder with the exact rollback command.

**Dependency: System Protection must be enabled.** If System Protection is
off on `%SystemDrive%`, `backup-windows.ps1` fails loud with exit code 2 and
the message *"Enable System Protection in System Properties -> System
Protection -> Configure -> Turn on, then re-run"*. Sarge will **not**
silently proceed without a checkpoint safety net. Pass `--skip-restore-point`
to override (config-only snapshot, no restore point) - not recommended for
production hosts.

**Flags:**

| Flag                    | Effect |
|-------------------------|--------|
| `--unattended`          | Skip the `[Y/n]` consent prompt (proceed). |
| `--skip-restore-point`  | Bypass `Checkpoint-Computer`; still produce snapshots. |
| `--run-id <id>`         | Use the supplied run-id (e.g. from `assess.ps1`). |

Rollback is **idempotent** - re-running it when state already matches the
snapshot performs no net change. Some surfaces (`HKLM\SYSTEM\...` keys,
secedit, auditpol) require an **elevated** PowerShell to fully restore;
non-elevated sessions will surface warnings on those steps but other
artifacts still apply cleanly.

---

## Testing

Sarge ships integration tests you can run in your environment. All tests are read-only unless noted.

### Linux / macOS

```bash
# Drift detection pipeline (snapshot, compare, detect changes)
bash tests/integration/drift-detection.sh

# Report structure validation (runs assessment, validates JSON/MD output)
bash tests/integration/report-validation.sh

# Hardening round-trip (assess, harden UFW, reassess, verify fix)
# Requires iptables/NET_ADMIN; skips gracefully in containers
bash tests/integration/hardening-roundtrip.sh

# Host-only mode validation
bash tests/integration/host-only-mode.sh

# Backup smoke tests
bash tests/integration/backup-ubuntu-smoke.sh
bash tests/integration/backup-macos-smoke.sh
```

### Windows

```powershell
Invoke-Pester -Path tests/Pester
```

If a test fails in your environment, please [open an issue](https://github.com/oscarsixsecllc/sarge/issues).

---

## Repository Structure

```
sarge/
├── SKILL.md                    # OpenClaw skill definition (ClawhHub)
├── README.md                   # This file
├── CHECKSUMS.sha256             # Script integrity verification
├── baseline/                   # 800-53 baseline configs and control mappings
├── scripts/                    # Hardening scripts (require sudo)
├── assessment/                 # Gap analysis runner and check scripts
├── drift/                      # Drift detection and snapshot tools
├── docs/                       # Quickstart and reference documentation
└── Dockerfile.hardened          # Validated test environment (Ubuntu 24.04 + Node 22)
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Community contributions are welcome. Changes to core security files (`scripts/`, `assessment/`, `baseline/`) require maintainer review.

## License

Apache 2.0 — Copyright 2026 Oscar Six Security LLC

## Community

- **Discord:** [Oscar Six Security](https://discord.com/invite/clawd) — channel `#sarge`
- **GitHub Issues:** [oscarsixsecllc/sarge/issues](https://github.com/oscarsixsecllc/sarge/issues)
- **Publisher:** [Oscar Six Security LLC](https://www.oscarsixsecurityllc.com)
