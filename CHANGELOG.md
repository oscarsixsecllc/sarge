# Changelog — Sarge

All notable changes to Sarge will be documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### In Progress
- ClawhHub submission

---

## [0.11.0] — 2026-09-05

### Added
- **macOS native IA-5/IA-2 probes** — password policy checks now probe `pwpolicy -getaccountpolicies` natively instead of emitting misleading FAILs with Ubuntu remediation text. MDM-managed Macs get a clean SKIP with an MDM-delegation rationale. (#23, #24, #82)
- **macOS native CM-6/SI-2 probes** — pending package and security update checks now probe `softwareupdate --list --no-scan` natively. Drift snapshots include `pending_updates` fields on macOS. (#23, #24, #82)

---

## [0.10.0] — 2026-09-05

### Added
- **AC/CM expansion** — 5 new controls added to `baseline/controls.json`: AC-2(3) Disable Inactive Accounts, AC-20 Use of External Systems, AC-22 Publicly Accessible Content, CM-10 Software Usage Restrictions, CM-12 Information Location. Total NIST 800-53 control count: 68 across 12 families. (#81)
- GitHub Actions CI workflow (lint, shellcheck, integration tests on push/PR). (#81)
- GitHub Actions release workflow (auto-creates GitHub Release on version tag push). (#81)
- GitHub issue and PR templates. (#80)
- Expanded CONTRIBUTING.md with development workflow and review expectations. (#80)

---

## [0.9.0] — 2026-09-04

### Added
- **Full NIST 800-53 coverage expansion** — 63 controls across 12 families (was 31 across 6). New families: CP, CA, SA, MP, SR, RA. New controls span AU-4/5/7/8/11, IA-4/7/8/11, SI-7/SI-16, CA-9, CP-9, SA-9/SA-22, MP-6, SR-11, RA-5, AC-4/5/7/8/10/11/12/14, CM-3/5/8/11, SC-2/4/12/13/15/23/39. (#79)
- **Drift detection rework** — file hashing, chain integrity verification, and inventory tracking for drift snapshots. (#79)
- Detailed per-control NIST 800-53 reference added to README with remediation guidance for all 63 controls.
- Baseline schema refreshed to OpenClaw 2026.7.1-2. (#63, #71)

---

## [0.7.0] — 2026-08-29

### Added
- **New AS (Agent Safety) control family** covering the OpenClaw agent-runtime primitives that make Sarge specifically an agent-safety control rather than a generic OS hardener. Eleven new checks under `assessment/checks/check-as.sh`, all agent-scoped (guarded by `SARGE_HOST_ONLY`): (#62, #65)
  - **AS-1** tool-gate hook installation (files present AND wired into `~/.claude/settings.json`)
  - **AS-2** tool-gate enforcement mode (`~/.config/o6-gate-mode`: FAIL missing, WARN shadow, PASS tier-c/tier-bc)
  - **AS-3** decisions ledger permissions (600) and freshness (mtime within 7 days)
  - **AS-4** daily digest cron registered
  - **AS-5** `gate_common.py` integrity vs upstream reference
  - **AS-6** workspace-attestations directory (700, newest attestation within 30 days)
  - **AS-7** skill-workshop review gate present
  - **AS-8** cron-trust.json permissions (600) and per-entry `CRON_JOB_NAME` coverage
  - Each AS check maps to underlying NIST 800-53 Rev 5 controls (AC-3, AC-6, AU-2, AU-9, CM-2, CM-5, CM-6, CM-7, SI-4, SI-7). See DECISIONS.md for the fold-under-SI-vs-new-family reasoning.
- New integration test `tests/integration/agent-safety-checks.sh` — 19 assertions covering three end-to-end scenarios (nothing installed / everything present / weak permissions), catalog coverage, and the host-only-mode agent-scope guard.
- **Baseline schema refresh (`baseline/openclaw.json.baseline` v0.2.0)** — added 11 sections that had drifted out since 2026-03: `approvals` (approval routing), `hooks`, `agents.subagents`, `skills.workshop`, `session.compaction`, `models.rateLimit`, `auth.profiles`, `mcp.servers`, `browser`, `sandboxes`, `plugins.workboard`. Each section carries `_control` annotations tying the hardening choice to the covering NIST 800-53 control. (#65)

---

## [0.6.1] — 2026-08-29

### Fixed
- **SC-28 config check + `harden-permissions.sh` now target the live OpenClaw config filename** (`openclaw.json`, with `config.json` fallback for legacy pre-2026.4 installs). Previously both looked only for the retired `config.json`, so SC-28 config-perm / config-owner silently SKIPped on every real install and `harden-permissions` never chmod'd the file that actually holds provider tokens. Config backups (`openclaw.json.bak*`, `.backup*`) get the same 600 treatment. (#61)
- **SC-28 world-readable check narrowed to a known-sensitive allowlist** — only the OpenClaw config (+ backups), `secrets/` / `credentials/` / `auth/`, and credential-shaped filenames (`*.key`, `*.pem`, `*.env`, `*-token*`, `*-secret*`, `id_rsa*`, `id_ed25519*`). Previously flagged intentionally-readable workspace canon (SOUL.md, HEARTBEAT.md, AGENTS.md, USER.md, TOOLS.md, BOOTSTRAP.md) and `workspace/.git/*` on every install, drowning real leaks in noise. (#64)

### Changed
- **README validated-results and control-coverage numbers refreshed** to reflect actual output on Ubuntu 24.04 + OpenClaw 2026.7.1-2: 57 checks / PASS 34 / WARN 12 / FAIL 9 / SKIP 2 (was: 47 / 30 / 7 / 4 / 2). (#66)
- Added top-level `DECISIONS.md` recording non-obvious scoping calls (starting with the two SC-28 decisions above).
- Integration tests added for drift detection, report validation, and hardening roundtrip. (#60)

---

## [0.6.0] — 2026-06-27

### Added
- **`--host-only` mode** — exclude agent-runtime findings entirely (not even SKIP) for hosts that don't run AI agents. (#50)
- Per-platform fix text in control catalog (macOS/Windows/Ubuntu-specific remediation). (#17, #20)
- `sarge_require_os` guard on Linux-only hardening scripts so they skip cleanly on macOS. (#26)
- Dependabot enabled for GitHub Actions and Docker dependencies. (#53)

---

## [0.5.0] — 2026-06-27

### Added
- **macOS SSH hardening** — `harden-ssh-macos.sh` applies CM-7 SSH hardening via drop-in config. (#55)

---

## [0.4.0] — 2026-06-27

### Added
- **macOS firewall hardening** — `harden-firewall-macos.sh` configures socketfilterfw + stealth mode (AC-17). (#54)
- **Windows Phase 1c** — depth-fill detection + recommendations across all 6 NIST 800-53 families. (#35, #46)
- **Windows pre-hardening backup + rollback** via System Restore checkpoint + config snapshots. (#28, #45)
- **Ubuntu pre-hardening backup + rollback** via Btrfs/ZFS/timeshift/LVM/file-level snapshots. (#29, #44)
- **macOS pre-hardening backup + rollback** (untested on real hardware) via APFS local snapshot + file-level capture. (#30, #43)
- **Windows `--inspect-policy` mode** for AAD/MDM and AD-GPO probing (Phase 1b). (#31, #37)
- **Windows breadth-first detection** across all 6 NIST 800-53 families (Phase 1a). (#32)
- Pester test suite wired into GitHub Actions CI for Windows. (#40)
- Per-run folder layout for assess + drift + report output. (#34, #42)

### Fixed
- Windows rollback: flatten `ConvertFrom-Json` array correctly under PowerShell 5.1. (#49)
- Windows rollback: persist task manifest + use TaskName+TaskPath. (#47)
- Platform detection: distinguish AAD-joined from AD-joined in context schema. (#39)

---

## [0.3.0] — 2026-05-12

### Added
- **Native macOS gap analysis + drift detection** via platform dispatch. Controls with a clean macOS analog are evaluated; Linux-only controls (auditd, clamav, fail2ban, unattended-upgrades) emit SKIP with a platform-aware rationale. (#19)

### Fixed
- Drift: preserve systemctl signal + graceful degradation under `set -e`.

---

## [0.2.0] — 2026-05-09

### Added
- **Windows detection layer** — PowerShell probes (no admin required) for domain/AAD join, Intune enrollment, GPO, AppLocker, WDAC, Defender context. (#13, #14)
- **Drift report format improvements** — drift counter, summary deltas, per-finding rationale. (#10)
- Cross-platform foundation with Ubuntu/macOS gates. (#3)
- CODEOWNERS: added @keonik alongside @oscarsixsecllc. (#4)

### Fixed
- `harden-permissions.sh`: resolve `$SUDO_USER`'s home instead of `/root`. (#7)
- `harden-permissions.sh`: avoid creating secrets dir during hardening. (#5)
- Platform: make dsregcmd probe Constrained Language Mode safe; AppLocker probe avoids ToXml.
- Platform: `dsregcmd` capture via temp file.
- Faillock value parser fix. (#15)

---

## [0.1.2] — 2026-03-19

### Added
- CODEOWNERS to protect core security files.

### Changed
- README updated to v0.1.1 with correct URLs, control counts, validated results.
- Footnotes explaining SC/SI partial coverage, linking to expansion issues #1 and #2.

---

## [0.1.1] — 2026-03-19

### Added
- `Dockerfile.hardened` for OpenClaw agent validation testing.

---

## [0.1.0] — 2026-03-18

### Added
- Initial repository structure
- SKILL.md — OpenClaw agent integration
- `baseline/openclaw.json.baseline` — hardened OpenClaw config template with 800-53 control mappings
- `baseline/controls.json` — machine-readable control mapping (AC, AU, CM, IA full; SC, SI partial)
- `baseline/controls.md` — human-readable control mapping
- `assessment/assess.sh` — main gap analysis runner
- `assessment/checks/check-ac.sh` — Access Control checks
- `assessment/checks/check-au.sh` — Audit & Accountability checks
- `assessment/checks/check-cm.sh` — Configuration Management checks
- `assessment/checks/check-ia.sh` — Identification & Authentication checks
- `assessment/checks/check-sc.sh` — System & Communications Protection checks (partial)
- `assessment/checks/check-si.sh` — System & Information Integrity checks (partial)
- `assessment/report/report.sh` — report generator
- `assessment/report/templates/` — Markdown and JSON report templates
- `scripts/install.sh` — interactive one-shot hardening script
- `scripts/harden-ufw.sh` — UFW firewall configuration
- `scripts/harden-auditd.sh` — auditd setup and rules
- `scripts/harden-pam.sh` — PAM faillock and pwquality
- `scripts/harden-fail2ban.sh` — brute force protection
- `scripts/harden-systemd.sh` — systemd service hardening
- `scripts/harden-permissions.sh` — file/directory permissions
- `drift/snapshot.sh` — baseline snapshot capture
- `drift/compare.sh` — snapshot comparison
- `drift/drift-cron.sh` — scheduled drift detection with OpenClaw notification
- `docs/quickstart.md` — getting started guide
- `docs/control-mapping.md` — control mapping reference
- `docs/accepted-risks.md` — accepted risk documentation template
- `docs/sarge-agent.md` — Sarge community agent documentation
- README.md, CONTRIBUTING.md, SECURITY.md, CODE_OF_CONDUCT.md, LICENSE

### Platform Support
- Ubuntu 22.04 LTS (x86_64, arm64)
- Ubuntu 24.04 LTS (x86_64, arm64)

### 800-53 Coverage
- NIST SP 800-53 Rev 5
- AC (Access Control): Full
- AU (Audit & Accountability): Full
- CM (Configuration Management): Full
- IA (Identification & Authentication): Full
- SC (System & Communications Protection): Partial
- SI (System & Information Integrity): Partial

---

[Unreleased]: https://github.com/oscarsixsecllc/sarge/compare/v0.11.0...HEAD
[0.11.0]: https://github.com/oscarsixsecllc/sarge/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/oscarsixsecllc/sarge/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/oscarsixsecllc/sarge/compare/v0.7.0...v0.9.0
[0.7.0]: https://github.com/oscarsixsecllc/sarge/compare/v0.6.1...v0.7.0
[0.6.1]: https://github.com/oscarsixsecllc/sarge/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/oscarsixsecllc/sarge/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/oscarsixsecllc/sarge/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/oscarsixsecllc/sarge/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/oscarsixsecllc/sarge/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/oscarsixsecllc/sarge/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/oscarsixsecllc/sarge/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/oscarsixsecllc/sarge/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/oscarsixsecllc/sarge/releases/tag/v0.1.0
