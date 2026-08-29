# Changelog — Sarge

All notable changes to Sarge will be documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### In Progress
- SC and SI check scripts
- Drift detection cron
- ClawhHub submission

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
  - Each AS check maps to underlying NIST 800-53 Rev 5 controls in its catalog entry (AC-3, AC-6, AU-2, AU-9, CM-2, CM-5, CM-6, CM-7, SI-4, SI-7). See DECISIONS.md for the fold-under-SI-vs-new-family reasoning.
- New integration test `tests/integration/agent-safety-checks.sh` — 19 assertions covering three end-to-end scenarios (nothing installed / everything present / weak permissions), catalog coverage, and the host-only-mode agent-scope guard.
- **Baseline schema refresh (`baseline/openclaw.json.baseline` v0.2.0)** — added 11 sections that had drifted out since 2026-03: `approvals` (approval routing), `hooks`, `agents.subagents`, `skills.workshop`, `session.compaction`, `models.rateLimit`, `auth.profiles`, `mcp.servers`, `browser`, `sandboxes`, `plugins.workboard`. Each section carries `_control` annotations tying the hardening choice to the covering NIST 800-53 control. Section-mapping decisions documented in DECISIONS.md. (#65)

### Fixed
- **SC-28 config check + `harden-permissions.sh` now target the live OpenClaw config filename** (`openclaw.json`, with `config.json` fallback for legacy pre-2026.4 installs). Previously both looked only for the retired `config.json`, so SC-28 config-perm / config-owner silently SKIPped on every real install and `harden-permissions` never chmod'd the file that actually holds provider tokens. Config backups (`openclaw.json.bak*`, `.backup*`) get the same 600 treatment. (#61)
- **SC-28 world-readable check narrowed to a known-sensitive allowlist** — only the OpenClaw config (+ backups), `secrets/` / `credentials/` / `auth/`, and credential-shaped filenames (`*.key`, `*.pem`, `*.env`, `*-token*`, `*-secret*`, `id_rsa*`, `id_ed25519*`). Previously flagged intentionally-readable workspace canon (SOUL.md, HEARTBEAT.md, AGENTS.md, USER.md, TOOLS.md, BOOTSTRAP.md) and `workspace/.git/*` on every install, drowning real leaks in noise. See DECISIONS.md for the scoping rationale. (#64)

### Changed
- **README validated-results and control-coverage numbers refreshed** to reflect actual output on Ubuntu 24.04 + OpenClaw 2026.7.1-2 with the two fixes above applied: 57 checks / PASS 34 / WARN 12 / FAIL 9 / SKIP 2 (was: 47 / 30 / 7 / 4 / 2). Per-family table updated (AC 17, AU 5, CM 15, IA 10, SC 5, SI 5). Old numbers were from the day-1 validation image (2026-03-19); intervening per-item enumeration expansion, stock Ubuntu 24.04 desktop packages, and the SC-28 false positive together account for the delta. (#66)
- Added top-level `DECISIONS.md` recording non-obvious scoping calls (starting with the two SC-28 decisions above).

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

## Version Roadmap

| Version | Target | Scope |
|---------|--------|-------|
| 0.1.0 | Mar 2026 | Initial structure, AC/AU/CM/IA checks, all hardening scripts |
| 0.2.0 | Apr 2026 | SC/SI complete, drift detection, full report generation |
| 0.3.0 | Apr 2026 | ClawhHub submission, soft launch, community Discord open |
| 1.0.0 | May 2026 | Public launch, blog post, community feedback incorporated |

---

[Unreleased]: https://github.com/oscarsixsecurity/sarge/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/oscarsixsecurity/sarge/releases/tag/v0.1.0
