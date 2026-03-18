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
