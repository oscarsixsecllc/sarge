# Sarge — NIST 800-53 Hardening Standard for OpenClaw

> **Focus Forward. We've Got Your Six.** — Oscar Six Security LLC

[![Version](https://img.shields.io/badge/version-v0.1.1-green)](https://github.com/oscarsixsecllc/sarge/releases)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Ubuntu%2022.04%20%7C%2024.04-orange)](docs/quickstart.md)

Sarge is an open source NIST 800-53 Rev 5 hardening standard, gap analysis tool, and drift detection system designed exclusively for [OpenClaw](https://openclaw.ai) deployments.

**Sarge answers one question:** *Is your OpenClaw instance configured to NIST 800-53 standards? If not, what's wrong and how do you fix it?*

---

## What Sarge Does

- 📋 **Gap Analysis** — Scans your OpenClaw instance and underlying OS against a documented 800-53 baseline. Produces a structured report: control ID, status (pass/warn/fail), current value, required value, and remediation steps. **47 controls assessed across 6 control families.**
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

---

## Control Coverage (v0.1.1)

| Family | ID | Controls Assessed | Coverage |
|--------|----|-------------------|----------|
| Access Control | AC | 8 | Full |
| Audit & Accountability | AU | 8 | Full |
| Configuration Management | CM | 10 | Full |
| Identification & Authentication | IA | 10 | Full |
| System & Communications Protection | SC | 6 | Partial |
| System & Information Integrity | SI | 5 | Partial |
| **Total** | | **47** | |

**Baseline:** NIST SP 800-53 Rev 5 | **OS:** Ubuntu 22.04 / 24.04 LTS (x86_64, arm64)

> **Why SC and SI are partial:**
> 
> **SC (partial):** Many System & Communications Protection controls require network infrastructure decisions that vary by deployment — full boundary protection architecture, PKI certificate lifecycle, and cryptographic key management go beyond what a single-VM OpenClaw deployment can meaningfully self-assess. Sarge covers the controls that are universally applicable: transmission confidentiality (SC-8) and protection of data at rest (SC-28). Expanded SC coverage is tracked in [#1](https://github.com/oscarsixsecllc/sarge/issues/1).
>
> **SI (partial):** Full System & Information Integrity coverage (particularly SI-4 System Monitoring) requires a SIEM or centralized log analysis setup — a significant dependency that would narrow Sarge's applicability. Sarge covers what every deployment can implement: flaw remediation (SI-2), malware protection (SI-3), and script integrity verification (SI-7). Expanded SI coverage is tracked in [#2](https://github.com/oscarsixsecllc/sarge/issues/2).

---

## Validated Results

On a clean Ubuntu 24.04 LTS system with Sarge hardening applied:

| Status | Count |
|--------|-------|
| ✅ PASS | 30 |
| ⚠️ WARN | 7 |
| ❌ FAIL | 4 (systemd-dependent services only) |
| ⏭️ SKIP | 2 |

The 4 remaining FAILs (auditd daemon, pam_faillock, fail2ban) require systemd and will pass on a standard Linux VM.

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
