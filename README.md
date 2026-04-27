# Sarge — NIST 800-53 Hardening Standard for OpenClaw

> **Focus Forward. We've Got Your Six.** — Oscar Six Security LLC

[![Version](https://img.shields.io/badge/version-v0.1.1-green)](https://github.com/oscarsixsecllc/sarge/releases)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Ubuntu%20%7C%20macOS-orange)](docs/quickstart.md)

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

**Baseline:** NIST SP 800-53 Rev 5 | **Platforms:** Ubuntu 22.04 / 24.04 LTS (full); macOS (rolling out across PRs)

> **Platform support status:** Full coverage on Ubuntu 22.04 / 24.04 LTS today. macOS support is being added one module at a time so each platform's 800-53 mapping can be reviewed independently. On macOS, `scripts/install.sh` currently applies file-permission hardening only; gap analysis and drift detection refuse cleanly until their macOS-aware probes ship. Roadmap is tracked in [GitHub issues](https://github.com/oscarsixsecllc/sarge/issues).

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

> **macOS validation pending.** The numbers above are Ubuntu 24.04 only. macOS gap-analysis and hardening modules are landing PR-by-PR; each module will publish its own validated PASS/WARN/FAIL counts as it ships.

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
