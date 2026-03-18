# Sarge — NIST 800-53 Hardening Standard for OpenClaw

> **Focus Forward. We've Got Your Six.** — Oscar Six Security LLC

Sarge is an open source NIST 800-53 Rev 5 hardening standard, gap analysis tool, and drift detection system designed exclusively for [OpenClaw](https://openclaw.ai) deployments.

**Sarge answers one question:** *Is your OpenClaw instance configured to NIST 800-53 standards? If not, what's wrong and how do you fix it?*

---

## What Sarge Does

- 📋 **Gap Analysis** — Scans your OpenClaw instance against a documented 800-53 baseline. Produces a structured report: control ID, status (pass/warn/fail), current value, required value, remediation steps.
- 🔒 **Hardening Scripts** — Idempotent, auditable scripts for UFW, auditd, PAM (faillock + pwquality), fail2ban, systemd service hardening, and file permissions.
- 📸 **Drift Detection** — Compares current system state against a captured baseline. Any drift generates a notification via your OpenClaw-configured channel.
- 🗺️ **Control Mapping** — Every OpenClaw setting and OS-level recommendation mapped to its 800-53 control ID, in both JSON and Markdown.

## What Sarge Is NOT

- Not a general-purpose compliance scanner
- Not a web vulnerability scanner (see: Radar)
- Not a CMMC certification tool (see: Sgt Major)
- Not a substitute for a professional security assessment
- Not applicable to non-OpenClaw systems

---

## Quickstart

```bash
# Clone the repo
git clone https://github.com/oscarsixsecurity/sarge.git
cd sarge

# Run gap analysis (no sudo required)
./assessment/assess.sh

# View report
cat /tmp/sarge-report-$(date +%Y%m%d).md

# Apply hardening (requires sudo, interactive)
sudo ./scripts/install.sh
```

Full docs: [docs/quickstart.md](docs/quickstart.md)

---

## Control Coverage (v1.0)

| Family | ID | Coverage |
|--------|----|----------|
| Access Control | AC | Full |
| Audit & Accountability | AU | Full |
| Configuration Management | CM | Full |
| Identification & Authentication | IA | Full |
| System & Communications Protection | SC | Partial |
| System & Information Integrity | SI | Partial |

---

## OpenClaw Integration

Sarge integrates with OpenClaw as a skill. Your agent can invoke:

- `"Run a Sarge gap analysis"` → executes `assess.sh`, posts summary to your channel
- `"Check for drift since last Sarge snapshot"` → runs `compare.sh`, reports changes
- `"Apply Sarge hardening"` → runs `install.sh` interactively
- `"Show Sarge control mapping for AC-2"` → reads from `controls.md`

See [SKILL.md](SKILL.md) for full agent integration instructions.

---

## Security

Sarge makes a hard commitment:

- ❌ **No data leaves your system.** Ever. No telemetry, no callbacks, no external API calls.
- ❌ **No API keys or service registration required.**
- ✅ **All scripts are human-readable and auditable.** No obfuscated code, no binary blobs.
- ✅ **Checksum verification available** for all scripts.
- ✅ **Sudo only required for hardening scripts** — gap analysis runs without elevated privileges.

See [SECURITY.md](SECURITY.md) for vulnerability disclosure policy.

---

## Platform Support

- Ubuntu 22.04 LTS (x86_64, arm64)
- Ubuntu 24.04 LTS (x86_64, arm64)
- Air-gap compatible — no internet connectivity required after install

---

## Repository Structure

```
sarge/
├── SKILL.md                    # OpenClaw skill definition
├── README.md                   # This file
├── baseline/                   # 800-53 baseline configs and control mappings
├── scripts/                    # Hardening scripts (require sudo)
├── assessment/                 # Gap analysis runner and check scripts
├── drift/                      # Drift detection and snapshot tools
└── docs/                       # Documentation
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Community contributions welcome.

## License

Apache 2.0 — Copyright 2026 Oscar Six Security LLC

## Community

- Discord: [Oscar Six Security](https://discord.gg/oscarsixsecurity) — channel `#sarge`
- GitHub Issues: [oscarsixsecurity/sarge/issues](https://github.com/oscarsixsecurity/sarge/issues)
