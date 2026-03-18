# Sarge — NIST 800-53 Hardening for OpenClaw

**Publisher:** oscarsixsecurity  
**Version:** 0.1.0  
**License:** Apache 2.0  
**Requires:** OpenClaw, Ubuntu 22.04/24.04 LTS (x86_64 or arm64)

## What Is Sarge?

Sarge is a NIST 800-53 Rev 5 gap analysis, hardening, and drift detection tool for OpenClaw deployments. It tells you whether your OpenClaw instance and its underlying OS meet the 800-53 baseline — and exactly what to fix if they don't.

**Sarge does NOT transmit any data off your system. No external services. No API keys required.**

## Invocation

Once installed, you can invoke Sarge by telling your OpenClaw agent:

- "Run a Sarge gap analysis" → runs assess.sh, generates report, posts summary
- "Check for drift since last Sarge snapshot" → runs compare.sh, reports changes
- "Apply Sarge hardening scripts" → runs install.sh interactively (requires confirmation)
- "Show Sarge control mapping for AC-2" → reads from baseline/controls.md
- "Take a Sarge snapshot" → runs snapshot.sh to capture current state

## Installation

  git clone https://github.com/oscarsixsecurity/sarge.git
  cd sarge
  chmod +x scripts/*.sh assessment/assess.sh assessment/report/report.sh drift/*.sh

Gap analysis requires no sudo. Hardening scripts require sudo only when applying changes.

## Security Model

- All scripts are human-readable bash — no binary blobs, no obfuscated code
- No network calls of any kind
- Sudo required only for hardening scripts; gap analysis is read-only
- Scripts are idempotent — safe to run multiple times
- Non-destructive by default — no changes without explicit operator confirmation
