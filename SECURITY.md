# Security Policy — Sarge

## Overview

Sarge is a security tool. We hold ourselves to a high standard: any vulnerability in Sarge itself — including false negatives in gap analysis, privilege escalation vectors in hardening scripts, or bypass conditions — is treated as a critical issue.

---

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest (main branch) | ✅ Yes |
| Tagged releases (v0.x, v1.x) | ✅ Yes |
| Forks / unofficial distributions | ❌ No |

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

### Private Disclosure

Report vulnerabilities via:

1. **GitHub Security Advisories** (preferred): [oscarsixsecurity/sarge/security/advisories](https://github.com/oscarsixsecurity/sarge/security/advisories)
2. **Email**: security@oscarsixsecurity.com
3. **Discord DM**: @rhinders on the Oscar Six Security Discord (for urgent issues)

### What to Include

- Vulnerability type (e.g., privilege escalation, false negative, code injection)
- Affected component (script name, check ID, etc.)
- Steps to reproduce
- Impact assessment (what an attacker could do, what a false negative could hide)
- Your suggested fix (optional but appreciated)

### Response Timeline

| Milestone | Target |
|-----------|--------|
| Acknowledgment | 48 hours |
| Initial assessment | 5 business days |
| Fix or mitigation | 30 days (critical), 90 days (moderate/low) |
| Public disclosure | Coordinated with reporter |

We follow responsible disclosure: we will not take legal action against researchers acting in good faith.

---

## Scope

### In Scope

- **Hardening scripts** (`scripts/`) — privilege escalation, unintended system changes, bypasses
- **Assessment scripts** (`assessment/`) — false negatives that hide real vulnerabilities, privilege escalation
- **Drift detection** (`drift/`) — bypass conditions, notification suppression
- **SKILL.md** — agent manipulation vectors, prompt injection pathways
- **Control mappings** — incorrect mappings that give false assurance

### Out of Scope

- Vulnerabilities in OpenClaw itself (report to OpenClaw project)
- Vulnerabilities in the OS packages Sarge recommends installing (report to Ubuntu)
- Theoretical attacks without a practical exploit path
- Social engineering attacks on maintainers

---

## Security Design Principles

Sarge was designed with these security properties:

1. **No network calls** — Sarge never transmits data off the local system. If you see network activity, that is a vulnerability.
2. **No persistent elevated access** — Hardening scripts require explicit sudo invocation. No setuid binaries, no background daemons.
3. **Read-only by default** — Assessment scripts do not modify system state. Only hardening scripts make changes.
4. **Checksum verification** — Scripts include SHA-256 checksums for verification. Verify before executing.
5. **Auditable code** — No obfuscated code, no binary blobs, no `eval` of external content.

### Verifying Script Integrity

```bash
# Verify all scripts against known-good checksums
cd sarge
sha256sum -c checksums.sha256
```

If checksums don't match, do not run the scripts. File a security report.

---

## Threat Model

Sarge's threat model explicitly addresses:

- **Tampered Sarge install** — Malicious actor modifies scripts before operator runs them. Mitigated by checksum verification and GitHub signed releases.
- **Prompt injection via community input** — Malicious GitHub issue/PR attempts to manipulate the Sarge agent. Mitigated by agent trust hierarchy (all community input is untrusted; anomalous instructions escalated, never executed).
- **False negative exploitation** — Sarge reports a control as passing when it is failing, giving false assurance. Treated as high severity.
- **Script privilege escalation** — A hardening script could be exploited to gain root via a crafted system state. Scripts are audited against this.

---

## Hall of Fame

Responsible disclosures that improve Sarge security are credited here with reporter permission.

*(None yet — we're new. Be first.)*

---

## License

This security policy applies to Sarge as distributed by Oscar Six Security LLC under Apache 2.0.
