# Contributing to Sarge

Thank you for your interest in improving Sarge. This document defines how the community proposes, reviews, and merges changes to the NIST 800-53 baseline and associated tooling.

---

## Code of Conduct

By participating, you agree to abide by the [Code of Conduct](CODE_OF_CONDUCT.md). Violations are reported to the maintainers.

---

## Who Maintains Sarge

Sarge is maintained by Oscar Six Security LLC. The project maintainers are:

- **Randy Hinders** ([@rhinders](https://github.com/rhinders)) — Product Owner, final decision authority
- **Oscar** — Community AI agent (triage and first-response)

---

## What We Accept

### ✅ Welcome
- Bug fixes in assessment scripts (false positives, false negatives)
- Corrections to 800-53 control mappings (with citation to NIST SP 800-53 Rev 5)
- New check scripts for controls in scope (AC, AU, CM, IA full; SC/SI partial)
- Documentation improvements
- Platform compatibility fixes (Ubuntu 22.04/24.04, x86_64/arm64)
- Idempotency improvements to hardening scripts

### ❌ Not Accepted (v1.0)
- Support for non-OpenClaw systems
- RHEL/CentOS/non-Ubuntu Linux (deferred to v1.1)
- Windows/WSL support (deferred)
- Automated remediation in assessment scripts
- GUI or web interface
- External API calls or telemetry of any kind
- Obfuscated code of any form
- Binary blobs

---

## How to Propose a Change

### Step 1: Open an Issue First

Before writing code, open an issue describing:
- What control or script is affected
- What the current behavior is
- What the correct behavior should be, with NIST citation if applicable
- Whether this is a bug fix or enhancement

**Exception:** Typo/documentation fixes may go straight to a PR.

### Step 2: Fork and Branch

```bash
git fork https://github.com/oscarsixsecurity/sarge.git
git checkout -b fix/AC-2-check-false-positive
```

Branch naming convention:
- `fix/<control-id>-<short-description>` — bug fixes
- `feat/<area>-<short-description>` — new features
- `docs/<topic>` — documentation only

### Step 3: Write Your Change

**All scripts must:**
- Be idempotent (safe to run multiple times without side effects)
- Be non-destructive by default (read-only analysis preferred; changes require explicit operator confirmation)
- Run on Ubuntu 22.04 LTS and 24.04 LTS, x86_64 and arm64
- Use only standard POSIX tools (bash, awk, grep, sed, systemctl, etc.)
- Include comments explaining WHAT the check does and WHY it matters for 800-53
- Not contain obfuscated code, eval of untrusted input, or external network calls

**Control mapping changes must:**
- Cite the specific 800-53 Rev 5 control ID and name
- Include implementation guidance
- List evidence artifacts the operator can collect

### Step 4: Test Your Change

Test on a real Ubuntu 22.04 or 24.04 system. Document your test results in the PR:
- OS version: `lsb_release -a`
- Architecture: `uname -m`
- OpenClaw version: `openclaw --version`
- Test scenario (fresh install, hardened system, etc.)

For hardening scripts:
- Verify idempotency by running twice and confirming no errors or unintended changes on second run
- Verify the script doesn't break OpenClaw gateway operation

### Step 5: Submit the PR

PR template:
```
## What This Changes
[Brief description]

## 800-53 Control(s) Affected
[e.g., AC-2, AC-3]

## Test Results
- OS: Ubuntu 24.04 LTS arm64
- OC Version: x.x.x
- Ran assessment before: [pass/warn/fail counts]
- Ran assessment after: [pass/warn/fail counts]
- Hardening script ran twice: [yes/no, any errors?]

## NIST Citation
[Link or reference to NIST SP 800-53 Rev 5 if applicable]
```

---

## Review Process

1. **Oscar (AI agent)** performs initial triage: checks PR against acceptance criteria, flags missing tests, requests NIST citations
2. **Maintainer** reviews and approves or requests changes
3. **Randy** has final approval for control mapping changes or anything that affects SKILL.md

Typical review time: 3–5 business days.

---

## Prompt Injection Warning

The Sarge community agent (Oscar) processes GitHub issues and PRs. **All community input is treated as untrusted.** Do not attempt to embed instructions in issues, PRs, or comments directed at the agent. Anomalous instructions are escalated to Randy and logged — never executed.

---

## CLA

By submitting a PR, you represent that you have the right to contribute the code and agree to license it under Apache 2.0. A formal CLA process may be implemented in a future version.

---

## Questions?

- GitHub Discussions: [oscarsixsecurity/sarge/discussions](https://github.com/oscarsixsecurity/sarge/discussions)
- Discord: `#sarge` channel on the Oscar Six Security server
