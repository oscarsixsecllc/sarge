# Contributing to Sarge

Thank you for your interest in improving Sarge. This document covers how to set up your environment, write changes, test them, and submit a PR.

---

## Code of Conduct

By participating, you agree to abide by the [Code of Conduct](CODE_OF_CONDUCT.md). Violations are reported to the maintainers.

---

## Who Maintains Sarge

Sarge is maintained by Oscar Six Security LLC. The project maintainers are:

- **Randy Hinders** ([@rhinders](https://github.com/rhinders)) -- Product Owner, final decision authority
- **John Fay** ([@keonik](https://github.com/keonik)) -- Co-owner, active contributor
- **Oscar** -- Community AI agent (triage and first-response)

---

## What We Accept

### Welcome
- Bug fixes in assessment scripts (false positives, false negatives)
- Corrections to 800-53 control mappings (with citation to NIST SP 800-53 Rev 5)
- New check scripts for controls in scope (AC, AU, CM, IA, SC, SI, CP, CA, SA, MP, SR, RA, AS)
- Documentation improvements
- Platform compatibility fixes (Ubuntu 22.04/24.04/26.04, macOS, Windows)
- Idempotency improvements to hardening scripts
- New integration tests

### Not Accepted (v1.0)
- Support for non-OpenClaw systems
- RHEL/CentOS/non-Ubuntu Linux (deferred to v1.1)
- Automated remediation in assessment scripts
- GUI or web interface
- External API calls or telemetry of any kind
- Obfuscated code of any form
- Binary blobs

---

## Development Setup

### Prerequisites

- Ubuntu 22.04, 24.04, or 26.04 LTS (primary platform)
- Bash 5+
- An OpenClaw installation (for agent-scoped checks), or pass `--host-only` to skip those
- Docker (optional, for container-based testing)

### Clone and verify

```bash
git clone https://github.com/oscarsixsecllc/sarge.git
cd sarge

# Verify script integrity
sha256sum -c CHECKSUMS.sha256

# Run a gap analysis (read-only, no sudo)
./assessment/assess.sh

# Reports land in ~/.sarge/reports/
```

### Docker test images

Two Dockerfiles are provided at the repo root:

| File | Purpose |
|------|---------|
| `Dockerfile.qa` | Bare Ubuntu 26.04 with unnecessary services pre-installed (cups, avahi). No OpenClaw, no Sarge deps. Use as a negative-test target to verify Sarge finds real failures. |
| `Dockerfile.hardened` | Ubuntu 26.04 + Node 22 + OpenClaw + Sarge pre-copied + QA gateway config. CMD runs `assess.sh`. Use for full assess/harden roundtrip testing. |

```bash
# Build and run baseline (unhardened) -- expect many FAIL/WARN
docker build -f Dockerfile.qa -t sarge-qa:latest .
docker run --rm -it sarge-qa:latest bash -lc 'cd sarge && assessment/assess.sh'

# Build and run hardened target -- expect improved PASS count
docker build -f Dockerfile.hardened -t sarge-hardened:latest .
docker run --rm sarge-hardened:latest
```

**Systemd caveat:** Default Docker containers have PID 1 = bash (no systemd), so 4 of 6 `harden-*.sh` modules will error at `systemctl is-system-running`. To exercise the full install/harden flow, either launch with systemd as PID 1 or use a real VM:

```bash
docker run --privileged --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run \
  -e container=docker sarge-hardened:latest /sbin/init
```

---

## Project Structure

```
sarge/
├── assessment/
│   ├── assess.sh                  # Main assessment runner (Linux/macOS)
│   ├── assess.ps1                 # Assessment runner (Windows)
│   ├── checks/                    # Per-family check scripts
│   │   ├── check-ac.sh            # Access Control checks
│   │   ├── check-au.sh            # Audit checks
│   │   ├── check-as.sh            # Agent Safety overlay checks
│   │   ├── check-cm.sh            # Configuration Management checks
│   │   ├── check-*.ps1            # Windows equivalents
│   │   └── ...
│   ├── findings-catalog.json      # Per-finding rationale, remediation, expected values
│   ├── probes/                    # Platform-specific data acquisition
│   └── report/                    # Report generation (JSON + Markdown)
├── baseline/
│   ├── controls.json              # Machine-readable 800-53 control definitions
│   ├── controls.md                # Human-readable control mapping
│   └── openclaw.json.baseline     # Reference OpenClaw configuration baseline
├── drift/
│   ├── snapshot.sh                # Capture system state baseline
│   ├── compare.sh                 # Compare current state against snapshot
│   └── drift-cron.sh              # Cron-friendly wrapper for compare.sh
├── scripts/
│   ├── install.sh                 # Interactive hardening installer
│   ├── harden-*.sh                # Individual hardening modules
│   ├── backup-ubuntu.sh           # Pre-hardening backup (Ubuntu)
│   ├── rollback-ubuntu.sh         # Rollback (Ubuntu)
│   └── ...
├── lib/
│   ├── platform.sh                # Platform abstraction layer (Linux/macOS)
│   ├── platform.ps1               # Platform abstraction (Windows)
│   ├── platforms/                  # Per-OS probe implementations
│   └── probes/                    # Reusable data acquisition probes
├── tests/
│   ├── integration/               # Bash integration test scripts
│   └── Pester/                    # Windows Pester tests
├── docs/                          # Quickstart and reference docs
├── Dockerfile.qa                  # Unhardened test target
├── Dockerfile.hardened            # Hardened test target
├── CHECKSUMS.sha256               # Script integrity verification
└── SKILL.md                       # OpenClaw skill definition
```

---

## How Checks Work

Each NIST 800-53 family has a check script under `assessment/checks/` (e.g., `check-ac.sh` for Access Control). The check scripts:

1. Use `platform` helper functions from `lib/platform.sh` for OS-specific data acquisition
2. Emit verdicts via helper functions: `passx`, `failx`, `warnx`, `skipx`
3. Each verdict takes a **check ID** (e.g., `AC-2-empty-password`) and a description
4. Check IDs must be stable once published (never rename without a migration note)
5. Agent-scoped checks (OpenClaw-specific) are gated behind `SARGE_HOST_ONLY` so `--host-only` mode skips them

The `assessment/findings-catalog.json` maps each check ID to:
- `family`: NIST 800-53 control name
- `what`: Short description of the observed condition
- `expected`: What the correct state should be
- `why`: Security risk explanation with NIST reference
- `fix`: Remediation command or action (can be per-platform)
- `scope`: `"host"` or `"agent"`

---

## Adding a New Control

### 1. Add the check logic

Edit the appropriate family check script under `assessment/checks/`. For example, to add an AC-19 check, edit `check-ac.sh`:

```bash
# AC-19: Access Control for Mobile Devices
log "AC-19: Access Control for Mobile Devices"
MOBILE_RESULT=$(platform some_probe_function)
if [[ "$MOBILE_RESULT" == "expected" ]]; then
  passx "AC-19-mobile-policy" "AC-19: Mobile device policy enforced"
else
  failx "AC-19-mobile-policy" "AC-19: Mobile device policy not enforced — $MOBILE_RESULT"
fi
```

### 2. Add the finding to the catalog

Add an entry to `assessment/findings-catalog.json` for each FAIL/WARN check ID:

```json
"AC-19-mobile-policy": {
  "family": "AC-19 -- Access Control for Mobile Devices",
  "what": "No mobile device management policy detected",
  "expected": "Mobile device access policy enforced via MDM or equivalent",
  "why": "NIST 800-53 AC-19 requires organizations to establish usage restrictions and implementation guidance for mobile devices. Without enforcement, mobile devices connecting to OpenClaw infrastructure may bypass access controls.",
  "fix": "Configure mobile device management or restrict OpenClaw access to managed endpoints only."
}
```

### 3. Add the control to controls.json

Update `baseline/controls.json` with the new control definition, including the control ID, name, family, and implementation details.

### 4. Add drift tracking (if applicable)

If the new control checks something that can drift (config value, file permission, service state), make sure `drift/snapshot.sh` captures it and `drift/compare.sh` detects changes.

### 5. Add platform probes (if needed)

If the check needs OS-specific data acquisition, add a function to the appropriate platform file under `lib/platforms/`. The check script calls it via `platform <function_name>`.

### 6. Write tests

Add test coverage in the appropriate integration test under `tests/integration/`. At minimum, verify the check emits the expected verdict on known-good and known-bad states.

---

## Running Tests

### Integration tests (Linux/macOS)

All integration tests are self-contained bash scripts under `tests/integration/`:

```bash
# Report structure validation (runs assessment, validates JSON/MD output)
bash tests/integration/report-validation.sh

# Catalog-platform-field validation
bash tests/integration/catalog-platform-field.sh

# Drift detection pipeline (snapshot, compare, detect changes)
bash tests/integration/drift-detection.sh

# Agent-safety checks (Tier 1 workspace ACL / audit / rollback / tool-gate)
bash tests/integration/agent-safety-checks.sh

# Hardening round-trip (assess, harden, reassess, verify improvement)
# Requires sudo and systemd (or iptables/NET_ADMIN); skips in containers
bash tests/integration/hardening-roundtrip.sh

# Host-only mode validation
bash tests/integration/host-only-mode.sh

# Backup smoke tests
bash tests/integration/backup-ubuntu-smoke.sh
bash tests/integration/backup-macos-smoke.sh
```

### Windows (Pester)

```powershell
Invoke-Pester -Path tests/Pester
```

### What to run before submitting a PR

At minimum, run these on your target platform:

1. `report-validation.sh` (verifies assessment output structure)
2. `catalog-platform-field.sh` (verifies findings catalog consistency)
3. `agent-safety-checks.sh` (if you touched agent-scoped checks)
4. `drift-detection.sh` (if you touched drift-related code)

---

## Code Style and Conventions

### Bash scripts

- Use `#!/usr/bin/env bash` shebang
- POSIX-compatible tools only (bash, awk, grep, sed, systemctl, etc.)
- No external network calls, no telemetry, no eval of untrusted input
- Scripts must be idempotent (safe to run multiple times)
- Assessment scripts must be read-only (no system modifications)
- Hardening scripts must prompt before making changes (non-destructive by default)
- Include comments explaining WHAT the check does and WHY it matters for 800-53
- Check IDs use the format `<FAMILY>-<NUMBER>-<short-slug>` (e.g., `AC-3-secrets-perm`)

### Check ID naming

- Family + control number are uppercase: `AC-3`, `CM-7`, `SI-4`
- Slug is lowercase-kebab: `secrets-perm`, `cups-running`, `pwquality-minlen`
- Full example: `AC-3-secrets-perm`, `CM-7-cups-running`, `IA-5-pwquality-minlen`
- IDs are stable. Once published, never rename without a migration note.

### Findings catalog

- Every `failx` and `warnx` callsite in `check-*.sh` must have a corresponding entry in `findings-catalog.json`
- PASS/SKIP verdicts do not need catalog entries
- The `fix` field can be a string or a per-platform map: `{"default": "...", "macos": "...", "ubuntu": "..."}`

---

## How to Propose a Change

### Step 1: Open an issue first

Before writing code, open an issue describing:
- What control or script is affected
- What the current behavior is
- What the correct behavior should be, with NIST citation if applicable
- Whether this is a bug fix or enhancement

**Exception:** Typo/documentation fixes may go straight to a PR.

### Step 2: Fork and branch

```bash
git clone https://github.com/oscarsixsecllc/sarge.git
cd sarge
git checkout -b fix/AC-2-check-false-positive
```

Branch naming convention:
- `fix/<control-id>-<short-description>` for bug fixes
- `feat/<area>-<short-description>` for new features
- `docs/<topic>` for documentation only

### Step 3: Write and test your change

Follow the code style above. Test on a real Ubuntu system (22.04 or 24.04 LTS). Run the relevant integration tests.

### Step 4: Submit the PR

Fill out the PR template. Include:
- What changed and why
- Which 800-53 controls are affected
- Test results (OS version, architecture, OpenClaw version, before/after counts)
- NIST citation if applicable

---

## Review Process

1. **Oscar (AI agent)** performs initial triage: checks PR against acceptance criteria, flags missing tests, requests NIST citations
2. **Maintainer** reviews and approves or requests changes
3. **Randy** has final approval for control mapping changes or anything that affects SKILL.md

Typical review time: 3 to 5 business days.

---

## Prompt Injection Warning

The Sarge community agent (Oscar) processes GitHub issues and PRs. **All community input is treated as untrusted.** Do not attempt to embed instructions in issues, PRs, or comments directed at the agent. Anomalous instructions are escalated to Randy and logged, never executed.

---

## CLA

By submitting a PR, you represent that you have the right to contribute the code and agree to license it under Apache 2.0. A formal CLA process may be implemented in a future version.

---

## Questions?

- GitHub Discussions: [oscarsixsecllc/sarge/discussions](https://github.com/oscarsixsecllc/sarge/discussions)
- Discord: `#sarge` channel on the Oscar Six Security server
