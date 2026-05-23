# Sarge — NIST 800-53 Hardening Standard for OpenClaw

> **Focus Forward. We've Got Your Six.** — Oscar Six Security LLC

[![Version](https://img.shields.io/badge/version-v0.1.1-green)](https://github.com/oscarsixsecllc/sarge/releases)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Ubuntu%20%7C%20macOS%20%7C%20Windows-orange)](docs/quickstart.md)

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

## Threat model & scope

Sarge is an **agent-safety control**, not a generic OS hardening kit.

The primary use case is verifying that a host running OpenClaw (or another AI agent) meets the organization's baseline **before** the agent is allowed to make autonomous changes. The risk Sarge addresses isn't "this laptop has CVE-X open" in the abstract — it's "an agent with shell or API access is about to act on a system whose posture we haven't verified, and a wrong action against a weak baseline cascades into incident territory."

Two halves of the safety net:

1. **Pre-flight (Sarge):** assess the host against an 800-53 baseline. If the host isn't safe for autonomous agent action — weak ACLs, missing audit, no antimalware, MSA-attached identity outside org control — that should be visible *before* the agent is handed the keys.
2. **Post-action recovery (rollback/restore, tracked in issues #28 / #29 / #30):** when the agent does make the wrong change, the rollback path is the safety net. Sarge's drift detection feeds this — drift is the signal that a recovery may be needed.

Sarge covers the broader 800-53 control surface (not just an "agent-relevant subset") because most agent-safety failures cascade from baseline hygiene issues. Weak workspace ACLs let one compromised tool exfiltrate secrets; missing audit means an agent's wrong action is invisible; no antimalware means a downloaded artifact runs unchecked. We cover the agent-relevant controls **and** the surrounding baseline that makes them meaningful.

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

**Baseline:** NIST SP 800-53 Rev 5 | **Platforms:** Ubuntu 22.04 / 24.04 LTS (full); macOS (gap analysis + drift; permissions hardening only); Windows (detection + breadth-first recommendations across all 6 control families; hardening blocked on pre-hardening backup work)

> **Platform support status:** Full coverage on Ubuntu 22.04 / 24.04 LTS today. On macOS, gap analysis (`assessment/assess.sh`) and drift detection (`drift/snapshot.sh`, `drift/compare.sh`) now run natively — controls with a clean macOS analog (filesystem, accounts, firewall, listening ports, SSH, integrity checksums, session timeout) are evaluated; controls rooted in Linux-only facilities (auditd / pam_faillock / pwquality / login.defs / apt / unattended-upgrades / clamav / fail2ban) are skipped with a platform-aware rationale rather than emitting misleading FAILs with Ubuntu remediation text. `scripts/install.sh` on macOS still applies file-permission hardening only; native macOS hardening modules (firewall, SSH, logging policy) are tracked in [GitHub issues](https://github.com/oscarsixsecllc/sarge/issues). **Windows now has detection + recommendation coverage across all six 800-53 families (AC, AU, CM, IA, SC, SI)** via `assessment/assess.ps1` — read-only PowerShell probes capture enterprise context (domain / AAD join, Intune enrollment, GPO, AppLocker, WDAC, Defender) AND per-control verdicts with concrete remediation steps. Findings on domain-joined hosts are tagged "may be overridden by GPO" unless `--inspect-policy` (Phase 1b, [#31](https://github.com/oscarsixsecllc/sarge/issues/31)) is passed — that mode probes managed-policy state (Intune MDM CSP on AAD-joined hosts; GPO via RSAT or `gpresult /h` on AD-joined hosts), emits a top-level `WIN-POL-1` finding when an AAD-joined device is not enrolled in any MDM, and overlays verdicts onto Phase 1a control findings (FAIL/WARN -> ENFORCED-EXTERNALLY) where managed policy already enforces the relevant setting. Side-output: `policy-inventory.json` in the run folder. Pester tests live under `tests/Pester/windows-*.Tests.ps1` (mocked cmdlets; run locally via `Invoke-Pester -Path tests/Pester`; no CI workflow wired up yet). Windows hardening (Phase 2) is gated on the pre-hardening backup features tracked in [#28](https://github.com/oscarsixsecllc/sarge/issues/28) (Windows), [#29](https://github.com/oscarsixsecllc/sarge/issues/29) (Ubuntu), and [#30](https://github.com/oscarsixsecllc/sarge/issues/30) (macOS). Sarge on Windows is scoped to OpenClaw deployment hardening — it is not a generic Windows hardening tool. Roadmap is tracked under parent issue [#12](https://github.com/oscarsixsecllc/sarge/issues/12).

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

> **Testing in containers — known limitation.** When running `scripts/install.sh` inside a default Docker container (PID 1 = `bash`/`sleep`, no systemd), only `harden-permissions` and `harden-pam` will apply — the other 4 modules error at `systemctl is-system-running`. To exercise the full install flow in a container, start it with systemd as PID 1 (`docker run --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run -e container=docker <image> /sbin/init`), or use a real VM (multipass / vagrant / lima). Validation runs against a standard Ubuntu 24.04 LTS VM, not a container.

> **macOS coverage.** The numbers above are Ubuntu 24.04 only. On macOS, gap analysis and drift detection now run natively; controls without a macOS-native equivalent emit SKIP with a platform-aware rationale (delegated to MDM, Endpoint Security, pwpolicy, etc.) rather than a misleading FAIL. Native macOS hardening modules (firewall, SSH, logging policy) are landing per-PR — each will publish its own validated PASS/WARN/FAIL count as it ships.

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

## Pre-hardening backup + rollback (Ubuntu)

Before any `harden-*.sh` runs on Ubuntu, Sarge captures a layered backup
so every change is reversible. Closes
[#29](https://github.com/oscarsixsecllc/sarge/issues/29).

### Snapshot tooling — preference order

`scripts/backup-ubuntu.sh` probes for snapshot tooling and uses the first
match. The file-level snapshot **always** runs regardless of which
block-level tool was selected (it's the safety net).

1. **Btrfs / ZFS root subvolume snapshot** — if `stat -f -c '%T' /`
   returns `btrfs` or `zfs`. Snapshot tagged
   `sarge-pre-hardening-<run-id>`.
2. **timeshift** — if installed.
   `timeshift --create --comments "Sarge pre-hardening <run-id>" --tags O`.
3. **LVM thin snapshot** — if root LV is on a thin pool. Classic LVM
   is skipped (thick provisioning makes snapshots brittle).
4. **File-level snapshot (fallback, always collected)** —
   `cp -p` of every `/etc/` path Phase 2 hardening can touch, plus
   `ufw status verbose`, `ufw show added`, `auditctl -l`, `auditctl -s`,
   `systemctl list-unit-files --state=enabled,disabled,masked`,
   `dpkg --get-selections`, full `/etc/pam.d/`.

Artifacts land under `~/.sarge/runs/<run-id>/backup/`:

```
~/.sarge/runs/<run-id>/backup/
├── fs/etc/...           # mirrored /etc tree (login.defs, ssh/, pam.d/, audit/rules.d/, sysctl.d/, security/limits.conf)
├── ufw-state.txt
├── audit-state.txt
├── services.txt
├── packages.txt
├── backup.log
├── rollback.sh          # auto-generated, executable
└── summary.md
```

### Usage

```bash
# Interactive opt-in (Y/Enter proceeds, N explicit-skip)
bash scripts/backup-ubuntu.sh --run-id "$SARGE_RUN_ID"

# Unattended (CI / chained from assess.sh)
bash scripts/backup-ubuntu.sh --unattended --run-id "$SARGE_RUN_ID"

# Roll back the most recent run (prompts for confirmation)
bash scripts/rollback-ubuntu.sh

# Roll back a specific run
bash scripts/rollback-ubuntu.sh --run-id 20260523-120000

# Unattended rollback
bash scripts/rollback-ubuntu.sh --backup-dir ~/.sarge/runs/<id>/backup --unattended
```

`--test-mode` logs the chosen snapshot tool but skips the destructive
block-level snapshot — used by the smoke test
(`tests/integration/backup-ubuntu-smoke.sh`).

### Sandbox / non-root testing

`rollback.sh` honors `SARGE_ROLLBACK_ROOT=<prefix>` for sandbox round-trip
tests — when set, file restores are written under the prefix and the
systemctl / ufw / auditctl / dpkg branches are skipped.

---

## Pre-hardening backup + rollback (macOS)

> **Untested on real macOS hardware.** Oscar Six does not currently have
> a Mac test surface available. The macOS backup + rollback scripts
> (`scripts/backup-macos.sh`, `scripts/rollback-macos.sh`) follow the
> issue [#30](https://github.com/oscarsixsecllc/sarge/issues/30) spec
> and the Ubuntu/Windows backup patterns, but have only been exercised
> via `bash -n` and a Linux dry-run smoke test
> (`tests/integration/backup-macos-smoke.sh`). The macOS-specific
> commands (`tmutil`, `pfctl`, `defaults`, `socketfilterfw`, `csrutil`,
> `spctl`, `fdesetup`, `launchctl`) have **not** been validated against
> live binaries. **Community validation contributions are welcome** —
> open a PR or comment on issue #30 with results from a real Mac.

Before any `harden-*.sh` runs on macOS, Sarge captures a layered backup
so any change is reversible:

1. **APFS local snapshot** (heavy-lift backstop) via `tmutil localsnapshot`.
   Survives reboots, costs no extra disk until divergence, restorable
   via `tmutil restore <snapshot-id>`. The script **fails loudly** if
   the boot volume isn't APFS or local snapshots are disabled — it does
   not silently proceed.
2. **Optional Time Machine snapshot** via `tmutil startbackup --block`
   when `--time-machine` is passed and TM is configured. Slower;
   complements the APFS snapshot.
3. **File-level capture** under `~/.sarge/runs/<run-id>/backup/`:
   - `/etc/pam.d/`, `/etc/ssh/sshd_config`, `/etc/sudoers.d/`,
     `/etc/security/audit_*` copied with `cp -Rp`
   - `socketfilterfw --getglobalstate` + per-app rules → `socketfilterfw.txt`
   - `pfctl -sa` → `pf-state.txt`
   - `launchctl list` → `launchctl.txt`
   - `defaults read` of touched domains (`com.apple.loginwindow`,
     `com.apple.screensaver`, `com.apple.security`,
     `/Library/Preferences/com.apple.alf`) → `defaults-<domain>.txt`
   - `csrutil status`, `spctl --status`, `fdesetup status` →
     `security-status.txt`
4. **Generated `rollback.sh`** that reverses each granular artifact
   (cp `/etc/` back, `pfctl -f` the saved state, re-enable
   socketfilterfw, replay launchctl delta, defaults manual-review
   pointer) and documents the APFS snapshot ID as the backstop.
5. **`summary.md`** with capture inventory + both rollback paths.

### Usage

```bash
# Interactive (prompts before snapshot)
bash scripts/backup-macos.sh --run-id "$SARGE_RUN_ID"

# Unattended (CI / chained from assess.sh)
bash scripts/backup-macos.sh --unattended --run-id "$SARGE_RUN_ID"

# Also trigger a Time Machine snapshot
bash scripts/backup-macos.sh --unattended --time-machine --run-id "$SARGE_RUN_ID"

# Roll back the most recent run
bash scripts/rollback-macos.sh --latest

# Roll back a specific run
bash scripts/rollback-macos.sh --run-id 20260523-120000
```

### Heavy-lift fallback

If granular rollback fails or leaves the system in an unexpected state,
restore the APFS local snapshot:

```bash
tmutil listlocalsnapshots /
tmutil restore <snapshot-id-from-summary.md>
```

### Phase 2 follow-ups (tracked as untested debt)

- `defaults read` capture is human-readable, not directly importable
  by `defaults import`. Phase 2 should switch to
  `defaults export <domain> <file>.plist` so `rollback.sh` can
  re-import non-interactively.
- `pfctl -sa` is a mixed-section dump; a finer-grained `pfctl -sr`
  capture would let `rollback.sh` reload rules deterministically.
- `socketfilterfw` per-app rules have no bulk-import; rollback emits
  the captured `--listapps` output for manual replay.

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
