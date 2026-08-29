# DECISIONS — Sarge

Non-obvious design and scoping calls made during Sarge development. Each entry
is dated, references the driving issue(s) or PR(s), and states what was decided
and why. Add entries at the top; do not edit historic entries.

---

## 2026-08-29 — SC-28 world-readable check: narrow to a sensitive allowlist

**Issue:** [#64](https://github.com/oscarsixsecllc/sarge/issues/64)

The previous SC-28 world-readable check ran `find ~/.openclaw -perm /004` and
FAILed the report on every hit. That caught intentionally-readable workspace
canon (SOUL.md, HEARTBEAT.md, AGENTS.md, USER.md, TOOLS.md, BOOTSTRAP.md) plus
`workspace/.git/*` internals on every real OpenClaw install — none of which
carry secrets. The signal (an actual world-readable credential file) was
drowned in noise, and the FAIL count made Sarge's reported posture look worse
than it was.

Three fixes were on the table:

1. **Exclusion list** — keep the recursive scan; skip known workspace canon.
   Rejected: exclusion lists rot as OpenClaw's workspace layout grows, and any
   file that lives outside the exclusion list still creates a FAIL for
   operators who checked in their own docs.

2. **Downgrade to WARN** — keep the same scope; report as WARN instead of FAIL.
   Rejected: WARN is the wrong verdict for "we found a leaked credential."
   Downgrading trades the false-positive problem for a can't-trust-the-severity
   problem.

3. **Invert to a sensitive-only allowlist** — chosen. Only flag files that
   match a known-sensitive shape:
   - the live and legacy OpenClaw config (`openclaw.json`, `config.json`) and
     their `.bak*` / `.backup*` siblings (they carry the same provider tokens)
   - anything under `secrets/`, `credentials/`, `auth/`
   - credential-shaped filenames: `*.key`, `*.pem`, `*.env`, `*-token*`,
     `*-secret*`, `id_rsa*`, `id_ed25519*`

Rationale: Sarge is positioned as an agent-safety control
(`project_sarge_agent_safety_lens.md`). Workspace ACLs on credential material
are Tier 1; workspace ACLs on documentation are not a control at all — those
files are intentionally readable by design (both git and the workspace agents
expect it). A tight allowlist keeps every real leak visible without generating
per-install noise, and the allowlist covers the paths the corresponding
`harden-permissions.sh` module already locks down.

The old `world_readable_files_in` primitive is still exposed on both platform
files in case a future control wants the un-narrowed sweep; SC-28 uses the new
`world_readable_sensitive_files_in` sibling.

---

## 2026-08-29 — SC-28 config filename: probe both, live first

**Issue:** [#61](https://github.com/oscarsixsecllc/sarge/issues/61)

OpenClaw renamed its runtime config from `config.json` to `openclaw.json`
around 2026-04. Sarge day-1 hardcoded the legacy name, so on every real install
today the SC-28 config-perm and config-owner checks silently SKIPped and
`harden-permissions.sh` did nothing to the actual live file.

Decision: probe `openclaw.json` first, then `config.json` as a fallback for
long-lived pre-2026.4 installs. Same in both directions — `check-sc.sh`
verdicts against whichever file exists, and `harden-permissions.sh` chmods
whichever exist (both, if a partial migration left both in place). Backup
siblings (`openclaw.json.bak*`, `.backup*`) get the same 600 treatment because
they carry the same secrets.

Alternative considered: shell out to `openclaw config path` to resolve the live
location dynamically. Rejected for now — Sarge's SI-7 script-integrity
guarantee requires that the assessment be a pure read of local state with no
dependency on the runtime being installed or working. Two hardcoded names is a
smaller, self-contained fix that also works on hosts where the OpenClaw CLI is
uninstalled but the config file is left behind.
