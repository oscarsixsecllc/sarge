# DECISIONS — Sarge

Non-obvious design and scoping calls made during Sarge development. Each entry
is dated, references the driving issue(s) or PR(s), and states what was decided
and why. Add entries at the top; do not edit historic entries.

---

## 2026-08-29 — AS (Agent Safety) as a new family, not folded under SI

**Issues:** [#62](https://github.com/oscarsixsecllc/sarge/issues/62),
[#65](https://github.com/oscarsixsecllc/sarge/issues/65)

Sprint 2 added coverage for tool-gate (issue #62) and workspace-attestations /
skill-workshop / cron-trust (issue #65). Both issues ask "new family or fold
under SI?"

Decision: **new AS family, but every AS check maps back to underlying NIST
800-53 Rev 5 controls in its catalog `family` field.**

Rationale:

1. **Grouping matches operator mental model.** Per
   `project_sarge_agent_safety_lens.md`, tool-gate + attestations + workshop
   + cron-trust are the Tier 1 agent-safety controls that make Sarge
   *specifically* about OpenClaw hardening rather than generic OS hygiene.
   Scattering them across AC-3 (tool-gate write-gate), AU-2 (decisions
   ledger), CM-2 (attestations), CM-5 (workshop), CM-6 (cron-trust), and
   SI-4 (digest) would hide the story — an operator scanning the report
   should be able to see "agent-runtime posture is here" in one block.

2. **NIST purity is preserved.** Each AS check_id documents its mapping in
   the catalog `family` string (e.g. `AS-1 — Tool-Gate Hook Installation
   (Sarge/OpenClaw overlay; maps to AC-3, AC-6)`). Anyone building an
   800-53 compliance matrix from Sarge output can still enumerate the
   NIST controls covered — the AS label is a grouping index, not a
   replacement mapping.

3. **SI fold rejected specifically.** SI-4 (system monitoring) is the
   closest single NIST fit but only covers AS-4 (digest) and AS-3
   (ledger freshness). AS-1 / AS-2 / AS-5 / AS-6 / AS-7 / AS-8 each
   have different NIST anchor points (AC-3, AC-6, SI-7, CM-2, CM-5, CM-6),
   so a SI fold would either misrepresent them or need per-check
   sub-mapping — same story as a standalone AS family, but harder to
   scan visually.

4. **Precedent in the Windows overlay.** Sarge already ships a `WIN-*`
   pseudo-family for Windows-specific controls that don't have a clean
   NIST-family home. AS follows the same pattern for the OpenClaw
   overlay.

All AS checks are agent-scoped (guarded by `SARGE_HOST_ONLY`) so
`--host-only` mode continues to emit a clean baseline scan without any
agent-runtime context.

## 2026-08-29 — Baseline schema section-mapping for openclaw.json.baseline v0.2

**Issue:** [#65](https://github.com/oscarsixsecllc/sarge/issues/65) (baseline
refresh scope)

The Sprint 2 brief called for adding 11 missing keys to
`baseline/openclaw.json.baseline`: approvalPolicy, hooks, subagents, workshop,
compaction, rateLimit, auth.profiles, mcp.servers, browser.\*, sandboxes,
workboard.

Live OpenClaw 2026.7.x schema (`openclaw config schema`) does not expose those
exact top-level names — several have moved into nested sections since Sarge
day-1 was written. Explicit section mapping for this baseline update:

| Brief name        | Baseline location                | Live-schema location                    |
|-------------------|----------------------------------|-----------------------------------------|
| approvalPolicy    | `approvals`                      | `approvals` (schema successor)          |
| hooks             | `hooks`                          | `hooks` (top-level)                     |
| subagents         | `agents.subagents`               | (schema-driven; nested under agents)    |
| workshop          | `skills.workshop`                | `skills.workshop`                       |
| compaction        | `session.compaction`             | `session.compaction`                    |
| rateLimit         | `models.rateLimit`               | `models.rateLimit`                      |
| auth.profiles     | `auth.profiles`                  | `auth.profiles` (top-level)             |
| mcp.servers       | `mcp.servers`                    | `mcp.servers` (top-level)               |
| browser.\*        | `browser` (block)                | `browser` (top-level)                   |
| sandboxes         | `sandboxes` (block, plus inherit)| `security` / `agents.defaults.sandbox`  |
| workboard         | `plugins.workboard`              | (plugin-scoped in current schema)       |

Baseline version bumped `0.1.0 -> 0.2.0` to reflect the schema surface change.
The file remains a documentation/hardening template — Sarge does not currently
diff a live config against this baseline (that's future work under drift). The
new sections carry `_control` annotations tying each hardening choice to the
NIST 800-53 control(s) it addresses.

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
