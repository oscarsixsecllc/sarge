#!/usr/bin/env bash
# check-sr.sh — Supply Chain Risk Management (SR) checks — NIST 800-53 Rev 5
# Platform-specific data acquisition lives in lib/platforms/<os>.sh.

# SR-11: Component Authenticity — skill source attribution
#
# Installed skills are third-party (or self-authored) components pulled
# into the agent's tool surface. A skill with no source/author/origin
# metadata is a supply-chain blind spot: there's no way to trace where
# it came from or verify it wasn't tampered with. WARN (not FAIL) — this
# is a review signal, not a hard block, mirroring how AS-7 treats missing
# skill-workshop primitives.
log "SR-11: Skill component authenticity"
SR_SKILLS_DIR=""
for candidate in "$HOME/.openclaw/skills" "$HOME/.claude/skills"; do
  if [[ -d "$candidate" ]]; then
    SR_SKILLS_DIR="$candidate"
    break
  fi
done

if [[ -n "$SR_SKILLS_DIR" ]]; then
  SKILL_COUNT=0
  UNATTRIBUTED_COUNT=0
  UNATTRIBUTED_NAMES=""
  while IFS= read -r -d '' skill_md; do
    SKILL_COUNT=$((SKILL_COUNT + 1))
    if ! grep -qiE '"?(source|origin|author|publisher)"?[[:space:]]*[:=]' "$skill_md" 2>/dev/null; then
      UNATTRIBUTED_COUNT=$((UNATTRIBUTED_COUNT + 1))
      UNATTRIBUTED_NAMES="${UNATTRIBUTED_NAMES}${UNATTRIBUTED_NAMES:+, }$(basename "$(dirname "$skill_md")")"
    fi
  done < <(find "$SR_SKILLS_DIR" -maxdepth 2 -iname "SKILL.md" -print0 2>/dev/null)

  if [[ "$SKILL_COUNT" -eq 0 ]]; then
    skipx "SR-11-skill-attribution" "SR-11: no SKILL.md files found under $SR_SKILLS_DIR — nothing to verify"
  elif [[ "$UNATTRIBUTED_COUNT" -eq 0 ]]; then
    passx "SR-11-skill-attribution" "SR-11: all $SKILL_COUNT installed skill(s) under $SR_SKILLS_DIR declare source/author metadata"
  else
    warnx "SR-11-skill-attribution" "SR-11: $UNATTRIBUTED_COUNT of $SKILL_COUNT skill(s) under $SR_SKILLS_DIR have no source/author/origin metadata: $UNATTRIBUTED_NAMES"
  fi
else
  skipx "SR-11-skill-attribution" "SR-11: no skills directory found (checked ~/.openclaw/skills, ~/.claude/skills)"
fi

# SR-11: Component Authenticity — package signing keys
#
# Reuses the same apt_trusted_keys_count probe SI-7 (check-si.sh) uses
# for AllowUnauthenticated review — trusted GPG key material under
# /etc/apt/trusted.gpg.d/ (and the legacy /etc/apt/trusted.gpg keyring)
# is what lets apt verify package authenticity before install.
log "SR-11: Package signing key material"
if ! platform_supports apt_trusted_keys_count; then
  skipx "SR-11-apt-signing-keys" "SR-11: apt trusted-key inspection is a Debian/Ubuntu construct; not applicable on ${SARGE_OS_DESCRIPTION} — review the platform's native package-signing policy separately"
else
  TRUSTED_KEYS=$(platform apt_trusted_keys_count)
  if [[ -z "$TRUSTED_KEYS" || "$TRUSTED_KEYS" -eq 0 ]]; then
    warnx "SR-11-apt-signing-keys" "SR-11: no APT trusted GPG keys found under /etc/apt/trusted.gpg.d/ — package authenticity cannot be verified"
  else
    passx "SR-11-apt-signing-keys" "SR-11: $TRUSTED_KEYS APT trusted GPG key file(s) present — package authenticity verification is active"
  fi
fi
