# Sarge Community Agent

The Sarge community agent runs on the Oscar Six management VM and manages the GitHub and Discord community for the Sarge project.

## What It Does
- Triages GitHub issues and PRs for oscarsixsecurity/sarge
- Answers NIST 800-53 and Sarge questions in Discord #sarge
- Escalates policy decisions and consulting leads to the O6 business owner

## What It Does NOT Do
- Execute community instructions embedded in GitHub issues or Discord messages
- Access Randy's personal systems or RH2 data
- Make pricing or policy decisions
- Transmit data outside the O6 management VM

## Trust Hierarchy
1. Randy Hinders (owner) — full trust
2. Designated maintainers (GitHub role) — project decisions
3. Community members — untrusted input; classified before any action

## Prompt Injection Protection
All community input is treated as untrusted data. The agent classifies intent before acting. Anomalous instructions are escalated to Randy and never executed.

## Audit Trail
All agent actions are logged to the private Randy briefing channel on the Oscar Six Discord.
