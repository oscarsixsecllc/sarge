# Sarge Quickstart

## Prerequisites
- One of:
  - Ubuntu 22.04 or 24.04 LTS (x86_64 or arm64) — full coverage
  - macOS — file-permission hardening today; assess / drift / additional hardening modules rolling out across PRs
- OpenClaw installed
- Git

## Install

```bash
git clone https://github.com/oscarsixsecurity/sarge.git
cd sarge
chmod +x scripts/*.sh assessment/assess.sh drift/*.sh assessment/report/report.sh
```

## Run a Gap Analysis (no sudo required)

```bash
./assessment/assess.sh
```

Reports are saved to `~/.sarge/reports/`. Both Markdown and JSON formats generated.

## Apply Hardening (sudo required)

```bash
sudo ./scripts/install.sh
```

Each module prompts before making changes. Non-destructive — nothing applied without confirmation.

## Set Up Drift Detection

```bash
# Take an initial snapshot after hardening
sudo ./drift/snapshot.sh

# Check for drift manually
./drift/compare.sh

# Schedule automated drift checks (daily at 6am)
echo "0 6 * * * $PWD/drift/drift-cron.sh >> ~/.sarge/drift.log 2>&1" | crontab -
```

## Tell Your OpenClaw Agent

Once installed, just say:
- "Run a Sarge gap analysis"
- "Check for drift since last Sarge snapshot"
- "Apply Sarge hardening scripts"
